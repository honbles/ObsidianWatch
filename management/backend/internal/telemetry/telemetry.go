// Package telemetry instruments the management server with the official
// OpenTelemetry Go SDK (traces over OTLP/HTTP protobuf) and sends the
// ObsidianWatch security-helper events (OTLP log records) that lift the
// service to Tier 2:
//
//   - server spans for every API request (method, route template, status,
//     client address) and an "exception" event with the Go stack when a
//     handler panics;
//   - client spans for every database statement made while serving a request
//     or running a job (sql.go), and for outgoing HTTP calls made with
//     http.DefaultClient, the DevOps client and the AWS client (Transport);
//   - internal spans for background jobs (ow.job.name);
//   - security events: auth.login, authz.deny, ratelimit.hit, admin.action,
//     data.export (events.go).
//
// Off unless OTEL_EXPORTER_OTLP_ENDPOINT (or ..._TRACES_ENDPOINT) is set.
// OTEL_SDK_DISABLED=true turns it off. Endpoints may be http://host:port or
// unix:///path/to/otlp.sock (the agent's socket, for containers).
package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Span kinds (OTLP numbering).
const (
	KindInternal = 1
	KindServer   = 2
	KindClient   = 3
)

const scopeName = "obsidianwatch/management"

type attr struct {
	k string
	v any // string | int | int64 | bool | float64
}

// Span is one unit of work. Methods are safe on a nil span.
type Span struct {
	s        trace.Span
	children *atomic.Int32 // per trace, shared with descendants
}

// Tracer owns the SDK provider and the helper-event exporter.
type Tracer struct {
	tp      *sdktrace.TracerProvider
	tracer  trace.Tracer
	events  *eventExporter
	sent    atomic.Int64
	dropped atomic.Int64
	logger  *slog.Logger
}

var global atomic.Pointer[Tracer]

// maxChildren caps the client/internal spans recorded under one request.
const maxChildren = 200

// Init reads the environment and starts the SDK. It returns nil (and
// telemetry stays off) when no endpoint is configured.
func Init(ctx context.Context, version string, logger *slog.Logger) *Tracer {
	if strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
		return nil
	}
	ep := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	base := strings.TrimRight(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), "/")
	if ep == "" && base != "" {
		ep = base + "/v1/traces"
	}
	if ep == "" {
		return nil
	}
	logsEP := os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
	if logsEP == "" {
		if base != "" {
			logsEP = base + "/v1/logs"
		} else {
			logsEP = strings.TrimSuffix(ep, "/v1/traces") + "/v1/logs"
		}
	}
	if logger == nil {
		logger = slog.Default()
	}
	t := &Tracer{logger: logger}
	res := resourceAttrs(version)

	exp, err := otlptracehttp.New(ctx, exporterOptions(ep)...)
	if err != nil {
		logger.Warn("telemetry: exporter not started", "err", err)
		return nil
	}
	r, err := resource.New(ctx, resource.WithTelemetrySDK(), resource.WithAttributes(toKV(res)...))
	if err != nil {
		logger.Warn("telemetry: resource", "err", err)
	}
	t.tp = sdktrace.NewTracerProvider(
		sdktrace.WithResource(r),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithBatcher(&countingExporter{SpanExporter: exp, t: t},
			sdktrace.WithBatchTimeout(2*time.Second), sdktrace.WithMaxQueueSize(8192), sdktrace.WithMaxExportBatchSize(512)),
	)
	t.tracer = t.tp.Tracer(scopeName)
	otel.SetTracerProvider(t.tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) { logger.Debug("telemetry: sdk", "err", err) }))

	t.events = newEventExporter(logsEP, resourceForLogs(res), logger)
	global.Store(t)
	go t.events.run(ctx)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = t.tp.Shutdown(sctx)
	}()
	logger.Info("telemetry: OpenTelemetry SDK exporting traces", "endpoint", redactEndpoint(ep), "logs", redactEndpoint(logsEP))
	return t
}

// exporterOptions points otlptracehttp at the endpoint. Options override any
// OTEL_EXPORTER_OTLP_* the SDK reads itself, so unix:// works too.
func exporterOptions(ep string) []otlptracehttp.Option {
	noProxy := otlptracehttp.WithProxy(func(*http.Request) (*url.URL, error) { return nil, nil })
	if _, urlPath, client, ok := unixClient(ep, "/v1/traces"); ok {
		return []otlptracehttp.Option{otlptracehttp.WithHTTPClient(client), otlptracehttp.WithEndpoint("localhost"),
			otlptracehttp.WithURLPath(urlPath), otlptracehttp.WithInsecure()}
	}
	return []otlptracehttp.Option{otlptracehttp.WithEndpointURL(ep), noProxy, otlptracehttp.WithTimeout(10 * time.Second)}
}

// countingExporter keeps sent/dropped totals for Stats.
type countingExporter struct {
	sdktrace.SpanExporter
	t *Tracer
}

func (c *countingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	err := c.SpanExporter.ExportSpans(ctx, spans)
	if err != nil {
		c.t.dropped.Add(int64(len(spans)))
		c.t.logger.Debug("telemetry: export failed", "err", err, "spans", len(spans))
	} else {
		c.t.sent.Add(int64(len(spans)))
	}
	return err
}

func redactEndpoint(ep string) string {
	if i := strings.Index(ep, "@"); i >= 0 {
		if j := strings.Index(ep, "://"); j >= 0 && j < i {
			return ep[:j+3] + "***" + ep[i:]
		}
	}
	return ep
}

// unixClient handles unix:///path/otlp.sock[/v1/...] endpoints: the socket
// path, the URL path to post to, and a client that dials the socket.
func unixClient(ep, defPath string) (sock, urlPath string, c *http.Client, ok bool) {
	path, ok := strings.CutPrefix(ep, "unix://")
	if !ok {
		return "", "", nil, false
	}
	sock, urlPath = path, defPath
	if i := strings.Index(path, ".sock/"); i >= 0 {
		sock, urlPath = path[:i+5], path[i+5:]
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	return sock, urlPath, &http.Client{Transport: tr, Timeout: 10 * time.Second}, true
}

// resourceAttrs builds the resource: service name, version, environment and
// the commit the binary was built from (so the Code tab can match it). The
// SDK adds telemetry.sdk.*.
func resourceAttrs(version string) []attr {
	name := os.Getenv("OTEL_SERVICE_NAME")
	if name == "" {
		name = "obsidianwatch-management"
	}
	env := "default"
	extra := map[string]string{}
	for _, kv := range strings.Split(os.Getenv("OTEL_RESOURCE_ATTRIBUTES"), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || k == "" {
			continue
		}
		switch k {
		case "deployment.environment", "deployment.environment.name":
			env = v
		default:
			extra[k] = v
		}
	}
	out := []attr{{"service.name", name}, {"deployment.environment", env}}
	if version != "" {
		out = append(out, attr{"service.version", version})
	}
	rev, dirty := buildRevision()
	if v := os.Getenv("OW_BUILD_COMMIT"); v != "" {
		rev, dirty = v, false
	}
	if rev != "" && !dirty {
		out = append(out, attr{"vcs.ref.head.revision", rev})
	}
	for k, v := range extra {
		if strings.HasPrefix(k, "vcs.") || k == "service.namespace" {
			out = append(out, attr{k, v})
		}
	}
	return out
}

// buildRevision is the VCS revision Go stamped into the binary, if any.
func buildRevision() (rev string, dirty bool) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	return rev, dirty
}

func toKV(as []attr) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(as))
	for _, a := range as {
		out = append(out, kv(a.k, a.v))
	}
	return out
}

func kv(k string, v any) attribute.KeyValue {
	switch x := v.(type) {
	case string:
		return attribute.String(k, x)
	case int:
		return attribute.Int(k, x)
	case int64:
		return attribute.Int64(k, x)
	case bool:
		return attribute.Bool(k, x)
	case float64:
		return attribute.Float64(k, x)
	default:
		return attribute.String(k, fmt.Sprint(x))
	}
}

// ── Spans ─────────────────────────────────────────────────────────────────────

type ctxKey struct{}

// FromContext returns the active span started by this package, or nil.
func FromContext(ctx context.Context) *Span {
	s, _ := ctx.Value(ctxKey{}).(*Span)
	return s
}

// Enabled reports whether telemetry is exporting.
func Enabled() bool { return global.Load() != nil }

var kinds = map[int]trace.SpanKind{KindInternal: trace.SpanKindInternal, KindServer: trace.SpanKindServer, KindClient: trace.SpanKindClient}

// Start begins a span. A span with a parent in ctx joins its trace; child
// spans beyond the per-trace cap are not recorded (nil is returned).
func Start(ctx context.Context, name string, kind int) (context.Context, *Span) {
	t := global.Load()
	if t == nil {
		return ctx, nil
	}
	var children *atomic.Int32
	if p := FromContext(ctx); p != nil {
		if p.children.Add(1) > maxChildren {
			return ctx, nil
		}
		children = p.children
	} else {
		children = new(atomic.Int32)
	}
	ctx, s := t.tracer.Start(ctx, name, trace.WithSpanKind(kinds[kind]))
	sp := &Span{s: s, children: children}
	return context.WithValue(ctx, ctxKey{}, sp), sp
}

// StartRemote begins a server span that continues an incoming W3C traceparent.
func StartRemote(ctx context.Context, name string, traceparent string) (context.Context, *Span) {
	if traceparent != "" {
		ctx = propagation.TraceContext{}.Extract(ctx, propagation.MapCarrier{"traceparent": traceparent})
	}
	return Start(ctx, name, KindServer)
}

func (s *Span) Set(k string, v any) {
	if s == nil {
		return
	}
	s.s.SetAttributes(kv(k, v))
}

// SetError marks the span failed.
func (s *Span) SetError(msg string) {
	if s == nil {
		return
	}
	s.s.SetStatus(codes.Error, msg)
}

// RecordException adds an "exception" event (type, message, Go stack).
func (s *Span) RecordException(typ, msg, stack string) {
	if s == nil {
		return
	}
	s.s.AddEvent("exception", trace.WithAttributes(attribute.String("exception.type", typ),
		attribute.String("exception.message", msg), attribute.String("exception.stacktrace", stack)))
	s.s.SetStatus(codes.Error, msg)
}

// End finishes the span; the SDK batches it for export.
func (s *Span) End() {
	if s == nil {
		return
	}
	s.s.End()
}

// TraceParent is the W3C header value for outgoing calls.
func (s *Span) TraceParent() string {
	if s == nil {
		return ""
	}
	sc := s.s.SpanContext()
	return "00-" + sc.TraceID().String() + "-" + sc.SpanID().String() + "-" + sc.TraceFlags().String()
}

// Transport wraps an outbound transport so each call made under a traced
// request or job becomes a client span (dependencies such as api.github.com).
// It may be called before Init: the SDK's global provider forwards to the real
// one once Init sets it. No trace headers are sent to third parties.
func Transport(rt http.RoundTripper) http.RoundTripper {
	return otelhttp.NewTransport(rt,
		otelhttp.WithPropagators(propagation.NewCompositeTextMapPropagator()),
		otelhttp.WithFilter(func(r *http.Request) bool { return FromContext(r.Context()) != nil }),
	)
}

// Stats returns spans sent and dropped since start.
func (t *Tracer) Stats() (sent, dropped int64) {
	if t == nil {
		return 0, 0
	}
	return t.sent.Load(), t.dropped.Load()
}

// Flush exports what is queued (tests and shutdown).
func (t *Tracer) Flush(ctx context.Context) {
	if t == nil {
		return
	}
	_ = t.tp.ForceFlush(ctx)
	t.events.flush()
}
