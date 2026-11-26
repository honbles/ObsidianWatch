// Package owsecurity is the ObsidianWatch security helper for Go (optional).
//
// It sends the security events the console shows (auth.login, authz.deny,
// admin.action, data.export, ...) as OTLP log records to the local agent, next
// to the traces. A service that sends them reaches Tier 2. Each event carries
// the trace and span of the request it was raised in.
//
// It needs only the standard library and go.opentelemetry.io/otel/trace: the
// records are posted as OTLP/HTTP JSON, batched every second, and dropped
// (counted) when the queue is full, so a call never blocks the request.
// Pass identifiers only, never request bodies, parameter values or headers.
// user, session and object_id are pseudonymised by the agent unless the
// service is set to cleartext users.
package owsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// HelperVersion is sent with every event (helper_version).
const HelperVersion = "go-1"

type record struct {
	name    string
	at      time.Time
	traceID trace.TraceID
	spanID  trace.SpanID
	attrs   [][2]string
}

type exporter struct {
	url      string
	client   *http.Client
	resource [][2]string
	ch       chan record
	sent     atomic.Int64
	dropped  atomic.Int64
	once     sync.Once
	done     chan struct{}
}

var current atomic.Pointer[exporter]

// Init starts the helper. endpoint is the logs URL, e.g.
// http://127.0.0.1:4318/v1/logs or unix:///run/obsidianwatch/otlp.sock/v1/logs.
// resource must carry the same service.name and deployment.environment as the
// traces (and may add service.version). The returned stop function flushes
// what is queued; call it on shutdown.
func Init(endpoint string, resource map[string]string) (stop func()) {
	e := &exporter{ch: make(chan record, 2048), done: make(chan struct{})}
	e.url, e.client = endpointClient(endpoint)
	keys := make([]string, 0, len(resource))
	for k := range resource {
		keys = append(keys, k)
	}
	for _, k := range keys {
		e.resource = append(e.resource, [2]string{k, resource[k]})
	}
	e.resource = append(e.resource, [2]string{"telemetry.sdk.language", "go"})
	current.Store(e)
	go e.run()
	return func() {
		e.once.Do(func() { close(e.done) })
		time.Sleep(50 * time.Millisecond)
		e.flush()
	}
}

// Stats returns the events sent and dropped since Init.
func Stats() (sent, dropped int64) {
	if e := current.Load(); e != nil {
		return e.sent.Load(), e.dropped.Load()
	}
	return 0, 0
}

func endpointClient(ep string) (string, *http.Client) {
	if path, ok := strings.CutPrefix(ep, "unix://"); ok {
		sock, urlPath := path, "/v1/logs"
		if i := strings.Index(path, ".sock/"); i >= 0 {
			sock, urlPath = path[:i+5], path[i+5:]
		}
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}}
		return "http://localhost" + urlPath, &http.Client{Transport: tr, Timeout: 10 * time.Second}
	}
	return ep, &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second}
}

// Emit sends one event. kv are attribute name/value pairs; empty values are
// left out. Use the typed functions below where one fits.
func Emit(ctx context.Context, eventName string, kv ...string) {
	e := current.Load()
	if e == nil {
		return
	}
	r := record{name: eventName, at: time.Now()}
	r.attrs = append(r.attrs, [2]string{"event.name", eventName}, [2]string{"helper_version", HelperVersion})
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			r.attrs = append(r.attrs, [2]string{kv[i], kv[i+1]})
		}
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.traceID, r.spanID = sc.TraceID(), sc.SpanID()
	}
	select {
	case e.ch <- r:
	default:
		e.dropped.Add(1)
	}
}

// ── One function per event name the agent accepts ─────────────────────────────

func Login(ctx context.Context, outcome, user, client, route, method, reason string) {
	Emit(ctx, "auth.login", "outcome", outcome, "user", user, "client.address", client, "route", route, "method", method, "reason", reason)
}

func MFA(ctx context.Context, outcome, user, client, route, method string) {
	Emit(ctx, "auth.mfa", "outcome", outcome, "user", user, "client.address", client, "route", route, "method", method)
}

func AuthzDenied(ctx context.Context, resourceType, action, user, route, client, policy string) {
	Emit(ctx, "authz.deny", "resource_type", resourceType, "action", action, "user", user, "route", route, "client.address", client, "policy", policy)
}

func InputRejected(ctx context.Context, kind, route, parameter, client string) {
	Emit(ctx, "input.rejected", "kind", kind, "route", route, "parameter", parameter, "client.address", client)
}

func SSRFBlocked(ctx context.Context, targetHost, route, client string) {
	Emit(ctx, "ssrf.blocked", "target_host", targetHost, "route", route, "client.address", client)
}

func DeserializationBlocked(ctx context.Context, typeName, route, client string) {
	Emit(ctx, "deserialization.blocked", "type_name", typeName, "route", route, "client.address", client)
}

func RateLimited(ctx context.Context, limitName, route, client, user string) {
	Emit(ctx, "ratelimit.hit", "limit_name", limitName, "route", route, "client.address", client, "user", user)
}

func AdminAction(ctx context.Context, action, user, targetType, targetID, client string) {
	Emit(ctx, "admin.action", "action", action, "user", user, "target_type", targetType, "target_id", targetID, "outcome", "success", "client.address", client)
}

func DataExport(ctx context.Context, objectType, user, format string, rows int, route, client string) {
	n := ""
	if rows > 0 {
		n = strconv.Itoa(rows)
	}
	Emit(ctx, "data.export", "object_type", objectType, "user", user, "format", format, "rows", n, "route", route, "client.address", client)
}

func DataAccess(ctx context.Context, objectType, objectID, user, route, client string) {
	Emit(ctx, "data.access", "object_type", objectType, "object_id", objectID, "user", user, "action", "read", "route", route, "client.address", client)
}

func SessionAnomaly(ctx context.Context, kind, user, session, reason, client string) {
	Emit(ctx, "session.anomaly", "kind", kind, "user", user, "session", session, "reason", reason, "client.address", client)
}

// ── Export ────────────────────────────────────────────────────────────────────

var pending struct {
	mu    sync.Mutex
	batch []record
}

func (e *exporter) run() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-e.done:
			return
		case r := <-e.ch:
			pending.mu.Lock()
			pending.batch = append(pending.batch, r)
			full := len(pending.batch) >= 256
			pending.mu.Unlock()
			if full {
				e.flush()
			}
		case <-tick.C:
			e.flush()
		}
	}
}

func (e *exporter) flush() {
	for drained := false; !drained; {
		select {
		case r := <-e.ch:
			pending.mu.Lock()
			pending.batch = append(pending.batch, r)
			pending.mu.Unlock()
		default:
			drained = true
		}
	}
	pending.mu.Lock()
	batch := pending.batch
	pending.batch = nil
	pending.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	if err := e.post(batch); err != nil {
		e.dropped.Add(int64(len(batch)))
		return
	}
	e.sent.Add(int64(len(batch)))
}

func kvs(as [][2]string) []map[string]any {
	out := make([]map[string]any, 0, len(as))
	for _, a := range as {
		out = append(out, map[string]any{"key": a[0], "value": map[string]string{"stringValue": a[1]}})
	}
	return out
}

func (e *exporter) post(batch []record) error {
	recs := make([]map[string]any, 0, len(batch))
	for _, r := range batch {
		ts := strconv.FormatInt(r.at.UnixNano(), 10)
		m := map[string]any{"timeUnixNano": ts, "observedTimeUnixNano": ts, "eventName": r.name,
			"severityNumber": 13, "severityText": "WARN", "body": map[string]string{"stringValue": r.name}, "attributes": kvs(r.attrs)}
		if r.traceID.IsValid() {
			m["traceId"], m["spanId"] = r.traceID.String(), r.spanID.String()
		}
		recs = append(recs, m)
	}
	body, err := json.Marshal(map[string]any{"resourceLogs": []any{map[string]any{
		"resource":  map[string]any{"attributes": kvs(e.resource)},
		"scopeLogs": []any{map[string]any{"scope": map[string]string{"name": "obsidianwatch.security", "version": HelperVersion}, "logRecords": recs}},
	}}})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("receiver answered %d", resp.StatusCode)
	}
	return nil
}
