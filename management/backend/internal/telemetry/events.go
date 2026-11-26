package telemetry

// events.go - the Go security helper. Security events are OTLP log records
// whose event.name the ObsidianWatch agent recognises (auth.login, authz.deny,
// ratelimit.hit, admin.action, data.export ...). The agent turns them into
// app.security events, which lifts the service to Tier 2. They are sent as
// OTLP/HTTP JSON to the logs endpoint next to the traces endpoint, carry the
// trace and span ids of the request that raised them, and never block the
// caller (a full queue drops the event and counts it).
//
// Identifiers (user, session, object_id) are pseudonymised by the agent with
// the organisation's key unless the service is set to "cleartext users".

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/sdk"
	"go.opentelemetry.io/otel/trace"
)

// HelperVersion is reported with every event (helper_version).
const HelperVersion = "ow-go/1"

type eventRec struct {
	name    string
	at      time.Time
	traceID trace.TraceID
	spanID  trace.SpanID
	attrs   []attr
}

type eventExporter struct {
	url      string
	client   *http.Client
	resource []attr
	ch       chan eventRec
	mu       sync.Mutex
	batch    []eventRec
	sent     atomic.Int64
	dropped  atomic.Int64
	logger   *slog.Logger
	health   *exportHealth
}

func newEventExporter(ep string, resource []attr, logger *slog.Logger) *eventExporter {
	e := &eventExporter{ch: make(chan eventRec, 2048), resource: resource, logger: logger}
	if _, urlPath, c, ok := unixClient(ep, "/v1/logs"); ok {
		e.url, e.client = "http://localhost"+urlPath, c
	} else {
		e.url, e.client = ep, &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second}
	}
	return e
}

// resourceForLogs is the trace resource plus the telemetry.sdk.* the SDK adds
// to spans, so the agent files both under the same service and instance.
func resourceForLogs(res []attr) []attr {
	return append(append([]attr{}, res...), attr{"telemetry.sdk.language", "go"},
		attr{"telemetry.sdk.name", "opentelemetry"}, attr{"telemetry.sdk.version", sdk.Version()})
}

// Event records a security event. kv is a list of attribute name/value pairs
// from the helper vocabulary: outcome, method, user, reason, mfa, action,
// resource_type, policy, kind, parameter, limit_name, target_type, target_id,
// rows, bytes, format, session, object_type, object_id. The request's route
// and client address are added when the event is raised inside a request.
func Event(ctx context.Context, name string, kv ...string) {
	t := global.Load()
	if t == nil || t.events == nil {
		return
	}
	rec := eventRec{name: name, at: time.Now(), attrs: make([]attr, 0, len(kv)/2+5)}
	rec.attrs = append(rec.attrs, attr{"event.name", name}, attr{"helper_version", HelperVersion})
	have := map[string]bool{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			continue
		}
		rec.attrs = append(rec.attrs, attr{kv[i], kv[i+1]})
		have[kv[i]] = true
	}
	if ri, ok := ctx.Value(reqKey{}).(reqInfo); ok {
		for _, a := range []attr{{"route", ri.route}, {"client.address", ri.client}, {"network.peer.address", ri.peer}} {
			if s := a.v.(string); s != "" && !have[a.k] {
				rec.attrs = append(rec.attrs, a)
			}
		}
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		rec.traceID, rec.spanID = sc.TraceID(), sc.SpanID()
	}
	select {
	case t.events.ch <- rec:
	default:
		t.events.dropped.Add(1)
	}
}

func (e *eventExporter) run(ctx context.Context) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			e.drain()
			e.flush()
			return
		case r := <-e.ch:
			e.mu.Lock()
			e.batch = append(e.batch, r)
			n := len(e.batch)
			e.mu.Unlock()
			if n >= 256 {
				e.flush()
			}
		case <-tick.C:
			e.flush()
		}
	}
}

func (e *eventExporter) drain() {
	for {
		select {
		case r := <-e.ch:
			e.mu.Lock()
			e.batch = append(e.batch, r)
			e.mu.Unlock()
		default:
			return
		}
	}
}

func (e *eventExporter) flush() {
	if e == nil {
		return
	}
	e.drain()
	e.mu.Lock()
	batch := e.batch
	e.batch = nil
	e.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	if err := e.post(batch); err != nil {
		e.dropped.Add(int64(len(batch)))
		if e.health != nil {
			e.health.fail(e.logger, "logs", err)
		}
		return
	}
	e.sent.Add(int64(len(batch)))
	if e.health != nil {
		e.health.ok(e.logger, "logs")
	}
}

func (e *eventExporter) post(batch []eventRec) error {
	recs := make([]map[string]any, 0, len(batch))
	for _, r := range batch {
		ts := strconv.FormatInt(r.at.UnixNano(), 10)
		m := map[string]any{"timeUnixNano": ts, "observedTimeUnixNano": ts, "eventName": r.name,
			"severityNumber": 9, "severityText": "INFO", "attributes": jsonKVs(r.attrs)}
		if r.traceID.IsValid() {
			m["traceId"], m["spanId"] = r.traceID.String(), r.spanID.String()
		}
		recs = append(recs, m)
	}
	body, err := json.Marshal(map[string]any{"resourceLogs": []any{map[string]any{
		"resource":  map[string]any{"attributes": jsonKVs(e.resource)},
		"scopeLogs": []any{map[string]any{"scope": map[string]any{"name": scopeName, "version": HelperVersion}, "logRecords": recs}},
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
		return fmt.Errorf("collector answered %d", resp.StatusCode)
	}
	return nil
}

// EventStats returns security events sent and dropped since start.
func (t *Tracer) EventStats() (sent, dropped int64) {
	if t == nil || t.events == nil {
		return 0, 0
	}
	return t.events.sent.Load(), t.events.dropped.Load()
}

// OTLP/JSON attribute values.
type jAny struct {
	S *string  `json:"stringValue,omitempty"`
	I *string  `json:"intValue,omitempty"`
	B *bool    `json:"boolValue,omitempty"`
	D *float64 `json:"doubleValue,omitempty"`
}
type jKV struct {
	Key   string `json:"key"`
	Value jAny   `json:"value"`
}

func jsonKVs(as []attr) []jKV {
	out := make([]jKV, 0, len(as))
	for _, a := range as {
		var v jAny
		switch x := a.v.(type) {
		case string:
			v.S = &x
		case int:
			s := strconv.Itoa(x)
			v.I = &s
		case int64:
			s := strconv.FormatInt(x, 10)
			v.I = &s
		case bool:
			v.B = &x
		case float64:
			v.D = &x
		default:
			s := fmt.Sprint(x)
			v.S = &s
		}
		out = append(out, jKV{a.k, v})
	}
	return out
}
