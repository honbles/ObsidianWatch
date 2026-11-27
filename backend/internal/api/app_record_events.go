package api

// app_record_events.go - every application record the ingest stores individually is also written to the
// platform's event store, with its full payload, so it can be searched and exported like any other event:
//
//	app.request    a kept trace (errors, slow and security requests, and the baseline sample; the service's
//	               sampling setting decides how many): route, status, duration and every span
//	app.payload    request parameters captured on a reviewed route (only what the route's policy allows)
//	app.error      an error report: type, message (as the service's error-message setting allows), stack frames
//	app.operation  a job or message consumer's runs in one minute, with failures
//
// Searches in the console leave application events out unless the query names an application (app:) or an
// app.* type, so host searches stay fast however busy the services are.

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/backend/internal/store"
	"obsidianwatch/backend/pkg/schema"
)

// appMaxEventRaw bounds one application event's payload; a larger trace keeps its first spans.
const appMaxEventRaw = 256 << 10

func appRecordEvents(agentID, host, osName string, b store.AppBatch, kept []store.AppPayload) []schema.Event {
	out := make([]schema.Event, 0, len(b.Traces)+len(kept)+len(b.Errors)+len(b.Operations))
	mk := func(t time.Time, et schema.EventType, sev schema.Severity, app map[string]any) schema.Event {
		if t.IsZero() {
			t = time.Now().UTC()
		}
		raw, _ := json.Marshal(map[string]any{"app": app})
		return schema.Event{ID: appNewEventID(), Time: t, AgentID: agentID, Host: host, OS: osName,
			EventType: et, Severity: sev, Source: appEventSourceLabel, Raw: raw}
	}
	for _, t := range b.Traces {
		sev := schema.SeverityInfo
		if t.Status == "error" || t.KeepReason == "error" {
			sev = schema.SeverityLow
		}
		if t.KeepReason == "security" {
			sev = schema.SeverityMedium
		}
		spans := t.Spans
		if len(spans) > appMaxEventRaw {
			spans = appTrimSpans(spans, appMaxEventRaw)
		}
		app := map[string]any{"event.name": "request", "service": t.Service, "environment": t.Environment,
			"trace_id": t.TraceID, "route": t.RootRoute, "status": t.Status, "duration_ms": t.DurationMs,
			"keep_reason": t.KeepReason, "span_count": t.SpanCount, "spans": spans}
		if m, r, ok := strings.Cut(t.RootRoute, " "); ok && m != "" && strings.ToUpper(m) == m {
			app["method"], app["path"] = m, r
		}
		out = append(out, mk(t.Started, "app.request", sev, app))
	}
	for _, p := range kept {
		app := map[string]any{"event.name": "payload", "service": p.Service, "environment": p.Environment,
			"route": p.Route, "method": p.Method, "http_status": p.Status, "duration_ms": p.DurationMs,
			"trace_id": p.TraceID, "params": p.Params}
		if len(p.Withheld) > 0 {
			app["withheld"] = p.Withheld
		}
		sev := schema.SeverityInfo
		if p.Status >= 500 {
			sev = schema.SeverityLow
		}
		out = append(out, mk(p.Time, "app.payload", sev, app))
	}
	for _, e := range b.Errors {
		app := map[string]any{"event.name": "error", "service": e.Service, "environment": e.Environment,
			"route": e.Route, "method": e.Method, "error_type": e.Type, "message": e.Message, "frame": e.Frame,
			"frames": e.Frames, "fingerprint": e.Fingerprint, "version": e.Version, "trace_id": e.TraceID,
			"count": e.Count}
		out = append(out, mk(e.Time, "app.error", schema.SeverityLow, app))
	}
	for _, o := range b.Operations {
		sev := schema.SeverityInfo
		if o.Failures > 0 {
			sev = schema.SeverityLow
		}
		app := map[string]any{"event.name": "operation", "service": o.Service, "environment": o.Environment,
			"operation_kind": o.Kind, "operation": o.Name, "runs": o.Runs, "failures": o.Failures,
			"last_run": o.LastRun}
		out = append(out, mk(o.Minute, "app.operation", sev, app))
	}
	return out
}

// appTrimSpans keeps the leading spans of a JSON array so the result stays under max bytes.
func appTrimSpans(raw json.RawMessage, max int) json.RawMessage {
	var spans []json.RawMessage
	if json.Unmarshal(raw, &spans) != nil {
		return json.RawMessage(`[]`)
	}
	size, n := 2, 0
	for n < len(spans) && size+len(spans[n])+1 < max {
		size += len(spans[n]) + 1
		n++
	}
	out, _ := json.Marshal(append(spans[:n:n], json.RawMessage(`{"truncated":`+strconv.Itoa(len(spans)-n)+`}`)))
	return out
}
