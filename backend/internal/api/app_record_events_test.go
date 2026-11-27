package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"obsidianwatch/backend/internal/store"
)

func TestAppRecordEvents(t *testing.T) {
	now := time.Now().UTC()
	b := store.AppBatch{
		Traces: []store.AppTrace{{TraceID: "t1", Service: "api", Environment: "prod", Started: now, DurationMs: 812,
			RootRoute: "POST /orders", Status: "error", KeepReason: "error", SpanCount: 2, Spans: json.RawMessage(`[{"name":"POST /orders"},{"name":"SELECT orders"}]`)}},
		Errors:     []store.AppError{{Service: "api", Environment: "prod", Route: "POST /orders", Type: "TimeoutError", Message: "db timeout", Frames: []string{"a.go:1"}, Count: 3, Time: now}},
		Operations: []store.AppOperation{{Service: "api", Kind: "job", Name: "billing", Minute: now, Runs: 4, Failures: 1}},
	}
	kept := []store.AppPayload{{Service: "api", Route: "/orders", Method: "POST", Status: 500, Time: now, Params: map[string]string{"sku": "x1"}, Withheld: []string{"card"}}}
	evs := appRecordEvents("ag1", "web1", "linux", b, kept)
	if len(evs) != 4 {
		t.Fatalf("got %d events", len(evs))
	}
	want := []string{"app.request", "app.payload", "app.error", "app.operation"}
	for i, e := range evs {
		if string(e.EventType) != want[i] || e.Host != "web1" || e.Source != "app" {
			t.Errorf("event %d: %s %s %s", i, e.EventType, e.Host, e.Source)
		}
		var raw struct{ App map[string]any }
		if json.Unmarshal(e.Raw, &raw) != nil || raw.App["service"] != "api" {
			t.Errorf("event %d raw: %s", i, e.Raw)
		}
	}
	if !strings.Contains(string(evs[0].Raw), `"SELECT orders"`) || !strings.Contains(string(evs[0].Raw), `"method":"POST"`) {
		t.Errorf("request payload: %s", evs[0].Raw)
	}
	if strings.Contains(string(evs[1].Raw), `card"`) && !strings.Contains(string(evs[1].Raw), `"withheld":["card"]`) {
		t.Errorf("payload leaked a withheld value: %s", evs[1].Raw)
	}
	big := `[` + strings.Repeat(`{"name":"`+strings.Repeat("x", 1000)+`"},`, 400) + `{"name":"last"}]`
	tr := appTrimSpans(json.RawMessage(big), 64<<10)
	if len(tr) > 64<<10 || !json.Valid(tr) || !strings.Contains(string(tr), "truncated") {
		t.Errorf("trim: %d bytes valid=%v", len(tr), json.Valid(tr))
	}
}
