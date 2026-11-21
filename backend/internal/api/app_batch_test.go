package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"obsidianwatch/backend/internal/store"
	"obsidianwatch/backend/pkg/schema"
)

type appFakeStore struct {
	agents  map[string]string
	got     store.AppBatch
	gotHost string
	changes []store.AppChange
	events  []schema.Event
	calls   int
}

func (f *appFakeStore) AppAgentInfo(_ context.Context, id string) (string, string, bool, error) {
	h, ok := f.agents[id]
	return h, "linux", ok, nil
}
func (f *appFakeStore) AppIngestBatch(_ context.Context, _ string, host string, b store.AppBatch, _ time.Time) (store.AppIngestResult, error) {
	f.calls++
	f.got, f.gotHost = b, host
	return store.AppIngestResult{Instances: len(b.Instances), Routes: len(b.Routes), Edges: len(b.Edges), Traces: len(b.Traces), Changes: f.changes}, nil
}
func (f *appFakeStore) InsertEvents(_ context.Context, ev []schema.Event) error {
	f.events = append(f.events, ev...)
	return nil
}

func appPost(t *testing.T, h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/v1/app/batch", strings.NewReader(body)))
	return rec
}

func appTestHandler(f *appFakeStore) http.HandlerFunc {
	return appHandleBatch(f, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestAppBatchRejectsUnknownAgent(t *testing.T) {
	f := &appFakeStore{agents: map[string]string{"a1": "web-01"}}
	rec := appPost(t, appTestHandler(f), `{"agent_id":"ghost","instances":[{"service":"api"}]}`)
	if rec.Code != http.StatusForbidden || f.calls != 0 {
		t.Fatalf("code=%d calls=%d", rec.Code, f.calls)
	}
}

func TestAppBatchBadInput(t *testing.T) {
	f := &appFakeStore{agents: map[string]string{"a1": "web-01"}}
	h := appTestHandler(f)
	if rec := appPost(t, h, `{nope`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid json: %d", rec.Code)
	}
	if rec := appPost(t, h, `{"instances":[]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing agent: %d", rec.Code)
	}
}

func TestAppBatchHostComesFromAgentRecord(t *testing.T) {
	f := &appFakeStore{agents: map[string]string{"a1": "web-01"}}
	rec := appPost(t, appTestHandler(f), `{"agent_id":"a1","host":"evil","instances":[{"service":"api","environment":"prod","instance_ref":"i1","version":"1.2"}]}`)
	if rec.Code != 200 || f.gotHost != "web-01" {
		t.Fatalf("code=%d host=%q", rec.Code, f.gotHost)
	}
}

func TestAppBatchStripsQueryAndCredentials(t *testing.T) {
	f := &appFakeStore{agents: map[string]string{"a1": "h"}}
	now := time.Now().UTC().Format(time.RFC3339)
	body := `{"agent_id":"a1","routes":[{"service":"api","environment":"prod","method":"get","route":"/users/{id}?token=abc#x","minute":"` + now + `","calls":3}],
	  "edges":[{"service":"api","environment":"prod","dst_kind":"external","source":"otel","dst_name":"https://user:pw@Pay.Example.com:8443/v1/charge?k=1","calls":2}]}`
	rec := appPost(t, appTestHandler(f), body)
	if rec.Code != 200 {
		t.Fatalf("code=%d %s", rec.Code, rec.Body.String())
	}
	if got := f.got.Routes[0]; got.Route != "/users/{id}" || got.Method != "GET" || len(got.DurBuckets) != store.AppHistLen {
		t.Fatalf("route not normalised: %+v", got)
	}
	if got := f.got.Edges[0].DstName; got != "pay.example.com:8443" {
		t.Fatalf("edge target leaked: %q", got)
	}
}

func TestAppBatchDropsBadItemsNotBatch(t *testing.T) {
	f := &appFakeStore{agents: map[string]string{"a1": "h"}}
	big := `"` + strings.Repeat("x", appMaxTraceBytes+10) + `"`
	body := `{"agent_id":"a1","instances":[{"service":""},{"service":"ok"}],
	  "edges":[{"service":"ok","dst_kind":"weird","source":"otel","dst_name":"x"}],
	  "routes":[{"service":"ok","method":"GET","route":"/","minute":"2001-01-01T00:00:00Z","calls":1}],
	  "traces":[{"trace_id":"T1","service":"ok","spans":` + big + `},{"trace_id":"T2","service":"ok","spans":[{"n":1}]}]}`
	rec := appPost(t, appTestHandler(f), body)
	if rec.Code != 200 {
		t.Fatalf("code=%d", rec.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["dropped"].(float64) != 4 || len(f.got.Instances) != 1 || len(f.got.Traces) != 1 || f.got.Traces[0].TraceID != "t2" {
		t.Fatalf("unexpected: %v %+v", out, f.got)
	}
}

func TestAppBatchCapsCounts(t *testing.T) {
	f := &appFakeStore{agents: map[string]string{"a1": "h"}}
	var sb strings.Builder
	sb.WriteString(`{"agent_id":"a1","instances":[`)
	for i := 0; i <= appMaxInstances; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"service":"s"}`)
	}
	sb.WriteString(`]}`)
	if rec := appPost(t, appTestHandler(f), sb.String()); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestAppBatchRateLimit(t *testing.T) {
	l := appNewLimiter()
	now := time.Now()
	if !l.allow("a", int(appItemsBurst), now) {
		t.Fatal("burst should pass")
	}
	if l.allow("a", 100, now) {
		t.Fatal("over budget should fail")
	}
	if !l.allow("a", 100, now.Add(2*time.Second)) {
		t.Fatal("refill should pass")
	}
	if !l.allow("b", 10, now) {
		t.Fatal("agents are independent")
	}
}

func TestAppChangeEvents(t *testing.T) {
	f := &appFakeStore{agents: map[string]string{"a1": "web-01"}, changes: []store.AppChange{
		{Kind: "version", Service: "api", Environment: "prod", InstanceID: 7, Version: "2", PrevVersion: "1"},
		{Kind: "edge", Service: "api", Environment: "prod", DstKind: "database", DstName: "pg:5432", Source: "otel", Baseline: true},
		{Kind: "instance", Service: "api", Environment: "prod", InstanceID: 7, PID: 42, Identity: "asserted"},
	}}
	rec := appPost(t, appTestHandler(f), `{"agent_id":"a1","instances":[{"service":"api"}]}`)
	if rec.Code != 200 || len(f.events) != 3 {
		t.Fatalf("code=%d events=%d", rec.Code, len(f.events))
	}
	if f.events[0].EventType != "app.service_change" || f.events[1].EventType != "app.dependency_new" || f.events[0].Host != "web-01" {
		t.Fatalf("bad events: %+v", f.events)
	}
	var raw map[string]map[string]any
	_ = json.Unmarshal(f.events[1].Raw, &raw)
	if raw["app"]["dependency"] != "pg:5432" || raw["app"]["baseline"] != true || raw["app"]["dependency_kind"] != "database" {
		t.Fatalf("raw.app: %v", raw)
	}
	_ = json.Unmarshal(f.events[2].Raw, &raw)
	if f.events[2].PID != 42 || raw["app"]["instance"] != "7" || raw["app"]["identity"] != "asserted" {
		t.Fatalf("instance event: pid=%d raw=%v", f.events[2].PID, raw)
	}
}

func TestAppBatchClientStatsSanitised(t *testing.T) {
	f := &appFakeStore{agents: map[string]string{"a1": "h"}}
	now := time.Now().UTC().Format(time.RFC3339)
	body := `{"agent_id":"a1","clients":[
	  {"service":"api","environment":"prod","route":"/login?x=1","method":"post","minute":"` + now + `","client_ip":"203.0.113.9","peer_ip":"10.0.0.2","failures":4,"status_401_403":4},
	  {"service":"api","environment":"prod","route":"/x","method":"GET","minute":"` + now + `","client_ip":"203.0.113.0/24","failures":1},
	  {"service":"api","environment":"prod","route":"/x","method":"GET","minute":"` + now + `","client_ip":"not an ip; DROP","failures":1},
	  {"service":"api","environment":"prod","route":"/x","method":"GET","minute":"` + now + `","failures":1},
	  {"service":"api","environment":"prod","route":"/x","method":"GET","minute":"` + now + `","client_ip":"1.2.3.4","failures":-5}]}`
	if rec := appPost(t, appTestHandler(f), body); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	c := f.got.Clients
	if len(c) != 2 || c[0].Route != "/login" || c[0].Method != "POST" || c[0].ClientIP != "203.0.113.9" || c[1].ClientIP != "203.0.113.0/24" {
		t.Fatalf("clients: %+v", c)
	}
}

type appFakeConfigStore struct {
	known bool
	svcs  []store.AppRemoteService
}

func (f appFakeConfigStore) AppAgentInfo(context.Context, string) (string, string, bool, error) {
	return "h", "linux", f.known, nil
}
func (f appFakeConfigStore) AppRemoteConfig(context.Context) ([]store.AppRemoteService, error) {
	return f.svcs, nil
}

func TestAppAgentConfigEndpoint(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	get := func(f appFakeConfigStore, q string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		appHandleAgentConfig(f, log)(rec, httptest.NewRequest("GET", "/api/v1/app/agent-config"+q, nil))
		return rec
	}
	svcs := []store.AppRemoteService{{Service: "api", Environment: "prod", StoreClientIP: "off", CleartextUsers: true, LatencyTargetMs: 250}}
	if rec := get(appFakeConfigStore{known: true, svcs: svcs}, "?agent_id=a1"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"store_client_ip":"off"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec := get(appFakeConfigStore{known: false, svcs: svcs}, "?agent_id=ghost"); rec.Code != http.StatusForbidden {
		t.Fatalf("unknown agent must be refused: %d", rec.Code)
	}
	if rec := get(appFakeConfigStore{known: true}, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing agent_id: %d", rec.Code)
	}
}

func TestAppBatchParamNamesAreValidatedNotTrusted(t *testing.T) {
	now := time.Now().UTC()
	b := &store.AppBatch{Params: []store.AppRouteParam{
		{Service: "api", Route: "/search?q=SECRET", Method: "get", Name: "q", Count: 3},
		{Service: "api", Route: "/search", Method: "GET", Name: "has space", Count: 1},
		{Service: "api", Route: "/search", Method: "GET", Name: "a=b", Count: 1},
		{Service: "api", Route: "/search", Method: "GET", Name: "", Count: 1},
		{Service: "api", Route: "/search", Method: "GET", Name: "user[name]", Count: 2},
		{Service: "api", Route: "/search", Method: "GET", Name: "ok", Count: 0},
		{Service: "api", Route: "/search", Method: "NOPE", Name: "ok", Count: 1},
		{Service: "api", Route: "/search", Method: "GET", Name: "3f9a8c1b2d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e9", Count: 1},
	}}
	dropped := appSanitizeBatch(b, now)
	if len(b.Params) != 2 || dropped != 6 {
		t.Fatalf("kept %+v dropped %d", b.Params, dropped)
	}
	if b.Params[0].Route != "/search" || b.Params[0].Method != "GET" || b.Params[0].Name != "q" || b.Params[1].Name != "user[name]" {
		t.Fatalf("%+v", b.Params)
	}
}
