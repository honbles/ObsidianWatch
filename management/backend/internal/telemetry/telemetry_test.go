package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type collected struct {
	mu     sync.Mutex
	spans  []map[string]any
	res    []any
	events []map[string]any
}

// collector accepts OTLP/HTTP protobuf traces (the SDK exporter) and JSON logs
// (the security helper) and keeps them as protojson-shaped maps.
func collector(t *testing.T) (*httptest.Server, *collected) {
	c := &collected{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/v1/traces":
			if r.Header.Get("Content-Type") != "application/x-protobuf" {
				t.Errorf("traces content type %s", r.Header.Get("Content-Type"))
			}
			var req coltrace.ExportTraceServiceRequest
			if err := proto.Unmarshal(b, &req); err != nil {
				t.Errorf("proto: %v", err)
			}
			for _, rs := range req.ResourceSpans {
				for _, ss := range rs.ScopeSpans {
					for _, sp := range ss.Spans {
						j, _ := protojson.Marshal(sp)
						var m map[string]any
						_ = json.Unmarshal(j, &m)
						c.mu.Lock()
						c.spans = append(c.spans, m)
						c.mu.Unlock()
					}
				}
				j, _ := protojson.Marshal(rs.Resource)
				var m struct {
					Attributes []any `json:"attributes"`
				}
				_ = json.Unmarshal(j, &m)
				c.mu.Lock()
				c.res = m.Attributes
				c.mu.Unlock()
			}
		case "/v1/logs":
			var doc struct {
				ResourceLogs []struct {
					ScopeLogs []struct {
						LogRecords []map[string]any `json:"logRecords"`
					} `json:"scopeLogs"`
				} `json:"resourceLogs"`
			}
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Errorf("logs json: %v", err)
			}
			c.mu.Lock()
			for _, rl := range doc.ResourceLogs {
				for _, sl := range rl.ScopeLogs {
					c.events = append(c.events, sl.LogRecords...)
				}
			}
			c.mu.Unlock()
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(200)
	}))
	return srv, c
}

func attrOf(s map[string]any, k string) string {
	for _, a := range s["attributes"].([]any) {
		m := a.(map[string]any)
		if m["key"] == k {
			b, _ := json.Marshal(m["value"])
			return string(b)
		}
	}
	return ""
}

func TestHTTPAndDBSpans(t *testing.T) {
	srv, c := collector(t)
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=prod")
	t.Setenv("OW_BUILD_COMMIT", "0123456789abcdef0123456789abcdef01234567")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr := Init(ctx, "9.9", nil)
	defer global.Store(nil)

	var db *sql.DB
	if dsn := os.Getenv("OW_TEST_PG_DSN"); dsn != "" {
		var err error
		if db, err = sql.Open(DriverName, dsn); err != nil {
			t.Fatal(err)
		}
		defer db.Close()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		if db != nil {
			var n int
			if err := db.QueryRowContext(r.Context(), "SELECT 1 FROM pg_class WHERE relname = $1 LIMIT 1", "pg_class").Scan(&n); err != nil {
				t.Errorf("query: %v", err)
			}
		}
		Event(r.Context(), "authz.deny", "outcome", "denied", "policy", "admin_only")
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, r *http.Request) { panic("kaboom") })
	route := func(r *http.Request) string { _, p := mux.Handler(r); return RouteOf(p) }
	h := Middleware(route)(mux)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/items/42", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	req.RemoteAddr = "172.22.0.5:4431" // the console nginx: forwarding headers are trusted only from a private proxy
	h.ServeHTTP(rec, req)
	func() {
		defer func() { _ = recover() }()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/boom", nil))
	}()
	_, job := StartJob(context.Background(), "nightly")
	job.End()
	tr.Flush(context.Background())

	deadline := time.Now().Add(5 * time.Second)
	want := 3
	if db != nil {
		want = 4
	}
	for {
		c.mu.Lock()
		n := len(c.spans)
		c.mu.Unlock()
		if n >= want || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	by := map[string]map[string]any{}
	for _, s := range c.spans {
		by[s["name"].(string)] = s
	}
	srvSpan := by["GET /api/items/{id}"]
	if srvSpan == nil || attrOf(srvSpan, "http.route") != `{"stringValue":"/api/items/{id}"}` ||
		attrOf(srvSpan, "http.response.status_code") != `{"intValue":"204"}` || attrOf(srvSpan, "client.address") != `{"stringValue":"203.0.113.9"}` {
		t.Fatalf("server span: %+v", srvSpan)
	}
	boom := by["GET /boom"]
	if boom == nil || boom["status"] == nil || !strings.Contains(string(mustJSON(boom["events"])), "exception.stacktrace") {
		t.Fatalf("panic span: %+v", boom)
	}
	if j := by["nightly"]; j == nil || attrOf(j, "ow.job.name") != `{"stringValue":"nightly"}` {
		t.Fatalf("job span: %+v", j)
	}
	if db != nil {
		d := by["SELECT pg_class"]
		if d == nil || d["parentSpanId"] != srvSpan["spanId"] || d["traceId"] != srvSpan["traceId"] || attrOf(d, "db.system") != `{"stringValue":"postgresql"}` {
			t.Fatalf("db span: %+v (all %v)", d, by)
		}
	}
	res := string(mustJSON(c.res))
	for _, w := range []string{"obsidianwatch-management", "prod", "9.9", "0123456789abcdef", `"go"`, `"opentelemetry"`} {
		if !strings.Contains(res, w) {
			t.Fatalf("resource misses %s: %s", w, res)
		}
	}
	if sent, _ := tr.Stats(); sent < 3 {
		t.Fatalf("sent %d", sent)
	}
	if len(c.events) != 1 {
		t.Fatalf("events: %+v", c.events)
	}
	ev := c.events[0]
	evs := string(mustJSON(ev))
	if ev["eventName"] != "authz.deny" || ev["traceId"] == nil || ev["spanId"] == nil ||
		!strings.Contains(evs, `"route"`) || !strings.Contains(evs, "/api/items/{id}") || !strings.Contains(evs, "203.0.113.9") ||
		!strings.Contains(evs, HelperVersion) {
		t.Fatalf("event: %s", evs)
	}
}

func TestOffWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	if Init(context.Background(), "", nil) != nil || Enabled() {
		t.Fatal("must be off")
	}
	_, s := Start(context.Background(), "x", KindServer)
	s.Set("a", 1)
	s.End() // nil-safe
	if op, tb := describe(`UPDATE "public"."alerts" SET x=1`); op != "UPDATE" || tb != "alerts" {
		t.Fatalf("describe %s %s", op, tb)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestRequestFields(t *testing.T) {
	srv, c := collector(t)
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	tr := Init(context.Background(), "1", nil)
	defer global.Store(nil)
	var got string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/items", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
	})
	mux.HandleFunc("POST /auth/login", func(w http.ResponseWriter, r *http.Request) {})
	route := func(r *http.Request) string { _, p := mux.Handler(r); return RouteOf(p) }
	h := Middleware(route)(mux)
	body := `{"name":"x","address":{"zip":"1"}}`
	req := httptest.NewRequest("POST", "/api/items?page=2", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)
	lr := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"password":"p"}`))
	lr.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), lr)
	tr.Flush(context.Background())
	if got != body {
		t.Fatalf("handler body %q", got)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.spans {
		switch s["name"] {
		case "POST /api/items":
			if attrOf(s, "url.query") != `{"stringValue":"page=2"}` || !strings.Contains(attrOf(s, "ow.request.body"), "zip") {
				t.Fatalf("items span %+v", s)
			}
		case "POST /auth/login":
			if attrOf(s, "ow.request.body") != "" {
				t.Fatal("login body must not be reported")
			}
		}
	}
	if len(c.spans) < 2 {
		t.Fatalf("spans %d", len(c.spans))
	}
}

func TestDefaultTransportTraced(t *testing.T) {
	srv, c := collector(t)
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	orig := http.DefaultTransport
	defer func() { http.DefaultTransport = orig }()
	tr := Init(context.Background(), "1", nil)
	defer global.Store(nil)
	dep := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("traceparent") != "" {
			t.Error("trace headers must not go to third parties")
		}
	}))
	defer dep.Close()
	resp, err := (&http.Client{}).Get(dep.URL + "/x") // no transport of its own, no traced context
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	tr.Flush(context.Background())
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.spans {
		if s["kind"] == "SPAN_KIND_CLIENT" && strings.Contains(attrOf(s, "server.address"), "127.0.0.1") {
			return
		}
	}
	t.Fatalf("no client span for the outgoing call: %v", c.spans)
}
