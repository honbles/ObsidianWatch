package api

import (
	"database/sql"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestAppPercentile(t *testing.T) {
	// 100 calls, all in the (50,100] bucket → median is mid-bucket.
	h := make([]int64, appHistLen)
	h[4] = 100
	if p, over := appPercentile(h, 0.5); over || math.Abs(p-75) > 0.001 {
		t.Fatalf("p50=%v over=%v", p, over)
	}
	// Split: 50 fast (≤5ms), 50 slow (500-1000ms].
	h = make([]int64, appHistLen)
	h[0], h[7] = 50, 50
	if p, _ := appPercentile(h, 0.25); p <= 0 || p > 5 {
		t.Fatalf("p25=%v", p)
	}
	if p, _ := appPercentile(h, 0.9); p < 500 || p > 1000 {
		t.Fatalf("p90=%v", p)
	}
	// Open-ended bucket is reported as the top bound with over=true, never invented.
	h = make([]int64, appHistLen)
	h[11] = 10
	if p, over := appPercentile(h, 0.99); !over || p != 10000 {
		t.Fatalf("p99=%v over=%v", p, over)
	}
	if p, over := appPercentile(make([]int64, appHistLen), 0.5); p != 0 || over {
		t.Fatal("empty histogram")
	}
	if p, _ := appPercentile(nil, 0.5); p != 0 {
		t.Fatal("nil histogram")
	}
}

func TestAppChooseStep(t *testing.T) {
	now := time.Now()
	cases := []struct {
		d    time.Duration
		req  int
		want int
	}{
		{time.Hour, 0, 60}, {6 * time.Hour, 0, 300}, {48 * time.Hour, 0, 1800}, {7 * 24 * time.Hour, 0, 3600},
		{60 * 24 * time.Hour, 0, 21600}, {time.Hour, 10, 60}, {time.Hour, 130, 120}, {time.Hour, 999999, 86400},
	}
	for _, c := range cases {
		if got := appChooseStep(now.Add(-c.d), now, c.req); got != c.want {
			t.Fatalf("range %v req %d: got %d want %d", c.d, c.req, got, c.want)
		}
	}
	// A tiny step over a long range is widened so the series never exceeds the cap.
	if s := appChooseStep(now.Add(-30*24*time.Hour), now, 60); float64(30*24*3600)/float64(s) > appMaxSeriesPts {
		t.Fatalf("step %d allows too many points", s)
	}
}

func TestAppParseRange(t *testing.T) {
	mk := func(q string) *http.Request { return httptest.NewRequest("GET", "/x?"+q, nil) }
	if _, _, msg := appParseRange(mk("")); msg != "" {
		t.Fatal(msg)
	}
	if _, _, msg := appParseRange(mk("from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z")); msg == "" {
		t.Fatal("reversed range must be rejected")
	}
	if _, _, msg := appParseRange(mk("from=2026-01-01T00:00:00Z&to=2026-06-01T00:00:00Z")); msg == "" {
		t.Fatal("range over 90 days must be rejected")
	}
}

func appGet(h http.HandlerFunc, url string, pv map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", url, nil)
	for k, v := range pv {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// Integration: runs only when OW_TEST_PG_DSN points at a scratch Postgres.
func TestAppREADAPIsIntegration(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE IF EXISTS service_declared_routes, service_openapi, app_traces, app_route_stats, app_baselines, service_versions, service_routes,
		service_edges, service_instances, services, service_settings, app_edge_stats, app_client_stats, app_service_merges, service_route_params CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"../../../../backend/internal/store/migrations/030_app_services.sql", "../../../../backend/internal/store/migrations/031_app_edge_client_stats.sql", "../../../../backend/internal/store/migrations/032_app_route_params.sql", "../../../../backend/internal/store/migrations/035_app_declared_api.sql", "../store/migrations/060_app_service_settings.sql", "../store/migrations/064_app_db_statement_mode.sql"} {
		b, _ := os.ReadFile(f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Minute)
	var sid, other int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('api','prod','otel',$1,$1) RETURNING id`, now.Add(-time.Hour)).Scan(&sid)
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('quiet','prod','otel',$1,$1) RETURNING id`, now.Add(-time.Hour)).Scan(&other)
	for _, r := range [][2]string{{"/orders/{id}", "GET"}, {"/login", "POST"}, {"/never", "GET"}} {
		raw.Exec(`INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,$2,$3,$4,$4)`, sid, r[0], r[1], now.Add(-time.Hour))
	}
	// Two minutes, two routes. /orders: 10 calls (hist bucket 3: 25-50ms); /login: 4 calls, 2×401, 1×5xx.
	ins := func(min time.Time, route, method string, calls, errs, s2, s4, s429, s5 int, hist string) {
		if _, err := raw.Exec(`INSERT INTO app_route_stats (minute, service_id, route, method, calls, errors, status_2xx, status_401_403, status_429, status_5xx, duration_buckets)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)`, min, sid, route, method, calls, errs, s2, s4, s429, s5, hist); err != nil {
			t.Fatal(err)
		}
	}
	m1, m2 := now.Add(-3*time.Minute), now.Add(-2*time.Minute)
	ins(m1, "/orders/{id}", "GET", 6, 0, 6, 0, 0, 0, "[0,0,0,6,0,0,0,0,0,0,0,0]")
	ins(m2, "/orders/{id}", "GET", 4, 0, 4, 0, 0, 0, "[0,0,0,4,0,0,0,0,0,0,0,0]")
	ins(m1, "/login", "POST", 4, 1, 1, 2, 0, 1, "[0,0,0,0,0,0,0,0,0,0,0,4]")
	db := &store.DB{DB: raw}
	pv := map[string]string{"id": strconv.FormatInt(sid, 10)}
	from, to := now.Add(-time.Hour).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339)
	rng := "?from=" + from + "&to=" + to

	// RED series, all routes.
	rec := appGet(appHandleREDSeries(db, nil), "/x"+rng+"&step=60", pv)
	var red struct {
		Step   int           `json:"step_seconds"`
		Series []appREDPoint `json:"series"`
		Totals appREDTotals  `json:"totals"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &red)
	if rec.Code != 200 || red.Step != 60 || len(red.Series) != 2 || red.Totals.Calls != 14 || red.Totals.Errors != 1 ||
		red.Totals.Status4013 != 2 || red.Totals.Status5xx != 1 || red.Totals.Status2xx != 11 {
		t.Fatalf("series: %d %s", rec.Code, rec.Body.String())
	}
	if !red.Series[0].T.Equal(m1) || red.Series[0].Calls != 10 || red.Series[1].Calls != 4 {
		t.Fatalf("buckets: %+v", red.Series)
	}
	if !red.Totals.OverRange || red.Totals.P99 != 10000 { // 4 of 14 calls are in the open-ended bucket
		t.Fatalf("p99 must flag over-range: %+v", red.Totals)
	}
	if red.Totals.P50 < 25 || red.Totals.P50 > 50 {
		t.Fatalf("p50=%v", red.Totals.P50)
	}
	// Wider step merges both minutes.
	rec = appGet(appHandleREDSeries(db, nil), "/x"+rng+"&step=3600", pv)
	_ = json.Unmarshal(rec.Body.Bytes(), &red)
	if len(red.Series) < 1 || red.Totals.Calls != 14 {
		t.Fatalf("hourly: %s", rec.Body.String())
	}
	// Route + method filter.
	rec = appGet(appHandleREDSeries(db, nil), "/x"+rng+"&route=/orders/%7Bid%7D&method=get", pv)
	red.Totals, red.Series = appREDTotals{}, nil // omitempty fields must not leak from the previous decode
	_ = json.Unmarshal(rec.Body.Bytes(), &red)
	if red.Totals.Calls != 10 || red.Totals.OverRange || red.Totals.P95 > 50 {
		t.Fatalf("filtered: %s", rec.Body.String())
	}
	if rec := appGet(appHandleREDSeries(db, nil), "/x?from=bad", map[string]string{"id": "x"}); rec.Code != 400 {
		t.Fatalf("bad id: %d", rec.Code)
	}

	raw.Exec(`INSERT INTO service_route_params (service_id, route, method, name, requests, first_seen, last_seen) VALUES
		($1,'/login','POST','user',7,$2,$2), ($1,'/login','POST','password_hint',2,$2,$2)`, sid, now.Add(-time.Minute))

	// Routes table: includes a known route with no traffic in range.
	rec = appGet(appHandleRoutes(db, nil), "/x"+rng, pv)
	var rt struct {
		Routes []appRouteRow `json:"routes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &rt)
	if rec.Code != 200 || len(rt.Routes) != 3 || rt.Routes[0].Route != "/orders/{id}" || rt.Routes[0].Stats.Calls != 10 || !rt.Routes[0].Active {
		t.Fatalf("routes: %s", rec.Body.String())
	}
	var login, never *appRouteRow
	for i := range rt.Routes {
		switch rt.Routes[i].Route {
		case "/login":
			login = &rt.Routes[i]
		case "/never":
			never = &rt.Routes[i]
		}
	}
	if login == nil || login.PayloadReview != "needs_review" || len(login.Params) != 2 || login.Params[0].Name != "user" || login.Params[0].Requests != 7 ||
		never == nil || never.PayloadReview != "" || len(never.Params) != 0 {
		t.Fatalf("parameter names and review state: %+v %+v", login, never)
	}
	if login == nil || login.Stats.ErrorRate != 0.25 || !login.Stats.OverRange || never == nil || never.Active || never.Stats.Calls != 0 {
		t.Fatalf("login/never: %+v %+v", login, never)
	}

	// Service list carries a RED summary for the range; the quiet service has none.
	rec = appGet(appHandleListServices(db, nil), "/x"+rng, nil)
	var list struct {
		Services []appServiceRow `json:"services"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	var gotAPI, gotQuiet *appServiceRow
	for i := range list.Services {
		if list.Services[i].ID == sid {
			gotAPI = &list.Services[i]
		} else if list.Services[i].ID == other {
			gotQuiet = &list.Services[i]
		}
	}
	if gotAPI == nil || gotAPI.Red == nil || gotAPI.Red.Calls != 14 || gotAPI.LearningCalls != 14 || gotQuiet == nil || gotQuiet.Red != nil || gotQuiet.LearningCalls != 0 {
		t.Fatalf("list red: %s", rec.Body.String())
	}

	// Edges: one old, one new inside the range.
	raw.Exec(`INSERT INTO service_edges (src_service, dst_kind, dst_name, source, calls, first_seen, last_seen) VALUES
		($1,'database','pg:5432','otel',50,$2,$3), ($1,'external','api.stripe.com','otel',5,$3,$3)`, sid, now.Add(-30*24*time.Hour), now.Add(-time.Minute))
	rec = appGet(appHandleServiceEdges(db, nil), "/x"+rng, pv)
	var ed struct {
		Edges []struct {
			DstName string `json:"dst_name"`
			New     bool   `json:"new"`
		} `json:"edges"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ed)
	if len(ed.Edges) != 2 || ed.Edges[0].DstName != "pg:5432" || ed.Edges[0].New || !ed.Edges[1].New {
		t.Fatalf("edges: %s", rec.Body.String())
	}

	// Traces: list filters + detail.
	tr := func(id string, ago time.Duration, dur int, route, status, reason string) {
		if _, err := raw.Exec(`INSERT INTO app_traces (trace_id, service_id, agent_id, started, duration_ms, root_route, status, keep_reason, span_count, spans)
			VALUES ($1,$2,'a1',$3,$4,$5,$6,$7,2,'[{"name":"GET /x"}]')`, id, sid, now.Add(-ago), dur, route, status, reason); err != nil {
			t.Fatal(err)
		}
	}
	tr("aa01", time.Minute, 20, "GET /orders/{id}", "ok", "baseline")
	tr("aa02", 2*time.Minute, 1800, "GET /orders/{id}", "ok", "slow")
	tr("aa03", 3*time.Minute, 15, "POST /login", "error", "error")
	count := func(q string) int {
		rec := appGet(appHandleListTraces(db, nil), "/x"+rng+q, nil)
		var o struct {
			Traces []appTraceRow `json:"traces"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &o)
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", q, rec.Code, rec.Body.String())
		}
		for _, x := range o.Traces {
			if len(x.Spans) != 0 || x.Service != "api" {
				t.Fatalf("list must not carry spans and must name the service: %+v", x)
			}
		}
		return len(o.Traces)
	}
	if count("") != 3 || count("&reason=slow") != 1 || count("&status=error") != 1 || count("&min_duration_ms=100") != 1 ||
		count("&route=login") != 1 || count("&service_id="+strconv.FormatInt(other, 10)) != 0 || count("&limit=2") != 2 {
		t.Fatal("trace filters")
	}
	if rec := appGet(appHandleListTraces(db, nil), "/x"+rng+"&reason=bogus", nil); rec.Code != 400 {
		t.Fatalf("bad reason: %d", rec.Code)
	}
	rec = appGet(appHandleGetTrace(db, nil), "/x", map[string]string{"trace_id": "AA02"})
	var one appTraceRow
	_ = json.Unmarshal(rec.Body.Bytes(), &one)
	if rec.Code != 200 || one.TraceID != "aa02" || one.KeepReason != "slow" || len(one.Spans) == 0 {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body.String())
	}
	if rec := appGet(appHandleGetTrace(db, nil), "/x", map[string]string{"trace_id": "ffff"}); rec.Code != 404 {
		t.Fatalf("missing: %d", rec.Code)
	}
	if rec := appGet(appHandleGetTrace(db, nil), "/x", map[string]string{"trace_id": "x'; DROP TABLE services;--"}); rec.Code != 400 {
		t.Fatalf("hostile id: %d", rec.Code)
	}
}
