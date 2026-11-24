package api

import (
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestAppEnrichSpansCriticalPath(t *testing.T) {
	raw := json.RawMessage(`[
	 {"span_id":"r","name":"GET","start_ms":0,"dur_ms":100},
	 {"span_id":"a","parent_id":"r","start_ms":1,"dur_ms":30},
	 {"span_id":"b","parent_id":"r","start_ms":35,"dur_ms":60},
	 {"span_id":"c","parent_id":"b","start_ms":36,"dur_ms":50,"self_ms":50}]`)
	out, path := appEnrichSpans(raw)
	if len(path) != 3 || path[0] != "r" || path[1] != "b" || path[2] != "c" {
		t.Fatalf("path: %v", path)
	}
	var spans []map[string]any
	_ = json.Unmarshal(out, &spans)
	if spans[0]["self_ms"] != float64(10) { // 100 - 30 - 60, derived because an old agent sent no self_ms
		t.Fatalf("self_ms: %v", spans[0]["self_ms"])
	}
	if spans[3]["self_ms"] != float64(50) {
		t.Fatalf("an agent-supplied self_ms must be kept: %v", spans[3]["self_ms"])
	}
	if o, p := appEnrichSpans(json.RawMessage(`not json`)); string(o) != "not json" || p != nil {
		t.Fatal("bad input must pass through")
	}
}

func TestAppDiagnosisAPI(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE IF EXISTS app_traces, app_route_stats, app_baselines, service_versions, service_routes,
		service_edges, service_instances, services, service_settings, app_edge_stats, app_client_stats, app_service_merges,
		service_route_params, service_declared_routes, service_openapi, app_payloads, app_route_payload_policy, app_route_payload_policy_log,
		app_route_children, app_db_stats, app_route_n1 CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"030_app_services.sql", "031_app_edge_client_stats.sql", "032_app_route_params.sql", "033_app_payloads.sql", "034_app_payloads_latency.sql", "035_app_declared_api.sql", "036_app_diagnosis.sql"} {
		b, _ := os.ReadFile("../../../../backend/internal/store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	for _, f := range []string{"060_app_service_settings.sql", "063_app_route_payload_policy.sql", "066_app_db_statement_mode.sql", "067_app_error_message_mode.sql", "068_app_sampling.sql", "069_app_slo.sql"} {
		b, _ := os.ReadFile("../store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Minute)
	var sid int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('orders','prod','otel',$1,$1) RETURNING id`, now.Add(-time.Hour)).Scan(&sid)
	raw.Exec(`INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,'/orders/:id','GET',$2,$2)`, sid, now)
	raw.Exec(`INSERT INTO app_route_stats (minute, service_id, route, method, calls) VALUES ($1,$2,'/orders/:id','GET',10)`, now, sid)
	for i, c := range []struct {
		kind, target, name string
		calls              int
		ms                 float64
	}{{"db", "postgresql", "SELECT orders", 10, 300}, {"http", "payments", "POST /charge/?", 10, 900}, {"db", "postgresql", "SELECT items", 100, 200}, {"http", "mail", "POST /send", 2, 20}} {
		_ = i
		raw.Exec(`INSERT INTO app_route_children (minute, service_id, route, method, kind, target, name, calls, total_ms) VALUES ($1,$2,'/orders/:id','GET',$3,$4,$5,$6,$7)`, now, sid, c.kind, c.target, c.name, c.calls, c.ms)
	}
	raw.Exec(`INSERT INTO app_route_n1 (minute, service_id, route, method, count) VALUES ($1,$2,'/orders/:id','GET',3)`, now, sid)
	raw.Exec(`INSERT INTO app_db_stats (minute, service_id, system, operation, tbl, fingerprint, text, calls, errors, total_ms, duration_buckets) VALUES
		($1,$2,'postgresql','SELECT','items','abc','select * from items where order_id = ?',100,1,200,'[0,0,100,0,0,0,0,0,0,0,0,0]'),
		($1,$2,'postgresql','SELECT','orders','','',10,0,300,'[0,0,0,0,0,0,10,0,0,0,0,0]')`, now, sid)

	db := &store.DB{DB: raw}
	pv := map[string]string{"id": strconv.FormatInt(sid, 10)}
	rng := "?from=" + now.Add(-time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Minute).Format(time.RFC3339)

	rec := appGet(appHandleRoutes(db, nil), "/x"+rng, pv)
	var rt struct {
		Routes []appRouteRow `json:"routes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &rt)
	if rec.Code != 200 || len(rt.Routes) != 1 {
		t.Fatalf("routes: %d %s", rec.Code, rec.Body.String())
	}
	r := rt.Routes[0]
	if len(r.TopChildren) != 3 || r.TopChildren[0].Name != "POST /charge/?" || r.TopChildren[1].Name != "SELECT orders" || r.NPlusOneCount != 3 {
		t.Fatalf("diagnosis on route: %+v n1=%d", r.TopChildren, r.NPlusOneCount)
	}
	if r.TopChildren[0].AvgMs != 90 {
		t.Fatalf("avg: %v", r.TopChildren[0].AvgMs)
	}

	rec = appGet(appHandleQueries(db, nil), "/x"+rng, pv)
	var qs struct {
		Queries []appQueryRow `json:"queries"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &qs)
	if rec.Code != 200 || len(qs.Queries) != 2 || qs.Queries[0].Table != "orders" || qs.Queries[1].Text == "" || qs.Queries[1].P95Ms <= 0 {
		t.Fatalf("queries: %d %s", rec.Code, rec.Body.String())
	}
	rec = appGet(appHandleQueries(db, nil), "/x"+rng+"&sort=calls", pv)
	_ = json.Unmarshal(rec.Body.Bytes(), &qs)
	if qs.Queries[0].Table != "items" {
		t.Fatalf("sort by calls: %+v", qs.Queries[0])
	}
	if rec := appGet(appHandleQueries(db, nil), "/x?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z", pv); rec.Code != 400 {
		t.Fatalf("range check: %d", rec.Code)
	}
}
