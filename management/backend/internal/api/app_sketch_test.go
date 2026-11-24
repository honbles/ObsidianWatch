package api

import (
	"database/sql"
	"encoding/json"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestAppPercentilesFromSketch(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE IF EXISTS error_group_hours, error_groups, app_traces, app_route_stats, app_baselines, service_versions, service_routes,
		service_edges, service_instances, services, service_settings, app_edge_stats, app_client_stats, app_service_merges,
		service_route_params, service_declared_routes, service_openapi, app_payloads, app_route_payload_policy, app_route_payload_policy_log,
		app_route_children, app_db_stats, app_route_n1 CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"../../../../backend/internal/store/migrations/030_app_services.sql", "../../../../backend/internal/store/migrations/031_app_edge_client_stats.sql",
		"../../../../backend/internal/store/migrations/032_app_route_params.sql", "../../../../backend/internal/store/migrations/035_app_declared_api.sql",
		"../../../../backend/internal/store/migrations/038_app_percentile_sketch.sql", "../store/migrations/060_app_service_settings.sql",
		"../store/migrations/066_app_db_statement_mode.sql", "../store/migrations/067_app_error_message_mode.sql", "../store/migrations/068_app_sampling.sql", "../store/migrations/069_app_slo.sql"} {
		b, _ := os.ReadFile(f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Minute)
	var sid int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('api','prod','otel',$1,$1) RETURNING id`, now.Add(-time.Hour)).Scan(&sid)
	raw.Exec(`INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,'/slow','GET',$2,$2)`, sid, now)
	raw.Exec(`INSERT INTO service_settings (service_id, latency_target_ms) VALUES ($1, 500)`, sid)

	// Three minutes of a log-uniform distribution from 1 ms to 60 s, one sketch per minute, histogram left empty
	// (the sketch is the source of truth here).
	r := rand.New(rand.NewSource(3))
	var all []float64
	for m := 0; m < 3; m++ {
		sk := newAppSketch()
		for i := 0; i < 4000; i++ {
			v := math.Exp(r.Float64()*math.Log(60000)) + 1
			all = append(all, v)
			sk.Add(v)
		}
		b, _ := json.Marshal(sk.Wire())
		raw.Exec(`INSERT INTO app_route_stats (minute, service_id, route, method, calls, duration_buckets, sketch, sketch_calls) VALUES ($1,$2,'/slow','GET',4000,'[0,0,0,0,0,0,0,0,0,0,0,4000]',$3::jsonb,4000)`,
			now.Add(-time.Duration(m+2)*time.Minute), sid, string(b))
	}
	sort.Float64s(all)
	want := all[int(0.99*float64(len(all)-1))]

	db := &store.DB{DB: raw}
	pv := map[string]string{"id": strconv.FormatInt(sid, 10)}
	rng := "?from=" + now.Add(-time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Minute).Format(time.RFC3339)
	red := func() (tot appREDTotals, method string) {
		t.Helper()
		rec := appGet(appHandleREDSeries(db, nil), "/x"+rng, pv)
		var out struct {
			Totals appREDTotals `json:"totals"`
			Method string       `json:"percentile_method"`
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("red: %d %s", rec.Code, rec.Body.String())
		}
		return out.Totals, out.Method
	}
	tot, method := red()
	if method != "sketch" || math.Abs(tot.P99-want)/want > 0.011 || tot.OverRange || tot.MaxMs < 50000 {
		t.Fatalf("sketch totals: method=%s p99=%.1f want %.1f over=%v max=%.0f", method, tot.P99, want, tot.OverRange, tot.MaxMs)
	}
	if tot.Apdex == nil || *tot.Apdex <= 0 || *tot.Apdex >= 1 {
		t.Fatalf("apdex: %v", tot.Apdex)
	}
	// Routes use the sketch too, and carry Apdex.
	rec := appGet(appHandleRoutes(db, nil), "/x"+rng, pv)
	var rt struct {
		Routes []appRouteRow `json:"routes"`
		Method string        `json:"percentile_method"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &rt)
	if rt.Method != "sketch" || len(rt.Routes) != 1 || math.Abs(rt.Routes[0].Stats.P99-want)/want > 0.011 || rt.Routes[0].Stats.Apdex == nil {
		t.Fatalf("routes: %s %+v", rt.Method, rt.Routes)
	}
	// A minute from an agent without sketches makes the range "mixed" and the histogram is used.
	raw.Exec(`INSERT INTO app_route_stats (minute, service_id, route, method, calls, duration_buckets) VALUES ($1,$2,'/slow','GET',10,'[10,0,0,0,0,0,0,0,0,0,0,0]')`, now.Add(-10*time.Minute), sid)
	if _, method = red(); method != "mixed" {
		t.Fatalf("mixed: %s", method)
	}
	// No sketches at all: histogram.
	raw.Exec(`UPDATE app_route_stats SET sketch = NULL, sketch_calls = 0`)
	if tot, method = red(); method != "histogram" || tot.MaxMs != 0 || tot.Apdex != nil {
		t.Fatalf("histogram: %s %+v", method, tot)
	}
}
