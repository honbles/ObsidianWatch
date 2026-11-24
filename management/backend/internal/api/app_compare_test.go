package api

import (
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestAppO12PostDeploy(t *testing.T) {
	fx := appNewFx(t)
	fx.d.deploys = []appDeploy{{Version: "1.5.0", FirstSeen: appNow.Add(-15 * time.Minute)}}
	fx.d.preTot = appWindowTotals{Calls: 10000, Errors: 100, P95Ms: 100} // 1%
	fx.d.postTot = appWindowTotals{Calls: 500, Errors: 50, P95Ms: 400}   // 10%, 4x slower
	fx.scan()
	got := fx.pos("APM-O12", 1)
	if !strings.Contains(got[0].F.Detail, "1.5.0") || !strings.Contains(got[0].F.Detail, "error rate 10.0%") || !strings.Contains(got[0].F.Detail, "p95 400 ms") {
		t.Fatal(got[0].F.Detail)
	}
	neg := func(mut func(*appFakeData)) {
		t.Helper()
		q := appNewFx(t)
		q.d.deploys = []appDeploy{{Version: "1.5.0", FirstSeen: appNow.Add(-15 * time.Minute)}}
		q.d.preTot = appWindowTotals{Calls: 10000, Errors: 100, P95Ms: 100}
		q.d.postTot = appWindowTotals{Calls: 500, Errors: 5, P95Ms: 105} // healthy
		mut(q.d)
		q.scan()
		q.neg("APM-O12")
	}
	neg(func(*appFakeData) {})
	neg(func(d *appFakeData) { d.postTot = appWindowTotals{Calls: 20, Errors: 20, P95Ms: 900} })                // too little traffic
	neg(func(d *appFakeData) { d.deploys[0].FirstSeen = appNow.Add(-2 * time.Minute); d.postTot.Errors = 400 }) // too soon to judge
	neg(func(d *appFakeData) { d.deploys[0].FirstSeen = appNow.Add(-5 * time.Hour); d.postTot.Errors = 400 })   // outside the watch window
}

func TestAppCompareAPI(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE IF EXISTS app_traces, app_route_stats, app_baselines, service_versions, service_routes, service_edges, service_instances, services, error_group_hours, error_groups CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"030_app_services.sql", "038_app_percentile_sketch.sql", "037_app_errors.sql"} {
		b, _ := os.ReadFile("../../../../backend/internal/store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Minute)
	var sid int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('api','prod','otel',$1,$1) RETURNING id`, now.Add(-48*time.Hour)).Scan(&sid)
	raw.Exec(`INSERT INTO service_versions (service_id, version, first_seen, last_seen) VALUES ($1,'1.0',$2,$3),($1,'1.1',$3,$4)`, sid, now.Add(-48*time.Hour), now.Add(-2*time.Hour), now)
	raw.Exec(`INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,'/new','GET',$2,$2)`, sid, now.Add(-time.Hour))
	h := func(i int, n int) string { b := make([]int, 12); b[i] = n; j, _ := json.Marshal(b); return string(j) }
	raw.Exec(`INSERT INTO app_route_stats (minute, service_id, route, method, calls, errors, duration_buckets) VALUES ($1,$2,'/o','GET',100,1,$3::jsonb)`, now.Add(-10*time.Hour), sid, h(2, 100))
	raw.Exec(`INSERT INTO app_route_stats (minute, service_id, route, method, calls, errors, duration_buckets) VALUES ($1,$2,'/o','GET',100,20,$3::jsonb)`, now.Add(-time.Hour), sid, h(8, 100))
	db := &store.DB{DB: raw}
	pv := map[string]string{"id": strconv.FormatInt(sid, 10)}
	rec := appGet(appHandleCompare(db, nil), "/x?a=1.0&b=1.1", pv)
	var out struct {
		A, B struct {
			Calls     int64   `json:"calls"`
			ErrorRate float64 `json:"error_rate"`
			P95       float64 `json:"p95_ms"`
		}
		Routes    []struct{ Route string }
		NewRoutes []string `json:"new_routes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || out.A.Calls != 100 || out.B.Calls != 100 || out.B.ErrorRate != 0.2 || out.B.P95 <= out.A.P95 || len(out.Routes) != 1 || len(out.NewRoutes) != 1 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec := appGet(appHandleCompare(db, nil), "/x?a=1.0&b=nope", pv); rec.Code != 404 {
		t.Fatalf("unknown version: %d", rec.Code)
	}
	if rec := appGet(appHandleCompare(db, nil), "/x?a=1.0", pv); rec.Code != 400 {
		t.Fatalf("one side: %d", rec.Code)
	}
}
