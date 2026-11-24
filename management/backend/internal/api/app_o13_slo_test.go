package api

import (
	"database/sql"
	"encoding/json"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

// 1000 requests a minute against a 99.9 % objective over 28 days: the budget is about 40,300 failures. Spending 5 %
// of it (about 2,000) in one hour is a burn of about 34x.
func TestAppO13FastBurn(t *testing.T) {
	fx := appNewFx(t)
	fx.d.sli = func(from, to time.Time, _ int) appSLICounts {
		d := to.Sub(from)
		calls := int64(d.Minutes() * 1000)
		if to.Before(appNow.Add(-2 * time.Hour)) { // older history is healthy
			return appSLICounts{Calls: calls}
		}
		return appSLICounts{Calls: calls, Errors: int64(float64(calls) * 0.0336)}
	}
	fx.scan()
	got := fx.pos("APM-O13", 1)
	if !strings.Contains(got[0].F.Detail, "availability") || !strings.Contains(got[0].F.Detail, "33.6x") {
		t.Fatal(got[0].F.Detail)
	}
}

func TestAppO13Quiet(t *testing.T) {
	steady := func(rate float64) func(time.Time, time.Time, int) appSLICounts {
		return func(from, to time.Time, _ int) appSLICounts {
			calls := int64(to.Sub(from).Minutes() * 1000)
			return appSLICounts{Calls: calls, Errors: int64(float64(calls) * rate)}
		}
	}
	// burning at 2x is within what the objective allows
	a := appNewFx(t)
	a.d.sli = steady(0.002)
	a.scan()
	a.neg("APM-O13")
	// a spike that is over: the long window burns, the short one does not
	b := appNewFx(t)
	b.d.sli = func(from, to time.Time, _ int) appSLICounts {
		calls := int64(to.Sub(from).Minutes() * 1000)
		if to.Sub(from) <= 30*time.Minute {
			return appSLICounts{Calls: calls}
		}
		return appSLICounts{Calls: calls, Errors: int64(float64(calls) * 0.05)}
	}
	b.scan()
	b.neg("APM-O13")
	// too little traffic to judge
	c := appNewFx(t)
	c.d.sli = func(from, to time.Time, _ int) appSLICounts { return appSLICounts{Calls: 20, Errors: 20} }
	c.scan()
	c.neg("APM-O13")
	// learning
	l := appNewFx(t)
	l.setSvc(func(s *appSvc) { s.FirstSeen = appNow.Add(-2 * time.Hour) })
	l.d.sli = steady(0.5)
	l.scan()
	l.neg("APM-O13")
}

func TestAppSLODefaultsAndSlow(t *testing.T) {
	s := appDefaultSettings()
	r := appResolveSLO(s)
	if r.AvailabilityPct != 99.9 || r.WindowDays != 28 || r.LatencyTargetMs != 0 {
		t.Fatalf("%+v", r)
	}
	b, lat := 2.0, 300
	s.ErrorBudgetPct, s.LatencyTargetMs = &b, &lat
	if r = appResolveSLO(s); r.AvailabilityPct != 98 || r.LatencyTargetMs != 300 {
		t.Fatalf("budget and target are the default objective: %+v", r)
	}
	bad := 100.0
	if appValidSLO(appSLO{AvailabilityPct: &bad}) == "" || appValidSLO(appSLO{WindowDays: 14}) == "" {
		t.Fatal("invalid SLO accepted")
	}
	// 100 requests in the 100-250 ms bucket, target 175: half are over; the 25-50 ms ones are under
	h := make([]int64, 12)
	h[5], h[3] = 100, 50
	if got := appSlowOf(h, 175); math.Abs(got-50) > 0.01 {
		t.Fatalf("slow: %v", got)
	}
}

func TestAppSLOAPI(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_, _ = raw.Exec(`DROP TABLE IF EXISTS app_route_stats, service_settings, services CASCADE`)
	for _, f := range []string{"../../../../backend/internal/store/migrations/030_app_services.sql", "../../../../backend/internal/store/migrations/038_app_percentile_sketch.sql",
		"../store/migrations/060_app_service_settings.sql", "../store/migrations/066_app_db_statement_mode.sql", "../store/migrations/067_app_error_message_mode.sql",
		"../store/migrations/068_app_sampling.sql", "../store/migrations/069_app_slo.sql"} {
		b, _ := os.ReadFile(f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Minute)
	var sid int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('api','prod','otel',$1,$1) RETURNING id`, now.Add(-30*24*time.Hour)).Scan(&sid)
	raw.Exec(`INSERT INTO service_settings (service_id, latency_target_ms, slo) VALUES ($1, 100, '{"availability_target_pct":99,"latency_target_pct":90}')`, sid)
	// 10,000 requests, 50 failures (a budget of 100), half of the requests in 100-250 ms: well over a 100 ms target
	raw.Exec(`INSERT INTO app_route_stats (minute, service_id, route, method, calls, errors, duration_buckets) VALUES ($1,$2,'/o','GET',10000,50,'[0,0,0,0,5000,5000,0,0,0,0,0,0]'::jsonb)`, now.Add(-2*time.Hour), sid)
	raw.Exec(`INSERT INTO app_route_stats (minute, service_id, route, method, calls, errors, duration_buckets) VALUES ($1,$2,'/o','GET',100,20,'[0,0,0,0,100,0,0,0,0,0,0,0]'::jsonb)`, now.Add(-10*time.Minute), sid)
	db := &store.DB{DB: raw}
	pv := map[string]string{"id": strconv.FormatInt(sid, 10)}
	rec := appGet(appHandleSLO(db, nil), "/x", pv)
	var out struct {
		WindowDays int            `json:"window_days"`
		SLOs       []appSLOStatus `json:"slos"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || out.WindowDays != 28 || len(out.SLOs) != 2 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	a := out.SLOs[0]
	if a.Name != "availability" || a.Calls != 10100 || a.Bad != 70 || a.TargetPct != 99 || a.RemainingPct < 30 || a.RemainingPct > 31 || a.Burn1h <= 0 || a.ExhaustsAt == nil {
		t.Fatalf("availability: %+v", a)
	}
	l := out.SLOs[1]
	if l.Name != "latency" || l.LatencyTargetMs != 100 || l.Bad < 5000 || l.RemainingPct >= 0 {
		t.Fatalf("latency: %+v", l)
	}
}
