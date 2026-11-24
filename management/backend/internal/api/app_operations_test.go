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

func runsEvery(step time.Duration, n int, last time.Time) []time.Time {
	out := make([]time.Time, n)
	for i := range out {
		out[i] = last.Add(-time.Duration(n-1-i) * step)
	}
	return out
}

func TestAppO10JobMissed(t *testing.T) {
	// a job that ran every 10 minutes, last 35 minutes ago (3.5 intervals)
	last := appNow.Add(-35 * time.Minute)
	fx := appNewFx(t)
	fx.d.jobs = []appJobHistory{{Name: "sync-inventory", Minutes: runsEvery(10*time.Minute, 20, last), LastRun: last}}
	fx.scan()
	got := fx.pos("APM-O10", 1)
	if !strings.Contains(got[0].F.Detail, "sync-inventory") || !strings.Contains(got[0].F.Detail, "about every 10 minutes") {
		t.Fatal(got[0].F.Detail)
	}
	neg := func(j appJobHistory) {
		t.Helper()
		q := appNewFx(t)
		q.d.jobs = []appJobHistory{j}
		q.scan()
		q.neg("APM-O10")
	}
	l2 := appNow.Add(-25 * time.Minute) // 2.5 intervals: not yet
	neg(appJobHistory{Name: "a", Minutes: runsEvery(10*time.Minute, 20, l2), LastRun: l2})
	neg(appJobHistory{Name: "b", Minutes: runsEvery(10*time.Minute, 3, last), LastRun: last}) // too little history
	old := appNow.Add(-10 * 24 * time.Hour)                                                   // retired long ago
	neg(appJobHistory{Name: "c", Minutes: runsEvery(10*time.Minute, 20, old), LastRun: old})
}

func TestAppO11JobFailing(t *testing.T) {
	fx := appNewFx(t)
	fx.d.ops = []appOpAgg{{Kind: "job", Name: "billing", Runs: 10, Failures: 6}, {Kind: "consumer", Name: "kafka orders process", Runs: 100, Failures: 2},
		{Kind: "job", Name: "tiny", Runs: 2, Failures: 2}}
	fx.scan()
	got := fx.pos("APM-O11", 1)
	if !strings.Contains(got[0].F.Detail, "billing") || !strings.Contains(got[0].F.Detail, "6 of 10") {
		t.Fatal(got[0].F.Detail)
	}
	q := appNewFx(t)
	q.d.ops = []appOpAgg{{Kind: "job", Name: "ok", Runs: 10, Failures: 1}}
	q.scan()
	q.neg("APM-O11")
}

func TestAppOperationsAPI(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_, _ = raw.Exec(`DROP TABLE IF EXISTS app_operations, services CASCADE`)
	for _, f := range []string{"030_app_services.sql", "041_app_operations.sql"} {
		b, _ := os.ReadFile("../../../../backend/internal/store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Minute)
	var sid int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('worker','prod','otel',$1,$1) RETURNING id`, now).Scan(&sid)
	for i := 0; i < 6; i++ { // a job that runs every 10 minutes
		m := now.Add(-time.Duration(i*10) * time.Minute)
		raw.Exec(`INSERT INTO app_operations (minute, service_id, kind, name, runs, failures, duration_buckets, last_run) VALUES ($1,$2,'job','nightly',1,$3,'[0,0,0,1,0,0,0,0,0,0,0,0]',$1)`, m, sid, i%2)
	}
	db := &store.DB{DB: raw}
	pv := map[string]string{"id": strconv.FormatInt(sid, 10)}
	rng := "?from=" + now.Add(-3*time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Hour).Format(time.RFC3339)
	rec := appGet(appHandleOperations(db, nil), "/x"+rng, pv)
	var out struct {
		Operations []appOperationRow `json:"operations"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || len(out.Operations) != 1 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	o := out.Operations[0]
	if o.Runs != 6 || o.Failures != 3 || o.FailureRate != 0.5 || o.P95Ms <= 0 || o.EveryMin != 10 {
		t.Fatalf("%+v", o)
	}
}
