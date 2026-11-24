package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestAppO07Saturation(t *testing.T) {
	fx := appNewFx(t)
	fx.d.metrics = []appMetricAgg{
		{Instance: "i-1", Name: "nodejs.eventloop.delay.p99", Unit: "s", Minutes: 8, Avg: 0.35, Max: 0.6},
		{Instance: "i-1", Name: "db.client.connection.count", Attr: "db.client.connection.pool.name=main,state=used", Minutes: 8, Avg: 10, Max: 10},
		{Instance: "i-1", Name: "db.client.connection.max", Attr: "db.client.connection.pool.name=main", Minutes: 8, Avg: 10, Max: 10},
		{Instance: "i-1", Name: "v8js.memory.heap.used", Attr: "v8js.heap.space.name=old_space", Minutes: 8, Avg: 95, Max: 99},
		{Instance: "i-1", Name: "v8js.memory.heap.limit", Attr: "v8js.heap.space.name=old_space", Minutes: 8, Avg: 100, Max: 100},
	}
	fx.scan()
	got := fx.pos("APM-O07", 3)
	all := ""
	for _, g := range got {
		all += g.F.Detail
	}
	for _, w := range []string{"event loop delay p99 is 350 ms", "main connection pool is 100%", "heap is 95%"} {
		if !strings.Contains(all, w) {
			t.Fatalf("missing %q in %s", w, all)
		}
	}
}

func TestAppO07Quiet(t *testing.T) {
	// healthy values
	h := appNewFx(t)
	h.d.metrics = []appMetricAgg{
		{Instance: "i-1", Name: "nodejs.eventloop.delay.p99", Unit: "s", Minutes: 8, Avg: 0.01, Max: 0.05},
		{Instance: "i-1", Name: "process.cpu.utilization", Attr: "state=user", Minutes: 8, Avg: 0.2, Max: 0.4},
	}
	h.scan()
	h.neg("APM-O07")
	// saturated but too little data
	s := appNewFx(t)
	s.d.metrics = []appMetricAgg{{Instance: "i-1", Name: "nodejs.eventloop.delay.p99", Unit: "s", Minutes: 1, Avg: 0.9, Max: 0.9}}
	s.scan()
	s.neg("APM-O07")
}

func TestAppMetricsAPI(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE IF EXISTS app_metrics, service_instances, services CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"030_app_services.sql", "039_app_metrics.sql"} {
		b, _ := os.ReadFile("../../../../backend/internal/store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Minute)
	var sid int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('api','prod','otel',$1,$1) RETURNING id`, now).Scan(&sid)
	for i := 0; i < 4; i++ {
		raw.Exec(`INSERT INTO app_metrics VALUES ($1,$2,'i-1','process.cpu.utilization','state=user','1','asserted',$3,0.1,0.9,$3,1)`, now.Add(-time.Duration(i)*time.Minute), sid, 0.2*float64(i+1))
	}
	db := &store.DB{DB: raw}
	pv := map[string]string{"id": strconv.FormatInt(sid, 10)}
	rng := "?from=" + now.Add(-time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Minute).Format(time.RFC3339)
	rec := appGet(appHandleMetrics(db, nil), "/x"+rng, pv)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"name":"process.cpu.utilization"`) || !strings.Contains(rec.Body.String(), `"last":0.2`) {
		t.Fatalf("catalog: %d %s", rec.Code, rec.Body.String())
	}
	rec = appGet(appHandleMetrics(db, nil), "/x"+rng+"&name=process.cpu.utilization&step=1", pv)
	var out struct {
		Series []struct{ Points []struct{ Avg float64 } } `json:"series"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || len(out.Series) != 1 || len(out.Series[0].Points) != 4 {
		t.Fatalf("points: %d %s", rec.Code, rec.Body.String())
	}
	if rec := appGet(appHandleMetrics(db, nil), "/x"+rng+"&name=secret.thing", pv); rec.Code != 400 {
		t.Fatalf("unknown name: %d", rec.Code)
	}
	if rt := appAttachRuntime(context.Background(), db, sid, now); rt["i-1"] == nil || rt["i-1"].CPUPct < 49 {
		t.Fatalf("runtime: %+v", rt["i-1"])
	}
}

func TestAppO06SlowQuery(t *testing.T) {
	fx := appNewFx(t)
	fx.d.qBase = []appQueryAgg{{System: "postgresql", Operation: "SELECT", Table: "orders", Calls: 5000, TotalMs: 50000},
		{System: "postgresql", Operation: "SELECT", Table: "users", Calls: 5000, TotalMs: 50000},
		{System: "postgresql", Operation: "UPDATE", Table: "stock", Calls: 5000, TotalMs: 50000}}
	fx.d.qCur = []appQueryAgg{{System: "postgresql", Operation: "SELECT", Table: "orders", Calls: 100, TotalMs: 5000}, // 50 ms vs 10 ms
		{System: "postgresql", Operation: "SELECT", Table: "users", Calls: 100, TotalMs: 1500},      // 15 vs 10: not twice
		{System: "postgresql", Operation: "UPDATE", Table: "stock", Calls: 5, TotalMs: 1000},        // too few calls
		{System: "postgresql", Operation: "SELECT", Table: "new_table", Calls: 100, TotalMs: 90000}} // no baseline
	fx.scan()
	got := fx.pos("APM-O06", 1)
	if !strings.Contains(got[0].F.Detail, "SELECT on orders") || !strings.Contains(got[0].F.Detail, "50 ms") {
		t.Fatal(got[0].F.Detail)
	}
	l := appNewFx(t) // learning: quiet
	l.setSvc(func(s *appSvc) { s.FirstSeen = appNow.Add(-2 * time.Hour) })
	l.d.qBase, l.d.qCur = fx.d.qBase, fx.d.qCur
	l.scan()
	l.neg("APM-O06")
}
