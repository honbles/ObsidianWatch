package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Integration test: runs only when OW_TEST_PG_DSN points at a scratch Postgres.
func appTestDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	// Scratch database: start clean so a schema change is always exercised.
	if _, err := raw.Exec(`DROP TABLE IF EXISTS app_traces, app_route_stats, app_baselines, service_versions, service_routes,
		service_edges, service_instances, services, service_settings, app_edge_stats, app_client_stats, service_route_params, app_payloads, app_route_payload_policy CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"migrations/002_agents.sql", "migrations/030_app_services.sql", "migrations/031_app_edge_client_stats.sql", "migrations/031_app_edge_client_stats.sql", "migrations/030_app_services.sql"} { // twice: idempotent
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if _, err := raw.Exec(`DELETE FROM agents`); err != nil {
		t.Fatal(err)
	}
	return &DB{DB: raw, logger: slog.Default()}
}

func TestAppIngestBatchIntegration(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	if h, o, ok, err := db.AppAgentInfo(ctx, "a1"); err != nil || !ok || h != "web-01" || o != "linux" {
		t.Fatalf("agent info: %q %q %v %v", h, o, ok, err)
	}
	if _, _, ok, _ := db.AppAgentInfo(ctx, "nope"); ok {
		t.Fatal("unknown agent must not be ok")
	}

	now := time.Now().UTC().Truncate(time.Minute)
	mk := func(version string, calls int64, pid int) AppBatch {
		return AppBatch{
			Instances: []AppInstance{{Service: "api", Environment: "prod", Source: "otel", InstanceRef: "i1", Version: version,
				PID: pid, ProcStart: now.Add(time.Duration(pid) * time.Second), Identity: "verified", Instrumented: true,
				Listen: json.RawMessage(`[8080]`), Language: "java"}},
			Routes: []AppRouteStat{{Service: "api", Environment: "prod", Method: "GET", Route: "/u/{id}", Minute: now,
				Calls: calls, Errors: 1, Status2xx: calls - 1, Status5xx: 1,
				DurBuckets: []int64{1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
			Edges:  []AppEdge{{Service: "api", Environment: "prod", DstKind: "database", DstName: "pg:5432", Source: "otel", Calls: 3}},
			Traces: []AppTrace{{TraceID: "t1", Service: "api", Environment: "prod", Started: now, KeepReason: "error", Spans: json.RawMessage(`[{"n":1}]`), SpanCount: 1}},
			Clients: []AppClientStat{
				{Service: "api", Environment: "prod", Route: "/login", Method: "POST", Minute: now, ClientIP: "203.0.113.9", PeerIP: "10.0.0.2",
					Failures: 4, Status40103: 3, Status5xx: 1},
				{Service: "api", Environment: "prod", Route: "/orders/{id}", Method: "GET", Minute: now, ClientIP: "203.0.113.9", ExcType: "java.sql.SQLSyntaxErrorException", Failures: 2, Status5xx: 2},
			},
			Notes: []AppServiceNote{{Service: "api", Environment: "prod", RouteOverflow: 2, TraceDrops: 1, ClientOverflow: 5}},
		}
	}
	kinds := func(r AppIngestResult) map[string]int {
		m := map[string]int{}
		for _, c := range r.Changes {
			m[c.Kind]++
		}
		return m
	}

	r1, err := db.AppIngestBatch(ctx, "a1", "web-01", mk("1.0", 5, 100), now)
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(r1); k["service"] != 1 || k["instance"] != 1 || k["version"] != 1 || k["edge"] != 1 {
		t.Fatalf("first batch changes: %+v", r1.Changes)
	}
	for _, c := range r1.Changes {
		if c.Kind != "instance" && !c.Baseline {
			t.Fatalf("first-ever %s must be baseline: %+v", c.Kind, c)
		}
	}
	// Same process again with a new version: no new instance, one real version change.
	r2, err := db.AppIngestBatch(ctx, "a1", "web-01", mk("1.1", 7, 100), now)
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(r2); len(r2.Changes) != 1 || k["version"] != 1 || r2.Changes[0].Baseline || r2.Changes[0].PrevVersion != "1.0" {
		t.Fatalf("second batch: %+v", r2.Changes)
	}
	// Restart (new pid/start, same instance_ref): new instance, old one stopped.
	r3, err := db.AppIngestBatch(ctx, "a1", "web-01", mk("1.1", 1, 200), now)
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(r3); len(r3.Changes) != 1 || k["instance"] != 1 || r3.Changes[0].InstanceID == 0 {
		t.Fatalf("restart: %+v", r3.Changes)
	}
	var stopped, live, instCount int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FILTER (WHERE stopped_at IS NOT NULL), COUNT(*) FILTER (WHERE stopped_at IS NULL) FROM service_instances`).Scan(&stopped, &live)
	_ = db.QueryRowContext(ctx, `SELECT instances FROM service_versions WHERE version='1.1'`).Scan(&instCount)
	if stopped != 1 || live != 1 || instCount != 1 {
		t.Fatalf("stopped=%d live=%d version_instances=%d", stopped, live, instCount)
	}

	var calls, c2xx, c5xx int64
	var hist string
	if err := db.QueryRowContext(ctx, `SELECT calls, status_2xx, status_5xx, duration_buckets::text FROM app_route_stats`).Scan(&calls, &c2xx, &c5xx, &hist); err != nil {
		t.Fatal(err)
	}
	if calls != 13 || c2xx != 10 || c5xx != 3 || hist != "[3, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]" {
		t.Fatalf("aggregation wrong: %d %d %d %s", calls, c2xx, c5xx, hist)
	}
	var edgeCalls int64
	var overflow, drops string
	var source string
	_ = db.QueryRowContext(ctx, `SELECT calls FROM service_edges`).Scan(&edgeCalls)
	_ = db.QueryRowContext(ctx, `SELECT source, attrs->>'route_overflow', attrs->>'trace_drops' FROM services`).Scan(&source, &overflow, &drops)
	var nTraces, nRoutes int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_traces`).Scan(&nTraces)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_routes`).Scan(&nRoutes)
	var cnt, fail, f401 int64
	var ph, co string
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_client_stats`).Scan(&cnt)
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(SUM(failures),0), COALESCE(SUM(status_401_403),0) FROM app_client_stats WHERE route='/login'`).Scan(&fail, &f401)
	_ = db.QueryRowContext(ctx, `SELECT peer_ip FROM app_client_stats WHERE route='/login'`).Scan(&ph)
	_ = db.QueryRowContext(ctx, `SELECT attrs->>'client_overflow' FROM services`).Scan(&co)
	if cnt != 2 || fail != 12 || f401 != 9 || ph != "10.0.0.2" || co != "15" { // 3 batches add: counters accumulate
		t.Fatalf("client stats: rows=%d failures=%d 401=%d peer=%q overflow=%s", cnt, fail, f401, ph, co)
	}
	var eh, ec int64
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*), SUM(calls) FROM app_edge_stats`).Scan(&eh, &ec)
	if eh != 1 || ec != 9 {
		t.Fatalf("hourly edge stats: rows=%d calls=%d", eh, ec)
	}
	if edgeCalls != 9 || nTraces != 1 || nRoutes != 1 || source != "otel" || overflow != "6" || drops != "3" {
		t.Fatalf("edge=%d traces=%d routes=%d source=%s overflow=%s drops=%s", edgeCalls, nTraces, nRoutes, source, overflow, drops)
	}
}

func TestAppRemoteConfigIntegration(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	// Management table not migrated yet: no error, no settings.
	if got, err := db.AppRemoteConfig(ctx); err != nil || len(got) != 0 {
		t.Fatalf("missing table must mean empty config: %v %v", got, err)
	}
	b, err := os.ReadFile("../../../management/backend/internal/store/migrations/060_app_service_settings.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	var id int64
	_ = db.QueryRowContext(ctx, `INSERT INTO services (name, environment, first_seen, last_seen) VALUES ('api','prod',NOW(),NOW()) RETURNING id`).Scan(&id)
	_, _ = db.ExecContext(ctx, `INSERT INTO services (name, environment, first_seen, last_seen) VALUES ('nosettings','prod',NOW(),NOW())`)
	if _, err := db.ExecContext(ctx, `INSERT INTO service_settings (service_id, store_client_ip, cleartext_users, latency_target_ms) VALUES ($1,'truncated',true,300)`, id); err != nil {
		t.Fatal(err)
	}
	got, err := db.AppRemoteConfig(ctx)
	if err != nil || len(got) != 1 || got[0].Service != "api" || got[0].StoreClientIP != "truncated" || !got[0].CleartextUsers || got[0].LatencyTargetMs != 300 {
		t.Fatalf("%+v %v", got, err)
	}
	_, _ = db.ExecContext(ctx, `DROP TABLE service_settings`)
}

func TestAppMergeDiscoveredIntoInstrumented(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../../management/backend/internal/store/migrations/060_app_service_settings.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().UTC().Truncate(time.Second)
	started := t0.Add(-time.Hour)
	// 1. The host sensor discovers a service under a name taken from its executable, three days ago.
	if _, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Instances: []AppInstance{{Service: "checkout-bin", Environment: "default", Source: "discovered",
		PID: 100, ProcStart: started, Identity: "verified", Listen: json.RawMessage(`[8080]`), Exe: "/usr/bin/java", Sensor: "procevent"}}}, t0.Add(-72*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var oldID int64
	_ = db.QueryRowContext(ctx, `SELECT id FROM services WHERE name='checkout-bin'`).Scan(&oldID)
	var src, sensor string
	_ = db.QueryRowContext(ctx, `SELECT s.source, i.attrs->>'sensor' FROM services s JOIN service_instances i ON i.service_id=s.id WHERE s.id=$1`, oldID).Scan(&src, &sensor)
	if src != "discovered" || sensor != "procevent" {
		t.Fatalf("discovered service: %s %s", src, sensor)
	}
	// ... with learned host baselines and an analyst's settings.
	_, _ = db.ExecContext(ctx, `INSERT INTO app_baselines (service_id, kind, key, samples, first_seen, updated) VALUES ($1,'destination','dns:db.internal',300,$2,$2)`, oldID, t0.Add(-70*time.Hour))
	_, _ = db.ExecContext(ctx, `INSERT INTO service_settings (service_id, exposure, criticality) VALUES ($1,'internet','critical')`, oldID)

	// 2. The same process starts reporting OpenTelemetry under the application's own name.
	res, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Instances: []AppInstance{{Service: "checkout", Environment: "prod", Source: "otel",
		PID: 100, ProcStart: started, Identity: "verified", Instrumented: true, InstanceRef: "i-1", Version: "1.0"}}}, t0)
	if err != nil {
		t.Fatal(err)
	}
	var svcCount, instCount, instrumented int
	var newID int64
	var first time.Time
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM services`).Scan(&svcCount)
	_ = db.QueryRowContext(ctx, `SELECT id, first_seen FROM services WHERE name='checkout'`).Scan(&newID, &first)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE instrumented) FROM service_instances WHERE service_id=$1`, newID).Scan(&instCount, &instrumented)
	if svcCount != 1 || instCount != 1 || instrumented != 1 {
		t.Fatalf("one instrumented service remains: services=%d instances=%d instrumented=%d changes=%+v", svcCount, instCount, instrumented, res.Changes)
	}
	if !first.Before(t0.Add(-71 * time.Hour)) {
		t.Fatalf("the learning clock must carry over from the discovered service: first_seen=%v", first)
	}
	var samples int64
	var expo string
	_ = db.QueryRowContext(ctx, `SELECT samples FROM app_baselines WHERE service_id=$1 AND key='dns:db.internal'`, newID).Scan(&samples)
	_ = db.QueryRowContext(ctx, `SELECT exposure FROM service_settings WHERE service_id=$1`, newID).Scan(&expo)
	if samples != 300 || expo != "internet" {
		t.Fatalf("baselines and settings move to the instrumented service: samples=%d exposure=%q", samples, expo)
	}
	// 2b. A sensor row for a process whose OpenTelemetry batch carries no start time is folded into the OpenTelemetry row, and the
	// sensor's details (container, unit, tier, ports) survive the next OpenTelemetry batch.
	if _, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Instances: []AppInstance{{Service: "juice-bin", Environment: "default", Source: "discovered",
		PID: 300, ProcStart: started.Add(2 * time.Second), Identity: "verified", Listen: json.RawMessage(`[3000]`), Exe: "/usr/bin/node", Sensor: "procevent",
		Unit: "juice.service", ContainerName: "juice", Image: "bkimminich/juice-shop"}}}, t0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // the second batch must not erase what the first one folded in
		if _, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Instances: []AppInstance{{Service: "juice-shop", Environment: "test", Source: "otel",
			PID: 300, Identity: "verified", Instrumented: true, InstanceRef: "j-1"}}}, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	var listen, unit, cname, img, tier string
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(i.listen::text), MAX(i.attrs->>'unit'), MAX(i.attrs->>'container_name'), MAX(i.attrs->>'image'), MAX(i.attrs->>'sensor')
		FROM service_instances i JOIN services s ON s.id = i.service_id WHERE s.name = 'juice-shop' AND i.pid = 300`).Scan(&n, &listen, &unit, &cname, &img, &tier)
	if n != 1 || listen != "[3000]" || unit != "juice.service" || cname != "juice" || img != "bkimminich/juice-shop" || tier != "procevent" {
		t.Fatalf("folded instance: n=%d listen=%s unit=%s container=%s image=%s tier=%s", n, listen, unit, cname, img, tier)
	}
	// 3. A discovered instance of an unrelated process is untouched, and merging works without the settings table.
	if _, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Instances: []AppInstance{{Service: "other-bin", Environment: "default", Source: "discovered", PID: 200, ProcStart: started, Identity: "verified"}}}, t0); err != nil {
		t.Fatal(err)
	}
	_, _ = db.ExecContext(ctx, `DROP TABLE service_settings`)
	if _, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Instances: []AppInstance{{Service: "other", Environment: "prod", Source: "otel", PID: 200, ProcStart: started, Identity: "verified", Instrumented: true}}}, t0); err != nil {
		t.Fatalf("a missing settings table must not fail the merge: %v", err)
	}
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM services`).Scan(&svcCount)
	if svcCount != 3 { // checkout, juice-shop and other
		t.Fatalf("services: %d", svcCount)
	}
}

func TestAppRouteParamsAccumulateAndAreCapped(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("migrations/032_app_route_params.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().UTC()
	send := func(ps ...AppRouteParam) {
		t.Helper()
		if _, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Params: ps}, t0); err != nil {
			t.Fatal(err)
		}
	}
	p := func(name string, n int64) AppRouteParam {
		return AppRouteParam{Service: "api", Environment: "prod", Route: "/rest/products/search", Method: "GET", Name: name, Count: n}
	}
	send(p("q", 2), p("sort", 1))
	send(p("q", 3))
	var q, sort int64
	var routes int
	_ = db.QueryRowContext(ctx, `SELECT requests FROM service_route_params WHERE name='q'`).Scan(&q)
	_ = db.QueryRowContext(ctx, `SELECT requests FROM service_route_params WHERE name='sort'`).Scan(&sort)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_routes WHERE route='/rest/products/search'`).Scan(&routes)
	if q != 5 || sort != 1 || routes != 1 {
		t.Fatalf("counts add up and the route exists: q=%d sort=%d routes=%d", q, sort, routes)
	}
	// The distinct names per route are capped; known names keep counting.
	var many []AppRouteParam
	for i := 0; i < AppMaxParamsPerRoute+50; i++ {
		many = append(many, p("n"+strconv.Itoa(i), 1))
	}
	send(many...)
	send(p("q", 1))
	var names int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_route_params`).Scan(&names)
	_ = db.QueryRowContext(ctx, `SELECT requests FROM service_route_params WHERE name='q'`).Scan(&q)
	if names != AppMaxParamsPerRoute || q != 6 {
		t.Fatalf("cap: %d names (want %d), q=%d", names, AppMaxParamsPerRoute, q)
	}
	// Nothing in the table can hold a value: only the name column exists.
	var cols int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_name='service_route_params' AND data_type='text'`).Scan(&cols)
	if cols != 3 { // route, method, name
		t.Fatalf("text columns: %d", cols)
	}
}

func TestAppPayloadsStoredOnlyUnderPolicy(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"migrations/032_app_route_params.sql", "migrations/033_app_payloads.sql", "migrations/034_app_payloads_latency.sql"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, string(b)); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = db.ExecContext(ctx, `DROP TABLE IF EXISTS app_route_payload_policy`)
	t0 := time.Now().UTC()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123"
	pl := AppPayload{Service: "api", Environment: "prod", Route: "/rest/products/search", Method: "GET", Time: t0, Status: 200,
		Params: map[string]string{"q": "apple", "sort": "asc", "password": "hunter2", "ref": jwt}}
	send := func() AppIngestResult {
		t.Helper()
		res, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Payloads: []AppPayload{pl}}, t0)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	count := func() (n int) {
		_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_payloads`).Scan(&n)
		return
	}
	// 1. No policy table at all: nothing is stored.
	if r := send(); r.Payloads != 0 || r.PayloadsRejected != 1 || count() != 0 {
		t.Fatalf("no policy table: %+v rows=%d", r, count())
	}
	// 2. A policy table, but no row for the route: still nothing.
	b, err := os.ReadFile("../../../management/backend/internal/store/migrations/063_app_route_payload_policy.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	if r := send(); r.Payloads != 0 || r.PayloadsRejected != 1 || count() != 0 {
		t.Fatalf("no policy row: %+v rows=%d", r, count())
	}
	// 3. The admin reviewed q, sort and password and masked sort: only q survives. password is always masked,
	// ref was not reviewed, and a credential-looking value is never stored.
	var sid int64
	_ = db.QueryRowContext(ctx, `SELECT id FROM services WHERE name='api'`).Scan(&sid)
	if _, err := db.ExecContext(ctx, `INSERT INTO app_route_payload_policy (service_id, route, method, reviewed_names, masked, reviewed_by)
		VALUES ($1,'/rest/products/search','GET','["q","sort","password"]','["sort"]','admin')`, sid); err != nil {
		t.Fatal(err)
	}
	if r := send(); r.Payloads != 1 || r.PayloadsRejected != 0 {
		t.Fatalf("reviewed route: %+v", r)
	}
	var params, withheld string
	_ = db.QueryRowContext(ctx, `SELECT params::text, withheld::text FROM app_payloads`).Scan(&params, &withheld)
	if params != `{"q": "apple"}` || withheld != `["password", "ref", "sort"]` {
		t.Fatalf("stored: params=%s withheld=%s", params, withheld)
	}
	var all string
	_ = db.QueryRowContext(ctx, `SELECT string_agg(params::text || withheld::text, '') FROM app_payloads`).Scan(&all)
	for _, leak := range []string{"hunter2", jwt, `"asc"`} {
		if strings.Contains(all, leak) {
			t.Fatalf("%q was stored", leak)
		}
	}
	// 4. The policy reaches the agent as an allow list, also for a service without saved settings.
	cfg, err := db.AppRemoteConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg) != 1 || !cfg[0].PolicyOnly || len(cfg[0].Payload) != 1 || strings.Join(cfg[0].Payload[0].Allow, ",") != "q" {
		t.Fatalf("remote config: %+v", cfg)
	}
}
