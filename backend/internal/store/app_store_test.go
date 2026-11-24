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
		service_edges, service_instances, services, service_settings, app_edge_stats, app_client_stats, service_route_params, app_payloads, app_route_payload_policy, error_group_hours, error_groups, app_route_children, app_db_stats, app_route_n1, app_metrics, app_sampling_stats, app_operations CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"migrations/002_agents.sql", "migrations/030_app_services.sql", "migrations/031_app_edge_client_stats.sql", "migrations/031_app_edge_client_stats.sql", "migrations/030_app_services.sql", "migrations/038_app_percentile_sketch.sql"} { // twice: idempotent
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
	for _, f := range []string{"migrations/032_app_route_params.sql", "migrations/035_app_declared_api.sql"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, string(b)); err != nil {
			t.Fatal(err)
		}
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
	if cols != 5 { // route, method, name, source, location: still no column that could hold a value
		t.Fatalf("text columns: %d", cols)
	}
}

func TestAppPayloadsStoredOnlyUnderPolicy(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"migrations/032_app_route_params.sql", "migrations/033_app_payloads.sql", "migrations/034_app_payloads_latency.sql", "migrations/035_app_declared_api.sql"} {
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

func TestAppRouteOtherStyle(t *testing.T) {
	for in, want := range map[string]string{
		"/users/{id}":             "/users/:id",
		"/users/:id/orders/:oid":  "/users/{id}/orders/{oid}",
		"/users/{id}/orders/:oid": "/users/:id/orders/:oid",
		"/plain/path":             "/plain/path",
		"/a/{b:int}":              "/a/{b:int}",
	} {
		if got := appRouteOtherStyle(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestAppObservedParamMergesWithDeclared(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"migrations/032_app_route_params.sql", "migrations/035_app_declared_api.sql"} {
		b, _ := os.ReadFile(f)
		if _, err := db.ExecContext(ctx, string(b)); err != nil {
			t.Fatal(err)
		}
	}
	t0 := time.Now().UTC()
	p := func(name string) AppRouteParam {
		return AppRouteParam{Service: "api", Environment: "prod", Route: "/Users", Method: "POST", Name: name, Count: 2}
	}
	if _, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Params: []AppRouteParam{p("email")}}, t0); err != nil {
		t.Fatal(err)
	}
	var sid int64
	_ = db.QueryRowContext(ctx, `SELECT id FROM services WHERE name='api'`).Scan(&sid)
	// the spec declares email and password; email already has traffic
	for _, n := range []string{"email", "password"} {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO service_route_params (service_id, route, method, name, requests, first_seen, last_seen, source, location)
			VALUES ($1,'/Users','POST',$2,0,NOW(),NOW(),'declared','body')
			ON CONFLICT (service_id, route, method, name) DO UPDATE SET source = CASE WHEN service_route_params.source='observed' THEN 'both' ELSE service_route_params.source END`, sid, n); err != nil {
			t.Fatal(err)
		}
	}
	// traffic now arrives for password (declared) and role (not declared)
	if _, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Params: []AppRouteParam{p("password"), p("role")}}, t0); err != nil {
		t.Fatal(err)
	}
	src := map[string]string{}
	rows, _ := db.QueryContext(ctx, `SELECT name, source FROM service_route_params WHERE service_id=$1`, sid)
	for rows.Next() {
		var n, s string
		_ = rows.Scan(&n, &s)
		src[n] = s
	}
	rows.Close()
	if src["email"] != "both" || src["password"] != "both" || src["role"] != "observed" {
		t.Fatalf("sources: %v", src)
	}
}

func TestAppDiagnosisIngestAccumulates(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("migrations/036_app_diagnosis.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	min := now.Truncate(time.Minute)
	send := func() {
		t.Helper()
		_, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{
			Children: []AppChild{{Service: "api", Environment: "prod", Route: "/x", Method: "GET", Minute: min, Kind: "db", Target: "postgresql", Name: "SELECT x", Calls: 2, TotalMs: 30}},
			Queries: []AppQuery{{Service: "api", Environment: "prod", Minute: min, System: "postgresql", Operation: "SELECT", Table: "x", Fingerprint: "f1",
				Text: "select * from x where id = ?", Calls: 2, Errors: 1, TotalMs: 30, DurBuckets: []int64{0, 0, 2}}},
			NPlusOne: []AppNPlusOne{{Service: "api", Environment: "prod", Route: "/x", Method: "GET", Count: 1}},
		}, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	send()
	send()
	var calls int64
	var ms float64
	_ = db.QueryRowContext(ctx, `SELECT calls, total_ms FROM app_route_children`).Scan(&calls, &ms)
	if calls != 4 || ms != 60 {
		t.Fatalf("children add up: %d %v", calls, ms)
	}
	var qc, qe int64
	var hist, text string
	_ = db.QueryRowContext(ctx, `SELECT calls, errors, duration_buckets::text, text FROM app_db_stats`).Scan(&qc, &qe, &hist, &text)
	if qc != 4 || qe != 2 || hist != "[0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]" || text == "" {
		t.Fatalf("queries add up: %d %d %s %q", qc, qe, hist, text)
	}
	var n int64
	_ = db.QueryRowContext(ctx, `SELECT count FROM app_route_n1`).Scan(&n)
	if n != 2 {
		t.Fatalf("n+1: %d", n)
	}
	// The management setting reaches the agent.
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS service_settings (service_id BIGINT PRIMARY KEY, store_client_ip TEXT NOT NULL DEFAULT 'full', cleartext_users BOOLEAN NOT NULL DEFAULT FALSE, latency_target_ms INT)`); err != nil {
		t.Fatal(err)
	}
	_, _ = db.ExecContext(ctx, `INSERT INTO service_settings (service_id) SELECT id FROM services WHERE name='api'`)
	cfg, err := db.AppRemoteConfig(ctx) // column missing (migration 066 not applied): falls back, mode off
	if err != nil || len(cfg) != 1 || cfg[0].DBStatementMode != "off" {
		t.Fatalf("fallback config: %+v %v", cfg, err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE service_settings ADD COLUMN db_statement_mode TEXT NOT NULL DEFAULT 'off'; ALTER TABLE service_settings ADD COLUMN error_message_mode TEXT NOT NULL DEFAULT 'off'; UPDATE service_settings SET db_statement_mode='fingerprint'`); err != nil {
		t.Fatal(err)
	}
	if cfg, err = db.AppRemoteConfig(ctx); err != nil || len(cfg) != 1 || cfg[0].DBStatementMode != "fingerprint" {
		t.Fatalf("config: %+v %v", cfg, err)
	}
}

func TestAppErrorGroupsCountAndRegress(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("migrations/037_app_errors.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	send := func(ver, trace string, n int64) {
		t.Helper()
		_, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Errors: []AppError{{Service: "api", Environment: "prod", Route: "/orders/:id", Method: "GET",
			Fingerprint: "0123456789abcdef", Type: "Error", Frame: "getOrder src/orders.js:42", Frames: []string{"getOrder src/orders.js:42"},
			Message: "order ? not found", Version: ver, TraceID: trace, Count: n, Time: now}}}, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	row := func() (cnt int64, status string, regressed bool, fv, lv string, traces string) {
		_ = db.QueryRowContext(ctx, `SELECT count, status, regressed, first_version, last_version, sample_traces::text FROM error_groups`).Scan(&cnt, &status, &regressed, &fv, &lv, &traces)
		return
	}
	send("1.0.0", "aaaa", 1)
	send("1.0.0", "bbbb", 1)
	if c, st, rg, fv, lv, tr := row(); c != 2 || st != "open" || rg || fv != "1.0.0" || lv != "1.0.0" || tr != `["bbbb", "aaaa"]` {
		t.Fatalf("two occurrences, one group: %d %s %v %s %s %s", c, st, rg, fv, lv, tr)
	}
	var hours int64
	_ = db.QueryRowContext(ctx, `SELECT SUM(count) FROM error_group_hours`).Scan(&hours)
	if hours != 2 {
		t.Fatalf("hourly counts: %d", hours)
	}
	// Resolved in 1.0.0: the same failure in 1.0.0 stays resolved, in 1.1.0 it regresses.
	if _, err := db.ExecContext(ctx, `UPDATE error_groups SET status='resolved', resolved_version='1.0.0'`); err != nil {
		t.Fatal(err)
	}
	send("1.0.0", "cccc", 1)
	if _, st, rg, _, _, _ := row(); st != "resolved" || rg {
		t.Fatalf("same version must not reopen: %s %v", st, rg)
	}
	send("1.1.0", "dddd", 1)
	if c, st, rg, _, lv, _ := row(); st != "open" || !rg || lv != "1.1.0" || c != 4 {
		t.Fatalf("regression: %d %s %v %s", c, st, rg, lv)
	}
	// An ignored group stays ignored.
	if _, err := db.ExecContext(ctx, `UPDATE error_groups SET status='ignored', regressed=FALSE`); err != nil {
		t.Fatal(err)
	}
	send("2.0.0", "eeee", 1)
	if _, st, rg, _, _, _ := row(); st != "ignored" || rg {
		t.Fatalf("ignored: %s %v", st, rg)
	}
}

func TestAppSketchMergesAndCoverage(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("migrations/038_app_percentile_sketch.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	min := now.Truncate(time.Minute).Add(-time.Minute)
	mk := func(vals ...float64) *SketchWire {
		s := NewSketch()
		for _, v := range vals {
			s.Add(v)
		}
		return s.Wire()
	}
	send := func(calls int64, sk *SketchWire) {
		t.Helper()
		_, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Routes: []AppRouteStat{{Service: "api", Environment: "prod", Route: "/x", Method: "GET",
			Minute: min, Calls: calls, DurBuckets: make([]int64, 12), Sketch: sk}}}, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	row := func() (calls, skCalls int64, sk string) {
		_ = db.QueryRowContext(ctx, `SELECT calls, sketch_calls, COALESCE(sketch::text,'') FROM app_route_stats`).Scan(&calls, &skCalls, &sk)
		return
	}
	send(2, mk(10, 90000))
	send(1, mk(30))
	c, sc, js := row()
	if c != 3 || sc != 3 {
		t.Fatalf("complete: %d %d", c, sc)
	}
	var w SketchWire
	if err := json.Unmarshal([]byte(js), &w); err != nil || SketchFromWire(&w).Count() != 3 || w.Max < 89000 {
		t.Fatalf("merged sketch: %v %+v", err, w)
	}
	send(4, nil) // an agent without the feature: the row is no longer sketch-complete
	c, sc, _ = row()
	if c != 7 || sc != 3 {
		t.Fatalf("incomplete: %d %d", c, sc)
	}
}

func TestAppMetricsMerge(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("migrations/039_app_metrics.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // idempotent
		if _, err := db.ExecContext(ctx, string(b)); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	min := now.Truncate(time.Minute)
	send := func(last, mn, mx, sum float64, n int64) {
		t.Helper()
		res, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Metrics: []AppMetric{{Service: "api", Environment: "prod", Instance: "i-1",
			Name: "process.cpu.utilization", Attr: "state=user", Identity: "asserted", Minute: min, Last: last, Min: mn, Max: mx, Sum: sum, Count: n}}}, now)
		if err != nil || res.Metrics != 1 {
			t.Fatalf("%v %+v", err, res)
		}
	}
	send(0.5, 0.2, 0.7, 1.0, 2)
	send(0.9, 0.1, 0.6, 1.5, 3)
	var last, mn, mx, sum float64
	var cnt int64
	if err := db.QueryRowContext(ctx, `SELECT last, min, max, sum, count FROM app_metrics`).Scan(&last, &mn, &mx, &sum, &cnt); err != nil {
		t.Fatal(err)
	}
	if last != 0.9 || mn != 0.1 || mx != 0.7 || sum != 2.5 || cnt != 5 {
		t.Fatalf("merge: %v %v %v %v %v", last, mn, mx, sum, cnt)
	}
}

func TestAppSamplingStatsAndRemoteConfig(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("migrations/040_app_sampling.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		if _, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Sampling: []AppSampling{{Service: "api", Environment: "prod", Reason: "baseline", Seen: 10, Kept: 1}}}, now); err != nil {
			t.Fatal(err)
		}
	}
	var seen, kept int64
	if err := db.QueryRowContext(ctx, `SELECT seen, kept FROM app_sampling_stats`).Scan(&seen, &kept); err != nil || seen != 20 || kept != 2 {
		t.Fatalf("%d %d %v", seen, kept, err)
	}
	// settings with a sampling policy reach the agent; without the column the pull still works
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS service_settings (service_id BIGINT PRIMARY KEY, store_client_ip TEXT NOT NULL DEFAULT 'full', cleartext_users BOOLEAN NOT NULL DEFAULT FALSE, latency_target_ms INT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE service_settings ADD COLUMN IF NOT EXISTS error_message_mode TEXT NOT NULL DEFAULT 'off', ADD COLUMN IF NOT EXISTS db_statement_mode TEXT NOT NULL DEFAULT 'off'`); err != nil {
		t.Fatal(err)
	}
	var sid int64
	_ = db.QueryRowContext(ctx, `SELECT id FROM services WHERE name='api'`).Scan(&sid)
	if _, err := db.ExecContext(ctx, `INSERT INTO service_settings (service_id) VALUES ($1)`, sid); err != nil {
		t.Fatal(err)
	}
	cfg, err := db.AppRemoteConfig(ctx)
	if err != nil || len(cfg) != 1 || cfg[0].Sampling != nil {
		t.Fatalf("no column: %d %+v %v", len(cfg), cfg, err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE service_settings ADD COLUMN IF NOT EXISTS sampling JSONB NOT NULL DEFAULT '{}'`); err != nil {
		t.Fatal(err)
	}
	if cfg, _ = db.AppRemoteConfig(ctx); cfg[0].Sampling != nil {
		t.Fatalf("empty policy is the default: %+v", cfg[0].Sampling)
	}
	if _, err := db.ExecContext(ctx, `UPDATE service_settings SET sampling='{"baseline_pct":0,"error_max_per_min":20}'`); err != nil {
		t.Fatal(err)
	}
	cfg, _ = db.AppRemoteConfig(ctx)
	if cfg[0].Sampling == nil || cfg[0].Sampling.BaselinePct == nil || *cfg[0].Sampling.BaselinePct != 0 || cfg[0].Sampling.ErrorMaxPerMin != 20 {
		t.Fatalf("%+v", cfg[0].Sampling)
	}
}

func TestAppOperationsIngest(t *testing.T) {
	db := appTestDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("migrations/041_app_operations.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(b)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	min := now.Truncate(time.Minute)
	for i, last := range []time.Time{now.Add(-20 * time.Second), now} {
		h := make([]int64, AppHistLen)
		h[3] = 2
		if _, err := db.AppIngestBatch(ctx, "a1", "web-01", AppBatch{Operations: []AppOperation{{Service: "worker", Environment: "prod", Kind: "job", Name: "nightly",
			Minute: min, Runs: 2, Failures: int64(i), DurBuckets: h, LastRun: last}}}, now); err != nil {
			t.Fatal(err)
		}
	}
	var runs, fails int64
	var last time.Time
	var hist string
	if err := db.QueryRowContext(ctx, `SELECT runs, failures, last_run, duration_buckets::text FROM app_operations`).Scan(&runs, &fails, &last, &hist); err != nil {
		t.Fatal(err)
	}
	if runs != 4 || fails != 1 || last.Before(now.Add(-time.Second)) || !strings.Contains(hist, "4") {
		t.Fatalf("%d %d %v %s", runs, fails, last, hist)
	}
}
