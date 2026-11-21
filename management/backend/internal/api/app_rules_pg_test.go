package api

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

type appPGFx struct {
	raw *sql.DB
	db  *store.DB
	r   *appRules
	now time.Time
	t   *testing.T
}

func appPGSetup(t *testing.T) *appPGFx {
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
	if _, err := raw.Exec(`DROP TABLE IF EXISTS app_traces, app_route_stats, app_baselines, service_versions, service_routes, service_edges,
		service_instances, services, service_settings, app_edge_stats, app_client_stats, app_service_merges, alert_entities, alerts,
		rule_settings, alert_related_events, events, agents CASCADE`); err != nil {
		t.Fatal(err)
	}
	// The production events table needs TimescaleDB; this stand-in has the columns the rules read.
	if _, err := raw.Exec(`CREATE TABLE events (id TEXT, time TIMESTAMPTZ NOT NULL, agent_id TEXT, host TEXT, event_type TEXT,
		process_name TEXT, pid INT, user_name TEXT, raw JSONB)`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"../../../../backend/internal/store/migrations/002_agents.sql", "../../../../backend/internal/store/migrations/030_app_services.sql",
		"../../../../backend/internal/store/migrations/031_app_edge_client_stats.sql", "../store/migrations/060_app_service_settings.sql",
		"../store/migrations/004_alerts.sql", "../store/migrations/010_alert_source_event.sql", "../store/migrations/014_alerts_dedup.sql",
		"../store/migrations/017_ai_analysis_cache.sql", "../store/migrations/027_alert_occurrences.sql", "../store/migrations/040_foundation_alert_entities.sql", "../store/migrations/041_foundation_rule_settings.sql", "../store/migrations/062_alert_related_events.sql"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	db := &store.DB{DB: raw}
	fx := &appPGFx{raw: raw, db: db, now: time.Now().UTC(), t: t}
	fx.r = appNewRules(appPGData{db: db, idb: db}, appPGEmitter{db: db}, func(ctx context.Context, rule string, svc appSvc) RuleGate {
		if svc.ID != 0 {
			return ruleGate(ctx, db, rule, "service", svc.Key())
		}
		return ruleGate(ctx, db, rule, "", "")
	})
	old := fx.now.Add(-30 * 24 * time.Hour)
	appMustExec(t, raw, `INSERT INTO agents (id, hostname, os, version) VALUES ('a1','web-01','linux','1')`)
	appMustExec(t, raw, `INSERT INTO services (id, name, environment, source, first_seen, last_seen) VALUES (1,'checkout','prod','otel',$1,$2)`, old, fx.now)
	appMustExec(t, raw, `INSERT INTO service_instances (id, service_id, agent_id, host, pid, proc_start, identity, instance_ref, first_seen, last_seen, attrs)
		VALUES (11,1,'a1','web-01',100,$1,'verified','i-1',$1,$2,'{"exe":"/usr/bin/java"}')`, old, fx.now)
	appMustExec(t, raw, `INSERT INTO service_settings (service_id, exposure, criticality, login_routes) VALUES (1,'internet','critical','["/login"]')`)
	return fx
}

func appMustExec(t *testing.T, raw *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := raw.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func (fx *appPGFx) alerts(rule string) []struct {
	ID       int64
	Title    string
	Severity int
	EventID  string
	Desc     string
} {
	rows, err := fx.raw.Query(`SELECT id, title, severity, event_id, description FROM alerts WHERE event_id LIKE $1 ORDER BY id`, "app:"+rule+":%")
	if err != nil {
		fx.t.Fatal(err)
	}
	defer rows.Close()
	var out []struct {
		ID       int64
		Title    string
		Severity int
		EventID  string
		Desc     string
	}
	for rows.Next() {
		var a struct {
			ID       int64
			Title    string
			Severity int
			EventID  string
			Desc     string
		}
		if err := rows.Scan(&a.ID, &a.Title, &a.Severity, &a.EventID, &a.Desc); err != nil {
			fx.t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func (fx *appPGFx) entities(alertID int64) map[string]string {
	rows, err := fx.raw.Query(`SELECT kind, key FROM alert_entities WHERE alert_id=$1`, alertID)
	if err != nil {
		fx.t.Fatal(err)
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		_ = rows.Scan(&k, &v)
		m[k] = v
	}
	return m
}

func (fx *appPGFx) event(pid int, name, raw string, typ string) store.Event {
	ev := appEv(typ, pid, 100, name, raw)
	ev.Time = fx.now
	return ev
}

func TestAppRulesEndToEndOnPostgres(t *testing.T) {
	fx := appPGSetup(t)
	ctx := context.Background()

	// 1. Observe by default: the alert exists but shows as Info.
	fx.r.OnEvent(ctx, fx.event(500, "bash", `{`+appAncJava+`}`, "process"))
	al := fx.alerts("APP-H01")
	if len(al) != 1 || al[0].Severity != appSevInfo || al[0].Title != "[APP-H01] Service process spawned a shell - checkout (prod)" {
		t.Fatalf("observe-by-default: %+v", al)
	}
	if !appContains(al[0].Desc, "Mode: observe") || !appContains(al[0].Desc, "Process lineage: java(100) > bash(500)") {
		t.Fatalf("alert text: %s", al[0].Desc)
	}
	ents := fx.entities(al[0].ID)
	if ents["service"] != "checkout|prod" || ents["service_instance"] != "11" || ents["host"] != "web-01" {
		t.Fatalf("entity links: %v", ents)
	}

	// 2. Dedup: the same finding in the same hour does not create a second alert.
	fx.r.OnEvent(ctx, fx.event(500, "bash", `{`+appAncJava+`}`, "process"))
	if n := len(fx.alerts("APP-H01")); n != 1 {
		t.Fatalf("dedup: %d", n)
	}

	// 3. Promote the rule: severity is weighted (High +1 internet +1 critical = capped Critical).
	appMustExec(t, fx.raw, `INSERT INTO rule_settings (rule_id, scope_kind, scope_id, enabled, observe) VALUES ('APP-H01','','',TRUE,FALSE)`)
	fx.r.OnEvent(ctx, fx.event(501, "bash", `{`+appAncJava+`}`, "process"))
	al = fx.alerts("APP-H01")
	// The 30-minute dedupe folds the repeat into the first alert and raises it to the weighted severity.
	if len(al) != 1 || al[0].Severity != appSevCrit || !appContains(al[0].Desc, "internet-facing +1") {
		t.Fatalf("promoted + weighted: %+v", al)
	}

	// 4. A per-service allowlist silences one pair without disabling the rule.
	appMustExec(t, fx.raw, `INSERT INTO rule_settings (rule_id, scope_kind, scope_id, enabled, observe, allowlist) VALUES ('APP-H01','service','checkout|prod',TRUE,FALSE,'["java>bash"]')`)
	fx.r.OnEvent(ctx, fx.event(502, "bash", `{`+appAncJava+`}`, "process"))
	if n := len(fx.alerts("APP-H01")); n != 1 {
		t.Fatalf("allowlist: %d", n)
	}
	appMustExec(t, fx.raw, `DELETE FROM rule_settings WHERE scope_kind='service'`)

	appMustExec(t, fx.raw, `INSERT INTO rule_settings (rule_id, scope_kind, scope_id, enabled, observe) VALUES ('APP-X02','','',TRUE,FALSE)`)
	// 5. X02: an application anomaly (an A09 alert) then host execution in the same service.
	appMustExec(t, fx.raw, `INSERT INTO alerts (title, severity, status, event_id) VALUES ('A09 earlier',3,'open','app:APP-A09:1:x:y')`)
	fx.r.OnEvent(ctx, fx.event(600, "bash", `{`+appAncJava+`}`, "process"))
	x := fx.alerts("APP-X02")
	if len(x) != 1 || x[0].Severity != appSevCrit {
		t.Fatalf("X02: %+v", x)
	}

	// 6. H04 through the database baseline: learning samples, a new destination, and no repeat.
	appMustExec(t, fx.raw, `INSERT INTO app_baselines (service_id, kind, key, samples, first_seen, updated) VALUES (1,'destination','dns:db.internal',300,$1,$1)`, fx.now)
	net := fx.event(100, "java", `{"dns":"evil.example.net"}`, "network")
	net.DstIP, net.DstPort = appSP("203.0.113.50"), appIP(443)
	appMustExec(t, fx.raw, `INSERT INTO rule_settings (rule_id, scope_kind, scope_id, enabled, observe) VALUES ('APP-H04','','',TRUE,FALSE)`)
	fx.r.OnEvent(ctx, net)
	fx.r.OnEvent(ctx, net)
	if h := fx.alerts("APP-H04"); len(h) != 1 || h[0].Severity < appSevMed {
		t.Fatalf("H04: %+v", h)
	}
	var samples int64
	_ = fx.raw.QueryRow(`SELECT samples FROM app_baselines WHERE key='dns:evil.example.net'`).Scan(&samples)
	if samples != 2 {
		t.Fatalf("destination recorded into the baseline: %d", samples)
	}
	// ... and a deploy (a new version) suppresses a further new destination.
	appMustExec(t, fx.raw, `INSERT INTO service_versions (service_id, version, first_seen, last_seen) VALUES (1,'2.0',$1,$1)`, fx.now.Add(-5*time.Minute))
	net2 := fx.event(100, "java", `{"dns":"another.example.org"}`, "network")
	net2.DstIP = appSP("203.0.113.77")
	fx.r.OnEvent(ctx, net2)
	if n := len(fx.alerts("APP-H04")); n != 1 {
		t.Fatalf("deploy window must suppress: %d", n)
	}

	// 7. Scan: A01 from app_client_stats, with the client address and route as entities.
	appMustExec(t, fx.raw, `INSERT INTO rule_settings (rule_id, scope_kind, scope_id, enabled, observe) VALUES ('APP-A01','','',TRUE,FALSE)`)
	appMustExec(t, fx.raw, `INSERT INTO app_client_stats (minute, service_id, route, method, client_ip, peer_ip, failures, status_401_403) VALUES ($1,1,'/login','POST','203.0.113.9','203.0.113.9',30,30)`, fx.now.Truncate(time.Minute).Add(-time.Minute))
	fx.r.Scan(ctx)
	a01 := fx.alerts("APP-A01")
	if len(a01) != 1 || a01[0].Severity != appSevCrit {
		t.Fatalf("A01: %+v", a01)
	}
	e := fx.entities(a01[0].ID)
	if e["ip"] != "203.0.113.9" || e["route"] != "checkout|prod|POST /login" || e["service"] != "checkout|prod" {
		t.Fatalf("A01 entities: %v", e)
	}
	fx.r.Scan(ctx)
	if n := len(fx.alerts("APP-A01")); n != 1 {
		t.Fatalf("a repeated scan must not duplicate: %d", n)
	}
}

func TestAppTapDeliversEventsToTheWorker(t *testing.T) {
	fx := appPGSetup(t)
	stop := appStartRules(fx.db, fx.db, nil)
	defer stop()
	appMustExec(t, fx.raw, `INSERT INTO rule_settings (rule_id, scope_kind, scope_id, enabled, observe) VALUES ('APP-H02','','',TRUE,FALSE)`)
	// Events the foundation does not hand to the tap are ignored; process events reach the worker.
	if got := appTap(fx.event(600, "curl", `{`+appAncJava+`}`, "process")); got != nil {
		t.Fatal("the tap must not return signatures (alerts are created by the rule worker)")
	}
	appTap(fx.event(601, "curl", `{`+appAncJava+`}`, "dns"))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(fx.alerts("APP-H02")) == 0 {
		time.Sleep(50 * time.Millisecond)
	}
	if n := len(fx.alerts("APP-H02")); n != 1 {
		t.Fatalf("worker did not raise the alert: %d", n)
	}
	// Starting twice is a no-op (one worker per process).
	if stop2 := appStartRules(fx.db, fx.db, nil); stop2 == nil {
		t.Fatal("second start returns a no-op stop")
	}
}

func (fx *appPGFx) promoteAll() {
	for _, id := range []string{"APP-H01", "APP-H02", "APP-H03", "APP-H04", "APP-H05", "APP-H06", "APP-H07", "APP-H08", "APP-H11",
		"APP-A01", "APP-A08", "APP-A09", "APP-A13", "APP-X02", "APP-X06", "APM-O01", "APM-O03", "APM-O05"} {
		appMustExec(fx.t, fx.raw, `INSERT INTO rule_settings (rule_id, scope_kind, scope_id, enabled, observe) VALUES ($1,'','',TRUE,FALSE)`, id)
	}
}

func TestAppRulesScanOperationalOnPostgres(t *testing.T) {
	fx := appPGSetup(t)
	fx.promoteAll()
	ctx := context.Background()
	min := fx.now.Truncate(time.Minute)

	// O01: 15% errors in the last window, above the default 5% budget; operational alerts are not weighted
	// even though this service is internet-facing and critical.
	appMustExec(t, fx.raw, `INSERT INTO app_route_stats (minute, service_id, route, method, calls, errors, status_5xx) VALUES ($1,1,'/orders','GET',200,30,30)`, min.Add(-5*time.Minute))
	// A08: a route first seen 20 minutes ago, after a week of learning and over 1000 requests.
	appMustExec(t, fx.raw, `INSERT INTO app_route_stats (minute, service_id, route, method, calls) VALUES ($1,1,'/orders','GET',5000)`, min.Add(-72*time.Hour))
	appMustExec(t, fx.raw, `INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES (1,'/admin/export','GET',$1,$1), (1,'/old','GET',$2,$1)`, fx.now.Add(-20*time.Minute), fx.now.Add(-10*24*time.Hour))
	// O05: a second instance on another host keeps reporting while instance 11 went silent 30 minutes ago.
	appMustExec(t, fx.raw, `INSERT INTO agents (id, hostname, os, version) VALUES ('a2','web-02','linux','1')`)
	appMustExec(t, fx.raw, `INSERT INTO service_instances (id, service_id, agent_id, host, pid, proc_start, identity, instance_ref, first_seen, last_seen) VALUES (12,1,'a2','web-02',200,$1,'verified','i-2',$1,$2)`, fx.now.Add(-5*24*time.Hour), fx.now)
	appMustExec(t, fx.raw, `UPDATE service_instances SET last_seen=$1 WHERE id=11`, fx.now.Add(-30*time.Minute))

	fx.r.Scan(ctx)

	o01 := fx.alerts("APM-O01")
	if len(o01) != 1 || o01[0].Severity != appSevHigh || !appContains(o01[0].Desc, "error budget is 5.0%") {
		t.Fatalf("O01: %+v", o01)
	}
	a08 := fx.alerts("APP-A08")
	if len(a08) != 1 || !appContains(a08[0].Title, "New route") || !appContains(a08[0].Desc, "/admin/export") || appContains(a08[0].Desc, "/old") {
		t.Fatalf("A08: %+v", a08)
	}
	if e := fx.entities(a08[0].ID); e["route"] != "checkout|prod|GET /admin/export" {
		t.Fatalf("A08 route entity: %v", e)
	}
	o05 := fx.alerts("APM-O05")
	if len(o05) != 1 || !appContains(o05[0].Desc, "web-01") {
		t.Fatalf("O05: %+v", o05)
	}
	if e := fx.entities(o05[0].ID); e["service_instance"] != "11" || e["host"] != "web-01" {
		t.Fatalf("O05 entities: %v", e)
	}
}

func TestAppRulesX06OnPostgres(t *testing.T) {
	fx := appPGSetup(t)
	fx.promoteAll()
	ctx := context.Background()
	min := fx.now.Truncate(time.Minute)
	// Traffic stopped 20 minutes ago after a busy hour ...
	appMustExec(t, fx.raw, `INSERT INTO app_route_stats (minute, service_id, route, method, calls) VALUES ($1,1,'/orders','GET',500)`, min.Add(-20*time.Minute))
	fx.r.Scan(ctx)
	if n := len(fx.alerts("APP-X06")); n != 0 {
		t.Fatalf("no evidence the process still runs: must stay quiet (%d)", n)
	}
	if appStatusSnapshot()["APP-X06"].Skipped["no evidence the process is still running"] == 0 {
		t.Fatalf("the missing evidence must be counted: %+v", appStatusSnapshot()["APP-X06"])
	}
	// ... but the host reports activity from the service's process: instrumentation was dropped.
	appMustExec(t, fx.raw, `INSERT INTO events (id, time, agent_id, host, event_type, process_name, pid) VALUES ('p1',$1,'a1','web-01','process','java',100)`, fx.now.Add(-time.Minute))
	fx.r.Scan(ctx)
	x := fx.alerts("APP-X06")
	if len(x) != 1 || !appContains(x[0].Desc, "pid 100") {
		t.Fatalf("X06: %+v", x)
	}
}
