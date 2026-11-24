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

func TestAppOverviewAlertsEventsIntegration(t *testing.T) {
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
		service_edges, service_instances, services, service_settings, app_edge_stats, app_client_stats, app_service_merges, alert_entities, alerts, events CASCADE`); err != nil {
		t.Fatal(err)
	}
	// The production events table needs TimescaleDB; a minimal stand-in has the columns this API reads.
	if _, err := raw.Exec(`CREATE TABLE events (id TEXT, time TIMESTAMPTZ NOT NULL, host TEXT, event_type TEXT, user_name TEXT, raw JSONB)`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		"../../../../backend/internal/store/migrations/030_app_services.sql", "../../../../backend/internal/store/migrations/031_app_edge_client_stats.sql", "../store/migrations/060_app_service_settings.sql", "../store/migrations/066_app_db_statement_mode.sql", "../store/migrations/067_app_error_message_mode.sql", "../store/migrations/068_app_sampling.sql", "../store/migrations/069_app_slo.sql",
		"../store/migrations/004_alerts.sql", "../store/migrations/040_foundation_alert_entities.sql",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC()
	old := now.Add(-30 * 24 * time.Hour)
	mk := func(name, env, src string, first time.Time, attrs string) int64 {
		var id int64
		if err := raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen, attrs) VALUES ($1,$2,$3,$4,$5,$6::jsonb) RETURNING id`,
			name, env, src, first, now.Add(-time.Minute), attrs).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	api := mk("api", "prod", "otel", old, `{"route_overflow":5}`)
	bare := mk("batch", "prod", "discovered", old, `{}`)
	fresh := mk("newsvc", "prod", "otel", now.Add(-2*time.Hour), `{}`)
	_ = fresh
	raw.Exec(`INSERT INTO service_instances (service_id, agent_id, host, pid, identity, first_seen, last_seen) VALUES ($1,'agent-9','web-01',100,'asserted',$2,$2)`, api, now.Add(-time.Minute))
	raw.Exec(`INSERT INTO service_instances (service_id, agent_id, host, pid, identity, attrs, first_seen, last_seen) VALUES ($1,'agent-7','db-01',200,'verified','{"sensor":"poll"}',$2,$2)`, bare, now.Add(-time.Minute))
	// api: an old edge (baseline), a new edge after the first hour, a new route and a new version.
	raw.Exec(`INSERT INTO service_edges (src_service, dst_kind, dst_name, source, first_seen, last_seen) VALUES
	  ($1,'database','pg','otel',$2,$3), ($1,'external','evil.example.com','otel',$4,$3)`, api, old, now, now.Add(-time.Hour))
	raw.Exec(`INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,'/old','GET',$2,$3),($1,'/admin/export','GET',$4,$3)`, api, old, now, now.Add(-time.Hour))
	raw.Exec(`INSERT INTO service_versions (service_id, version, first_seen, last_seen) VALUES ($1,'1.0',$2,$3),($1,'1.1',$4,$3)`, api, old, now, now.Add(-time.Hour))
	raw.Exec(`INSERT INTO service_settings (service_id, exposure, criticality) VALUES ($1,'internet','critical')`, api)
	// Alerts linked to the service entity.
	var a1, a2, a3 int64
	raw.QueryRow(`INSERT INTO alerts (title, severity, status, host) VALUES ('SQLi burst', 4, 'open', 'web-01') RETURNING id`).Scan(&a1)
	raw.QueryRow(`INSERT INTO alerts (title, severity, status, host) VALUES ('old one', 2, 'closed', 'web-01') RETURNING id`).Scan(&a2)
	raw.QueryRow(`INSERT INTO alerts (title, severity, status, host) VALUES ('other service', 5, 'open', 'x') RETURNING id`).Scan(&a3)
	raw.Exec(`INSERT INTO alert_entities (alert_id, kind, key) VALUES ($1,'service','api|prod'),($2,'service','api|prod'),($3,'service','batch|prod')`, a1, a2, a3)
	// app.security events.
	ev := func(id, svc, name string, ago time.Duration) {
		raw.Exec(`INSERT INTO events (id, time, host, event_type, user_name, raw) VALUES ($1,$2,'web-01','app.security','u-hash',
		  jsonb_build_object('app', jsonb_build_object('service',$3::text,'environment','prod','event.name',$4::text,'route','/login')))`, id, now.Add(-ago), svc, name)
	}
	ev("e1", "api", "auth.login", time.Minute)
	ev("e2", "api", "authz.deny", 2*time.Minute)
	ev("e3", "batch", "auth.login", time.Minute)
	db := &store.DB{DB: raw}
	rng := "?from=" + now.Add(-24*time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Minute).Format(time.RFC3339)

	rec := appGet(appHandleOverview(db, nil), "/x"+rng, nil)
	var ov struct {
		Services int            `json:"services"`
		Exposure map[string]int `json:"exposure"`
		Tiers    map[string]int `json:"tiers"`
		Coverage float64        `json:"coverage"`
		Total    int            `json:"open_alerts_total"`
		Open     []struct {
			Service     appOverviewService `json:"service"`
			Open        int                `json:"open"`
			MaxSeverity int                `json:"max_severity"`
		} `json:"open_alerts"`
		Changes struct {
			NewServices []appOverviewService `json:"new_services"`
			NewDeps     []struct {
				DstName string `json:"dst_name"`
			} `json:"new_dependencies"`
			NewRoutes int `json:"new_routes"`
			Deploys   []struct {
				Version string `json:"version"`
			} `json:"deploys"`
		} `json:"changes"`
		Sensors   map[string]int `json:"sensors"`
		PollHosts []string       `json:"poll_hosts"`
		Degraded  []struct {
			Service appOverviewService `json:"service"`
			Reasons []string           `json:"reasons"`
		} `json:"degraded"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ov)
	if rec.Code != 200 || ov.Services != 3 || ov.Exposure["internet"] != 1 || ov.Exposure["unknown"] != 2 || ov.Tiers["1"] != 2 || ov.Tiers["0"] != 1 {
		t.Fatalf("posture: %s", rec.Body.String())
	}
	if ov.Coverage < 0.66 || ov.Coverage > 0.67 {
		t.Fatalf("coverage %v", ov.Coverage)
	}
	if ov.Total != 2 || len(ov.Open) != 2 || ov.Open[0].Service.Name == "" {
		t.Fatalf("open alerts: %s", rec.Body.String())
	}
	if len(ov.Changes.NewServices) != 1 || ov.Changes.NewServices[0].Name != "newsvc" || len(ov.Changes.NewDeps) != 1 || ov.Changes.NewDeps[0].DstName != "evil.example.com" ||
		ov.Changes.NewRoutes != 1 || len(ov.Changes.Deploys) != 1 || ov.Changes.Deploys[0].Version != "1.1" {
		t.Fatalf("changes (baseline items must not count): %s", rec.Body.String())
	}
	if ov.Sensors["poll"] != 1 || ov.Sensors["unknown"] != 1 || len(ov.PollHosts) != 1 || ov.PollHosts[0] != "db-01" {
		t.Fatalf("sensor tiers per host: %+v %v", ov.Sensors, ov.PollHosts)
	}
	var apiReasons []string
	for _, d := range ov.Degraded {
		if d.Service.Name == "api" {
			apiReasons = d.Reasons
		}
	}
	if len(apiReasons) != 2 {
		t.Fatalf("api should be degraded for asserted identity and route overflow: %s", rec.Body.String())
	}

	pv := map[string]string{"id": strconv.FormatInt(api, 10)}
	rec = appGet(appHandleServiceAlerts(db, nil), "/x", pv)
	var al struct {
		Alerts []struct {
			ID     int64
			Title  string
			Status string
		} `json:"alerts"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &al)
	if rec.Code != 200 || len(al.Alerts) != 1 || al.Alerts[0].Title != "SQLi burst" {
		t.Fatalf("open alerts only by default: %s", rec.Body.String())
	}
	rec = appGet(appHandleServiceAlerts(db, nil), "/x?state=all", pv)
	_ = json.Unmarshal(rec.Body.Bytes(), &al)
	if len(al.Alerts) != 2 {
		t.Fatalf("state=all: %s", rec.Body.String())
	}

	rec = appGet(appHandleServiceEvents(db, nil), "/x"+rng, pv)
	var es struct {
		Events []struct {
			ID   string
			User string `json:"user"`
		} `json:"events"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &es)
	if rec.Code != 200 || len(es.Events) != 2 || es.Events[0].ID != "e1" || es.Events[0].User != "u-hash" {
		t.Fatalf("events must be scoped to the service: %s", rec.Body.String())
	}
	rec = appGet(appHandleServiceEvents(db, nil), "/x"+rng+"&event_name=authz.deny", pv)
	_ = json.Unmarshal(rec.Body.Bytes(), &es)
	if len(es.Events) != 1 || es.Events[0].ID != "e2" {
		t.Fatalf("event_name filter: %s", rec.Body.String())
	}

	// Host panel: only services with an instance on that agent.
	rec = appGet(appHandleListServices(db, nil), "/x"+rng+"&agent_id=agent-7", nil)
	var ls struct {
		Services []appServiceRow `json:"services"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ls)
	if len(ls.Services) != 1 || ls.Services[0].Name != "batch" {
		t.Fatalf("agent filter: %s", rec.Body.String())
	}
	var iid int64
	raw.QueryRow(`SELECT id FROM service_instances WHERE agent_id='agent-9'`).Scan(&iid)
	rec = appGet(appHandleGetInstance(db, nil), "/x", map[string]string{"id": strconv.FormatInt(iid, 10)})
	var inst struct {
		Key      string `json:"key"`
		Host     string `json:"host"`
		Identity string `json:"identity"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &inst)
	if rec.Code != 200 || inst.Key != "api|prod" || inst.Host != "web-01" || inst.Identity != "asserted" {
		t.Fatalf("instance: %d %s", rec.Code, rec.Body.String())
	}
	if rec := appGet(appHandleGetInstance(db, nil), "/x", map[string]string{"id": "999999"}); rec.Code != 404 {
		t.Fatalf("unknown instance: %d", rec.Code)
	}
	if rec := appGet(appHandleServiceAlerts(db, nil), "/x", map[string]string{"id": "999999"}); rec.Code != 404 {
		t.Fatalf("unknown service: %d", rec.Code)
	}
}
