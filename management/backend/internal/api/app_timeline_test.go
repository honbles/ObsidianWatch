package api

import (
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestAppTimelineIntegration(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE IF EXISTS app_traces, app_route_stats, app_baselines, service_versions, service_routes, service_edges,
		service_instances, services, service_settings, app_payloads, app_edge_stats, app_client_stats, app_service_merges, events, alert_entities, alerts CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE events (id TEXT, time TIMESTAMPTZ NOT NULL, agent_id TEXT, host TEXT, event_type TEXT, source TEXT,
		pid INT, ppid INT, process_name TEXT, command_line TEXT, user_name TEXT, dst_ip TEXT, dst_port INT, file_path TEXT, raw JSONB)`); err != nil {
		t.Fatal(err) // dst_ip is TEXT in production (migration 004)
	}
	for _, f := range []string{"../../../../backend/internal/store/migrations/030_app_services.sql", "../../../../backend/internal/store/migrations/031_app_edge_client_stats.sql", "../../../../backend/internal/store/migrations/033_app_payloads.sql", "../../../../backend/internal/store/migrations/034_app_payloads_latency.sql", "../store/migrations/060_app_service_settings.sql"} {
		b, _ := os.ReadFile(f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC()
	appMustExec(t, raw, `INSERT INTO services (id, name, environment, source, first_seen, last_seen) VALUES (1,'postgres','prod','discovered',$1,$2)`, now.Add(-30*24*time.Hour), now)
	appMustExec(t, raw, `INSERT INTO service_instances (id, service_id, agent_id, host, pid, proc_start, identity, listen, attrs, first_seen, last_seen)
		VALUES (11,1,'a1','db-01',100,$1,'verified','[5432]','{"container_name":"pg"}',$1,$2)`, now.Add(-30*time.Minute), now)
	appMustExec(t, raw, `INSERT INTO service_versions (service_id, version, first_seen, last_seen) VALUES (1,'16.2',$1,$2)`, now.Add(-20*time.Minute), now)
	appMustExec(t, raw, `INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES (1,'/x','GET',$1,$2)`, now.Add(-10*time.Minute), now)
	appMustExec(t, raw, `INSERT INTO service_edges (src_service, dst_kind, dst_name, source, first_seen, last_seen) VALUES (1,'external','a.example','otel',$1,$2)`, now.Add(-9*time.Minute), now)
	ev := func(id string, ago time.Duration, typ string, pid int, dip string, dport int) {
		appMustExec(t, raw, `INSERT INTO events (id, time, agent_id, host, event_type, source, pid, ppid, process_name, user_name, dst_ip, dst_port, raw)
			VALUES ($1,$2,'a1','db-01',$3,'ebpf',$4,1,'postgres','pg',NULLIF($5,''),NULLIF($6,0),'{}')`, id, now.Add(-ago), typ, pid, dip, dport)
	}
	ev("old", 48*time.Hour, "network", 100, "10.0.0.7", 5432) // seen before the range: not first-seen
	ev("c1", 5*time.Minute, "network", 100, "10.0.0.7", 5432)
	ev("c2", 4*time.Minute, "network", 100, "203.0.113.9", 443) // new destination
	ev("c3", 3*time.Minute, "network", 100, "203.0.113.9", 443) // same destination again: only the earliest is flagged
	ev("p1", 2*time.Minute, "process", 100, "", 0)
	ev("o1", 2*time.Minute, "network", 100, "127.0.0.1", 4318) // the app's own telemetry export: hidden
	ev("l1", 2*time.Minute, "network", 100, "127.0.0.1", 5432) // a local database connection: kept
	ev("u1", 2*time.Minute, "network", 999, "198.51.100.1", 80) // unrelated pid

	appMustExec(t, raw, `INSERT INTO app_payloads (service_id, time, route, method, status, duration_ms, trace_id, params, withheld) VALUES (1,$1,'/search','GET',200,12,'t1','{"q":"apple"}','["sort"]')`, now.Add(-time.Minute))
	db := &store.DB{DB: raw}
	rng := "?from=" + now.Add(-time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Minute).Format(time.RFC3339)
	pv := map[string]string{"id": "1"}
	type resp struct {
		Items []struct {
			Category  string `json:"category"`
			Kind      string `json:"kind"`
			Title     string `json:"title"`
			FirstSeen bool   `json:"first_seen"`
		} `json:"items"`
		Counts map[string]int `json:"counts"`
		Hosts  []string       `json:"hosts"`
	}
	get := func(q string) resp {
		rec := appGet(appHandleServiceTimeline(db, nil), "/x"+rng+q, pv)
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", q, rec.Code, rec.Body.String())
		}
		var out resp
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	all := get("")
	if all.Counts["connection"] != 4 || all.Counts["process"] != 1 || all.Counts["lifecycle"] != 4 || all.Counts["request"] != 1 || len(all.Hosts) != 1 {
		t.Fatalf("counts: %+v", all)
	}
	kinds := map[string]bool{}
	first := 0
	for _, it := range all.Items {
		kinds[it.Kind] = true
		if it.FirstSeen {
			first++
			if it.Title != "Connection to 203.0.113.9:443" && it.Title != "Connection to 127.0.0.1:5432" {
				t.Fatalf("wrong first-seen item: %+v", it)
			}
		}
	}
	for _, k := range []string{"instance_started", "new_version", "new_route", "new_dependency"} {
		if !kinds[k] {
			t.Fatalf("missing lifecycle kind %s: %+v", k, all.Items)
		}
	}
	if first != 2 { // 203.0.113.9:443 once (not twice) and the local database; 10.0.0.7:5432 was seen before the range
		t.Fatalf("exactly the earliest sighting of each new destination is flagged: %d", first)
	}
	if c := get("&category=connection"); len(c.Items) != 4 {
		t.Fatalf("category filter: %+v", c.Items)
	}
	if h := get("&host=nope"); len(h.Items) != 0 {
		t.Fatalf("host filter: %+v", h.Items)
	}
	if rec := appGet(appHandleServiceTimeline(db, nil), "/x"+rng+"&category=bogus", pv); rec.Code != 400 {
		t.Fatalf("bad category: %d", rec.Code)
	}
}
