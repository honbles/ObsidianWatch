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

func TestAppRuntimeAPIIntegration(t *testing.T) {
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
		service_instances, services, service_settings, app_edge_stats, app_client_stats, app_service_merges, events CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE events (id TEXT, time TIMESTAMPTZ NOT NULL, agent_id TEXT, host TEXT, event_type TEXT, source TEXT,
		pid INT, ppid INT, process_name TEXT, command_line TEXT, user_name TEXT, dst_ip INET, dst_port INT, file_path TEXT, raw JSONB)`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"../../../../backend/internal/store/migrations/030_app_services.sql", "../../../../backend/internal/store/migrations/031_app_edge_client_stats.sql", "../store/migrations/060_app_service_settings.sql", "../store/migrations/064_app_db_statement_mode.sql"} {
		b, _ := os.ReadFile(f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC()
	appMustExec(t, raw, `INSERT INTO services (id, name, environment, source, first_seen, last_seen) VALUES (1,'checkout','prod','otel',$1,$1), (2,'idle','prod','discovered',$1,$1)`, now.Add(-24*time.Hour))
	appMustExec(t, raw, `INSERT INTO service_instances (id, service_id, agent_id, host, pid, proc_start, identity, instrumented, listen, attrs, first_seen, last_seen)
		VALUES (11,1,'a1','web-01',100,$1,'verified',true,'[8080]','{"sensor":"procevent","exe":"/usr/bin/java"}',$1,$2),
		       (21,2,'a1','web-01',300,$1,'verified',false,'[9000]','{"sensor":"poll"}',$1,$3)`, now.Add(-time.Hour), now, now.Add(-30*24*time.Hour))
	ev := func(id string, pid, ppid int, typ, agent, rawProc string, extra func() (any, any, any)) {
		var dip, dport, fp any
		if extra != nil {
			dip, dport, fp = extra()
		}
		appMustExec(t, raw, `INSERT INTO events (id, time, agent_id, host, event_type, source, pid, ppid, process_name, command_line, user_name, dst_ip, dst_port, file_path, raw)
			VALUES ($1,$2,$3,'web-01',$4,'ebpf',$5,$6,'bash','bash -c id','www-data',$7,$8,$9,$10::jsonb)`, id, now.Add(-5*time.Minute), agent, typ, pid, ppid, dip, dport, fp, rawProc)
	}
	ev("e1", 500, 100, "process", "a1", `{"proc":{"ancestors":[{"pid":100,"name":"java"}],"tty":false,"sensor":"procevent"}}`, nil)
	ev("e2", 600, 500, "process", "a1", `{"proc":{"ancestors":[{"pid":500,"name":"bash"},{"pid":100,"name":"java"}]}}`, nil)
	ev("e3", 100, 1, "network", "a1", `{"proc":{"sensor":"procfs"}}`, func() (any, any, any) { return "203.0.113.9", 443, nil })
	ev("e4", 600, 500, "file", "a1", `{"proc":{"ancestors":[{"pid":500},{"pid":100}],"op":"write"}}`, func() (any, any, any) { return nil, nil, "/var/www/html/x.php" })
	ev("e5", 999, 1, "process", "a1", `{"proc":{"ancestors":[{"pid":1,"name":"systemd"}]}}`, nil) // unrelated process
	ev("e6", 100, 1, "process", "a2", `{}`, nil)                                                  // same pid on another host
	ev("e7", 700, 100, "dns", "a1", `{}`, nil)                                                    // not a host event type
	db := &store.DB{DB: raw}
	rng := "?from=" + now.Add(-time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Minute).Format(time.RFC3339)
	pv := map[string]string{"id": "1"}

	rec := appGet(appHandleServiceRuntime(db, nil), "/x"+rng, pv)
	var out struct {
		Instances []struct {
			ID           int64           `json:"id"`
			Sensor       string          `json:"sensor"`
			Listen       json.RawMessage `json:"listen"`
			Instrumented bool            `json:"instrumented"`
		} `json:"instances"`
		Events []struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			DstIP   string `json:"dst_ip"`
			DstPort int    `json:"dst_port"`
			Path    string `json:"path"`
		} `json:"events"`
		Counts map[string]int `json:"counts"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || len(out.Instances) != 1 || out.Instances[0].Sensor != "procevent" || string(out.Instances[0].Listen) != "[8080]" || !out.Instances[0].Instrumented {
		t.Fatalf("instances: %d %s", rec.Code, rec.Body.String())
	}
	ids := map[string]bool{}
	for _, e := range out.Events {
		ids[e.ID] = true
	}
	if len(out.Events) != 4 || !ids["e1"] || !ids["e2"] || !ids["e3"] || !ids["e4"] {
		t.Fatalf("a grandchild is attributed through its ancestry; unrelated pids, other hosts and non-host events are not: %s", rec.Body.String())
	}
	if out.Counts["process"] != 2 || out.Counts["network"] != 1 || out.Counts["file"] != 1 {
		t.Fatalf("counts: %v", out.Counts)
	}
	for _, e := range out.Events {
		if e.ID == "e3" && (e.DstIP != "203.0.113.9" || e.DstPort != 443) || e.ID == "e4" && e.Path != "/var/www/html/x.php" {
			t.Fatalf("event details: %+v", e)
		}
	}
	rec = appGet(appHandleServiceRuntime(db, nil), "/x"+rng+"&type=network", pv)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Events) != 1 || out.Events[0].ID != "e3" {
		t.Fatalf("type filter: %s", rec.Body.String())
	}
	if rec := appGet(appHandleServiceRuntime(db, nil), "/x"+rng+"&type=dns", pv); rec.Code != 400 {
		t.Fatalf("bad type: %d", rec.Code)
	}
	rec = appGet(appHandleServiceRuntime(db, nil), "/x"+rng, map[string]string{"id": strconv.Itoa(2)}) // only a stale instance
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || len(out.Events) != 0 {
		t.Fatalf("a service with no live instance has no host events: %s", rec.Body.String())
	}
}
