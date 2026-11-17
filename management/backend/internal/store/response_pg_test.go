package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Runs against a real Postgres when OW_TEST_PG is set: applies migration 044,
// creates a minimal events table and exercises the response/hunt store.
func TestResponseAndHuntStorePG(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG")
	if dsn == "" {
		t.Skip("OW_TEST_PG not set")
	}
	sdb, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	mig, err := os.ReadFile("migrations/044_response_and_hunt.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // twice: the migration must be idempotent
		if _, err := sdb.Exec(string(mig)); err != nil {
			t.Fatalf("migration run %d: %v", i+1, err)
		}
	}
	sdb.Exec(`DROP TABLE IF EXISTS events`)
	if _, err := sdb.Exec(`CREATE TABLE events (id text primary key, time timestamptz, ingested_at timestamptz default now(), agent_id text, host text, os text,
		event_type text, severity int, source text, raw jsonb, pid int, ppid int, process_name text, command_line text, image_path text, user_name text,
		domain text, logon_id text, src_ip text, src_port int, dst_ip text, dst_port int, proto text, reg_key text, reg_value text, reg_data text,
		file_path text, file_hash text, event_id bigint, channel text, record_id bigint, process_guid text, parent_process_guid text)`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ins := func(id, agent, host, typ, cmd string, ago time.Duration) {
		_, err := sdb.Exec(`INSERT INTO events (id,time,agent_id,host,os,event_type,severity,source,raw,command_line) VALUES ($1,$2,$3,$4,'windows',$5,2,'sysmon','{}',$6)`,
			id, now.Add(-ago), agent, host, typ, cmd)
		if err != nil {
			t.Fatal(err)
		}
	}
	ins("1", "a1", "LAP1", "process", "powershell -enc AAAA", time.Hour)
	ins("2", "a1", "LAP1", "process", "powershell -enc BBBB", time.Minute)
	ins("3", "a2", "SRV2", "process", "powershell -enc CCCC", 2*time.Minute)
	ins("4", "a2", "SRV2", "network", "", time.Minute)
	ins("5", "a3", "LAP3", "process", "notepad", time.Minute)

	db := &DB{DB: sdb}
	ctx := context.Background()

	// historical rollup: hosts that ran encoded PowerShell
	e, err := ParseEventQuery(`type:process cmd:"-enc"`)
	if err != nil {
		t.Fatal(err)
	}
	hosts, total, err := db.HuntRollup(ctx, EventFilter{Expr: e, Since: now.Add(-24 * time.Hour)}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(hosts) != 2 || hosts[0].Host != "LAP1" || hosts[0].Count != 2 || hosts[1].Count != 1 {
		t.Fatalf("rollup: total=%d %+v", total, hosts)
	}
	if len(hosts[0].EventTypes) != 1 || hosts[0].EventTypes[0] != "process" || hosts[0].Sample == "" {
		t.Fatalf("rollup detail: %+v", hosts[0])
	}
	// QueryEvents must still behave after the where-builder refactor
	evs, n, err := db.QueryEvents(ctx, EventFilter{Expr: e, Since: now.Add(-24 * time.Hour), Limit: 10})
	if err != nil || n != 3 || len(evs) != 3 {
		t.Fatalf("QueryEvents: %v n=%d len=%d", err, n, len(evs))
	}

	// response actions + state
	if err := db.CreateResponseAction(ctx, ResponseAction{ID: "act1", AgentID: "a1", Hostname: "LAP1", Action: "isolate", Status: "pending", RequestedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteResponseAction(ctx, "act1", "ok", "isolated", json.RawMessage(`{"isolated":true}`)); err != nil {
		t.Fatal(err)
	}
	acts, err := db.ListResponseActions(ctx, "a1", 10)
	if err != nil || len(acts) != 1 || acts[0].Status != "ok" || acts[0].CompletedAt == nil {
		t.Fatalf("actions: %v %+v", err, acts)
	}
	if err := db.SetDesiredIsolation(ctx, "a1", true, 30); err != nil {
		t.Fatal(err)
	}
	st := db.GetRespState(ctx, "a1")
	if !st.DesiredIsolated || st.DesiredTTLMin != 30 || st.Isolated {
		t.Fatalf("desired: %+v", st)
	}
	since := now
	if err := db.SetReportedState(ctx, "a1", true, &since, nil, 2); err != nil {
		t.Fatal(err)
	}
	st = db.GetRespState(ctx, "a1")
	if !st.Isolated || !st.DesiredIsolated || st.Quarantined != 2 || st.IsolatedSince == nil {
		t.Fatalf("reported: %+v", st)
	}
	iso, err := db.IsolatedAgents(ctx)
	if err != nil || len(iso) != 1 {
		t.Fatalf("isolated list: %v %+v", err, iso)
	}
	db.SetDesiredIsolation(ctx, "a1", false, 0)
	db.SetReportedState(ctx, "a1", false, nil, nil, 2)
	if iso, _ := db.IsolatedAgents(ctx); len(iso) != 0 {
		t.Fatalf("released host still listed: %+v", iso)
	}

	// live fleet hunt lifecycle
	h := FleetHunt{ID: "hunt1", Name: "t", Kind: "processes", Match: "x", RequestedBy: "admin"}
	if err := db.CreateFleetHunt(ctx, h, []Agent{{ID: "a1", Hostname: "LAP1", OS: "windows"}, {ID: "a2", Hostname: "SRV2", OS: "linux"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteHuntResult(ctx, "hunt1", "a1", "ok", "2 row(s)", json.RawMessage(`["pid","name"]`), json.RawMessage(`[["1","a"],["2","b"]]`), 2, false); err != nil {
		t.Fatal(err)
	}
	got, res, err := db.GetFleetHunt(ctx, "hunt1")
	if err != nil || got.Responded != 1 || got.Hosts != 1 || got.Rows != 2 || got.CompletedAt != nil || len(res) != 2 {
		t.Fatalf("hunt midway: %v %+v", err, got)
	}
	if err := db.TimeoutHunt(ctx, "hunt1"); err != nil {
		t.Fatal(err)
	}
	got, res, _ = db.GetFleetHunt(ctx, "hunt1")
	if got.CompletedAt == nil || got.Responded != 2 {
		t.Fatalf("hunt after timeout: %+v", got)
	}
	for _, r := range res {
		if r.AgentID == "a2" && r.Status != "timeout" {
			t.Fatalf("a2 status %s", r.Status)
		}
		if r.AgentID == "a1" && r.Status != "ok" {
			t.Fatalf("a1 must keep its answer, got %s", r.Status)
		}
	}
	if l, err := db.ListFleetHunts(ctx, 10); err != nil || len(l) == 0 {
		t.Fatalf("list: %v", err)
	}
	sdb.Exec(`DELETE FROM fleet_hunts; DELETE FROM response_actions; DELETE FROM agent_response_state`)
}
