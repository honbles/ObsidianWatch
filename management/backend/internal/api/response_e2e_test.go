package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"

	"obsidianwatch/management/internal/agentid"
	"obsidianwatch/management/internal/store"
)

// fakeAgent speaks the real tunnel protocol: it connects, reports its
// isolation state, answers actions, and records what it was asked.
type fakeAgent struct {
	t        *testing.T
	conn     *websocket.Conn
	mu       sync.Mutex
	isolated bool
	got      []string // actions received
	failKill bool
	wmu      sync.Mutex
}

func (a *fakeAgent) send(v any) {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	_ = a.conn.WriteJSON(v)
}

func (a *fakeAgent) state() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string]any{"type": "response_state", "payload": map[string]any{"isolated": a.isolated, "quarantined": 0}}
}

const (
	e2eA1     = "ag-0000000000000000000000000000e2e1"
	e2eA2     = "ag-0000000000000000000000000000e2e2"
	e2eSecret = "e2e-secret"
)

// connectFakeAgent opens a tunnel the way the ingest backend passes one on:
// with the agent identity in signed headers.
func connectFakeAgent(t *testing.T, srvURL, id string, isolated bool) *fakeAgent {
	ts := time.Now().Unix()
	hdr := http.Header{}
	hdr.Set(hdrAgentID, id)
	hdr.Set(hdrAgentSerial, "e2e")
	hdr.Set(hdrAgentTime, strconv.FormatInt(ts, 10))
	hdr.Set(hdrAgentSig, signTunnelIdentity(tunnelIdentityKey(e2eSecret), id, "e2e", ts))
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srvURL, "http")+"/tunnel?agent_id="+id, hdr)
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeAgent{t: t, conn: c, isolated: isolated}
	a.send(a.state())
	go func() {
		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			var env struct {
				Type    string          `json:"type"`
				Token   string          `json:"token"`
				Payload json.RawMessage `json:"payload"`
			}
			if json.Unmarshal(msg, &env) != nil || env.Type != "action" {
				continue
			}
			var req struct {
				Action string         `json:"action"`
				Params map[string]any `json:"params"`
			}
			_ = json.Unmarshal(env.Payload, &req)
			a.mu.Lock()
			a.got = append(a.got, req.Action)
			res := map[string]any{"ok": true, "message": req.Action + " done"}
			switch req.Action {
			case "isolate":
				a.isolated = true
			case "release":
				a.isolated = false
			case "kill_process":
				if a.failKill {
					res = map[string]any{"ok": false, "message": "pid is now bash, not evil.exe (PID reused); not killed"}
				}
			case "query":
				res["data"] = map[string]any{"columns": []string{"pid", "name"}, "rows": [][]string{{"10", "powershell.exe"}, {"11", "cmd.exe"}}}
			}
			a.mu.Unlock()
			a.send(map[string]any{"type": "action_result", "token": env.Token, "payload": res})
			a.send(a.state())
		}
	}()
	return a
}

func (a *fakeAgent) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.got...)
}

func waitFor(t *testing.T, what string, f func() bool) {
	for i := 0; i < 100; i++ {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Runs the whole response/hunt flow (tunnel, broker, DB) against a real
// Postgres holding the migrated schema, with a simulated agent.
func TestResponseAndHuntEndToEnd(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_FULL")
	if dsn == "" {
		t.Skip("OW_TEST_PG_FULL not set")
	}
	sdb, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	sdb.Exec(`DELETE FROM response_actions; DELETE FROM agent_response_state; DELETE FROM fleet_hunts; DELETE FROM agents WHERE id LIKE 'ag-%e2e_'`)
	for _, id := range []string{e2eA1, e2eA2} {
		if _, err := sdb.Exec(`INSERT INTO agents (id, hostname, os, version) VALUES ($1, $1, 'windows', '1')`, id); err != nil {
			t.Fatal(err)
		}
	}
	db := &store.DB{DB: sdb}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := NewTunnelRegistry()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tunnel", handleAgentTunnel(db, reg, logger, &tunnelAuth{rev: agentid.NewRevocations(nil), now: time.Now, fwdKey: tunnelIdentityKey(e2eSecret)}))
	mux.HandleFunc("POST /agents/{id}/actions", handleAgentAction(db, reg, logger))
	mux.HandleFunc("POST /hunt", handleStartFleetHunt(db, reg, logger))
	mux.HandleFunc("GET /hunt/{id}", handleGetFleetHunt(db))
	mux.HandleFunc("GET /agents/{id}/response", handleAgentResponseState(db, reg))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	// the real tunnel route lives under /api/v1/live-response/agent-tunnel; same handler
	post := func(path string, body any) (int, map[string]any) {
		b, _ := json.Marshal(body)
		resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}

	// 1. online isolate
	a1 := connectFakeAgent(t, srv.URL, e2eA1, false)
	waitFor(t, "tunnel registration", func() bool { _, ok := reg.Get(e2eA1); return ok })
	code, m := post("/agents/"+e2eA1+"/actions", map[string]any{"action": "isolate", "params": map[string]any{"ttl_minutes": 30}, "reason": "ransomware"})
	if code != 200 || m["status"] != "ok" {
		t.Fatalf("isolate: %d %v", code, m)
	}
	waitFor(t, "reported isolated", func() bool { return db.GetRespState(t.Context(), e2eA1).Isolated })
	st := db.GetRespState(t.Context(), e2eA1)
	if !st.DesiredIsolated || st.DesiredTTLMin != 30 {
		t.Fatalf("state: %+v", st)
	}

	// 2. a failing action is reported as failed, not swallowed
	a1.failKill = true
	code, m = post("/agents/"+e2eA1+"/actions", map[string]any{"action": "kill_process", "params": map[string]any{"pid": 4242, "image": "evil.exe"}})
	if code != 502 || m["status"] != "failed" || !strings.Contains(m["message"].(string), "PID reused") {
		t.Fatalf("failed kill: %d %v", code, m)
	}

	// 3. validation and unknown agent
	if code, _ = post("/agents/"+e2eA1+"/actions", map[string]any{"action": "kill_process", "params": map[string]any{"pid": 1}}); code != 400 {
		t.Fatalf("pid 1 accepted: %d", code)
	}
	if code, _ = post("/agents/nope/actions", map[string]any{"action": "release"}); code != 404 {
		t.Fatalf("unknown agent: %d", code)
	}

	// 4. history recorded with the requester and reason
	acts, _ := db.ListResponseActions(t.Context(), e2eA1, 10)
	if len(acts) != 2 {
		t.Fatalf("history: %+v", acts)
	}
	for _, a := range acts {
		if a.Action == "isolate" && (a.Status != "ok" || a.Reason != "ransomware" || a.RequestedBy != "admin") {
			t.Fatalf("isolate row: %+v", a)
		}
	}

	// 5. offline: isolate is queued, kill is refused; reconnect reconciles
	a1.conn.Close()
	waitFor(t, "tunnel gone", func() bool { _, ok := reg.Get(e2eA1); return !ok })
	if code, m = post("/agents/"+e2eA1+"/actions", map[string]any{"action": "kill_process", "params": map[string]any{"pid": 77}}); code != 409 {
		t.Fatalf("offline kill: %d %v", code, m)
	}
	post("/agents/"+e2eA1+"/actions", map[string]any{"action": "release"}) // queued: desired=not isolated
	if s := db.GetRespState(t.Context(), e2eA1); s.DesiredIsolated {
		t.Fatal("desired state not updated while offline")
	}
	// the host comes back still isolated (it kept its rules): the server must release it
	b1 := connectFakeAgent(t, srv.URL, e2eA1, true)
	waitFor(t, "reconcile release", func() bool {
		for _, x := range b1.actions() {
			if x == "release" {
				return true
			}
		}
		return false
	})
	waitFor(t, "reported released", func() bool { return !db.GetRespState(t.Context(), e2eA1).Isolated })
	// a rebooted host that lost its rules while we want it isolated gets isolated again
	db.SetDesiredIsolation(t.Context(), e2eA2, true, 0)
	b2 := connectFakeAgent(t, srv.URL, e2eA2, false)
	waitFor(t, "reconcile isolate", func() bool { return len(b2.actions()) == 1 && b2.actions()[0] == "isolate" })
	// an elapsed isolation window must not re-isolate
	b2.conn.Close()
	waitFor(t, "e2e-2 gone", func() bool { _, ok := reg.Get(e2eA2); return !ok })
	sdb.Exec(`UPDATE agent_response_state SET desired_isolated=true, desired_expires_at=now() - interval '1 minute' WHERE agent_id='ag-0000000000000000000000000000e2e2'`)
	b3 := connectFakeAgent(t, srv.URL, e2eA2, false)
	time.Sleep(400 * time.Millisecond)
	if len(b3.actions()) != 0 || db.GetRespState(t.Context(), e2eA2).DesiredIsolated {
		t.Fatalf("expired isolation was re-applied: %v", b3.actions())
	}

	// 6. fleet hunt: both agents are online and answer
	waitFor(t, "both online", func() bool { _, a := reg.Get(e2eA1); _, b := reg.Get(e2eA2); return a && b })
	code, m = post("/hunt", map[string]any{"kind": "processes", "match": "powershell"})
	if code != 202 || m["agents"].(float64) != 2 {
		t.Fatalf("hunt start: %d %v", code, m)
	}
	id := m["id"].(string)
	waitFor(t, "hunt complete", func() bool {
		h, _, err := db.GetFleetHunt(t.Context(), id)
		return err == nil && h.CompletedAt != nil
	})
	h, res, _ := db.GetFleetHunt(t.Context(), id)
	if h.Responded != 2 || h.Hosts != 2 || h.Rows != 4 {
		t.Fatalf("hunt summary: %+v", h)
	}
	if len(res) != 2 || res[0].Status != "ok" || !strings.Contains(string(res[0].Rows), "powershell.exe") {
		t.Fatalf("hunt results: %+v", res)
	}
	// a bad kind and an empty file search are refused
	if code, _ = post("/hunt", map[string]any{"kind": "rm -rf"}); code != 400 {
		t.Fatalf("bad kind: %d", code)
	}
	if code, _ = post("/hunt", map[string]any{"kind": "file_find"}); code != 400 {
		t.Fatalf("empty file_find: %d", code)
	}
	b1.conn.Close()
	b3.conn.Close()
	sdb.Exec(`DELETE FROM response_actions; DELETE FROM agent_response_state; DELETE FROM fleet_hunts; DELETE FROM agents WHERE id LIKE 'ag-%e2e_'`)
}
