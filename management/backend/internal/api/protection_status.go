package api

// protection_status.go - GET /api/v1/agents/{id}/protection: whether a host is protected, and the proof.
//
// It combines what the server intends for the host (the prevention policy, after the canary tags), what the
// agent last reported in its health heartbeat (the modes it applies, its list, the kernel block, and 24-hour
// counters of files, programs, connections and DNS answers checked and threats stopped), the latest
// protection test (Pass once the agent's prevention event for the planted test file arrives) and the
// latest scan. Scans and tests are response actions (scan, test_protection) on POST /agents/{id}/actions.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// prevTestSource is the ioc_source of a protection test's indicator (agents' prevention.TestSource).
const prevTestSource = "obsidianwatch-test"

const (
	protHeartbeatStale = 10 * time.Minute
	protListStale      = 2 * time.Hour
	protTestTimeout    = 3 * time.Minute
)

type protTest struct {
	Status    string    `json:"status"` // pending | pass | fail
	Detail    string    `json:"detail"`
	Started   time.Time `json:"started"`
	Action    string    `json:"action,omitempty"` // what the agent did: quarantined, audit...
	Folder    string    `json:"folder,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

// protVerdict: protected | audit | off | unknown, with a reason.
func protVerdict(reported map[string]any, hbAge time.Duration, online bool) (string, string) {
	if reported == nil {
		return "unknown", "This agent does not report its protection state yet; update it to see this."
	}
	if en, ok := reported["enabled"].(bool); ok && !en {
		return "off", "Prevention is turned off in this agent's configuration."
	}
	if !online || hbAge > protHeartbeatStale {
		return "unknown", "The agent has not reported for a while; this is its last known state."
	}
	modes, _ := reported["modes"].(map[string]any)
	enforce, audit := 0, 0
	for _, k := range []string{"hash", "ip", "domain"} {
		switch modes[k] {
		case PrevEnforce:
			enforce++
		case PrevAudit:
			audit++
		}
	}
	if lc, ok := reported["list_counts"].(map[string]any); ok && enforce+audit > 0 {
		total := 0.0
		for _, v := range lc {
			f, _ := v.(float64)
			total += f
		}
		if total == 0 {
			return "off", "The host's malicious list is empty, so nothing can be matched. Check that the server can reach its threat feeds (Platform settings → Threat intelligence) or add indicators."
		}
	}
	if s, ok := reported["list_received"].(string); ok {
		if t, err := time.Parse(time.RFC3339, s); err == nil && time.Since(t) > protListStale {
			return "audit", "The host's malicious list is more than 2 hours old: it cannot reach the server for updates."
		}
	}
	switch {
	case enforce > 0 && modes["hash"] == PrevEnforce:
		return "protected", "Known malicious files, programs and connections are stopped."
	case enforce > 0:
		return "protected", "Some threat types are stopped; the others are only reported."
	case audit > 0:
		return "audit", "Threats are detected and alerted on, but nothing is stopped (audit mode)."
	}
	return "off", "Every prevention type is off for this host."
}

func latestEvent(ctx context.Context, db *store.DB, agentID, eventType string, since time.Time) (*store.Event, error) {
	evs, _, err := db.QueryEvents(ctx, store.EventFilter{AgentID: agentID, EventType: eventType, Since: since, Limit: 1, SkipCount: true})
	if err != nil || len(evs) == 0 {
		return nil, err
	}
	return &evs[0], nil
}

func rawMap(raw json.RawMessage) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

// testResult works out the latest protection test from its action record and the agent's events.
func testResult(ctx context.Context, db *store.DB, agentID string, acts []store.ResponseAction) *protTest {
	var act *store.ResponseAction
	for i := range acts {
		if acts[i].Action == "test_protection" {
			act = &acts[i]
			break
		}
	}
	if act == nil {
		return nil
	}
	t := &protTest{Status: "pending", Started: act.RequestedAt, Detail: "Waiting for the agent to find the test file."}
	switch act.Status {
	case "failed", "timeout":
		t.Status, t.Detail = "fail", act.Message
		return t
	case "pending", "sent", "queued":
		if time.Since(act.RequestedAt) > protTestTimeout {
			t.Status, t.Detail = "fail", "The agent did not answer the test request."
		}
		return t
	}
	data := rawMap(act.Result)
	sum, _ := data["sha256"].(string)
	t.Folder, _ = data["folder"].(string)
	if sum == "" {
		t.Status, t.Detail = "fail", "The agent did not report the test file."
		return t
	}
	evs, _, err := db.QueryEvents(ctx, store.EventFilter{AgentID: agentID, EventType: "prevention", Since: act.RequestedAt.Add(-time.Minute),
		Expr: mustQuery("hash:" + sum), Limit: 5, SkipCount: true})
	if err == nil {
		for _, ev := range evs {
			r := rawMap(ev.Raw)
			if r["ioc_source"] != prevTestSource {
				continue
			}
			t.Action, _ = r["action"].(string)
			t.CheckedAt = ev.Time
			switch t.Action {
			case "quarantined", "killed", "killed+quarantined", "blocked":
				t.Status, t.Detail = "pass", "The agent found the test file in "+t.Folder+" and quarantined it."
			case "audit":
				t.Status, t.Detail = "pass", "The agent found the test file and reported it. Files are in audit mode, so it was left in place."
			default:
				t.Status, t.Detail = "fail", "The agent found the test file but could not act on it: "+t.Action
			}
			return t
		}
	}
	if time.Since(act.RequestedAt) > protTestTimeout {
		t.Status, t.Detail = "fail", "The agent wrote the test file but did not detect it within 3 minutes."
	}
	return t
}

func mustQuery(q string) *store.QueryExpr {
	e, _ := store.ParseEventQuery(q)
	return e
}

func handleAgentProtection(db *store.DB, reg *TunnelRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		id := r.PathValue("id")
		agent, err := db.GetAgent(ctx, id)
		if err != nil || agent == nil {
			writeJSON(w, 404, map[string]string{"error": "agent not found"})
			return
		}
		_, tunnel := reg.Get(id)
		pol := loadPreventionPolicy(ctx, db)
		intended := modesFor(pol, hostTags(ctx, db, agent.Hostname))
		out := map[string]any{"intended_modes": intended, "canary_tags": pol.EnforceTags, "tunnel_online": tunnel}

		var reported map[string]any
		var hbAge time.Duration = -1
		if hb, _ := latestEvent(ctx, db, id, "health", time.Now().Add(-24*time.Hour)); hb != nil {
			hbAge = time.Since(hb.Time)
			out["reported_at"] = hb.Time
			if p, ok := rawMap(hb.Raw)["protection"].(map[string]any); ok {
				reported = p
				out["reported"] = p
			}
		}
		verdict, why := protVerdict(reported, hbAge, agent.Online)
		out["verdict"], out["verdict_detail"] = verdict, why

		since := time.Now().Add(-24 * time.Hour)
		if evs, _, err := db.QueryEvents(ctx, store.EventFilter{AgentID: id, EventType: "prevention", Since: since, Limit: 500, SkipCount: true}); err == nil {
			stopped, matched := 0, 0
			for _, ev := range evs {
				p := rawMap(ev.Raw)
				if p["ioc_source"] == prevTestSource {
					continue
				}
				matched++
				if a, _ := p["action"].(string); prevStopped(a) {
					stopped++
				}
			}
			out["threats_24h"] = map[string]int{"matched": matched, "stopped": stopped}
		}
		acts, _ := db.ListResponseActions(ctx, id, 50)
		if t := testResult(ctx, db, id, acts); t != nil {
			out["test"] = t
		}
		for _, a := range acts {
			if a.Action == "scan" {
				sc := map[string]any{"requested_at": a.RequestedAt, "status": a.Status, "message": a.Message, "requested_by": a.RequestedBy}
				if ev, _ := latestEvent(ctx, db, id, "prevention_scan", a.RequestedAt.Add(-time.Minute)); ev != nil {
					res := rawMap(ev.Raw)
					if ex, ok := res["executables"].([]any); ok {
						res["executables_checked"] = len(ex)
						delete(res, "executables")
					}
					sc["result"], sc["status"] = res, "finished"
				} else if a.Status == "ok" {
					sc["status"] = "running"
				}
				out["scan"] = sc
				break
			}
		}
		writeJSON(w, 200, out)
	}
}

// ingestScanHashes queues the executables a scan reported for the tiered reputation lookups, like hashes
// seen in file events.
func (e *VirusTotalEngine) ingestScanHashes(ctx context.Context) {
	rows, err := e.db.QueryContext(ctx, `SELECT host, raw->'executables' FROM events
		WHERE event_type = 'prevention_scan' AND time > NOW() - INTERVAL '1 hour' ORDER BY time DESC LIMIT 20`)
	if err != nil {
		return
	}
	type ex struct{ SHA256, Path string }
	var all []struct {
		host string
		list []ex
	}
	for rows.Next() {
		var host string
		var raw []byte
		if rows.Scan(&host, &raw) != nil {
			continue
		}
		var list []ex
		_ = json.Unmarshal(raw, &list)
		all = append(all, struct {
			host string
			list []ex
		}{host, list})
	}
	rows.Close()
	queued := 0
	for _, s := range all {
		for _, x := range s.list {
			h := normalizeHash(x.SHA256)
			if len(h) != 64 {
				continue
			}
			name := x.Path
			if i := strings.LastIndexAny(name, `/\`); i >= 0 {
				name = name[i+1:]
			}
			res, err := e.db.ExecContext(ctx, `
				INSERT INTO file_hash_cache (hash, file_name, vt_verdict, first_seen, last_seen, last_host)
				VALUES ($1, $2, 'queued', NOW(), NOW(), $3) ON CONFLICT (hash) DO NOTHING`, h, name, s.host)
			if err == nil {
				if n, _ := res.RowsAffected(); n > 0 {
					queued++
				}
			}
		}
	}
	if queued > 0 {
		e.logger.Info("hash-intel: scan executables queued", "count", queued)
	}
}
