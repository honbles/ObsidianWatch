package api

// response_actions.go - one-click response: isolate / release a host, kill a
// process, quarantine / restore a file. Actions travel over the agent's
// existing live-response tunnel (so they need live_response.enabled on the
// agent) and every one is recorded with who asked, why, and the outcome.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// ── broker: matches action results coming back on the tunnel to requests ─────

type actionResult struct {
	OK      bool            `json:"ok"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type actionBroker struct {
	mu      sync.Mutex
	waiters map[string]func(actionResult)
	owner   map[string]string // token -> agent that was asked (A3)
}

func newActionBroker() *actionBroker {
	return &actionBroker{waiters: map[string]func(actionResult){}, owner: map[string]string{}}
}

// expect registers cb for token, sent to agentID. If no result arrives within
// ttl, cb receives a timeout result so nothing stays "sent" forever.
func (b *actionBroker) expect(agentID, token string, ttl time.Duration, cb func(actionResult)) {
	b.mu.Lock()
	b.waiters[token] = cb
	b.owner[token] = agentID
	b.mu.Unlock()
	time.AfterFunc(ttl, func() {
		b.mu.Lock()
		f, ok := b.waiters[token]
		delete(b.waiters, token)
		delete(b.owner, token)
		b.mu.Unlock()
		if ok {
			f(actionResult{Message: "timeout: the agent did not answer in time"})
		}
	})
}

// deliverFrom accepts a result frame read from agentID's tunnel. A3: a result
// for a token issued to another agent is dropped, so one agent cannot answer
// (or forge the outcome of) an action sent to another.
func (b *actionBroker) deliverFrom(agentID, token string, payload json.RawMessage) bool {
	b.mu.Lock()
	owner, known := b.owner[token]
	b.mu.Unlock()
	if !known || owner != agentID {
		return false
	}
	b.deliver(token, payload)
	return true
}

// deliver completes token with payload. Server-side use only (send errors);
// frames from agents go through deliverFrom.
func (b *actionBroker) deliver(token string, payload json.RawMessage) {
	b.mu.Lock()
	f, ok := b.waiters[token]
	delete(b.waiters, token)
	delete(b.owner, token)
	b.mu.Unlock()
	if !ok {
		return
	}
	var r actionResult
	if err := json.Unmarshal(payload, &r); err != nil {
		r = actionResult{Message: "unreadable result from agent"}
	}
	f(r)
}

func newToken() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sendAction writes an action frame to the agent's tunnel.
func sendAction(t *agentTunnel, token, action string, params json.RawMessage) error {
	if len(params) == 0 {
		params = json.RawMessage(`{}`)
	}
	p, _ := json.Marshal(map[string]json.RawMessage{"action": json.RawMessage(strconvQuote(action)), "params": params})
	return t.sendJSON(wireMsg{Type: "action", Token: token, Payload: p})
}

func strconvQuote(s string) string { b, _ := json.Marshal(s); return string(b) }

// ── request validation ───────────────────────────────────────────────────────

var winAbs = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

func absPath(p string) bool {
	return strings.HasPrefix(p, "/") || winAbs.MatchString(p) || strings.HasPrefix(p, `\\`)
}

type actionParams struct {
	PID        int    `json:"pid,omitempty"`
	Image      string `json:"image,omitempty"`
	Tree       bool   `json:"tree,omitempty"`
	Path       string `json:"path,omitempty"`
	ID         string `json:"id,omitempty"`
	TTLMinutes int    `json:"ttl_minutes,omitempty"`
}

var quarIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// validateAction returns an error message for a bad request, "" when fine.
func validateAction(action string, p actionParams) string {
	switch action {
	case "isolate":
		if p.TTLMinutes < 0 || p.TTLMinutes > 7*24*60 {
			return "ttl_minutes must be between 0 and 10080"
		}
	case "release", "list_quarantine", "list_blocked":
	case "kill_process":
		if p.PID <= 1 || p.PID > 4194304 {
			return "a valid pid is required"
		}
		if len(p.Image) > 1024 {
			return "image too long"
		}
	case "block_process", "unblock_process":
		if !absPath(p.Path) || len(p.Path) > 2048 || strings.ContainsRune(p.Path, 0) {
			return "the full path of the program is required"
		}
	case "quarantine_file":
		if !absPath(p.Path) || len(p.Path) > 2048 || strings.ContainsRune(p.Path, 0) {
			return "an absolute file path is required"
		}
	case "restore_file":
		if !quarIDRe.MatchString(p.ID) {
			return "a valid quarantine id is required"
		}
	default:
		return "unknown action"
	}
	return ""
}

func actor(r *http.Request) string {
	if c := auth.GetClaims(r); c != nil {
		return c.Username
	}
	return "admin"
}

// ── POST /api/v1/agents/{id}/actions ─────────────────────────────────────────

func handleAgentAction(db *store.DB, reg *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		var req struct {
			Action  string       `json:"action"`
			Params  actionParams `json:"params"`
			Reason  string       `json:"reason"`
			AlertID string       `json:"alert_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if msg := validateAction(req.Action, req.Params); msg != "" {
			writeJSON(w, 400, map[string]string{"error": msg})
			return
		}
		agent, err := db.GetAgent(r.Context(), agentID)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "agent not found"})
			return
		}
		if len(req.Reason) > 500 {
			req.Reason = req.Reason[:500]
		}
		by := actor(r)
		pj, _ := json.Marshal(req.Params)
		act := store.ResponseAction{
			ID: newToken(), AgentID: agentID, Hostname: agent.Hostname, Action: req.Action, Params: pj,
			Status: "pending", RequestedBy: by, Reason: req.Reason, AlertID: req.AlertID,
		}

		// Desired isolation state is recorded first so it survives an offline host.
		if req.Action == "isolate" || req.Action == "release" {
			if err := db.SetDesiredIsolation(r.Context(), agentID, req.Action == "isolate", req.Params.TTLMinutes); err != nil {
				writeJSON(w, 500, map[string]string{"error": "db error"})
				return
			}
		}

		tunnel, online := reg.Get(agentID)
		if !online {
			if req.Action == "isolate" || req.Action == "release" {
				act.Status, act.Message = "queued", "host is offline; this will be applied as soon as it reconnects"
				_ = db.CreateResponseAction(r.Context(), act)
				db.WriteAudit(r.Context(), by, "response_"+req.Action, "agent:"+agentID, "queued (offline) "+req.Reason, clientIP(r))
				writeJSON(w, 202, act)
				return
			}
			writeJSON(w, 409, map[string]string{"error": "agent is offline or its Live Response tunnel is not connected; this action needs a live agent"})
			return
		}

		if err := db.CreateResponseAction(r.Context(), act); err != nil {
			writeJSON(w, 500, map[string]string{"error": "db error"})
			return
		}
		db.WriteAudit(r.Context(), by, "response_"+req.Action, "agent:"+agentID, string(pj)+" "+req.Reason, clientIP(r))
		logger.Warn("response action", "agent", agentID, "action", req.Action, "by", by)

		done := make(chan actionResult, 1)
		reg.broker.expect(agentID, act.ID, 3*time.Minute, func(res actionResult) {
			status := "ok"
			if !res.OK {
				status = "failed"
				if strings.HasPrefix(res.Message, "timeout") {
					status = "timeout"
				}
			}
			_ = db.CompleteResponseAction(context.Background(), act.ID, status, res.Message, res.Data)
			done <- res
		})
		if err := sendAction(tunnel, act.ID, req.Action, pj); err != nil {
			reg.broker.deliver(act.ID, mustJSON(actionResult{Message: "could not reach the agent: " + err.Error()}))
		} else {
			_ = db.SetResponseActionStatus(r.Context(), act.ID, "sent")
		}

		select {
		case <-done:
		case <-time.After(100 * time.Second):
			// still running; the UI polls the action list
			writeJSON(w, 202, map[string]string{"id": act.ID, "status": "sent", "message": "still running; check the action history"})
			return
		case <-r.Context().Done():
			return
		}
		list, _ := db.ListResponseActions(r.Context(), agentID, 20)
		for _, a := range list {
			if a.ID == act.ID {
				code := 200
				if a.Status != "ok" {
					code = 502
				}
				writeJSON(w, code, a)
				return
			}
		}
		writeJSON(w, 200, act)
	}
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

// ── GET /api/v1/agents/{id}/response ─────────────────────────────────────────

func handleAgentResponseState(db *store.DB, reg *TunnelRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		_, online := reg.Get(id)
		acts, _ := db.ListResponseActions(r.Context(), id, 30)
		writeJSON(w, 200, map[string]any{
			"state":         db.GetRespState(r.Context(), id),
			"tunnel_online": online,
			"actions":       acts,
		})
	}
}

// GET /api/v1/response/isolated - small list used to badge hosts in lists.
func handleIsolatedAgents(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l, err := db.IsolatedAgents(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, 200, map[string]any{"agents": l})
	}
}

// GET /api/v1/response/actions - fleet-wide recent actions.
func handleResponseActions(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l, err := db.ListResponseActions(r.Context(), "", 100)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, 200, map[string]any{"actions": l})
	}
}

// ── tunnel hooks ─────────────────────────────────────────────────────────────

type agentRespState struct {
	Isolated    bool       `json:"isolated"`
	Since       *time.Time `json:"since"`
	Expires     *time.Time `json:"expires"`
	Quarantined int        `json:"quarantined"`
}

func zeroNil(t *time.Time) *time.Time {
	if t == nil || t.IsZero() || t.Year() < 2000 {
		return nil
	}
	return t
}

// onResponseState records what the agent reported. On the FIRST report after a
// (re)connect it also reconciles: if we want the host isolated and it is not
// (or the reverse) the missing action is sent. Reconciling only once per
// connection means a failing isolate cannot loop.
func onResponseState(db *store.DB, t *agentTunnel, agentID string, payload json.RawMessage, first bool, logger *slog.Logger) {
	var st agentRespState
	if json.Unmarshal(payload, &st) != nil {
		return
	}
	ctx := context.Background()
	_ = db.SetReportedState(ctx, agentID, st.Isolated, zeroNil(st.Since), zeroNil(st.Expires), st.Quarantined)
	if !first {
		return
	}
	want := db.GetRespState(ctx, agentID)
	if want.DesiredIsolated && want.DesiredExpires != nil && time.Now().After(*want.DesiredExpires) {
		_ = db.SetDesiredIsolation(ctx, agentID, false, 0) // isolation window elapsed while offline
		want.DesiredIsolated = false
	}
	var action string
	var params json.RawMessage
	switch {
	case want.DesiredIsolated && !st.Isolated:
		ttl := 0
		if want.DesiredExpires != nil {
			ttl = int(time.Until(*want.DesiredExpires).Minutes()) + 1 // the time that is left, not a fresh window
		}
		action, params = "isolate", mustJSON(map[string]int{"ttl_minutes": ttl})
	case !want.DesiredIsolated && st.Isolated:
		action = "release"
	default:
		return
	}
	agent, _ := db.GetAgent(ctx, agentID)
	host := ""
	if agent != nil {
		host = agent.Hostname
	}
	act := store.ResponseAction{ID: newToken(), AgentID: agentID, Hostname: host, Action: action, Params: params,
		Status: "sent", RequestedBy: "system", Reason: "reconcile after reconnect"}
	if err := db.CreateResponseAction(ctx, act); err != nil {
		return
	}
	logger.Warn("response: reconciling isolation state", "agent", agentID, "action", action)
	// The result frame is correlated by the broker like any other action.
	brokerFor(t).expect(agentID, act.ID, 3*time.Minute, func(res actionResult) {
		status := "ok"
		if !res.OK {
			status = "failed"
		}
		_ = db.CompleteResponseAction(ctx, act.ID, status, res.Message, res.Data)
	})
	if err := sendAction(t, act.ID, action, params); err != nil {
		brokerFor(t).deliver(act.ID, mustJSON(actionResult{Message: err.Error()}))
	}
}

var _ = fmt.Sprintf

// GET /api/v1/agents/{id}/processes - live process list (pid, ppid, user, name, memory, path,
// command line) read from the host right now through the Live Response tunnel. Read-only.
func handleAgentProcesses(db *store.DB, reg *TunnelRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		t, up := reg.Get(id)
		if !up {
			writeJSON(w, 409, map[string]string{"error": "agent is offline or its Live Response tunnel is not connected"})
			return
		}
		tok := newToken()
		ch := make(chan actionResult, 1)
		reg.broker.expect(id, tok, 40*time.Second, func(res actionResult) { ch <- res })
		if err := sendAction(t, tok, "query", mustJSON(map[string]any{"kind": "processes", "limit": 5000})); err != nil {
			reg.broker.deliver(tok, mustJSON(actionResult{Message: "could not reach the agent: " + err.Error()}))
		}
		select {
		case res := <-ch:
			if !res.OK {
				writeJSON(w, 502, map[string]string{"error": res.Message})
				return
			}
			var tb json.RawMessage = res.Data
			writeJSON(w, 200, map[string]any{"table": tb, "at": time.Now().UTC()})
		case <-r.Context().Done():
		}
	}
}

// DELETE /api/v1/agents/{id} - remove a stale agent record (for example the old record left
// behind when a machine is renamed or re-imaged, since an agent's identity is its host name).
// Refused while the agent is connected or has reported within the last 10 minutes.
func handleDeleteAgent(db *store.DB, reg *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		a, err := db.GetAgent(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "agent not found"})
			return
		}
		if _, up := reg.Get(id); up || time.Since(a.LastSeen) < 10*time.Minute {
			writeJSON(w, 409, map[string]string{"error": "this agent reported within the last 10 minutes; only offline agents can be removed"})
			return
		}
		if err := db.DeleteAgent(r.Context(), id); err != nil {
			writeJSON(w, 409, map[string]string{"error": "could not remove: " + err.Error()})
			return
		}
		db.WriteAudit(r.Context(), actor(r), "agent_removed", "agent:"+id, a.Hostname+" "+a.LastIP, clientIP(r))
		logger.Warn("agent record removed", "agent", id, "by", actor(r))
		writeJSON(w, 200, map[string]string{"status": "removed"})
	}
}
