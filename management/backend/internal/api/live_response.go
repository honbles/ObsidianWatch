package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// ── WebSocket upgrader ────────────────────────────────────────────────────────

var lrUpgrader = websocket.Upgrader{
	CheckOrigin:     checkWSOrigin,
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
}

// lrMaxSession is the hard cap on a live-response session (F-04).
const lrMaxSession = 60 * time.Minute

// Maximum single WebSocket frame sizes. Analyst input is keystrokes/resize
// messages; agent frames carry terminal output and file chunks.
const (
	lrAnalystMaxFrame = 64 << 10
	lrAgentMaxFrame   = 4 << 20
)

// ── Agent tunnel registry ─────────────────────────────────────────────────────

type agentTunnel struct {
	agentID  string
	conn     *websocket.Conn
	mu       sync.Mutex
	sessions map[string]chan []byte
}

func (t *agentTunnel) sendJSON(v any) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn.WriteJSON(v)
}

// TunnelRegistry maps agentID → active WebSocket tunnel from the agent.
type TunnelRegistry struct {
	mu      sync.RWMutex
	tunnels map[string]*agentTunnel
}

func NewTunnelRegistry() *TunnelRegistry {
	return &TunnelRegistry{tunnels: make(map[string]*agentTunnel)}
}

func (r *TunnelRegistry) Register(agentID string, t *agentTunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tunnels[agentID] = t
}

// UnregisterIf removes the entry only if it is still t, so an old handler
// exiting after a reconnect can't delete the newer, live tunnel (F-05).
func (r *TunnelRegistry) UnregisterIf(agentID string, t *agentTunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tunnels[agentID] == t {
		delete(r.tunnels, agentID)
	}
}

func (r *TunnelRegistry) Unregister(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tunnels, agentID)
}

func (r *TunnelRegistry) Get(agentID string) (*agentTunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tunnels[agentID]
	return t, ok
}

func (r *TunnelRegistry) ConnectedAgents() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.tunnels))
	for id := range r.tunnels {
		ids = append(ids, id)
	}
	return ids
}

// ── Wire message protocol ─────────────────────────────────────────────────────
// All messages between management and agent are JSON envelopes.
// Payload is always json.RawMessage (JSON-encoded []byte for data messages).

type wireMsg struct {
	Type    string          `json:"type"`
	Token   string          `json:"token,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// ── handleAgentTunnel ─────────────────────────────────────────────────────────
// Agent connects here to establish its control tunnel.
// URL: GET /api/v1/live-response/agent-tunnel?agent_id=HOSTNAME

func handleAgentTunnel(db *store.DB, registry *TunnelRegistry, logger *slog.Logger, agentAPIKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.URL.Query().Get("agent_id")
		if agentID == "" {
			http.Error(w, "agent_id required", 400)
			return
		}
		// M-02: without this check, any caller could open a tunnel claiming
		// to be any agent_id, hijacking live-response sessions meant for a
		// real endpoint.
		if !validAgentAPIKey(agentAPIKey, r) {
			http.Error(w, "invalid or missing X-API-Key", 401)
			return
		}
		if _, err := db.GetAgent(r.Context(), agentID); err != nil {
			http.Error(w, "unknown agent_id", 401)
			return
		}

		conn, err := lrUpgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Warn("lr: agent tunnel upgrade failed", "agent", agentID, "err", err)
			return
		}
		conn.SetReadLimit(lrAgentMaxFrame) // bound a single inbound frame

		// Close any stale tunnel already registered for this agent before
		// replacing it, so a crashed/reconnecting agent doesn't leave a
		// dead entry that silently blocks the new, real connection.
		if old, ok := registry.Get(agentID); ok && old != nil {
			old.conn.Close()
		}

		tunnel := &agentTunnel{
			agentID:  agentID,
			conn:     conn,
			sessions: make(map[string]chan []byte),
		}
		registry.Register(agentID, tunnel)
		logger.Info("lr: agent tunnel connected", "agent", agentID)

		// F-05: heartbeat. Ping every 30s; if no pong (or any frame) arrives
		// within 75s the read fails and the stale tunnel is cleaned up, so a
		// silently-dead TCP connection can't show as "connected".
		const pongWait = 75 * time.Second
		conn.SetReadDeadline(time.Now().Add(pongWait))
		conn.SetPongHandler(func(string) error {
			return conn.SetReadDeadline(time.Now().Add(pongWait))
		})
		stopPing := make(chan struct{})
		go func() {
			tk := time.NewTicker(30 * time.Second)
			defer tk.Stop()
			for {
				select {
				case <-stopPing:
					return
				case <-tk.C:
					if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
						conn.Close()
						return
					}
				}
			}
		}()

		defer func() {
			close(stopPing)
			registry.UnregisterIf(agentID, tunnel)
			conn.Close()
			logger.Info("lr: agent tunnel disconnected", "agent", agentID)
		}()

		// Read loop — agent sends data back to waiting analyst connections
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				break
			}
			conn.SetReadDeadline(time.Now().Add(pongWait))
			var env wireMsg
			if err := json.Unmarshal(msg, &env); err != nil {
				continue
			}
			switch env.Type {
			case "data":
				if env.Token == "" {
					continue
				}
				tunnel.mu.Lock()
				ch, ok := tunnel.sessions[env.Token]
				tunnel.mu.Unlock()
				if ok {
					select {
					case ch <- env.Payload: // Payload is json.RawMessage (JSON-encoded []byte)
					default:
					}
				}
			case "session_end":
				if env.Token == "" {
					continue
				}
				tunnel.mu.Lock()
				ch, ok := tunnel.sessions[env.Token]
				if ok {
					delete(tunnel.sessions, env.Token)
					close(ch)
				}
				tunnel.mu.Unlock()
				logger.Info("lr: agent signaled session end", "token", env.Token[:8]+"...")

			case "register_credentials":
				var creds struct {
					Username string `json:"username"`
					Mode     string `json:"mode"`
				}
				// M-05: the agent used to also send password/password_hash
				// here and we persisted them centrally; neither was ever
				// read back, so we no longer ask for or store a secret at
				// all — only which mode this agent's sessions use.
				if err := json.Unmarshal(env.Payload, &creds); err == nil {
					db.UpsertLRCredential(r.Context(), agentID, creds.Username, creds.Mode)
					logger.Info("lr: credentials registered", "agent", agentID, "user", creds.Username, "mode", creds.Mode)
				}
			}
		}
	}
}

// ── handleInitiateSession ─────────────────────────────────────────────────────
// Analyst requests a live response session.
// URL: POST /api/v1/live-response/sessions

func handleInitiateSession(db *store.DB, registry *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AgentID string `json:"agent_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" {
			http.Error(w, `{"error":"agent_id required"}`, 400)
			return
		}

		agent, err := db.GetAgent(r.Context(), req.AgentID)
		if err != nil {
			http.Error(w, `{"error":"agent not found"}`, 404)
			return
		}

		// Check credentials are registered
		username, _, err := db.GetLRCredential(r.Context(), req.AgentID)
		if err != nil {
			writeJSON(w, 503, map[string]string{
				"error": "Agent has no live response credentials. Ensure agent is running and has connected at least once.",
			})
			return
		}

		// Check tunnel is connected
		_, connected := registry.Get(req.AgentID)
		if !connected {
			writeJSON(w, 503, map[string]string{
				"error": "Agent tunnel not connected. Agent must be online.",
			})
			return
		}

		// Generate session token
		tokenBytes := make([]byte, 16)
		rand.Read(tokenBytes)
		token := hex.EncodeToString(tokenBytes)

		initiatedBy := "admin"
		if claims := auth.GetClaims(r); claims != nil {
			initiatedBy = claims.Username
		}

		sessionID, err := db.CreateLRSession(r.Context(), req.AgentID, initiatedBy, token, "ssh")
		if err != nil {
			logger.Warn("lr: create session failed", "err", err)
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}

		db.WriteAudit(r.Context(), initiatedBy, "live_response_initiate", "agent:"+req.AgentID,
			fmt.Sprintf("session=%d", sessionID), clientIP(r))
		logger.Info("lr: session initiated",
			"agent", req.AgentID, "session", sessionID, "by", initiatedBy)

		writeJSON(w, 200, map[string]interface{}{
			"session_id":    sessionID,
			"session_token": token,
			"agent_id":      req.AgentID,
			"protocol":      "ssh",
			"username":      username,
			"hostname":      agent.Hostname,
		})
	}
}

// ── handleSessionTerminal ─────────────────────────────────────────────────────
// Analyst WebSocket for interactive SSH terminal.
// Flow:
//  1. Upgrade analyst connection
//  2. Register data channel on tunnel
//  3. Send "open_session" to agent → agent dials local SSH and starts proxying
//  4. Bidirectional proxy: analyst ↔ management ↔ agent ↔ local SSH
//
// URL: GET /api/v1/live-response/terminal?token=TOKEN&auth=JWT

func handleSessionTerminal(db *store.DB, registry *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "token required", 400)
			return
		}

		session, err := db.GetLRSession(r.Context(), token)
		if err != nil {
			logger.Warn("lr: terminal - session lookup failed", "token", token[:8]+"...", "err", err)
			http.Error(w, "invalid or expired session", 400)
			return
		}
		// F-04: the token is bound to the analyst who created the session…
		actor := ""
		if c := auth.GetClaims(r); c != nil {
			actor = c.Username
		}
		if actor == "" || actor != session.InitiatedBy {
			logger.Warn("lr: terminal - token used by a different user", "token", token[:8]+"...", "by", actor)
			http.Error(w, "forbidden", 403)
			return
		}
		// …and is single-use: claim pending→active atomically.
		if ok, err := db.ClaimLRSession(r.Context(), token); err != nil || !ok {
			logger.Warn("lr: terminal - session not claimable", "token", token[:8]+"...", "status", session.Status)
			http.Error(w, "session already used or closed", 400)
			return
		}
		db.WriteAudit(r.Context(), actor, "live_response_start", "agent:"+session.AgentID,
			fmt.Sprintf("session=%d", session.ID), clientIP(r))

		logger.Info("lr: terminal - session found", "agent", session.AgentID, "status", session.Status)

		tunnel, ok := registry.Get(session.AgentID)
		if !ok {
			logger.Warn("lr: terminal - agent tunnel not connected", "agent", session.AgentID)
			http.Error(w, "agent tunnel not connected", 503)
			return
		}

		logger.Info("lr: terminal - tunnel found, upgrading WebSocket")

		// Upgrade analyst WebSocket
		analystConn, err := lrUpgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Warn("lr: terminal - WebSocket upgrade failed", "err", err)
			return
		}
		defer analystConn.Close()
		analystConn.SetReadLimit(lrAnalystMaxFrame)

		// Register data channel on the agent tunnel BEFORE telling the agent to open
		dataCh := make(chan []byte, 512)
		tunnel.mu.Lock()
		tunnel.sessions[token] = dataCh
		tunnel.mu.Unlock()

		defer func() {
			tunnel.mu.Lock()
			delete(tunnel.sessions, token)
			tunnel.mu.Unlock()
			db.UpdateLRSessionStatus(context.Background(), token, "closed")
			db.WriteAudit(context.Background(), actor, "live_response_end", "agent:"+session.AgentID,
				fmt.Sprintf("session=%d", session.ID), clientIP(r))
			logger.Info("lr: terminal session closed", "token", token[:8]+"...")
		}()

		// *** Tell the agent to open the SSH session ***
		// This is the missing step — without it the agent never dials SSH.
		if err := tunnel.sendJSON(map[string]interface{}{
			"type":  "open_session",
			"token": token,
		}); err != nil {
			logger.Warn("lr: failed to send open_session to agent", "err", err)
			analystConn.WriteMessage(websocket.TextMessage,
				[]byte(`{"error":"failed to signal agent"}`))
			return
		}

		logger.Info("lr: terminal connected", "agent", session.AgentID)

		// Analyst → Agent
		// xterm.js sends raw bytes; we JSON-encode them so the agent can json.Unmarshal(payload, &raw)
		go func() {
			for {
				mt, msg, err := analystConn.ReadMessage()
				if err != nil {
					return
				}
				// Resize arrives as a TEXT frame; keystrokes are BINARY frames.
				if mt == websocket.TextMessage {
					if cols, rows, ok := parseResizeFrame(msg); ok {
						tunnel.sendJSON(map[string]interface{}{
							"type": "resize", "token": token, "cols": cols, "rows": rows,
						})
					}
					continue
				}
				db.AppendLRTranscript(context.Background(), session.ID, "in", msg)
				// JSON-encode the raw bytes so agent can decode with json.Unmarshal(&[]byte)
				encoded, _ := json.Marshal(msg)
				env := map[string]interface{}{
					"type":    "data",
					"token":   token,
					"payload": json.RawMessage(encoded),
				}
				if err := tunnel.sendJSON(env); err != nil {
					return
				}
			}
		}()

		// Hard maximum session length (F-04): previously a 30-minute *idle*
		// timer that reset on every message, so an active session never ended.
		maxLife := time.NewTimer(lrMaxSession)
		defer maxLife.Stop()

		// Agent → Analyst
		// Agent sends json.RawMessage(json.Marshal([]byte{...})) — decode and forward raw bytes
		for {
			select {
			case rawPayload, ok := <-dataCh:
				if !ok {
					return
				}
				// rawPayload is json.RawMessage (JSON-encoded []byte) — decode to raw bytes
				var raw []byte
				if err := json.Unmarshal(rawPayload, &raw); err != nil {
					// Fallback: send as-is
					raw = rawPayload
				}
				db.AppendLRTranscript(context.Background(), session.ID, "out", raw)
				if err := analystConn.WriteMessage(websocket.BinaryMessage, raw); err != nil {
					return
				}
			case <-maxLife.C:
				analystConn.WriteMessage(websocket.TextMessage, []byte(`{"error":"session reached maximum duration"}`))
				return
			}
		}
	}
}

// ── Other handlers ────────────────────────────────────────────────────────────

func handleListSessions(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.URL.Query().Get("agent_id")
		sessions, err := db.ListLRSessions(r.Context(), agentID, 100)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		if sessions == nil {
			sessions = []store.LRSession{}
		}
		writeJSON(w, 200, sessions)
	}
}

func handleListLRAgents(db *store.DB, registry *TunnelRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agents, err := db.ListAgents(r.Context())
		if err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		creds, _ := db.ListLRCredentials(r.Context())
		credMap := make(map[string]store.LRCredential)
		for _, c := range creds {
			credMap[c.AgentID] = c
		}
		connected := registry.ConnectedAgents()
		connMap := make(map[string]bool)
		for _, id := range connected {
			connMap[id] = true
		}

		type lrAgent struct {
			store.Agent
			LRReady      bool   `json:"lr_ready"`
			LRUsername   string `json:"lr_username,omitempty"`
			TunnelOnline bool   `json:"tunnel_online"`
		}

		result := make([]lrAgent, 0, len(agents))
		for _, a := range agents {
			la := lrAgent{Agent: a, TunnelOnline: connMap[a.ID]}
			if c, ok := credMap[a.ID]; ok {
				la.LRUsername = c.Username
				la.LRReady = connMap[a.ID]
			}
			result = append(result, la)
		}
		writeJSON(w, 200, result)
	}
}

func handleCloseSession(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		if token == "" {
			http.Error(w, `{"error":"token required"}`, 400)
			return
		}
		db.UpdateLRSessionStatus(r.Context(), token, "closed")
		writeJSON(w, 200, map[string]string{"status": "closed"})
	}
}

func isWindows(os string) bool {
	if os == "" {
		return false
	}
	for _, w := range []string{"windows", "win"} {
		if len(os) >= len(w) {
			match := true
			for i, c := range w {
				if os[i] != byte(c) && os[i] != byte(c-32) {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// parseResizeFrame validates an analyst terminal-resize message.
func parseResizeFrame(msg []byte) (cols, rows int, ok bool) {
	var m struct {
		Type string `json:"type"`
		Cols int    `json:"cols"`
		Rows int    `json:"rows"`
	}
	if json.Unmarshal(msg, &m) != nil || m.Type != "resize" {
		return 0, 0, false
	}
	if m.Cols < 10 || m.Cols > 500 || m.Rows < 5 || m.Rows > 200 {
		return 0, 0, false
	}
	return m.Cols, m.Rows, true
}
