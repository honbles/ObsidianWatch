package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
}

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

func handleAgentTunnel(db *store.DB, registry *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.URL.Query().Get("agent_id")
		if agentID == "" {
			http.Error(w, "agent_id required", 400)
			return
		}

		conn, err := lrUpgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Warn("lr: agent tunnel upgrade failed", "agent", agentID, "err", err)
			return
		}

		tunnel := &agentTunnel{
			agentID:  agentID,
			conn:     conn,
			sessions: make(map[string]chan []byte),
		}
		registry.Register(agentID, tunnel)
		logger.Info("lr: agent tunnel connected", "agent", agentID)

		defer func() {
			registry.Unregister(agentID)
			conn.Close()
			logger.Info("lr: agent tunnel disconnected", "agent", agentID)
		}()

		// Read loop — agent sends data back to waiting analyst connections
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				break
			}
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
					Username     string `json:"username"`
					PasswordHash string `json:"password_hash"`
					Password     string `json:"password"`
					Mode         string `json:"mode"`
				}
				if err := json.Unmarshal(env.Payload, &creds); err == nil {
					// Direct-shell mode: no password needed — agent spawns shell directly
					if creds.Mode == "direct-shell" {
						creds.PasswordHash = "direct-shell"
						creds.Password = "direct-shell"
					}
					db.UpsertLRCredential(r.Context(), agentID, creds.Username, creds.PasswordHash, creds.Password)
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
		username, _, _, err := db.GetLRCredential(r.Context(), req.AgentID)
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
		if session.Status == "closed" || session.Status == "failed" {
			logger.Warn("lr: terminal - session already closed", "token", token[:8]+"...", "status", session.Status)
			http.Error(w, "session already closed", 400)
			return
		}

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

		db.UpdateLRSessionStatus(r.Context(), token, "active")
		logger.Info("lr: terminal connected", "agent", session.AgentID)

		// Analyst → Agent
		// xterm.js sends raw bytes; we JSON-encode them so the agent can json.Unmarshal(payload, &raw)
		go func() {
			for {
				_, msg, err := analystConn.ReadMessage()
				if err != nil {
					return
				}
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
				if err := analystConn.WriteMessage(websocket.BinaryMessage, raw); err != nil {
					return
				}
			case <-time.After(30 * time.Minute):
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
