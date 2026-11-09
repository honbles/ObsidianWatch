package api

import (
	"encoding/json"
	"net/http"
	"time"

	"obsidianwatch/management/internal/store"
)

// handleAgentRegisterKey allows an agent to register/update its own install key.
// Called at install time with the password the operator chose interactively.
// Auth: X-API-Key header matching any backend api_key.
// registerKeyLimiter bounds install-key registrations per source IP. The fleet
// API key can create agent rows by registering unseen agent_ids, so an
// unthrottled loop would let a leaked key flood the agents table.
var registerKeyLimiter = NewRateLimiter(1*time.Minute, 60)

func handleAgentRegisterKey(db *store.DB, agentAPIKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validAgentAPIKey(agentAPIKey, r) {
			writeJSON(w, 401, map[string]string{"error": "invalid or missing X-API-Key"})
			return
		}
		if !registerKeyLimiter.Allow(clientIP(r)) {
			writeJSON(w, 429, map[string]string{"error": "too many registrations, try again later"})
			return
		}
		var body struct {
			InstallKey string `json:"install_key"`
			AgentID    string `json:"agent_id"`
			OS         string `json:"os"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if body.InstallKey == "" {
			writeJSON(w, 400, map[string]string{"error": "install_key required"})
			return
		}
		if len(body.InstallKey) > 256 || len(body.AgentID) > 128 || len(body.OS) > 32 {
			writeJSON(w, 400, map[string]string{"error": "field too long"})
			return
		}
		// agentID optional — if not provided we try to find by API key header
		agentID := body.AgentID
		if agentID == "" {
			writeJSON(w, 400, map[string]string{"error": "agent_id required"})
			return
		}
		if err := db.SetInstallKey(r.Context(), agentID, body.InstallKey, body.OS); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

// handleVerifyInstallKey allows agents to verify their install key on service install
// installKeyLimiter (M-04): the install/uninstall key is the ONLY thing that
// should be able to authorize uninstalling an agent (tamper protection is
// meant to make the toggle alone insufficient — see F-01), so this endpoint
// is a prime brute-force target and needs its own limiter independent of
// login.
var installKeyLimiter = NewRateLimiter(1*time.Minute, 10)

// handleVerifyInstallKey (M-04): previously GET with the key as a query
// param — query params land in server/proxy access logs and browser
// history, so the uninstall key could leak long after use. Moved to POST
// with the key in the body, requires the shared agent X-API-Key on top of
// the install key itself, rate-limited, and rotates the key on success so
// a logged/observed key can't be replayed to authorize a second uninstall.
func handleVerifyInstallKey(db *store.DB, agentAPIKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validAgentAPIKey(agentAPIKey, r) {
			writeJSON(w, 401, map[string]string{"error": "invalid or missing X-API-Key"})
			return
		}
		if !installKeyLimiter.Allow(clientIP(r)) {
			writeJSON(w, 429, map[string]string{"error": "too many attempts, try again later"})
			return
		}
		var body struct {
			Key string `json:"key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		// The key is accepted from the POST body only. A query-string fallback
		// (older agents) put the uninstall key into access logs, so it is gone.
		key := body.Key
		if key == "" {
			writeJSON(w, 400, map[string]string{"error": "key required"})
			return
		}
		agent, err := db.GetAgentByInstallKey(r.Context(), key)
		if err != nil || agent == nil {
			writeJSON(w, 403, map[string]string{"error": "invalid key"})
			return
		}
		newKey, err := db.RegenerateInstallKey(r.Context(), agent.ID)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "key rotation failed"})
			return
		}
		db.WriteAudit(r.Context(), "agent:"+agent.ID, "verify_install_key", agent.ID, "key rotated on successful verification", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "ok", "hostname": agent.Hostname, "new_key": newKey})
	}
}
