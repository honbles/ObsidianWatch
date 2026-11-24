package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/agentid"
	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// Tunnel authentication modes (spec A2), mirroring the ingest backend's
// agent_identity.mode.
const (
	tunnelAuthLegacy   = "legacy"   // fleet key only (before A1)
	tunnelAuthMixed    = "mixed"    // certificate when presented, else fleet key
	tunnelAuthEnforced = "enforced" // certificate required
)

// agentCAPool holds the agent CA published by the ingest backend. It is
// reloaded periodically so management never needs the CA key.
type agentCAPool struct {
	mu   sync.RWMutex
	pem  string
	pool *x509.CertPool
	load func(ctx context.Context) (string, error)
}

func (p *agentCAPool) Refresh(ctx context.Context) error {
	pemText, err := p.load(ctx)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if pemText == p.pem {
		return nil
	}
	if pemText == "" {
		p.pem, p.pool = "", nil
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemText)) {
		return errors.New("agent CA: published certificate does not parse")
	}
	p.pem, p.pool = pemText, pool
	return nil
}

func (p *agentCAPool) Get() *x509.CertPool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.pool
}

// tunnelAuth decides who is on the other end of an agent tunnel.
type tunnelAuth struct {
	mode   string
	ca     *agentCAPool
	rev    *agentid.Revocations
	apiKey string
	now    func() time.Time
}

type tunnelCaller struct {
	agentID string
	serial  string // empty for fleet-key (legacy) callers
}

type authError struct {
	code int
	msg  string
}

func (e *authError) Error() string { return e.msg }

func (ta *tunnelAuth) authenticate(r *http.Request) (tunnelCaller, error) {
	claimed := r.URL.Query().Get("agent_id")
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && ta.mode != tunnelAuthLegacy {
		pool := ta.ca.Get()
		if pool == nil {
			return tunnelCaller{}, &authError{http.StatusServiceUnavailable, "agent CA not published yet"}
		}
		id, err := agentid.Verify(r.TLS.PeerCertificates[0], r.TLS.PeerCertificates[1:], pool, ta.now())
		if err != nil {
			return tunnelCaller{}, &authError{http.StatusUnauthorized, "client certificate not accepted"}
		}
		if ta.rev.Revoked(id.AgentID) {
			return tunnelCaller{}, &authError{http.StatusUnauthorized, "agent identity revoked"}
		}
		if claimed != "" && claimed != id.AgentID {
			return tunnelCaller{}, &authError{http.StatusForbidden, "agent_id does not match the client certificate"}
		}
		return tunnelCaller{agentID: id.AgentID, serial: id.Serial}, nil
	}
	if ta.mode == tunnelAuthEnforced {
		return tunnelCaller{}, &authError{http.StatusUnauthorized, "client certificate required; enroll this agent"}
	}
	if claimed == "" {
		return tunnelCaller{}, &authError{http.StatusBadRequest, "agent_id required"}
	}
	// An enrolled id can only be used with its certificate; the fleet key
	// must not let anyone speak for an enrolled agent.
	if agentid.Valid(claimed) {
		return tunnelCaller{}, &authError{http.StatusForbidden, "enrolled agents must present their certificate"}
	}
	// M-02: the fleet key proves membership of the fleet, not identity.
	if !validAgentAPIKey(ta.apiKey, r) {
		return tunnelCaller{}, &authError{http.StatusUnauthorized, "invalid or missing X-API-Key"}
	}
	return tunnelCaller{agentID: claimed}, nil
}

// refuseSecondTunnel records a refused takeover (A3): logged and alerted.
func refuseSecondTunnel(db *store.DB, logger *slog.Logger, c tunnelCaller, existingSerial, ip string) {
	logger.Warn("lr: second tunnel for agent refused", "agent", c.agentID, "ip", ip,
		"new_cert", c.serial, "live_cert", existingSerial)
	if db == nil {
		return
	}
	host := ""
	if a, err := db.GetAgent(contextBG(), c.agentID); err == nil && a != nil {
		host = a.Hostname
	}
	desc := fmt.Sprintf("A second Live Response tunnel for agent %s was refused while its tunnel was live.\n"+
		"Source address: %s\nPresented certificate: %s\nLive tunnel certificate: %s\n"+
		"A copied agent identity or a takeover attempt looks like this. Check the host and revoke its identity if it was cloned.",
		c.agentID, ip, orNone(c.serial), orNone(existingSerial))
	_, _, err := db.CreateAlertDeduped(contextBG(), store.Alert{
		Title:       "Live Response tunnel takeover refused",
		Description: desc,
		Severity:    appSevHigh,
		AgentID:     c.agentID,
		Host:        host,
		EventType:   "agent_identity",
		EventID:     "tunnel-dup:" + c.agentID + ":" + time.Now().UTC().Format("2006-01-02T15"),
	})
	if err != nil {
		logger.Warn("lr: could not raise takeover alert", "err", err)
	}
}

func orNone(s string) string {
	if s == "" {
		return "none (fleet key)"
	}
	return s
}

// closeRevokedTunnels drops live tunnels whose identity was revoked (A4).
func (r *TunnelRegistry) closeRevokedTunnels(revoked map[string]bool, logger *slog.Logger) {
	r.mu.RLock()
	var drop []*agentTunnel
	for id, t := range r.tunnels {
		if revoked[id] {
			drop = append(drop, t)
		}
	}
	r.mu.RUnlock()
	for _, t := range drop {
		logger.Warn("lr: closing tunnel of revoked agent", "agent", t.agentID)
		t.conn.Close()
	}
}

// ── Enrollment tokens and identities (admin) ─────────────────────────────────

const (
	maxTokenUses = 100000
	maxTokenTTL  = 90 * 24 * time.Hour
)

// enrollmentTokenHash must match backend api.TokenHash.
func enrollmentTokenHash(token string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(h[:])
}

func newEnrollmentToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "owe_" + base64.RawURLEncoding.EncodeToString(b)
}

// POST /api/v1/enrollment-tokens {label, ttl_hours, max_uses}. The token is
// returned once and stored only as a hash.
func handleCreateEnrollmentToken(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Label    string `json:"label"`
			TTLHours int    `json:"ttl_hours"`
			MaxUses  int    `json:"max_uses"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		body.Label = strings.TrimSpace(body.Label)
		ttl := time.Duration(body.TTLHours) * time.Hour
		switch {
		case len(body.Label) > 120:
			writeJSON(w, 400, map[string]string{"error": "label is too long"})
			return
		case ttl <= 0 || ttl > maxTokenTTL:
			writeJSON(w, 400, map[string]string{"error": "ttl_hours must be between 1 and 2160 (90 days)"})
			return
		case body.MaxUses < 1 || body.MaxUses > maxTokenUses:
			writeJSON(w, 400, map[string]string{"error": "max_uses must be between 1 and 100000"})
			return
		}
		tok := newEnrollmentToken()
		by := ""
		if c := auth.GetClaims(r); c != nil {
			by = c.Username
		}
		t, err := db.CreateEnrollmentToken(r.Context(), enrollmentTokenHash(tok), body.Label, by, time.Now().Add(ttl), body.MaxUses)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not create token"})
			return
		}
		writeJSON(w, 201, map[string]any{"token": tok, "enrollment_token": t})
	}
}

func handleListEnrollmentTokens(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ts, err := db.ListEnrollmentTokens(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, map[string]any{"tokens": ts})
	}
}

func handleRevokeEnrollmentToken(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		by := ""
		if c := auth.GetClaims(r); c != nil {
			by = c.Username
		}
		if err := db.RevokeEnrollmentToken(r.Context(), id, by); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSON(w, 404, map[string]string{"error": "no such live token"})
				return
			}
			writeJSON(w, 500, map[string]string{"error": "revoke failed"})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "revoked"})
	}
}

func handleListAgentIdentities(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ids, err := db.ListAgentIdentities(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, map[string]any{"identities": ids})
	}
}

// POST /api/v1/agent-identities/{id}/revoke {reason}: takes effect on the
// tunnel at once and on ingest within one refresh (A4: within 60 s).
func handleRevokeAgentIdentity(db *store.DB, reg *TunnelRegistry, rev *agentid.Revocations, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var body struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		body.Reason = strings.TrimSpace(body.Reason)
		if body.Reason == "" || len(body.Reason) > 500 {
			writeJSON(w, 400, map[string]string{"error": "a reason (up to 500 characters) is required"})
			return
		}
		by := ""
		if c := auth.GetClaims(r); c != nil {
			by = c.Username
		}
		if err := db.RevokeAgentIdentity(r.Context(), id, by, body.Reason); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSON(w, 404, map[string]string{"error": "no such active identity"})
				return
			}
			writeJSON(w, 500, map[string]string{"error": "revoke failed"})
			return
		}
		if rev != nil {
			rev.Mark(id)
			reg.closeRevokedTunnels(map[string]bool{id: true}, logger)
		}
		logger.Warn("agent identity revoked", "agent", id, "by", by)
		writeJSON(w, 200, map[string]any{"status": "revoked", "ingest_within_seconds": int(agentid.DefaultRefresh.Seconds()) + 5})
	}
}
