package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"obsidianwatch/backend/internal/enroll"
	"obsidianwatch/backend/internal/store"
	"obsidianwatch/backend/pkg/agentid"
)

// enrollStore is what enrollment needs from the database.
type enrollStore interface {
	ConsumeEnrollmentToken(ctx context.Context, tokenHash string) (int64, error)
	CreateAgentIdentity(ctx context.Context, in store.AgentIdentity) error
	RenewAgentIdentity(ctx context.Context, agentID, serial string, notAfter time.Time) error
	SupersedeByHost(ctx context.Context, newID, hostname string) (int64, error)
}

var _ enrollStore = (*store.DB)(nil)

type enrollConfig struct {
	ca            *enroll.CA
	certTTL       time.Duration
	fleetKeys     []string // accepted in place of a token only when allowFleetKey
	allowFleetKey bool
	now           func() time.Time
}

// TokenHash is how enrollment tokens are stored: never in plain text.
func TokenHash(token string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(h[:])
}

type enrollResponse struct {
	AgentID       string    `json:"agent_id"`
	Certificate   string    `json:"certificate"`
	CACertificate string    `json:"ca_certificate"`
	NotAfter      time.Time `json:"not_after"`
	RenewAfter    time.Time `json:"renew_after"`
}

func (c *enrollConfig) respond(w http.ResponseWriter, id, certPEM string, notBefore, notAfter time.Time) {
	half := notBefore.Add(notAfter.Sub(notBefore) / 2)
	writeJSON(w, http.StatusOK, enrollResponse{
		AgentID: id, Certificate: certPEM, CACertificate: string(c.ca.CertPEM),
		NotAfter: notAfter.UTC(), RenewAfter: half.UTC(),
	})
}

// handleEnroll: POST /api/v1/enroll (no client certificate needed).
//
// The agent generates its key pair locally and sends only a CSR with a
// tenant enrollment token. It gets back a certificate for a fresh random
// agent_id. Every call creates a new identity, so a cloned image that
// enrolls on first boot gets one id per clone (A1).
func handleEnroll(db enrollStore, cfg *enrollConfig, logger *slog.Logger) http.HandlerFunc {
	limit := newIPLimiter(20, time.Minute)
	return func(w http.ResponseWriter, r *http.Request) {
		ip := peerIP(r)
		if !limit.allow(ip, cfg.now()) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, `{"error":"too many enrollment attempts"}`, http.StatusTooManyRequests)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var body struct {
			Token        string `json:"token"`
			CSR          string `json:"csr"`
			Hostname     string `json:"hostname"`
			OS           string `json:"os"`
			AgentVersion string `json:"agent_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		if len(body.Hostname) > 253 || len(body.OS) > 32 || len(body.AgentVersion) > 64 {
			http.Error(w, `{"error":"field too long"}`, http.StatusBadRequest)
			return
		}
		csr, err := enroll.ParseCSR([]byte(body.CSR))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		var tokenID *int64
		switch {
		case body.Token != "":
			id, err := db.ConsumeEnrollmentToken(r.Context(), TokenHash(body.Token))
			if err != nil {
				if !errors.Is(err, store.ErrTokenInvalid) {
					logger.Error("enroll: token lookup failed", "err", err)
					http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
					return
				}
				logger.Warn("enroll: rejected token", "ip", ip, "host", body.Hostname)
				http.Error(w, `{"error":"enrollment token is invalid, expired, revoked or used up"}`, http.StatusUnauthorized)
				return
			}
			tokenID = &id
		default:
			http.Error(w, `{"error":"enrollment token required"}`, http.StatusUnauthorized)
			return
		}

		now := cfg.now()
		id := agentid.New()
		cert, certPEM, err := cfg.ca.Issue(csr, id, cfg.certTTL, now)
		if err != nil {
			logger.Error("enroll: issue failed", "err", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		if err := db.CreateAgentIdentity(r.Context(), store.AgentIdentity{
			AgentID: id, Hostname: body.Hostname, OS: body.OS, TokenID: tokenID,
			CertSerial: agentid.Serial(cert), CertNotAfter: cert.NotAfter, EnrolledFrom: ip,
		}); err != nil {
			logger.Error("enroll: save identity failed", "err", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		// A reinstall: hide older records of this host from the fleet. Any of
		// them that is still alive reappears with its next batch.
		if n, err := db.SupersedeByHost(r.Context(), id, body.Hostname); err != nil {
			logger.Warn("enroll: could not mark older records of this host", "host", body.Hostname, "err", err)
		} else if n > 0 {
			logger.Info("enroll: older records of this host marked as replaced", "host", body.Hostname, "records", n, "by", id)
		}
		logger.Info("enroll: agent enrolled", "agent", id, "host", body.Hostname, "ip", ip, "by_token", tokenID != nil)
		cfg.respond(w, id, string(certPEM), cert.NotBefore, cert.NotAfter)
	}
}

// handleRenew: POST /api/v1/enroll/renew, authenticated by the current,
// still-valid certificate. Issues a new certificate for the same agent_id
// over a new key (A4: agents renew at half life). Revoked identities fail at
// the identity gate before reaching here, and again in the store.
func handleRenew(db enrollStore, cfg *enrollConfig, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cur, ok := certIdentity(r)
		if !ok {
			http.Error(w, `{"error":"renewal requires the current agent certificate"}`, http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var body struct {
			CSR string `json:"csr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		csr, err := enroll.ParseCSR([]byte(body.CSR))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		cert, certPEM, err := cfg.ca.Issue(csr, cur.AgentID, cfg.certTTL, cfg.now())
		if err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		if err := db.RenewAgentIdentity(r.Context(), cur.AgentID, agentid.Serial(cert), cert.NotAfter); err != nil {
			if errors.Is(err, store.ErrIdentityRevoked) {
				http.Error(w, `{"error":"agent identity revoked"}`, http.StatusUnauthorized)
				return
			}
			logger.Error("enroll: renew save failed", "agent", cur.AgentID, "err", err)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		logger.Info("enroll: certificate renewed", "agent", cur.AgentID, "not_after", cert.NotAfter)
		cfg.respond(w, cur.AgentID, string(certPEM), cert.NotBefore, cert.NotAfter)
	}
}

// certOnly refuses routes that an agent certificate must not reach (event
// and agent queries over the whole fleet).
func certOnlyForbidden(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := certIdentity(r); ok {
			http.Error(w, `{"error":"not available to agent certificates"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ipLimiter is a fixed-window counter per source address.
type ipLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	m      map[string]*ipWindow
}

type ipWindow struct {
	start time.Time
	n     int
}

func newIPLimiter(max int, window time.Duration) *ipLimiter {
	return &ipLimiter{max: max, window: window, m: map[string]*ipWindow{}}
}

func (l *ipLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) > 10000 { // bound memory under a spray of addresses
		for k, v := range l.m {
			if now.Sub(v.start) > l.window {
				delete(l.m, k)
			}
		}
	}
	w := l.m[ip]
	if w == nil || now.Sub(w.start) > l.window {
		l.m[ip] = &ipWindow{start: now, n: 1}
		return true
	}
	w.n++
	return w.n <= l.max
}
