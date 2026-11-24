package api

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"obsidianwatch/backend/pkg/agentid"
)

type ctxKey int

const identityKey ctxKey = 1

// withIdentity stores a verified identity on the request context.
func withIdentity(r *http.Request, id agentid.Identity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey, id))
}

// certIdentity returns the identity proven by the caller's certificate.
func certIdentity(r *http.Request) (agentid.Identity, bool) {
	id, ok := r.Context().Value(identityKey).(agentid.Identity)
	return id, ok
}

// boundAgentMismatch reports whether a request proven by a certificate claims
// a different agent_id in its body (A2: such batches are rejected).
// Every agent route requires a certificate, so a request without one never
// reaches here; it is treated as a mismatch all the same.
func boundAgentMismatch(r *http.Request, claimed string) bool {
	id, ok := certIdentity(r)
	return !ok || claimed != id.AgentID
}

const errAgentMismatch = `{"error":"agent_id does not match the client certificate"}`

// identityGate admits only callers with a valid, unrevoked agent
// certificate (spec A2). There is no API-key fallback.
type identityGate struct {
	roots   *x509.CertPool // agent CA only
	revoked *agentid.Revocations
	now     func() time.Time
}

func (g *identityGate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, `{"error":"client certificate required; enroll this agent"}`, http.StatusUnauthorized)
			return
		}
		id, err := agentid.Verify(r.TLS.PeerCertificates[0], r.TLS.PeerCertificates[1:], g.roots, g.now())
		if err != nil {
			http.Error(w, `{"error":"client certificate not accepted"}`, http.StatusUnauthorized)
			return
		}
		if g.revoked != nil && g.revoked.Revoked(id.AgentID) {
			http.Error(w, `{"error":"agent identity revoked"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, withIdentity(r, id))
	})
}
