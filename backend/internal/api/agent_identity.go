package api

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"obsidianwatch/backend/pkg/agentid"
)

// Agent identity modes (spec A2). The mode only decides what happens to a
// request WITHOUT an identity certificate; a request that presents one is
// always verified and bound to the id it names.
const (
	// IdentityLegacy: fleet API key on every route (behaviour before A1).
	IdentityLegacy = "legacy"
	// IdentityMixed: a certificate is used when presented, the fleet key is
	// still accepted from agents that have not enrolled yet. Default.
	IdentityMixed = "mixed"
	// IdentityEnforced: a certificate is required on every ingest route; the
	// fleet key is accepted only on the enrollment endpoint.
	IdentityEnforced = "enforced"
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
// a different agent_id in its body (A2: such batches are rejected). Requests
// without a certificate (legacy/mixed key auth) are not bound.
//
// The reverse also holds: an enrolled id ("ag-…") can only be used with its
// certificate, so the fleet key cannot speak for an enrolled agent.
func boundAgentMismatch(r *http.Request, claimed string) bool {
	id, ok := certIdentity(r)
	if !ok {
		return agentid.Valid(claimed)
	}
	return claimed != id.AgentID
}

const errAgentMismatch = `{"error":"agent_id does not match the client certificate"}`

// identityGate authenticates agents by certificate, falling back to the fleet
// key where the mode allows it.
type identityGate struct {
	mode     string
	roots    *x509.CertPool // agent CA only
	revoked  *agentid.Revocations
	keyAuth  func(http.Handler) http.Handler // fleet key middleware
	legacyCA bool                            // mtls_enabled with the deployment CA (pre-A1 certificates)
	now      func() time.Time
}

func (g *identityGate) wrap(next http.Handler) http.Handler {
	keyed := g.keyAuth(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			leaf := r.TLS.PeerCertificates[0]
			id, err := agentid.Verify(leaf, r.TLS.PeerCertificates[1:], g.roots, g.now())
			switch {
			case err == nil:
				if g.revoked != nil && g.revoked.Revoked(id.AgentID) {
					http.Error(w, `{"error":"agent identity revoked"}`, http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, withIdentity(r, id))
				return
			case g.legacyCA && len(r.TLS.VerifiedChains) > 0 && g.mode != IdentityEnforced && noAgentIdentity(leaf):
				// A deployment-CA certificate from before enrollment existed:
				// proves membership, not identity. Not accepted once enforced.
				next.ServeHTTP(w, r)
				return
			case errors.Is(err, agentid.ErrNoIdentity) && g.roots == nil:
				// No agent CA configured: fall through to key auth below.
			default:
				http.Error(w, `{"error":"client certificate not accepted"}`, http.StatusUnauthorized)
				return
			}
		}
		if g.mode == IdentityEnforced {
			http.Error(w, `{"error":"client certificate required; enroll this agent"}`, http.StatusUnauthorized)
			return
		}
		keyed.ServeHTTP(w, r)
	})
}

// noAgentIdentity reports whether a certificate carries no agent identity at
// all (a pre-enrollment certificate from the deployment CA). One that names
// an agent but fails verification is never treated as legacy.
func noAgentIdentity(c *x509.Certificate) bool {
	_, err := agentid.FromCert(c)
	return errors.Is(err, agentid.ErrNoIdentity)
}
