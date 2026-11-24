// Package agentid is the agent identity contract shared by the ingest backend
// and the management server (spec WS-A, A1 to A4).
//
// An enrolled agent holds a client certificate issued by the agent CA. The
// certificate names a random agent_id, never the hostname, in two places that
// must agree: the subject CommonName and a URI SAN of the form
// urn:obsidianwatch:agent:<agent_id>. Both servers derive the caller's identity
// from a verified certificate only, and refuse anything that claims another id.
//
// management/backend/internal/agentid is a byte-for-byte copy of this file
// (the two modules do not import each other); a test there keeps them equal.
package agentid

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// URIPrefix is the URI SAN scheme that marks an agent identity certificate.
const URIPrefix = "urn:obsidianwatch:agent:"

// idPrefix makes enrolled ids easy to tell from legacy hostname ids.
const idPrefix = "ag-"

// New returns a fresh random agent_id: "ag-" followed by 32 hex characters.
func New() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("agentid: no randomness: " + err.Error())
	}
	return idPrefix + hex.EncodeToString(b)
}

// Valid reports whether s has the shape New produces.
func Valid(s string) bool {
	if len(s) != len(idPrefix)+32 || !strings.HasPrefix(s, idPrefix) {
		return false
	}
	_, err := hex.DecodeString(s[len(idPrefix):])
	return err == nil && strings.ToLower(s) == s
}

var (
	ErrNoIdentity = errors.New("agentid: certificate carries no agent identity")
	ErrMismatch   = errors.New("agentid: certificate CommonName and URI SAN disagree")
	ErrRevoked    = errors.New("agentid: agent identity is revoked")
)

// FromCert extracts the agent_id from an identity certificate. It does not
// verify the chain; use Verify for that.
func FromCert(c *x509.Certificate) (string, error) {
	var fromURI string
	for _, u := range c.URIs {
		if s := u.String(); strings.HasPrefix(s, URIPrefix) {
			if fromURI != "" {
				return "", ErrMismatch // two identities in one certificate
			}
			fromURI = strings.TrimPrefix(s, URIPrefix)
		}
	}
	if fromURI == "" {
		return "", ErrNoIdentity
	}
	if fromURI != c.Subject.CommonName || !Valid(fromURI) {
		return "", ErrMismatch
	}
	return fromURI, nil
}

// URI returns the SAN URI for id.
func URI(id string) *url.URL {
	u, _ := url.Parse(URIPrefix + id)
	return u
}

// Identity is a verified caller.
type Identity struct {
	AgentID  string
	Serial   string // hex, lower case
	NotAfter time.Time
}

// Verify checks leaf (and any intermediates) against the agent CA pool for
// client authentication and returns the identity it names.
func Verify(leaf *x509.Certificate, intermediates []*x509.Certificate, roots *x509.CertPool, now time.Time) (Identity, error) {
	if leaf == nil || roots == nil {
		return Identity{}, ErrNoIdentity
	}
	inter := x509.NewCertPool()
	for _, c := range intermediates {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return Identity{}, fmt.Errorf("agentid: certificate not trusted: %w", err)
	}
	id, err := FromCert(leaf)
	if err != nil {
		return Identity{}, err
	}
	return Identity{AgentID: id, Serial: Serial(leaf), NotAfter: leaf.NotAfter}, nil
}

// Serial is the lower-case hex form of the certificate serial number.
func Serial(c *x509.Certificate) string { return strings.ToLower(c.SerialNumber.Text(16)) }

// Revocations is a periodically refreshed set of revoked agent ids. Both
// servers refresh it well inside the 60 s revocation budget (A4).
type Revocations struct {
	mu      sync.RWMutex
	revoked map[string]bool
	loaded  time.Time
	load    func(ctx context.Context) ([]string, error)
	onLoad  func(revoked map[string]bool) // optional: e.g. close live tunnels
}

// DefaultRefresh keeps worst-case revocation latency at about 20 s.
const DefaultRefresh = 15 * time.Second

func NewRevocations(load func(ctx context.Context) ([]string, error)) *Revocations {
	return &Revocations{revoked: map[string]bool{}, load: load}
}

// OnLoad registers a hook that runs after every successful refresh.
func (r *Revocations) OnLoad(f func(revoked map[string]bool)) { r.onLoad = f }

// Refresh reloads the set. On error the previous set stays in force.
func (r *Revocations) Refresh(ctx context.Context) error {
	ids, err := r.load(ctx)
	if err != nil {
		return err
	}
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	r.mu.Lock()
	r.revoked, r.loaded = m, time.Now()
	hook := r.onLoad
	r.mu.Unlock()
	if hook != nil {
		hook(m)
	}
	return nil
}

// Run refreshes every interval until ctx ends.
func (r *Revocations) Run(ctx context.Context, interval time.Duration) {
	_ = r.Refresh(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.Refresh(ctx)
		}
	}
}

// Revoked reports whether id is in the current set.
func (r *Revocations) Revoked(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.revoked[id]
}

// Mark adds id at once, for the server that performed the revocation.
func (r *Revocations) Mark(id string) {
	r.mu.Lock()
	r.revoked[id] = true
	r.mu.Unlock()
}
