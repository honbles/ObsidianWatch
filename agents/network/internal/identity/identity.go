// Package identity gives the agent its own certificate (spec A1, A4).
//
// On first start the agent creates a key pair locally and enrolls with the
// enrollment token built into it: it sends a certificate request to the
// backend's /api/v1/enroll and gets back a short-lived client certificate
// for a random agent id. That certificate authenticates every connection to
// the backend (events, app telemetry, location, the live-response tunnel);
// there is no shared API key. The certificate renews itself at half life.
//
// The key never leaves the host. It is stored with the certificate in one
// bundle: a root-only 0600 file on Linux and macOS, DPAPI-protected for the
// SYSTEM account on Windows (keystore_<os>.go).
//
// This file is shared by every agent; keep the copies identical.
package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Options configure a Manager.
type Options struct {
	BackendURL string         // ingest backend, e.g. https://siem.example.com:8443
	Token      string         // enrollment token built into the agent
	RootCAs    *x509.CertPool // trusts the backend's server certificate (nil = system roots)
	Dir        string         // where the identity bundle is kept
	Hostname   string
	OS         string
	Version    string
	Logger     *slog.Logger
}

// State of the identity, for logs and health events.
const (
	StateNone    = "not enrolled"
	StateValid   = "valid"
	StateExpired = "expired"
	StateRevoked = "revoked"
)

// Manager holds the current certificate and keeps it fresh.
type Manager struct {
	opt    Options
	store  keyStore
	client *http.Client

	mu    sync.RWMutex
	cert  *tls.Certificate
	leaf  *x509.Certificate
	id    string
	state string
}

type bundle struct {
	AgentID string `json:"agent_id"`
	CertPEM string `json:"certificate"`
	KeyPEM  string `json:"key"`
	CAPEM   string `json:"ca_certificate,omitempty"`
}

// New loads the stored identity, if there is one.
func New(opt Options) (*Manager, error) {
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	opt.BackendURL = strings.TrimRight(opt.BackendURL, "/")
	m := &Manager{opt: opt, store: newKeyStore(opt.Dir), state: StateNone}
	m.client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: m.TLSConfig(),
		Proxy:           http.ProxyFromEnvironment,
	}}
	b, err := m.store.load()
	if err != nil {
		if errors.Is(err, errNoBundle) {
			return m, nil
		}
		return nil, fmt.Errorf("identity: read stored identity: %w", err)
	}
	if err := m.use(b); err != nil {
		opt.Logger.Error("identity: stored identity is unusable; enrolling again", "err", err)
		return m, nil
	}
	return m, nil
}

func (m *Manager) use(b bundle) error {
	pair, err := tls.X509KeyPair([]byte(b.CertPEM), []byte(b.KeyPEM))
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	pair.Leaf = leaf
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cert, m.leaf, m.id = &pair, leaf, b.AgentID
	m.state = StateValid
	if time.Now().After(leaf.NotAfter) {
		m.state = StateExpired
	}
	return nil
}

// AgentID is the enrolled id, "" before enrollment.
func (m *Manager) AgentID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.id
}

// State reports the identity state.
func (m *Manager) State() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// NotAfter is when the current certificate expires.
func (m *Manager) NotAfter() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.leaf == nil {
		return time.Time{}
	}
	return m.leaf.NotAfter
}

// TLSConfig is the client TLS configuration for every connection to the
// backend. The certificate is looked up per handshake, so renewals apply to
// new connections without rebuilding clients.
func (m *Manager) TLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: m.opt.RootCAs}
	m.Apply(cfg)
	return cfg
}

// Apply makes cfg present this agent's certificate.
func (m *Manager) Apply(cfg *tls.Config) {
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		if m.cert == nil {
			return &tls.Certificate{}, nil // no certificate yet: the server refuses
		}
		return m.cert, nil
	}
}

// ── process-wide hook ─────────────────────────────────────────────────────────

var active atomic.Pointer[Manager]

// SetActive makes m the identity used by ApplyActive.
func SetActive(m *Manager) { active.Store(m) }

// Active returns the process identity, or nil.
func Active() *Manager { return active.Load() }

// ApplyActive makes cfg present the agent certificate, if there is one.
// Every HTTP or WebSocket client that talks to the backend calls this.
func ApplyActive(cfg *tls.Config) {
	if m := active.Load(); m != nil {
		m.Apply(cfg)
	}
}

// ── enrollment and renewal ───────────────────────────────────────────────────

// ErrRevoked means the server refused this identity; enrolling again would
// undo the revocation, so the agent does not.
var ErrRevoked = errors.New("identity: this agent's identity was revoked on the server; reinstall with a new enrollment token")

type enrollResponse struct {
	AgentID       string    `json:"agent_id"`
	Certificate   string    `json:"certificate"`
	CACertificate string    `json:"ca_certificate"`
	NotAfter      time.Time `json:"not_after"`
	RenewAfter    time.Time `json:"renew_after"`
}

func newKeyAndCSR(host string) (*ecdsa.PrivateKey, string, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	// The subject is a hint only; the CA names the certificate after the
	// agent id it assigns.
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}}, k)
	if err != nil {
		return nil, "", err
	}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func keyPEM(k *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.code, e.msg) }

func (m *Manager) post(ctx context.Context, path string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.opt.BackendURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "obsidianwatch-agent/"+m.opt.Version)
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return &httpError{code: resp.StatusCode, msg: e.Error}
	}
	return json.Unmarshal(data, out)
}

func (m *Manager) save(id string, k *ecdsa.PrivateKey, r enrollResponse) error {
	kp, err := keyPEM(k)
	if err != nil {
		return err
	}
	b := bundle{AgentID: id, CertPEM: r.Certificate, KeyPEM: kp, CAPEM: r.CACertificate}
	if err := m.store.save(b); err != nil {
		return fmt.Errorf("identity: store: %w", err)
	}
	return m.use(b)
}

// Enroll gets a new identity with the enrollment token.
func (m *Manager) Enroll(ctx context.Context) error {
	if m.opt.Token == "" {
		return errors.New("identity: no enrollment token in this agent build; rebuild it in the Agent builder")
	}
	k, csr, err := newKeyAndCSR(m.opt.Hostname)
	if err != nil {
		return err
	}
	var r enrollResponse
	err = m.post(ctx, "/api/v1/enroll", map[string]string{
		"token": m.opt.Token, "csr": csr, "hostname": m.opt.Hostname, "os": m.opt.OS, "agent_version": m.opt.Version,
	}, &r)
	if err != nil {
		return fmt.Errorf("identity: enroll: %w", err)
	}
	if r.AgentID == "" || r.Certificate == "" {
		return errors.New("identity: enroll: incomplete answer from the server")
	}
	if err := m.save(r.AgentID, k, r); err != nil {
		return err
	}
	m.opt.Logger.Info("identity: enrolled", "agent_id", r.AgentID, "not_after", r.NotAfter)
	return nil
}

// Renew replaces the certificate (and key) for the same agent id.
func (m *Manager) Renew(ctx context.Context) error {
	id := m.AgentID()
	if id == "" {
		return errors.New("identity: nothing to renew")
	}
	k, csr, err := newKeyAndCSR(m.opt.Hostname)
	if err != nil {
		return err
	}
	var r enrollResponse
	if err := m.post(ctx, "/api/v1/enroll/renew", map[string]string{"csr": csr}, &r); err != nil {
		var he *httpError
		if errors.As(err, &he) && he.code == http.StatusUnauthorized && strings.Contains(he.msg, "revoked") {
			m.mu.Lock()
			m.state = StateRevoked
			m.mu.Unlock()
			return ErrRevoked
		}
		return fmt.Errorf("identity: renew: %w", err)
	}
	if r.AgentID != id {
		return fmt.Errorf("identity: renew returned a different agent id %q", r.AgentID)
	}
	if err := m.save(id, k, r); err != nil {
		return err
	}
	m.opt.Logger.Info("identity: certificate renewed", "agent_id", id, "not_after", r.NotAfter)
	return nil
}

// Ensure returns once the agent has a usable identity: the stored one, or a
// new one from the enrollment token (first start, or a certificate that
// expired while the host was off). It keeps retrying until ctx ends, because
// the service may start before the network or the server is up.
func (m *Manager) Ensure(ctx context.Context) error {
	delay := 5 * time.Second
	for {
		switch m.State() {
		case StateValid:
			return nil
		case StateRevoked:
			return ErrRevoked
		}
		if m.State() == StateExpired {
			m.opt.Logger.Warn("identity: certificate expired while the agent was not running; enrolling again")
		}
		err := m.Enroll(ctx)
		if err == nil {
			return nil
		}
		var he *httpError
		if errors.As(err, &he) && he.code == http.StatusUnauthorized {
			// A bad token will not fix itself quickly; say so plainly.
			m.opt.Logger.Error("identity: enrollment refused - the token is invalid, expired, revoked or used up; rebuild the agent with a new token", "err", err)
			delay = 10 * time.Minute
		} else {
			m.opt.Logger.Warn("identity: enrollment failed, retrying", "err", err, "in", delay.String())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 5*time.Minute {
			delay *= 2
		}
	}
}

// nextRenewal is half way through the certificate's life, plus jitter.
func nextRenewal(leaf *x509.Certificate, now time.Time) time.Duration {
	half := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	jitter, _ := rand.Int(rand.Reader, big.NewInt(int64(time.Hour)))
	d := half.Sub(now) + time.Duration(jitter.Int64())
	if d < time.Minute {
		d = time.Minute
	}
	return d
}

// Run renews the certificate at half life until ctx ends. A revoked identity
// stops renewal: the agent keeps running (and queueing) but the server
// refuses it until it is reinstalled.
func (m *Manager) Run(ctx context.Context) {
	for {
		m.mu.RLock()
		leaf := m.leaf
		m.mu.RUnlock()
		wait := time.Hour
		if leaf != nil {
			wait = nextRenewal(leaf, time.Now())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if leaf == nil {
			continue
		}
		for {
			err := m.Renew(ctx)
			if err == nil {
				break
			}
			if errors.Is(err, ErrRevoked) {
				m.opt.Logger.Error(err.Error())
				return
			}
			m.opt.Logger.Warn("identity: renewal failed, retrying in 30 minutes", "err", err, "expires", m.NotAfter())
			if time.Now().After(m.NotAfter()) {
				m.mu.Lock()
				m.state = StateExpired
				m.mu.Unlock()
				m.opt.Logger.Error("identity: certificate expired; enrolling again with the built-in token")
				if err := m.Ensure(ctx); err != nil {
					return
				}
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Minute):
			}
		}
	}
}

// Forget removes the stored identity (uninstall).
func (m *Manager) Forget() error { return m.store.remove() }
