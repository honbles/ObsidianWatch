package api

// Gate tests for spec A1, A2 and A4 (Phase 0 exit: forgery and takeover
// tests fail). They run a real TLS listener so certificates are presented and
// verified the way agents will use them.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"obsidianwatch/backend/internal/enroll"
	"obsidianwatch/backend/internal/store"
	"obsidianwatch/backend/pkg/agentid"
)

type fakeToken struct {
	id             int64
	uses, max      int
	expired, revok bool
}

type fakeEnrollStore struct {
	mu      sync.Mutex
	tokens  map[string]*fakeToken
	ids     map[string]store.AgentIdentity
	revoked map[string]bool
}

func newFakeEnrollStore() *fakeEnrollStore {
	return &fakeEnrollStore{tokens: map[string]*fakeToken{}, ids: map[string]store.AgentIdentity{}, revoked: map[string]bool{}}
}

func (f *fakeEnrollStore) addToken(plain string, max int, expired, revoked bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[TokenHash(plain)] = &fakeToken{id: int64(len(f.tokens) + 1), max: max, expired: expired, revok: revoked}
}

func (f *fakeEnrollStore) ConsumeEnrollmentToken(_ context.Context, h string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.tokens[h]
	if t == nil || t.expired || t.revok || t.uses >= t.max {
		return 0, store.ErrTokenInvalid
	}
	t.uses++
	return t.id, nil
}

func (f *fakeEnrollStore) CreateAgentIdentity(_ context.Context, in store.AgentIdentity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, dup := f.ids[in.AgentID]; dup {
		return fmt.Errorf("duplicate")
	}
	f.ids[in.AgentID] = in
	return nil
}

func (f *fakeEnrollStore) RenewAgentIdentity(_ context.Context, id, serial string, na time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revoked[id] {
		return store.ErrIdentityRevoked
	}
	in := f.ids[id]
	in.CertSerial, in.CertNotAfter = serial, na
	f.ids[id] = in
	return nil
}

func (f *fakeEnrollStore) revoke(id string) {
	f.mu.Lock()
	f.revoked[id] = true
	f.mu.Unlock()
}

func (f *fakeEnrollStore) revokedIDs(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id := range f.revoked {
		out = append(out, id)
	}
	return out, nil
}

type gateRig struct {
	srv    *httptest.Server
	ca     *enroll.CA
	st     *fakeEnrollStore
	ingest *fakeIngestStore
	rev    *agentid.Revocations
}

const testFleetKey = "fleet-key-0123456789abcdef"

func newGateRig(t *testing.T) *gateRig {
	t.Helper()
	ca, _, _, err := enroll.NewCA("test agent CA", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rg := &gateRig{ca: ca, st: newFakeEnrollStore(), ingest: &fakeIngestStore{}}
	rg.rev = agentid.NewRevocations(rg.st.revokedIDs)
	ec := &enrollConfig{ca: ca, certTTL: 30 * 24 * time.Hour, now: time.Now}
	gate := &identityGate{roots: ca.Pool(), revoked: rg.rev, now: time.Now}

	protected := http.NewServeMux()
	protected.HandleFunc("POST /api/v1/events", handleIngest(rg.ingest, 1000, quietLogger()))
	protected.HandleFunc("GET /api/v1/events", certOnlyForbidden(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	protected.HandleFunc("POST /api/v1/enroll/renew", handleRenew(rg.st, ec, quietLogger()))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/enroll", handleEnroll(rg.st, ec, quietLogger()))
	mux.Handle("/api/", gate.wrap(protected))

	rg.srv = httptest.NewUnstartedServer(mux)
	rg.srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.Pool(), MinVersion: tls.VersionTLS13}
	rg.srv.StartTLS()
	t.Cleanup(rg.srv.Close)
	return rg
}

func (rg *gateRig) client(cert *tls.Certificate) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(rg.srv.Certificate())
	cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

func (rg *gateRig) do(t *testing.T, cert *tls.Certificate, method, path string, body any, hdr map[string]string) (int, []byte, error) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, rg.srv.URL+path, rd)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := rg.client(cert).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, nil
}

func newCSR(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "victim-host"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// enrollAs runs the agent side of A1 and returns its TLS identity.
func (rg *gateRig) enrollAs(t *testing.T, token string, hdr map[string]string) (enrollResponse, *tls.Certificate, int) {
	t.Helper()
	k, csr := newCSR(t)
	code, body, err := rg.do(t, nil, "POST", "/api/v1/enroll", map[string]string{"token": token, "csr": csr, "hostname": "web-01", "os": "linux"}, hdr)
	if err != nil {
		t.Fatal(err)
	}
	if code != 200 {
		return enrollResponse{}, nil, code
	}
	var er enrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(k)
	pair, err := tls.X509KeyPair([]byte(er.Certificate), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return er, &pair, code
}

func batch(agent string, eventAgent string) map[string]any {
	ev := map[string]any{"event_type": "process", "host": "web-01", "time": time.Now().UTC().Format(time.RFC3339)}
	if eventAgent != "" {
		ev["agent_id"] = eventAgent
	}
	return map[string]any{"agent_id": agent, "host": "web-01", "events": []any{ev}}
}

func TestEnrollIssuesRandomIdentityPerHost(t *testing.T) {
	rg := newGateRig(t)
	rg.st.addToken("tok-golden-image", 2, false, false)

	a, _, code := rg.enrollAs(t, "tok-golden-image", nil)
	b, _, code2 := rg.enrollAs(t, "tok-golden-image", nil)
	if code != 200 || code2 != 200 {
		t.Fatalf("enroll: %d %d", code, code2)
	}
	if a.AgentID == b.AgentID {
		t.Fatal("two clones of one image got the same agent_id")
	}
	for _, r := range []enrollResponse{a, b} {
		if !agentid.Valid(r.AgentID) || strings.Contains(r.AgentID, "web-01") {
			t.Errorf("agent_id %q must be random, not the hostname", r.AgentID)
		}
		blk, _ := pem.Decode([]byte(r.Certificate))
		c, _ := x509.ParseCertificate(blk.Bytes)
		if id, err := agentid.FromCert(c); err != nil || id != r.AgentID {
			t.Errorf("certificate names %q (%v), want %q", id, err, r.AgentID)
		}
		if c.Subject.CommonName == "victim-host" {
			t.Error("CA copied the CSR subject")
		}
		if d := c.NotAfter.Sub(c.NotBefore); d > 31*24*time.Hour {
			t.Errorf("certificate lifetime %s exceeds 30 days", d)
		}
		if !r.RenewAfter.Before(r.NotAfter) || r.RenewAfter.Before(time.Now().Add(14*24*time.Hour)) {
			t.Errorf("renew_after %s should be about half life", r.RenewAfter)
		}
	}
	if _, _, code := rg.enrollAs(t, "tok-golden-image", nil); code != 401 {
		t.Errorf("used-up token: got %d want 401", code)
	}
}

func TestEnrollTokenRules(t *testing.T) {
	rg := newGateRig(t)
	rg.st.addToken("expired", 5, true, false)
	rg.st.addToken("revoked", 5, false, true)
	for _, tok := range []string{"expired", "revoked", "never-issued", ""} {
		if _, _, code := rg.enrollAs(t, tok, nil); code != 401 {
			t.Errorf("token %q: got %d want 401", tok, code)
		}
	}
	// The fleet key is not an enrollment credential unless allowed.
	if _, _, code := rg.enrollAs(t, "", map[string]string{"X-API-Key": testFleetKey}); code != 401 {
		t.Errorf("fleet key enrollment when disabled: got %d want 401", code)
	}
	// Weak or malformed keys are refused before a token is spent.
	rg.st.addToken("good", 1, false, false)
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, weak)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if code, _, _ := rg.do(t, nil, "POST", "/api/v1/enroll", map[string]string{"token": "good", "csr": csr}, nil); code != 400 {
		t.Errorf("RSA-1024 CSR: got %d want 400", code)
	}
	if _, _, code := rg.enrollAs(t, "good", nil); code != 200 {
		t.Errorf("token must still be unspent after a rejected CSR: got %d", code)
	}
}

// The old shared fleet key opens nothing: not enrollment, not ingest.
func TestFleetKeyNeverWorks(t *testing.T) {
	rg := newGateRig(t)
	key := map[string]string{"X-API-Key": testFleetKey}
	if _, _, code := rg.enrollAs(t, "", key); code != 401 {
		t.Errorf("fleet key enrollment: got %d want 401", code)
	}
	if code, _, _ := rg.do(t, nil, "POST", "/api/v1/events", batch("web-01", ""), key); code != 401 {
		t.Errorf("fleet key ingest: got %d want 401", code)
	}
	if code, _, _ := rg.do(t, nil, "GET", "/api/v1/events", nil, key); code != 401 {
		t.Errorf("fleet key query: got %d want 401", code)
	}
}

func TestForgedAgentIDRejected(t *testing.T) {
	rg := newGateRig(t)
	rg.st.addToken("t", 2, false, false)
	me, myCert, _ := rg.enrollAs(t, "t", nil)
	other, _, _ := rg.enrollAs(t, "t", nil)

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"own id", batch(me.AgentID, ""), 200},
		{"own id on event", batch(me.AgentID, me.AgentID), 200},
		{"other agent's id", batch(other.AgentID, ""), 403},
		{"hostname as id", batch("web-01", ""), 403},
		{"own batch, foreign event", batch(me.AgentID, other.AgentID), 403},
	}
	for _, c := range cases {
		code, body, err := rg.do(t, myCert, "POST", "/api/v1/events", c.body, nil)
		if err != nil || code != c.want {
			t.Errorf("%s: got %d %s (%v) want %d", c.name, code, body, err, c.want)
		}
	}
	for _, e := range rg.ingest.events {
		if e.AgentID != me.AgentID {
			t.Errorf("stored event for %q from %q's certificate", e.AgentID, me.AgentID)
		}
	}
	// A certificate never opens fleet-wide queries.
	if code, _, _ := rg.do(t, myCert, "GET", "/api/v1/events", nil, nil); code != 403 {
		t.Errorf("cert query of all events: got %d want 403", code)
	}
}

func TestCertificateRequired(t *testing.T) {
	rg := newGateRig(t)
	key := map[string]string{"X-API-Key": testFleetKey}
	if code, _, _ := rg.do(t, nil, "POST", "/api/v1/events", batch("web-01", ""), key); code != 401 {
		t.Errorf("fleet key on ingest when enforced: got %d want 401", code)
	}
	// A certificate from a different CA does not get past the handshake.
	other, _, _, _ := enroll.NewCA("attacker CA", time.Hour)
	k, csrPEM := newCSR(t)
	csr, _ := enroll.ParseCSR([]byte(csrPEM))
	forged, certPEM, _ := other.Issue(csr, agentid.New(), time.Hour, time.Now())
	_ = forged
	keyDER, _ := x509.MarshalECPrivateKey(k)
	pair, _ := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if code, _, err := rg.do(t, &pair, "POST", "/api/v1/events", batch("x", ""), nil); err == nil && code == 200 {
		t.Error("certificate from a foreign CA was accepted")
	}
}

func TestRevocationTakesEffect(t *testing.T) {
	if agentid.DefaultRefresh > 30*time.Second {
		t.Fatalf("refresh interval %s leaves no margin in the 60 s revocation budget", agentid.DefaultRefresh)
	}
	rg := newGateRig(t)
	rg.st.addToken("t", 1, false, false)
	me, cert, _ := rg.enrollAs(t, "t", nil)
	if code, _, _ := rg.do(t, cert, "POST", "/api/v1/events", batch(me.AgentID, ""), nil); code != 200 {
		t.Fatalf("before revoke: %d", code)
	}
	rg.st.revoke(me.AgentID)
	_ = rg.rev.Refresh(context.Background()) // what the ticker does every DefaultRefresh
	if code, _, _ := rg.do(t, cert, "POST", "/api/v1/events", batch(me.AgentID, ""), nil); code != 401 {
		t.Errorf("after revoke, ingest: got %d want 401", code)
	}
	_, csr := newCSR(t)
	if code, _, _ := rg.do(t, cert, "POST", "/api/v1/enroll/renew", map[string]string{"csr": csr}, nil); code != 401 {
		t.Errorf("after revoke, renew: got %d want 401", code)
	}
}

func TestRenewKeepsIdentity(t *testing.T) {
	rg := newGateRig(t)
	rg.st.addToken("t", 1, false, false)
	me, cert, _ := rg.enrollAs(t, "t", nil)
	_, csr := newCSR(t)
	code, body, _ := rg.do(t, cert, "POST", "/api/v1/enroll/renew", map[string]string{"csr": csr}, nil)
	if code != 200 {
		t.Fatalf("renew: %d %s", code, body)
	}
	var r enrollResponse
	_ = json.Unmarshal(body, &r)
	if r.AgentID != me.AgentID || r.Certificate == me.Certificate {
		t.Errorf("renew changed identity or returned the old certificate")
	}
	// Renewal without a certificate is not possible, fleet key or not.
	if code, _, _ := rg.do(t, nil, "POST", "/api/v1/enroll/renew", map[string]string{"csr": csr}, map[string]string{"X-API-Key": testFleetKey}); code != 401 {
		t.Errorf("renew without cert: got %d want 401", code)
	}
}

// Client certificates from the deployment CA (the old mtls_enabled option)
// carry no agent identity and are refused.
func TestDeploymentCertificatesRefused(t *testing.T) {
	agentCA, _, _, _ := enroll.NewCA("agent CA", 365*24*time.Hour)
	// The deployment CA (cert-init) signs a client certificate with no agent identity.
	dk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dtmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "deployment CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	dder, _ := x509.CreateCertificate(rand.Reader, dtmpl, dtmpl, &dk.PublicKey, dk)
	deployCA, _ := x509.ParseCertificate(dder)
	k, _ := newCSR(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "web-01"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	legacyDER, err := x509.CreateCertificate(rand.Reader, tmpl, deployCA, &k.PublicKey, dk)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(legacyDER)
	for _, c := range []struct {
		mode string
		want int
	}{{"default", 401}} {
		g := &identityGate{roots: agentCA.Pool(), now: time.Now}
		h := g.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := certIdentity(r); ok {
				t.Error("legacy certificate produced an identity")
			}
			w.WriteHeader(200)
		}))
		r := httptest.NewRequest("POST", "/api/v1/events", nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, deployCA}}}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if rr.Code != c.want {
			t.Errorf("%s: got %d want %d", c.mode, rr.Code, c.want)
		}
	}
}
