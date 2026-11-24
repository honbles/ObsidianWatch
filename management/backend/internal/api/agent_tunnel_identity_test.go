package api

// Gate tests for spec A2/A3/A4 on the management side (tunnel identity,
// one tunnel per agent, results only from the asked agent, revocation).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"obsidianwatch/management/internal/agentid"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: k, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (ca *testCA) issue(t *testing.T, id string, serial int64) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(agentid.URIPrefix + id)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: id}, URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func newTestTunnelAuth(t *testing.T, mode string, ca *testCA, revoked ...string) *tunnelAuth {
	t.Helper()
	pool := &agentCAPool{load: func(context.Context) (string, error) { return ca.pem, nil }}
	if err := pool.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	rev := agentid.NewRevocations(func(context.Context) ([]string, error) { return revoked, nil })
	_ = rev.Refresh(context.Background())
	return &tunnelAuth{mode: mode, ca: pool, rev: rev, apiKey: "fleet-key", now: time.Now}
}

func tunnelReq(cert *x509.Certificate, claimed, key string) *http.Request {
	r := httptest.NewRequest("GET", "/api/v1/live-response/agent-tunnel?agent_id="+url.QueryEscape(claimed), nil)
	if cert != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	if key != "" {
		r.Header.Set("X-API-Key", key)
	}
	return r
}

func authCode(err error) int {
	if err == nil {
		return 200
	}
	if ae, ok := err.(*authError); ok {
		return ae.code
	}
	return -1
}

func TestTunnelAuthenticatesByCertificate(t *testing.T) {
	ca, attacker := newTestCA(t), newTestCA(t)
	me, other, gone := agentid.New(), agentid.New(), agentid.New()
	ta := newTestTunnelAuth(t, tunnelAuthMixed, ca, gone)
	mine := ca.issue(t, me, 10)

	cases := []struct {
		name string
		r    *http.Request
		want int
		id   string
	}{
		{"own cert, no claim", tunnelReq(mine, "", ""), 200, me},
		{"own cert, own claim", tunnelReq(mine, me, ""), 200, me},
		{"own cert, other agent's id", tunnelReq(mine, other, ""), 403, ""},
		{"own cert, hostname", tunnelReq(mine, "web-01", "fleet-key"), 403, ""},
		{"foreign CA", tunnelReq(attacker.issue(t, me, 11), me, ""), 401, ""},
		{"revoked identity", tunnelReq(ca.issue(t, gone, 12), gone, ""), 401, ""},
		{"fleet key, legacy host id", tunnelReq(nil, "web-01", "fleet-key"), 200, "web-01"},
		{"fleet key, enrolled id", tunnelReq(nil, me, "fleet-key"), 403, ""},
		{"wrong fleet key", tunnelReq(nil, "web-01", "nope"), 401, ""},
	}
	for _, c := range cases {
		got, err := ta.authenticate(c.r)
		if authCode(err) != c.want || (c.want == 200 && got.agentID != c.id) {
			t.Errorf("%s: got %d %q (%v), want %d %q", c.name, authCode(err), got.agentID, err, c.want, c.id)
		}
	}

	enforced := newTestTunnelAuth(t, tunnelAuthEnforced, ca)
	if _, err := enforced.authenticate(tunnelReq(nil, "web-01", "fleet-key")); authCode(err) != 401 {
		t.Errorf("enforced mode accepted the fleet key: %v", err)
	}
	if got, err := enforced.authenticate(tunnelReq(mine, "", "")); err != nil || got.agentID != me {
		t.Errorf("enforced mode refused a valid certificate: %v", err)
	}
}

func TestOneTunnelPerAgent(t *testing.T) {
	reg := NewTunnelRegistry()
	live := &agentTunnel{agentID: "ag", certSerial: "a1"}
	if _, ok := reg.Claim("ag", live); !ok {
		t.Fatal("first claim refused")
	}
	for _, intruder := range []*agentTunnel{{certSerial: "b2"}, {certSerial: ""}} {
		holder, ok := reg.Claim("ag", intruder)
		if ok || holder != live {
			t.Fatalf("second tunnel (cert %q) replaced the live one", intruder.certSerial)
		}
		if got, _ := reg.Get("ag"); got != live {
			t.Fatal("live tunnel lost")
		}
	}
	// Same certificate reconnecting (agent restarted) replaces its stale entry.
	again := &agentTunnel{agentID: "ag", certSerial: "a1"}
	prev, ok := reg.Claim("ag", again)
	if !ok || prev != live {
		t.Fatal("same-certificate reconnect refused")
	}
	// Fleet-key tunnels never replace one another either.
	legacy := &agentTunnel{agentID: "web-01"}
	reg.Claim("web-01", legacy)
	if _, ok := reg.Claim("web-01", &agentTunnel{agentID: "web-01"}); ok {
		t.Fatal("second fleet-key tunnel replaced a live one")
	}
}

func TestActionResultOnlyFromAskedAgent(t *testing.T) {
	b := newActionBroker()
	got := make(chan actionResult, 2)
	b.expect("ag-victim", "tok", time.Minute, func(r actionResult) { got <- r })
	forged, _ := json.Marshal(actionResult{OK: true, Message: "isolated"})
	if b.deliverFrom("ag-attacker", "tok", forged) {
		t.Fatal("result from another agent's tunnel accepted")
	}
	select {
	case <-got:
		t.Fatal("forged result reached the waiter")
	case <-time.After(30 * time.Millisecond):
	}
	if !b.deliverFrom("ag-victim", "tok", forged) {
		t.Fatal("genuine result dropped")
	}
	if r := <-got; !r.OK {
		t.Fatalf("result: %+v", r)
	}
	if b.deliverFrom("ag-victim", "never-issued", forged) {
		t.Fatal("unsolicited result accepted")
	}
}

func TestRevocationClosesLiveTunnel(t *testing.T) {
	up := websocket.Upgrader{}
	serverConn := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := up.Upgrade(w, r, nil)
		serverConn <- c
	}))
	defer srv.Close()
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sc := <-serverConn

	reg := NewTunnelRegistry()
	reg.Claim("ag-x", &agentTunnel{agentID: "ag-x", certSerial: "s", conn: sc})
	rev := agentid.NewRevocations(func(context.Context) ([]string, error) { return []string{"ag-x"}, nil })
	rev.OnLoad(func(m map[string]bool) { reg.closeRevokedTunnels(m, slog.New(slog.NewTextHandler(io.Discard, nil))) })
	if agentid.DefaultRefresh > 30*time.Second {
		t.Fatalf("refresh %s leaves no margin in the 60 s budget", agentid.DefaultRefresh)
	}
	_ = rev.Refresh(context.Background())
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := client.ReadMessage(); err == nil {
		t.Fatal("tunnel still open after revocation")
	}
}

func TestEnrollmentTokenFormat(t *testing.T) {
	a, b := newEnrollmentToken(), newEnrollmentToken()
	if a == b || !strings.HasPrefix(a, "owe_") || len(a) < 40 {
		t.Fatalf("weak token: %q", a)
	}
	// Must match backend api.TokenHash (sha256 hex of the trimmed token).
	if enrollmentTokenHash(" x ") != "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881" {
		t.Fatal("token hash differs from the ingest backend's")
	}
}
