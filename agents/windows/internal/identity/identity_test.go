package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCA is a minimal enrollment server: it signs CSRs with a test CA.
func fakeServer(t *testing.T, ttl time.Duration, revoked *atomic.Bool, enrolls *atomic.Int32) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	ca := newTestCA(t)
	mux := http.NewServeMux()
	issue := func(w http.ResponseWriter, csrPEM, id string) {
		c := ca.sign(t, csrPEM, id, ttl)
		json.NewEncoder(w).Encode(map[string]any{"agent_id": id, "certificate": c, "ca_certificate": ca.pem,
			"not_after": time.Now().Add(ttl), "renew_after": time.Now().Add(ttl / 2)})
	}
	mux.HandleFunc("POST /api/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		if b["token"] != "good-token" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"enrollment token is invalid"}`))
			return
		}
		n := enrolls.Add(1)
		issue(w, b["csr"], "ag-"+strings.Repeat("0", 31)+string(rune('0'+n)))
	})
	mux.HandleFunc("POST /api/v1/enroll/renew", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(401)
			return
		}
		if revoked.Load() {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"agent identity revoked"}`))
			return
		}
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		issue(w, b["csr"], r.TLS.PeerCertificates[0].Subject.CommonName)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func TestEnrollPersistRenewRevoke(t *testing.T) {
	var revoked atomic.Bool
	var enrolls atomic.Int32
	srv, pool := fakeServer(t, 2*time.Hour, &revoked, &enrolls)
	dir := t.TempDir()
	opt := Options{BackendURL: srv.URL, Token: "good-token", RootCAs: pool, Dir: dir, Hostname: "web-01", OS: "linux", Version: "t"}

	m, err := New(opt)
	if err != nil || m.State() != StateNone {
		t.Fatalf("new: %v %s", err, m.State())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	id := m.AgentID()
	if !strings.HasPrefix(id, "ag-") || m.State() != StateValid {
		t.Fatalf("after enroll: %q %s", id, m.State())
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(dir, "identity", "agent-identity.json"))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("bundle mode: %v %v", st, err)
		}
		dst, _ := os.Stat(filepath.Join(dir, "identity"))
		if dst.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %v", dst.Mode().Perm())
		}
	}

	// A restart loads the same identity without enrolling again.
	m2, _ := New(opt)
	if m2.AgentID() != id || m2.State() != StateValid || enrolls.Load() != 1 {
		t.Fatalf("reload: %q %s enrolls=%d", m2.AgentID(), m2.State(), enrolls.Load())
	}
	before := m2.NotAfter()
	time.Sleep(1100 * time.Millisecond)
	if err := m2.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	if m2.AgentID() != id || !m2.NotAfter().After(before) {
		t.Fatal("renew changed id or did not extend")
	}
	revoked.Store(true)
	if err := m2.Renew(ctx); err != ErrRevoked || m2.State() != StateRevoked {
		t.Fatalf("revoked: %v %s", err, m2.State())
	}
	if err := m2.Ensure(ctx); err != ErrRevoked || enrolls.Load() != 1 {
		t.Fatal("a revoked agent must not enroll again on its own")
	}
}

func TestBadTokenAndNoToken(t *testing.T) {
	var r atomic.Bool
	var n atomic.Int32
	srv, pool := fakeServer(t, time.Hour, &r, &n)
	m, _ := New(Options{BackendURL: srv.URL, Token: "wrong", RootCAs: pool, Dir: t.TempDir()})
	if err := m.Enroll(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad token: %v", err)
	}
	m, _ = New(Options{BackendURL: srv.URL, RootCAs: pool, Dir: t.TempDir()})
	if err := m.Enroll(context.Background()); err == nil || !strings.Contains(err.Error(), "no enrollment token") {
		t.Fatalf("no token: %v", err)
	}
}

func TestExpiredCertificateEnrollsAgain(t *testing.T) {
	var r atomic.Bool
	var n atomic.Int32
	srv, pool := fakeServer(t, time.Second, &r, &n)
	dir := t.TempDir()
	opt := Options{BackendURL: srv.URL, Token: "good-token", RootCAs: pool, Dir: dir}
	m, _ := New(opt)
	ctx := context.Background()
	if err := m.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	first := m.AgentID()
	time.Sleep(1500 * time.Millisecond)
	m2, _ := New(opt)
	if m2.State() != StateExpired {
		t.Fatalf("state %s", m2.State())
	}
	if err := m2.Ensure(ctx); err != nil || m2.AgentID() == first {
		t.Fatalf("re-enroll: %v %q", err, m2.AgentID())
	}
}

func TestApplyActive(t *testing.T) {
	cfg := &tls.Config{}
	ApplyActive(cfg)
	if cfg.GetClientCertificate != nil {
		t.Fatal("no active identity must leave the config alone")
	}
	m, _ := New(Options{Dir: t.TempDir()})
	SetActive(m)
	defer SetActive(nil)
	ApplyActive(cfg)
	if c, err := cfg.GetClientCertificate(nil); err != nil || c == nil {
		t.Fatal("hook not installed")
	}
}
