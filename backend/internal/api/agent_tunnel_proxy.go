package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"time"
)

// The live-response tunnel rides on the ingest port (spec A2 without a new
// port): the agent opens it here with the same client certificate it uses
// for ingest, this server verifies the certificate, and the WebSocket is
// passed through to the management server. The verified identity travels in
// headers signed with a key both servers derive from OW_SECRET_KEY, so the
// management server can tell a verified agent from anyone who can reach it.

// Forwarded identity headers. Anything a client sends under these names is
// removed before the request is passed on.
const (
	HdrAgentID     = "X-Ow-Agent-Id"
	HdrAgentSerial = "X-Ow-Agent-Serial"
	HdrAgentTime   = "X-Ow-Agent-Time"
	HdrAgentSig    = "X-Ow-Agent-Sig"
)

// TunnelIdentityKey derives the header-signing key from the shared secret.
// management/backend/internal/api uses the same derivation.
func TunnelIdentityKey(secret string) []byte {
	if secret == "" {
		return nil
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("obsidianwatch tunnel identity v1"))
	return m.Sum(nil)
}

// SignTunnelIdentity signs id|serial|unix-time.
func SignTunnelIdentity(key []byte, id, serial string, ts int64) string {
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "%s|%s|%d", id, serial, ts)
	return hex.EncodeToString(m.Sum(nil))
}

type tunnelProxy struct {
	rp     *httputil.ReverseProxy
	key    []byte
	now    func() time.Time
	logger *slog.Logger
}

// newTunnelProxy builds the pass-through to the management server.
// caFile/serverName verify the management certificate (the deployment CA
// and a name in its SANs); insecure skips that check (lab use only).
func newTunnelProxy(target, caFile, serverName string, insecure bool, secret string, logger *slog.Logger) (*tunnelProxy, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("tunnel proxy: invalid management url %q", target)
	}
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, InsecureSkipVerify: insecure} //nolint:gosec // opt-in, documented
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("tunnel proxy: read management CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tunnel proxy: no certificate in %s", caFile)
		}
		tcfg.RootCAs = pool
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.URL.Path = pr.In.URL.Path // keep the route; SetURL would prefix a base path
			pr.Out.URL.RawPath = ""
			pr.Out.Host = u.Host
			pr.SetXForwarded()
		},
		Transport: &http.Transport{TLSClientConfig: tcfg, Proxy: nil, ResponseHeaderTimeout: 30 * time.Second},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Warn("tunnel proxy: management unreachable", "err", err)
			http.Error(w, `{"error":"management server unreachable"}`, http.StatusBadGateway)
		},
	}
	return &tunnelProxy{rp: rp, key: TunnelIdentityKey(secret), now: time.Now, logger: logger}, nil
}

func (p *tunnelProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, h := range []string{HdrAgentID, HdrAgentSerial, HdrAgentTime, HdrAgentSig} {
		r.Header.Del(h)
	}
	r.Header.Del("X-API-Key") // never passed on: there is no shared key any more
	claimed := r.URL.Query().Get("agent_id")
	id, ok := certIdentity(r)
	if !ok {
		http.Error(w, `{"error":"client certificate required"}`, http.StatusUnauthorized)
		return
	}
	if claimed != "" && claimed != id.AgentID {
		http.Error(w, errAgentMismatch, http.StatusForbidden)
		return
	}
	if p.key == nil {
		http.Error(w, `{"error":"identity forwarding is not configured (OW_SECRET_KEY)"}`, http.StatusServiceUnavailable)
		return
	}
	ts := p.now().Unix()
	r.Header.Set(HdrAgentID, id.AgentID)
	r.Header.Set(HdrAgentSerial, id.Serial)
	r.Header.Set(HdrAgentTime, strconv.FormatInt(ts, 10))
	r.Header.Set(HdrAgentSig, SignTunnelIdentity(p.key, id.AgentID, id.Serial, ts))
	// A WebSocket lives far longer than the server's request timeouts.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	p.rp.ServeHTTP(w, r)
}
