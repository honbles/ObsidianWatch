package api

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

const tunnelVector = "6c91d6533660a7a8649d0b38a700c1c75500dadae5478d47e4cb1c7cbac4b06b"

func TestTunnelSignatureVector(t *testing.T) {
	// Same vector as management's test: both servers must sign identically.
	if got := SignTunnelIdentity(TunnelIdentityKey("secret"), "ag-00000000000000000000000000000000", "ab", 1700000000); got != tunnelVector {
		t.Fatalf("signature %s", got)
	}
	if TunnelIdentityKey("") != nil {
		t.Fatal("empty secret must give no key")
	}
}

// fakeMgmt records what the management server receives and echoes bytes
// after a WebSocket-style upgrade.
type seen struct{ id, serial, ts, sig, key, claimed string }

func newFakeMgmt(t *testing.T) (*httptest.Server, chan seen) {
	ch := make(chan seen, 4)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ch <- seen{r.Header.Get(HdrAgentID), r.Header.Get(HdrAgentSerial), r.Header.Get(HdrAgentTime), r.Header.Get(HdrAgentSig), r.Header.Get("X-API-Key"), r.URL.Query().Get("agent_id")}
		if r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(400)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		brw.Flush()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(brw, buf); err == nil {
			conn.Write(buf)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

func TestTunnelRidesIngestPort(t *testing.T) {
	mgmt, got := newFakeMgmt(t)
	rg := newGateRig(t)
	tp, err := newTunnelProxy(mgmt.URL, "", "", true, "secret", quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	rg.st.addToken("t", 2, false, false)
	me, cert, _ := rg.enrollAs(t, "t", nil)
	other, _, _ := rg.enrollAs(t, "t", nil)
	// Rebuild the rig's server with the tunnel route on the protected mux.
	gate := &identityGate{roots: rg.ca.Pool(), revoked: rg.rev, now: time.Now}
	protected := http.NewServeMux()
	protected.Handle("GET /api/v1/live-response/agent-tunnel", tp)
	rg.srv.Config.Handler = gate.wrap(protected)

	open := func(c *tls.Certificate, q string, hdr map[string]string) (int, io.ReadWriteCloser) {
		req, _ := http.NewRequest("GET", rg.srv.URL+"/api/v1/live-response/agent-tunnel?agent_id="+q, nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		cl := rg.client(c)
		cl.Timeout = 0 // a timeout wraps the body and hides the upgraded connection
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 101 {
			resp.Body.Close()
			return resp.StatusCode, nil
		}
		return 101, resp.Body.(io.ReadWriteCloser)
	}

	// 1. Enrolled agent: identity is verified here and signed for management;
	//    forged identity headers from the client are replaced.
	code, conn := open(cert, me.AgentID, map[string]string{HdrAgentID: other.AgentID, HdrAgentSig: "forged"})
	if code != 101 {
		t.Fatalf("enrolled tunnel: %d", code)
	}
	s := <-got
	if s.id != me.AgentID || s.sig == "" {
		t.Fatalf("management saw %+v", s)
	}
	ts, _ := strconv.ParseInt(s.ts, 10, 64)
	if SignTunnelIdentity(TunnelIdentityKey("secret"), s.id, s.serial, ts) != s.sig {
		t.Fatal("signature does not verify")
	}
	conn.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(bufio.NewReader(conn), buf); err != nil || string(buf) != "hello" {
		t.Fatalf("tunnel bytes: %q %v", buf, err)
	}
	conn.Close()

	// 2. A certificate cannot open another agent's tunnel.
	if code, _ := open(cert, other.AgentID, nil); code != 403 {
		t.Errorf("claiming another agent: %d", code)
	}
	// 3. The old fleet key opens nothing.
	if code, _ := open(nil, other.AgentID, map[string]string{"X-API-Key": testFleetKey}); code != 401 {
		t.Errorf("fleet key tunnel: %d", code)
	}
	if code, _ := open(nil, "web-01", map[string]string{"X-API-Key": testFleetKey, HdrAgentID: me.AgentID}); code != 401 {
		t.Errorf("fleet key tunnel with forged identity header: %d", code)
	}
	// 4. No credentials at all.
	if code, _ := open(nil, "web-01", nil); code != 401 {
		t.Errorf("no credentials: %d", code)
	}
}
