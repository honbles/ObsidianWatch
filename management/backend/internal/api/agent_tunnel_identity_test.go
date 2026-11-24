package api

// Gate tests for spec A2/A3/A4 on the management side (tunnel identity,
// one tunnel per agent, results only from the asked agent, revocation).

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"obsidianwatch/management/internal/agentid"
)

func newTestTunnelAuth(t *testing.T, revoked ...string) *tunnelAuth {
	t.Helper()
	rev := agentid.NewRevocations(func(context.Context) ([]string, error) { return revoked, nil })
	_ = rev.Refresh(context.Background())
	return &tunnelAuth{rev: rev, now: time.Now, fwdKey: tunnelIdentityKey("secret")}
}

func tunnelReq(claimed, key string) *http.Request {
	r := httptest.NewRequest("GET", "/api/v1/live-response/agent-tunnel?agent_id="+url.QueryEscape(claimed), nil)
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

// No API key, no direct connection: only an identity the backend signed.
func TestTunnelNeedsForwardedIdentity(t *testing.T) {
	ta := newTestTunnelAuth(t)
	for _, r := range []*http.Request{tunnelReq("web-01", "fleet-key"), tunnelReq(agentid.New(), ""), tunnelReq("", "")} {
		if _, err := ta.authenticate(r); authCode(err) != 401 {
			t.Errorf("%s accepted: %v", r.URL, err)
		}
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

func TestForwardedTunnelIdentity(t *testing.T) {
	// Same vector as the ingest backend's test.
	if got := signTunnelIdentity(tunnelIdentityKey("secret"), "ag-00000000000000000000000000000000", "ab", 1700000000); got != "6c91d6533660a7a8649d0b38a700c1c75500dadae5478d47e4cb1c7cbac4b06b" {
		t.Fatalf("signature differs from the backend's: %s", got)
	}
	me, other, gone := agentid.New(), agentid.New(), agentid.New()
	ta := newTestTunnelAuth(t, gone)
	now := time.Now()
	fwd := func(key []byte, id, claimed string, at time.Time, sig string) *http.Request {
		r := tunnelReq(claimed, "")
		ts := at.Unix()
		r.Header.Set(hdrAgentID, id)
		r.Header.Set(hdrAgentSerial, "5e1a")
		r.Header.Set(hdrAgentTime, strconv.FormatInt(ts, 10))
		if sig == "" {
			sig = signTunnelIdentity(key, id, "5e1a", ts)
		}
		r.Header.Set(hdrAgentSig, sig)
		return r
	}
	good := tunnelIdentityKey("secret")
	cases := []struct {
		name string
		r    *http.Request
		want int
	}{
		{"verified by backend", fwd(good, me, me, now, ""), 200},
		{"no claim", fwd(good, me, "", now, ""), 200},
		{"claims another agent", fwd(good, me, other, now, ""), 403},
		{"wrong key", fwd(tunnelIdentityKey("guess"), me, me, now, ""), 401},
		{"forged signature", fwd(good, me, me, now, "00"), 401},
		{"replayed later", fwd(good, me, me, now.Add(-2*time.Minute), ""), 401},
		{"revoked", fwd(good, gone, gone, now, ""), 401},
		{"hostname id", fwd(good, "web-01", "web-01", now, ""), 401},
	}
	for _, c := range cases {
		got, err := ta.authenticate(c.r)
		if authCode(err) != c.want || (c.want == 200 && got.agentID != me) {
			t.Errorf("%s: got %d %q (%v) want %d", c.name, authCode(err), got.agentID, err, c.want)
		}
	}
	ta.fwdKey = nil
	if _, err := ta.authenticate(fwd(good, me, me, now, "")); authCode(err) != 401 {
		t.Error("forwarded identity accepted without OW_SECRET_KEY")
	}
}
