package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/agentid"
)

// signedAgentRequest builds a request as the ingest backend passes it on.
func signedAgentRequest(ta *tunnelAuth, method, path, body, id string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	ts := time.Now().Unix()
	r.Header.Set(hdrAgentID, id)
	r.Header.Set(hdrAgentSerial, "s1")
	r.Header.Set(hdrAgentTime, strconv.FormatInt(ts, 10))
	r.Header.Set(hdrAgentSig, signTunnelIdentity(ta.fwdKey, id, "s1", ts))
	return r
}

func TestInstallKeyRoutesNeedAgentIdentity(t *testing.T) {
	ta := newTestTunnelAuth(t)
	for _, h := range []http.HandlerFunc{handleVerifyInstallKey(nil, ta), handleAgentRegisterKey(nil, ta)} {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"key":"k","install_key":"k"}`))
		r.Header.Set("X-API-Key", "old-fleet-key")
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != 401 {
			t.Fatalf("fleet key accepted: %d", w.Code)
		}
	}
}

func TestVerifyInstallKeyIgnoresQueryString(t *testing.T) {
	ta := newTestTunnelAuth(t)
	// nil db: the handler must reject before touching it when no body key is given.
	h := handleVerifyInstallKey(nil, ta)
	r := signedAgentRequest(ta, http.MethodPost, "/api/v1/verify-install-key?key=abc123", "", agentid.New())
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 400 {
		t.Fatalf("query-string key must not be accepted, got %d", w.Code)
	}
}

func TestRegisterKeyRejectsOtherAgentAndOversizedFields(t *testing.T) {
	ta := newTestTunnelAuth(t)
	h := handleAgentRegisterKey(nil, ta) // rejected before any DB use
	me := agentid.New()
	for _, c := range []struct {
		body string
		want int
	}{
		{`{"install_key":"k","agent_id":"` + agentid.New() + `","os":"linux"}`, 403},
		{`{"install_key":"k","agent_id":"` + strings.Repeat("a", 200) + `","os":"linux"}`, 400},
	} {
		w := httptest.NewRecorder()
		h(w, signedAgentRequest(ta, http.MethodPost, "/api/v1/agent/register-key", c.body, me))
		if w.Code != c.want {
			t.Errorf("%s: got %d want %d", c.body[:40], w.Code, c.want)
		}
	}
}
