package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifyInstallKeyIgnoresQueryString(t *testing.T) {
	// nil db: the handler must reject before touching it when no body key is given.
	h := handleVerifyInstallKey(nil, "agentkey")
	r := httptest.NewRequest(http.MethodGet, "/api/v1/verify-install-key?key=abc123", nil)
	r.Header.Set("X-API-Key", "agentkey")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 400 {
		t.Fatalf("query-string key must not be accepted, got %d", w.Code)
	}
}

func TestRegisterKeyRejectsOversizedFields(t *testing.T) {
	h := handleAgentRegisterKey(nil, "agentkey") // rejected before any DB use
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'a'
	}
	body := `{"install_key":"k","agent_id":"` + string(long) + `","os":"linux"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/register-key", strings.NewReader(body))
	r.Header.Set("X-API-Key", "agentkey")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 400 {
		t.Fatalf("got %d, want 400", w.Code)
	}
}
