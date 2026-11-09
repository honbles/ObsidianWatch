package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if c := GetClaims(r); c != nil {
		w.Header().Set("X-User", c.Username)
	}
	w.WriteHeader(200)
})

func TestJWTSignVerifyRevoke(t *testing.T) {
	j := NewJWTService("test-secret-123456789012345678901234", time.Hour)
	tok, err := j.Sign(7, "alice", "admin")
	if err != nil {
		t.Fatal(err)
	}
	c, err := j.Verify(tok)
	if err != nil || c.Username != "alice" || c.Role != "admin" || c.UserID != 7 {
		t.Fatalf("verify: %v %+v", err, c)
	}
	j.Revoke(c)
	if _, err := j.Verify(tok); err == nil {
		t.Fatal("revoked token must fail")
	}
	other := NewJWTService("a-different-secret-1234567890123456", time.Hour)
	tok2, _ := j.Sign(1, "bob", "viewer")
	if _, err := other.Verify(tok2); err == nil {
		t.Fatal("token from another secret must fail")
	}
	if _, err := j.Verify("garbage"); err == nil {
		t.Fatal("garbage must fail")
	}
}

func TestJWTExpiry(t *testing.T) {
	j := NewJWTService("test-secret-123456789012345678901234", -time.Minute)
	tok, _ := j.Sign(1, "x", "viewer")
	if _, err := j.Verify(tok); err == nil {
		t.Fatal("expired token must fail")
	}
}

func TestMiddleware(t *testing.T) {
	j := NewJWTService("test-secret-123456789012345678901234", time.Hour)
	h := Middleware(j)(okHandler)
	do := func(path, authz, query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path+query, nil)
		if authz != "" {
			r.Header.Set("Authorization", authz)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if do("/api/v1/alerts", "", "").Code != 401 {
		t.Error("missing token must be 401")
	}
	if do("/api/v1/alerts", "Bearer nope", "").Code != 401 {
		t.Error("bad token must be 401")
	}
	tok, _ := j.Sign(1, "carol", "viewer")
	w := do("/api/v1/alerts", "Bearer "+tok, "")
	if w.Code != 200 || w.Header().Get("X-User") != "carol" {
		t.Errorf("valid bearer: %d %q", w.Code, w.Header().Get("X-User"))
	}
	if do("/ws/events", "", "?auth="+tok).Code != 401 {
		t.Error("JWT in the query string must no longer authenticate")
	}
	tk, _ := IssueWSTicket(&Claims{UserID: 1, Username: "carol", Role: "viewer"})
	if do("/api/v1/alerts", "", "?ticket="+tk).Code != 401 {
		t.Error("a ticket must not work on non-WebSocket paths")
	}
	tk, _ = IssueWSTicket(&Claims{UserID: 1, Username: "carol", Role: "viewer"})
	if do("/ws/events", "", "?ticket="+tk).Code != 200 {
		t.Error("valid ticket should work for websockets")
	}
	if do("/ws/events", "", "?ticket="+tk).Code != 401 {
		t.Error("ticket must be single-use")
	}
	if do("/api/v1/verify-install-key", "", "").Code != 200 {
		t.Error("public path should pass")
	}
	if do("/api/v1/devops/webhook/12", "", "").Code != 200 {
		t.Error("webhook prefix should pass")
	}
	if do("/api/v1/verify-install-keyX", "", "").Code != 401 {
		t.Error("public path matching must be exact")
	}
}

func TestAgentKeyMiddlewareFailsClosed(t *testing.T) {
	call := func(configured, sent string) int {
		h := AgentKeyMiddleware(configured)(okHandler)
		r := httptest.NewRequest("GET", "/x", nil)
		if sent != "" {
			r.Header.Set("X-API-Key", sent)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if call("", "") != 503 || call("", "anything") != 503 {
		t.Error("empty configured key must reject everything")
	}
	if call("k1", "") != 401 || call("k1", "k2") != 401 {
		t.Error("wrong key must be 401")
	}
	if call("k1", "k1") != 200 {
		t.Error("right key must pass")
	}
}

func TestRevokeUserInvalidatesOlderTokens(t *testing.T) {
	j := NewJWTService("test-secret-123456789012345678901234", time.Hour)
	old, _ := j.Sign(5, "dave", "viewer")
	other, _ := j.Sign(6, "erin", "viewer")
	time.Sleep(1100 * time.Millisecond) // JWT iat has 1s resolution
	j.RevokeUser(5)
	if _, err := j.Verify(old); err == nil {
		t.Fatal("token issued before RevokeUser must fail")
	}
	if _, err := j.Verify(other); err != nil {
		t.Fatalf("other users must be unaffected: %v", err)
	}
	fresh, _ := j.Sign(5, "dave", "viewer")
	if _, err := j.Verify(fresh); err != nil {
		t.Fatalf("token issued after RevokeUser must work: %v", err)
	}
}

func TestUserCutoffPersistAndRestore(t *testing.T) {
	j := NewJWTService("test-secret-123456789012345678901234", time.Hour)
	var gotID int64
	var gotCut time.Time
	j.OnUserRevoked = func(id int64, c time.Time) { gotID, gotCut = id, c }
	j.RevokeUser(5)
	if gotID != 5 || gotCut.IsZero() {
		t.Fatalf("callback not invoked: %d %v", gotID, gotCut)
	}
	// A fresh service (restart) starts with no cutoffs, then restores them.
	j2 := NewJWTService("test-secret-123456789012345678901234", time.Hour)
	tok, _ := j2.Sign(5, "u", "analyst")
	if _, err := j2.Verify(tok); err != nil {
		t.Fatal(err)
	}
	j2.RestoreUserCutoffs(map[int64]time.Time{5: time.Now().Add(time.Hour)})
	if _, err := j2.Verify(tok); err == nil {
		t.Fatal("restored cutoff must invalidate older tokens")
	}
}

func TestRevokedJTISurvivesRestartViaCallbacks(t *testing.T) {
	saved := map[string]time.Time{}
	j1 := NewJWTService("0123456789abcdef0123456789abcdef", time.Hour)
	j1.OnRevoked = func(jti string, exp time.Time) { saved[jti] = exp }
	tok, _ := j1.Sign(1, "dave", "viewer")
	claims, err := j1.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	j1.Revoke(claims)
	if len(saved) != 1 {
		t.Fatal("revocation not reported to OnRevoked")
	}
	// "Restart": a new service restored from what was saved.
	j2 := NewJWTService("0123456789abcdef0123456789abcdef", time.Hour)
	if _, err := j2.Verify(tok); err != nil {
		t.Fatal("before restore the token should verify on a fresh service")
	}
	j2.RestoreRevoked(saved)
	if _, err := j2.Verify(tok); err == nil {
		t.Fatal("token must stay revoked after restore")
	}
	j2.RestoreRevoked(map[string]time.Time{"old": time.Now().Add(-time.Hour)})
}
