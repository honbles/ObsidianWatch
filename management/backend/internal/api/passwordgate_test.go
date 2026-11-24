package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

func TestPasswordGate(t *testing.T) {
	state := map[int64]bool{1: false, 2: true}
	calls := 0
	g := newPasswordGate(func(_ context.Context, id int64) (bool, error) {
		calls++
		if id == 9 {
			return false, errors.New("db down")
		}
		v, ok := state[id]
		if !ok {
			return false, sql.ErrNoRows
		}
		return v, nil
	})
	h := g.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	do := func(uid int64, method, path string) int {
		r := httptest.NewRequest(method, path, nil)
		if uid != 0 {
			r = r.WithContext(context.WithValue(r.Context(), auth.ClaimsKey, &auth.Claims{UserID: uid, Username: "u", Role: "admin"}))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	cases := []struct {
		uid          int64
		method, path string
		want         int
	}{
		{1, "GET", "/api/v1/alerts", 403},
		{1, "POST", "/api/v1/agents/a/actions", 403},
		{1, "GET", "/api/v1/users", 403},
		{1, "POST", "/auth/ws-ticket", 403},
		{1, "GET", "/ws/events", 403},
		{1, "PATCH", "/auth/password", 200},
		{1, "GET", "/auth/me", 200},
		{1, "POST", "/auth/logout", 200},
		{2, "GET", "/api/v1/alerts", 200},
		{3, "GET", "/api/v1/alerts", 401}, // deleted account
		{9, "GET", "/api/v1/alerts", 503}, // lookup failed: fail closed
		{0, "GET", "/api/v1/alerts", 200}, // no claims: auth layer decides
	}
	for _, c := range cases {
		if got := do(c.uid, c.method, c.path); got != c.want {
			t.Errorf("user %d %s %s: got %d want %d", c.uid, c.method, c.path, got, c.want)
		}
	}

	// After the change the same token works, and the positive answer is cached.
	state[1] = true
	if got := do(1, "GET", "/api/v1/alerts"); got != 200 {
		t.Fatalf("after change: got %d want 200", got)
	}
	before := calls
	for i := 0; i < 5; i++ {
		do(1, "GET", "/api/v1/alerts")
	}
	if calls != before {
		t.Errorf("changed user looked up again: %d extra calls", calls-before)
	}
}

func TestUserListAdminOnly(t *testing.T) {
	h := adminOnly(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	for role, want := range map[string]int{"admin": 200, "analyst": 403, "viewer": 403} {
		r := httptest.NewRequest("GET", "/api/v1/users", nil)
		r = r.WithContext(context.WithValue(r.Context(), auth.ClaimsKey, &auth.Claims{UserID: 1, Role: role}))
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != want {
			t.Errorf("%s: got %d want %d", role, w.Code, want)
		}
	}
}

func TestAssigneesOmitPrivateFields(t *testing.T) {
	out := assigneesOf([]store.User{
		{ID: 1, Username: "root", Role: "admin", PasswordChanged: false},
		{ID: 2, Username: "ann", Role: "analyst"},
		{ID: 3, Username: "vic", Role: "viewer"},
	})
	if len(out) != 2 || out[0].Username != "root" || out[1].Username != "ann" {
		t.Fatalf("unexpected assignees: %+v", out)
	}
}
