package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"obsidianwatch/management/internal/auth"
)

func TestReadOnlyRole(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := readOnlyRole(ok)
	do := func(role, method, path string) int {
		r := httptest.NewRequest(method, path, nil)
		if role != "" {
			r = r.WithContext(context.WithValue(r.Context(), auth.ClaimsKey, &auth.Claims{Username: "u", Role: role}))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	cases := []struct {
		role, method, path string
		want               int
	}{
		{"viewer", "GET", "/api/v1/alerts", 200},
		{"viewer", "POST", "/api/v1/alerts/1/status", 403},
		{"viewer", "DELETE", "/api/v1/users/2", 403},
		{"viewer", "POST", "/auth/logout", 200},
		{"viewer", "POST", "/auth/ws-ticket", 200},
		{"analyst", "POST", "/api/v1/alerts/1/status", 200},
		{"admin", "DELETE", "/api/v1/users/2", 200},
		{"", "POST", "/x", 200}, // no claims: auth layer decides, not this one
	}
	for _, c := range cases {
		if got := do(c.role, c.method, c.path); got != c.want {
			t.Errorf("%s %s %s: got %d want %d", c.role, c.method, c.path, got, c.want)
		}
	}
}
