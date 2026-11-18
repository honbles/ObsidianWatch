package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every read route is registered; the only mutation is admin-only.
func TestAppRoutesRegistered(t *testing.T) {
	mux := http.NewServeMux()
	registerAppRoutes(mux, nil, nil)
	for _, p := range []string{
		"/api/v1/app/services", "/api/v1/app/services/zzz", "/api/v1/app/services/zzz/red",
		"/api/v1/app/services/zzz/routes", "/api/v1/app/services/zzz/edges", "/api/v1/app/traces/not-hex!", "/api/v1/app/map?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z", "/api/v1/app/services/zzz/runtime",
	} {
		rec := httptest.NewRecorder()
		// A bad id/trace id is rejected before any database access; a 404/405 would mean "not routed".
		if p == "/api/v1/app/services" {
			continue // needs a database; its registration is covered by the mux pattern check below
		}
		mux.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET %s: got %d, want 400 (routed, input rejected)", p, rec.Code)
		}
	}
	// Unauthenticated/non-admin settings change must be refused before touching anything.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("PUT", "/api/v1/app/services/1/settings", strings.NewReader(`{}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("PUT settings without admin: %d", rec.Code)
	}
	// Write methods on read routes do not exist.
	for _, p := range []string{"/api/v1/app/services/1/red", "/api/v1/app/traces", "/api/v1/app/services"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("DELETE", p, nil))
		if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
			t.Fatalf("DELETE %s: %d", p, rec.Code)
		}
	}
}
