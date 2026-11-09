package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"obsidianwatch/management/internal/auth"
)

func TestAdminOnly(t *testing.T) {
	called := false
	h := adminOnly(func(w http.ResponseWriter, r *http.Request) { called = true })
	run := func(c *auth.Claims) int {
		called = false
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		if c != nil {
			r = r.WithContext(context.WithValue(r.Context(), auth.ClaimsKey, c))
		}
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}
	if run(nil) != 403 || called {
		t.Fatal("no claims must be refused")
	}
	if run(&auth.Claims{Role: "analyst"}) != 403 || called {
		t.Fatal("analyst must be refused")
	}
	if run(&auth.Claims{Role: "admin"}) != 200 || !called {
		t.Fatal("admin must pass")
	}
}

// Guards against a refactor silently dropping the wrapper from a sensitive route.
func TestSensitiveRoutesStayAdminOnly(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	must := []string{
		`PATCH /api/v1/agents/{id}/tamper`, `POST /api/v1/agents/{id}/regen-key`,
		`POST /api/v1/live-response/sessions`, `POST /api/v1/cloud-connectors"`,
		`DELETE /api/v1/cloud-connectors/{id}`, `POST /api/v1/devops-connectors"`,
		`PATCH /api/v1/detections/{id}`, `POST /api/v1/agent-builder/build`,
		`POST /api/v1/settings/api-keys`, `POST /api/v1/settings/smtp"`,
		`GET /api/v1/agent-builder/settings`, `GET /api/v1/agent-builder/download/{platform}`,
		`POST /api/v1/settings/webhooks"`, `POST /api/v1/settings/syslog"`,
	}
	for _, route := range must {
		re := regexp.MustCompile(`protected\.HandleFunc\("` + regexp.QuoteMeta(strings.TrimSuffix(route, `"`)) + `", adminOnly\(`)
		if !re.Match(src) {
			t.Errorf("route %q is not wrapped in adminOnly", route)
		}
	}
}

func TestISPLookupRateLimited(t *testing.T) {
	h := handleISPLookup()
	var last int
	for i := 0; i < 25; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/enrichment/isp", strings.NewReader(`{"ips":[]}`))
		r = r.WithContext(context.WithValue(r.Context(), auth.ClaimsKey, &auth.Claims{Username: "isp-test-user", Role: "analyst"}))
		w := httptest.NewRecorder()
		h(w, r)
		last = w.Code
	}
	if last != 429 {
		t.Fatalf("25th request: got %d, want 429", last)
	}
}
