package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	do := func(origins []string, origin, method string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/x", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		corsMiddleware(origins)(next).ServeHTTP(w, r)
		return w
	}
	w := do([]string{"https://app.example.com"}, "https://app.example.com", "GET")
	if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" || w.Header().Get("Vary") != "Origin" {
		t.Errorf("allowed origin headers wrong: %v", w.Header())
	}
	if do([]string{"https://app.example.com"}, "https://evil.example", "GET").Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("unlisted origin must not be allowed")
	}
	if do([]string{"*"}, "", "GET").Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("no Origin header must not produce an ACAO header")
	}
	if w := do([]string{"*"}, "https://x.io", "OPTIONS"); w.Code != 204 {
		t.Errorf("preflight should be 204, got %d", w.Code)
	}
}
