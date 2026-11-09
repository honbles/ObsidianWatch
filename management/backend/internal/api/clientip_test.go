package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIP(t *testing.T) {
	mk := func(remote, xff string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return clientIP(r)
	}
	cases := []struct{ name, remote, xff, want string }{
		{"direct public peer ignores XFF", "203.0.113.9:5555", "1.2.3.4", "203.0.113.9"},
		{"port stripped", "203.0.113.9:1", "", "203.0.113.9"},
		{"proxy appends real client", "10.0.0.2:4000", "198.51.100.7", "198.51.100.7"},
		{"client-forged leftmost entry is ignored", "10.0.0.2:4000", "6.6.6.6, 198.51.100.7", "198.51.100.7"},
		{"private hops skipped", "172.18.0.5:1", "198.51.100.7, 10.1.1.1", "198.51.100.7"},
		{"internal client behind proxy", "10.0.0.2:4000", "192.168.1.20", "192.168.1.20"},
		{"loopback proxy", "127.0.0.1:80", "198.51.100.7", "198.51.100.7"},
		{"garbage XFF falls back to peer", "10.0.0.2:4000", "not-an-ip", "10.0.0.2"},
		{"v4-mapped v6 peer", "[::ffff:203.0.113.9]:1", "1.1.1.1", "203.0.113.9"},
	}
	for _, c := range cases {
		if got := mk(c.remote, c.xff); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestLimitRequestBody(t *testing.T) {
	h := limitRequestBody(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 100)
		if _, err := r.Body.Read(buf); err != nil && err.Error() != "EOF" {
			http.Error(w, "too big", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(200)
	}))
	post := func(body string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/x", strings.NewReader(body)))
		return w.Code
	}
	if post("small") != 200 {
		t.Error("small body should pass")
	}
	if post(strings.Repeat("x", 50)) != http.StatusRequestEntityTooLarge {
		t.Error("oversized body should be rejected")
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	do := func(path string) http.Header {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w.Header()
	}
	api := do("/api/v1/alerts")
	if api.Get("X-Content-Type-Options") != "nosniff" || api.Get("X-Frame-Options") != "DENY" || api.Get("Cache-Control") != "no-store" {
		t.Errorf("api headers wrong: %v", api)
	}
	if do("/static/app.js").Get("Cache-Control") != "" {
		t.Error("non-API paths must not be forced uncacheable")
	}
}
