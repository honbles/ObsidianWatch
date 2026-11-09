package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyMiddleware(t *testing.T) {
	h := APIKeyMiddleware([]string{"k1", "k2"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	cases := []struct {
		key  string
		want int
	}{{"", 401}, {"nope", 401}, {"k", 401}, {"k1x", 401}, {"k1", 204}, {"k2", 204}}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "/x", nil)
		if c.key != "" {
			req.Header.Set("X-API-Key", c.key)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != c.want {
			t.Errorf("key %q: got %d want %d", c.key, rr.Code, c.want)
		}
	}
}

func TestAPIKeyMiddlewareNoKeysRejectsEverything(t *testing.T) {
	h := APIKeyMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-API-Key", "anything")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("got %d", rr.Code)
	}
}
