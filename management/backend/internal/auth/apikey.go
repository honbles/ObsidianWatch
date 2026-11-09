package auth

import (
	"crypto/subtle"
	"net/http"
)

// AgentKeyMiddleware authenticates requests using the X-API-Key header.
// Used for agent-facing endpoints (tunnel, credential registration) that
// cannot use JWT because agents don't log in interactively.
//
// It fails closed: an empty configured key rejects every request instead of
// silently disabling authentication, and the comparison is constant-time.
func AgentKeyMiddleware(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if apiKey == "" {
				http.Error(w, `{"error":"agent api key not configured"}`, http.StatusServiceUnavailable)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), []byte(apiKey)) != 1 {
				http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
