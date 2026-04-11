package auth

import "net/http"

// AgentKeyMiddleware authenticates requests using the X-API-Key header.
// Used for agent-facing endpoints (tunnel, credential registration) that
// cannot use JWT because agents don't log in interactively.
func AgentKeyMiddleware(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if apiKey != "" && r.Header.Get("X-API-Key") != apiKey {
				http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
