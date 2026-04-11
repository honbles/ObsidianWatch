package auth

import (
	"crypto/subtle"
	"net/http"
)

// APIKeyMiddleware validates the X-API-Key header against a list of accepted keys.
// Requests without a matching key receive 401 Unauthorized.
func APIKeyMiddleware(validKeys []string) func(http.Handler) http.Handler {
	// Pre-convert to [][]byte for constant-time comparison.
	keys := make([][]byte, len(validKeys))
	for i, k := range validKeys {
		keys[i] = []byte(k)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provided := []byte(r.Header.Get("X-API-Key"))
			if len(provided) == 0 {
				http.Error(w, `{"error":"missing X-API-Key header"}`, http.StatusUnauthorized)
				return
			}

			var matched bool
			for _, k := range keys {
				if subtle.ConstantTimeCompare(provided, k) == 1 {
					matched = true
					break
				}
			}

			if !matched {
				http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
