package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const ClaimsKey contextKey = "claims"

// publicAPIPaths are routes under /api/ that don't require JWT auth.
var publicAPIPaths = map[string]bool{
	"/api/v1/agent/register-key":         true,
	"/api/v1/verify-install-key":         true,
	"/api/v1/live-response/agent-tunnel": true, // agent WS tunnel — uses API key auth
	"/api/v1/devops/webhook/":            true, // prefix — webhooks use their own secret
}

// Middleware validates the Authorization: Bearer <token> header.
// For WebSocket connections that can't set headers, also accepts ?auth=<token> query param.
func Middleware(jwt *JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allow public API routes through without JWT
			path := r.URL.Path
			for pub := range publicAPIPaths {
				if path == pub || (strings.HasSuffix(pub, "/") && strings.HasPrefix(path, pub)) {
					next.ServeHTTP(w, r)
					return
				}
			}
			// Try Authorization header first
			token := ""
			header := r.Header.Get("Authorization")
			if header != "" {
				parts := strings.SplitN(header, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
					token = parts[1]
				}
			}
			// Fall back to ?auth= query param (used by WebSocket clients)
			if token == "" {
				token = r.URL.Query().Get("auth")
			}
			if token == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}
			claims, err := jwt.Verify(token)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims extracts claims from context (set by Middleware).
func GetClaims(r *http.Request) *Claims {
	c, _ := r.Context().Value(ClaimsKey).(*Claims)
	return c
}
