package api

import (
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/telemetry"
)

// aiUserLimiter caps LLM-backed requests per user. Each one spends the
// organisation's paid API key, so an unthrottled loop (or a stolen analyst
// token) could burn the budget in minutes.
var aiUserLimiter = NewRateLimiter(10*time.Minute, 40)

func aiLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := clientIP(r)
		if c := auth.GetClaims(r); c != nil && c.Username != "" {
			key = "u:" + c.Username
		}
		if !aiUserLimiter.Allow(key) {
			telemetry.Event(r.Context(), "ratelimit.hit", "limit_name", "ai", "user", strings.TrimPrefix(key, "u:"), "client.address", clientIP(r))
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "AI request limit reached, try again in a few minutes"})
			return
		}
		next(w, r)
	}
}
