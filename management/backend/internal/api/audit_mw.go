package api

import (
	"net/http"
	"strings"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// M-11: every state-changing authenticated API call is written to the audit
// log (who, what, target, outcome, source IP). Handlers that already write a
// richer entry are skipped to avoid duplicates. Request bodies are never
// logged — only method, path and status — so secrets can't leak via audit.

type auditRecorder struct {
	http.ResponseWriter
	code int
}

func (a *auditRecorder) WriteHeader(c int) {
	a.code = c
	a.ResponseWriter.WriteHeader(c)
}

func (a *auditRecorder) Write(b []byte) (int, error) {
	if a.code == 0 {
		a.code = http.StatusOK
	}
	return a.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (a *auditRecorder) Unwrap() http.ResponseWriter { return a.ResponseWriter }

var auditSkipPrefixes = []string{
	"/api/v1/suppressions",         // audited in handler
	"/api/v1/live-response",        // audited in handler
	"/api/v1/events/saved-queries", // per-user bookmarks, not security relevant
	"/api/v1/ai/",                  // read-only analysis calls
	"/api/v1/enrichment/",          // lookups
}

func auditMutations(db *store.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			next.ServeHTTP(w, r)
			return
		}
		for _, p := range auditSkipPrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				next.ServeHTTP(w, r)
				return
			}
		}
		rec := &auditRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.code == 0 {
			rec.code = http.StatusOK
		}
		actor := "unknown"
		if c := auth.GetClaims(r); c != nil && c.Username != "" {
			actor = c.Username
		}
		outcome := "ok"
		if rec.code >= 400 {
			outcome = "failed"
		}
		db.WriteAudit(r.Context(), actor, "api:"+strings.ToLower(r.Method),
			r.URL.Path, outcome+" status="+itoa(rec.code), clientIP(r))
	})
}

func itoa(n int) string {
	// tiny helper to avoid another strconv import at call sites
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
