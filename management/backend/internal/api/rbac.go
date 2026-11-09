package api

import (
	"net/http"

	"obsidianwatch/management/internal/auth"
)

// adminOnly restricts a handler to the "admin" role. Routes that change how
// the platform is wired (connectors and their credentials, notification and
// API-key settings, detection toggles, agent builds, agent key/tamper control)
// or that open a remote shell on an endpoint must not be available to the
// analyst role, which exists for triage.
func adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := auth.GetClaims(r)
		if c == nil || c.Role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
			return
		}
		next(w, r)
	}
}

// viewerWriteAllowed are the only mutating requests a read-only "viewer" may
// make: managing their own session and password.
var viewerWriteAllowed = map[string]bool{
	"/auth/logout":    true,
	"/auth/password":  true,
	"/auth/ws-ticket": true,
}

// readOnlyRole enforces that the "viewer" role is read-only on the server, no
// matter what the UI shows. Must run after the auth middleware set the claims.
func readOnlyRole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := auth.GetClaims(r); c != nil && c.Role == "viewer" {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
			default:
				if !viewerWriteAllowed[r.URL.Path] {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "read-only role"})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
