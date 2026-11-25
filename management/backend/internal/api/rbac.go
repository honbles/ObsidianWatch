package api

import (
	"net/http"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/telemetry"
)

// denyEvent reports a refused request as an authz.deny security event.
func denyEvent(r *http.Request, c *auth.Claims, policy string) {
	user := ""
	if c != nil {
		user = c.Username
	}
	telemetry.Event(r.Context(), "authz.deny", "outcome", "denied", "policy", policy, "action", r.Method,
		"user", user, "client.address", clientIP(r))
}

// adminOnly restricts a handler to the "admin" role. Routes that change how
// the platform is wired (connectors and their credentials, notification and
// API-key settings, detection toggles, agent builds, agent key/tamper control)
// or that open a remote shell on an endpoint must not be available to the
// analyst role, which exists for triage.
func adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := auth.GetClaims(r)
		if c == nil || c.Role != "admin" {
			denyEvent(r, c, "admin_only")
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
					denyEvent(r, c, "read_only_role")
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "read-only role"})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// exportEvent reports a download of platform data as a data.export security event.
func exportEvent(r *http.Request, objectType, objectID, format string) {
	user := ""
	if c := auth.GetClaims(r); c != nil {
		user = c.Username
	}
	telemetry.Event(r.Context(), "data.export", "outcome", "success", "object_type", objectType, "object_id", objectID,
		"format", format, "user", user, "client.address", clientIP(r))
}
