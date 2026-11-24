package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sync"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// passwordGateAllowed are the only routes an account that still has its
// initial password may call: change it, see who it is, or log out.
var passwordGateAllowed = map[string]bool{
	"/auth/password": true,
	"/auth/logout":   true,
	"/auth/me":       true,
}

// passwordLookup reports whether the user has changed the initial password.
// It returns sql.ErrNoRows when the account no longer exists.
type passwordLookup func(ctx context.Context, userID int64) (changed bool, err error)

// passwordGate enforces require_password_change on the server (spec F2).
// Login only tells the UI that a change is required; without this gate a
// client could ignore that flag and use the default password indefinitely.
//
// password_changed only ever goes from false to true, so a positive answer is
// cached for the life of the process and the database is only consulted for
// accounts that have not changed it yet (normally none after first login).
type passwordGate struct {
	lookup  passwordLookup
	changed sync.Map // int64 -> struct{}
}

func newPasswordGate(lookup passwordLookup) *passwordGate {
	return &passwordGate{lookup: lookup}
}

// storePasswordLookup reads the flag from the users table.
func storePasswordLookup(get func(ctx context.Context, id int64) (*store.User, error)) passwordLookup {
	return func(ctx context.Context, id int64) (bool, error) {
		u, err := get(ctx, id)
		if err != nil {
			return false, err
		}
		return u.PasswordChanged, nil
	}
}

// markChanged records a completed password change so the next request passes
// without a lookup.
func (g *passwordGate) markChanged(userID int64) { g.changed.Store(userID, struct{}{}) }

func (g *passwordGate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := auth.GetClaims(r)
		if c == nil || passwordGateAllowed[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := g.changed.Load(c.UserID); ok {
			next.ServeHTTP(w, r)
			return
		}
		changed, err := g.lookup(r.Context(), c.UserID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "account no longer exists"})
			return
		case err != nil:
			// Fail closed: an unknown state must not grant access.
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "could not verify account state"})
			return
		case !changed:
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "password change required",
				"code":  "password_change_required",
			})
			return
		}
		g.markChanged(c.UserID)
		next.ServeHTTP(w, r)
	})
}
