package api

// DR-05: administrator-defined links between account names, so one person's
// endpoint login, Entra UPN and GitHub/GitLab handle appear on one timeline.
// Stored as {"canonical": ["alias1", "alias2"]} in the settings table. Links
// are deliberately explicit: guessing that two names are the same person
// would merge unrelated users.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

const identityAliasKey = "identity.aliases"

func loadIdentityAliases(ctx context.Context, db *store.DB) map[string][]string {
	out := map[string][]string{}
	if v, err := db.GetSetting(ctx, identityAliasKey); err == nil && v != "" {
		_ = json.Unmarshal([]byte(v), &out)
	}
	return out
}

// identityNames returns the normalised account names linked to user (always
// including user itself). A link group is canonical name plus its aliases and
// works in both directions.
func identityNames(user string, aliases map[string][]string) map[string]bool {
	user = normUser(user)
	for canon, list := range aliases {
		group := map[string]bool{normUser(canon): true}
		for _, a := range list {
			group[normUser(a)] = true
		}
		if group[user] {
			delete(group, "")
			return group
		}
	}
	return map[string]bool{user: true}
}

func sanitizeAliases(in map[string][]string) map[string][]string {
	out := map[string][]string{}
	for canon, list := range in {
		c := strings.TrimSpace(canon)
		if c == "" || len(c) > 200 {
			continue
		}
		var clean []string
		for _, a := range list {
			a = strings.TrimSpace(a)
			if a != "" && len(a) <= 200 {
				clean = append(clean, a)
			}
		}
		if len(clean) > 0 && len(clean) <= 50 {
			out[c] = clean
		}
		if len(out) >= 500 {
			break
		}
	}
	return out
}

func handleIdentityAliases(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, map[string]interface{}{"aliases": loadIdentityAliases(r.Context(), db)})
			return
		}
		var req struct {
			Aliases map[string][]string `json:"aliases"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid body")
			return
		}
		clean := sanitizeAliases(req.Aliases)
		b, _ := json.Marshal(clean)
		if err := db.SetSetting(r.Context(), identityAliasKey, string(b)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to save")
			return
		}
		user := "unknown"
		if c := auth.GetClaims(r); c != nil {
			user = c.Username
		}
		db.WriteAudit(r.Context(), user, "update_identity_aliases", identityAliasKey, "groups="+itoa(len(clean)), clientIP(r))
		writeJSON(w, http.StatusOK, map[string]interface{}{"aliases": clean})
	}
}
