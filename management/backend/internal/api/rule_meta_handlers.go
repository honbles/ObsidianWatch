package api

// Shared read/write API for rule metadata and settings. Owned by the
// integration owner.

import (
	"encoding/json"
	"net/http"
	"sort"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

func handleRuleMeta() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all := AllRuleMeta()
		sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
		writeJSON(w, 200, map[string]any{"items": all, "total": len(all)})
	}
}

func handleListRuleSettings(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items, err := db.ListRuleSettings(r.Context(), r.URL.Query().Get("rule_id"))
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to load rule settings"})
			return
		}
		if items == nil {
			items = []store.RuleSetting{}
		}
		writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
	}
}

func handlePutRuleSetting(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var s store.RuleSetting
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&s); err != nil || s.RuleID == "" {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if _, ok := RuleMetaFor(s.RuleID); !ok {
			writeJSON(w, 404, map[string]string{"error": "unknown rule"})
			return
		}
		if c := auth.GetClaims(r); c != nil {
			s.UpdatedBy = c.Username
		}
		if err := db.UpsertRuleSetting(r.Context(), s); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to save"})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}
