package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

var hostTagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9:_.-]{0,31}$`)

// cleanHostMeta validates a criticality and tag list (pure).
func cleanHostMeta(crit string, tags []string) (string, []string, string) {
	crit = strings.ToLower(strings.TrimSpace(crit))
	if crit == "" {
		crit = "normal"
	}
	switch crit {
	case "low", "normal", "high", "critical":
	default:
		return "", nil, "criticality must be low, normal, high or critical"
	}
	if len(tags) > 10 {
		return "", nil, "at most 10 tags"
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		if !hostTagRe.MatchString(t) {
			return "", nil, "tags must be 1-32 chars: letters, digits, : _ . -"
		}
		seen[t] = true
		out = append(out, t)
	}
	return crit, out, ""
}

func handleListHostMeta(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m, err := db.ListHostMeta(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"hosts": m})
	}
}

func handleSetHostMeta(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := strings.TrimSpace(r.PathValue("host"))
		if host == "" || len(host) > 255 {
			writeJSON(w, 400, map[string]string{"error": "invalid host"})
			return
		}
		var body struct {
			Criticality string   `json:"criticality"`
			Tags        []string `json:"tags"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&body) != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		crit, tags, msg := cleanHostMeta(body.Criticality, body.Tags)
		if msg != "" {
			writeJSON(w, 400, map[string]string{"error": msg})
			return
		}
		by := ""
		if c := auth.GetClaims(r); c != nil {
			by = c.Username
		}
		if err := db.SetHostMeta(r.Context(), host, crit, tags, by); err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not save"})
			return
		}
		writeJSON(w, 200, store.HostMeta{Host: host, Criticality: crit, Tags: tags})
	}
}
