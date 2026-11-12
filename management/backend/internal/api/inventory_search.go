package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// P-03: searchable endpoint inventory built from each host's most recent
// vulnerability.scan event. "Which hosts run openssl 1.1.1?" is one request.
type invHit struct {
	Host    string    `json:"host"`
	OS      string    `json:"os"`
	Kind    string    `json:"kind"` // package | service
	Name    string    `json:"name"`
	Version string    `json:"version,omitempty"`
	State   string    `json:"state,omitempty"`
	ScanAt  time.Time `json:"scanned_at"`
}

// inventoryFromScans extracts matches from the newest scan per host.
// events must be ordered newest first (as QueryEvents returns them).
func inventoryFromScans(events []store.Event, kind, q, version string) []invHit {
	q, version = strings.ToLower(q), strings.ToLower(version)
	seen := map[string]bool{}
	out := []invHit{}
	for _, ev := range events {
		if seen[ev.Host] {
			continue
		}
		seen[ev.Host] = true
		var m struct {
			Packages []struct{ Name, Version string } `json:"packages"`
			Services []struct{ Name, State string }   `json:"services"`
		}
		if json.Unmarshal(ev.Raw, &m) != nil {
			continue
		}
		if kind == "" || kind == "package" {
			for _, p := range m.Packages {
				if strings.Contains(strings.ToLower(p.Name), q) &&
					(version == "" || strings.HasPrefix(strings.ToLower(p.Version), version)) {
					out = append(out, invHit{ev.Host, ev.OS, "package", p.Name, p.Version, "", ev.Time})
				}
			}
		}
		if (kind == "" || kind == "service") && version == "" {
			for _, s := range m.Services {
				if strings.Contains(strings.ToLower(s.Name), q) {
					out = append(out, invHit{ev.Host, ev.OS, "service", s.Name, "", s.State, ev.Time})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func handleInventorySearch(db, backendDB *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if len(q) < 2 || len(q) > 100 {
			writeJSONError(w, http.StatusBadRequest, "q must be 2-100 characters")
			return
		}
		kind := r.URL.Query().Get("kind")
		if kind != "" && kind != "package" && kind != "service" {
			writeJSONError(w, http.StatusBadRequest, "kind must be package or service")
			return
		}
		f := store.EventFilter{EventType: "vulnerability.scan", Since: time.Now().Add(-14 * 24 * time.Hour), Limit: 2000, SkipCount: true}
		events, _, err := db.QueryEvents(r.Context(), f)
		if (err != nil || len(events) == 0) && backendDB != nil {
			events, _, err = backendDB.QueryEvents(r.Context(), f)
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "query failed")
			return
		}
		hits := inventoryFromScans(events, kind, q, r.URL.Query().Get("version"))
		trunc := false
		if len(hits) > 1000 {
			hits, trunc = hits[:1000], true
		}
		hosts := map[string]bool{}
		for _, h := range hits {
			hosts[h.Host] = true
		}
		meta := map[string]store.HostMeta{}
		if all, merr := db.ListHostMeta(r.Context()); merr == nil {
			for _, m := range all {
				meta[m.Host] = m
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"hits": hits, "host_count": len(hosts), "truncated": trunc, "host_meta": meta})
	}
}
