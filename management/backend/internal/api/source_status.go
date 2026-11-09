package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// AZ-02 / CC-05: per-source telemetry status for cloud connectors, so a
// missing permission or license is visible instead of looking like "healthy".
// State: ok | permission_missing | license_missing | error | unknown.
// Kept in memory (resets on restart; repopulated on the next sync).

type SourceStatus struct {
	Source      string    `json:"source"`
	State       string    `json:"state"`
	Detail      string    `json:"detail,omitempty"`
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success,omitempty"`
}

var (
	srcStatusMu sync.Mutex
	srcStatuses = map[int64]map[string]*SourceStatus{}
)

func recordSourceStatus(connID int64, source, state, detail string) {
	srcStatusMu.Lock()
	defer srcStatusMu.Unlock()
	m := srcStatuses[connID]
	if m == nil {
		m = map[string]*SourceStatus{}
		srcStatuses[connID] = m
	}
	s := m[source]
	if s == nil {
		s = &SourceStatus{Source: source}
		m[source] = s
	}
	now := time.Now().UTC()
	s.State, s.Detail, s.LastAttempt = state, truncateRunes(detail, 300), now
	if state == "ok" {
		s.LastSuccess = now
	}
}

// classifyGraphFailure maps an HTTP status/body from Graph/ARM to a state.
func classifyAzureFailure(status int, body string) (string, string) {
	b := strings.ToLower(body)
	switch {
	case strings.Contains(b, "nonpremiumtenant") || strings.Contains(b, "premium license") ||
		strings.Contains(b, "azure ad premium") || strings.Contains(b, "requires a premium"):
		return "license_missing", "Entra ID P1/P2 license required for this log"
	case status == 401 || status == 403:
		return "permission_missing", "HTTP " + strconv.Itoa(status) + " — grant the required API permission and admin consent"
	default:
		return "error", "HTTP " + strconv.Itoa(status)
	}
}

func handleConnectorSources() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, `{"error":"bad id"}`, http.StatusBadRequest)
			return
		}
		srcStatusMu.Lock()
		out := []SourceStatus{}
		for _, s := range srcStatuses[id] {
			out = append(out, *s)
		}
		srcStatusMu.Unlock()
		sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
		writeJSON(w, 200, map[string]interface{}{"sources": out})
	}
}

// handleLogSources (P-10): per agent/collector ingestion rates and silent
// streams, plus the latest self-reported health state per agent.
func handleLogSources(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		silentAfter := 30 * time.Minute
		if v := r.URL.Query().Get("silent_minutes"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 5 && n <= 1440 {
				silentAfter = time.Duration(n) * time.Minute
			}
		}
		rows, err := db.ListLogSources(r.Context(), silentAfter)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "query failed")
			return
		}
		silent := 0
		for _, row := range rows {
			if row.Silent {
				silent++
			}
		}
		if rows == nil {
			rows = []store.LogSourceRow{}
		}
		writeJSON(w, 200, map[string]interface{}{
			"sources": rows, "total": len(rows), "silent": silent,
			"silent_after_minutes": int(silentAfter.Minutes()),
		})
	}
}
