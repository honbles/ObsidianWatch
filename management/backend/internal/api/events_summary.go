package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// handleEventSummary serves the Events explorer header: counts over time (split by severity)
// and the top values of host, event type, source, user and process, over every event that
// matches the query. It takes the same parameters as GET /api/v1/events and
// GET /api/v1/events/search (q, the filter chips, since, until).
// GET /api/v1/events/summary?q=...&since=RFC3339&until=RFC3339&facet_limit=10
func handleEventSummary(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := parseEventFilter(r)
		if raw := strings.TrimSpace(q.Get("q")); raw != "" {
			expr, perr := store.ParseEventQuery(raw)
			if perr != nil {
				writeJSON(w, 400, map[string]string{"error": perr.Error()})
				return
			}
			f.Search = ""
			f.Expr = expr
		}
		// Same bounds as search (F-06): default 24 h, never more than the max lookback.
		if f.Since.IsZero() {
			f.Since = time.Now().Add(-24 * time.Hour)
		}
		if minSince := time.Now().Add(-eventSearchMaxLookback); f.Since.Before(minSince) {
			f.Since = minSince
		}
		limit, _ := strconv.Atoi(q.Get("facet_limit"))

		ctx, cancel := context.WithTimeout(r.Context(), eventSearchTimeout)
		defer cancel()
		sum, err := db.SummarizeEvents(ctx, f, limit)
		if err != nil {
			var qe *store.QueryError
			if errors.As(err, &qe) {
				writeJSON(w, 400, map[string]string{"error": qe.Error()})
				return
			}
			writeJSON(w, 500, map[string]string{"error": "summary failed"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"since": f.Since, "until": f.Until, "summary": sum})
	}
}
