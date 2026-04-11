package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"obsidianwatch/backend/internal/store"
	"obsidianwatch/backend/pkg/schema"
)

type queryStore interface {
	QueryEvents(ctx context.Context, f store.QueryFilter) ([]schema.Event, error)
	CountEvents(ctx context.Context, f store.QueryFilter) (int64, error)
}

// GET /api/v1/events
//
// Query parameters:
//   agent_id, host, event_type, severity (min), src_ip, dst_ip, user_name
//   since (RFC3339), until (RFC3339)
//   limit (default 100, max 1000), offset (default 0)
func handleQueryEvents(db queryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		q := r.URL.Query()
		f := store.QueryFilter{
			AgentID:   q.Get("agent_id"),
			Host:      q.Get("host"),
			EventType: q.Get("event_type"),
			SrcIP:     q.Get("src_ip"),
			DstIP:     q.Get("dst_ip"),
			UserName:  q.Get("user_name"),
		}

		if s := q.Get("severity"); s != "" {
			if v, err := strconv.Atoi(s); err == nil {
				f.Severity = v
			}
		}
		if s := q.Get("since"); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				f.Since = t
			}
		}
		if s := q.Get("until"); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				f.Until = t
			}
		}
		if s := q.Get("limit"); s != "" {
			if v, err := strconv.Atoi(s); err == nil {
				f.Limit = v
			}
		}
		if s := q.Get("offset"); s != "" {
			if v, err := strconv.Atoi(s); err == nil {
				f.Offset = v
			}
		}

		// Default time window: last 24 hours if not specified
		if f.Since.IsZero() && f.Until.IsZero() {
			f.Since = time.Now().UTC().Add(-24 * time.Hour)
		}

		events, err := db.QueryEvents(r.Context(), f)
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
			return
		}

		total, err := db.CountEvents(r.Context(), f)
		if err != nil {
			total = -1 // non-fatal
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"events": events,
			"total":  total,
			"limit":  f.Limit,
			"offset": f.Offset,
		})
	}
}

// Ensure queryStore is satisfied by *store.DB at compile time.
var _ queryStore = (*store.DB)(nil)
