package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// handleEventSearch — tokenized full-text search across all events
// GET /api/v1/events/search?q=root+ssh+failed&since=1h&until=now&limit=200
func handleEventSearch(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		q := r.URL.Query()

		// Parse search query — split on whitespace into tokens
		raw := strings.TrimSpace(q.Get("q"))
		var tokens []string
		var specialFilters []func(*store.EventFilter)

		if raw != "" {
			for _, tok := range strings.Fields(raw) {
				tok = strings.TrimSpace(tok)
				if tok == "" { continue }

				// Special prefix filters: host:lab, type:process, sev:4, src:1.2.3.4
				if strings.Contains(tok, ":") {
					parts := strings.SplitN(tok, ":", 2)
					key, val := strings.ToLower(parts[0]), parts[1]
					switch key {
					case "host":
						specialFilters = append(specialFilters, func(f *store.EventFilter) { f.Host = val })
					case "type", "event_type":
						specialFilters = append(specialFilters, func(f *store.EventFilter) { f.EventType = val })
					case "sev", "severity":
						if n, err := strconv.Atoi(val); err == nil {
							specialFilters = append(specialFilters, func(f *store.EventFilter) { f.Severity = n })
						}
					case "src", "src_ip":
						specialFilters = append(specialFilters, func(f *store.EventFilter) { f.SrcIP = val })
					case "dst", "dst_ip":
						specialFilters = append(specialFilters, func(f *store.EventFilter) { f.DstIP = val })
					case "user":
						specialFilters = append(specialFilters, func(f *store.EventFilter) { f.UserName = val })
					case "proc", "process":
						specialFilters = append(specialFilters, func(f *store.EventFilter) { f.ProcessName = val })
					case "os":
						specialFilters = append(specialFilters, func(f *store.EventFilter) { f.OS = val })
					case "source":
						specialFilters = append(specialFilters, func(f *store.EventFilter) { f.Source = val })
					default:
						// Unknown prefix — treat as regular token
						tokens = append(tokens, tok)
					}
				} else {
					tokens = append(tokens, tok)
				}
			}
		}

		// Time range
		since := time.Now().Add(-24 * time.Hour) // default: last 24 hours
		if s := q.Get("since"); s != "" {
			switch s {
			case "15m":  since = time.Now().Add(-15 * time.Minute)
			case "1h":   since = time.Now().Add(-1 * time.Hour)
			case "6h":   since = time.Now().Add(-6 * time.Hour)
			case "24h":  since = time.Now().Add(-24 * time.Hour)
			case "7d":   since = time.Now().Add(-7 * 24 * time.Hour)
			case "30d":  since = time.Now().Add(-30 * 24 * time.Hour)
			case "all":  since = time.Time{} // no time filter
			default:
				if t, err := time.Parse(time.RFC3339, s); err == nil {
					since = t
				}
			}
		}

		limit := 200
		if l := q.Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
				limit = n
			}
		}

		f := store.EventFilter{
			Tokens: tokens,
			Since:  since,
			Limit:  limit,
		}
		for _, apply := range specialFilters {
			apply(&f)
		}

		events, total, err := db.QueryEvents(ctx, f)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, 200, map[string]interface{}{
			"events": events,
			"total":  total,
			"limit":  limit,
			"query":  raw,
			"tokens": tokens,
		})
	}
}

// handleSavedQueries — CRUD for saved search queries
// GET  /api/v1/events/saved-queries
// POST /api/v1/events/saved-queries
// DELETE /api/v1/events/saved-queries/{id}
func handleSavedQueries(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		switch r.Method {
		case http.MethodGet:
			rows, err := db.QueryContext(ctx,
				`SELECT id, name, query, created_at FROM saved_event_queries ORDER BY created_at DESC`)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			defer rows.Close()
			var queries []map[string]interface{}
			for rows.Next() {
				var id int64
				var name, query string
				var createdAt time.Time
				if err := rows.Scan(&id, &name, &query, &createdAt); err != nil { continue }
				queries = append(queries, map[string]interface{}{
					"id": id, "name": name, "query": query, "created_at": createdAt,
				})
			}
			if queries == nil { queries = []map[string]interface{}{} }
			writeJSON(w, 200, map[string]interface{}{"queries": queries})

		case http.MethodPost:
			var req struct {
				Name  string `json:"name"`
				Query string `json:"query"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Query == "" {
				writeJSON(w, 400, map[string]string{"error": "name and query required"})
				return
			}
			var id int64
			err := db.QueryRowContext(ctx,
				`INSERT INTO saved_event_queries (name, query) VALUES ($1, $2) RETURNING id`,
				req.Name, req.Query,
			).Scan(&id)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]interface{}{"id": id, "name": req.Name, "query": req.Query})

		case http.MethodDelete:
			// Extract ID from path
			parts := strings.Split(r.URL.Path, "/")
			id, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": "invalid id"})
				return
			}
			db.ExecContext(ctx, `DELETE FROM saved_event_queries WHERE id = $1`, id)
			writeJSON(w, 200, map[string]string{"status": "deleted"})
		}
	}
}
