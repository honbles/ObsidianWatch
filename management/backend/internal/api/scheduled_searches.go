package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// P-07: scheduled searches as detections. A saved query runs every N minutes
// over the last M minutes; when matches reach the threshold an alert is raised
// (once per run bucket, so a persistent condition re-alerts at the schedule
// interval rather than every tick).

type ScheduledSearchEngine struct {
	db     *store.DB
	logger *slog.Logger
}

func NewScheduledSearchEngine(db *store.DB, logger *slog.Logger) *ScheduledSearchEngine {
	return &ScheduledSearchEngine{db: db, logger: logger}
}

func (e *ScheduledSearchEngine) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.runDue(ctx)
		}
	}
}

func (e *ScheduledSearchEngine) runDue(ctx context.Context) {
	rows, err := e.db.QueryContext(ctx, `
		SELECT id, name, query, owner, sched_every_min, sched_window_min, sched_threshold, sched_severity
		FROM saved_event_queries
		WHERE sched_enabled AND (sched_last_run IS NULL OR sched_last_run <= NOW() - (sched_every_min || ' minutes')::interval)
		LIMIT 100`)
	if err != nil {
		e.logger.Warn("scheduled searches: list failed", "err", err)
		return
	}
	type job struct {
		id                            int64
		name, query, owner            string
		every, window, threshold, sev int
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.name, &j.query, &j.owner, &j.every, &j.window, &j.threshold, &j.sev); err == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()
	for _, j := range jobs {
		qctx, cancel := context.WithTimeout(ctx, eventSearchTimeout)
		tokens, notTokens, special := parseSearchQuery(j.query)
		f := store.EventFilter{Tokens: tokens, NotTokens: notTokens,
			Since: time.Now().Add(-time.Duration(j.window) * time.Minute), Limit: 1}
		for _, apply := range special {
			apply(&f)
		}
		events, total, err := e.db.QueryEvents(qctx, f)
		cancel()
		if err != nil {
			e.logger.Warn("scheduled searches: query failed", "id", j.id, "err", err)
			continue
		}
		_, _ = e.db.ExecContext(ctx,
			`UPDATE saved_event_queries SET sched_last_run = NOW(), sched_last_count = $2 WHERE id = $1`, j.id, total)
		if int(total) < j.threshold {
			continue
		}
		bucket := time.Now().UTC().Unix() / int64(j.every*60)
		a := store.Alert{
			Title: fmt.Sprintf("Scheduled search matched: %s", j.name),
			Description: fmt.Sprintf("Saved search %q (%s) matched %d events in the last %d minutes (threshold %d).\nQuery: %s",
				j.name, j.owner, total, j.window, j.threshold, j.query),
			Severity:  j.sev,
			EventType: "scheduled_search",
			EventID:   fmt.Sprintf("sched:%d:%d", j.id, bucket),
		}
		if len(events) > 0 {
			a.AgentID, a.Host, a.SourceEventID = events[0].AgentID, events[0].Host, events[0].ID
		}
		if _, _, err := e.db.CreateAlertDeduped(ctx, a); err != nil {
			e.logger.Warn("scheduled searches: alert failed", "id", j.id, "err", err)
		}
	}
}

// handleScheduleSavedQuery: PUT /api/v1/events/saved-queries/{id}/schedule
func handleScheduleSavedQuery(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := auth.GetClaims(r)
		if c == nil {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		var req struct {
			Enabled   bool `json:"enabled"`
			Every     int  `json:"every_minutes"`
			Window    int  `json:"window_minutes"`
			Threshold int  `json:"threshold"`
			Severity  int  `json:"severity"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid body")
			return
		}
		clamp := func(v, lo, hi, def int) int {
			if v == 0 {
				return def
			}
			if v < lo {
				return lo
			}
			if v > hi {
				return hi
			}
			return v
		}
		every := clamp(req.Every, 5, 1440, 15)
		window := clamp(req.Window, 5, 1440, every)
		threshold := clamp(req.Threshold, 1, 1000000, 1)
		sev := clamp(req.Severity, 1, 5, 3)
		res, err := db.ExecContext(r.Context(), `
			UPDATE saved_event_queries
			   SET sched_enabled=$3, sched_every_min=$4, sched_window_min=$5, sched_threshold=$6, sched_severity=$7,
			       sched_last_run=NULL
			 WHERE id=$1 AND owner=$2`,
			r.PathValue("id"), c.Username, req.Enabled, every, window, threshold, sev)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid id")
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			writeJSONError(w, http.StatusNotFound, "saved query not found (only the owner can schedule it)")
			return
		}
		writeJSON(w, 200, map[string]interface{}{"enabled": req.Enabled, "every_minutes": every,
			"window_minutes": window, "threshold": threshold, "severity": sev})
	}
}
