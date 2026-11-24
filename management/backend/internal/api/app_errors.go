package api

// app_errors.go - error tracking (APM spec item 4): the read and triage API for error groups, and the rules that
// raise a new group (APM-O08) and a regression (APM-O09). The agent fingerprints and scrubs; this file never sees
// raw messages or arguments.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

type appErrorGroup struct {
	ID           int64      `json:"id"`
	ServiceID    int64      `json:"service_id"`
	Fingerprint  string     `json:"fingerprint"`
	Type         string     `json:"type"`
	Route        string     `json:"route"`
	Method       string     `json:"method"`
	Frame        string     `json:"frame"`
	Message      string     `json:"message,omitempty"`
	FirstSeen    time.Time  `json:"first_seen"`
	LastSeen     time.Time  `json:"last_seen"`
	Count        int64      `json:"count"`       // all time
	RangeCount   int64      `json:"range_count"` // inside the requested range (hourly resolution)
	FirstVersion string     `json:"first_version"`
	LastVersion  string     `json:"last_version"`
	Status       string     `json:"status"`
	Assignee     string     `json:"assignee"`
	Regressed    bool       `json:"regressed"`
	RegressedAt  *time.Time `json:"regressed_at,omitempty"`
	Frames       []string   `json:"frames,omitempty"`
	SampleTraces []string   `json:"sample_traces,omitempty"`
	ResolvedIn   string     `json:"resolved_version,omitempty"`
	ServiceName  string     `json:"service,omitempty"`
	ServiceEnv   string     `json:"environment,omitempty"`
}

const appErrCols = `g.id, g.service_id, g.fingerprint, g.type, g.route, g.method, g.frame, g.message, g.first_seen, g.last_seen, g.count,
	g.first_version, g.last_version, g.status, g.assignee, g.regressed, g.regressed_at, g.frames, g.sample_traces, g.resolved_version`

func appScanErrorGroup(sc interface{ Scan(...any) error }, g *appErrorGroup, extra ...any) error {
	var fr, st []byte
	var rat sql.NullTime
	dst := append([]any{&g.ID, &g.ServiceID, &g.Fingerprint, &g.Type, &g.Route, &g.Method, &g.Frame, &g.Message, &g.FirstSeen, &g.LastSeen, &g.Count,
		&g.FirstVersion, &g.LastVersion, &g.Status, &g.Assignee, &g.Regressed, &rat, &fr, &st, &g.ResolvedIn}, extra...)
	if err := sc.Scan(dst...); err != nil {
		return err
	}
	if rat.Valid {
		g.RegressedAt = &rat.Time
	}
	_ = json.Unmarshal(fr, &g.Frames)
	_ = json.Unmarshal(st, &g.SampleTraces)
	return nil
}

// appHandleErrors lists a service's error groups. status filters (open, resolved, ignored); groups are ordered by
// occurrences in the range, then last seen.
func appHandleErrors(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		from, to, msg := appParseRange(r)
		if msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		status := r.URL.Query().Get("status")
		if status != "" && status != "open" && status != "resolved" && status != "ignored" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be open, resolved or ignored"})
			return
		}
		rows, err := idb.QueryContext(r.Context(), `
			SELECT `+appErrCols+`, COALESCE(h.n, 0)
			FROM error_groups g
			LEFT JOIN (SELECT group_id, SUM(count) n FROM error_group_hours WHERE hour >= $2 AND hour < $3 GROUP BY group_id) h ON h.group_id = g.id
			WHERE g.service_id = $1 AND g.last_seen >= $2 AND g.first_seen < $3 AND ($4 = '' OR g.status = $4)
			ORDER BY COALESCE(h.n, 0) DESC, g.last_seen DESC LIMIT 200`, id, from.Truncate(time.Hour), to, status)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		defer rows.Close()
		list := []appErrorGroup{}
		for rows.Next() {
			var g appErrorGroup
			if appScanErrorGroup(rows, &g, &g.RangeCount) == nil {
				g.Frames, g.SampleTraces = nil, nil // detail only
				list = append(list, g)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "errors": list})
	}
}

func appHandleGetError(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		var g appErrorGroup
		err = appScanErrorGroup(idb.QueryRowContext(r.Context(), `SELECT `+appErrCols+`, s.name, s.environment
			FROM error_groups g JOIN services s ON s.id = g.service_id WHERE g.id = $1`, id), &g, &g.ServiceName, &g.ServiceEnv)
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "error group not found"})
			return
		}
		if err != nil {
			appQueryFailed(w, r.URL.Path, 0, err)
			return
		}
		writeJSON(w, http.StatusOK, g)
	}
}

// appHandlePatchError changes a group's status and assignee. Resolving records the version that was running, so a
// later failure under a different version reopens it as a regression. The route is open to admin and analyst
// (viewers are blocked from every write by the shared role check).
func appHandlePatchError(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		var body struct {
			Status   *string `json:"status"`
			Assignee *string `json:"assignee"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil || (body.Status == nil && body.Assignee == nil) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "send a status or an assignee"})
			return
		}
		if body.Status != nil && *body.Status != "open" && *body.Status != "resolved" && *body.Status != "ignored" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be open, resolved or ignored"})
			return
		}
		if body.Assignee != nil {
			a := strings.TrimSpace(*body.Assignee)
			if len(a) > 128 || strings.ContainsAny(a, "\x00\r\n") {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "assignee too long or invalid"})
				return
			}
			body.Assignee = &a
		}
		by := ""
		if c := auth.GetClaims(r); c != nil {
			by = c.Username
		}
		res, err := idb.ExecContext(r.Context(), `
			UPDATE error_groups SET
			  status = COALESCE($2, status),
			  resolved_version = CASE WHEN $2 = 'resolved' THEN last_version WHEN $2 IS NOT NULL THEN '' ELSE resolved_version END,
			  regressed = CASE WHEN $2 IS NOT NULL THEN FALSE ELSE regressed END,
			  assignee = COALESCE($3, assignee)
			WHERE id = $1`, id, body.Status, body.Assignee)
		if err != nil {
			appQueryFailed(w, r.URL.Path, 0, err)
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "error group not found"})
			return
		}
		st, as := "", ""
		if body.Status != nil {
			st = *body.Status
		}
		if body.Assignee != nil {
			as = *body.Assignee
		}
		slog.Info("application error group updated", "group", id, "status", st, "assignee", as, "by", by)
		appHandleGetError(db, backendDB)(w, r)
	}
}

// ── rules ──────────────────────────────────────────────────────────────────

type appErrGroupRef struct {
	ID          int64
	Fingerprint string
	Type        string
	Route       string
	Method      string
	Frame       string
	Count       int64
	FirstSeen   time.Time
	RegressedAt time.Time
	Version     string
	Status      string
}

// ErrorGroups returns groups first seen or regressed since the given time.
func (d appPGData) ErrorGroups(ctx context.Context, svcID int64, since time.Time) ([]appErrGroupRef, error) {
	rows, err := d.idb.QueryContext(ctx, `
		SELECT id, fingerprint, type, route, method, frame, count, first_seen, COALESCE(regressed_at, 'epoch'), last_version, status
		FROM error_groups WHERE service_id = $1 AND (first_seen >= $2 OR regressed_at >= $2) ORDER BY id LIMIT 200`, svcID, since)
	if err != nil {
		return nil, nil // the table appears with the ingest migration; a missing one means no groups yet
	}
	defer rows.Close()
	var out []appErrGroupRef
	for rows.Next() {
		var g appErrGroupRef
		if rows.Scan(&g.ID, &g.Fingerprint, &g.Type, &g.Route, &g.Method, &g.Frame, &g.Count, &g.FirstSeen, &g.RegressedAt, &g.Version, &g.Status) == nil {
			out = append(out, g)
		}
	}
	return out, nil
}

func appErrLabel(g appErrGroupRef) string {
	l := g.Type
	if l == "" {
		l = "error"
	}
	if g.Route != "" {
		l += " on " + g.Method + " " + g.Route
	}
	if g.Frame != "" {
		l += " at " + g.Frame
	}
	return l
}

// o08: a new error group. A service in its first day of learning is skipped (everything is new then), and a group
// must reach min_count occurrences so a single stray exception does not alert.
func (r *appRules) o08(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O08", svc)
	if !on || appInMaintenance(svc.Settings, now) {
		return
	}
	if now.Sub(appLearningStart(svc)) < 24*time.Hour {
		appSkip("APM-O08", "learning")
		return
	}
	win := time.Duration(g.Param("window_min", 30)) * time.Minute
	minCount := int64(g.Param("min_count", 3))
	groups, err := r.d.ErrorGroups(ctx, svc.ID, now.Add(-win))
	if err != nil {
		return
	}
	for _, e := range groups {
		if e.FirstSeen.Before(now.Add(-win)) || e.Status == "ignored" {
			continue
		}
		if e.Count < minCount {
			continue
		}
		r.fire(ctx, appFinding{RuleID: "APM-O08", Svc: svc, BaseSev: appSevMed, Summary: "New error group",
			Detail: fmt.Sprintf("%s: %d occurrences since it first appeared.%s", appErrLabel(e), e.Count, appNotifyLine(svc)),
			Route:  e.Route, Method: e.Method, EventType: "app.alert", Time: now, DedupKey: fmt.Sprintf("%d:%s", svc.ID, e.Fingerprint)})
	}
}

// o09: a resolved error that came back under a different version.
func (r *appRules) o09(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O09", svc)
	if !on || appInMaintenance(svc.Settings, now) {
		return
	}
	win := time.Duration(g.Param("window_min", 30)) * time.Minute
	groups, err := r.d.ErrorGroups(ctx, svc.ID, now.Add(-win))
	if err != nil {
		return
	}
	for _, e := range groups {
		if e.RegressedAt.Before(now.Add(-win)) || e.Status != "open" {
			continue
		}
		v := e.Version
		if v == "" {
			v = "a newer version"
		}
		r.fire(ctx, appFinding{RuleID: "APM-O09", Svc: svc, BaseSev: appSevHigh, Summary: "Resolved error is back",
			Detail: fmt.Sprintf("%s was resolved and has failed again in %s.%s", appErrLabel(e), v, appNotifyLine(svc)),
			Route:  e.Route, Method: e.Method, EventType: "app.alert", Time: now,
			DedupKey: fmt.Sprintf("%d:%s:%s", svc.ID, e.Fingerprint, e.RegressedAt.UTC().Format("20060102150405"))})
	}
}
