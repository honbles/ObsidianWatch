package api

// app_traces.go - sampled trace and dependency read APIs. Owned by the Application build.
//
//	GET /api/v1/app/traces                  list (service_id, route, status, reason, min_duration_ms, from, to, limit)
//	GET /api/v1/app/traces/{trace_id}       one trace with its spans
//	GET /api/v1/app/services/{id}/edges     dependencies seen in the range
//
// Traces are metadata only (names, timings, routes, status); the agent never sends bodies,
// headers or query strings.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

var appTraceIDRe = regexp.MustCompile(`^[0-9a-f]{1,64}$`)
var appKeepReasons = map[string]bool{"error": true, "slow": true, "security": true, "baseline": true}

type appTraceRow struct {
	TraceID     string          `json:"trace_id"`
	ServiceID   int64           `json:"service_id"`
	Service     string          `json:"service"`
	Environment string          `json:"environment"`
	AgentID     string          `json:"agent_id"`
	Started     time.Time       `json:"started"`
	DurationMs  int             `json:"duration_ms"`
	RootRoute   string          `json:"root_route"`
	Status      string          `json:"status"`
	KeepReason  string          `json:"keep_reason"`
	SpanCount   int             `json:"span_count"`
	Spans       json.RawMessage `json:"spans,omitempty"`
}

func appHandleListTraces(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		from, to, msg := appParseRange(r)
		if msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		q := r.URL.Query()
		var sid int64
		if v := q.Get("service_id"); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid service_id"})
				return
			}
			sid = n
		}
		reason, status := q.Get("reason"), q.Get("status")
		if reason != "" && !appKeepReasons[reason] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reason must be error, slow, security or baseline"})
			return
		}
		if status != "" && status != "ok" && status != "error" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be ok or error"})
			return
		}
		minDur, _ := strconv.Atoi(q.Get("min_duration_ms"))
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		route := strings.TrimSpace(q.Get("route"))

		rows, err := idb.QueryContext(r.Context(), `
			SELECT t.trace_id, t.service_id, COALESCE(s.name,''), COALESCE(s.environment,''), t.agent_id, t.started,
			       t.duration_ms, t.root_route, t.status, t.keep_reason, t.span_count
			FROM app_traces t LEFT JOIN services s ON s.id = t.service_id
			WHERE t.started >= $1 AND t.started < $2
			  AND ($3 = 0 OR t.service_id = $3) AND ($4 = '' OR t.keep_reason = $4) AND ($5 = '' OR t.status = $5)
			  AND t.duration_ms >= $6 AND ($7 = '' OR t.root_route ILIKE '%' || $7 || '%')
			ORDER BY t.started DESC LIMIT $8`, from, to, sid, reason, status, minDur, route, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
			return
		}
		defer rows.Close()
		list := []appTraceRow{}
		for rows.Next() {
			var t appTraceRow
			if err := rows.Scan(&t.TraceID, &t.ServiceID, &t.Service, &t.Environment, &t.AgentID, &t.Started,
				&t.DurationMs, &t.RootRoute, &t.Status, &t.KeepReason, &t.SpanCount); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
				return
			}
			list = append(list, t)
		}
		writeJSON(w, http.StatusOK, map[string]any{"traces": list, "from": from, "to": to})
	}
}

func appHandleGetTrace(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id := strings.ToLower(r.PathValue("trace_id"))
		if !appTraceIDRe.MatchString(id) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid trace id"})
			return
		}
		var t appTraceRow
		var spans []byte
		err := idb.QueryRowContext(r.Context(), `
			SELECT t.trace_id, t.service_id, COALESCE(s.name,''), COALESCE(s.environment,''), t.agent_id, t.started,
			       t.duration_ms, t.root_route, t.status, t.keep_reason, t.span_count, t.spans
			FROM app_traces t LEFT JOIN services s ON s.id = t.service_id WHERE t.trace_id = $1`, id).
			Scan(&t.TraceID, &t.ServiceID, &t.Service, &t.Environment, &t.AgentID, &t.Started,
				&t.DurationMs, &t.RootRoute, &t.Status, &t.KeepReason, &t.SpanCount, &spans)
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "trace not found (traces are kept for 7 days)"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
			return
		}
		t.Spans = json.RawMessage(spans)
		writeJSON(w, http.StatusOK, t)
	}
}

func appHandleServiceEdges(db, backendDB *store.DB) http.HandlerFunc {
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
		rows, err := idb.QueryContext(r.Context(), `
			SELECT e.dst_kind, e.dst_name, e.source, e.calls, e.errors, e.first_seen, e.last_seen,
			       COALESCE(h.calls,0), COALESCE(h.errors,0)
			FROM service_edges e
			LEFT JOIN (SELECT dst_kind, dst_name, source, SUM(calls) AS calls, SUM(errors) AS errors
			           FROM app_edge_stats WHERE src_service = $1 AND hour >= $4 AND hour < $3 GROUP BY 1,2,3) h
			  USING (dst_kind, dst_name, source)
			WHERE e.src_service = $1 AND e.last_seen >= $2 AND e.first_seen < $3
			ORDER BY COALESCE(h.calls,0) DESC, e.calls DESC LIMIT 500`, id, from, to, from.Truncate(time.Hour))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
			return
		}
		defer rows.Close()
		type edge struct {
			DstKind     string    `json:"dst_kind"`
			DstName     string    `json:"dst_name"`
			Source      string    `json:"source"`
			Calls       int64     `json:"calls"`       // cumulative since first seen
			Errors      int64     `json:"errors"`      // cumulative since first seen
			RangeCalls  int64     `json:"range_calls"` // calls inside the requested range (hourly resolution)
			RangeErrors int64     `json:"range_errors"`
			FirstSeen   time.Time `json:"first_seen"`
			LastSeen    time.Time `json:"last_seen"`
			New         bool      `json:"new"` // first seen inside the range
		}
		list := []edge{}
		for rows.Next() {
			var e edge
			if rows.Scan(&e.DstKind, &e.DstName, &e.Source, &e.Calls, &e.Errors, &e.FirstSeen, &e.LastSeen, &e.RangeCalls, &e.RangeErrors) == nil {
				e.New = !e.FirstSeen.Before(from)
				list = append(list, e)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "edges": list})
	}
}
