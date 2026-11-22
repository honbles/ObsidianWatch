package api

// app_diagnosis.go - where a route's time goes and what the database is asked (APM spec items 1 and 2).
// Read side only: the agent computes self time, children and fingerprints; the ingest backend stores them.

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"obsidianwatch/management/internal/store"
)

type appChildRow struct {
	Kind    string  `json:"kind"`
	Target  string  `json:"target"`
	Name    string  `json:"name"`
	Calls   int64   `json:"calls"`
	TotalMs float64 `json:"total_ms"`
	AvgMs   float64 `json:"avg_ms"`
}

// appAttachDiagnosis adds the slowest downstream calls (top 3 by total time) and the N+1 count to each route.
// A missing table (ingest migration not run) or an old agent that sends nothing leaves the fields empty.
func appAttachDiagnosis(ctx context.Context, idb *store.DB, id int64, from, to time.Time, list []appRouteRow, idx map[string]int) {
	rows, err := idb.QueryContext(ctx, `
		SELECT route, method, kind, target, name, SUM(calls), SUM(total_ms)
		FROM app_route_children WHERE service_id = $1 AND minute >= $2 AND minute < $3
		GROUP BY route, method, kind, target, name`, id, from, to)
	if err == nil {
		per := map[int][]appChildRow{}
		for rows.Next() {
			var route, method string
			var c appChildRow
			if rows.Scan(&route, &method, &c.Kind, &c.Target, &c.Name, &c.Calls, &c.TotalMs) != nil {
				continue
			}
			if i, ok := idx[method+" "+route]; ok && c.Calls > 0 {
				c.AvgMs = c.TotalMs / float64(c.Calls)
				per[i] = append(per[i], c)
			}
		}
		rows.Close()
		for i, cs := range per {
			sort.Slice(cs, func(a, b int) bool { return cs[a].TotalMs > cs[b].TotalMs })
			if len(cs) > 3 {
				cs = cs[:3]
			}
			list[i].TopChildren = cs
		}
	}
	nrows, err := idb.QueryContext(ctx, `
		SELECT route, method, SUM(count) FROM app_route_n1
		WHERE service_id = $1 AND minute >= $2 AND minute < $3 GROUP BY route, method`, id, from, to)
	if err == nil {
		for nrows.Next() {
			var route, method string
			var n int64
			if nrows.Scan(&route, &method, &n) == nil {
				if i, ok := idx[method+" "+route]; ok {
					list[i].NPlusOneCount = n
				}
			}
		}
		nrows.Close()
	}
}

type appQueryRow struct {
	System      string  `json:"system"`
	Operation   string  `json:"operation"`
	Table       string  `json:"table"`
	Fingerprint string  `json:"fingerprint,omitempty"`
	Text        string  `json:"text,omitempty"`
	Calls       int64   `json:"calls"`
	Errors      int64   `json:"errors"`
	TotalMs     float64 `json:"total_ms"`
	AvgMs       float64 `json:"avg_ms"`
	P95Ms       float64 `json:"p95_ms"`
	OverRange   bool    `json:"over_range,omitempty"`
}

// appHandleQueries lists database calls for a service in the range, grouped by operation, table and (when the
// service allows fingerprints) statement. sort=total_ms (default) | p95 | calls | errors.
func appHandleQueries(db, backendDB *store.DB) http.HandlerFunc {
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
			SELECT system, operation, tbl, fingerprint, MAX(text), SUM(calls), SUM(errors), SUM(total_ms)
			FROM app_db_stats WHERE service_id = $1 AND minute >= $2 AND minute < $3
			GROUP BY system, operation, tbl, fingerprint LIMIT 2000`, id, from, to)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		list := []appQueryRow{}
		idx := map[[4]string]int{}
		for rows.Next() {
			var q appQueryRow
			if rows.Scan(&q.System, &q.Operation, &q.Table, &q.Fingerprint, &q.Text, &q.Calls, &q.Errors, &q.TotalMs) != nil {
				continue
			}
			if q.Calls > 0 {
				q.AvgMs = q.TotalMs / float64(q.Calls)
			}
			idx[[4]string{q.System, q.Operation, q.Table, q.Fingerprint}] = len(list)
			list = append(list, q)
		}
		rows.Close()
		hrows, err := idb.QueryContext(r.Context(), `
			SELECT s.system, s.operation, s.tbl, s.fingerprint, g.i, SUM(COALESCE((s.duration_buckets->>g.i)::bigint, 0))
			FROM app_db_stats s CROSS JOIN generate_series(0, 11) AS g(i)
			WHERE s.service_id = $1 AND s.minute >= $2 AND s.minute < $3
			GROUP BY s.system, s.operation, s.tbl, s.fingerprint, g.i`, id, from, to)
		if err == nil {
			hist := map[int]*[12]int64{}
			for hrows.Next() {
				var sy, op, tb, fp string
				var bi int
				var n int64
				if hrows.Scan(&sy, &op, &tb, &fp, &bi, &n) != nil {
					continue
				}
				if i, ok := idx[[4]string{sy, op, tb, fp}]; ok && bi >= 0 && bi < 12 {
					if hist[i] == nil {
						hist[i] = &[12]int64{}
					}
					hist[i][bi] = n
				}
			}
			hrows.Close()
			for i, h := range hist {
				list[i].P95Ms, list[i].OverRange = appPercentile(h[:], 0.95)
			}
		}
		switch r.URL.Query().Get("sort") {
		case "p95":
			sort.SliceStable(list, func(i, j int) bool { return list[i].P95Ms > list[j].P95Ms })
		case "calls":
			sort.SliceStable(list, func(i, j int) bool { return list[i].Calls > list[j].Calls })
		case "errors":
			sort.SliceStable(list, func(i, j int) bool { return list[i].Errors > list[j].Errors })
		default:
			sort.SliceStable(list, func(i, j int) bool { return list[i].TotalMs > list[j].TotalMs })
		}
		if len(list) > 200 {
			list = list[:200]
		}
		writeJSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "queries": list})
	}
}

// appCriticalPath returns the span ids, root first, that decided when the trace ended: from the root, the
// child that finished last, and so on down. Spans must carry span_id, parent_id, start_ms and dur_ms.
// self_ms is added to any span that lacks it (traces from an agent older than this feature).
func appEnrichSpans(raw json.RawMessage) (spans json.RawMessage, path []string) {
	var list []map[string]any
	if json.Unmarshal(raw, &list) != nil || len(list) == 0 {
		return raw, nil
	}
	num := func(m map[string]any, k string) float64 { v, _ := m[k].(float64); return v }
	str := func(m map[string]any, k string) string { v, _ := m[k].(string); return v }
	byID := map[string]map[string]any{}
	kids := map[string][]map[string]any{}
	for _, s := range list {
		byID[str(s, "span_id")] = s
	}
	var root map[string]any
	for _, s := range list {
		p := str(s, "parent_id")
		if _, ok := byID[p]; p != "" && ok {
			kids[p] = append(kids[p], s)
		} else if root == nil || num(s, "dur_ms") > num(root, "dur_ms") {
			root = s // no parent in the kept set: the longest such span is the root
		}
	}
	for _, s := range list {
		if _, has := s["self_ms"]; !has {
			v := num(s, "dur_ms")
			for _, c := range kids[str(s, "span_id")] {
				v -= num(c, "dur_ms")
			}
			if v < 0 {
				v = 0
			}
			s["self_ms"] = float64(int64(v*10+0.5)) / 10
		}
	}
	for cur, i := root, 0; cur != nil && i < 64; i++ {
		path = append(path, str(cur, "span_id"))
		var next map[string]any
		for _, c := range kids[str(cur, "span_id")] {
			if next == nil || num(c, "start_ms")+num(c, "dur_ms") > num(next, "start_ms")+num(next, "dur_ms") {
				next = c
			}
		}
		cur = next
	}
	out, err := json.Marshal(list)
	if err != nil {
		return raw, path
	}
	return out, path
}
