package api

// app_timeline.go - one chronological activity feed per service (spec D2): the host sensor's
// connections, process starts and file activity, lifecycle changes (instance started or stopped,
// new version, route or dependency), alerts and security events.
//
//	GET /api/v1/app/services/{id}/timeline?from&to&category=&host=&limit=

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"obsidianwatch/management/internal/store"
)

type appTimelineItem struct {
	Time      time.Time `json:"time"`
	Category  string    `json:"category"` // connection | process | file | lifecycle | alert | security
	Kind      string    `json:"kind"`
	Host      string    `json:"host,omitempty"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail,omitempty"`
	FirstSeen bool      `json:"first_seen,omitempty"` // a destination not seen before the range
	AlertID   int64     `json:"alert_id,omitempty"`
	Severity  int       `json:"severity,omitempty"`
	TraceID   string    `json:"trace_id,omitempty"`
	Route     string    `json:"route,omitempty"`
	Method    string    `json:"method,omitempty"`
}

var appTimelineCategories = map[string]bool{"connection": true, "process": true, "file": true, "lifecycle": true, "alert": true, "security": true, "request": true}

func appHandleServiceTimeline(db, backendDB *store.DB) http.HandlerFunc {
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
		cat := r.URL.Query().Get("category")
		if cat != "" && !appTimelineCategories[cat] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "category must be connection, process, file, lifecycle, alert, security or request"})
			return
		}
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 300
		}
		ctx := r.Context()
		var name, env string
		if err := idb.QueryRowContext(ctx, `SELECT name, environment FROM services WHERE id=$1`, id).Scan(&name, &env); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "service not found"})
			return
		}
		want := func(c string) bool { return cat == "" || cat == c }
		var items []appTimelineItem
		var hosts = map[string]bool{}

		// Instances active in the range: their pids scope the host events, and they are lifecycle entries.
		type instRow struct {
			agent, host string
			pid         int
		}
		var insts []instRow
		irows, err := idb.QueryContext(ctx, `
			SELECT agent_id, host, pid, COALESCE(NULLIF(attrs->>'container_name',''), NULLIF(attrs->>'unit',''), ''), first_seen, stopped_at
			FROM service_instances WHERE service_id=$1 AND last_seen >= $2 AND first_seen < $3 ORDER BY first_seen DESC LIMIT 300`, id, from, to)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		for irows.Next() {
			var in instRow
			var where string
			var first time.Time
			var stopped sql.NullTime
			if irows.Scan(&in.agent, &in.host, &in.pid, &where, &first, &stopped) != nil {
				continue
			}
			hosts[in.host] = true
			if in.pid > 0 {
				insts = append(insts, in)
			}
			if host != "" && in.host != host {
				continue
			}
			label := "pid " + strconv.Itoa(in.pid)
			if where != "" {
				label += " (" + where + ")"
			}
			if want("lifecycle") {
				if !first.Before(from) && first.Before(to) {
					items = append(items, appTimelineItem{Time: first, Category: "lifecycle", Kind: "instance_started", Host: in.host, Title: "Instance started", Detail: label})
				}
				if stopped.Valid && !stopped.Time.Before(from) && stopped.Time.Before(to) {
					items = append(items, appTimelineItem{Time: stopped.Time, Category: "lifecycle", Kind: "instance_stopped", Host: in.host, Title: "Instance stopped", Detail: label})
				}
			}
		}
		irows.Close()

		if want("lifecycle") && host == "" {
			lc := func(q, kind, title string, detail func(a, b string) string) {
				rows, err := idb.QueryContext(ctx, q, id, from, to)
				if err != nil {
					return
				}
				defer rows.Close()
				for rows.Next() {
					var t time.Time
					var a, b string
					if rows.Scan(&t, &a, &b) == nil {
						items = append(items, appTimelineItem{Time: t, Category: "lifecycle", Kind: kind, Title: title, Detail: detail(a, b)})
					}
				}
			}
			lc(`SELECT first_seen, version, '' FROM service_versions WHERE service_id=$1 AND first_seen >= $2 AND first_seen < $3 LIMIT 200`,
				"new_version", "New version", func(a, _ string) string { return a })
			lc(`SELECT first_seen, method, route FROM service_routes WHERE service_id=$1 AND first_seen >= $2 AND first_seen < $3 LIMIT 200`,
				"new_route", "New route", func(a, b string) string { return a + " " + b })
			lc(`SELECT first_seen, dst_kind, dst_name FROM service_edges WHERE src_service=$1 AND first_seen >= $2 AND first_seen < $3 LIMIT 200`,
				"new_dependency", "New dependency", func(a, b string) string { return b + " (" + a + ")" })
		}

		// Host sensor events under the service's processes.
		if len(insts) > 0 && (want("connection") || want("process") || want("file")) {
			agents := map[string]bool{}
			pidSet := map[int64]bool{}
			for _, in := range insts {
				if host == "" || in.host == host {
					agents[in.agent] = true
					pidSet[int64(in.pid)] = true
				}
			}
			var agentList []string
			var pids []int64
			for a := range agents {
				agentList = append(agentList, a)
			}
			for p := range pidSet {
				pids = append(pids, p)
			}
			types := []string{}
			if want("process") {
				types = append(types, "process")
			}
			if want("connection") {
				types = append(types, "network")
			}
			if want("file") {
				types = append(types, "file")
			}
			if len(pids) > 0 {
				rows, err := idb.QueryContext(ctx, `
					SELECT time, event_type, host, COALESCE(process_name,''), COALESCE(pid,0), COALESCE(command_line,''),
					       COALESCE(split_part(dst_ip::text,'/',1),''), COALESCE(dst_port,0), COALESCE(raw->>'path', COALESCE(file_path,''))
					FROM events
					WHERE agent_id = ANY($1) AND time >= $2 AND time < $3 AND event_type = ANY($4)
					  AND NOT (event_type = 'network' AND dst_port IN (4317, 4318) AND split_part(dst_ip::text, '/', 1) IN ('127.0.0.1', '::1')) 
					  AND (pid = ANY($5) OR ppid = ANY($5)
					       OR EXISTS (SELECT 1 FROM unnest($5::bigint[]) p WHERE raw->'proc'->'ancestors' @> jsonb_build_array(jsonb_build_object('pid', p))))
					ORDER BY time DESC LIMIT $6`, pq.Array(agentList), from, to, pq.Array(types), pq.Array(pids), limit)
				if err != nil {
					appQueryFailed(w, r.URL.Path, id, err)
					return
				}
				var netIdx []int
				for rows.Next() {
					var t time.Time
					var typ, h, proc, cmd, dip, path string
					var pid, dport int
					if rows.Scan(&t, &typ, &h, &proc, &pid, &cmd, &dip, &dport, &path) != nil {
						continue
					}
					hosts[h] = true
					switch typ {
					case "network":
						items = append(items, appTimelineItem{Time: t, Category: "connection", Kind: "connection", Host: h,
							Title: "Connection to " + dip + ":" + strconv.Itoa(dport), Detail: proc + " pid " + strconv.Itoa(pid)})
						netIdx = append(netIdx, len(items)-1)
					case "file":
						items = append(items, appTimelineItem{Time: t, Category: "file", Kind: "file", Host: h, Title: "File activity", Detail: path + "  " + proc})
					default:
						d := cmd
						if d == "" {
							d = proc
						}
						items = append(items, appTimelineItem{Time: t, Category: "process", Kind: "process", Host: h, Title: "Process started: " + proc, Detail: d})
					}
				}
				rows.Close()
				appFlagFirstSeen(ctx, idb, agentList, pids, from, items, netIdx)
			}
		}

		if want("alert") {
			rows, err := db.QueryContext(ctx, `
				SELECT a.id, a.created_at, a.title, a.severity, COALESCE(a.host,'')
				FROM alerts a JOIN alert_entities e ON e.alert_id = a.id
				WHERE e.kind='service' AND e.key=$1 AND a.created_at >= $2 AND a.created_at < $3
				ORDER BY a.id DESC LIMIT 200`, appServiceKey(name, env), from, to)
			if err == nil {
				for rows.Next() {
					var it appTimelineItem
					if rows.Scan(&it.AlertID, &it.Time, &it.Title, &it.Severity, &it.Host) == nil {
						it.Category, it.Kind = "alert", "alert"
						if host == "" || it.Host == host {
							items = append(items, it)
						}
					}
				}
				rows.Close()
			}
		}
		if want("security") {
			rows, err := idb.QueryContext(ctx, `
				SELECT time, host, COALESCE(raw->'app'->>'event.name',''), COALESCE(raw->'app'->>'route','')
				FROM events WHERE event_type='app.security' AND time >= $1 AND time < $2
				  AND raw->'app'->>'service' = $3 AND raw->'app'->>'environment' = $4 ORDER BY time DESC LIMIT 200`, from, to, name, env)
			if err == nil {
				for rows.Next() {
					var it appTimelineItem
					var ev, route string
					if rows.Scan(&it.Time, &it.Host, &ev, &route) == nil && (host == "" || it.Host == host) {
						it.Category, it.Kind, it.Title, it.Detail = "security", "security", "Security event: "+ev, route
						items = append(items, it)
					}
				}
				rows.Close()
			}
		}

		if want("request") && host == "" { // samples are not tied to a host
			// Sampled requests from reviewed routes: field names only here. Values stay on the review page (admin only).
			rows, err := idb.QueryContext(ctx, `
				SELECT time, method, route, status, trace_id, ARRAY(SELECT jsonb_object_keys(params)), withheld
				FROM app_payloads WHERE service_id=$1 AND time >= $2 AND time < $3 ORDER BY time DESC LIMIT 100`, id, from, to)
			if err == nil {
				for rows.Next() {
					var it appTimelineItem
					var st int
					var tr sql.NullString
					var names pq.StringArray
					var wj []byte
					if rows.Scan(&it.Time, &it.Method, &it.Route, &st, &tr, &names, &wj) == nil {
						var wh []string
						_ = json.Unmarshal(wj, &wh)
						it.Category, it.Kind, it.TraceID = "request", "request", tr.String
						it.Title = fmt.Sprintf("Request sample: %s %s (%d)", it.Method, it.Route, st)
						it.Detail = "captured: " + strings.Join(names, ", ")
						if len(wh) > 0 {
							it.Detail += "; withheld: " + strings.Join(wh, ", ")
						}
						items = append(items, it)
					}
				}
				rows.Close()
			}
		}

		counts := map[string]int{}
		for _, it := range items {
			counts[it.Category]++
		}
		sort.SliceStable(items, func(i, j int) bool { return items[i].Time.After(items[j].Time) })
		if len(items) > limit {
			items = items[:limit]
		}
		hl := make([]string, 0, len(hosts))
		for h := range hosts {
			hl = append(hl, h)
		}
		sort.Strings(hl)
		if items == nil {
			items = []appTimelineItem{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "counts": counts, "hosts": hl, "from": from, "to": to})
	}
}

// appFlagFirstSeen marks connection items whose destination was not contacted by these processes in the
// 30 days before the range; only the earliest item for a destination is flagged.
func appFlagFirstSeen(ctx context.Context, idb *store.DB, agents []string, pids []int64, from time.Time, items []appTimelineItem, idx []int) {
	if len(idx) == 0 {
		return
	}
	keys := map[string]bool{}
	for _, i := range idx {
		keys[strings.TrimPrefix(items[i].Title, "Connection to ")] = true
	}
	list := make([]string, 0, len(keys))
	for k := range keys {
		list = append(list, k)
	}
	known := map[string]bool{}
	rows, err := idb.QueryContext(ctx, `
		SELECT DISTINCT split_part(dst_ip::text,'/',1) || ':' || COALESCE(dst_port,0)::text AS k FROM events
		WHERE agent_id = ANY($1) AND event_type='network' AND time >= $2 AND time < $3 AND pid = ANY($4)
		  AND split_part(dst_ip::text,'/',1) || ':' || COALESCE(dst_port,0)::text = ANY($5)`,
		pq.Array(agents), from.Add(-30*24*time.Hour), from, pq.Array(pids), pq.Array(list))
	if err != nil {
		return
	}
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			known[k] = true
		}
	}
	rows.Close()
	// items are newest first, so walk backwards to flag the earliest sighting of each new destination.
	flagged := map[string]bool{}
	for n := len(idx) - 1; n >= 0; n-- {
		k := strings.TrimPrefix(items[idx[n]].Title, "Connection to ")
		if !known[k] && !flagged[k] {
			items[idx[n]].FirstSeen, flagged[k] = true, true
		}
	}
}
