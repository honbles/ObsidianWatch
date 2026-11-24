package api

// app_compare.go - compare two versions or two time ranges of a service (APM spec item 10.2) and watch a new
// version after it ships (APM-O12, item 10.3). A version's window runs from the time it was first seen to the time
// the next version was first seen (or now).

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"obsidianwatch/management/internal/store"
)

type appCmpSide struct {
	Label     string    `json:"label"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Calls     int64     `json:"calls"`
	Errors    int64     `json:"errors"`
	ErrorRate float64   `json:"error_rate"`
	P50       float64   `json:"p50_ms"`
	P95       float64   `json:"p95_ms"`
}

type appCmpRoute struct {
	Method string      `json:"method"`
	Route  string      `json:"route"`
	A      *appCmpSide `json:"a,omitempty"`
	B      *appCmpSide `json:"b,omitempty"`
}

type appWinAgg struct {
	calls, errors int64
	hist          [12]int64
}

func (w *appWinAgg) side(label string, from, to time.Time) *appCmpSide {
	s := &appCmpSide{Label: label, From: from, To: to, Calls: w.calls, Errors: w.errors}
	if w.calls > 0 {
		s.ErrorRate = float64(w.errors) / float64(w.calls)
	}
	s.P50, _ = appPercentile(w.hist[:], 0.5)
	s.P95, _ = appPercentile(w.hist[:], 0.95)
	return s
}

// appWindowByRoute reads per-route totals and latency histograms over [from, to).
func appWindowByRoute(ctx context.Context, idb *store.DB, id int64, from, to time.Time) (map[[2]string]*appWinAgg, *appWinAgg, error) {
	per := map[[2]string]*appWinAgg{}
	tot := &appWinAgg{}
	rows, err := idb.QueryContext(ctx, `SELECT route, method, SUM(calls), SUM(errors) FROM app_route_stats
		WHERE service_id = $1 AND minute >= $2 AND minute < $3 GROUP BY route, method LIMIT 5000`, id, from, to)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var r, m string
		var c, e int64
		if rows.Scan(&r, &m, &c, &e) == nil {
			per[[2]string{m, r}] = &appWinAgg{calls: c, errors: e}
			tot.calls += c
			tot.errors += e
		}
	}
	rows.Close()
	hrows, err := idb.QueryContext(ctx, `
		SELECT s.route, s.method, g.i, SUM(COALESCE((s.duration_buckets->>g.i)::bigint, 0))
		FROM app_route_stats s CROSS JOIN generate_series(0, 11) AS g(i)
		WHERE s.service_id = $1 AND s.minute >= $2 AND s.minute < $3 GROUP BY s.route, s.method, g.i`, id, from, to)
	if err == nil {
		for hrows.Next() {
			var r, m string
			var i int
			var n int64
			if hrows.Scan(&r, &m, &i, &n) == nil && i >= 0 && i < 12 {
				if a := per[[2]string{m, r}]; a != nil {
					a.hist[i] += n
				}
				tot.hist[i] += n
			}
		}
		hrows.Close()
	}
	return per, tot, nil
}

// appVersionWindow returns the window a version was live.
func appVersionWindow(ctx context.Context, idb *store.DB, id int64, version string, now time.Time) (from, to time.Time, ok bool) {
	if idb.QueryRowContext(ctx, `SELECT first_seen FROM service_versions WHERE service_id = $1 AND version = $2`, id, version).Scan(&from) != nil {
		return from, to, false
	}
	var next time.Time
	if idb.QueryRowContext(ctx, `SELECT MIN(first_seen) FROM service_versions WHERE service_id = $1 AND first_seen > $2`, id, from).Scan(&next) == nil && !next.IsZero() {
		return from, next, true
	}
	return from, now.Add(time.Minute), true
}

func appHandleCompare(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		q := r.URL.Query()
		now := time.Now().UTC()
		var af, at, bf, bt time.Time
		la, lb := "range A", "range B"
		if va, vb := q.Get("a"), q.Get("b"); va != "" || vb != "" {
			if va == "" || vb == "" || len(va) > 64 || len(vb) > 64 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "send both a and b"})
				return
			}
			var ok1, ok2 bool
			af, at, ok1 = appVersionWindow(r.Context(), idb, id, va, now)
			bf, bt, ok2 = appVersionWindow(r.Context(), idb, id, vb, now)
			if !ok1 || !ok2 {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "version not found"})
				return
			}
			la, lb = va, vb
		} else {
			p := func(k string) time.Time { t, _ := time.Parse(time.RFC3339, q.Get(k)); return t }
			af, at, bf, bt = p("a_from"), p("a_to"), p("b_from"), p("b_to")
			if af.IsZero() || at.IsZero() || bf.IsZero() || bt.IsZero() || !af.Before(at) || !bf.Before(bt) ||
				at.Sub(af) > appMaxRangeDays*24*time.Hour || bt.Sub(bf) > appMaxRangeDays*24*time.Hour {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "send a and b (versions) or a_from, a_to, b_from, b_to"})
				return
			}
		}
		pa, ta, err := appWindowByRoute(r.Context(), idb, id, af, at)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		pb, tb, err := appWindowByRoute(r.Context(), idb, id, bf, bt)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		keys := map[[2]string]bool{}
		for k := range pa {
			keys[k] = true
		}
		for k := range pb {
			keys[k] = true
		}
		routes := make([]appCmpRoute, 0, len(keys))
		for k := range keys {
			rt := appCmpRoute{Method: k[0], Route: k[1]}
			if a := pa[k]; a != nil {
				rt.A = a.side(la, af, at)
			}
			if b := pb[k]; b != nil {
				rt.B = b.side(lb, bf, bt)
			}
			routes = append(routes, rt)
		}
		sort.Slice(routes, func(i, j int) bool {
			ci, cj := int64(0), int64(0)
			if routes[i].B != nil {
				ci = routes[i].B.Calls
			}
			if routes[j].B != nil {
				cj = routes[j].B.Calls
			}
			if ci != cj {
				return ci > cj
			}
			return routes[i].Route < routes[j].Route
		})
		if len(routes) > 200 {
			routes = routes[:200]
		}
		out := map[string]any{"a": ta.side(la, af, at), "b": tb.side(lb, bf, bt), "routes": routes,
			"new_routes":       appFirstSeenIn(r.Context(), idb, `SELECT method || ' ' || route FROM service_routes WHERE service_id = $1 AND first_seen >= $2 AND first_seen < $3 ORDER BY first_seen LIMIT 100`, id, bf, bt),
			"new_error_groups": appFirstSeenIn(r.Context(), idb, `SELECT COALESCE(NULLIF(type,''),'error') || CASE WHEN route <> '' THEN ' on ' || method || ' ' || route ELSE '' END FROM error_groups WHERE service_id = $1 AND first_seen >= $2 AND first_seen < $3 ORDER BY first_seen LIMIT 100`, id, bf, bt),
			"new_dependencies": appFirstSeenIn(r.Context(), idb, `SELECT dst_name || ' (' || dst_kind || ')' FROM service_edges WHERE src_service = $1 AND first_seen >= $2 AND first_seen < $3 ORDER BY first_seen LIMIT 100`, id, bf, bt)}
		writeJSON(w, http.StatusOK, out)
	}
}

func appFirstSeenIn(ctx context.Context, idb *store.DB, q string, id int64, from, to time.Time) []string {
	out := []string{}
	rows, err := idb.QueryContext(ctx, q, id, from, to)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			out = append(out, s)
		}
	}
	return out
}

// ── APM-O12 ────────────────────────────────────────────────────────────────

type appDeploy struct {
	Version   string
	FirstSeen time.Time
}

type appWindowTotals struct {
	Calls, Errors int64
	P95Ms         float64
}

// Deploys lists versions first seen since the given time, other than the service's first version.
func (d appPGData) Deploys(ctx context.Context, svcID int64, since time.Time) ([]appDeploy, error) {
	rows, err := d.idb.QueryContext(ctx, `
		SELECT version, first_seen FROM service_versions
		WHERE service_id = $1 AND first_seen >= $2
		  AND first_seen > (SELECT MIN(first_seen) FROM service_versions WHERE service_id = $1) ORDER BY first_seen LIMIT 20`, svcID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []appDeploy
	for rows.Next() {
		var x appDeploy
		if rows.Scan(&x.Version, &x.FirstSeen) == nil {
			out = append(out, x)
		}
	}
	return out, nil
}

// WindowTotals returns service-wide calls, errors and p95 over [from, to).
func (d appPGData) WindowTotals(ctx context.Context, svcID int64, from, to time.Time) (appWindowTotals, error) {
	_, tot, err := appWindowByRoute(ctx, d.idb, svcID, from, to)
	if err != nil {
		return appWindowTotals{}, err
	}
	p95, _ := appPercentile(tot.hist[:], 0.95)
	return appWindowTotals{Calls: tot.calls, Errors: tot.errors, P95Ms: p95}, nil
}

// o12: after a new version appears, its error rate or p95 is well above what the day before looked like.
func (r *appRules) o12(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O12", svc)
	if !on || appInMaintenance(svc.Settings, now) {
		return
	}
	watch := time.Duration(g.Param("window_min", 30)) * time.Minute
	minWait := time.Duration(g.Param("min_wait_min", 5)) * time.Minute
	minCalls := int64(g.Param("min_calls", 100))
	errDelta := g.Param("error_delta_pct", 2) / 100
	errFactor := g.Param("error_factor", 1.5)
	latFactor := g.Param("p95_factor", 1.5)
	latDelta := g.Param("p95_delta_ms", 50)
	deps, err := r.d.Deploys(ctx, svc.ID, now.Add(-watch))
	if err != nil {
		return
	}
	for _, dp := range deps {
		if now.Sub(dp.FirstSeen) < minWait {
			continue
		}
		post, err := r.d.WindowTotals(ctx, svc.ID, dp.FirstSeen, now.Add(time.Minute))
		if err != nil || post.Calls < minCalls {
			continue
		}
		pre, err := r.d.WindowTotals(ctx, svc.ID, dp.FirstSeen.Add(-24*time.Hour), dp.FirstSeen)
		if err != nil || pre.Calls < minCalls {
			continue
		}
		pr, br := float64(post.Errors)/float64(post.Calls), float64(pre.Errors)/float64(pre.Calls)
		var why []string
		if pr-br >= errDelta && pr >= br*errFactor {
			why = append(why, fmt.Sprintf("error rate %.1f%% (was %.1f%%)", pr*100, br*100))
		}
		if pre.P95Ms > 0 && post.P95Ms >= pre.P95Ms*latFactor && post.P95Ms-pre.P95Ms >= latDelta {
			why = append(why, fmt.Sprintf("p95 %.0f ms (was %.0f ms)", post.P95Ms, pre.P95Ms))
		}
		if len(why) == 0 {
			continue
		}
		r.fire(ctx, appFinding{RuleID: "APM-O12", Svc: svc, BaseSev: appSevHigh, Summary: "Post-deploy regression",
			Detail:    fmt.Sprintf("Since version %s appeared, %s, against the 24 hours before it.%s", dp.Version, joinAnd(why), appNotifyLine(svc)),
			EventType: "app.alert", Time: now, DedupKey: fmt.Sprintf("%d:%s", svc.ID, dp.Version)})
	}
}

func joinAnd(s []string) string {
	if len(s) == 2 {
		return s[0] + " and " + s[1]
	}
	return s[0]
}
