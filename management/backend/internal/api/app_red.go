package api

// app_red.go - RED (rate, errors, duration) read APIs over app_route_stats.
// Owned by the Application build. Statistics are read through backendDB.
//
//	GET /api/v1/app/services/{id}/red     time series (optional route + method filter)
//	GET /api/v1/app/services/{id}/routes  per-route table for the range
//
// Percentiles are estimated from the 12-bucket histograms (linear interpolation
// inside a bucket); a value in the last bucket is reported as the highest bound
// with over_range=true instead of inventing a number.

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"obsidianwatch/management/internal/store"
)

// appDurBounds are the histogram upper bounds (ms); keep in step with the ingest store.
var appDurBounds = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

const (
	appHistLen      = 12
	appMaxRangeDays = 90
	appMaxSeriesPts = 2000
	appMaxRouteRows = 1000
	appStepMinSecs  = 60
	appStepMaxSecs  = 86400
)

// appPercentile estimates the q-quantile (0..1) in ms from histogram counts.
// over is true when the quantile falls in the open-ended last bucket.
func appPercentile(h []int64, q float64) (ms float64, over bool) {
	var total int64
	for _, v := range h {
		total += v
	}
	if total == 0 || len(h) == 0 {
		return 0, false
	}
	target := q * float64(total)
	var cum float64
	for i, v := range h {
		if v == 0 {
			continue
		}
		if cum+float64(v) >= target {
			if i >= len(appDurBounds) {
				return appDurBounds[len(appDurBounds)-1], true
			}
			lower := 0.0
			if i > 0 {
				lower = appDurBounds[i-1]
			}
			frac := (target - cum) / float64(v)
			return lower + (appDurBounds[i]-lower)*frac, false
		}
		cum += float64(v)
	}
	return appDurBounds[len(appDurBounds)-1], true
}

// appChooseStep picks a bucket width in seconds for a range, or validates a requested one.
func appChooseStep(from, to time.Time, requested int) int {
	if requested > 0 {
		if requested < appStepMinSecs {
			requested = appStepMinSecs
		}
		if requested > appStepMaxSecs {
			requested = appStepMaxSecs
		}
		requested -= requested % 60
	} else {
		d := to.Sub(from)
		switch {
		case d <= 2*time.Hour:
			requested = 60
		case d <= 12*time.Hour:
			requested = 300
		case d <= 3*24*time.Hour:
			requested = 1800
		case d <= 14*24*time.Hour:
			requested = 3600
		default:
			requested = 21600
		}
	}
	// Never more points than the cap.
	for float64(to.Sub(from).Seconds())/float64(requested) > appMaxSeriesPts && requested < appStepMaxSecs {
		requested *= 2
	}
	return requested
}

// appParseRange validates from/to (RFC3339). Defaults to the last 24 hours.
func appParseRange(r *http.Request) (from, to time.Time, msg string) {
	from, to = appRange(r)
	if !from.Before(to) {
		return from, to, "from must be before to"
	}
	if to.Sub(from) > appMaxRangeDays*24*time.Hour {
		return from, to, "range too large (max 90 days)"
	}
	return from, to, ""
}

type appREDPoint struct {
	T          time.Time `json:"t"`
	Calls      int64     `json:"calls"`
	Errors     int64     `json:"errors"`
	Status2xx  int64     `json:"status_2xx"`
	Status4013 int64     `json:"status_401_403"`
	Status429  int64     `json:"status_429"`
	Status5xx  int64     `json:"status_5xx"`
	P50        float64   `json:"p50_ms"`
	P95        float64   `json:"p95_ms"`
	P99        float64   `json:"p99_ms"`
	OverRange  bool      `json:"over_range,omitempty"`
}

type appREDTotals struct {
	Calls      int64   `json:"calls"`
	Errors     int64   `json:"errors"`
	ErrorRate  float64 `json:"error_rate"`
	Status2xx  int64   `json:"status_2xx"`
	Status4013 int64   `json:"status_401_403"`
	Status429  int64   `json:"status_429"`
	Status5xx  int64   `json:"status_5xx"`
	P50        float64 `json:"p50_ms"`
	P95        float64 `json:"p95_ms"`
	P99        float64 `json:"p99_ms"`
	OverRange  bool    `json:"over_range,omitempty"`
}

func appFinishPoint(p *appREDPoint, h []int64) {
	var o1, o2, o3 bool
	p.P50, o1 = appPercentile(h, 0.50)
	p.P95, o2 = appPercentile(h, 0.95)
	p.P99, o3 = appPercentile(h, 0.99)
	p.OverRange = o1 || o2 || o3
}

func appHandleREDSeries(db, backendDB *store.DB) http.HandlerFunc {
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
		reqStep, _ := strconv.Atoi(r.URL.Query().Get("step"))
		step := appChooseStep(from, to, reqStep)
		route := r.URL.Query().Get("route")
		method := strings.ToUpper(r.URL.Query().Get("method"))

		rows, err := idb.QueryContext(r.Context(), `
			SELECT to_timestamp(floor(extract(epoch FROM minute) / $5) * $5) AS b,
			       SUM(calls), SUM(errors), SUM(status_2xx), SUM(status_401_403), SUM(status_429), SUM(status_5xx)
			FROM app_route_stats
			WHERE service_id = $1 AND minute >= $2 AND minute < $3
			  AND ($4 = '' OR route = $4) AND ($6 = '' OR method = $6)
			GROUP BY b ORDER BY b`, id, from, to, route, step, method)
		if err != nil {
			appQueryFailed(w, r.URL.Path, 0, err)
			return
		}
		points := map[int64]*appREDPoint{}
		var order []int64
		tot := appREDTotals{}
		for rows.Next() {
			var p appREDPoint
			if err := rows.Scan(&p.T, &p.Calls, &p.Errors, &p.Status2xx, &p.Status4013, &p.Status429, &p.Status5xx); err != nil {
				rows.Close()
				appQueryFailed(w, r.URL.Path, 0, err)
				return
			}
			p.T = p.T.UTC()
			points[p.T.Unix()] = &p
			order = append(order, p.T.Unix())
			tot.Calls += p.Calls
			tot.Errors += p.Errors
			tot.Status2xx += p.Status2xx
			tot.Status4013 += p.Status4013
			tot.Status429 += p.Status429
			tot.Status5xx += p.Status5xx
		}
		rows.Close()

		// Histograms are summed element-wise in SQL, then percentiles are computed here.
		hrows, err := idb.QueryContext(r.Context(), `
			SELECT to_timestamp(floor(extract(epoch FROM s.minute) / $5) * $5) AS b, g.i,
			       SUM(COALESCE((s.duration_buckets->>g.i)::bigint, 0))
			FROM app_route_stats s CROSS JOIN generate_series(0, 11) AS g(i)
			WHERE s.service_id = $1 AND s.minute >= $2 AND s.minute < $3
			  AND ($4 = '' OR s.route = $4) AND ($6 = '' OR s.method = $6)
			GROUP BY b, g.i`, id, from, to, route, step, method)
		if err != nil {
			appQueryFailed(w, r.URL.Path, 0, err)
			return
		}
		hists := map[int64][]int64{}
		all := make([]int64, appHistLen)
		for hrows.Next() {
			var t time.Time
			var i int
			var n int64
			if hrows.Scan(&t, &i, &n) == nil && i >= 0 && i < appHistLen {
				k := t.UTC().Unix()
				if hists[k] == nil {
					hists[k] = make([]int64, appHistLen)
				}
				hists[k][i] += n
				all[i] += n
			}
		}
		hrows.Close()

		series := make([]appREDPoint, 0, len(order))
		for _, k := range order {
			p := points[k]
			appFinishPoint(p, hists[k])
			series = append(series, *p)
		}
		var tp appREDPoint
		appFinishPoint(&tp, all)
		tot.P50, tot.P95, tot.P99, tot.OverRange = tp.P50, tp.P95, tp.P99, tp.OverRange
		if tot.Calls > 0 {
			tot.ErrorRate = float64(tot.Errors) / float64(tot.Calls)
		}
		writeJSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "step_seconds": step, "series": series, "totals": tot})
	}
}

type appRouteRow struct {
	Route     string       `json:"route"`
	Method    string       `json:"method"`
	FirstSeen time.Time    `json:"first_seen"`
	LastSeen  time.Time    `json:"last_seen"`
	Active    bool         `json:"active"`      // traffic inside the requested range
	Observed  bool         `json:"observed"`    // reported by the service at some time (false: only declared by an API spec)
	Declared  bool         `json:"declared"`    // listed in the service's loaded API spec
	NotInSpec bool         `json:"not_in_spec"` // observed, a spec is loaded, and the spec does not list it
	Stats     appREDTotals `json:"stats"`
	// Parameter NAMES seen on the route (never values), most used first. Until a masking policy is saved for
	// the route (payload design, step 2) a route with parameters is reported as needing review, and no payload
	// leaves the agent for it.
	Params        []appRouteParam   `json:"params"`
	PayloadReview string            `json:"payload_review"` // "" (no parameters) | needs_review | new_fields | reviewed
	Policy        *appPayloadPolicy `json:"policy,omitempty"`
	// Slowest downstream calls (top 3 by total time in the range) and the N+1 patterns the agent found.
	TopChildren   []appChildRow `json:"top_children,omitempty"`
	NPlusOneCount int64         `json:"n_plus_one_count,omitempty"`
}

type appRouteParam struct {
	Name      string    `json:"name"`
	State     string    `json:"state"` // always_masked | pending | new | masked | captured
	Requests  int64     `json:"requests"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Source is where the name comes from: observed (seen in traffic), declared (API spec only, no traffic yet)
	// or both. Location is query, path, header or body when the spec says. Undocumented marks a field seen in
	// traffic that the loaded spec does not list for a route it does list (mass-assignment candidates).
	Source       string `json:"source"`
	Location     string `json:"location,omitempty"`
	Undocumented bool   `json:"undocumented,omitempty"`
}

func appHandleRoutes(db, backendDB *store.DB) http.HandlerFunc {
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
			SELECT r.route, r.method, r.first_seen, r.last_seen,
			       COALESCE(s.calls,0), COALESCE(s.errors,0), COALESCE(s.s2,0), COALESCE(s.s4,0), COALESCE(s.s429,0), COALESCE(s.s5,0)
			FROM service_routes r
			LEFT JOIN (
			  SELECT route, method, SUM(calls) calls, SUM(errors) errors, SUM(status_2xx) s2,
			         SUM(status_401_403) s4, SUM(status_429) s429, SUM(status_5xx) s5
			  FROM app_route_stats WHERE service_id = $1 AND minute >= $2 AND minute < $3 GROUP BY route, method
			) s ON s.route = r.route AND s.method = r.method
			WHERE r.service_id = $1
			ORDER BY COALESCE(s.calls,0) DESC, r.last_seen DESC LIMIT $4`, id, from, to, appMaxRouteRows)
		if err != nil {
			appQueryFailed(w, r.URL.Path, 0, err)
			return
		}
		list := []appRouteRow{}
		idx := map[string]int{}
		for rows.Next() {
			var x appRouteRow
			if err := rows.Scan(&x.Route, &x.Method, &x.FirstSeen, &x.LastSeen, &x.Stats.Calls, &x.Stats.Errors,
				&x.Stats.Status2xx, &x.Stats.Status4013, &x.Stats.Status429, &x.Stats.Status5xx); err != nil {
				rows.Close()
				appQueryFailed(w, r.URL.Path, 0, err)
				return
			}
			x.Active = x.Stats.Calls > 0
			x.Observed = true
			x.Params = []appRouteParam{}
			if x.Stats.Calls > 0 {
				x.Stats.ErrorRate = float64(x.Stats.Errors) / float64(x.Stats.Calls)
			}
			idx[x.Method+" "+x.Route] = len(list)
			list = append(list, x)
		}
		rows.Close()

		hrows, err := idb.QueryContext(r.Context(), `
			SELECT s.route, s.method, g.i, SUM(COALESCE((s.duration_buckets->>g.i)::bigint, 0))
			FROM app_route_stats s CROSS JOIN generate_series(0, 11) AS g(i)
			WHERE s.service_id = $1 AND s.minute >= $2 AND s.minute < $3
			GROUP BY s.route, s.method, g.i`, id, from, to)
		if err == nil {
			hists := map[string][]int64{}
			for hrows.Next() {
				var route, method string
				var i int
				var n int64
				if hrows.Scan(&route, &method, &i, &n) == nil && i >= 0 && i < appHistLen {
					k := method + " " + route
					if hists[k] == nil {
						hists[k] = make([]int64, appHistLen)
					}
					hists[k][i] += n
				}
			}
			hrows.Close()
			for k, h := range hists {
				if j, ok := idx[k]; ok {
					var p appREDPoint
					appFinishPoint(&p, h)
					list[j].Stats.P50, list[j].Stats.P95, list[j].Stats.P99, list[j].Stats.OverRange = p.P50, p.P95, p.P99, p.OverRange
				}
			}
		}
		policies := appLoadPayloadPolicies(r, db, id)

		// Routes declared by an API spec: they join an observed route of the same shape, or are listed on their
		// own as "declared, no traffic yet".
		alias := map[string]int{} // "METHOD declared-route" -> row, when the declared template differs from the observed one
		specLoaded := appLoadOpenAPIInfo(r.Context(), idb, id).Loaded
		if specLoaded {
			shapes := map[string]int{}
			for j, x := range list {
				shapes[x.Method+" "+appRouteShape(x.Route)] = j
			}
			if drows, err := idb.QueryContext(r.Context(), `SELECT route, method, declared_at FROM service_declared_routes WHERE service_id = $1 LIMIT 2000`, id); err == nil {
				for drows.Next() {
					var route, method string
					var at time.Time
					if drows.Scan(&route, &method, &at) != nil {
						continue
					}
					if j, ok := idx[method+" "+route]; ok {
						list[j].Declared = true
						continue
					}
					if j, ok := shapes[method+" "+appRouteShape(route)]; ok {
						list[j].Declared = true
						alias[method+" "+route] = j
						continue
					}
					list = append(list, appRouteRow{Route: route, Method: method, FirstSeen: at, LastSeen: at, Declared: true, Params: []appRouteParam{}})
					idx[method+" "+route] = len(list) - 1
				}
				drows.Close()
			}
			for j := range list {
				list[j].NotInSpec = list[j].Observed && !list[j].Declared
			}
		}
		if prows, err := idb.QueryContext(r.Context(), `
			SELECT route, method, name, requests, first_seen, last_seen, source, location FROM service_route_params
			WHERE service_id = $1 ORDER BY requests DESC LIMIT 5000`, id); err == nil {
			byName := map[int]map[string]int{} // route row -> name -> index in its Params
			for prows.Next() {
				var route, method string
				var p appRouteParam
				if prows.Scan(&route, &method, &p.Name, &p.Requests, &p.FirstSeen, &p.LastSeen, &p.Source, &p.Location) != nil {
					continue
				}
				j, ok := idx[method+" "+route]
				if !ok {
					if j, ok = alias[method+" "+route]; !ok {
						continue
					}
				}
				if byName[j] == nil {
					byName[j] = map[string]int{}
				}
				if k, dup := byName[j][p.Name]; dup { // the same name on the declared and the observed template
					q := &list[j].Params[k]
					q.Requests += p.Requests
					if q.Source != p.Source {
						q.Source = "both"
					}
					if q.Location == "" {
						q.Location = p.Location
					}
					continue
				}
				var pol *appPayloadPolicy
				if v, has := policies[list[j].Method+" "+list[j].Route]; has {
					pol = &v
				}
				p.State = appParamState(p.Name, pol)
				byName[j][p.Name] = len(list[j].Params)
				list[j].Params = append(list[j].Params, p)
			}
			prows.Close()
		}
		for j := range list {
			if !list[j].Declared {
				continue
			}
			for k := range list[j].Params {
				list[j].Params[k].Undocumented = list[j].Params[k].Source == "observed"
			}
		}
		for i := range list {
			if len(list[i].Params) == 0 {
				continue
			}
			list[i].PayloadReview = "needs_review"
			if pol, ok := policies[list[i].Method+" "+list[i].Route]; ok {
				pol := pol
				list[i].Policy = &pol
				list[i].PayloadReview = "reviewed"
				for _, p := range list[i].Params {
					if p.State == "new" {
						list[i].PayloadReview = "new_fields"
					}
				}
			}
		}
		appAttachDiagnosis(r.Context(), idb, id, from, to, list, idx)
		sort.SliceStable(list, func(i, j int) bool { return list[i].Stats.Calls > list[j].Stats.Calls })
		writeJSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "routes": list})
	}
}

// appServiceTotals returns RED totals per service for the range (services without
// traffic in the range are absent from the map).
func appServiceTotals(ctx context.Context, idb *store.DB, ids []int64, from, to time.Time) map[int64]appREDTotals {
	out := map[int64]appREDTotals{}
	if len(ids) == 0 {
		return out
	}
	rows, err := idb.QueryContext(ctx, `
		SELECT service_id, SUM(calls), SUM(errors), SUM(status_2xx), SUM(status_401_403), SUM(status_429), SUM(status_5xx)
		FROM app_route_stats WHERE minute >= $1 AND minute < $2 AND service_id = ANY($3)
		GROUP BY service_id`, from, to, pq.Array(ids))
	if err != nil {
		return out
	}
	for rows.Next() {
		var id int64
		var t appREDTotals
		if rows.Scan(&id, &t.Calls, &t.Errors, &t.Status2xx, &t.Status4013, &t.Status429, &t.Status5xx) == nil {
			if t.Calls > 0 {
				t.ErrorRate = float64(t.Errors) / float64(t.Calls)
			}
			out[id] = t
		}
	}
	rows.Close()
	hrows, err := idb.QueryContext(ctx, `
		SELECT s.service_id, g.i, SUM(COALESCE((s.duration_buckets->>g.i)::bigint, 0))
		FROM app_route_stats s CROSS JOIN generate_series(0, 11) AS g(i)
		WHERE s.minute >= $1 AND s.minute < $2 AND s.service_id = ANY($3)
		GROUP BY s.service_id, g.i`, from, to, pq.Array(ids))
	if err != nil {
		return out
	}
	defer hrows.Close()
	hists := map[int64][]int64{}
	for hrows.Next() {
		var id int64
		var i int
		var n int64
		if hrows.Scan(&id, &i, &n) == nil && i >= 0 && i < appHistLen {
			if hists[id] == nil {
				hists[id] = make([]int64, appHistLen)
			}
			hists[id][i] = n
		}
	}
	for id, h := range hists {
		if t, ok := out[id]; ok {
			var p appREDPoint
			appFinishPoint(&p, h)
			t.P50, t.P95, t.P99, t.OverRange = p.P50, p.P95, p.P99, p.OverRange
			out[id] = t
		}
	}
	return out
}

// appLearningCalls returns the requests each service has handled since its learning
// started: since first_seen by default, or since service_settings.learning_started
// when an analyst restarted learning. Retention bounds the history (90 days).
func appLearningCalls(ctx context.Context, idb *store.DB, ids []int64, settings map[int64]appServiceSettings) map[int64]int64 {
	out := map[int64]int64{}
	if len(ids) == 0 {
		return out
	}
	var custom []int64
	for _, id := range ids {
		if s, ok := settings[id]; ok && s.LearningStarted != nil {
			custom = append(custom, id)
		}
	}
	if rows, err := idb.QueryContext(ctx, `
		SELECT s.service_id, SUM(s.calls) FROM app_route_stats s JOIN services v ON v.id = s.service_id
		WHERE s.service_id = ANY($1) AND s.minute >= v.first_seen GROUP BY s.service_id`, pq.Array(ids)); err == nil {
		for rows.Next() {
			var id, n int64
			if rows.Scan(&id, &n) == nil {
				out[id] = n
			}
		}
		rows.Close()
	}
	for _, id := range custom {
		var n int64
		if idb.QueryRowContext(ctx, `SELECT COALESCE(SUM(calls),0) FROM app_route_stats WHERE service_id=$1 AND minute >= $2`,
			id, settings[id].LearningStarted).Scan(&n) == nil {
			out[id] = n
		}
	}
	return out
}
