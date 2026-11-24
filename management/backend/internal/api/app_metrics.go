package api

// app_metrics.go - runtime and pool metrics (APM spec item 3): the read API, the per-instance runtime summary and
// the saturation rule APM-O07. The agent keeps only allowlisted runtime and pool metrics; this file never sees
// anything else.

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

const appMetricMaxSeries = 300

// appMetricAgg is one series of one instance over a window.
type appMetricAgg struct {
	Instance string
	Name     string
	Attr     string
	Unit     string
	Minutes  int
	Avg      float64
	Max      float64
}

// MetricWindow returns per-instance aggregates over [from, to). A missing table means no metrics yet.
func (d appPGData) MetricWindow(ctx context.Context, svcID int64, from, to time.Time) ([]appMetricAgg, error) {
	rows, err := d.idb.QueryContext(ctx, `
		SELECT instance, name, attr, MAX(unit), COUNT(DISTINCT minute), COALESCE(SUM(sum)/NULLIF(SUM(count),0), 0), MAX(max)
		FROM app_metrics WHERE service_id = $1 AND minute >= $2 AND minute < $3
		GROUP BY instance, name, attr LIMIT 5000`, svcID, from, to)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	var out []appMetricAgg
	for rows.Next() {
		var m appMetricAgg
		if rows.Scan(&m.Instance, &m.Name, &m.Attr, &m.Unit, &m.Minutes, &m.Avg, &m.Max) == nil {
			out = append(out, m)
		}
	}
	return out, nil
}

// ── reading attributes and ratios ──────────────────────────────────────────

func appMetricAttrs(a string) map[string]string {
	m := map[string]string{}
	for _, kv := range strings.Split(a, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

// appRuntime is what an instance's runtime looks like over a window. A value of -1 means not reported.
type appRuntime struct {
	CPUPct      float64 `json:"cpu_pct"`
	MemBytes    float64 `json:"mem_bytes"`
	EventLoopMs float64 `json:"eventloop_ms"`
	HeapPct     float64 `json:"heap_pct"`
	PoolPct     float64 `json:"pool_pct"`
	PoolName    string  `json:"pool_name,omitempty"`
	Minutes     int     `json:"minutes"`
}

func appToMs(v float64, unit string) float64 {
	switch unit {
	case "ms":
		return v
	case "us":
		return v / 1000
	case "ns":
		return v * 1e-6
	}
	return v * 1000 // seconds are the OpenTelemetry default
}

// appRuntimeByInstance reduces aggregates to one appRuntime per instance.
func appRuntimeByInstance(aggs []appMetricAgg) map[string]*appRuntime {
	type acc struct {
		cpu, mem, el          float64
		hasCPU, hasMem, hasEL bool
		used, limit           map[string]float64 // heap (by space)
		pu, pl                map[string]float64 // pools
		minutes               int
	}
	by := map[string]*acc{}
	get := func(i string) *acc {
		a := by[i]
		if a == nil {
			a = &acc{used: map[string]float64{}, limit: map[string]float64{}, pu: map[string]float64{}, pl: map[string]float64{}}
			by[i] = a
		}
		return a
	}
	for _, m := range aggs {
		a := get(m.Instance)
		if m.Minutes > a.minutes {
			a.minutes = m.Minutes
		}
		at := appMetricAttrs(m.Attr)
		switch m.Name {
		case "process.cpu.utilization", "jvm.cpu.recent_utilization", "process.runtime.jvm.cpu.utilization":
			a.cpu += m.Avg * 100
			a.hasCPU = true
		case "process.memory.usage", "process.runtime.memory.rss":
			if m.Avg > a.mem {
				a.mem = m.Avg
			}
			a.hasMem = true
		case "nodejs.eventloop.delay.p99":
			a.el, a.hasEL = appToMs(m.Avg, m.Unit), true
		case "v8js.memory.heap.used":
			a.used["v8:"+at["v8js.heap.space.name"]] += m.Avg
		case "v8js.memory.heap.limit":
			a.limit["v8:"+at["v8js.heap.space.name"]] += m.Max
		case "jvm.memory.used":
			if at["jvm.memory.type"] == "heap" {
				a.used["jvm:"+at["jvm.memory.pool.name"]] += m.Avg
			}
		case "jvm.memory.limit":
			if at["jvm.memory.type"] == "heap" {
				a.limit["jvm:"+at["jvm.memory.pool.name"]] += m.Max
			}
		case "db.client.connection.count", "db.client.connections.usage":
			if st := at["state"]; st == "used" || at["db.client.connection.state"] == "used" {
				a.pu[appPoolName(at)] += m.Avg
			}
		case "db.client.connection.max", "db.client.connections.max":
			a.pl[appPoolName(at)] += m.Max
		}
	}
	out := map[string]*appRuntime{}
	for inst, a := range by {
		rt := &appRuntime{CPUPct: -1, MemBytes: -1, EventLoopMs: -1, HeapPct: -1, PoolPct: -1, Minutes: a.minutes}
		if a.hasCPU {
			rt.CPUPct = a.cpu
		}
		if a.hasMem {
			rt.MemBytes = a.mem
		}
		if a.hasEL {
			rt.EventLoopMs = a.el
		}
		var u, l float64
		for k, lim := range a.limit {
			if lim > 0 && a.used[k] > 0 {
				u += a.used[k]
				l += lim
			}
		}
		if l > 0 {
			rt.HeapPct = u / l * 100
		}
		for pool, lim := range a.pl {
			if lim > 0 {
				if p := a.pu[pool] / lim * 100; p > rt.PoolPct {
					rt.PoolPct, rt.PoolName = p, pool
				}
			}
		}
		out[inst] = rt
	}
	return out
}

func appPoolName(at map[string]string) string {
	if n := at["db.client.connection.pool.name"]; n != "" {
		return n
	}
	return at["pool.name"]
}

// ── rule APM-O07 ───────────────────────────────────────────────────────────

// o07: a service instance is saturated: a blocked event loop, a nearly full heap, an exhausted connection pool or a
// pegged CPU, sustained over the window. One finding per instance and kind.
func (r *appRules) o07(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O07", svc)
	if !on || appInMaintenance(svc.Settings, now) {
		return
	}
	win := time.Duration(g.Param("window_min", 10)) * time.Minute
	minMin := int(g.Param("min_minutes", 3))
	aggs, err := r.d.MetricWindow(ctx, svc.ID, now.Add(-win), now.Add(time.Minute))
	if err != nil || len(aggs) == 0 {
		return
	}
	rts := appRuntimeByInstance(aggs)
	insts := make([]string, 0, len(rts))
	for i := range rts {
		insts = append(insts, i)
	}
	sort.Strings(insts)
	for _, inst := range insts {
		rt := rts[inst]
		if rt.Minutes < minMin {
			continue
		}
		type hit struct {
			kind, text string
			sev        int
		}
		var hits []hit
		if th := g.Param("eventloop_ms", 200); rt.EventLoopMs >= th {
			hits = append(hits, hit{"eventloop", fmt.Sprintf("event loop delay p99 is %.0f ms (limit %.0f ms)", rt.EventLoopMs, th), appSevMed})
		}
		if th := g.Param("heap_pct", 90); rt.HeapPct >= th {
			hits = append(hits, hit{"heap", fmt.Sprintf("heap is %.0f%% full (limit %.0f%%)", rt.HeapPct, th), appSevMed})
		}
		if th := g.Param("pool_pct", 95); rt.PoolPct >= th {
			p := rt.PoolName
			if p == "" {
				p = "database"
			}
			hits = append(hits, hit{"pool", fmt.Sprintf("the %s connection pool is %.0f%% in use (limit %.0f%%)", p, rt.PoolPct, th), appSevHigh})
		}
		if th := g.Param("cpu_pct", 90); rt.CPUPct >= th {
			hits = append(hits, hit{"cpu", fmt.Sprintf("CPU is at %.0f%% (limit %.0f%%)", rt.CPUPct, th), appSevMed})
		}
		for _, h := range hits {
			r.fire(ctx, appFinding{RuleID: "APM-O07", Svc: svc, BaseSev: h.sev, Summary: "Runtime saturated",
				Detail:    fmt.Sprintf("Instance %s: %s, sustained for the last %d minutes.%s", inst, h.text, int(win/time.Minute), appNotifyLine(svc)),
				EventType: "app.alert", Time: now, DedupKey: fmt.Sprintf("%d:%s:%s", svc.ID, inst, h.kind)})
		}
	}
}

// appAttachRuntime sets Runtime on each instance from the last five minutes of metrics.
func appAttachRuntime(ctx context.Context, idb *store.DB, id int64, now time.Time) map[string]*appRuntime {
	aggs, _ := appPGData{idb: idb}.MetricWindow(ctx, id, now.Add(-5*time.Minute), now.Add(time.Minute))
	return appRuntimeByInstance(aggs)
}

// ── API ────────────────────────────────────────────────────────────────────

type appMetricPoint struct {
	T    time.Time `json:"t"`
	Avg  float64   `json:"avg"`
	Min  float64   `json:"min"`
	Max  float64   `json:"max"`
	Last float64   `json:"last"`
}

type appMetricSeries struct {
	Attr   string           `json:"attr"`
	Points []appMetricPoint `json:"points"`
}

type appMetricCatalogRow struct {
	Name      string  `json:"name"`
	Attr      string  `json:"attr"`
	Unit      string  `json:"unit"`
	Instances int     `json:"instances"`
	Avg       float64 `json:"avg"`
	Min       float64 `json:"min"`
	Max       float64 `json:"max"`
	Last      float64 `json:"last"`
}

// appHandleMetrics serves GET /services/{id}/metrics. Without name it lists the series reported in the range with
// their latest value; with name it returns the points, bucketed by step (minutes), optionally for one instance.
func appHandleMetrics(db, backendDB *store.DB) http.HandlerFunc {
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
		q := r.URL.Query()
		name, inst := q.Get("name"), q.Get("instance")
		if len(name) > 96 || len(inst) > 128 || (name != "" && !appMetricNameKnown(name)) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown metric"})
			return
		}
		if name == "" {
			appMetricCatalog(w, r, idb, id, from, to, inst)
			return
		}
		step := int(math.Ceil(to.Sub(from).Minutes() / 120))
		if s, err := strconv.Atoi(q.Get("step")); err == nil && s >= 1 && s <= 1440 {
			step = s
		}
		if step < 1 {
			step = 1
		}
		args := []any{id, name, from, to, step}
		instClause := ""
		if inst != "" {
			args = append(args, inst)
			instClause = ` AND instance = $6`
		}
		rows, err := idb.QueryContext(r.Context(), `
			SELECT to_timestamp(floor(extract(epoch FROM minute) / ($5::int * 60)) * $5::int * 60) AS b, attr, MAX(unit),
			  COALESCE(SUM(sum)/NULLIF(SUM(count),0), 0), MIN(min), MAX(max), AVG(last)
			FROM app_metrics WHERE service_id = $1 AND name = $2 AND minute >= $3 AND minute < $4`+instClause+`
			GROUP BY b, attr ORDER BY attr, b LIMIT 20000`, args...)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		defer rows.Close()
		var series []appMetricSeries
		unit := ""
		for rows.Next() {
			var t time.Time
			var attr, u string
			var p appMetricPoint
			if rows.Scan(&t, &attr, &u, &p.Avg, &p.Min, &p.Max, &p.Last) != nil {
				continue
			}
			p.T, unit = t.UTC(), u
			if n := len(series); n == 0 || series[n-1].Attr != attr {
				series = append(series, appMetricSeries{Attr: attr})
			}
			s := &series[len(series)-1]
			s.Points = append(s.Points, p)
		}
		if series == nil {
			series = []appMetricSeries{}
		}
		insts := []string{}
		if irows, err := idb.QueryContext(r.Context(), `SELECT DISTINCT instance FROM app_metrics WHERE service_id = $1 AND name = $2 AND minute >= $3 AND minute < $4 ORDER BY instance LIMIT 100`, id, name, from, to); err == nil {
			for irows.Next() {
				var s string
				if irows.Scan(&s) == nil {
					insts = append(insts, s)
				}
			}
			irows.Close()
		}
		writeJSON(w, http.StatusOK, map[string]any{"name": name, "unit": unit, "step_min": step, "series": series, "instances": insts})
	}
}

func appMetricNameKnown(n string) bool {
	for _, p := range []string{"process.cpu.", "process.memory.", "process.runtime.", "process.uptime", "v8js.", "nodejs.", "jvm.", "dotnet.",
		"db.client.connections.", "db.client.connection.", "http.server.active_requests"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func appMetricCatalog(w http.ResponseWriter, r *http.Request, idb *store.DB, id int64, from, to time.Time, inst string) {
	args := []any{id, from, to}
	ic := ""
	if inst != "" {
		args = append(args, inst)
		ic = ` AND instance = $4`
	}
	rows, err := idb.QueryContext(r.Context(), `
		SELECT name, attr, MAX(unit), COUNT(DISTINCT instance), COALESCE(SUM(sum)/NULLIF(SUM(count),0), 0), MIN(min), MAX(max)
		FROM app_metrics WHERE service_id = $1 AND minute >= $2 AND minute < $3`+ic+`
		GROUP BY name, attr ORDER BY name, attr LIMIT `+strconv.Itoa(appMetricMaxSeries), args...)
	if err != nil {
		appQueryFailed(w, r.URL.Path, id, err)
		return
	}
	list := []appMetricCatalogRow{}
	idx := map[[2]string]int{}
	for rows.Next() {
		var c appMetricCatalogRow
		if rows.Scan(&c.Name, &c.Attr, &c.Unit, &c.Instances, &c.Avg, &c.Min, &c.Max) == nil {
			idx[[2]string{c.Name, c.Attr}] = len(list)
			list = append(list, c)
		}
	}
	rows.Close()
	lrows, err := idb.QueryContext(r.Context(), `
		SELECT m.name, m.attr, AVG(m.last) FROM app_metrics m
		WHERE m.service_id = $1 AND m.minute >= $2 AND m.minute < $3`+strings.ReplaceAll(ic, "instance", "m.instance")+`
		  AND m.minute = (SELECT MAX(x.minute) FROM app_metrics x WHERE x.service_id = $1 AND x.minute >= $2 AND x.minute < $3
		                  AND x.name = m.name AND x.attr = m.attr`+strings.ReplaceAll(ic, "instance", "x.instance")+`)
		GROUP BY m.name, m.attr`, args...)
	if err == nil {
		for lrows.Next() {
			var n, a string
			var v float64
			if lrows.Scan(&n, &a, &v) == nil {
				if i, ok := idx[[2]string{n, a}]; ok {
					list[i].Last = v
				}
			}
		}
		lrows.Close()
	}
	writeJSON(w, http.StatusOK, map[string]any{"metrics": list})
}
