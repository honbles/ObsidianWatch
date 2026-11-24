package api

// app_operations.go - jobs and message consumers (APM spec item 7): the list API and the rules APM-O10 (a job
// stopped running) and APM-O11 (a job or consumer fails often). The agent aggregates by name only.

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"

	"obsidianwatch/management/internal/store"
)

type appOpAgg struct {
	Kind, Name     string
	Runs, Failures int64
}

type appJobHistory struct {
	Name    string
	Minutes []time.Time // distinct minutes with at least one run, ascending
	LastRun time.Time
}

// OperationWindow returns runs and failures per operation over [from, to). A missing table means none.
func (d appPGData) OperationWindow(ctx context.Context, svcID int64, from, to time.Time) ([]appOpAgg, error) {
	rows, err := d.idb.QueryContext(ctx, `SELECT kind, name, SUM(runs), SUM(failures) FROM app_operations
		WHERE service_id = $1 AND minute >= $2 AND minute < $3 GROUP BY kind, name LIMIT 1000`, svcID, from, to)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	var out []appOpAgg
	for rows.Next() {
		var o appOpAgg
		if rows.Scan(&o.Kind, &o.Name, &o.Runs, &o.Failures) == nil {
			out = append(out, o)
		}
	}
	return out, nil
}

// JobHistory returns the minutes each job ran in since, for learning its cadence.
func (d appPGData) JobHistory(ctx context.Context, svcID int64, since time.Time) ([]appJobHistory, error) {
	rows, err := d.idb.QueryContext(ctx, `SELECT name, minute, last_run FROM app_operations
		WHERE service_id = $1 AND kind = 'job' AND minute >= $2 ORDER BY name, minute LIMIT 50000`, svcID, since)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	var out []appJobHistory
	for rows.Next() {
		var n string
		var m, l time.Time
		if rows.Scan(&n, &m, &l) != nil {
			continue
		}
		if len(out) == 0 || out[len(out)-1].Name != n {
			out = append(out, appJobHistory{Name: n})
		}
		h := &out[len(out)-1]
		h.Minutes = append(h.Minutes, m)
		if l.After(h.LastRun) {
			h.LastRun = l
		}
	}
	return out, nil
}

// appMedianGap is the median spacing of runs. It is at least a minute, the resolution of the data.
func appMedianGap(mins []time.Time) time.Duration {
	if len(mins) < 2 {
		return 0
	}
	gaps := make([]time.Duration, 0, len(mins)-1)
	for i := 1; i < len(mins); i++ {
		gaps = append(gaps, mins[i].Sub(mins[i-1]))
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	g := gaps[len(gaps)/2]
	if g < time.Minute {
		g = time.Minute
	}
	return g
}

// o10: a job that ran on a steady cadence has not run for several of its usual intervals.
func (r *appRules) o10(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O10", svc)
	if !on || appInMaintenance(svc.Settings, now) {
		return
	}
	mult := g.Param("interval_multiple", 3)
	minRuns := int(g.Param("min_runs", 5))
	minLate := time.Duration(g.Param("min_late_min", 5)) * time.Minute
	maxAge := time.Duration(g.Param("max_age_days", 7)) * 24 * time.Hour
	jobs, err := r.d.JobHistory(ctx, svc.ID, now.Add(-14*24*time.Hour))
	if err != nil {
		return
	}
	for _, j := range jobs {
		if len(j.Minutes) < minRuns {
			continue
		}
		gap := appMedianGap(j.Minutes)
		late := now.Sub(j.LastRun)
		if gap <= 0 || late < time.Duration(mult*float64(gap)) || late < minLate || late > maxAge {
			continue
		}
		r.fire(ctx, appFinding{RuleID: "APM-O10", Svc: svc, BaseSev: appSevMed, Summary: "Job has stopped running",
			Detail: fmt.Sprintf("%s usually runs about every %s and has not run for %s (last run %s).%s", j.Name, appDur(gap), appDur(late),
				j.LastRun.UTC().Format("2006-01-02 15:04 UTC"), appNotifyLine(svc)),
			EventType: "app.alert", Time: now, DedupKey: fmt.Sprintf("%d:%s", svc.ID, j.Name)})
	}
}

// o11: a job or consumer fails a large share of its runs.
func (r *appRules) o11(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O11", svc)
	if !on || appInMaintenance(svc.Settings, now) {
		return
	}
	win := time.Duration(g.Param("window_min", 30)) * time.Minute
	rate := g.Param("rate_pct", 25) / 100
	minRuns := int64(g.Param("min_runs", 5))
	ops, err := r.d.OperationWindow(ctx, svc.ID, now.Add(-win), now.Add(time.Minute))
	if err != nil {
		return
	}
	for _, o := range ops {
		if o.Runs < minRuns || float64(o.Failures)/float64(o.Runs) < rate {
			continue
		}
		r.fire(ctx, appFinding{RuleID: "APM-O11", Svc: svc, BaseSev: appSevMed, Summary: "Job failing",
			Detail:    fmt.Sprintf("%s %q failed %d of %d runs in the last %d minutes.%s", o.Kind, o.Name, o.Failures, o.Runs, int(win/time.Minute), appNotifyLine(svc)),
			EventType: "app.alert", Time: now, DedupKey: fmt.Sprintf("%d:%s:%s", svc.ID, o.Kind, o.Name)})
	}
}

func appDur(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
}

// ── API ────────────────────────────────────────────────────────────────────

type appOperationRow struct {
	Kind        string    `json:"kind"`
	Name        string    `json:"name"`
	Runs        int64     `json:"runs"`
	Failures    int64     `json:"failures"`
	FailureRate float64   `json:"failure_rate"`
	AvgMs       float64   `json:"avg_ms,omitempty"`
	P50Ms       float64   `json:"p50_ms"`
	P95Ms       float64   `json:"p95_ms"`
	OverRange   bool      `json:"over_range,omitempty"`
	LastRun     time.Time `json:"last_run"`
	EveryMin    float64   `json:"usual_interval_min,omitempty"` // jobs only: the learned cadence
}

// appHandleOperations serves GET /services/{id}/operations: jobs and consumers with runs, failures, latency and last run.
func appHandleOperations(db, backendDB *store.DB) http.HandlerFunc {
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
			SELECT kind, name, SUM(runs), SUM(failures), MAX(last_run) FROM app_operations
			WHERE service_id = $1 AND minute >= $2 AND minute < $3 GROUP BY kind, name ORDER BY SUM(runs) DESC LIMIT 500`, id, from, to)
		list := []appOperationRow{}
		idx := map[[2]string]int{}
		if err == nil { // a missing table means no operations yet
			for rows.Next() {
				var o appOperationRow
				if rows.Scan(&o.Kind, &o.Name, &o.Runs, &o.Failures, &o.LastRun) == nil {
					if o.Runs > 0 {
						o.FailureRate = float64(o.Failures) / float64(o.Runs)
					}
					idx[[2]string{o.Kind, o.Name}] = len(list)
					list = append(list, o)
				}
			}
			rows.Close()
			hrows, err := idb.QueryContext(r.Context(), `
				SELECT s.kind, s.name, g.i, SUM(COALESCE((s.duration_buckets->>g.i)::bigint, 0))
				FROM app_operations s CROSS JOIN generate_series(0, 11) AS g(i)
				WHERE s.service_id = $1 AND s.minute >= $2 AND s.minute < $3 GROUP BY s.kind, s.name, g.i`, id, from, to)
			if err == nil {
				hist := map[int]*[12]int64{}
				for hrows.Next() {
					var k, n string
					var bi int
					var c int64
					if hrows.Scan(&k, &n, &bi, &c) == nil && bi >= 0 && bi < 12 {
						if i, ok := idx[[2]string{k, n}]; ok {
							if hist[i] == nil {
								hist[i] = &[12]int64{}
							}
							hist[i][bi] += c
						}
					}
				}
				hrows.Close()
				for i, h := range hist {
					list[i].P50Ms, _ = appPercentile(h[:], 0.5)
					list[i].P95Ms, list[i].OverRange = appPercentile(h[:], 0.95)
				}
			}
			if jobs, _ := (appPGData{idb: idb}).JobHistory(r.Context(), id, time.Now().Add(-14*24*time.Hour)); len(jobs) > 0 {
				for _, j := range jobs {
					if i, ok := idx[[2]string{"job", j.Name}]; ok && len(j.Minutes) >= 5 {
						list[i].EveryMin = appMedianGap(j.Minutes).Minutes()
					}
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"operations": list})
	}
}
