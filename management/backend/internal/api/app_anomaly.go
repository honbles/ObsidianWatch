package api

// app_anomaly.go - seasonal baselines (APM spec item 15.3). The same window one, two, three and four weeks ago
// gives a baseline that follows the weekly pattern. APM-O03 uses it for the expected traffic when at least three
// weeks of history exist (otherwise it falls back to the previous day), and APM-O14 alerts when error rate,
// latency or traffic is far outside what that hour of the week usually looks like.

import (
	"context"
	"fmt"
	"sort"
	"time"
)

const (
	appSeasonWeeks    = 4
	appSeasonMinWeeks = 3
)

// seasonalTotals returns the totals of the same window in each of the previous weeks that had traffic.
func (r *appRules) seasonalTotals(ctx context.Context, svc appSvc, from, to time.Time, minCalls int64) []appWindowTotals {
	if to.Sub(appLearningStart(svc)) < (appSeasonMinWeeks*7+1)*24*time.Hour {
		return nil // not enough history yet
	}
	var out []appWindowTotals
	for k := 1; k <= appSeasonWeeks; k++ {
		off := time.Duration(k) * 7 * 24 * time.Hour
		t, err := r.d.WindowTotals(ctx, svc.ID, from.Add(-off), to.Add(-off))
		if err == nil && t.Calls >= minCalls {
			out = append(out, t)
		}
	}
	if len(out) < appSeasonMinWeeks {
		return nil
	}
	return out
}

func appMedian(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// o14: error rate, latency or traffic is outside the seasonal band for a sustained window.
func (r *appRules) o14(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O14", svc)
	if !on || appInMaintenance(svc.Settings, now) {
		return
	}
	win := time.Duration(g.Param("window_min", 10)) * time.Minute
	minCalls := int64(g.Param("min_calls", 100))
	to := now.Add(-appRecentLag)
	from := to.Add(-win)
	cur, err := r.d.WindowTotals(ctx, svc.ID, from, to)
	if err != nil || cur.Calls < minCalls {
		return
	}
	hist := r.seasonalTotals(ctx, svc, from, to, minCalls)
	if hist == nil {
		appSkip("APM-O14", "learning")
		return
	}
	var rates, p95s, calls []float64
	for _, h := range hist {
		rates = append(rates, float64(h.Errors)/float64(h.Calls))
		p95s = append(p95s, h.P95Ms)
		calls = append(calls, float64(h.Calls))
	}
	mr, mp, mc := appMedian(rates), appMedian(p95s), appMedian(calls)
	hour := now.UTC().Format("2006010215")
	fire := func(kind, summary, detail string) {
		r.fire(ctx, appFinding{RuleID: "APM-O14", Svc: svc, BaseSev: appSevMed, Summary: summary,
			Detail:    detail + " " + fmt.Sprintf("The usual figure is the median of the same %d minutes in each of the last %d weeks.", int(win.Minutes()), len(hist)) + appNotifyLine(svc),
			EventType: "app.alert", Time: now, DedupKey: fmt.Sprintf("%d:%s:%s", svc.ID, kind, hour)})
	}
	if cr := float64(cur.Errors) / float64(cur.Calls); cr >= mr*g.Param("error_factor", 3) && cr-mr >= g.Param("error_delta_pct", 2)/100 {
		fire("errors", "Error rate unusual for this time of week", fmt.Sprintf("Error rate is %.1f%% against a usual %.1f%%.", cr*100, mr*100))
	}
	if mp > 0 && cur.P95Ms >= mp*g.Param("p95_factor", 2) && cur.P95Ms-mp >= g.Param("p95_delta_ms", 100) {
		fire("latency", "Latency unusual for this time of week", fmt.Sprintf("p95 is %.0f ms against a usual %.0f ms.", cur.P95Ms, mp))
	}
	if mc >= g.Param("min_baseline", 100) && float64(cur.Calls) >= mc*g.Param("spike_factor", 4) {
		fire("traffic", "Traffic spike for this time of week", fmt.Sprintf("%d requests against a usual %.0f.", cur.Calls, mc))
	}
}
