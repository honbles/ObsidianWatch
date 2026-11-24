package api

// app_slowquery.go - APM-O06: a database call became much slower than it was. The current window's average time per
// call is compared with the previous day's, per operation, table and (when the service sends them) fingerprint.

import (
	"context"
	"fmt"
	"time"
)

type appQueryAgg struct {
	System, Operation, Table, Fingerprint string
	Calls                                 int64
	TotalMs                               float64
}

func (q appQueryAgg) label() string {
	l := q.Operation
	if l == "" {
		l = "query"
	}
	if q.Table != "" {
		l += " on " + q.Table
	}
	if q.System != "" {
		l += " (" + q.System + ")"
	}
	return l
}

// QueryWindow returns database call totals over [from, to). A missing table means nothing to compare.
func (d appPGData) QueryWindow(ctx context.Context, svcID int64, from, to time.Time) ([]appQueryAgg, error) {
	rows, err := d.idb.QueryContext(ctx, `
		SELECT system, operation, tbl, fingerprint, SUM(calls), SUM(total_ms)
		FROM app_db_stats WHERE service_id = $1 AND minute >= $2 AND minute < $3
		GROUP BY system, operation, tbl, fingerprint LIMIT 2000`, svcID, from, to)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()
	var out []appQueryAgg
	for rows.Next() {
		var q appQueryAgg
		if rows.Scan(&q.System, &q.Operation, &q.Table, &q.Fingerprint, &q.Calls, &q.TotalMs) == nil {
			out = append(out, q)
		}
	}
	return out, nil
}

func (r *appRules) o06(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O06", svc)
	if !on || appInMaintenance(svc.Settings, now) {
		return
	}
	if now.Sub(appLearningStart(svc)) < 24*time.Hour {
		appSkip("APM-O06", "learning")
		return
	}
	win := time.Duration(g.Param("window_min", 30)) * time.Minute
	factor := g.Param("factor", 2)
	minCalls := int64(g.Param("min_calls", 50))
	minDelta := g.Param("min_delta_ms", 20)
	cur, err := r.d.QueryWindow(ctx, svc.ID, now.Add(-win), now.Add(time.Minute))
	if err != nil || len(cur) == 0 {
		return
	}
	base, err := r.d.QueryWindow(ctx, svc.ID, now.Add(-win-24*time.Hour), now.Add(-win))
	if err != nil {
		return
	}
	key := func(q appQueryAgg) [4]string { return [4]string{q.System, q.Operation, q.Table, q.Fingerprint} }
	bm := map[[4]string]appQueryAgg{}
	for _, b := range base {
		bm[key(b)] = b
	}
	for _, c := range cur {
		b, ok := bm[key(c)]
		if !ok || c.Calls < minCalls || b.Calls < minCalls {
			continue
		}
		ca, ba := c.TotalMs/float64(c.Calls), b.TotalMs/float64(b.Calls)
		if ba <= 0 || ca < ba*factor || ca-ba < minDelta {
			continue
		}
		r.fire(ctx, appFinding{RuleID: "APM-O06", Svc: svc, BaseSev: appSevMed, Summary: "Database call slowed down",
			Detail: fmt.Sprintf("%s averages %.0f ms per call now, against %.0f ms over the previous day (%d calls in the last %d minutes).%s",
				c.label(), ca, ba, c.Calls, int(win/time.Minute), appNotifyLine(svc)),
			EventType: "app.alert", Time: now, DedupKey: fmt.Sprintf("%d:%s:%s:%s:%s", svc.ID, c.System, c.Operation, c.Table, c.Fingerprint)})
	}
}
