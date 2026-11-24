package api

// app_slo.go - service level objectives (APM spec item 15): the SLO figures, remaining error budget and projected
// exhaustion for the SLO page, and the multi-window burn-rate rule APM-O13. Availability counts requests that did
// not fail (the error count the statistics already keep); latency counts requests at or under the service's
// latency target, read from the latency histogram with linear interpolation inside a bucket.

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"obsidianwatch/management/internal/store"
)

// appSLO is a service's objective. Zero values mean the defaults.
type appSLO struct {
	WindowDays      int      `json:"window_days,omitempty"` // 7 or 28
	AvailabilityPct *float64 `json:"availability_target_pct,omitempty"`
	LatencyPct      *float64 `json:"latency_target_pct,omitempty"`
}

type appSLOResolved struct {
	WindowDays      int
	AvailabilityPct float64
	LatencyPct      float64
	LatencyTargetMs int // 0: no latency SLO
}

func appResolveSLO(s appServiceSettings) appSLOResolved {
	r := appSLOResolved{WindowDays: 28, AvailabilityPct: 99.9, LatencyPct: 95}
	if s.ErrorBudgetPct != nil {
		r.AvailabilityPct = 100 - *s.ErrorBudgetPct
	}
	if s.SLO.WindowDays == 7 || s.SLO.WindowDays == 28 {
		r.WindowDays = s.SLO.WindowDays
	}
	if s.SLO.AvailabilityPct != nil {
		r.AvailabilityPct = *s.SLO.AvailabilityPct
	}
	if s.SLO.LatencyPct != nil {
		r.LatencyPct = *s.SLO.LatencyPct
	}
	if s.LatencyTargetMs != nil && *s.LatencyTargetMs > 0 {
		r.LatencyTargetMs = *s.LatencyTargetMs
	}
	return r
}

func appValidSLO(o appSLO) string {
	switch {
	case o.WindowDays != 0 && o.WindowDays != 7 && o.WindowDays != 28:
		return "slo window_days must be 7 or 28"
	case o.AvailabilityPct != nil && (*o.AvailabilityPct <= 0 || *o.AvailabilityPct >= 100):
		return "slo availability_target_pct must be above 0 and below 100"
	case o.LatencyPct != nil && (*o.LatencyPct <= 0 || *o.LatencyPct >= 100):
		return "slo latency_target_pct must be above 0 and below 100"
	}
	return ""
}

type appSLICounts struct {
	Calls, Errors int64
	Slow          float64 // requests over the latency target (an estimate from the histogram)
}

// appSlowFraction estimates how many of a histogram's requests took longer than target.
func appSlowOf(h []int64, target float64) float64 {
	var slow float64
	for i, n := range h {
		if n == 0 {
			continue
		}
		lo, hi := 0.0, math.Inf(1)
		if i > 0 && i-1 < len(appDurBounds) {
			lo = appDurBounds[i-1]
		}
		if i < len(appDurBounds) {
			hi = appDurBounds[i]
		}
		switch {
		case target <= lo:
			slow += float64(n)
		case target >= hi && !math.IsInf(hi, 1):
		case math.IsInf(hi, 1):
			slow += float64(n)
		default:
			slow += float64(n) * (hi - target) / (hi - lo)
		}
	}
	return slow
}

// SLICounts reads calls, errors and the estimated slow count over [from, to).
func (d appPGData) SLICounts(ctx context.Context, svcID int64, from, to time.Time, targetMs int) (appSLICounts, error) {
	var c appSLICounts
	if err := d.idb.QueryRowContext(ctx, `SELECT COALESCE(SUM(calls),0), COALESCE(SUM(errors),0) FROM app_route_stats
		WHERE service_id = $1 AND minute >= $2 AND minute < $3`, svcID, from, to).Scan(&c.Calls, &c.Errors); err != nil {
		return c, err
	}
	if targetMs > 0 && c.Calls > 0 {
		rows, err := d.idb.QueryContext(ctx, `
			SELECT g.i, SUM(COALESCE((s.duration_buckets->>g.i)::bigint, 0))
			FROM app_route_stats s CROSS JOIN generate_series(0, 11) AS g(i)
			WHERE s.service_id = $1 AND s.minute >= $2 AND s.minute < $3 GROUP BY g.i ORDER BY g.i`, svcID, from, to)
		if err != nil {
			return c, err
		}
		defer rows.Close()
		h := make([]int64, 12)
		for rows.Next() {
			var i int
			var n int64
			if rows.Scan(&i, &n) == nil && i >= 0 && i < 12 {
				h[i] = n
			}
		}
		c.Slow = appSlowOf(h, float64(targetMs))
	}
	return c, nil
}

// ── burn rate rule ─────────────────────────────────────────────────────────

func appBurn(bad, calls float64, budget float64) float64 {
	if calls <= 0 || budget <= 0 {
		return 0
	}
	return bad / calls / budget
}

// o13: the error budget is being spent far faster than the objective allows, over a long and a short window at
// once (so a spike that has already ended does not alert). Fast: 14.4x over 1 h and 5 min. Slow: 6x over 6 h and 30 min.
func (r *appRules) o13(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O13", svc)
	if !on || appInMaintenance(svc.Settings, now) {
		return
	}
	if now.Sub(appLearningStart(svc)) < 24*time.Hour {
		appSkip("APM-O13", "learning")
		return
	}
	slo := appResolveSLO(svc.Settings)
	minCalls := int64(g.Param("min_calls", 100))
	type win struct {
		name        string
		long, short time.Duration
		factor      float64
		sev         int
	}
	wins := []win{
		{"fast", time.Hour, 5 * time.Minute, g.Param("fast_factor", 14.4), appSevHigh},
		{"slow", 6 * time.Hour, 30 * time.Minute, g.Param("slow_factor", 6), appSevMed},
	}
	to := now.Add(-appRecentLag)
	type sli struct {
		name   string
		budget float64
		bad    func(c appSLICounts) float64
		target int
	}
	slis := []sli{{"availability", (100 - slo.AvailabilityPct) / 100, func(c appSLICounts) float64 { return float64(c.Errors) }, 0}}
	if slo.LatencyTargetMs > 0 {
		slis = append(slis, sli{"latency", (100 - slo.LatencyPct) / 100, func(c appSLICounts) float64 { return c.Slow }, slo.LatencyTargetMs})
	}
	for _, s := range slis {
		for _, w := range wins {
			long, err := r.d.SLICounts(ctx, svc.ID, to.Add(-w.long), to, s.target)
			if err != nil || long.Calls < minCalls {
				continue
			}
			short, err := r.d.SLICounts(ctx, svc.ID, to.Add(-w.short), to, s.target)
			if err != nil || short.Calls == 0 {
				continue
			}
			bl, bs := appBurn(s.bad(long), float64(long.Calls), s.budget), appBurn(s.bad(short), float64(short.Calls), s.budget)
			if bl < w.factor || bs < w.factor {
				continue
			}
			// the share of the whole window's budget this long window has used
			used := bl * w.long.Hours() / float64(slo.WindowDays*24) * 100
			what := "requests failed"
			if s.name == "latency" {
				what = fmt.Sprintf("requests slower than %d ms", slo.LatencyTargetMs)
			}
			r.fire(ctx, appFinding{RuleID: "APM-O13", Svc: svc, BaseSev: w.sev, Summary: "Error budget burning fast",
				Detail: fmt.Sprintf("%s objective (%.2f%% over %d days): %s at %.1fx the allowed rate over the last %s and %.1fx over the last %s, about %.1f%% of the window's budget used in %s.%s",
					s.name, map[string]float64{"availability": slo.AvailabilityPct, "latency": slo.LatencyPct}[s.name], slo.WindowDays, what, bl, appDur(w.long), bs, appDur(w.short), used, appDur(w.long), appNotifyLine(svc)),
				EventType: "app.alert", Time: now, DedupKey: fmt.Sprintf("%d:%s:%s", svc.ID, s.name, w.name)})
			break // the fast window already says it; do not also fire the slow one for the same objective
		}
	}
}

// ── API ────────────────────────────────────────────────────────────────────

type appSLOStatus struct {
	Name            string     `json:"name"` // availability | latency
	TargetPct       float64    `json:"target_pct"`
	LatencyTargetMs int        `json:"latency_target_ms,omitempty"`
	SLIPct          float64    `json:"sli_pct"`
	Calls           int64      `json:"calls"`
	Bad             float64    `json:"bad"`
	BudgetBad       float64    `json:"budget_bad"` // the number of bad requests the window allows
	RemainingPct    float64    `json:"budget_remaining_pct"`
	Burn1h          float64    `json:"burn_1h"`
	Burn6h          float64    `json:"burn_6h"`
	ExhaustsAt      *time.Time `json:"exhausts_at,omitempty"`
}

// appHandleSLO serves GET /services/{id}/slo.
func appHandleSLO(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		st, ok := appSettingsByID(r.Context(), db, []int64{id})[id]
		if !ok {
			st = appDefaultSettings()
		}
		slo := appResolveSLO(st)
		now := time.Now().UTC()
		d := appPGData{idb: idb}
		win := time.Duration(slo.WindowDays) * 24 * time.Hour
		type spec struct {
			name   string
			target float64
			ms     int
			bad    func(c appSLICounts) float64
		}
		specs := []spec{{"availability", slo.AvailabilityPct, 0, func(c appSLICounts) float64 { return float64(c.Errors) }}}
		if slo.LatencyTargetMs > 0 {
			specs = append(specs, spec{"latency", slo.LatencyPct, slo.LatencyTargetMs, func(c appSLICounts) float64 { return c.Slow }})
		}
		out := []appSLOStatus{}
		for _, sp := range specs {
			full, err := d.SLICounts(r.Context(), id, now.Add(-win), now.Add(time.Minute), sp.ms)
			if err != nil {
				appQueryFailed(w, r.URL.Path, id, err)
				return
			}
			s := appSLOStatus{Name: sp.name, TargetPct: sp.target, LatencyTargetMs: sp.ms, Calls: full.Calls, Bad: sp.bad(full), SLIPct: 100, RemainingPct: 100}
			budget := (100 - sp.target) / 100
			if full.Calls > 0 {
				s.SLIPct = (1 - s.Bad/float64(full.Calls)) * 100
				s.BudgetBad = float64(full.Calls) * budget
				if s.BudgetBad > 0 {
					s.RemainingPct = (1 - s.Bad/s.BudgetBad) * 100
				}
			}
			for _, h := range []struct {
				d   time.Duration
				dst *float64
			}{{time.Hour, &s.Burn1h}, {6 * time.Hour, &s.Burn6h}} {
				if c, err := d.SLICounts(r.Context(), id, now.Add(-h.d), now.Add(time.Minute), sp.ms); err == nil {
					*h.dst = appBurn(sp.bad(c), float64(c.Calls), budget)
				}
			}
			// Projected exhaustion: at the last 24 hours' pace of spending, when does the remaining budget run out?
			if c24, err := d.SLICounts(r.Context(), id, now.Add(-24*time.Hour), now.Add(time.Minute), sp.ms); err == nil && s.BudgetBad > 0 && s.RemainingPct > 0 {
				perHour := sp.bad(c24) / 24
				if perHour > 0 {
					left := s.BudgetBad - s.Bad
					t := now.Add(time.Duration(left / perHour * float64(time.Hour)))
					if t.Before(now.Add(win)) { // beyond a window it would renew before running out
						s.ExhaustsAt = &t
					}
				}
			}
			out = append(out, s)
		}
		writeJSON(w, http.StatusOK, map[string]any{"window_days": slo.WindowDays, "slos": out})
	}
}
