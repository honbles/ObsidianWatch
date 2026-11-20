package api

// app_rules_ops.go - operational rules O01, O03, O05 (APM family, not weighted by exposure) and the
// cross-layer rule X06, plus the scan driver that runs every data-driven rule.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// appInMaintenance reports whether now falls inside one of the service's maintenance windows.
func appInMaintenance(st appServiceSettings, now time.Time) bool {
	for _, m := range st.Maintenance {
		if !now.Before(m.Start) && now.Before(m.End) {
			return true
		}
	}
	return false
}

// appRecentLag is how far behind real time statistics are: the agent only sends closed minutes
// every 30 seconds, so the newest two minutes are incomplete and are never judged.
const appRecentLag = 2 * time.Minute

func appNotifyLine(svc appSvc) string {
	if svc.Settings.NotifyRoute != "" {
		return "\nNotification route: " + svc.Settings.NotifyRoute
	}
	return ""
}

// ── O01: error rate above budget ───────────────────────────────────────────

func (r *appRules) o01(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O01", svc)
	if !on || appInMaintenance(svc.Settings, now) {
		return
	}
	win := time.Duration(g.Param("window_min", 10)) * time.Minute
	to := now.Add(-appRecentLag)
	stats, err := r.d.RouteWindow(ctx, svc.ID, to.Add(-win), to)
	if err != nil {
		return
	}
	budget := g.Param("default_budget_pct", 5)
	if svc.Settings.ErrorBudgetPct != nil {
		budget = *svc.Settings.ErrorBudgetPct
	}
	minCalls := int64(g.Param("min_calls", 50))
	var calls, errs int64
	for _, s := range stats {
		calls += s.Calls
		errs += s.Errors
	}
	hour := now.UTC().Format("2006010215")
	rate := func(e, c int64) float64 { return float64(e) / float64(c) * 100 }
	if calls >= minCalls && rate(errs, calls) > budget {
		r.fire(ctx, appFinding{RuleID: "APM-O01", Svc: svc, BaseSev: appSevHigh, Summary: "Error rate above budget",
			Detail: fmt.Sprintf("%.1f%% of %d requests failed in the last %d minutes; the service's error budget is %.1f%%.%s",
				rate(errs, calls), calls, int(win.Minutes()), budget, appNotifyLine(svc)),
			EventType: "app.alert", Time: now, DedupKey: fmt.Sprintf("%d:all:%s", svc.ID, hour)})
		return // the service-level alert covers its routes
	}
	for _, s := range stats {
		if s.Calls >= minCalls && rate(s.Errors, s.Calls) > budget {
			r.fire(ctx, appFinding{RuleID: "APM-O01", Svc: svc, BaseSev: appSevHigh, Summary: "Route error rate above budget",
				Detail: fmt.Sprintf("%.1f%% of %d requests to %s %s failed in the last %d minutes; the error budget is %.1f%%.%s",
					rate(s.Errors, s.Calls), s.Calls, s.Method, s.Route, int(win.Minutes()), budget, appNotifyLine(svc)),
				Route: s.Route, Method: s.Method, EventType: "app.alert", Time: now,
				DedupKey: fmt.Sprintf("%d:%s %s:%s", svc.ID, s.Method, s.Route, hour)})
		}
	}
}

// ── O03: traffic drop ──────────────────────────────────────────────────────

func (r *appRules) o03(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O03", svc)
	if !on || appInMaintenance(svc.Settings, now) {
		return
	}
	reqs, err := r.d.Requests(ctx, svc)
	if err != nil {
		return
	}
	if now.Sub(appLearningStart(svc)) < 24*time.Hour || reqs < 1000 {
		appSkip("APM-O03", "learning")
		return
	}
	win := time.Duration(g.Param("window_min", 10)) * time.Minute
	to := now.Add(-appRecentLag)
	cur, err := r.d.RouteWindow(ctx, svc.ID, to.Add(-win), to)
	if err != nil {
		return
	}
	base, err := r.d.RouteWindow(ctx, svc.ID, now.Add(-25*time.Hour), now.Add(-time.Hour))
	if err != nil {
		return
	}
	sum := func(l []appWindowStats) (n int64) {
		for _, s := range l {
			n += s.Calls
		}
		return
	}
	perWindow := float64(sum(base)) / (24 * 60 / win.Minutes())
	if perWindow < g.Param("min_baseline", 100) {
		appSkip("APM-O03", "baseline too small")
		return
	}
	curN := float64(sum(cur))
	drop := g.Param("drop_pct", 80)
	if curN <= perWindow*(1-drop/100) {
		r.fire(ctx, appFinding{RuleID: "APM-O03", Svc: svc, BaseSev: appSevHigh, Summary: "Traffic dropped sharply",
			Detail: fmt.Sprintf("%d requests in the last %d minutes against a usual %.0f (down %.0f%%).%s",
				int64(curN), int(win.Minutes()), perWindow, (1-curN/perWindow)*100, appNotifyLine(svc)),
			EventType: "app.alert", Time: now, DedupKey: fmt.Sprintf("%d:%s", svc.ID, now.UTC().Format("2006010215"))})
	}
}

// ── O05: instance stopped reporting ────────────────────────────────────────

func (r *appRules) o05(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APM-O05", svc)
	// Only services that report telemetry have a heartbeat to lose. A discovered (non-OTel) service is seen
	// by polling, and its processes legitimately come and go (workers, one docker-proxy per published port).
	if !on || svc.Source != "otel" || appInMaintenance(svc.Settings, now) {
		return
	}
	insts, err := r.d.Instances(ctx, svc.ID)
	if err != nil {
		return
	}
	grace := time.Duration(g.Param("grace_min", 10)) * time.Minute
	reporting := 0
	for _, i := range insts {
		if !i.Stopped && now.Sub(i.LastSeen) <= grace {
			reporting++
		}
	}
	if reporting == 0 {
		return // nobody reports: that is a traffic problem (O03) or an idle service, not one missing instance
	}
	var missing []string
	var first *appInst
	for idx, i := range insts {
		if i.Stopped || now.Sub(i.LastSeen) <= grace || now.Sub(i.LastSeen) > 24*time.Hour {
			continue
		}
		replaced := false
		for _, o := range insts { // a newer instance in the same place took over (restart)
			if o.ID != i.ID && !o.Stopped && o.AgentID == i.AgentID && o.ContainerID == i.ContainerID &&
				o.FirstSeen.After(i.FirstSeen) && now.Sub(o.LastSeen) <= grace {
				replaced = true
				break
			}
		}
		if replaced {
			continue
		}
		seen, err := r.d.AgentSeen(ctx, i.AgentID)
		if err != nil || now.Sub(seen) > 2*time.Minute {
			continue // the host itself is silent: a different problem
		}
		if r.d.InDeployWindow(ctx, svc, i.AgentID, now, 30*time.Minute) {
			appSkip("APM-O05", "deploy window")
			continue
		}
		missing = append(missing, fmt.Sprintf("pid %d on %s (silent %d min)", i.PID, i.Host, int(now.Sub(i.LastSeen).Minutes())))
		if first == nil {
			first = &insts[idx]
		}
	}
	if first == nil {
		return
	}
	// One alert per service and hour, however many instances went quiet.
	exposure := svc.Settings.EffectiveExposure()
	if exposure == "" {
		exposure = "unknown"
	}
	lastReq := "no request statistics yet"
	if last, err := r.d.LastRequestMinute(ctx, svc.ID); err == nil && !last.IsZero() {
		lastReq = "last request seen " + last.UTC().Format("15:04 UTC")
	}
	list := missing
	more := ""
	if len(list) > 5 {
		more = fmt.Sprintf(" and %d more", len(list)-5)
		list = list[:5]
	}
	r.fire(ctx, appFinding{RuleID: "APM-O05", Svc: svc, BaseSev: appSevHigh,
		Summary: fmt.Sprintf("%d of %d instances of %s stopped reporting", len(missing), len(insts), svc.Name),
		Detail: fmt.Sprintf("Service %s (%s, exposure: %s) has %d instance(s) that stopped sending telemetry for more than %d minutes while the host is up and %d other instance(s) still report: %s%s. %s.\n"+
			"What to check: whether the process is still running on that host (it may have crashed or been replaced), whether the application's exporter can still reach the agent at 127.0.0.1:4318, and whether a deploy is in progress. If this is expected, add a maintenance window or a deploy window to the service.%s",
			svc.Name, svc.Env, exposure, len(missing), int(grace.Minutes()), reporting, strings.Join(list, "; "), more, lastReq, appNotifyLine(svc)),
		InstanceID: first.ID, AgentID: first.AgentID, Host: first.Host, EventType: "app.alert", Time: now,
		DedupKey: fmt.Sprintf("%d:o05:%s", svc.ID, now.UTC().Format("2006010215"))})
}

// ── X06: instrumentation dropped while the process runs ────────────────────

func (r *appRules) x06(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APP-X06", svc)
	if !on || svc.Source != "otel" || appInMaintenance(svc.Settings, now) {
		return
	}
	last, err := r.d.LastRequestMinute(ctx, svc.ID)
	if err != nil || last.IsZero() {
		return
	}
	grace := time.Duration(g.Param("grace_min", 10)) * time.Minute
	if now.Sub(last) < grace || now.Sub(last) > 24*time.Hour {
		return
	}
	before, err := r.d.RouteWindow(ctx, svc.ID, last.Add(-time.Hour), last.Add(time.Minute))
	if err != nil {
		return
	}
	var n int64
	for _, s := range before {
		n += s.Calls
	}
	if n < 20 {
		return // never had meaningful traffic: nothing "dropped"
	}
	if r.d.InDeployWindow(ctx, svc, "", now, time.Duration(g.Param("deploy_window_min", 30))*time.Minute) {
		appSkip("APP-X06", "deploy window")
		return
	}
	insts, err := r.d.Instances(ctx, svc.ID)
	if err != nil {
		return
	}
	for _, i := range insts {
		if i.Stopped || i.PID == 0 {
			continue
		}
		seen, err := r.d.AgentSeen(ctx, i.AgentID)
		if err != nil || now.Sub(seen) > 2*time.Minute {
			continue
		}
		alive, err := r.d.ProcessAlive(ctx, i.AgentID, i.PID, now.Add(-grace))
		if err != nil {
			continue
		}
		if !alive {
			appSkip("APP-X06", "no evidence the process is still running")
			continue
		}
		r.fire(ctx, appFinding{RuleID: "APP-X06", Svc: svc, BaseSev: appSevMed, Summary: "Instrumentation stopped while the process runs",
			Detail: fmt.Sprintf("No telemetry from this service for %d minutes, but its process (pid %d on %s) is still active and the host is up. Telemetry may have been disabled or the SDK tampered with.",
				int(now.Sub(last).Minutes()), i.PID, i.Host),
			InstanceID: i.ID, AgentID: i.AgentID, Host: i.Host, Identity: i.Identity, EventType: "app.alert", Time: now,
			DedupKey: fmt.Sprintf("%d:%s", svc.ID, now.UTC().Format("2006010215"))})
		return
	}
}

// ── scan driver ────────────────────────────────────────────────────────────

// Scan runs every data-driven rule over the services that were active recently.
func (r *appRules) Scan(ctx context.Context) {
	now := r.now()
	svcs, err := r.d.ActiveServices(ctx, now.Add(-24*time.Hour))
	if err != nil {
		return
	}
	for _, svc := range svcs {
		if ctx.Err() != nil {
			return
		}
		r.sourceRules(ctx, svc, now)
		r.a08(ctx, svc, now)
		r.o01(ctx, svc, now)
		r.o03(ctx, svc, now)
		r.o05(ctx, svc, now)
		r.x06(ctx, svc, now)
	}
}
