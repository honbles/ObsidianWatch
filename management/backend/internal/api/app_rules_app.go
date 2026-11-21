package api

// app_rules_app.go - Tier 1 application rules A01, A08, A09, A13 and the cross-layer rule X02.
// They read the aggregate tables (app_client_stats, service_routes, app_route_stats), not raw
// events, so they run from Scan.

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// appEffectiveClient picks the address a source-based rule counts (spec section 7): a forwarded
// client address is trusted only when the direct peer is a configured trusted proxy. When no
// proxy is configured and every request appears to come from a private peer while a different
// client address was reported, the peer is used and the result is marked degraded (the rule
// runs at reduced severity).
func appEffectiveClient(client, peer string, trusted []string) (addr string, degraded bool, note string) {
	inTrusted := func(ip string) bool {
		p := net.ParseIP(ip)
		if p == nil {
			return false
		}
		for _, t := range trusted {
			if _, n, err := net.ParseCIDR(t); err == nil && n.Contains(p) {
				return true
			}
			if tp := net.ParseIP(t); tp != nil && tp.Equal(p) {
				return true
			}
		}
		return false
	}
	switch {
	case peer != "" && client != "" && inTrusted(peer):
		return client, false, ""
	case peer != "":
		if client != "" && client != peer && len(trusted) == 0 {
			if c := appClassifyIP(peer); c == appIPPrivate || c == appIPLoopback {
				return peer, true, "requests appear to come from a proxy at " + peer + "; add it to the service's trusted proxies to count the real client address"
			}
		}
		return peer, false, ""
	}
	return client, false, ""
}

// appIsInjectionExc classifies an exception type as an injection class (spec A09).
func appIsInjectionExc(t string) bool {
	l := strings.ToLower(t)
	if l == "" {
		return false
	}
	if strings.HasPrefix(l, "param.") || strings.Contains(l, "injection") || strings.Contains(l, "ognl") || strings.Contains(l, "spelevaluation") || strings.Contains(l, "spelparse") {
		return true
	}
	return strings.Contains(l, "sql") && (strings.Contains(l, "syntax") || strings.Contains(l, "grammar") || strings.Contains(l, "parse"))
}

// appLoginRoutes returns the routes counted as login routes: the service's configured list, or
// (when none is configured) routes whose template looks like one. inferred reports which.
func appLoginRoutes(st appServiceSettings, route string) (isLogin, inferred bool) {
	for _, r := range st.LoginRoutes {
		if r == route {
			return true, false
		}
	}
	if len(st.LoginRoutes) > 0 {
		return false, false
	}
	l := strings.ToLower(route)
	for _, m := range []string{"login", "signin", "sign-in", "/token", "/auth"} {
		if strings.Contains(l, m) {
			return true, true
		}
	}
	return false, false
}

type appClientAgg struct {
	addr, peer, client string
	degraded           bool
	note               string
	sum                int64
	other              int64 // 4xx/5xx besides the counted class, for context
	routes             map[string]int64
	excs               map[string]int64
}

func (a *appClientAgg) topRoute() (route string) {
	var best int64 = -1
	for r, n := range a.routes {
		if n > best || (n == best && r < route) {
			route, best = r, n
		}
	}
	return route
}

func appSplitRoute(k string) (method, route string) {
	if i := strings.Index(k, " "); i > 0 {
		return k[:i], k[i+1:]
	}
	return "", k
}

// sourceRules evaluates A01, A09 and A13 for one service.
func (r *appRules) sourceRules(ctx context.Context, svc appSvc, now time.Time) {
	g01, on01 := r.enabled(ctx, "APP-A01", svc)
	g09, on09 := r.enabled(ctx, "APP-A09", svc)
	g13, on13 := r.enabled(ctx, "APP-A13", svc)
	if !on01 && !on09 && !on13 {
		return
	}
	maxWin := 5.0
	for _, w := range []struct {
		on bool
		g  RuleGate
	}{{on01, g01}, {on09, g09}, {on13, g13}} {
		if w.on {
			if v := w.g.Param("window_min", 5); v > maxWin {
				maxWin = v
			}
		}
	}
	rows, err := r.d.ClientRows(ctx, svc.ID, now.Add(-time.Duration(maxWin)*time.Minute))
	if err != nil {
		return
	}
	trusted := svc.Settings.TrustedProxies
	type key struct{ addr, route string }
	login := map[string]*appClientAgg{}
	limited := map[string]*appClientAgg{}
	inject := map[key]*appClientAgg{}
	sawLoginRoute := false
	get := func(m map[string]*appClientAgg, addr, client, peer string, deg bool, note string) *appClientAgg {
		a := m[addr]
		if a == nil {
			a = &appClientAgg{addr: addr, peer: peer, client: client, degraded: deg, note: note, routes: map[string]int64{}, excs: map[string]int64{}}
			m[addr] = a
		}
		return a
	}
	for _, row := range rows {
		addr, deg, note := appEffectiveClient(row.ClientIP, row.PeerIP, trusted)
		if addr == "" {
			continue
		}
		rk := row.Method + " " + row.Route
		if on01 && !row.Minute.Before(now.Add(-time.Duration(g01.Param("window_min", 5))*time.Minute)) {
			if isLogin, _ := appLoginRoutes(svc.Settings, row.Route); isLogin {
				sawLoginRoute = true
				if row.Status40103 > 0 {
					a := get(login, addr, row.ClientIP, row.PeerIP, deg, note)
					a.sum += row.Status40103
					a.routes[rk] += row.Status40103
				}
			}
		}
		if on13 && row.Status429 > 0 && !row.Minute.Before(now.Add(-time.Duration(g13.Param("window_min", 5))*time.Minute)) {
			a := get(limited, addr, row.ClientIP, row.PeerIP, deg, note)
			a.sum += row.Status429
			a.routes[rk] += row.Status429
		}
		if on09 && appIsInjectionExc(row.ExcType) && !row.Minute.Before(now.Add(-time.Duration(g09.Param("window_min", 5))*time.Minute)) {
			k := key{addr, rk}
			a := inject[k]
			if a == nil {
				a = &appClientAgg{addr: addr, peer: row.PeerIP, client: row.ClientIP, degraded: deg, note: note, routes: map[string]int64{}, excs: map[string]int64{}}
				inject[k] = a
			}
			a.sum += row.Failures
			a.other += row.Status4xxOther + row.Status5xx
			a.excs[row.ExcType] += row.Failures
		}
	}
	if on01 && !sawLoginRoute && len(svc.Settings.LoginRoutes) == 0 {
		appSkip("APP-A01", "no login routes configured or recognised")
	}
	hour := now.UTC().Format("2006010215")
	finish := func(rule string, a *appClientAgg, sev int, summary, detail, route string) {
		method, tpl := appSplitRoute(route)
		f := appFinding{RuleID: rule, Svc: svc, BaseSev: sev, Summary: summary, Detail: detail, Route: tpl, Method: method,
			ClientIP: a.addr, Degraded: a.degraded, DegradeNote: a.note, Identity: "", EventType: "app.alert", Time: now,
			DedupKey: fmt.Sprintf("%d:%s:%s", svc.ID, a.addr, hour), AllowVals: []string{a.addr, a.peer, a.client}}
		r.fire(ctx, f)
	}
	if on01 {
		th := int64(g01.Param("threshold", 20))
		for _, addr := range appSortedAgg(login) {
			a := login[addr]
			if a.sum >= th {
				finish("APP-A01", a, appSevHigh, "Login failure burst",
					fmt.Sprintf("%d failed logins (401/403) from %s in %d minutes across %d login route(s): %s.", a.sum, a.addr, int(g01.Param("window_min", 5)), len(a.routes), appTopList(a.routes)), a.topRoute())
			}
		}
	}
	if on13 {
		th := int64(g13.Param("threshold", 50))
		for _, addr := range appSortedAgg(limited) {
			a := limited[addr]
			if a.sum >= th {
				finish("APP-A13", a, appSevMed, "Rate-limit abuse",
					fmt.Sprintf("%d rate-limited responses (429) for %s in %d minutes: %s.", a.sum, a.addr, int(g13.Param("window_min", 5)), appTopList(a.routes)), a.topRoute())
			}
		}
	}
	if on09 {
		th := int64(g09.Param("threshold", 3))
		var keys []key
		for k := range inject {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].addr+keys[i].route < keys[j].addr+keys[j].route })
		for _, k := range keys {
			a := inject[k]
			if a.sum >= th {
				detail := fmt.Sprintf("%d injection-class failures from %s on %s in %d minutes (exception types: %s); %d other 4xx/5xx responses from the same client.",
					a.sum, a.addr, k.route, int(g09.Param("window_min", 5)), appTopList(a.excs), a.other)
				f := appFinding{RuleID: "APP-A09", Svc: svc, BaseSev: appSevMed, Summary: "Injection attempts", Detail: detail, ClientIP: a.addr,
					Degraded: a.degraded, DegradeNote: a.note, EventType: "app.alert", Time: now,
					DedupKey: fmt.Sprintf("%d:%s:%s:%s", svc.ID, a.addr, k.route, hour), AllowVals: []string{a.addr, a.peer, a.client}}
				f.Method, f.Route = appSplitRoute(k.route)
				r.fire(ctx, f)
			}
		}
	}
}

func appSortedAgg(m map[string]*appClientAgg) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func appTopList(m map[string]int64) string {
	type kv struct {
		k string
		v int64
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	var parts []string
	for i, x := range l {
		if i == 3 {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, fmt.Sprintf("%s ×%d", x.k, x.v))
	}
	return strings.Join(parts, ", ")
}

// ── A08: new route ─────────────────────────────────────────────────────────

func (r *appRules) a08(ctx context.Context, svc appSvc, now time.Time) {
	g, on := r.enabled(ctx, "APP-A08", svc)
	if !on {
		return
	}
	learnEnd := appLearningStart(svc).Add(time.Duration(g.Param("min_days", 7)*24) * time.Hour)
	reqs, err := r.d.Requests(ctx, svc)
	if err != nil {
		return
	}
	if now.Before(learnEnd) || reqs < int64(g.Param("min_samples", 1000)) {
		appSkip("APP-A08", "learning")
		return
	}
	since := now.Add(-time.Hour)
	if learnEnd.After(since) {
		since = learnEnd
	}
	routes, err := r.d.NewRoutes(ctx, svc.ID, since)
	if err != nil {
		return
	}
	window := time.Duration(g.Param("deploy_window_min", 30)) * time.Minute
	for _, rt := range routes {
		if rt.Route == "other" || rt.Route == "(unmatched)" {
			continue
		}
		if r.d.InDeployWindow(ctx, svc, "", rt.FirstSeen, window) {
			appSkip("APP-A08", "deploy window")
			continue
		}
		public := false
		for _, p := range svc.Settings.PublicRoutes {
			if p == rt.Route {
				public = true
			}
		}
		detail := fmt.Sprintf("A route this service never served during learning appeared: %s %s (first seen %s).", rt.Method, rt.Route, rt.FirstSeen.UTC().Format(time.RFC3339))
		if public {
			detail += " It is tagged as a public route, so authentication is not expected."
		} else {
			detail += " Check whether authentication is expected on it."
		}
		r.fire(ctx, appFinding{RuleID: "APP-A08", Svc: svc, BaseSev: appSevLow, Summary: "New route", Detail: detail, Route: rt.Route, Method: rt.Method,
			EventType: "app.alert", Time: now, DedupKey: fmt.Sprintf("%d:%s %s", svc.ID, rt.Method, rt.Route), AllowVals: []string{rt.Route, rt.Method + " " + rt.Route}})
	}
}

// ── X02: application anomaly, then host execution ──────────────────────────

// x02 is called when H01 or H02 fired for a service. It raises the cross-layer alert when the
// service showed an application anomaly (an A09 alert, or a 5xx spike) within the window.
func (r *appRules) x02(ctx context.Context, ev store.Event, p appProcInfo, svc appSvc, inst appInst, trigger string) {
	g, on := r.enabled(ctx, "APP-X02", svc)
	if !on {
		return
	}
	window := time.Duration(g.Param("window_min", 15)) * time.Minute
	desc, ok := r.d.AppAnomaly(ctx, svc, ev.Time.Add(-window), int64(g.Param("spike_5xx", 30)))
	if !ok {
		return
	}
	f := r.base(ev, p, svc, inst, "APP-X02")
	f.BaseSev, f.Summary = appSevCrit, "Application anomaly followed by host execution"
	f.Detail = fmt.Sprintf("%s, then %s ran from the same service's process within %d minutes.\nExecuted: %s", desc, trigger, int(window.Minutes()), appCmdText(p))
	f.Lineage = p.lineageText(inst, 1)
	f.DedupKey = fmt.Sprintf("%d:%d", svc.ID, p.PID)
	f.AllowVals = []string{p.base()}
	appDegradedLineage(p, inst, &f)
	r.fire(ctx, f)
}
