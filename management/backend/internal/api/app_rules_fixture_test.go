package api

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

var appNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// ── fake data layer ────────────────────────────────────────────────────────

type appFakeData struct {
	insts           []appInst
	svcs            map[int64]appSvc
	baselines       map[string]int64
	deploy          bool
	intel           map[string]string
	anomaly         string
	clientRows      []appClientRow
	newRoutes       []appRouteRef
	requests        int64
	curWin          []appWindowStats
	baseWin         []appWindowStats
	agentSeen       map[string]time.Time
	alive           map[int]bool
	lastReq         time.Time
	errGroups       []appErrGroupRef
	metrics         []appMetricAgg
	qCur, qBase     []appQueryAgg
	deploys         []appDeploy
	ops             []appOpAgg
	sli             func(from, to time.Time, target int) appSLICounts
	totals          func(from, to time.Time) appWindowTotals // overrides preTot and postTot
	jobs            []appJobHistory
	postTot, preTot appWindowTotals
	prior           []appWindowStats // traffic before lastReq
}

func (f *appFakeData) ServiceForLineage(_ context.Context, agentID, container string, pids []int) (appSvc, appInst, int, bool) {
	best := -1
	var bi appInst
	for _, i := range f.insts {
		if i.AgentID != agentID || i.Stopped {
			continue
		}
		idx := -1
		for k, p := range pids {
			if p > 0 && p == i.PID {
				idx = k
				break
			}
		}
		if idx < 0 && container != "" && i.ContainerID == container {
			idx = 0
		}
		if idx >= 0 && (best < 0 || idx < best) {
			best, bi = idx, i
		}
	}
	if best < 0 {
		return appSvc{}, appInst{}, 0, false
	}
	return f.svcs[bi.ServiceID], bi, best, true
}
func (f *appFakeData) bkey(id int64, kind, key string) string {
	return kind + "|" + key + "|" + string(rune('0'+id))
}
func (f *appFakeData) Baseline(_ context.Context, id int64, kind, key string) (bool, error) {
	_, ok := f.baselines[f.bkey(id, kind, key)]
	return ok, nil
}
func (f *appFakeData) RecordBaseline(_ context.Context, id int64, kind, key string, _ time.Time) error {
	f.baselines[f.bkey(id, kind, key)]++
	return nil
}
func (f *appFakeData) BaselineSamples(_ context.Context, id int64, kind string) (int64, error) {
	var n int64
	for k, v := range f.baselines {
		if strings.HasPrefix(k, kind+"|") && !strings.HasPrefix(k, kind+"|dnsdom:") {
			n += v
		}
	}
	return n, nil
}
func (f *appFakeData) InDeployWindow(context.Context, appSvc, string, time.Time, time.Duration) bool {
	return f.deploy
}
func (f *appFakeData) IPIntel(_ context.Context, ip string) (string, bool) {
	s, ok := f.intel[ip]
	return s, ok
}
func (f *appFakeData) AppAnomaly(context.Context, appSvc, time.Time, int64) (string, bool) {
	return f.anomaly, f.anomaly != ""
}
func (f *appFakeData) ActiveServices(context.Context, time.Time) ([]appSvc, error) {
	var out []appSvc
	for _, s := range f.svcs {
		out = append(out, s)
	}
	return out, nil
}
func (f *appFakeData) ClientRows(context.Context, int64, time.Time) ([]appClientRow, error) {
	return f.clientRows, nil
}
func (f *appFakeData) NewRoutes(context.Context, int64, time.Time) ([]appRouteRef, error) {
	return f.newRoutes, nil
}
func (f *appFakeData) Requests(context.Context, appSvc) (int64, error) { return f.requests, nil }
func (f *appFakeData) RouteWindow(_ context.Context, _ int64, from, to time.Time) ([]appWindowStats, error) {
	if to.Sub(from) > 2*time.Hour {
		return f.baseWin, nil
	}
	if !f.lastReq.IsZero() && to.Before(f.lastReq.Add(2*time.Hour)) && to.After(f.lastReq) {
		return f.prior, nil
	}
	return f.curWin, nil
}
func (f *appFakeData) Instances(context.Context, int64) ([]appInst, error) { return f.insts, nil }
func (f *appFakeData) AgentSeen(_ context.Context, a string) (time.Time, error) {
	return f.agentSeen[a], nil
}
func (f *appFakeData) ProcessAlive(_ context.Context, _ string, pid int, _ time.Time) (bool, error) {
	return f.alive[pid], nil
}
func (f *appFakeData) LastRequestMinute(context.Context, int64) (time.Time, error) {
	return f.lastReq, nil
}

func (f *appFakeData) QueryWindow(_ context.Context, _ int64, from, to time.Time) ([]appQueryAgg, error) {
	if to.After(appNow) { // the current window reaches "now"
		return f.qCur, nil
	}
	return f.qBase, nil
}

func (f *appFakeData) Deploys(_ context.Context, _ int64, since time.Time) ([]appDeploy, error) {
	var out []appDeploy
	for _, d := range f.deploys {
		if !d.FirstSeen.Before(since) {
			out = append(out, d)
		}
	}
	return out, nil
}

func (f *appFakeData) WindowTotals(_ context.Context, _ int64, from, to time.Time) (appWindowTotals, error) {
	if f.totals != nil {
		return f.totals(from, to), nil
	}
	if to.After(appNow) {
		return f.postTot, nil
	}
	return f.preTot, nil
}

func (f *appFakeData) OperationWindow(context.Context, int64, time.Time, time.Time) ([]appOpAgg, error) {
	return f.ops, nil
}

func (f *appFakeData) JobHistory(context.Context, int64, time.Time) ([]appJobHistory, error) {
	return f.jobs, nil
}

func (f *appFakeData) SLICounts(_ context.Context, _ int64, from, to time.Time, target int) (appSLICounts, error) {
	if f.sli == nil {
		return appSLICounts{}, nil
	}
	return f.sli(from, to, target), nil
}

func (f *appFakeData) MetricWindow(context.Context, int64, time.Time, time.Time) ([]appMetricAgg, error) {
	return f.metrics, nil
}

func (f *appFakeData) ErrorGroups(context.Context, int64, time.Time) ([]appErrGroupRef, error) {
	return f.errGroups, nil
}

// ── fake emitter: applies the same gate, weighting and dedup the real one does ──

type appFakeAlert struct {
	F       appFinding
	Sev     int
	Factors []string
	Observe bool
}

type appFakeEmitter struct {
	mu    sync.Mutex
	gates map[string]RuleGate
	seen  map[string]bool
	out   []appFakeAlert
}

func (e *appFakeEmitter) gate(rule string) RuleGate {
	if g, ok := e.gates[rule]; ok {
		return g
	}
	return RuleGate{Enabled: true, Observe: false, Params: map[string]float64{}}
}

func (e *appFakeEmitter) Emit(_ context.Context, f appFinding) (int64, bool, error) {
	meta, ok := RuleMetaFor(f.RuleID)
	if !ok {
		panic("no RuleMeta for " + f.RuleID)
	}
	sev, factors, skip := appFinalSeverity(e.gate(f.RuleID), f, meta)
	if skip {
		return 0, false, nil
	}
	k := f.RuleID + ":" + f.DedupKey
	if e.seen[k] {
		return 0, false, nil
	}
	e.seen[k] = true
	e.out = append(e.out, appFakeAlert{f, sev, factors, e.gate(f.RuleID).Observe})
	return int64(len(e.out)), true, nil
}

func (e *appFakeEmitter) byRule(rule string) []appFakeAlert {
	var out []appFakeAlert
	for _, a := range e.out {
		if a.F.RuleID == rule {
			out = append(out, a)
		}
	}
	return out
}

// ── fixture harness ────────────────────────────────────────────────────────

type appFx struct {
	t   *testing.T
	d   *appFakeData
	em  *appFakeEmitter
	r   *appRules
	svc appSvc
}

// appFixtureSeen records which rules have positive and negative fixtures (enforced by TestAppRuleFixtureCoverage).
var appFixtureSeen = struct {
	sync.Mutex
	pos, neg map[string]bool
}{pos: map[string]bool{}, neg: map[string]bool{}}

func appNewFx(t *testing.T) *appFx {
	t.Helper()
	appStatusReset()
	svc := appSvc{ID: 1, Name: "checkout", Env: "prod", Source: "otel", FirstSeen: appNow.Add(-30 * 24 * time.Hour), Settings: appDefaultSettings()}
	d := &appFakeData{
		svcs:      map[int64]appSvc{1: svc},
		baselines: map[string]int64{},
		agentSeen: map[string]time.Time{"a1": appNow},
		alive:     map[int]bool{},
		requests:  50000,
		insts: []appInst{{ID: 11, ServiceID: 1, AgentID: "a1", Host: "web-01", PID: 100, Identity: "verified", Name: "java",
			FirstSeen: appNow.Add(-30 * 24 * time.Hour), LastSeen: appNow}},
	}
	em := &appFakeEmitter{gates: map[string]RuleGate{}, seen: map[string]bool{}}
	fx := &appFx{t: t, d: d, em: em, svc: svc}
	fx.r = appNewRules(d, em, func(_ context.Context, rule string, _ appSvc) RuleGate { return em.gate(rule) })
	fx.r.now = func() time.Time { return appNow }
	return fx
}

func (fx *appFx) setSvc(mut func(*appSvc)) {
	mut(&fx.svc)
	fx.d.svcs[1] = fx.svc
}

func (fx *appFx) gate(rule string, g RuleGate) {
	if g.Params == nil {
		g.Params = map[string]float64{}
	}
	fx.em.gates[rule] = g
}

func (fx *appFx) fired(rule string) []appFakeAlert { return fx.em.byRule(rule) }

// pos asserts the rule fired exactly n times (a positive fixture).
func (fx *appFx) pos(rule string, n int) []appFakeAlert {
	fx.t.Helper()
	got := fx.fired(rule)
	if len(got) != n {
		fx.t.Fatalf("%s: want %d alert(s), got %d: %+v", rule, n, len(got), got)
	}
	appFixtureSeen.Lock()
	appFixtureSeen.pos[rule] = true
	appFixtureSeen.Unlock()
	return got
}

// neg asserts the rule did not fire (a negative fixture).
func (fx *appFx) neg(rule string) {
	fx.t.Helper()
	if got := fx.fired(rule); len(got) != 0 {
		fx.t.Fatalf("%s: must stay quiet, got %+v", rule, got)
	}
	appFixtureSeen.Lock()
	appFixtureSeen.neg[rule] = true
	appFixtureSeen.Unlock()
}

func appSP(s string) *string { return &s }
func appIP(i int) *int       { return &i }

// appEv builds a host event. raw is the JSON of the "proc" object (may be "").
func appEv(typ string, pid, ppid int, name, raw string) store.Event {
	ev := store.Event{ID: "ev-" + typ + "-" + name, Time: appNow, AgentID: "a1", Host: "web-01", EventType: typ,
		PID: appIP(pid), PPID: appIP(ppid), ProcessName: appSP(name), CommandLine: appSP(name + " -c something")}
	if raw != "" {
		ev.Raw = []byte(`{"proc":` + raw + `}`)
	}
	return ev
}

func (fx *appFx) event(ev store.Event) { fx.r.OnEvent(context.Background(), ev) }

const appAncJava = `"ancestors":[{"pid":100,"name":"java","exe":"/usr/bin/java"}]`
