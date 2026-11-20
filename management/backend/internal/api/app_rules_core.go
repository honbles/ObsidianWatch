package api

// app_rules_core.go - what every Application rule shares: the finding, severity weighting
// (spec 10.1), the allowlist test and the emitter that applies the rule contract (enabled /
// observe / allowlist through ruleGate) and creates the alert with its entity links.
// Alerts are created through CreateAlertDeduped; the dedup key is stored in the alert's
// event_id and always starts with "app:<RULE-ID>:".

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// Severity scale (matches the Alerts UI).
const (
	appSevInfo = 1
	appSevLow  = 2
	appSevMed  = 3
	appSevHigh = 4
	appSevCrit = 5
)

// appSvc is the service a finding is about.
type appSvc struct {
	ID        int64
	Name      string
	Env       string
	Source    string
	FirstSeen time.Time
	Settings  appServiceSettings
}

func (s appSvc) Key() string { return appServiceKey(s.Name, s.Env) }
func (s appSvc) Tier() int   { return appTier(s.Source) }

// appFinding is a rule result before gating and weighting.
type appFinding struct {
	RuleID  string
	Svc     appSvc // zero ID: not tied to a service (host-wide)
	BaseSev int
	Summary string // short title text
	Detail  string // body

	InstanceID  int64
	AgentID     string
	Host        string
	Route       string // template
	Method      string
	ClientIP    string
	User        string
	TraceID     string
	Lineage     string
	Identity    string // verified | asserted | "" (not applicable)
	Degraded    bool
	DegradeNote string

	DedupKey      string
	SourceEventID string
	EventType     string
	AllowVals     []string // values compared with the rule's allowlist
	Time          time.Time
}

// appWeigh applies spec 10.1: raise one level for an internet-facing service and one for high
// or critical criticality (up to Critical); degraded inputs lower the result one level;
// telemetry with an asserted identity is capped at Medium. Operational rules are not weighted.
func appWeigh(base int, st appServiceSettings, identity string, degraded, operational bool) (int, []string) {
	sev := base
	var factors []string
	if operational {
		return sev, factors
	}
	if st.EffectiveExposure() == "internet" && sev < appSevCrit {
		sev++
		factors = append(factors, "internet-facing +1")
	}
	if (st.Criticality == "high" || st.Criticality == "critical") && sev < appSevCrit {
		sev++
		factors = append(factors, st.Criticality+" criticality +1")
	}
	if degraded && sev > appSevLow {
		sev--
		factors = append(factors, "degraded input -1")
	}
	if identity == "asserted" && sev > appSevMed {
		sev = appSevMed
		factors = append(factors, "asserted identity (capped at Medium)")
	}
	return sev, factors
}

// appAllowMatch reports whether a rule allowlist entry matches a value: case-insensitive
// equality, or an IP inside a CIDR entry.
func appAllowMatch(entry, val string) bool {
	entry, val = strings.TrimSpace(entry), strings.TrimSpace(val)
	if entry == "" || val == "" {
		return false
	}
	if strings.EqualFold(entry, val) {
		return true
	}
	if _, n, err := net.ParseCIDR(entry); err == nil {
		if ip := net.ParseIP(val); ip != nil {
			return n.Contains(ip)
		}
	}
	return false
}

func appAllowed(allow []string, vals ...string) bool {
	for _, a := range allow {
		for _, v := range vals {
			if appAllowMatch(a, v) {
				return true
			}
		}
	}
	return false
}

// ── status counters (Coverage page: skipped and degraded rules) ────────────

type appRuleCounters struct {
	Fired    int64            `json:"fired"`
	Observed int64            `json:"observed"` // fired in observe mode
	Degraded int64            `json:"degraded"`
	Skipped  map[string]int64 `json:"skipped"` // reason -> count
	LastFire time.Time        `json:"last_fired,omitempty"`
}

var appStatus = struct {
	sync.Mutex
	m map[string]*appRuleCounters
}{m: map[string]*appRuleCounters{}}

func appStatusFor(rule string) *appRuleCounters {
	c := appStatus.m[rule]
	if c == nil {
		c = &appRuleCounters{Skipped: map[string]int64{}}
		appStatus.m[rule] = c
	}
	return c
}

// appSkip counts a rule that could not run (missing source, no login routes configured, ...).
func appSkip(rule, reason string) {
	appStatus.Lock()
	appStatusFor(rule).Skipped[reason]++
	appStatus.Unlock()
}

func appStatusSnapshot() map[string]appRuleCounters {
	appStatus.Lock()
	defer appStatus.Unlock()
	out := make(map[string]appRuleCounters, len(appStatus.m))
	for k, v := range appStatus.m {
		cp := *v
		cp.Skipped = map[string]int64{}
		for r, n := range v.Skipped {
			cp.Skipped[r] = n
		}
		out[k] = cp
	}
	return out
}

func appStatusReset() {
	appStatus.Lock()
	appStatus.m = map[string]*appRuleCounters{}
	appStatus.Unlock()
}

// ── emitting ───────────────────────────────────────────────────────────────

// appAlertEmitter turns a finding into an alert (or nothing, when the rule is disabled,
// allowlisted or a duplicate). Tests substitute an in-memory emitter.
type appAlertEmitter interface {
	Emit(ctx context.Context, f appFinding) (alertID int64, created bool, err error)
}

// appPGEmitter is the database-backed emitter.
type appPGEmitter struct{ db *store.DB }

func appRuleGateFor(ctx context.Context, db *store.DB, f appFinding) RuleGate {
	if f.Svc.ID != 0 {
		return ruleGate(ctx, db, f.RuleID, "service", f.Svc.Key())
	}
	return ruleGate(ctx, db, f.RuleID, "", "")
}

// appFinalSeverity combines weighting, degradation and the gate's observe mode. It also
// reports whether the rule is disabled or the finding allowlisted.
func appFinalSeverity(g RuleGate, f appFinding, meta RuleMeta) (sev int, factors []string, skip bool) {
	if !g.Enabled || appAllowed(g.Allowlist, f.AllowVals...) {
		return 0, nil, true
	}
	w, factors := appWeigh(f.BaseSev, f.Svc.Settings, f.Identity, f.Degraded, meta.Operational)
	return GateSeverity(g, w), factors, false
}

func (e appPGEmitter) Emit(ctx context.Context, f appFinding) (int64, bool, error) {
	meta, ok := RuleMetaFor(f.RuleID)
	if !ok {
		return 0, false, fmt.Errorf("app rule %s has no RuleMeta", f.RuleID)
	}
	g := appRuleGateFor(ctx, e.db, f)
	sev, factors, skip := appFinalSeverity(g, f, meta)
	if skip {
		return 0, false, nil
	}
	alert := store.Alert{
		Title:         appAlertTitle(f),
		Description:   appAlertBody(f, meta, g.Observe, sev, factors),
		Severity:      sev,
		AgentID:       f.AgentID,
		Host:          f.Host,
		EventType:     f.EventType,
		EventID:       "app:" + f.RuleID + ":" + f.DedupKey,
		SourceEventID: f.SourceEventID,
	}
	if alert.EventType == "" {
		alert.EventType = "app.alert"
	}
	id, inserted, err := e.db.CreateAlertDeduped(ctx, alert)
	if err != nil {
		return 0, false, err
	}
	appStatus.Lock()
	c := appStatusFor(f.RuleID)
	if inserted {
		c.Fired++
		c.LastFire = time.Now()
		if g.Observe {
			c.Observed++
		}
	}
	if f.Degraded {
		c.Degraded++
	}
	appStatus.Unlock()
	if inserted {
		appLinkEntities(ctx, e.db, id, f)
	}
	return id, inserted, nil
}

func appAlertTitle(f appFinding) string {
	t := "[" + f.RuleID + "] " + f.Summary
	if f.Svc.ID != 0 {
		t += " - " + f.Svc.Name + " (" + f.Svc.Env + ")"
	}
	return t
}

// appAlertBody carries what the spec requires on every alert: service, environment, instance,
// host, route, client address, trace id, process lineage, tier, identity, the weighting
// factors and the "what to check" note.
func appAlertBody(f appFinding, meta RuleMeta, observe bool, sev int, factors []string) string {
	var b strings.Builder
	b.WriteString(f.Detail)
	b.WriteString("\n\n")
	line := func(k, v string) {
		if v != "" {
			b.WriteString(k + ": " + v + "\n")
		}
	}
	if f.Svc.ID != 0 {
		line("Service", f.Svc.Name)
		line("Environment", f.Svc.Env)
	}
	if f.InstanceID != 0 {
		line("Instance", strconv.FormatInt(f.InstanceID, 10))
	}
	line("Host", f.Host)
	if f.Route != "" {
		r := f.Route
		if f.Method != "" {
			r = f.Method + " " + r
		}
		line("Route", r)
	}
	line("Client address", f.ClientIP)
	line("User (hashed)", f.User)
	line("Trace", f.TraceID)
	line("Process lineage", f.Lineage)
	if f.Svc.ID != 0 {
		line("Telemetry tier", "T"+strconv.Itoa(f.Svc.Tier()))
	}
	line("Identity", f.Identity)
	if f.Svc.ID != 0 && !meta.Operational {
		line("Service exposure / criticality", f.Svc.Settings.EffectiveExposure()+" / "+f.Svc.Settings.Criticality)
	}
	sevNote := fmt.Sprintf("default %d", f.BaseSev)
	if len(factors) > 0 {
		sevNote += "; " + strings.Join(factors, "; ")
	}
	line("Severity", sevNote)
	if f.Degraded {
		line("Degraded input", f.DegradeNote)
	}
	if observe {
		b.WriteString("Mode: observe - shown as Info until the rule is promoted.\n")
	}
	if len(meta.ATTCK) > 0 {
		line("MITRE ATT&CK", strings.Join(meta.ATTCK, ", "))
	}
	b.WriteString("\nWhat to check: " + meta.WhatToCheck + "\n")
	if meta.FalsePositives != "" {
		b.WriteString("Likely false positives: " + meta.FalsePositives + "\n")
	}
	return b.String()
}

// appLinkEntities links the alert to everything it is about (alert_entities).
func appLinkEntities(ctx context.Context, db *store.DB, alertID int64, f appFinding) {
	link := func(kind, key string) { _ = db.LinkAlertEntity(ctx, alertID, kind, key) }
	if f.Svc.ID != 0 {
		link(EntityService, f.Svc.Key())
		if f.Route != "" {
			m := f.Method
			if m == "" {
				m = "*"
			}
			link(EntityRoute, f.Svc.Key()+"|"+m+" "+f.Route)
		}
	}
	if f.InstanceID != 0 {
		link(EntityServiceInstance, strconv.FormatInt(f.InstanceID, 10))
	}
	if f.Host != "" {
		link(EntityHost, f.Host)
	}
	if f.ClientIP != "" {
		link(EntityIP, f.ClientIP)
	}
	if f.User != "" {
		link(EntityUser, f.User)
	}
}

// appRouteKey formats a route entity key.
func appRouteKey(svc appSvc, method, route string) string {
	if method == "" {
		method = "*"
	}
	return svc.Key() + "|" + method + " " + route
}

// ── small helpers shared by the evaluators ─────────────────────────────────

func appLower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func appBaseName(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(p)
}

func appSortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// appIPClass classifies an address string.
type appIPClass int

const (
	appIPInvalid appIPClass = iota
	appIPLoopback
	appIPPrivate
	appIPLinkLocal
	appIPPublic
)

func appClassifyIP(s string) appIPClass {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return appIPInvalid
	}
	switch {
	case ip.IsLoopback() || ip.IsUnspecified():
		return appIPLoopback
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return appIPLinkLocal
	case ip.IsPrivate():
		return appIPPrivate
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10 carrier-grade NAT
		return appIPPrivate
	}
	return appIPPublic
}
