package api

// engine_hooks.go — the only integration points the Network and Application
// builds have into the detection engine. Owned by the integration owner.
// A side registers from an init() in its own file; it never edits the engine.

import (
	"context"
	"strings"
	"sync"

	"obsidianwatch/management/internal/store"
)

var (
	hookMu           sync.RWMutex
	sigProviders     []func(ev store.Event) []ThreatSig
	entityExtractors []func(ev store.Event) map[string][]string
	scopeResolvers   []func(ev store.Event) (kind, id string)
)

// RegisterSigProvider adds rules evaluated for any event the provider returns
// signatures for (return nil to opt out). Called once per event.
func RegisterSigProvider(f func(ev store.Event) []ThreatSig) {
	hookMu.Lock()
	sigProviders = append(sigProviders, f)
	hookMu.Unlock()
}

// RegisterEntityExtractor maps an event to the alert-entity links created when
// an alert is raised from it: kind -> keys (kinds are in entity_kinds.go).
func RegisterEntityExtractor(f func(ev store.Event) map[string][]string) {
	hookMu.Lock()
	entityExtractors = append(entityExtractors, f)
	hookMu.Unlock()
}

// RegisterScopeResolver maps an event to the rule_settings scope that applies
// (e.g. "service", "web|prod"). Return "" for global scope only.
func RegisterScopeResolver(f func(ev store.Event) (kind, id string)) {
	hookMu.Lock()
	scopeResolvers = append(scopeResolvers, f)
	hookMu.Unlock()
}

func extraSignaturesFor(ev store.Event) []ThreatSig {
	hookMu.RLock()
	defer hookMu.RUnlock()
	var out []ThreatSig
	for _, p := range sigProviders {
		out = append(out, p(ev)...)
	}
	return out
}

// engineGate applies the rule contract to a rule that has registered
// RuleMeta: disabled or allowlisted => skip; observe mode => severity 1.
// Rules without RuleMeta (all pre-existing rules) are untouched.
func engineGate(ctx context.Context, db *store.DB, ruleID string, ev store.Event) (adjust func(int) int, skip bool) {
	if _, ok := RuleMetaFor(ruleID); !ok {
		return func(s int) int { return s }, false
	}
	scopeKind, scopeID := "", ""
	hookMu.RLock()
	for _, r := range scopeResolvers {
		if k, id := r(ev); k != "" {
			scopeKind, scopeID = k, id
			break
		}
	}
	hookMu.RUnlock()
	g := ruleGate(ctx, db, ruleID, scopeKind, scopeID)
	if !g.Enabled || gateAllowlisted(g, ev) {
		return nil, true
	}
	return func(s int) int { return GateSeverity(g, s) }, false
}

func gateAllowlisted(g RuleGate, ev store.Event) bool {
	if len(g.Allowlist) == 0 {
		return false
	}
	vals := []string{ev.Host}
	for _, p := range []*string{ev.SrcIP, ev.DstIP, ev.ProcessName, ev.UserName} {
		if p != nil {
			vals = append(vals, *p)
		}
	}
	for _, a := range g.Allowlist {
		for _, v := range vals {
			if v != "" && strings.EqualFold(a, v) {
				return true
			}
		}
	}
	return false
}

// engineLinkEntities records the alert-entity links for a freshly created alert.
func engineLinkEntities(ctx context.Context, db *store.DB, alertID int64, ev store.Event) {
	hookMu.RLock()
	defer hookMu.RUnlock()
	for _, x := range entityExtractors {
		for kind, keys := range x(ev) {
			for _, k := range keys {
				_ = db.LinkAlertEntity(ctx, alertID, kind, k)
			}
		}
	}
}
