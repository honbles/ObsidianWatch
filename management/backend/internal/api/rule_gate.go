package api

// rule_gate.go — runtime gate for rules shared by both builds. Owned by the
// integration owner. Every NET-/APP- rule evaluator calls ruleGate before it
// raises an alert, and passes the severity through GateSeverity.

import (
	"context"
	"encoding/json"

	"obsidianwatch/management/internal/store"
)

// RuleGate is the effective setting for one rule in one scope.
type RuleGate struct {
	Enabled   bool
	Observe   bool
	Params    map[string]float64
	Allowlist []string
}

// Param returns a tunable, falling back to def.
func (g RuleGate) Param(key string, def float64) float64 {
	if v, ok := g.Params[key]; ok {
		return v
	}
	return def
}

// ruleGate resolves the effective setting: a scoped row wins over the global
// row; with no row the rule is enabled and takes DefaultObserve from its
// RuleMeta (observe when unknown).
func ruleGate(ctx context.Context, db *store.DB, ruleID, scopeKind, scopeID string) RuleGate {
	g := RuleGate{Enabled: true, Observe: true, Params: map[string]float64{}}
	if m, ok := RuleMetaFor(ruleID); ok {
		g.Observe = m.DefaultObserve
	}
	rows, err := db.ListRuleSettings(ctx, ruleID)
	if err != nil {
		return g
	}
	apply := func(s store.RuleSetting) {
		g.Enabled, g.Observe = s.Enabled, s.Observe
		var p map[string]float64
		if json.Unmarshal(s.Params, &p) == nil && p != nil {
			g.Params = p
		}
		var a []string
		if json.Unmarshal(s.Allowlist, &a) == nil {
			g.Allowlist = a
		}
	}
	for _, s := range rows {
		if s.ScopeKind == "" {
			apply(s)
		}
	}
	for _, s := range rows {
		if scopeKind != "" && s.ScopeKind == scopeKind && s.ScopeID == scopeID {
			apply(s)
		}
	}
	return g
}

// GateSeverity applies observe mode: observe-mode rules always show as Info (1).
func GateSeverity(g RuleGate, sev int) int {
	if g.Observe {
		return 1
	}
	return sev
}
