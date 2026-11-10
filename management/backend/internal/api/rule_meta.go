package api

// rule_meta.go — rule contract metadata shared by both builds. Owned by the
// integration owner. A side registers metadata for its own rule IDs from its
// own files (see RegisterRuleMeta); it never edits ThreatSig.

import "sync"

// RuleTunable describes one adjustable parameter of a rule.
type RuleTunable struct {
	Key     string  `json:"key"`
	Label   string  `json:"label"`
	Default float64 `json:"default"`
	Unit    string  `json:"unit,omitempty"` // "s", "count", "bytes", "pct"
}

// RuleMeta is the analyst-facing contract of a rule.
type RuleMeta struct {
	ID             string        `json:"id"`
	Family         string        `json:"family"`         // e.g. "ndr-a", "app-h", "app-a", "app-x", "apm-o"
	Layer          string        `json:"layer"`          // "network" | "application" | "host" | "cross"
	Tier           int           `json:"tier,omitempty"` // application telemetry tier 0..2 (0 = n/a)
	ATTCK          []string      `json:"attck,omitempty"`
	WhatToCheck    string        `json:"what_to_check"`
	FalsePositives string        `json:"false_positives,omitempty"`
	Tunables       []RuleTunable `json:"tunables,omitempty"`
	DefaultObserve bool          `json:"default_observe"`       // true: new rules start in observe mode
	Operational    bool          `json:"operational,omitempty"` // routed separately, never mixed into the security queue
}

var (
	ruleMetaMu sync.RWMutex
	ruleMetaBy = map[string]RuleMeta{}
)

// RegisterRuleMeta registers (or replaces) metadata; call from an init().
func RegisterRuleMeta(m RuleMeta) {
	ruleMetaMu.Lock()
	ruleMetaBy[m.ID] = m
	ruleMetaMu.Unlock()
}

// RuleMetaFor returns the metadata for a rule ID.
func RuleMetaFor(id string) (RuleMeta, bool) {
	ruleMetaMu.RLock()
	defer ruleMetaMu.RUnlock()
	m, ok := ruleMetaBy[id]
	return m, ok
}

// AllRuleMeta returns a copy of every registered entry.
func AllRuleMeta() []RuleMeta {
	ruleMetaMu.RLock()
	defer ruleMetaMu.RUnlock()
	out := make([]RuleMeta, 0, len(ruleMetaBy))
	for _, m := range ruleMetaBy {
		out = append(out, m)
	}
	return out
}
