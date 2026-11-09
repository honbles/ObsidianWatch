package api

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestGateAllowlistAndSeverity(t *testing.T) {
	g := RuleGate{Enabled: true, Observe: true, Allowlist: []string{"10.0.0.9", "Build-01"}}
	ip := "10.0.0.9"
	if !gateAllowlisted(g, store.Event{DstIP: &ip}) {
		t.Fatal("allowlisted IP should skip")
	}
	if !gateAllowlisted(g, store.Event{Host: "build-01"}) {
		t.Fatal("allowlist is case-insensitive on host")
	}
	if gateAllowlisted(g, store.Event{Host: "other"}) {
		t.Fatal("non-listed host must not skip")
	}
	if GateSeverity(g, 4) != 1 {
		t.Fatal("observe mode forces Info")
	}
	g.Observe = false
	if GateSeverity(g, 4) != 4 {
		t.Fatal("promoted rule keeps severity")
	}
}

func TestRuleMetaRegistry(t *testing.T) {
	RegisterRuleMeta(RuleMeta{ID: "ZZ-TEST-1", Family: "test", Layer: "network", DefaultObserve: true, WhatToCheck: "x"})
	m, ok := RuleMetaFor("ZZ-TEST-1")
	if !ok || !m.DefaultObserve {
		t.Fatal("registered meta not found")
	}
	if _, ok := RuleMetaFor("NOPE"); ok {
		t.Fatal("unknown rule must not resolve")
	}
}
