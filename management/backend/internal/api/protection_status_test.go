package api

import (
	"encoding/json"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestProtVerdict(t *testing.T) {
	recent := time.Now().UTC().Format(time.RFC3339)
	old := time.Now().Add(-5 * time.Hour).UTC().Format(time.RFC3339)
	m := func(h, ip, d, list string) map[string]any {
		return map[string]any{"modes": map[string]any{"hash": h, "ip": ip, "domain": d}, "list_received": list}
	}
	cases := []struct {
		rep    map[string]any
		age    time.Duration
		online bool
		want   string
	}{
		{nil, time.Minute, true, "unknown"},
		{map[string]any{"enabled": false}, time.Minute, true, "off"},
		{m("enforce", "enforce", "audit", recent), time.Minute, true, "protected"},
		{m("audit", "enforce", "off", recent), time.Minute, true, "protected"},
		{m("audit", "audit", "audit", recent), time.Minute, true, "audit"},
		{m("off", "off", "off", recent), time.Minute, true, "off"},
		{map[string]any{"modes": map[string]any{"hash": "enforce"}, "list_received": recent, "list_counts": map[string]any{"hashes": 0.0, "ips": 0.0, "domains": 0.0}}, time.Minute, true, "off"}, // empty list
		{m("enforce", "enforce", "enforce", old), time.Minute, true, "audit"}, // stale list
		{m("enforce", "enforce", "enforce", recent), time.Hour, true, "unknown"},
		{m("enforce", "enforce", "enforce", recent), time.Minute, false, "unknown"},
	}
	for i, c := range cases {
		if got, _ := protVerdict(c.rep, c.age, c.online); got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}

func TestProtectionActions(t *testing.T) {
	ok := map[string]actionParams{
		"scan":            {Path: "/home/alice/Downloads"},
		"test_protection": {},
	}
	for a, p := range ok {
		if msg := validateAction(a, p); msg != "" {
			t.Errorf("%s: %s", a, msg)
		}
	}
	if validateAction("scan", actionParams{Kind: "whole"}) != "" {
		t.Error("whole-disk scan refused")
	}
	for _, p := range []actionParams{{}, {Path: "relative"}, {Kind: "everything"}} {
		if validateAction("scan", p) == "" {
			t.Errorf("bad scan accepted: %+v", p)
		}
	}
	// a protection test is never raised as an alert
	raw, _ := json.Marshal(map[string]any{"kind": "hash", "action": "quarantined", "ioc_source": prevTestSource})
	if _, ok := prevOf(store.Event{EventType: "prevention", Raw: raw}); ok {
		t.Error("test event treated as a prevention match")
	}
}

func TestPreventionAlertOutcome(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"kind": "hash", "action": "killed+quarantined", "ioc_source": "threatfox"})
	var e AlertEvidence
	json.Unmarshal(endpointEvidence("signature", store.Event{EventType: "prevention", Raw: raw}), &e)
	if e.Outcome != "killed+quarantined" {
		t.Errorf("outcome %q", e.Outcome)
	}
}
