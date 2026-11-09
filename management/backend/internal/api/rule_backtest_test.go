package api

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestBacktestEvents(t *testing.T) {
	sig := ThreatSig{ID: "T-1", Match: func(ev store.Event) bool { return ev.EventType == "process" }}
	evs := []store.Event{{ID: "1", Host: "a", EventType: "process"}, {ID: "2", Host: "a", EventType: "dns"}, {ID: "3", Host: "b", EventType: "process"}}
	n, hosts, samples := backtestEvents(sig, evs)
	if n != 2 || hosts["a"] != 1 || hosts["b"] != 1 || len(samples) != 2 {
		t.Fatalf("%d %v %v", n, hosts, samples)
	}
	bad := ThreatSig{ID: "T-2", Match: func(ev store.Event) bool { panic("boom") }}
	if n, _, _ := backtestEvents(bad, evs); n != 0 {
		t.Fatal("panicking matcher must count as no match")
	}
}

func TestFindSignature(t *testing.T) {
	if _, ok := findSignature("C-AWS-048"); !ok {
		t.Fatal("registered rule not found")
	}
	if _, ok := findSignature("NOPE-999"); ok {
		t.Fatal("unknown rule must not be found")
	}
}
