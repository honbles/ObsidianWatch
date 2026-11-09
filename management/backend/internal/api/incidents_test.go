package api

import (
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestBuildIncidents(t *testing.T) {
	t0 := time.Now().Add(-10 * time.Hour)
	mk := func(id int64, host string, sev int, off time.Duration, et string) store.Alert {
		return store.Alert{ID: id, Host: host, Severity: sev, CreatedAt: t0.Add(off), EventType: et, Title: "t"}
	}
	inc := buildIncidents([]store.Alert{
		mk(1, "a", 5, 0, "process"), mk(2, "a", 3, time.Hour, "network"),
		mk(3, "a", 3, 6*time.Hour, "process"), // new incident (gap > 2h)
		mk(4, "b", 1, 0, "process"),
	})
	if len(inc) != 3 {
		t.Fatalf("want 3 incidents, got %d", len(inc))
	}
	if inc[0].Host != "a" || inc[0].AlertCount != 2 || inc[0].MaxSev != 5 {
		t.Fatalf("top incident wrong: %+v", inc[0])
	}
}

func TestApplyIncidentState(t *testing.T) {
	inc := []Incident{{ID: "inc-a"}, {ID: "inc-b"}, {ID: "inc-c"}}
	st := map[string]IncidentState{"inc-b": {Status: "resolved"}, "inc-c": {Status: "investigating", Owner: "sam"}}
	if got := applyIncidentState(inc, st, ""); len(got) != 2 {
		t.Fatalf("default should hide resolved, got %d", len(got))
	}
	if got := applyIncidentState(inc, st, "all"); len(got) != 3 {
		t.Fatalf("all: %d", len(got))
	}
	got := applyIncidentState(inc, st, "investigating")
	if len(got) != 1 || got[0].State.Owner != "sam" {
		t.Fatalf("investigating: %+v", got)
	}
}

func TestIdentityNames(t *testing.T) {
	al := map[string][]string{"alice": {"alice@corp.com", "alice-gh", `CORP\a.smith`}}
	for _, who := range []string{"alice", "ALICE@corp.com", "alice-gh", `corp\a.smith`} {
		n := identityNames(who, al)
		// normUser strips the domain, so alice@corp.com collapses into alice.
		if len(n) != 3 || !n["alice-gh"] || !n["a.smith"] || !n["alice"] {
			t.Errorf("%s: group %v", who, n)
		}
	}
	if n := identityNames("bob", al); len(n) != 1 || !n["bob"] {
		t.Errorf("unlinked user: %v", n)
	}
	clean := sanitizeAliases(map[string][]string{" a ": {" b ", ""}, "": {"x"}, "c": {}})
	if len(clean) != 1 || clean["a"][0] != "b" {
		t.Errorf("sanitize: %v", clean)
	}
}
