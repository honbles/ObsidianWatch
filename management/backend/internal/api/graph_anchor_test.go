package api

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func ip(i int) *int { return &i }

func anchorSet(as []Anchor) map[string]bool {
	m := map[string]bool{}
	for _, a := range as {
		m[a.Kind+"="+a.Key] = true
	}
	return m
}

func TestDeriveAnchors(t *testing.T) {
	// process with GUID leads; logon and user also anchored
	ev := store.Event{AgentID: "a1", Host: "h1", EventType: "process", ProcessGUID: "{G}", LogonID: sp("0x1F4"), UserName: sp("Bob")}
	as := deriveAnchors(ev)
	if len(as) < 2 || as[0] != (Anchor{EntityProcess, "a1|{G}"}) {
		t.Fatalf("primary anchor: %+v", as)
	}
	if !anchorSet(as)["logon=a1|0x1f4"] {
		t.Errorf("logon anchor missing: %+v", as)
	}
	if anchorSet(as)["user=bob"] {
		t.Errorf("process events must not anchor user: %+v", as)
	}

	// no GUID: pid fallback
	as = deriveAnchors(store.Event{AgentID: "a1", EventType: "process", PID: ip(42), ProcessName: sp("Foo.exe")})
	if as[0].Key != "a1|pid:42|foo.exe" {
		t.Errorf("pid fallback: %+v", as)
	}

	// auth event leads with identity, not process
	as = deriveAnchors(store.Event{AgentID: "a1", Host: "h1", EventType: "logon", UserName: sp("Admin"), SrcIP: sp("203.0.113.9")})
	if as[0] != (Anchor{EntityUser, "admin"}) || !anchorSet(as)["ip=203.0.113.9"] {
		t.Errorf("auth anchors: %+v", as)
	}

	// network: ip vs domain; file; registry
	if !anchorSet(deriveAnchors(store.Event{AgentID: "a", EventType: "network", DstIP: sp("8.8.8.8")}))["ip=8.8.8.8"] {
		t.Error("network ip")
	}
	if !anchorSet(deriveAnchors(store.Event{AgentID: "a", EventType: "dns", DstIP: sp("Evil.Example.com")}))["domain=evil.example.com"] {
		t.Error("dns domain")
	}
	if !anchorSet(deriveAnchors(store.Event{AgentID: "a", Host: "h", EventType: "file", FilePath: sp("/Tmp/X")}))["file=h|/tmp/x"] {
		t.Error("file")
	}
	if !anchorSet(deriveAnchors(store.Event{AgentID: "a", Host: "h", EventType: "registry", RegKey: sp(`HKLM\Run`)}))[`reg=h|hklm\run`] {
		t.Error("registry")
	}
	// nothing derivable -> empty, never panics
	if got := deriveAnchors(store.Event{}); len(got) != 0 {
		t.Errorf("empty event: %+v", got)
	}
}
