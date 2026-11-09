package api

import (
	"strings"
	"testing"
	"unicode/utf8"

	"obsidianwatch/backend/pkg/schema"
)

func TestCapStrRuneSafe(t *testing.T) {
	s := strings.Repeat("é", 10) // 2 bytes per rune
	got := capStr(s, 4)
	if utf8.RuneCountInString(got) != 4 || !utf8.ValidString(got) {
		t.Fatalf("got %q", got)
	}
	if capStr("abc", 10) != "abc" {
		t.Fatal("short string must pass through")
	}
}

func TestSanitizeEvent(t *testing.T) {
	e := &schema.Event{CommandLine: strings.Repeat("a", maxCmdLineRunes+50), Host: "h"}
	e.Raw = []byte(strings.Repeat("x", maxRawBytes+1))
	if !sanitizeEvent(e) {
		t.Fatal("expected change")
	}
	if len(e.CommandLine) != maxCmdLineRunes {
		t.Fatalf("cmdline len %d", len(e.CommandLine))
	}
	if !strings.Contains(string(e.Raw), "truncated") {
		t.Fatalf("raw not stubbed: %s", e.Raw)
	}
	ok := &schema.Event{Host: "h", CommandLine: "ls"}
	if sanitizeEvent(ok) {
		t.Fatal("clean event must be unchanged")
	}
}

func TestAgentThrottle(t *testing.T) {
	th := &agentThrottle{m: map[string]*agentBucket{}}
	if !th.allow("a", int(agentBurstEvents)) {
		t.Fatal("burst should be allowed")
	}
	if th.allow("a", int(agentBurstEvents)) {
		t.Fatal("second full burst immediately must be refused")
	}
	if !th.allow("b", 10) {
		t.Fatal("other agents are independent")
	}
}
