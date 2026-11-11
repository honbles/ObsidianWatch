package api

import (
	"strings"
	"testing"

	"obsidianwatch/management/internal/store"
)

func sigRule(t *testing.T, yml string) store.SigmaRule {
	t.Helper()
	r, err := parseSigmaRule([]byte(yml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return *r
}

func sigProc(img, cmd string) store.Event {
	return store.Event{EventType: "process", OS: "windows", Host: "h", ImagePath: &img, CommandLine: &cmd}
}

func TestSigmaEvaluator(t *testing.T) {
	oab := sigRule(t, `title: Exchange Set Oab
id: 11111111-1111-1111-1111-111111111111
status: test
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'Set-OabVirtualDirectory'
            - '-ExternalUrl'
    condition: selection
`)
	if matchSigmaRule(oab, sigProc(`C:\Windows\System32\cmd.exe`, `cmd.exe /c dir -ExternalUrl`)) {
		t.Error("|all must require every value (only one present)")
	}
	if !matchSigmaRule(oab, sigProc(`C:\x\powershell.exe`, `powershell Set-OabVirtualDirectory -Identity a -ExternalUrl http://x`)) {
		t.Error("expected match when all values present")
	}
	file := sigProc("a", "Set-OabVirtualDirectory -ExternalUrl")
	file.EventType = "file"
	if matchSigmaRule(oab, file) {
		t.Error("process_creation rule must not match file events")
	}
	linux := sigProc("a", "Set-OabVirtualDirectory -ExternalUrl")
	linux.OS = "linux"
	if matchSigmaRule(oab, linux) {
		t.Error("product windows must not match linux")
	}

	filt := sigRule(t, `title: Whoami not by admin tool
id: 22222222-2222-2222-2222-222222222222
status: stable
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    filter_main:
        CommandLine|contains: '/priv'
    condition: selection and not filter_main
`)
	if !matchSigmaRule(filt, sigProc(`C:\Windows\System32\whoami.exe`, `whoami`)) {
		t.Error("endswith should match")
	}
	if matchSigmaRule(filt, sigProc(`C:\Windows\System32\whoami.exe`, `whoami /priv`)) {
		t.Error("filter should exclude")
	}
	if matchSigmaRule(filt, sigProc(`C:\x\notwhoami.exe.txt`, `a`)) {
		t.Error("endswith must anchor")
	}

	oneOf := sigRule(t, `title: One of
id: 33333333-3333-3333-3333-333333333333
status: stable
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_a:
        Image|endswith: '\a.exe'
    selection_b:
        CommandLine|re: '(?i)-enc\s+[a-z0-9+/=]{20,}'
    condition: 1 of selection_*
`)
	if !matchSigmaRule(oneOf, sigProc(`C:\q\b.exe`, `b.exe -ENC AAAAAAAAAAAAAAAAAAAAAAAA`)) {
		t.Error("regex branch should match")
	}
	if matchSigmaRule(oneOf, sigProc(`C:\q\b.exe`, `b.exe hello`)) {
		t.Error("no branch should match")
	}

	// exact match without modifier is NOT contains
	exact := sigRule(t, `title: Exact
id: 44444444-4444-4444-4444-444444444444
status: stable
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'whoami'
    condition: selection
`)
	if matchSigmaRule(exact, sigProc("a", "whoami /all")) || !matchSigmaRule(exact, sigProc("a", "WHOAMI")) {
		t.Error("unmodified value must be an exact (case-insensitive) match")
	}

	// a field we do not collect: the rule must not fire at all (not even via a filter)
	parent := sigRule(t, `title: Parent
id: 55555555-5555-5555-5555-555555555555
status: stable
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\winword.exe'
    condition: selection
`)
	if matchSigmaRule(parent, sigProc("a", "b")) {
		t.Error("rule with unavailable field must not fire")
	}
	ev := sigProc("a", "b")
	ev.Raw = []byte(`{"event_data":{"ParentImage":"C:\\Office\\WINWORD.EXE"}}`)
	if !matchSigmaRule(parent, ev) {
		t.Error("field present in event_data should be usable")
	}

	// unsupported pieces never fire
	for name, det := range map[string]string{
		"base64":      "CommandLine|base64offset|contains: 'x'\n    condition: selection",
		"aggregation": "CommandLine|contains: 'x'\n    condition: selection | count() > 3",
		"timeframe":   "CommandLine|contains: 'x'\n    timeframe: 5m\n    condition: selection",
	} {
		r := sigRule(t, "title: U "+name+"\nid: 66666666-6666-6666-6666-666666666666\nlevel: high\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        "+det+"\n")
		if matchSigmaRule(r, sigProc("a", "x")) {
			t.Errorf("%s must not fire", name)
		}
	}

	// windows event-log (service) rule only on matching channel
	svc := sigRule(t, `title: Svc
id: 77777777-7777-7777-7777-777777777777
status: stable
level: high
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
`)
	id, ch := uint32(4625), "Security"
	e := store.Event{EventType: "logon", OS: "windows", EventID: &id, Channel: &ch}
	if !matchSigmaRule(svc, e) {
		t.Error("security-service rule should match Security channel event")
	}
	ch2 := "System"
	e.Channel = &ch2
	if matchSigmaRule(svc, e) {
		t.Error("security-service rule must not match System channel")
	}
	// ...and never on process events (the old matcher did exactly that)
	if matchSigmaRule(svc, sigProc("a", "b")) {
		t.Error("event-log rule matched a process event")
	}
}

func TestSigmaAlertSeverity(t *testing.T) {
	cases := []struct {
		status, level string
		sev           int
		want          int
		ok            bool
	}{
		{"experimental", "high", 4, 2, true},
		{"test", "critical", 5, 3, true},
		{"stable", "high", 4, 4, true},
		{"deprecated", "high", 4, 0, false},
		{"stable", "informational", 1, 0, false},
	}
	for _, c := range cases {
		got, ok := sigmaAlertSeverity(store.SigmaRule{Status: c.status, Level: c.level, Severity: c.sev})
		if got != c.want || ok != c.ok {
			t.Errorf("%+v -> %d,%v", c, got, ok)
		}
	}
	_ = strings.ToLower
}
