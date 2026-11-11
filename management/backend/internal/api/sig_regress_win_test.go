package api

// Regression tests for false positives seen on a real Windows host:
// "LSASS Memory Dump" criticals on logon and raw events, Run key and service
// alerts from normal installs.

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestLsassRuleIgnoresMentionsInNonProcessEvents(t *testing.T) {
	sig, _ := fxFind("W-T1003.001")
	raw := []byte(`{"event_data":{"LogonProcessName":"C:\\Windows\\System32\\lsass.exe","Message":"trusted logon process registered by lsass"}}`)
	for _, typ := range []string{"logon", "raw", "eventlog", "network"} {
		if sig.Match(store.Event{EventType: typ, Raw: raw}) {
			t.Errorf("a %s event that merely mentions lsass must not fire", typ)
		}
	}
	// a process whose command line mentions lsass in a harmless way
	if sig.Match(fxProc("tasklist.exe", "tasklist /fi \"imagename eq lsass.exe\"")) {
		t.Error("listing lsass is not a dump")
	}
	for _, cmd := range []string{
		"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\t\\a.dmp full",
		"mimikatz.exe sekurlsa::logonpasswords",
		"procdump64.exe -accepteula -ma lsass.exe l.dmp",
	} {
		if !sig.Match(fxProc("x.exe", cmd)) {
			t.Errorf("dump command should fire: %s", cmd)
		}
	}
	if !sig.Match(fxFile(`C:\Users\a\AppData\Local\Temp\lsass.DMP`)) {
		t.Error("lsass dump file should fire")
	}
}

func TestLsassAccessMasksAndAllowlist(t *testing.T) {
	sig, _ := fxFind("W-T1003.001")
	target := `C:\Windows\System32\lsass.exe`
	if sig.Match(fxSysmonAccess(`C:\Users\a\x.exe`, target, "0x1000")) {
		t.Error("a benign access mask must not fire")
	}
	if sig.Match(fxSysmonAccess(`C:\Windows\System32\svchost.exe`, target, "0x1410")) {
		t.Error("system svchost is a normal accessor")
	}
	if !sig.Match(fxSysmonAccess(`C:\Users\Public\svchost.exe`, target, "0x1410")) {
		t.Error("svchost.exe outside system paths is masquerading and must fire")
	}
	if sig.Match(fxSysmonAccess(`C:\Users\a\x.exe`, `C:\Windows\System32\notepad.exe`, "0x1fffff")) {
		t.Error("only lsass.exe as the target counts")
	}
}

func TestRunKeySplit(t *testing.T) {
	hi, _ := fxFind("W-T1547.001")
	lo, _ := fxFind("W-T1547.001b")
	key := `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x`
	trusted := fxRegData(key, `"C:\Program Files\App\app.exe" --minimized`)
	if hi.Match(trusted) || lo.Match(trusted) {
		t.Error("Program Files autostart must not alert")
	}
	script := fxRegData(key, `powershell -w hidden -c iex(...)`)
	if !hi.Match(script) || lo.Match(script) {
		t.Error("script-host autostart is high severity only")
	}
	other := fxRegData(key, `D:\Tools\x.exe`)
	if hi.Match(other) || !lo.Match(other) {
		t.Error("untrusted-path autostart is the low-severity entry")
	}
}

func TestServiceInstallIgnoresOwnComponents(t *testing.T) {
	sig, _ := fxFind("W-T1543.003b")
	mk := func(img string) store.Event {
		id := uint32(7045)
		return store.Event{EventType: "process", EventID: &id, Raw: []byte(`{"event_data":{"ImagePath":` + jsonStr(img) + `}}`)}
	}
	if sig.Match(mk(`C:\ProgramData\ObsidianWatch\obsidianwatch-agent.exe`)) {
		t.Error("the agent's own service must not alert")
	}
	if !sig.Match(mk(`C:\Users\Public\evil.exe`)) {
		t.Error("service from a public directory should alert")
	}
}

func TestCredentialSearchNeedsSearchBehaviour(t *testing.T) {
	sig, _ := fxFind("W-T1552.001")
	for _, c := range []string{`chrome.exe --user-data-dir=C:\x\credential`, `keepass.exe c:\db.kdbx`, `app.exe --vault-path x`} {
		if sig.Match(fxProc("x.exe", c)) {
			t.Errorf("must not fire on %q", c)
		}
	}
}

func TestSecurityServiceStopIgnoresEventLogAndSubstrings(t *testing.T) {
	sig, _ := fxFind("W-T1562.001d")
	mk := func(name, state string) store.Event {
		id := uint32(7036)
		return store.Event{EventType: "eventlog", EventID: &id, Raw: []byte(`{"event_data":{"param1":` + jsonStr(name) + `,"param2":` + jsonStr(state) + `}}`)}
	}
	if sig.Match(mk("Windows Event Log", "stopped")) {
		t.Error("Event Log stops on every shutdown and must not alert")
	}
	if sig.Match(mk("Windows License Manager Service", "stopped")) {
		t.Error("unrelated service must not alert")
	}
	if !sig.Match(mk("Microsoft Defender Antivirus Service", "stopped")) || !sig.Match(mk("Sysmon64", "stopped")) {
		t.Error("security service stopping must alert")
	}
	if sig.Match(mk("Sysmon64", "running")) {
		t.Error("running state must not alert")
	}
}
