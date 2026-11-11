package api

// Helpers for the Windows credential-access and persistence rules.

import (
	"encoding/json"
	"strings"

	"obsidianwatch/management/internal/store"
)

// sysmonData returns the event_data map the agent stores in Raw.
func sysmonData(ev store.Event) map[string]string {
	if len(ev.Raw) == 0 {
		return nil
	}
	var w struct {
		EventData map[string]interface{} `json:"event_data"`
	}
	if json.Unmarshal(ev.Raw, &w) != nil {
		return nil
	}
	out := make(map[string]string, len(w.EventData))
	for k, v := range w.EventData {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// lsassAccessMasks are the GrantedAccess values credential dumpers request
// (PROCESS_VM_READ combinations and PROCESS_ALL_ACCESS).
var lsassAccessMasks = map[string]bool{
	"0x1fffff": true, "0x1f0fff": true, "0x1f1fff": true, "0x1f2fff": true, "0x1f3fff": true,
	"0x1010": true, "0x1410": true, "0x1438": true, "0x143a": true, "0x1418": true,
}

// lsassBenignAccessors are system and security components that legitimately
// open lsass.exe; they are trusted only when running from a system location.
var lsassBenignAccessors = map[string]bool{
	"msmpeng.exe": true, "csrss.exe": true, "wininit.exe": true, "services.exe": true,
	"svchost.exe": true, "taskmgr.exe": true, "werfault.exe": true, "vmtoolsd.exe": true,
	"smss.exe": true, "securityhealthservice.exe": true, "mssense.exe": true, "senseir.exe": true,
	"csfalconservice.exe": true, "sentinelagent.exe": true, "sedservice.exe": true,
}

func trustedSystemPath(p string) bool {
	p = strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	return strings.HasPrefix(p, `c:\windows\`) || strings.HasPrefix(p, `c:\program files\`) ||
		strings.HasPrefix(p, `c:\program files (x86)\`) || strings.HasPrefix(p, `c:\programdata\microsoft\windows defender\`)
}

func baseName(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// lsassAccess matches a Sysmon ProcessAccess (event 10) on lsass.exe with a
// dump-capable access mask from a process that is not a known system component.
func lsassAccess(ev store.Event) bool {
	if ev.EventID == nil || *ev.EventID != 10 {
		return false
	}
	d := sysmonData(ev)
	if !strings.HasSuffix(strings.ToLower(d["TargetImage"]), `\lsass.exe`) {
		return false
	}
	if !lsassAccessMasks[strings.ToLower(strings.TrimSpace(d["GrantedAccess"]))] {
		return false
	}
	src := d["SourceImage"]
	if lsassBenignAccessors[baseName(src)] && trustedSystemPath(src) {
		return false
	}
	return true
}

// lsassDump is the W-T1003.001 matcher. It looks at what a process does, not
// at whether the word "lsass" appears somewhere in an event: logon and log
// events routinely mention lsass.exe as the authentication provider.
func lsassDump(ev store.Event) bool {
	switch ev.EventType {
	case "process":
		if ev.EventID != nil && *ev.EventID == 10 {
			return lsassAccess(ev)
		}
		c := cl(ev)
		if containsAny(c, "sekurlsa", "mimikatz", "lsass.dmp", "out-minidump", "lsassy") {
			return true
		}
		if strings.Contains(c, "comsvcs") && strings.Contains(c, "minidump") {
			return true
		}
		if strings.Contains(c, "lsass") && containsAny(c, "procdump", "minidump", "createdump", "-ma ", "/ma ") {
			return true
		}
		return procIn(ev, "procdump.exe", "procdump64.exe") && containsAny(c, "-ma ", "/ma ", "lsass")
	case "file":
		f := fp(ev)
		return strings.Contains(f, "lsass") && strings.HasSuffix(f, ".dmp")
	}
	return false
}

// runKeyData extracts the value written to a Run key (Sysmon event 13 Details).
func runKeyData(ev store.Event) string {
	if ev.RegValue != nil && *ev.RegValue != "" {
		return strings.ToLower(*ev.RegValue)
	}
	return strings.ToLower(sysmonData(ev)["Details"])
}

func isRunKey(ev store.Event) bool {
	return ev.EventType == "registry" && containsAny(rk(ev),
		`\currentversion\run`, `\currentversion\runonce`, `policies\explorer\run`)
}

// runKeySuspicious: the autorun target lives in a user-writable location or is
// launched through a script host / LOLBin.
func runKeySuspicious(ev store.Event) bool {
	if !isRunKey(ev) {
		return false
	}
	return containsAny(runKeyData(ev), `\users\`, `\appdata\`, `\temp\`, `\programdata\`, `\public\`,
		"powershell", "cmd.exe /c", "cmd /c", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
		".vbs", ".js", ".bat", ".ps1", "http://", "https://")
}

// runKeyUntrusted: any Run key write whose target is not under Program Files
// or the Windows directory (those are the normal installer cases).
func runKeyUntrusted(ev store.Event) bool {
	if !isRunKey(ev) || runKeySuspicious(ev) {
		return false
	}
	d := strings.Trim(runKeyData(ev), `"' `)
	return !(strings.HasPrefix(d, `c:\program files`) || strings.HasPrefix(d, `c:\windows\`) || strings.HasPrefix(d, `%programfiles`) || strings.HasPrefix(d, `%systemroot%`))
}
