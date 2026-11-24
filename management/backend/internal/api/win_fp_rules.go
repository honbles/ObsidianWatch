package api

// win_fp_rules.go - Windows and domain-controller matchers rewritten to cut
// false positives. Each function replaces the inline Match body of the rule of
// the same name in detection_engine.go.

import (
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

var (
	officeParents  = map[string]bool{"winword.exe": true, "excel.exe": true, "powerpnt.exe": true, "outlook.exe": true, "onenote.exe": true, "mspub.exe": true}
	browserParents = map[string]bool{"chrome.exe": true, "msedge.exe": true, "firefox.exe": true, "iexplore.exe": true, "brave.exe": true}
	// Management agents that legitimately launch encoded PowerShell.
	mgmtParents      = map[string]bool{"ccmexec.exe": true, "ccmsetup.exe": true, "intunemanagementextension.exe": true, "agentexecutor.exe": true, "senseir.exe": true}
	userWritableDirs = []string{`\temp\`, `%temp%`, `\appdata\`, `\downloads\`, `\users\public\`}
	// Hosts whose documented installers pipe a download into PowerShell.
	psInstallerHosts = []string{"community.chocolatey.org", "chocolatey.org/install.ps1", "get.scoop.sh", "raw.githubusercontent.com/scoopinstaller"}
)

// winParent is the lower-case base name (with .exe) of the parent image, from
// Sysmon ParentImage or the 4688 ParentProcessName field.
func winParent(ev store.Event) string {
	d := sysmonData(ev)
	for _, k := range []string{"ParentImage", "ParentProcessName"} {
		if v := d[k]; v != "" {
			return baseName(v)
		}
	}
	return ""
}

func winRegsvr32Squiblydoo(ev store.Event) bool {
	if ev.EventType != "process" || !procIn(ev, "regsvr32") {
		return false
	}
	c := cl(ev)
	return strings.Contains(c, "scrobj") ||
		(strings.Contains(c, "/i:") && strings.Contains(c, "http")) ||
		(strings.Contains(c, "/n ") && strings.Contains(c, "/u "))
}

func winUACBypass(ev store.Event) bool {
	if ev.EventType == "registry" {
		return containsAny(rk(ev), `\classes\ms-settings\shell\open\command`, `\classes\mscfile\shell\open\command`,
			`\classes\exefile\shell\open\command`, `\classes\folder\shell\open\command`)
	}
	if ev.EventType != "process" {
		return false
	}
	switch winParent(ev) {
	case "eventvwr.exe", "fodhelper.exe", "sdclt.exe", "computerdefaults.exe":
		return procIn(ev, "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32")
	}
	return false
}

func winSAMAccess(ev store.Event) bool {
	return containsAny(fp(ev)+rk(ev)+cl(ev),
		`sam\sam\domains`, `reg save hklm\sam`, `reg save hklm\system`, `reg save hklm\security`,
		`reg save hkey_local_machine\sam`, `reg save hkey_local_machine\system`, `\config\sam`)
}

func winOfficeChild(ev store.Event) bool {
	if ev.EventType != "process" {
		return false
	}
	if !procIn(ev, "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32") {
		return false
	}
	return officeParents[winParent(ev)]
}

func winRundll32Susp(ev store.Event) bool {
	if ev.EventType != "process" || !procIn(ev, "rundll32") {
		return false
	}
	c := cl(ev)
	if containsAny(c, "javascript:", "vbscript:", "mshtml", "comsvcs.dll,minidump", "comsvcs.dll, minidump", "comsvcs.dll,#24") {
		return true
	}
	if strings.Contains(c, "advpack") && strings.Contains(c, "launchinfsection") && containsAny(c, userWritableDirs...) {
		return true
	}
	return containsAny(c, `\temp\`, `\downloads\`, `\users\public\`) && strings.Contains(c, ".dll")
}

func winPSEncoded(ev store.Event) bool {
	if ev.EventType != "process" || !containsAny(cl(ev), "-enc ", "-encodedcommand", "-e jab", "-e sqb") {
		return false
	}
	p := winParent(ev)
	return !mgmtParents[p] && !strings.Contains(p, "ansible")
}

var psDownloadTokens = []string{"downloadstring", "downloadfile", "webclient", "invoke-webrequest", "iwr ", "invoke-restmethod", "irm ", "start-bitstransfer"}
var psExecTokens = []string{"iex ", "iex(", "|iex", "invoke-expression", "start-process"}

// winPSCradle: a download that is also executed, from a host that is not a
// documented installer. Download-only commands are W-T1059.001d.
func winPSCradle(ev store.Event) bool {
	if ev.EventType != "process" {
		return false
	}
	c := cl(ev)
	if !containsAny(c, psDownloadTokens...) ||
		!(containsAny(c, psExecTokens...) || strings.HasSuffix(strings.TrimSpace(c), "iex")) {
		return false
	}
	return !containsAny(c, psInstallerHosts...)
}

func winPSDownloadOnly(ev store.Event) bool {
	if ev.EventType != "process" || !procIn(ev, "powershell", "pwsh") {
		return false
	}
	c := cl(ev)
	return containsAny(c, psDownloadTokens...) && !winPSCradle(ev)
}

func winObfuscated(ev store.Event) bool {
	if ev.EventType != "process" {
		return false
	}
	c := cl(ev)
	if containsAny(c, "frombase64string", "`i`e`x") {
		return true
	}
	return procIn(ev, "cmd") && strings.Count(c, "^") > 15
}

func winSchedTask(ev store.Event) bool {
	if ev.EventType == "process" && ev.EventID == nil && containsAny(cl(ev), "schtasks /create", "new-scheduledtask") {
		return true
	}
	if ev.EventID == nil || *ev.EventID != 4698 { // 4702 (update) dropped: Windows churns tasks constantly
		return false
	}
	name := strings.ToLower(sysmonData(ev)["TaskName"])
	if strings.HasPrefix(name, `\microsoft\windows\`) || strings.HasPrefix(name, `\microsoft\office\`) ||
		containsAny(name, "googleupdate", "microsoftedgeupdate", "onedrive", "adobeacrobatupdate") {
		return false
	}
	raw := rawStr(ev)
	return containsAny(raw, userWritableDirs...) ||
		containsAny(raw, "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "bitsadmin", "certutil")
}

func winWScript(ev store.Event) bool {
	if ev.EventType != "process" || !procIn(ev, "wscript", "cscript") {
		return false
	}
	c := cl(ev)
	if containsAny(c, userWritableDirs...) || strings.Contains(c, "//e:") {
		return true
	}
	p := winParent(ev)
	return officeParents[p] || browserParents[p]
}

var masqSystem32 = map[string]bool{"svchost.exe": true, "lsass.exe": true, "winlogon.exe": true, "csrss.exe": true,
	"services.exe": true, "smss.exe": true, "wininit.exe": true}

func winMasquerade(ev store.Event) bool {
	i := img(ev)
	if i == "" || len(i) < 3 || i[1] != ':' {
		return false
	}
	name := baseName(proc(ev))
	if !strings.HasSuffix(name, ".exe") {
		name += ".exe"
	}
	rest := i[2:]
	switch {
	case masqSystem32[name]:
		return !strings.HasPrefix(rest, `\windows\system32\`) && !strings.HasPrefix(rest, `\windows\syswow64\`)
	case name == "explorer.exe":
		return !strings.HasPrefix(rest, `\windows\`)
	}
	return false
}

func winScanner(ev store.Event) bool {
	if ev.EventType != "process" || !procIn(ev, "nmap", "masscan", "rustscan", "nikto", "nessus", "nessuscli") {
		return false
	}
	return !strings.Contains(img(ev), `\tenable\`) // Tenable Nessus Agent
}

func winDLLWritable(ev store.Event) bool {
	if ev.EventType != "file" || !strings.HasSuffix(fp(ev), ".dll") {
		return false
	}
	if procIn(ev, "csc", "powershell", "pwsh") { // compilers / scripts legitimately drop DLLs
		return false
	}
	return containsAny(fp(ev), `\downloads\`, `\desktop\`, `\users\public\`)
}

var ransomExts = []string{".locked", ".encrypted", ".crypto", ".crypt", ".enc", ".ransom", ".locky"}

const (
	ransomBurstN      = 20
	ransomBurstWindow = 60 * time.Second
)

// winRansomRenames: files given a ransomware extension, at least 20 distinct
// files by the same process on the same host within 60 s. A single ".enc" file
// is ordinary application data.
func winRansomRenames(ev store.Event) bool {
	if ev.EventType != "file" {
		return false
	}
	p := fp(ev)
	ext := ""
	for _, e := range ransomExts {
		if strings.HasSuffix(p, e) {
			ext = e
			break
		}
	}
	if ext == "" {
		return false
	}
	return bursts.count("ransom|"+ev.Host+"|"+proc(ev)+"|"+ext, p, ev.Time, ransomBurstWindow) >= ransomBurstN
}

// ── Domain controller ────────────────────────────────────────────────────────

func kerbRC4(ev store.Event) bool {
	if ev.EventType != "kerberos" || ev.EventID == nil || *ev.EventID != 4769 {
		return false
	}
	switch strings.ToLower(sysmonData(ev)["TicketEncryptionType"]) {
	case "0x17", "0x18":
	default:
		return false
	}
	if ev.ProcessName != nil {
		sn := strings.ToLower(*ev.ProcessName)
		if strings.HasSuffix(sn, "$") || sn == "krbtgt" {
			return false
		}
	}
	return !(ev.UserName != nil && strings.HasSuffix(*ev.UserName, "$"))
}

// dcKerberoastBurst: RC4 tickets for 5 or more distinct SPNs by one account
// from one source within 5 minutes.
func dcKerberoastBurst(ev store.Event) bool {
	if !kerbRC4(ev) {
		return false
	}
	user, src, svc := "", "", ""
	if ev.UserName != nil {
		user = strings.ToLower(*ev.UserName)
	}
	if ev.SrcIP != nil {
		src = *ev.SrcIP
	}
	if ev.ProcessName != nil {
		svc = strings.ToLower(*ev.ProcessName)
	}
	return bursts.count("kerberoast|"+user+"|"+src, svc, ev.Time, 5*time.Minute) >= 5
}

func dcASREP(ev store.Event) bool {
	if ev.EventType != "kerberos" || ev.EventID == nil || *ev.EventID != 4768 {
		return false
	}
	if ev.UserName != nil && strings.HasSuffix(*ev.UserName, "$") {
		return false
	}
	return sysmonData(ev)["PreAuthType"] == "0"
}

var dcSyncSafeAccounts = []string{"msol_", "aad_", "azure atp", "mdi-", "mdi_", "adsync"}

func dcSync(ev store.Event) bool {
	if ev.EventType != "ad_object_access" {
		return false
	}
	d := sysmonData(ev)
	props := strings.ToLower(d["Properties"])
	if ev.CommandLine != nil {
		props += " " + strings.ToLower(*ev.CommandLine)
	}
	// DS-Replication-Get-Changes / -All / -In-Filtered-Set rights GUIDs.
	if !containsAny(props, "1131f6aa", "1131f6ad", "89e95b76") {
		return false
	}
	user := strings.ToLower(d["SubjectUserName"])
	if user == "" && ev.UserName != nil {
		user = strings.ToLower(*ev.UserName)
	}
	if strings.HasSuffix(user, "$") || containsAny(user, dcSyncSafeAccounts...) {
		return false
	}
	return true
}
