package api

// Endpoint compliance catalog. Agents report only {id, status, detail} for
// each check they can evaluate (vulnerability.scan -> "posture"); the titles,
// severities and remediation text live here so they can be improved without
// redeploying agents, and an agent that does not know a check simply omits it.
//
// Status values: pass | fail | unknown (agent could not determine it, for
// example because a command is missing or needs rights it does not have).
// Unknown is shown separately and never counted as a pass.

import (
	"encoding/json"
	"sort"
	"strings"
)

type postureDef struct {
	Title    string
	Category string
	Severity string
	Fix      string
	OS       string // windows | macos | linux
}

var endpointPostureCatalog = map[string]postureDef{
	// ── Windows ──
	"EC-W-001": {"Antivirus product is installed and active", "Antivirus", "critical", "Install or re-enable an antivirus/EDR product (Windows Security, Defender, or your corporate agent).", "windows"},
	"EC-W-002": {"Defender real-time protection is on", "Antivirus", "critical", "Set-MpPreference -DisableRealtimeMonitoring $false (or confirm a third-party AV is the active provider).", "windows"},
	"EC-W-003": {"Antivirus signatures are up to date (7 days)", "Antivirus", "high", "Run Update-MpSignature or check the update channel / proxy for the AV product.", "windows"},
	"EC-W-004": {"Defender tamper protection is on", "Antivirus", "medium", "Enable Tamper Protection in Windows Security > Virus & threat protection settings.", "windows"},
	"EC-W-005": {"Windows Firewall is on for all profiles", "Network", "high", "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True", "windows"},
	"EC-W-006": {"System drive is encrypted (BitLocker)", "Data protection", "high", "Enable BitLocker on the OS drive and escrow the recovery key.", "windows"},
	"EC-W-007": {"Windows updates installed in the last 45 days", "Patching", "high", "Run Windows Update; check WSUS/Intune policy if updates are not arriving.", "windows"},
	"EC-W-008": {"User Account Control (UAC) is enabled", "Permissions", "high", `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f`, "windows"},
	"EC-W-009": {"SMBv1 is disabled", "Network", "high", "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force", "windows"},
	"EC-W-010": {"RDP requires Network Level Authentication (or RDP is off)", "Network", "high", "Enable 'Require user authentication for remote connections' or disable Remote Desktop.", "windows"},
	"EC-W-011": {"Guest account is disabled", "Permissions", "medium", "net user Guest /active:no", "windows"},
	"EC-W-012": {"Built-in Administrator account is disabled", "Permissions", "medium", "net user Administrator /active:no (use named admin accounts or LAPS).", "windows"},
	"EC-W-013": {"Local Administrators group has 3 or fewer members", "Permissions", "medium", "Remove users that do not need admin rights from the local Administrators group.", "windows"},
	"EC-W-014": {"Minimum password length is at least 14", "Password policy", "medium", "Set the minimum password length to 14 via Group Policy or net accounts /minpwlen:14.", "windows"},
	"EC-W-015": {"Account lockout threshold is set (1-10 attempts)", "Password policy", "medium", "net accounts /lockoutthreshold:5", "windows"},
	"EC-W-016": {"Screen locks after 15 minutes or less", "Permissions", "low", "Set 'Interactive logon: Machine inactivity limit' to 900 seconds or less.", "windows"},
	"EC-W-017": {"Secure Boot is enabled", "Platform", "medium", "Enable Secure Boot in UEFI firmware settings.", "windows"},
	"EC-W-018": {"TPM is present and ready", "Platform", "low", "Enable the TPM in firmware; required for BitLocker and Credential Guard.", "windows"},
	"EC-W-019": {"PowerShell script block logging is enabled", "Logging", "medium", "Enable 'Turn on PowerShell Script Block Logging' via Group Policy.", "windows"},
	"EC-W-020": {"AutoRun is disabled for removable drives", "Hardening", "medium", `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f`, "windows"},
	"EC-W-021": {"LSA protection (RunAsPPL) is enabled", "Hardening", "medium", `reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f (reboot required).`, "windows"},
	"EC-W-022": {"Logon/Logoff auditing records success and failure", "Logging", "low", `auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable`, "windows"},

	// ── macOS ──
	"EC-M-001": {"FileVault disk encryption is on", "Data protection", "high", "Turn on FileVault in System Settings > Privacy & Security.", "macos"},
	"EC-M-002": {"System Integrity Protection (SIP) is enabled", "Hardening", "critical", "Boot to Recovery and run: csrutil enable", "macos"},
	"EC-M-003": {"Gatekeeper is enabled", "Hardening", "high", "sudo spctl --master-enable", "macos"},
	"EC-M-004": {"Application firewall is on", "Network", "high", "System Settings > Network > Firewall, or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on", "macos"},
	"EC-M-005": {"Automatic update checks are on", "Patching", "medium", "System Settings > General > Software Update > Automatic updates.", "macos"},
	"EC-M-006": {"Remote Login (SSH) is off", "Network", "medium", "sudo systemsetup -setremotelogin off", "macos"},
	"EC-M-007": {"Guest account is disabled", "Permissions", "medium", "sudo sysadminctl -guestAccount off", "macos"},
	"EC-M-008": {"Screen Sharing / Remote Management is off", "Network", "medium", "Turn off Screen Sharing and Remote Management in System Settings > General > Sharing.", "macos"},
	"EC-M-009": {"Only expected users have admin rights", "Permissions", "medium", "Remove users that do not need admin rights from the 'admin' group (dseditgroup -o edit -d USER -t user admin).", "macos"},

	// ── Linux ──
	"EC-L-001": {"Root filesystem is on encrypted storage (LUKS)", "Data protection", "medium", "Use full-disk encryption (LUKS) for laptops and hosts holding sensitive data.", "linux"},
	"EC-L-002": {"A mandatory access control system is enforcing (SELinux / AppArmor)", "Hardening", "medium", "Enable SELinux in enforcing mode or AppArmor profiles for exposed services.", "linux"},
	"EC-L-003": {"Host firewall is active", "Network", "high", "Enable ufw, firewalld or an nftables ruleset with a default-deny inbound policy.", "linux"},
	"EC-L-004": {"SSH root login is disabled", "Permissions", "high", "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.", "linux"},
	"EC-L-005": {"SSH password authentication is disabled", "Permissions", "medium", "Set 'PasswordAuthentication no' and use keys.", "linux"},
	"EC-L-006": {"ASLR is fully enabled", "Hardening", "medium", "sysctl -w kernel.randomize_va_space=2", "linux"},
	"EC-L-007": {"Only root has UID 0", "Permissions", "critical", "Investigate and remove any other UID 0 account; it is a full-privilege backdoor.", "linux"},
	"EC-L-008": {"No account has an empty password", "Password policy", "critical", "Lock or set a password for every account (passwd -l USER).", "linux"},
	"EC-L-009": {"An antivirus / EDR agent is installed", "Antivirus", "medium", "Install ClamAV or your organisation's EDR agent.", "linux"},
	"EC-L-010": {"No passwordless sudo for all commands", "Permissions", "medium", "Remove 'NOPASSWD: ALL' entries from /etc/sudoers and /etc/sudoers.d.", "linux"},
}

type postureReport struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// postureChecks converts the agent's posture array into admin-facing checks.
// Unknown ids and invalid statuses are ignored so a newer agent never breaks
// an older backend, and duplicates keep the worst status.
func postureChecks(raw json.RawMessage) []HostCheck {
	var wrap struct {
		Posture []postureReport `json:"posture"`
	}
	if json.Unmarshal(raw, &wrap) != nil {
		return nil
	}
	byID := map[string]HostCheck{}
	rank := map[string]int{"pass": 0, "unknown": 1, "fail": 2}
	for _, p := range wrap.Posture {
		def, ok := endpointPostureCatalog[p.ID]
		st := strings.ToLower(p.Status)
		if _, valid := rank[st]; !ok || !valid {
			continue
		}
		detail := p.Detail
		if len(detail) > 300 {
			detail = detail[:300] + "…"
		}
		c := HostCheck{ID: p.ID, Title: def.Title, Category: def.Category, Status: st, Severity: def.Severity, Fix: def.Fix}
		if st != "pass" {
			c.Detail = detail
		}
		if old, dup := byID[p.ID]; !dup || rank[st] > rank[old.Status] {
			byID[p.ID] = c
		}
	}
	out := make([]HostCheck, 0, len(byID))
	for _, c := range byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// hostOSFamily returns windows | macos | linux from a vulnerability.scan.
func hostOSFamily(raw json.RawMessage) string {
	var s struct {
		OS     string `json:"os"`
		System struct {
			OSRelease string `json:"os_release"`
		} `json:"system"`
	}
	_ = json.Unmarshal(raw, &s)
	l := strings.ToLower(s.OS + " " + s.System.OSRelease)
	switch {
	case strings.Contains(l, "windows"):
		return "windows"
	case strings.Contains(l, "darwin"), strings.Contains(l, "macos"), strings.Contains(l, "mac os"):
		return "macos"
	}
	return "linux"
}

// endpointChecks is the single entry point used by the API: agent-reported
// posture for every OS, plus the package/port based checks for Linux only
// (they inspect apt/rpm package names and would give wrong failures on other OSes).
func endpointChecks(raw json.RawMessage) []HostCheck {
	out := postureChecks(raw)
	if hostOSFamily(raw) == "linux" {
		out = append(out, evalHostChecks(raw)...)
	} else {
		out = append(out, portExposureChecks(raw)...)
	}
	return out
}

// portExposureChecks are the OS-independent checks based only on open ports.
func portExposureChecks(raw json.RawMessage) []HostCheck {
	var keep []HostCheck
	for _, c := range evalHostChecks(raw) {
		switch c.ID {
		case "HC-002", "HC-006", "HC-008":
			keep = append(keep, c)
		}
	}
	return keep
}
