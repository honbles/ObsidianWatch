package collector

// posture_eval.go - turns the raw values read from a Windows host into
// pass / fail / unknown results. It is deliberately free of OS calls so it can
// be unit tested anywhere. The check ids match the catalog on the backend
// (endpoint_posture.go), which owns titles, severities and remediation text.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PostureCheck is one endpoint compliance result sent in the vulnerability scan.
type PostureCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"` // pass | fail | unknown
	Detail string `json:"detail,omitempty"`
}

type winAV struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	UpToDate bool   `json:"up_to_date"`
}

type winFWProfile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// winPostureRaw mirrors the JSON produced by the collection script. Pointer
// fields are nil when the value could not be read.
type winPostureRaw struct {
	AV       json.RawMessage `json:"av"`
	Defender *struct {
		Realtime   *bool `json:"realtime"`
		SigAgeDays *int  `json:"sig_age_days"`
		Tamper     *bool `json:"tamper"`
	} `json:"defender"`
	Firewall          json.RawMessage `json:"firewall"`
	BitLocker         *string         `json:"bitlocker"`
	HotfixAgeDays     *int            `json:"hotfix_age_days"`
	EnableLUA         *int            `json:"enable_lua"`
	SMB1              *bool           `json:"smb1"`
	RDPDeny           *int            `json:"rdp_deny"`
	RDPNLA            *int            `json:"rdp_nla"`
	GuestEnabled      *bool           `json:"guest_enabled"`
	AdminEnabled      *bool           `json:"admin_enabled"`
	LocalAdmins       *int            `json:"local_admins"`
	MinPasswordLength *int            `json:"min_password_length"`
	LockoutThreshold  *int            `json:"lockout_threshold"`
	InactivitySecs    *int            `json:"inactivity_secs"`
	SecureBoot        *bool           `json:"secure_boot"`
	TPMReady          *bool           `json:"tpm_ready"`
	ScriptBlockLog    *int            `json:"script_block_logging"`
	AutoRunMask       *int            `json:"autorun_mask"`
	RunAsPPL          *int            `json:"run_as_ppl"`
	AuditLogon        string          `json:"audit_logon"`
}

// decodeList accepts a JSON array or a single object (PowerShell collapses
// one-element arrays to an object in some versions).
func decodeList[T any](raw json.RawMessage) []T {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var many []T
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	var one T
	if json.Unmarshal(raw, &one) == nil {
		return []T{one}
	}
	return nil
}

func pc(id, status, detail string) PostureCheck {
	return PostureCheck{ID: id, Status: status, Detail: detail}
}

func boolCheck(id string, v *bool, failDetail, unknownDetail string) PostureCheck {
	switch {
	case v == nil:
		return pc(id, "unknown", unknownDetail)
	case *v:
		return pc(id, "pass", "")
	}
	return pc(id, "fail", failDetail)
}

// evalWindowsPosture evaluates every Windows check from the raw values.
func evalWindowsPosture(r winPostureRaw) []PostureCheck {
	var out []PostureCheck
	avs := decodeList[winAV](r.AV)
	fws := decodeList[winFWProfile](r.Firewall)

	enabledAV := []winAV{}
	for _, a := range avs {
		if a.Enabled {
			enabledAV = append(enabledAV, a)
		}
	}
	thirdPartyActive := false
	for _, a := range enabledAV {
		if !strings.Contains(strings.ToLower(a.Name), "defender") {
			thirdPartyActive = true
		}
	}
	defRT := (*bool)(nil)
	if r.Defender != nil {
		defRT = r.Defender.Realtime
	}

	// EC-W-001 antivirus present and active
	switch {
	case len(enabledAV) > 0:
		out = append(out, pc("EC-W-001", "pass", ""))
	case len(avs) > 0:
		names := []string{}
		for _, a := range avs {
			names = append(names, a.Name)
		}
		out = append(out, pc("EC-W-001", "fail", "installed but not active: "+strings.Join(names, ", ")))
	case defRT != nil && *defRT:
		out = append(out, pc("EC-W-001", "pass", ""))
	case defRT != nil:
		out = append(out, pc("EC-W-001", "fail", "no antivirus product reported"))
	default:
		out = append(out, pc("EC-W-001", "unknown", "Security Center and Defender status unavailable"))
	}

	// EC-W-002 Defender real-time (a passive Defender beside an active third-party AV is normal)
	switch {
	case defRT == nil:
		out = append(out, pc("EC-W-002", "unknown", "Defender status unavailable"))
	case *defRT || thirdPartyActive:
		out = append(out, pc("EC-W-002", "pass", ""))
	default:
		out = append(out, pc("EC-W-002", "fail", "real-time protection is off and no other AV is active"))
	}

	// EC-W-003 signature age
	switch {
	case r.Defender != nil && r.Defender.SigAgeDays != nil && !thirdPartyActive:
		if age := *r.Defender.SigAgeDays; age <= 7 {
			out = append(out, pc("EC-W-003", "pass", ""))
		} else {
			out = append(out, pc("EC-W-003", "fail", fmt.Sprintf("signatures are %d days old", age)))
		}
	case len(enabledAV) > 0:
		stale := []string{}
		for _, a := range enabledAV {
			if !a.UpToDate {
				stale = append(stale, a.Name)
			}
		}
		if len(stale) == 0 {
			out = append(out, pc("EC-W-003", "pass", ""))
		} else {
			out = append(out, pc("EC-W-003", "fail", "out of date: "+strings.Join(stale, ", ")))
		}
	default:
		out = append(out, pc("EC-W-003", "unknown", "signature age unavailable"))
	}

	// EC-W-004 tamper protection
	if r.Defender == nil {
		out = append(out, pc("EC-W-004", "unknown", "Defender status unavailable"))
	} else if thirdPartyActive && r.Defender.Tamper == nil {
		out = append(out, pc("EC-W-004", "unknown", "Defender is passive; tamper state not reported"))
	} else {
		out = append(out, boolCheck("EC-W-004", r.Defender.Tamper, "tamper protection is off", "tamper state not reported"))
	}

	// EC-W-005 firewall profiles
	if len(fws) == 0 {
		out = append(out, pc("EC-W-005", "unknown", "firewall profiles could not be read"))
	} else {
		off := []string{}
		for _, f := range fws {
			if !f.Enabled {
				off = append(off, f.Name)
			}
		}
		if len(off) == 0 {
			out = append(out, pc("EC-W-005", "pass", ""))
		} else {
			out = append(out, pc("EC-W-005", "fail", "off for: "+strings.Join(off, ", ")))
		}
	}

	// EC-W-006 BitLocker
	switch {
	case r.BitLocker == nil:
		out = append(out, pc("EC-W-006", "unknown", "BitLocker status unavailable (edition or rights)"))
	case strings.EqualFold(*r.BitLocker, "on") || *r.BitLocker == "1":
		out = append(out, pc("EC-W-006", "pass", ""))
	default:
		out = append(out, pc("EC-W-006", "fail", "protection status: "+*r.BitLocker))
	}

	// EC-W-007 patch recency
	switch {
	case r.HotfixAgeDays == nil:
		out = append(out, pc("EC-W-007", "unknown", "no installed update date found"))
	case *r.HotfixAgeDays <= 45:
		out = append(out, pc("EC-W-007", "pass", ""))
	default:
		out = append(out, pc("EC-W-007", "fail", fmt.Sprintf("last update installed %d days ago", *r.HotfixAgeDays)))
	}

	// EC-W-008 UAC (a missing value means the default, which is enabled)
	if r.EnableLUA != nil && *r.EnableLUA == 0 {
		out = append(out, pc("EC-W-008", "fail", "EnableLUA is 0"))
	} else {
		out = append(out, pc("EC-W-008", "pass", ""))
	}

	// EC-W-009 SMBv1
	if r.SMB1 == nil {
		out = append(out, pc("EC-W-009", "unknown", "SMB configuration unavailable"))
	} else if *r.SMB1 {
		out = append(out, pc("EC-W-009", "fail", "SMBv1 server is enabled"))
	} else {
		out = append(out, pc("EC-W-009", "pass", ""))
	}

	// EC-W-010 RDP needs NLA when enabled
	switch {
	case r.RDPDeny == nil:
		out = append(out, pc("EC-W-010", "unknown", "RDP setting unavailable"))
	case *r.RDPDeny != 0:
		out = append(out, pc("EC-W-010", "pass", ""))
	case r.RDPNLA == nil:
		out = append(out, pc("EC-W-010", "unknown", "RDP is on; NLA setting unavailable"))
	case *r.RDPNLA == 1:
		out = append(out, pc("EC-W-010", "pass", ""))
	default:
		out = append(out, pc("EC-W-010", "fail", "RDP is on without Network Level Authentication"))
	}

	// EC-W-011 / 012 built-in accounts
	out = append(out, invBool("EC-W-011", r.GuestEnabled, "Guest account is enabled"))
	out = append(out, invBool("EC-W-012", r.AdminEnabled, "built-in Administrator account is enabled"))

	// EC-W-013 local admins
	switch {
	case r.LocalAdmins == nil:
		out = append(out, pc("EC-W-013", "unknown", "group membership unavailable"))
	case *r.LocalAdmins <= 3:
		out = append(out, pc("EC-W-013", "pass", ""))
	default:
		out = append(out, pc("EC-W-013", "fail", fmt.Sprintf("%d members in Administrators", *r.LocalAdmins)))
	}

	// EC-W-014 / 015 password policy
	switch {
	case r.MinPasswordLength == nil:
		out = append(out, pc("EC-W-014", "unknown", "policy export unavailable"))
	case *r.MinPasswordLength >= 14:
		out = append(out, pc("EC-W-014", "pass", ""))
	default:
		out = append(out, pc("EC-W-014", "fail", fmt.Sprintf("minimum length is %d", *r.MinPasswordLength)))
	}
	switch {
	case r.LockoutThreshold == nil:
		out = append(out, pc("EC-W-015", "unknown", "policy export unavailable"))
	case *r.LockoutThreshold >= 1 && *r.LockoutThreshold <= 10:
		out = append(out, pc("EC-W-015", "pass", ""))
	case *r.LockoutThreshold == 0:
		out = append(out, pc("EC-W-015", "fail", "accounts never lock out"))
	default:
		out = append(out, pc("EC-W-015", "fail", fmt.Sprintf("threshold is %d", *r.LockoutThreshold)))
	}

	// EC-W-016 inactivity lock (per-user screen saver settings are invisible to a service)
	switch {
	case r.InactivitySecs == nil || *r.InactivitySecs == 0:
		out = append(out, pc("EC-W-016", "unknown", "no machine-wide inactivity limit is set by policy"))
	case *r.InactivitySecs <= 900:
		out = append(out, pc("EC-W-016", "pass", ""))
	default:
		out = append(out, pc("EC-W-016", "fail", fmt.Sprintf("locks after %d seconds", *r.InactivitySecs)))
	}

	out = append(out, boolCheck("EC-W-017", r.SecureBoot, "Secure Boot is off", "not supported (legacy BIOS) or unreadable"))
	out = append(out, boolCheck("EC-W-018", r.TPMReady, "TPM missing or not ready", "TPM status unavailable"))

	// EC-W-019 script block logging
	if r.ScriptBlockLog != nil && *r.ScriptBlockLog == 1 {
		out = append(out, pc("EC-W-019", "pass", ""))
	} else {
		out = append(out, pc("EC-W-019", "fail", "script block logging policy is not enabled"))
	}

	// EC-W-020 AutoRun
	if r.AutoRunMask != nil && *r.AutoRunMask&0xFF == 0xFF {
		out = append(out, pc("EC-W-020", "pass", ""))
	} else {
		out = append(out, pc("EC-W-020", "fail", "NoDriveTypeAutoRun is not 0xFF"))
	}

	// EC-W-021 LSA protection
	if r.RunAsPPL != nil && (*r.RunAsPPL == 1 || *r.RunAsPPL == 2) {
		out = append(out, pc("EC-W-021", "pass", ""))
	} else {
		out = append(out, pc("EC-W-021", "fail", "RunAsPPL is not set"))
	}

	// EC-W-022 audit policy (output is localised; only English wording is recognised)
	switch a := strings.ToLower(r.AuditLogon); {
	case a == "":
		out = append(out, pc("EC-W-022", "unknown", "auditpol output unavailable"))
	case strings.Contains(a, "success and failure"):
		out = append(out, pc("EC-W-022", "pass", ""))
	case strings.Contains(a, "success") || strings.Contains(a, "failure") || strings.Contains(a, "no auditing"):
		out = append(out, pc("EC-W-022", "fail", "logon auditing is incomplete"))
	default:
		out = append(out, pc("EC-W-022", "unknown", "auditpol output not recognised (non-English?)"))
	}
	return out
}

// invBool: a true value is a failure (an account that should be off is on).
func invBool(id string, v *bool, failDetail string) PostureCheck {
	switch {
	case v == nil:
		return pc(id, "unknown", "account state unavailable")
	case *v:
		return pc(id, "fail", failDetail)
	}
	return pc(id, "pass", "")
}
