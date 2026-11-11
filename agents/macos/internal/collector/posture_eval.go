package collector

// posture_eval.go - evaluates macOS endpoint compliance from raw command
// output. No OS calls here so it can be unit tested anywhere. Ids match the
// backend catalog (endpoint_posture.go), which owns titles and fix text.

import (
	"fmt"
	"strings"
)

// PostureCheck is one endpoint compliance result sent in the vulnerability scan.
type PostureCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"` // pass | fail | unknown
	Detail string `json:"detail,omitempty"`
}

// macPostureRaw holds trimmed command output; empty means the command failed
// or produced nothing, which is reported as unknown.
type macPostureRaw struct {
	FileVault      string // fdesetup status
	SIP            string // csrutil status
	Gatekeeper     string // spctl --status
	FirewallState  string // defaults read com.apple.alf globalstate
	AutoUpdate     string // defaults read com.apple.SoftwareUpdate AutomaticCheckEnabled
	RemoteLogin    string // systemsetup -getremotelogin
	GuestEnabled   string // defaults read com.apple.loginwindow GuestEnabled
	LaunchctlList  string // launchctl list
	AdminGroup     string // dscl . -read /Groups/admin GroupMembership
	LaunchctlReady bool   // launchctl list could be read
}

func mp(id, status, detail string) PostureCheck {
	return PostureCheck{ID: id, Status: status, Detail: detail}
}

func evalMacPosture(r macPostureRaw) []PostureCheck {
	var out []PostureCheck

	// EC-M-001 FileVault
	switch l := strings.ToLower(r.FileVault); {
	case l == "":
		out = append(out, mp("EC-M-001", "unknown", "fdesetup returned nothing"))
	case strings.Contains(l, "filevault is on"):
		out = append(out, mp("EC-M-001", "pass", ""))
	case strings.Contains(l, "filevault is off"):
		out = append(out, mp("EC-M-001", "fail", "startup disk is not encrypted"))
	default:
		out = append(out, mp("EC-M-001", "unknown", clip(r.FileVault)))
	}

	// EC-M-002 SIP
	switch l := strings.ToLower(r.SIP); {
	case l == "":
		out = append(out, mp("EC-M-002", "unknown", "csrutil returned nothing"))
	case strings.Contains(l, "enabled") && !strings.Contains(l, "custom configuration"):
		out = append(out, mp("EC-M-002", "pass", ""))
	case strings.Contains(l, "disabled"):
		out = append(out, mp("EC-M-002", "fail", "SIP is disabled"))
	default:
		out = append(out, mp("EC-M-002", "fail", "SIP has a custom configuration: "+clip(r.SIP)))
	}

	// EC-M-003 Gatekeeper
	switch l := strings.ToLower(r.Gatekeeper); {
	case l == "":
		out = append(out, mp("EC-M-003", "unknown", "spctl returned nothing"))
	case strings.Contains(l, "assessments enabled"):
		out = append(out, mp("EC-M-003", "pass", ""))
	case strings.Contains(l, "disabled"):
		out = append(out, mp("EC-M-003", "fail", "Gatekeeper is disabled"))
	default:
		out = append(out, mp("EC-M-003", "unknown", clip(r.Gatekeeper)))
	}

	// EC-M-004 application firewall (0 off, 1 on, 2 block all)
	switch r.FirewallState {
	case "":
		out = append(out, mp("EC-M-004", "unknown", "firewall state unavailable"))
	case "1", "2":
		out = append(out, mp("EC-M-004", "pass", ""))
	case "0":
		out = append(out, mp("EC-M-004", "fail", "application firewall is off"))
	default:
		out = append(out, mp("EC-M-004", "unknown", "unexpected value "+clip(r.FirewallState)))
	}

	// EC-M-005 automatic update checks (a missing key means the default, which is on)
	if r.AutoUpdate == "0" {
		out = append(out, mp("EC-M-005", "fail", "automatic update check is off"))
	} else {
		out = append(out, mp("EC-M-005", "pass", ""))
	}

	// EC-M-006 Remote Login
	switch l := strings.ToLower(r.RemoteLogin); {
	case l == "" || strings.Contains(l, "full disk access") || strings.Contains(l, "error"):
		out = append(out, mp("EC-M-006", "unknown", "systemsetup unavailable (needs Full Disk Access)"))
	case strings.Contains(l, "off"):
		out = append(out, mp("EC-M-006", "pass", ""))
	default:
		out = append(out, mp("EC-M-006", "fail", "SSH server is on"))
	}

	// EC-M-007 Guest account (key absent: cannot tell)
	switch r.GuestEnabled {
	case "":
		out = append(out, mp("EC-M-007", "unknown", "GuestEnabled is not set"))
	case "0":
		out = append(out, mp("EC-M-007", "pass", ""))
	default:
		out = append(out, mp("EC-M-007", "fail", "guest login is enabled"))
	}

	// EC-M-008 screen sharing / remote management
	if !r.LaunchctlReady {
		out = append(out, mp("EC-M-008", "unknown", "launchctl list unavailable"))
	} else if strings.Contains(r.LaunchctlList, "com.apple.screensharing") || strings.Contains(r.LaunchctlList, "ARDAgent") {
		out = append(out, mp("EC-M-008", "fail", "Screen Sharing or Remote Management is running"))
	} else {
		out = append(out, mp("EC-M-008", "pass", ""))
	}

	// EC-M-009 admin group size (root is not counted)
	if r.AdminGroup == "" {
		out = append(out, mp("EC-M-009", "unknown", "admin group unavailable"))
	} else {
		members := []string{}
		for _, f := range strings.Fields(strings.TrimPrefix(strings.TrimSpace(r.AdminGroup), "GroupMembership:")) {
			if f != "root" {
				members = append(members, f)
			}
		}
		if len(members) <= 2 {
			out = append(out, mp("EC-M-009", "pass", ""))
		} else {
			out = append(out, mp("EC-M-009", "fail", fmt.Sprintf("%d admin users: %s", len(members), strings.Join(members, ", "))))
		}
	}
	return out
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
