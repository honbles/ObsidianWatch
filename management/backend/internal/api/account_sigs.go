package api

import (
	"net/netip"
	"path/filepath"
	"strings"

	"obsidianwatch/management/internal/store"
)

// P-12: local account and group change detections.

func winEventIs(ev store.Event, ids ...uint32) bool {
	if ev.EventID == nil {
		return false
	}
	for _, id := range ids {
		if *ev.EventID == id {
			return true
		}
	}
	return false
}

var windowsAccountSignatures = []ThreatSig{
	{
		ID: "W-ACCT-001", Name: "Local User Account Created",
		Description: "A user account was created (Event 4720). Attackers create accounts for persistence; verify the change was authorised.",
		Severity: 3, MITRE: "T1136.001", Category: "Persistence",
		Match: func(ev store.Event) bool { return winEventIs(ev, 4720) },
	},
	{
		ID: "W-ACCT-002", Name: "User Account Deleted",
		Description: "A user account was deleted (Event 4726). Can indicate cleanup of attacker-created accounts or destruction of access.",
		Severity: 2, MITRE: "T1531", Category: "Impact",
		Match: func(ev store.Event) bool { return winEventIs(ev, 4726) },
	},
	{
		ID: "W-ACCT-003", Name: "Account Password Reset by Another User",
		Description: "An account's password was reset by someone other than its owner (Event 4724). Common step in account takeover.",
		Severity: 3, MITRE: "T1098", Category: "Persistence",
		Match: func(ev store.Event) bool { return winEventIs(ev, 4724) },
	},
	{
		ID: "W-ACCT-004", Name: "Member Added to Local Group",
		Description: "A member was added to a security-enabled local group (Event 4732). Adding to Administrators grants full control of the host.",
		Severity: 3, MITRE: "T1098", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return winEventIs(ev, 4732) && !strings.Contains(rawStr(ev), "domain admins")
		},
	},
}

var linuxAccountCmds = map[string]bool{
	"useradd": true, "adduser": true, "userdel": true, "deluser": true,
	"usermod": true, "groupadd": true, "groupmod": true, "gpasswd": true, "chpasswd": true,
}

var linuxAccountSignatures = []ThreatSig{
	{
		ID: "L-ACCT-001", Name: "Local Account or Group Modified via CLI",
		Description: "A user/group management utility (useradd, usermod, gpasswd, chpasswd...) was run. Attackers add accounts or privileged group membership for persistence.",
		Severity: 3, MITRE: "T1136.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" || ev.ProcessName == nil {
				return false
			}
			return linuxAccountCmds[strings.ToLower(filepath.Base(*ev.ProcessName))]
		},
	},
	{
		ID: "L-ACCT-002", Name: "User Added to Privileged Group",
		Description: "usermod/gpasswd/adduser was used to add an account to sudo, wheel, admin, docker or root groups — a direct privilege-escalation path.",
		Severity: 4, MITRE: "T1098", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" || ev.ProcessName == nil || ev.CommandLine == nil {
				return false
			}
			if !linuxAccountCmds[strings.ToLower(filepath.Base(*ev.ProcessName))] {
				return false
			}
			c := strings.ToLower(*ev.CommandLine)
			if !containsAny(c, "-ag", "-a -g", "-g ", "--append", "gpasswd -a", "adduser ") {
				return false
			}
			return containsAny(c, " sudo", ",sudo", " wheel", ",wheel", " admin", " docker", ",docker", " root")
		},
	},
}

// publicIP reports whether s parses as a globally routable address.
func publicIP(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsValid() && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() &&
		!a.IsMulticast() && !a.IsUnspecified() && !cgnatPrefix.Contains(a)
}

// P-12: remote-session visibility.
var remoteSessionSignatures = []ThreatSig{
	{
		ID: "W-RDP-001", Name: "RDP Logon from a Public IP Address",
		Description: "A successful Remote Desktop logon (Event 4624, logon type 10) came from a publicly routable address. Exposed RDP is a leading ransomware entry point.",
		Severity: 4, MITRE: "T1021.001", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return winEventIs(ev, 4624) && ev.SrcIP != nil && publicIP(*ev.SrcIP) &&
				logonTypeNetRe.FindStringSubmatch(rawStr(ev)) != nil &&
				logonTypeNetRe.FindStringSubmatch(rawStr(ev))[1] == "10"
		},
	},
}
