package api

import (
	"strings"

	"obsidianwatch/management/internal/store"
)

// windowsTamperSignatures cover defence-evasion events that the generic
// command-line rules miss because they come from the Windows event log or
// Sysmon rather than a process command line (W-04).
var windowsTamperSignatures = []ThreatSig{
	{
		ID: "W-T1562.001d", Name: "Security Service Stopped",
		Description: "Service Control Manager reports a security-relevant service (Defender, Sysmon, firewall, event log, EDR agent) entered the stopped state.",
		Severity:    4, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			if ev.EventID == nil || *ev.EventID != 7036 {
				return false
			}
			r := rawStr(ev)
			if !strings.Contains(r, "stopped") {
				return false
			}
			return containsAny(r, "windefend", "windows defender", "sysmon", "mpssvc", "windows firewall",
				"eventlog", "windows event log", "wscsvc", "sense", "obsidianwatch")
		},
	},
	{
		ID: "W-T1562.002", Name: "Audit Policy Changed",
		Description: "System audit policy was modified (4719) — attackers disable auditing to hide activity.",
		Severity:    4, MITRE: "T1562.002", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventID != nil && *ev.EventID == 4719
		},
	},
	{
		ID: "W-T1562.006", Name: "Sysmon Driver Unloaded or Config Changed",
		Description: "Sysmon reported a configuration change (16) or a service state change (4) — possible tampering with telemetry.",
		Severity:    4, MITRE: "T1562.006", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			if ev.EventID == nil || ev.Channel == nil ||
				!strings.Contains(strings.ToLower(*ev.Channel), "sysmon") {
				return false
			}
			return *ev.EventID == 16 || (*ev.EventID == 4 && strings.Contains(rawStr(ev), "stopped"))
		},
	},
	{
		ID: "W-T1543.003b", Name: "New Service Installed",
		Description: "A new service was installed (7045 / 4697) — review binary path for persistence or driver abuse.",
		Severity:    3, MITRE: "T1543.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventID != nil && (*ev.EventID == 7045 || *ev.EventID == 4697) &&
				containsAny(rawStr(ev), `\temp\`, `\appdata\`, `\users\public\`, "cmd.exe /c", "powershell", `\programdata\`)
		},
	},
	{
		ID: "W-T1546.003b", Name: "WMI Event Subscription Persistence",
		Description: "WMI-Activity reported a permanent event consumer binding (5861) — a common fileless persistence mechanism.",
		Severity:    4, MITRE: "T1546.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventID != nil && *ev.EventID == 5861 && ev.Channel != nil &&
				strings.Contains(strings.ToLower(*ev.Channel), "wmi-activity")
		},
	},
}
