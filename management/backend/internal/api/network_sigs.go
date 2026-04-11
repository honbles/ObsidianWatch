package api

import (
	"strings"
	"obsidianwatch/management/internal/store"
)

// networkSignatures — detection rules for Network Probe events (NET- prefix).
// Events arrive with OS="network-probe" and EventType starting with "net."
var networkSignatures = []ThreatSig{

	// ── Device Discovery ───────────────────────────────────────────────────
	{
		ID: "NET-001", Name: "Unknown Device Joined Network",
		Description: "A device with an unrecognised MAC address appeared on the network — could be an unauthorised device, rogue access point, or attacker.",
		Severity: 3, MITRE: "T1200", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.new_device"
		},
	},
	{
		ID: "NET-002", Name: "ARP Spoofing / MAC Address Changed",
		Description: "An IP address changed its MAC address — classic ARP poisoning used for MITM attacks. The attacker is intercepting traffic for this IP.",
		Severity: 5, MITRE: "T1557.002", Category: "Collection",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.mac_change"
		},
	},

	// ── Reconnaissance ─────────────────────────────────────────────────────
	{
		ID: "NET-003", Name: "Port Scan Detected",
		Description: "A single source IP connected to many ports on a destination in a short window — active reconnaissance or vulnerability scanning.",
		Severity: 3, MITRE: "T1046", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.port_scan"
		},
	},
	{
		ID: "NET-004", Name: "Network Brute Force Attack",
		Description: "Repeated authentication failures from a single source — brute force attack against SSH, Telnet, HTTPS management interface, or VPN.",
		Severity: 4, MITRE: "T1110", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.brute_force" ||
				(ev.EventType == "net.auth_failure" && ev.Severity >= 3)
		},
	},

	// ── Lateral Movement ───────────────────────────────────────────────────
	{
		ID: "NET-005", Name: "Lateral Movement — Internal Host Scanning",
		Description: "An internal host connected to SMB (445), RDP (3389), WinRM (5985), or SSH (22) on another internal host — possible lateral movement.",
		Severity: 4, MITRE: "T1021", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.lateral"
		},
	},

	// ── Firewall / Traffic ──────────────────────────────────────────────────
	{
		ID: "NET-006", Name: "High Volume of Firewall Denies from Single Source",
		Description: "Unusually high number of firewall deny events from one source IP — possible scanning, misconfigured device, or blocked malware C2 traffic.",
		Severity: 3, MITRE: "T1046", Category: "Discovery",
		Match: func(ev store.Event) bool {
			if ev.EventType != "net.fw_deny" {
				return false
			}
			raw := strings.ToLower(rawStr(ev))
			return containsAny(raw, "deny_count", "repeated") && ev.Severity >= 3
		},
	},
	{
		ID: "NET-007", Name: "Firewall Deny — Known Malicious Destination",
		Description: "Traffic was blocked to/from a known malicious IP or domain — malware C2 blocked at perimeter.",
		Severity: 4, MITRE: "T1071", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.fw_deny" && ev.Severity >= 4
		},
	},

	// ── Network Infrastructure ─────────────────────────────────────────────
	{
		ID: "NET-008", Name: "Network Device Configuration Changed",
		Description: "A network device (router, switch, firewall) had its configuration modified — could indicate unauthorised change or attacker persistence.",
		Severity: 4, MITRE: "T1601", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.config_change"
		},
	},
	{
		ID: "NET-009", Name: "Network Interface Went Down",
		Description: "A network interface on a monitored device went down — could be physical failure, misconfiguration, or intentional disruption.",
		Severity: 3, MITRE: "T1499", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.iface_down"
		},
	},
	{
		ID: "NET-010", Name: "Network Device Unreachable via SNMP",
		Description: "A monitored network device stopped responding to SNMP polls — device may be down, rebooting, or SNMP disabled.",
		Severity: 3, MITRE: "T1489", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.device_down"
		},
	},

	// ── VPN / Remote Access ────────────────────────────────────────────────
	{
		ID: "NET-011", Name: "VPN Connection Outside Business Hours",
		Description: "VPN tunnel established outside normal business hours — verify whether this access is expected.",
		Severity: 3, MITRE: "T1133", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			if ev.EventType != "net.vpn_connect" {
				return false
			}
			hour := ev.Time.UTC().Hour()
			return hour < 6 || hour >= 22
		},
	},
	{
		ID: "NET-012", Name: "Multiple VPN Connections from Same Source",
		Description: "Multiple VPN sessions established from the same source IP — possible credential sharing, VPN hijacking, or automated attack tool.",
		Severity: 3, MITRE: "T1133", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.vpn_connect" && ev.Severity >= 3
		},
	},

	// ── Bandwidth / Exfiltration ───────────────────────────────────────────
	{
		ID: "NET-013", Name: "Unusual Bandwidth Spike — Possible Exfiltration",
		Description: "A device is sending significantly more data than its established baseline — possible data exfiltration.",
		Severity: 4, MITRE: "T1048", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.bandwidth" && ev.Severity >= 3
		},
	},
	{
		ID: "NET-014", Name: "Device Communicating with Unusual External Destination",
		Description: "An internal device is establishing connections to an external destination it has never contacted before — possible C2 or exfiltration.",
		Severity: 3, MITRE: "T1071", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.flow" && ev.Severity >= 3 &&
				containsAny(strings.ToLower(rawStr(ev)), "new_destination", "first_seen")
		},
	},

	// ── Device Auth ────────────────────────────────────────────────────────
	{
		ID: "NET-015", Name: "Successful Login to Network Device After Failures",
		Description: "A successful login to a network device preceded by multiple failures — brute force succeeded.",
		Severity: 5, MITRE: "T1110", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.auth_success" && ev.Severity >= 4
		},
	},
	{
		ID: "NET-016", Name: "SNMP Community String Brute Force",
		Description: "Multiple SNMP requests with different community strings — attacker enumerating SNMP communities to gain read/write access to network devices.",
		Severity: 4, MITRE: "T1110", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.snmp_trap" &&
				containsAny(strings.ToLower(rawStr(ev)), "authenticationfailure", "wrong community")
		},
	},

	// ── Topology Changes ───────────────────────────────────────────────────
	{
		ID: "NET-017", Name: "New CDP/LLDP Neighbour Discovered",
		Description: "A new device was detected via CDP or LLDP neighbour discovery — verify this device is authorised in the network topology.",
		Severity: 2, MITRE: "T1200", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.topology" && ev.Severity >= 2
		},
	},
	{
		ID: "NET-018", Name: "DHCP Starvation — Rapid DISCOVER Bursts",
		Description: "Rapid sequence of DHCP DISCOVER messages from multiple MACs — possible DHCP starvation attack that exhausts the IP pool.",
		Severity: 4, MITRE: "T1498", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "net.dhcp_lease" && ev.Severity >= 4
		},
	},
}

// isNetworkProbeEvent returns true if the event came from a network probe
func isNetworkProbeEvent(ev store.Event) bool {
	return ev.OS == "network-probe" ||
		strings.HasPrefix(string(ev.EventType), "net.")
}
