package parser

// syslog.go — Generic syslog parser + device-specific pattern extraction
//
// Handles:
//   - RFC 3164 (BSD syslog) — <priority>timestamp hostname message
//   - RFC 5424 (structured syslog) — version, structured data
//   - Non-standard formats (Cisco, Fortinet, Palo Alto raw output)
//
// From the parsed syslog we extract structured events:
//   - Firewall allow/deny (src/dst IP/port/proto)
//   - Authentication success/failure
//   - DHCP lease/release
//   - Interface state changes
//   - VPN connect/disconnect
//   - Config changes
//   - Generic syslog for anything else

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SyslogMessage is the normalized parsed message
type SyslogMessage struct {
	Time      time.Time
	Facility  int
	Severity  int
	Hostname  string
	Program   string
	PID       int
	MsgID     string
	Message   string
	Raw       string
	SourceIP  net.IP // UDP source
}

// NetworkEvent is extracted from syslog
type NetworkEvent struct {
	Type      string // matches schema constants
	Time      time.Time
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Proto     string
	Action    string // permit|deny|drop|reset
	Interface string
	User      string
	Device    string // hostname of device that sent syslog
	Severity  int
	Message   string
	Raw       string
	Extra     map[string]string
}

// ── Patterns for device-specific log extraction ───────────────────────────────

var (
	// Cisco ASA/Firepower: %ASA-6-302013: Built inbound TCP connection ...
	//   %ASA-3-106014: Deny inbound icmp src outside:1.2.3.4 dst inside:10.0.0.1
	reCiscoFW = regexp.MustCompile(
		`%(ASA|FTD|PIX)-(\d)-(\d+):\s*(.+)`)
	reCiscoFWConn = regexp.MustCompile(
		`(?i)(Built|Teardown|Deny|Permit)\s+(?:inbound|outbound)?\s*(\w+)\s+(?:connection\s+\d+\s+)?` +
		`(?:for|from|src)\s+\S+[:\s](\d+\.\d+\.\d+\.\d+)/(\d+)\s+` +
		`(?:to|dst)\s+\S+[:\s](\d+\.\d+\.\d+\.\d+)/(\d+)`)

	// Cisco IOS ACL: list 101 denied tcp 192.168.1.1(1234) -> 8.8.8.8(53)
	reCiscoACL = regexp.MustCompile(
		`(?i)list\s+\S+\s+(denied|permitted)\s+(\w+)\s+(\d+\.\d+\.\d+\.\d+)\((\d+)\)\s*-+>\s*(\d+\.\d+\.\d+\.\d+)\((\d+)\)`)

	// Cisco DHCP: DHCPACK/DHCPREQUEST: IP 192.168.1.100 MAC aa:bb:cc:dd:ee:ff
	reCiscoDHCP = regexp.MustCompile(
		`(?i)(DHCPACK|DHCPDISCOVER|DHCPREQUEST|DHCPRELEASE|DHCPNAK)\s+(?:assigned\s+)?(?:IP\s+)?(\d+\.\d+\.\d+\.\d+)` +
		`(?:\s+(?:for|to|MAC)\s+([0-9a-fA-F:.-]+))?(?:\s+via\s+(\S+))?`)

	// Linux/ISC DHCP: dhcpd: DHCPACK on 192.168.1.100 to aa:bb:cc:dd:ee:ff
	reLinuxDHCP = regexp.MustCompile(
		`(?i)DHCP(?:ACK|DISCOVER|REQUEST|RELEASE|NAK)\s+(?:on|from|for)?\s+(\d+\.\d+\.\d+\.\d+)` +
		`\s+(?:to|from)?\s*([0-9a-fA-F:.-]+)`)

	// Generic IP/port pattern for firewall allow/deny
	reGenericFW = regexp.MustCompile(
		`(?i)(allow|deny|drop|block|accept|reject|permit|forward)\w*\s+` +
		`(?:protocol\s+)?(\w+)\s+` +
		`(?:from\s+)?(\d+\.\d+\.\d+\.\d+)(?::(\d+))?\s+` +
		`(?:to\s+)?(\d+\.\d+\.\d+\.\d+)(?::(\d+))?`)

	// Fortinet FortiGate: action=deny srcip=1.2.3.4 srcport=1234 dstip=5.6.7.8 dstport=80 proto=6
	reFortigate = regexp.MustCompile(
		`(\w+)=([^\s]+)`)

	// Palo Alto: proto/src/dst/sport/dport/action in CSV or KV format
	rePaloAlto = regexp.MustCompile(
		`(?i)(?:src|from)[=:\s]+(\d+\.\d+\.\d+\.\d+).*(?:dst|to)[=:\s]+(\d+\.\d+\.\d+\.\d+)`)

	// SSH brute force: Failed password for user from 1.2.3.4
	reSSHFail = regexp.MustCompile(
		`(?i)Failed\s+(?:password|publickey)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)`)
	reSSHSuccess = regexp.MustCompile(
		`(?i)Accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)`)

	// Interface up/down
	reIfaceDown = regexp.MustCompile(
		`(?i)(?:Interface|Line protocol|link)\s+(\S+)\s*[,]?\s*(?:changed state to\s+)?(?:is\s+)?(down|up)`)
	reIfaceUp = regexp.MustCompile(
		`(?i)(?:Interface|Line protocol|link)\s+(\S+)\s+(?:is\s+)?(up|UP)`)

	// VPN
	reVPNConnect = regexp.MustCompile(
		`(?i)(?:VPN|tunnel|Phase\s+2|IKE)\s+(?:tunnel|SA)?\s*(?:established|connected|built|up)\s+.*?(\d+\.\d+\.\d+\.\d+)`)
	reVPNDisconnect = regexp.MustCompile(
		`(?i)(?:VPN|tunnel|Phase\s+2|IKE)\s+(?:tunnel|SA)?\s*(?:deleted|disconnected|down|removed)\s+.*?(\d+\.\d+\.\d+\.\d+)`)

	// Config change
	reConfigChange = regexp.MustCompile(
		`(?i)(?:config\s+changed|configuration\s+(?:change|modified|saved)|SYS-5-CONFIG_I)`)

	// Auth failure on device itself
	reDeviceAuthFail = regexp.MustCompile(
		`(?i)(?:Login\s+failed|Authentication\s+(?:failed|failure)|Invalid\s+(?:password|username))(?:.*from\s+(\d+\.\d+\.\d+\.\d+))?`)
	reDeviceAuthSuccess = regexp.MustCompile(
		`(?i)(?:Login\s+(?:succeeded|successful)|Accepted\s+login|User\s+logged\s+in)(?:.*from\s+(\d+\.\d+\.\d+\.\d+))?(?:.*user[:\s]+(\S+))?`)
)

// ParseSyslog parses a raw syslog line (RFC 3164 or 5424)
func ParseSyslog(raw string, sourceIP net.IP) SyslogMessage {
	msg := SyslogMessage{Raw: raw, SourceIP: sourceIP, Time: time.Now()}
	raw = strings.TrimSpace(raw)

	// RFC 3164: <priority>timestamp hostname message
	if strings.HasPrefix(raw, "<") {
		end := strings.Index(raw, ">")
		if end > 0 {
			prio, _ := strconv.Atoi(raw[1:end])
			msg.Facility = prio / 8
			msg.Severity = prio % 8
			raw = strings.TrimSpace(raw[end+1:])
		}
	}

	// Parse timestamp (RFC 3164: "Jan  2 15:04:05")
	if len(raw) >= 15 {
		ts, err := time.Parse("Jan  2 15:04:05", raw[:15])
		if err == nil {
			msg.Time = ts.UTC()
			raw = strings.TrimSpace(raw[15:])
		} else {
			// Try "Jan 02 15:04:05"
			ts, err = time.Parse("Jan 02 15:04:05", raw[:15])
			if err == nil {
				msg.Time = ts.UTC()
				raw = strings.TrimSpace(raw[15:])
			}
		}
	}

	// Extract hostname (next word)
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) == 2 && !strings.ContainsAny(parts[0], "[]%:") {
		msg.Hostname = parts[0]
		raw = strings.TrimSpace(parts[1])
	}

	// Extract program[pid]:
	if idx := strings.Index(raw, ": "); idx > 0 {
		prog := raw[:idx]
		if pidStart := strings.Index(prog, "["); pidStart > 0 {
			msg.Program = prog[:pidStart]
			pid, _ := strconv.Atoi(strings.Trim(prog[pidStart:], "[]"))
			msg.PID = pid
		} else {
			msg.Program = prog
		}
		msg.Message = strings.TrimSpace(raw[idx+2:])
	} else {
		msg.Message = raw
	}

	if msg.Hostname == "" && sourceIP != nil {
		msg.Hostname = sourceIP.String()
	}

	return msg
}

// ExtractEvents extracts structured network events from a syslog message
func ExtractEvents(msg SyslogMessage) []NetworkEvent {
	var events []NetworkEvent
	text := msg.Message
	device := msg.Hostname
	if device == "" && msg.SourceIP != nil {
		device = msg.SourceIP.String()
	}

	// ── Cisco ASA/FTD firewall events ─────────────────────────────────────
	if m := reCiscoFW.FindStringSubmatch(text); len(m) >= 4 {
		msgBody := m[4]
		if conn := reCiscoFWConn.FindStringSubmatch(msgBody); len(conn) >= 7 {
			action := strings.ToLower(conn[1])
			proto := strings.ToLower(conn[2])
			srcIP, srcPort := conn[3], toInt(conn[4])
			dstIP, dstPort := conn[5], toInt(conn[6])
			evType := "net.fw_allow"
			sev := 1
			if action == "deny" || action == "teardown" {
				evType = "net.fw_deny"
				sev = 2
			}
			events = append(events, NetworkEvent{
				Type: evType, Time: msg.Time, Device: device,
				SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort,
				Proto: proto, Action: action, Severity: sev,
				Message: msgBody, Raw: msg.Raw,
			})
			return events
		}
	}

	// ── Cisco IOS ACL ──────────────────────────────────────────────────────
	if m := reCiscoACL.FindStringSubmatch(text); len(m) >= 7 {
		action := strings.ToLower(m[1])
		evType := "net.fw_allow"
		if action == "denied" {
			evType = "net.fw_deny"
		}
		events = append(events, NetworkEvent{
			Type: evType, Time: msg.Time, Device: device,
			Proto: m[2], SrcIP: m[3], SrcPort: toInt(m[4]),
			DstIP: m[5], DstPort: toInt(m[6]),
			Action: action, Severity: 1, Message: text, Raw: msg.Raw,
		})
		return events
	}

	// ── Fortinet KV format ─────────────────────────────────────────────────
	if strings.Contains(text, "srcip=") || strings.Contains(text, "dstip=") {
		kv := parseKV(text, reFortigate)
		if kv["srcip"] != "" && kv["dstip"] != "" {
			action := strings.ToLower(kv["action"])
			evType := "net.fw_allow"
			if action == "deny" || action == "drop" || action == "block" {
				evType = "net.fw_deny"
			}
			events = append(events, NetworkEvent{
				Type: evType, Time: msg.Time, Device: device,
				SrcIP: kv["srcip"], DstIP: kv["dstip"],
				SrcPort: toInt(kv["srcport"]), DstPort: toInt(kv["dstport"]),
				Proto: protoNum(kv["proto"]), Action: action,
				User: kv["user"], Interface: kv["srcintf"],
				Severity: 1, Message: text, Raw: msg.Raw,
				Extra: kv,
			})
			return events
		}
	}

	// ── DHCP ───────────────────────────────────────────────────────────────
	if m := reCiscoDHCP.FindStringSubmatch(text); len(m) >= 3 {
		dhcpType := strings.ToUpper(m[1])
		ip := m[2]
		mac := ""
		if len(m) >= 4 {
			mac = m[3]
		}
		evType := "net.dhcp_lease"
		if dhcpType == "DHCPRELEASE" {
			evType = "net.dhcp_release"
		}
		events = append(events, NetworkEvent{
			Type: evType, Time: msg.Time, Device: device,
			DstIP: ip, Severity: 1,
			Message: text, Raw: msg.Raw,
			Extra: map[string]string{"mac": mac, "dhcp_type": dhcpType},
		})
		return events
	}
	if m := reLinuxDHCP.FindStringSubmatch(text); len(m) >= 3 {
		events = append(events, NetworkEvent{
			Type: "net.dhcp_lease", Time: msg.Time, Device: device,
			DstIP: m[1], Severity: 1, Message: text, Raw: msg.Raw,
			Extra: map[string]string{"mac": m[2]},
		})
		return events
	}

	// ── SSH auth ───────────────────────────────────────────────────────────
	if m := reSSHFail.FindStringSubmatch(text); len(m) >= 3 {
		events = append(events, NetworkEvent{
			Type: "net.auth_failure", Time: msg.Time, Device: device,
			SrcIP: m[2], User: m[1], Severity: 3,
			Proto: "ssh", Message: text, Raw: msg.Raw,
		})
		return events
	}
	if m := reSSHSuccess.FindStringSubmatch(text); len(m) >= 3 {
		events = append(events, NetworkEvent{
			Type: "net.auth_success", Time: msg.Time, Device: device,
			SrcIP: m[2], User: m[1], Severity: 1,
			Proto: "ssh", Message: text, Raw: msg.Raw,
		})
		return events
	}

	// ── Interface state ────────────────────────────────────────────────────
	if m := reIfaceDown.FindStringSubmatch(text); len(m) >= 3 {
		state := strings.ToLower(m[2])
		evType := "net.iface_up"
		if state == "down" {
			evType = "net.iface_down"
		}
		events = append(events, NetworkEvent{
			Type: evType, Time: msg.Time, Device: device,
			Interface: m[1], Severity: 3, Message: text, Raw: msg.Raw,
		})
		return events
	}

	// ── VPN ────────────────────────────────────────────────────────────────
	if m := reVPNConnect.FindStringSubmatch(text); len(m) >= 2 {
		events = append(events, NetworkEvent{
			Type: "net.vpn_connect", Time: msg.Time, Device: device,
			SrcIP: m[1], Severity: 2, Message: text, Raw: msg.Raw,
		})
		return events
	}
	if m := reVPNDisconnect.FindStringSubmatch(text); len(m) >= 2 {
		events = append(events, NetworkEvent{
			Type: "net.vpn_disconnect", Time: msg.Time, Device: device,
			SrcIP: m[1], Severity: 1, Message: text, Raw: msg.Raw,
		})
		return events
	}

	// ── Config change ──────────────────────────────────────────────────────
	if reConfigChange.MatchString(text) {
		events = append(events, NetworkEvent{
			Type: "net.config_change", Time: msg.Time, Device: device,
			Severity: 4, Message: text, Raw: msg.Raw,
		})
		return events
	}

	// ── Device auth ────────────────────────────────────────────────────────
	if m := reDeviceAuthFail.FindStringSubmatch(text); len(m) > 0 {
		srcIP := ""
		if len(m) >= 2 {
			srcIP = m[1]
		}
		events = append(events, NetworkEvent{
			Type: "net.auth_failure", Time: msg.Time, Device: device,
			SrcIP: srcIP, Severity: 3, Message: text, Raw: msg.Raw,
		})
		return events
	}

	// ── Generic firewall allow/deny ────────────────────────────────────────
	if m := reGenericFW.FindStringSubmatch(text); len(m) >= 6 {
		action := strings.ToLower(m[1])
		evType := "net.fw_allow"
		sev := 1
		if containsAny(action, "deny", "drop", "block", "reject") {
			evType = "net.fw_deny"
			sev = 2
		}
		events = append(events, NetworkEvent{
			Type: evType, Time: msg.Time, Device: device,
			Proto: m[2], SrcIP: m[3], SrcPort: toInt(m[4]),
			DstIP: m[5], DstPort: toInt(m[6]),
			Action: action, Severity: sev, Message: text, Raw: msg.Raw,
		})
		return events
	}

	// ── Generic syslog (anything else) ────────────────────────────────────
	sev := syslogSevToInt(msg.Severity)
	events = append(events, NetworkEvent{
		Type: "net.syslog", Time: msg.Time, Device: device,
		Severity: sev, Message: text, Raw: msg.Raw,
	})
	return events
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func toInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func parseKV(text string, re *regexp.Regexp) map[string]string {
	m := make(map[string]string)
	for _, match := range re.FindAllStringSubmatch(text, -1) {
		if len(match) >= 3 {
			m[strings.ToLower(match[1])] = match[2]
		}
	}
	return m
}

func protoNum(s string) string {
	switch s {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	default:
		return strings.ToLower(s)
	}
}

func syslogSevToInt(sev int) int {
	// syslog severity 0=emerg,1=alert,2=crit,3=err,4=warn,5=notice,6=info,7=debug
	switch {
	case sev <= 2:
		return 5 // Critical
	case sev == 3:
		return 4 // High
	case sev == 4:
		return 3 // Medium
	default:
		return 1 // Info
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
