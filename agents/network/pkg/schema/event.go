package schema

import (
	"encoding/json"
	"time"
)

// ProbeEvent is a normalized event from the network probe.
// Sent to the management backend in the same batch format as endpoint agents.
type ProbeEvent struct {
	ID        string          `json:"id"`
	Time      time.Time       `json:"time"`
	AgentID   string          `json:"agent_id"`
	Host      string          `json:"host"`   // probe hostname
	OS        string          `json:"os"`     // "network-probe"
	EventType string          `json:"event_type"`
	Severity  int             `json:"severity"`
	Source    string          `json:"source"` // syslog | netflow | snmp | arp
	SrcIP     string          `json:"src_ip,omitempty"`
	DstIP     string          `json:"dst_ip,omitempty"`
	SrcPort   int             `json:"src_port,omitempty"`
	DstPort   int             `json:"dst_port,omitempty"`
	Proto     string          `json:"proto,omitempty"`
	UserName  string          `json:"user_name,omitempty"`
	Raw       json.RawMessage `json:"raw,omitempty"`
}

// EventBatch mirrors the backend ingest format
type EventBatch struct {
	AgentID    string       `json:"agent_id"`
	Hostname   string       `json:"hostname"`
	AgentVer   string       `json:"agent_ver"`
	InstallKey string       `json:"install_key,omitempty"`
	Events     []ProbeEvent `json:"events"`
}

// Event types
const (
	// Syslog-derived
	EventSyslog        = "net.syslog"       // raw syslog message parsed
	EventFirewallDeny  = "net.fw_deny"      // firewall deny/drop
	EventFirewallAllow = "net.fw_allow"     // firewall permit
	EventVPNConnect    = "net.vpn_connect"  // VPN session established
	EventVPNDisconnect = "net.vpn_disconnect"
	EventAuthFailure   = "net.auth_failure" // SSH/Telnet/HTTPS login failure on device
	EventAuthSuccess   = "net.auth_success" // successful device login
	EventInterfaceDown = "net.iface_down"   // interface went down
	EventInterfaceUp   = "net.iface_up"
	EventDHCPLease     = "net.dhcp_lease"   // new DHCP lease → new device
	EventDHCPRelease   = "net.dhcp_release"
	EventConfigChange  = "net.config_change" // device config was changed

	// NetFlow-derived
	EventNetFlow       = "net.flow"         // individual flow record
	EventBandwidth     = "net.bandwidth"    // hourly bandwidth summary per device
	EventTopTalker     = "net.top_talker"   // top bandwidth consumers
	EventPortScan      = "net.port_scan"    // detected port scan
	EventLateralMove   = "net.lateral"      // east-west movement anomaly

	// SNMP-derived
	EventDeviceHealth  = "net.device_health" // CPU, memory, uptime
	EventInterfaceStat = "net.iface_stat"    // per-port bytes in/out
	EventDeviceDown    = "net.device_down"   // SNMP unreachable
	EventSNMPTrap      = "net.snmp_trap"     // SNMP trap received

	// ARP/Discovery
	EventNewDevice     = "net.new_device"   // unknown MAC seen on network
	EventDeviceSeen    = "net.device_seen"  // known device heartbeat
	EventMACChange     = "net.mac_change"   // IP address changed MAC (potential ARP spoofing)
	EventTopology      = "net.topology"     // CDP/LLDP neighbor update
	EventInventory     = "net.inventory"    // full device+ARP+topology snapshot

	// Severity
	SevInfo     = 1
	SevLow      = 2
	SevMedium   = 3
	SevHigh     = 4
	SevCritical = 5
)
