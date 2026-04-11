package config

import (
	"fmt"
	"os"
	"strings"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Probe     ProbeConfig     `yaml:"probe"`
	Forwarder ForwarderConfig `yaml:"forwarder"`
	Syslog    SyslogConfig    `yaml:"syslog"`
	NetFlow   NetFlowConfig   `yaml:"netflow"`
	SNMP      SNMPConfig      `yaml:"snmp"`
	ARP       ARPConfig       `yaml:"arp"`
	Detection DetectionConfig `yaml:"detection"`
	Store     StoreConfig     `yaml:"store"`
	Log       LogConfig       `yaml:"log"`
}

type ProbeConfig struct {
	ID       string `yaml:"id"`       // auto-generated on first run
	Version  string `yaml:"version"`
	Location string `yaml:"location"` // e.g. "HQ-Floor2", "DataCenter-Rack3"
	SiteName string `yaml:"site_name"`
}

type ForwarderConfig struct {
	BackendURL     string `yaml:"backend_url"`
	ManagementURL  string `yaml:"management_url"`
	APIKey         string `yaml:"api_key"`
	CACertPEM      string `yaml:"ca_cert_pem"`
	ManagementCACert string `yaml:"management_ca_cert_pem"`
	BatchSize      int    `yaml:"batch_size"`
	FlushInterval  string `yaml:"flush_interval"`
	// How often to send summaries vs real-time alerts
	SummaryInterval string `yaml:"summary_interval"` // default 5m
}

type SyslogConfig struct {
	Enabled    bool   `yaml:"enabled"`
	UDPAddr    string `yaml:"udp_addr"`  // :514
	TCPAddr    string `yaml:"tcp_addr"`  // :514
	BufferSize int    `yaml:"buffer_size"`
}

type NetFlowConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Addr           string `yaml:"addr"`           // :2055
	SFlowAddr      string `yaml:"sflow_addr"`     // :6343
	ActiveTimeout  int    `yaml:"active_timeout"` // seconds, for flow expiry
	SummaryInterval string `yaml:"summary_interval"`
}

type SNMPConfig struct {
	Enabled      bool             `yaml:"enabled"`
	PollInterval string           `yaml:"poll_interval"` // default 60s
	AutoDiscover SNMPAutoDiscover `yaml:"auto_discover"`
	Targets      []SNMPTarget     `yaml:"targets"`
}

type SNMPTarget struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`       // default 161
	Version   string `yaml:"version"`    // v2c | v3
	Community string `yaml:"community"`  // for v2c
	// v3 fields
	Username  string `yaml:"username"`
	AuthProto string `yaml:"auth_proto"` // MD5 | SHA
	AuthKey   string `yaml:"auth_key"`
	PrivProto string `yaml:"priv_proto"` // DES | AES
	PrivKey   string `yaml:"priv_key"`
	Label     string `yaml:"label"`      // friendly name e.g. "core-switch"
}

type ARPConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Interfaces   []string `yaml:"interfaces"` // e.g. ["eth0", "eth1"]
	PollInterval string `yaml:"poll_interval"` // default 30s
	// Known devices — don't alert on these
	KnownMACs    []string `yaml:"known_macs"`
}

type DetectionConfig struct {
	// Port scan detection
	PortScanThreshold    int `yaml:"port_scan_threshold"`    // distinct ports/min to trigger
	PortScanWindow       int `yaml:"port_scan_window"`       // seconds
	// Brute force
	BruteForceThreshold  int `yaml:"brute_force_threshold"`  // failures/min
	// Bandwidth spike
	BandwidthSpikeMultiplier float64 `yaml:"bandwidth_spike_multiplier"` // 3x baseline
	// Lateral movement (east-west new connection)
	LateralMovementEnabled bool `yaml:"lateral_movement_enabled"`
	// Known subnets — traffic outside these is flagged
	InternalSubnets []string `yaml:"internal_subnets"` // e.g. ["192.168.0.0/16"]
}

type StoreConfig struct {
	DBPath        string `yaml:"db_path"`         // SQLite path for local state
	RetentionDays int    `yaml:"retention_days"`  // how long to keep local data
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	setDefaults(&cfg)
	return &cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.Probe.Version == "" { cfg.Probe.Version = "0.1.0" }
	if cfg.Syslog.UDPAddr == "" { cfg.Syslog.UDPAddr = ":514" }
	if cfg.Syslog.TCPAddr == "" { cfg.Syslog.TCPAddr = ":514" }
	if cfg.Syslog.BufferSize == 0 { cfg.Syslog.BufferSize = 65536 }
	if cfg.NetFlow.Addr == "" { cfg.NetFlow.Addr = ":2055" }
	if cfg.NetFlow.SFlowAddr == "" { cfg.NetFlow.SFlowAddr = ":6343" }
	if cfg.NetFlow.ActiveTimeout == 0 { cfg.NetFlow.ActiveTimeout = 30 }
	if cfg.NetFlow.SummaryInterval == "" { cfg.NetFlow.SummaryInterval = "5m" }
	if cfg.SNMP.PollInterval == "" { cfg.SNMP.PollInterval = "60s" }
	if cfg.ARP.PollInterval == "" { cfg.ARP.PollInterval = "30s" }
	if cfg.Detection.PortScanThreshold == 0 { cfg.Detection.PortScanThreshold = 20 }
	if cfg.Detection.PortScanWindow == 0 { cfg.Detection.PortScanWindow = 60 }
	if cfg.Detection.BruteForceThreshold == 0 { cfg.Detection.BruteForceThreshold = 10 }
	if cfg.Detection.BandwidthSpikeMultiplier == 0 { cfg.Detection.BandwidthSpikeMultiplier = 3.0 }
	if cfg.Store.DBPath == "" { cfg.Store.DBPath = "/var/lib/obsidianwatch-probe/state.db" }
	if cfg.Store.RetentionDays == 0 { cfg.Store.RetentionDays = 7 }
	if cfg.Forwarder.BatchSize == 0 { cfg.Forwarder.BatchSize = 200 }
	if cfg.Forwarder.FlushInterval == "" { cfg.Forwarder.FlushInterval = "10s" }
	if cfg.Forwarder.SummaryInterval == "" { cfg.Forwarder.SummaryInterval = "5m" }
	if cfg.Log.Level == "" { cfg.Log.Level = "info" }
	if cfg.Log.Format == "" { cfg.Log.Format = "json" }
}

// LoadFromString parses config from a YAML string (used for embedded config)
func LoadFromString(s string) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(s), &cfg); err != nil {
		return nil, err
	}
	setDefaults(&cfg)
	return &cfg, nil
}

// SNMPAutoDiscover config for automatic subnet scanning
type SNMPAutoDiscover struct {
	Subnet    string `yaml:"subnet"`    // e.g. 192.168.1.0/24
	Community string `yaml:"community"` // SNMP v2c community
}

// AppendSNMPTargets adds newly discovered targets to the on-disk config file
func AppendSNMPTargets(cfgPath string, targets []SNMPTarget) error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	var lines []string
	for _, t := range targets {
		lines = append(lines, fmt.Sprintf(
			"    - host: %q\n      port: 161\n      version: \"v2c\"\n      community: \"public\"\n      label: %q",
			t.Host, t.Label))
	}
	// Replace empty targets list with discovered ones
	updated := strings.ReplaceAll(string(data),
		"  targets: []",
		"  targets:\n"+strings.Join(lines, "\n"))
	return os.WriteFile(cfgPath, []byte(updated), 0600)
}
