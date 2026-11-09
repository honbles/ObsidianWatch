package main

// main.go — ObsidianWatch Network Probe entry point
//
// Commands:
//   (no args)                       — run the probe
//   install [--subnet 192.168.1.0/24] [--community public] [--site "HQ"]
//                                   — install as systemd service + write config
//   uninstall                       — remove service + binary
//   discover --subnet 192.168.1.0/24 [--community public]
//                                   — scan subnet, print discovered devices
//   version                         — print version

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"obsidianwatch/network-probe/internal/collector"
	cfg_pkg "obsidianwatch/network-probe/internal/config"
	"obsidianwatch/network-probe/internal/forwarder"
	"obsidianwatch/network-probe/internal/store"
	"obsidianwatch/network-probe/pkg/schema"
)

const (
	version    = "0.1.0"
	binaryDest = "/usr/local/bin/obsidianwatch-network-probe"
	configDir  = "/etc/obsidianwatch-probe"
	configPath = "/etc/obsidianwatch-probe/probe.yaml"
	dataDir    = "/var/lib/obsidianwatch-probe"
	unitPath   = "/etc/systemd/system/obsidianwatch-probe.service"
)

func main() {
	if len(os.Args) < 2 {
		runProbe()
		return
	}
	switch os.Args[1] {
	case "install":
		cmdInstall(os.Args[2:])
	case "uninstall":
		cmdUninstall()
	case "discover":
		cmdDiscover(os.Args[2:])
	case "version":
		fmt.Println("obsidianwatch-network-probe", version)
	default:
		runProbe()
	}
}

// ── Run ───────────────────────────────────────────────────────────────────────

func runProbe() {
	// Load config — embedded (baked by agent builder) takes priority
	var cfg *cfg_pkg.Config
	var err error
	if cfg_pkg.EmbeddedConfig != "" {
		cfg, err = cfg_pkg.LoadFromString(cfg_pkg.EmbeddedConfig)
	} else {
		cfg, err = cfg_pkg.Load(configPath)
	}
	if err != nil {
		fatalf("config error: %v\n", err)
	}

	// Logger
	level := slog.LevelInfo
	if cfg.Log.Level == "debug" {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	// Ensure data directory exists
	mustMkdir(dataDir)

	// Probe ID — stable across restarts
	probeID := loadOrCreateID(filepath.Join(dataDir, "probe.id"))
	hostname, _ := os.Hostname()
	if cfg.Probe.SiteName != "" {
		hostname = cfg.Probe.SiteName
	}

	logger.Info("network probe starting",
		"id", probeID,
		"site", hostname,
		"location", cfg.Probe.Location,
		"version", version,
	)

	// Local SQLite
	db, err := store.Open(filepath.Join(dataDir, "probe.db"))
	if err != nil {
		logger.Error("store open failed", "err", err)
		os.Exit(1)
	}

	// Event channel
	eventCh := make(chan schema.ProbeEvent, 10000)

	// Forwarder
	fwd, err := forwarder.New(cfg.Forwarder, probeID, hostname, version, logger)
	if err != nil {
		logger.Error("forwarder init failed", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Collectors ─────────────────────────────────────────────────────────

	if cfg.Syslog.Enabled {
		sc := collector.NewSyslogCollector(
			cfg.Syslog, cfg.Detection, db, probeID, hostname, eventCh, logger)
		go sc.Run(ctx)
		logger.Info("syslog collector started", "udp", cfg.Syslog.UDPAddr)
	}

	if cfg.NetFlow.Enabled {
		nc := collector.NewNetFlowCollector(
			cfg.NetFlow, cfg.Detection, db, probeID, hostname, eventCh, logger)
		go nc.Run(ctx)
		logger.Info("netflow collector started", "addr", cfg.NetFlow.Addr)
	}

	if cfg.SNMP.Enabled {
		// Auto-discover if subnet configured and no explicit targets
		if cfg.SNMP.AutoDiscover.Subnet != "" && len(cfg.SNMP.Targets) == 0 {
			logger.Info("snmp: auto-discovering devices",
				"subnet", cfg.SNMP.AutoDiscover.Subnet)
			discovered := collector.DiscoverSNMP(ctx,
				cfg.SNMP.AutoDiscover.Subnet,
				cfg.SNMP.AutoDiscover.Community,
				logger)
			cfg.SNMP.Targets = append(cfg.SNMP.Targets, discovered...)
			logger.Info("snmp: discovery complete", "found", len(discovered))
			// Persist discovered targets to config file for next run
			if len(discovered) > 0 {
				cfg_pkg.AppendSNMPTargets(configPath, discovered)
			}
		}
		sc := collector.NewSNMPCollector(
			cfg.SNMP, db, probeID, hostname, eventCh, logger)
		go sc.Run(ctx)
		logger.Info("snmp collector started", "targets", len(cfg.SNMP.Targets))
	}

	if cfg.ARP.Enabled {
		ac := collector.NewARPCollector(
			cfg.ARP, cfg.Detection, db, probeID, hostname, eventCh, logger)
		go ac.Run(ctx)
		logger.Info("arp collector started", "interfaces", cfg.ARP.Interfaces)
	}

	// ── Forwarder ──────────────────────────────────────────────────────────
	go fwd.Run(ctx, eventCh)

	// ── Analysis engine — runs queries on SQLite, sends summaries ──────────
	ae := collector.NewAnalysisEngine(db, fwd, probeID, hostname, logger)
	go ae.Run(ctx)

	// ── Device inventory broadcast every 5 min ────────────────────────────
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		// Send immediately on startup
		sendInventory(ctx, db, fwd)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sendInventory(ctx, db, fwd)
			}
		}
	}()

	// ── Daily cleanup of old SQLite data ──────────────────────────────────
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				db.Cleanup(ctx, cfg.Store.RetentionDays)
				logger.Info("store: cleanup complete",
					"retention_days", cfg.Store.RetentionDays)
			}
		}
	}()

	// ── Graceful shutdown ──────────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	got := <-sig
	logger.Info("shutting down...")
	finalRaw, _ := json.Marshal(map[string]interface{}{
		"reason": "signal", "signal": got.String(), "probe_id": probeID,
	})
	fwd.SendFinal(schema.ProbeEvent{
		ID:        fmt.Sprintf("tamper:%s:%d", probeID, time.Now().UnixNano()),
		OS:        "network-probe",
		EventType: "probe.tamper",
		Severity:  schema.SevHigh,
		Source:    "probe",
		Raw:       finalRaw,
	})
	cancel()
	time.Sleep(3 * time.Second)
}

func sendInventory(ctx context.Context, db *store.DB, fwd *forwarder.Forwarder) {
	devices, _ := db.GetAllDevices(ctx)
	arp, _ := db.GetARPTable(ctx)
	topology, _ := db.GetTopology(ctx)
	fwd.SendInventory(ctx, devices, arp, topology)
}

// ── Install command ───────────────────────────────────────────────────────────

func cmdInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	subnet    := fs.String("subnet",    "",       "Subnet for SNMP auto-discovery, e.g. 192.168.1.0/24")
	community := fs.String("community", "public", "SNMP community string")
	site      := fs.String("site",      "",       "Site name shown in dashboard, e.g. HQ-Network")
	location  := fs.String("location",  "",       "Physical location, e.g. Server Room")
	fs.Parse(args)

	fmt.Println("ObsidianWatch Network Probe — Installer")
	fmt.Println("========================================")

	// 1. Create directories
	mustMkdir(configDir)
	mustMkdir(dataDir)
	fmt.Println("✓ Created directories")

	// 2. Copy binary to /usr/local/bin/
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		fatalf("cannot read own binary: %v\n", err)
	}
	if err := os.WriteFile(binaryDest, self, 0755); err != nil {
		fatalf("cannot write binary to %s: %v\n", binaryDest, err)
	}
	fmt.Printf("✓ Binary installed to %s\n", binaryDest)

	// 3. Write config file (from embedded or generate default)
	var cfgContent string
	if cfg_pkg.EmbeddedConfig != "" {
		cfgContent = cfg_pkg.EmbeddedConfig
		// Patch site name if provided via flag
		if *site != "" {
			cfgContent = strings.ReplaceAll(cfgContent,
				`site_name: ""`, fmt.Sprintf(`site_name: %q`, *site))
			cfgContent = strings.ReplaceAll(cfgContent,
				"site_name: \"HQ-Network\"", fmt.Sprintf(`site_name: %q`, *site))
		}
	} else {
		cfgContent = generateDefaultConfig(*site, *location, *subnet, *community)
	}

	cfgFile := filepath.Join(configDir, "probe.yaml")
	if err := os.WriteFile(cfgFile, []byte(cfgContent), 0600); err != nil {
		fatalf("cannot write config: %v\n", err)
	}
	fmt.Printf("✓ Config written to %s\n", cfgFile)

	// 4. Run SNMP auto-discovery if subnet provided
	if *subnet != "" {
		fmt.Printf("\nDiscovering SNMP devices on %s...\n", *subnet)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		discovered := collector.DiscoverSNMP(ctx, *subnet, *community, logger)
		if len(discovered) > 0 {
			cfg_pkg.AppendSNMPTargets(cfgFile, discovered)
			fmt.Printf("✓ Discovered and saved %d SNMP devices\n", len(discovered))
			for _, t := range discovered {
				fmt.Printf("  • %s (%s)\n", t.Host, t.Label)
			}
		} else {
			fmt.Printf("  No SNMP devices found on %s (devices may need SNMP enabled)\n", *subnet)
		}
	}

	// 5. Install systemd unit
	if err := os.WriteFile(unitPath, []byte(systemdUnit()), 0644); err != nil {
		fatalf("cannot write systemd unit: %v\n", err)
	}
	fmt.Printf("✓ systemd unit installed at %s\n", unitPath)

	// 6. Print next steps
	fmt.Println("\n========================================")
	fmt.Println("Installation complete. Next steps:")
	fmt.Println("")
	fmt.Println("  1. Edit config if needed:")
	fmt.Printf("       nano %s\n", cfgFile)
	fmt.Println("")
	fmt.Println("  2. Start and enable the probe:")
	fmt.Println("       systemctl enable --now obsidianwatch-probe")
	fmt.Println("")
	fmt.Println("  3. Configure network devices to send syslog to this host:")
	fmt.Println("       Cisco:     logging <THIS-HOST-IP>")
	fmt.Println("       Palo Alto: Device → Server Profiles → Syslog")
	fmt.Println("       Fortinet:  config log syslogd → set server <THIS-HOST-IP>")
	fmt.Println("       pfSense:   Status → System Logs → Settings → Remote log server")
	fmt.Println("")
	fmt.Println("  4. Configure NetFlow export to this host port 2055:")
	fmt.Println("       Cisco IOS: ip flow-export destination <THIS-HOST-IP> 2055")
	fmt.Println("                  ip flow-export version 9")
	fmt.Println("")
	fmt.Println("  5. View logs:")
	fmt.Println("       journalctl -u obsidianwatch-probe -f")
}

// ── Discover command ──────────────────────────────────────────────────────────

func cmdDiscover(args []string) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	subnet    := fs.String("subnet",    "",       "Subnet to scan, e.g. 192.168.1.0/24")
	community := fs.String("community", "public", "SNMP v2c community string")
	fs.Parse(args)

	if *subnet == "" {
		fmt.Println("Usage: obsidianwatch-network-probe discover --subnet 192.168.1.0/24")
		os.Exit(1)
	}

	fmt.Printf("Scanning %s for SNMP devices...\n\n", *subnet)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	devices := collector.DiscoverSNMP(ctx, *subnet, *community, logger)

	if len(devices) == 0 {
		fmt.Println("No SNMP-capable devices found.")
		fmt.Println("Ensure devices have SNMP enabled and community string is correct.")
		return
	}

	fmt.Printf("Found %d device(s):\n\n", len(devices))
	fmt.Printf("%-18s %-20s %-10s %-30s\n", "IP", "Label", "Version", "Description")
	fmt.Println(strings.Repeat("-", 80))
	for _, d := range devices {
		fmt.Printf("%-18s %-20s %-10s %-30s\n",
			d.Host, d.Label, d.Version, truncate(d.Label, 30))
	}
	fmt.Println("\nAdd these to your probe.yaml under snmp.targets")
}

// ── Uninstall ─────────────────────────────────────────────────────────────────

func cmdUninstall() {
	fmt.Println("Uninstalling ObsidianWatch Network Probe...")
	os.Remove(unitPath)
	os.Remove(binaryDest)
	fmt.Println("✓ Service unit and binary removed")
	fmt.Println("  Config and data preserved at:")
	fmt.Printf("    %s\n", configDir)
	fmt.Printf("    %s\n", dataDir)
	fmt.Println("  Remove manually if desired.")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func systemdUnit() string {
	return `[Unit]
Description=ObsidianWatch Network Probe
Documentation=https://docs.obsidianwatch.io/network-probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/obsidianwatch-network-probe
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536
# Allow binding to syslog port 514 without full root
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
# Protect rest of system
ProtectSystem=strict
ReadWritePaths=/var/lib/obsidianwatch-probe /etc/obsidianwatch-probe
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryMax=512M

[Install]
WantedBy=multi-user.target
`
}

func generateDefaultConfig(site, location, subnet, community string) string {
	if site == "" {
		site = "Network-Site-1"
	}
	snmpTargets := "  targets: []\n"
	if subnet != "" {
		snmpTargets = fmt.Sprintf(
			"  auto_discover:\n    subnet: %q\n    community: %q\n  targets: []\n",
			subnet, community)
	}
	return fmt.Sprintf(`# ObsidianWatch Network Probe Configuration
# Edit this file then restart: systemctl restart obsidianwatch-probe

probe:
  version: "0.1.0"
  site_name: %q
  location:  %q

forwarder:
  backend_url:    ""   # ← REQUIRED: e.g. https://192.168.1.140:8443
  management_url: ""   # ← REQUIRED: e.g. http://192.168.1.140
  api_key:        ""   # ← REQUIRED: agent API key from Agent Builder
  batch_size:     200
  flush_interval: "10s"

syslog:
  enabled:     true
  udp_addr:    ":514"    # Devices send syslog here
  tcp_addr:    ":514"
  buffer_size: 65536

netflow:
  enabled:   true
  addr:      ":2055"    # Devices send NetFlow/IPFIX here
  sflow_addr: ":6343"   # Devices send sFlow here

snmp:
  enabled:       true
  poll_interval: "60s"
%s
arp:
  enabled:       true
  interfaces:    ["eth0"]
  poll_interval: "30s"

detection:
  port_scan_threshold:           20
  port_scan_window:              60
  brute_force_threshold:         10
  bandwidth_spike_multiplier:    3.0
  lateral_movement_enabled:      true
  internal_subnets:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"

store:
  db_path:        "/var/lib/obsidianwatch-probe/probe.db"
  retention_days: 7

log:
  level:  "info"
  format: "json"
`, site, location, snmpTargets)
}

func loadOrCreateID(path string) string {
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		return strings.TrimSpace(string(data))
	}
	id := fmt.Sprintf("netprobe-%d", time.Now().UnixNano())
	os.MkdirAll(filepath.Dir(path), 0700)
	os.WriteFile(path, []byte(id), 0600)
	return id
}

func mustMkdir(path string) {
	// Holds the flow database and probe config (SNMP communities, API key):
	// root-only.
	if err := os.MkdirAll(path, 0700); err != nil {
		fatalf("cannot create directory %s: %v\n", path, err)
	}
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format, args...)
	os.Exit(1)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
