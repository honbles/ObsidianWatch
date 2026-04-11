package collector

// arp.go — Active ARP monitoring via /proc/net/arp (Linux)
// Reads the kernel ARP table periodically.
// Detects: new devices, MAC changes (ARP spoofing), stale devices.

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"obsidianwatch/network-probe/internal/config"
	"obsidianwatch/network-probe/internal/store"
	"obsidianwatch/network-probe/pkg/schema"
)

type ARPCollector struct {
	cfg     config.ARPConfig
	det     config.DetectionConfig
	db      *store.DB
	out     chan<- schema.ProbeEvent
	logger  *slog.Logger
	probeID string
	host    string
}

func NewARPCollector(cfg config.ARPConfig, det config.DetectionConfig,
	db *store.DB, probeID, host string, out chan<- schema.ProbeEvent,
	logger *slog.Logger) *ARPCollector {
	return &ARPCollector{
		cfg: cfg, det: det, db: db, out: out,
		logger: logger, probeID: probeID, host: host,
	}
}

func (c *ARPCollector) Run(ctx context.Context) error {
	interval, err := time.ParseDuration(c.cfg.PollInterval)
	if err != nil {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Poll immediately on start
	c.poll(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.poll(ctx)
		}
	}
}

func (c *ARPCollector) poll(ctx context.Context) {
	entries, err := readARPTable()
	if err != nil {
		c.logger.Warn("arp: read failed", "err", err)
		return
	}

	for _, e := range entries {
		if e.MAC == "" || e.MAC == "00:00:00:00:00:00" {
			continue
		}

		// Check for MAC change on same IP (ARP spoofing indicator)
		macChanged, oldMAC, _ := c.db.UpsertARP(ctx, e.IP, e.MAC, e.Iface)
		if macChanged {
			c.logger.Warn("arp: MAC change detected — possible ARP spoofing",
				"ip", e.IP, "old_mac", oldMAC, "new_mac", e.MAC)
			c.emit(schema.ProbeEvent{
				ID:        eventID("mac-change", e.IP),
				Time:      time.Now().UTC(),
				AgentID:   c.probeID, Host: c.host, OS: "network-probe",
				EventType: schema.EventMACChange,
				Severity:  schema.SevCritical,
				Source:    "arp",
				SrcIP:     e.IP,
				Raw: toRaw(map[string]interface{}{
					"ip":      e.IP,
					"old_mac": oldMAC,
					"new_mac": e.MAC,
					"iface":   e.Iface,
					"note":    "IP address changed MAC — possible ARP spoofing / MITM attack",
				}),
			})
		}

		// Track device
		dev := store.Device{
			MAC:       e.MAC,
			IP:        e.IP,
			Vendor:    store.VendorFromMAC(e.MAC),
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		isNew, _ := c.db.UpsertDevice(ctx, dev)

		if isNew {
			c.logger.Info("arp: new device discovered",
				"ip", e.IP, "mac", e.MAC, "vendor", dev.Vendor)
			c.emit(schema.ProbeEvent{
				ID:        eventID("new-dev", e.MAC),
				Time:      time.Now().UTC(),
				AgentID:   c.probeID, Host: c.host, OS: "network-probe",
				EventType: schema.EventNewDevice,
				Severity:  schema.SevMedium,
				Source:    "arp",
				SrcIP:     e.IP,
				Raw: toRaw(map[string]interface{}{
					"mac":    e.MAC,
					"ip":     e.IP,
					"vendor": dev.Vendor,
					"iface":  e.Iface,
					"via":    "arp-table",
				}),
			})
		}
	}
}

type arpEntry struct {
	IP    string
	MAC   string
	Iface string
}

// readARPTable parses /proc/net/arp
// Format: IP address  HW type  Flags  HW address         Mask  Device
func readARPTable() ([]arpEntry, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []arpEntry
	scanner := bufio.NewScanner(f)
	// Skip header line
	scanner.Scan()
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// fields: [IP, HW_type, Flags, MAC, Mask, Device]
		flags := fields[2]
		// Skip incomplete entries (flag 0x0 means not resolved)
		if flags == "0x0" {
			continue
		}
		entries = append(entries, arpEntry{
			IP:    fields[0],
			MAC:   strings.ToLower(fields[3]),
			Iface: fields[5],
		})
	}
	return entries, scanner.Err()
}

func (c *ARPCollector) emit(ev schema.ProbeEvent) {
	select {
	case c.out <- ev:
	default:
	}
}
