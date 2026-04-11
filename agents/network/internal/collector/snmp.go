package collector

// snmp.go — SNMP v2c/v3 poller
// Polls network devices every 60s for:
//   - Interface stats (bytes in/out per physical port)
//   - Device health (CPU, memory, uptime)
//   - ARP table (IP→MAC mapping for device discovery)
//   - CDP/LLDP neighbors (topology)

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/gosnmp/gosnmp"

	"obsidianwatch/network-probe/internal/config"
	"obsidianwatch/network-probe/internal/store"
	"obsidianwatch/network-probe/pkg/schema"
)

// OID constants
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysUptime   = "1.3.6.1.2.1.1.3.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidIfDescr     = "1.3.6.1.2.1.2.2.1.2"    // ifDescr table
	oidIfInOctets  = "1.3.6.1.2.1.2.2.1.10"   // ifInOctets
	oidIfOutOctets = "1.3.6.1.2.1.2.2.1.16"   // ifOutOctets
	oidIfInErrors  = "1.3.6.1.2.1.2.2.1.14"   // ifInErrors
	oidIfOutErrors = "1.3.6.1.2.1.2.2.1.20"   // ifOutErrors
	oidIfOperStatus = "1.3.6.1.2.1.2.2.1.8"   // ifOperStatus (1=up, 2=down)
	oidAtPhysAddr  = "1.3.6.1.2.1.3.1.1.2"    // ARP table MAC
	oidAtNetAddr   = "1.3.6.1.2.1.3.1.1.3"    // ARP table IP
	oidCiscoCPU    = "1.3.6.1.4.1.9.2.1.57.0" // Cisco CPU 5min avg
	oidCiscoMem    = "1.3.6.1.4.1.9.9.48.1.1.1.5.1" // Cisco free mem
)

type SNMPCollector struct {
	cfg     config.SNMPConfig
	db      *store.DB
	out     chan<- schema.ProbeEvent
	logger  *slog.Logger
	probeID string
	host    string
	// previous interface counters for delta calculation
	prevCounters map[string]ifCounters
}

type ifCounters struct {
	inOctets  uint64
	outOctets uint64
	ts        time.Time
}

func NewSNMPCollector(cfg config.SNMPConfig, db *store.DB,
	probeID, host string, out chan<- schema.ProbeEvent, logger *slog.Logger) *SNMPCollector {
	return &SNMPCollector{
		cfg: cfg, db: db, out: out,
		logger: logger, probeID: probeID, host: host,
		prevCounters: make(map[string]ifCounters),
	}
}

func (c *SNMPCollector) Run(ctx context.Context) error {
	if len(c.cfg.Targets) == 0 {
		c.logger.Info("snmp: no targets configured, skipping")
		return nil
	}
	c.logger.Info("snmp: starting", "targets", len(c.cfg.Targets))

	interval, err := time.ParseDuration(c.cfg.PollInterval)
	if err != nil {
		interval = 60 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Poll immediately
	c.pollAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.pollAll(ctx)
		}
	}
}

func (c *SNMPCollector) pollAll(ctx context.Context) {
	for _, target := range c.cfg.Targets {
		go c.pollTarget(ctx, target)
	}
}

func (c *SNMPCollector) pollTarget(ctx context.Context, target config.SNMPTarget) {
	g := &gosnmp.GoSNMP{
		Target:    target.Host,
		Port:      uint16(target.Port),
		Community: target.Community,
		Version:   gosnmp.Version2c,
		Timeout:   5 * time.Second,
		Retries:   1,
		Logger:    gosnmp.NewLogger(noopLogger{}),
	}
	if target.Port == 0 {
		g.Port = 161
	}
	if target.Version == "v3" {
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = gosnmp.AuthPriv
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 target.Username,
			AuthenticationProtocol:   snmpAuthProto(target.AuthProto),
			AuthenticationPassphrase: target.AuthKey,
			PrivacyProtocol:          snmpPrivProto(target.PrivProto),
			PrivacyPassphrase:        target.PrivKey,
		}
	}

	if err := g.Connect(); err != nil {
		c.logger.Warn("snmp: connect failed", "host", target.Host, "err", err)
		c.emit(schema.ProbeEvent{
			ID:        eventID("snmp-down", target.Host),
			Time:      time.Now().UTC(),
			AgentID:   c.probeID, Host: c.host, OS: "network-probe",
			EventType: schema.EventDeviceDown,
			Severity:  schema.SevHigh, Source: "snmp",
			DstIP: target.Host,
			Raw:   toRaw(map[string]interface{}{"host": target.Host, "error": err.Error()}),
		})
		return
	}
	defer g.Conn.Close()

	label := target.Label
	if label == "" {
		label = target.Host
	}

	// ── System info ────────────────────────────────────────────────────────
	sysResult, err := g.Get([]string{oidSysDescr, oidSysUptime, oidSysName})
	if err != nil {
		return
	}
	sysDescr, sysName, uptimeSec := "", "", uint64(0)
	for _, v := range sysResult.Variables {
		switch v.Name {
		case "."+oidSysDescr:
			sysDescr = string(v.Value.([]byte))
		case "."+oidSysName:
			sysName = string(v.Value.([]byte))
		case "."+oidSysUptime:
			if u, ok := v.Value.(uint32); ok {
				uptimeSec = uint64(u) / 100 // centiseconds → seconds
			}
		}
	}

	// ── Interface stats ────────────────────────────────────────────────────
	ifStats := c.pollInterfaces(g, target.Host)

	// ── ARP table ──────────────────────────────────────────────────────────
	c.pollARP(ctx, g)

	// ── Send device health event ───────────────────────────────────────────
	c.emit(schema.ProbeEvent{
		ID:        eventID("snmp-health", target.Host),
		Time:      time.Now().UTC(),
		AgentID:   c.probeID, Host: c.host, OS: "network-probe",
		EventType: schema.EventDeviceHealth,
		Severity:  schema.SevInfo, Source: "snmp",
		DstIP: target.Host,
		Raw: toRaw(map[string]interface{}{
			"host":        target.Host,
			"label":       label,
			"sys_name":    sysName,
			"sys_descr":   sysDescr,
			"uptime_sec":  uptimeSec,
			"interfaces":  ifStats,
		}),
	})
}

type ifStat struct {
	Name      string  `json:"name"`
	InBytes   uint64  `json:"in_bytes"`
	OutBytes  uint64  `json:"out_bytes"`
	InBps     float64 `json:"in_bps"`   // bytes/sec delta
	OutBps    float64 `json:"out_bps"`
	InErrors  uint64  `json:"in_errors"`
	OutErrors uint64  `json:"out_errors"`
	Status    string  `json:"status"` // up|down
}

func (c *SNMPCollector) pollInterfaces(g *gosnmp.GoSNMP, host string) []ifStat {
	// Walk interface tables
	descrTable := make(map[string]string)
	inTable := make(map[string]uint64)
	outTable := make(map[string]uint64)
	inErrTable := make(map[string]uint64)
	outErrTable := make(map[string]uint64)
	statusTable := make(map[string]string)

	walkTable := func(oid string, fn func(index string, v gosnmp.SnmpPDU)) {
		g.BulkWalk(oid, func(pdu gosnmp.SnmpPDU) error {
			// Extract index (last OID component)
			idx := lastOIDComponent(pdu.Name)
			fn(idx, pdu)
			return nil
		})
	}

	walkTable(oidIfDescr, func(idx string, v gosnmp.SnmpPDU) {
		if b, ok := v.Value.([]byte); ok {
			descrTable[idx] = string(b)
		}
	})
	walkTable(oidIfInOctets, func(idx string, v gosnmp.SnmpPDU) {
		inTable[idx] = toUint64(v.Value)
	})
	walkTable(oidIfOutOctets, func(idx string, v gosnmp.SnmpPDU) {
		outTable[idx] = toUint64(v.Value)
	})
	walkTable(oidIfInErrors, func(idx string, v gosnmp.SnmpPDU) {
		inErrTable[idx] = toUint64(v.Value)
	})
	walkTable(oidIfOutErrors, func(idx string, v gosnmp.SnmpPDU) {
		outErrTable[idx] = toUint64(v.Value)
	})
	walkTable(oidIfOperStatus, func(idx string, v gosnmp.SnmpPDU) {
		if v.Value.(int) == 1 {
			statusTable[idx] = "up"
		} else {
			statusTable[idx] = "down"
		}
	})

	now := time.Now()
	var stats []ifStat
	for idx, name := range descrTable {
		key := host + ":" + idx
		prev := c.prevCounters[key]
		inBytes := inTable[idx]
		outBytes := outTable[idx]

		var inBps, outBps float64
		if prev.ts.Unix() > 0 {
			elapsed := now.Sub(prev.ts).Seconds()
			if elapsed > 0 {
				inBps = float64(inBytes-prev.inOctets) / elapsed
				outBps = float64(outBytes-prev.outOctets) / elapsed
			}
		}
		c.prevCounters[key] = ifCounters{inOctets: inBytes, outOctets: outBytes, ts: now}

		stats = append(stats, ifStat{
			Name:      name,
			InBytes:   inBytes,
			OutBytes:  outBytes,
			InBps:     inBps,
			OutBps:    outBps,
			InErrors:  inErrTable[idx],
			OutErrors: outErrTable[idx],
			Status:    statusTable[idx],
		})
	}
	return stats
}

func (c *SNMPCollector) pollARP(ctx context.Context, g *gosnmp.GoSNMP) {
	// Walk ARP table: OID .1.3.6.1.2.1.3.1.1.2 (MAC) and .1.3.6.1.2.1.3.1.1.3 (IP)
	macMap := make(map[string]string) // index → MAC
	g.BulkWalk(oidAtPhysAddr, func(pdu gosnmp.SnmpPDU) error {
		idx := lastOIDComponent(pdu.Name)
		if b, ok := pdu.Value.([]byte); ok && len(b) == 6 {
			mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				b[0], b[1], b[2], b[3], b[4], b[5])
			macMap[idx] = mac
		}
		return nil
	})
	g.BulkWalk(oidAtNetAddr, func(pdu gosnmp.SnmpPDU) error {
		idx := lastOIDComponent(pdu.Name)
		mac, ok := macMap[idx]
		if !ok {
			return nil
		}
		if b, ok := pdu.Value.([]byte); ok && len(b) == 4 {
			ip := net.IP(b).String()
			macChanged, oldMAC, _ := c.db.UpsertARP(ctx, ip, mac, "")
			vendor := store.VendorFromMAC(mac)

			// New device seen via ARP
			dev := store.Device{MAC: mac, IP: ip, Vendor: vendor,
				FirstSeen: time.Now(), LastSeen: time.Now()}
			isNew, _ := c.db.UpsertDevice(ctx, dev)

			if isNew {
				c.emit(schema.ProbeEvent{
					ID:        eventID("new-dev-arp", mac),
					Time:      time.Now().UTC(),
					AgentID:   c.probeID, Host: c.host, OS: "network-probe",
					EventType: schema.EventNewDevice,
					Severity:  schema.SevMedium, Source: "snmp-arp",
					SrcIP: ip,
					Raw: toRaw(map[string]interface{}{
						"mac": mac, "ip": ip, "vendor": vendor, "via": "snmp-arp",
					}),
				})
			}

			// ARP spoofing detection (MAC changed for same IP)
			if macChanged {
				c.emit(schema.ProbeEvent{
					ID:        eventID("mac-change", ip),
					Time:      time.Now().UTC(),
					AgentID:   c.probeID, Host: c.host, OS: "network-probe",
					EventType: schema.EventMACChange,
					Severity:  schema.SevCritical, Source: "snmp-arp",
					SrcIP: ip,
					Raw: toRaw(map[string]interface{}{
						"ip": ip, "old_mac": oldMAC, "new_mac": mac,
						"note": "possible ARP spoofing / MITM",
					}),
				})
			}
		}
		return nil
	})
}

func (c *SNMPCollector) emit(ev schema.ProbeEvent) {
	select {
	case c.out <- ev:
	default:
	}
}

// Helpers
func toUint64(v interface{}) uint64 {
	switch n := v.(type) {
	case uint:
		return uint64(n)
	case uint32:
		return uint64(n)
	case uint64:
		return n
	case int:
		return uint64(n)
	}
	return 0
}

func lastOIDComponent(oid string) string {
	parts := splitOID(oid)
	if len(parts) == 0 {
		return oid
	}
	return parts[len(parts)-1]
}

func splitOID(oid string) []string {
	start := 0
	if len(oid) > 0 && oid[0] == '.' {
		start = 1
	}
	result := []string{}
	last := start
	for i := start; i < len(oid); i++ {
		if oid[i] == '.' {
			result = append(result, oid[last:i])
			last = i + 1
		}
	}
	result = append(result, oid[last:])
	return result
}

func snmpAuthProto(s string) gosnmp.SnmpV3AuthProtocol {
	if s == "SHA" {
		return gosnmp.SHA
	}
	return gosnmp.MD5
}

func snmpPrivProto(s string) gosnmp.SnmpV3PrivProtocol {
	if s == "AES" {
		return gosnmp.AES
	}
	return gosnmp.DES
}

type noopLogger struct{}

func (noopLogger) Print(v ...interface{})                 {}
func (noopLogger) Printf(format string, v ...interface{}) {}
