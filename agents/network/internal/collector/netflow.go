package collector

// netflow.go — NetFlow v5/v9/IPFIX + sFlow collector
// Receives flow exports from routers/switches, stores locally,
// detects anomalies (port scan, bandwidth spike, lateral movement).

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net"
	"sync"
	"time"

	"obsidianwatch/network-probe/internal/config"
	"obsidianwatch/network-probe/internal/store"
	"obsidianwatch/network-probe/pkg/schema"
)

type NetFlowCollector struct {
	cfg     config.NetFlowConfig
	det     config.DetectionConfig
	db      *store.DB
	out     chan<- schema.ProbeEvent
	logger  *slog.Logger
	probeID string
	host    string
	// baseline: src_ip -> avg bytes/min over last hour
	baseline map[string]float64
}

func NewNetFlowCollector(cfg config.NetFlowConfig, det config.DetectionConfig,
	db *store.DB, probeID, host string, out chan<- schema.ProbeEvent, logger *slog.Logger) *NetFlowCollector {
	return &NetFlowCollector{
		cfg: cfg, det: det, db: db, out: out,
		logger: logger, probeID: probeID, host: host,
		baseline: make(map[string]float64),
	}
}

func (c *NetFlowCollector) Run(ctx context.Context) error {
	c.logger.Info("netflow: starting", "addr", c.cfg.Addr)

	go c.listenNetFlow(ctx)
	go c.runRollup(ctx)

	<-ctx.Done()
	return nil
}

// NetFlow v5 packet (fixed 20-byte header + 48-byte records)
type nfv5Header struct {
	Version        uint16
	Count          uint16
	SysUptime      uint32
	UnixSecs       uint32
	UnixNsecs      uint32
	FlowSequence   uint32
	EngineType     uint8
	EngineID       uint8
	SamplingMode   uint16
}

type nfv5Record struct {
	SrcAddr    uint32
	DstAddr    uint32
	NextHop    uint32
	Input      uint16
	Output     uint16
	DPkts      uint32
	DOctets    uint32
	First      uint32
	Last       uint32
	SrcPort    uint16
	DstPort    uint16
	_          uint8
	TCPFlags   uint8
	Proto      uint8
	ToS        uint8
	SrcAS      uint16
	DstAS      uint16
	SrcMask    uint8
	DstMask    uint8
	_          uint16
}

func (c *NetFlowCollector) listenNetFlow(ctx context.Context) {
	addr, err := net.ResolveUDPAddr("udp", c.cfg.Addr)
	if err != nil {
		c.logger.Error("netflow: resolve failed", "err", err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		c.logger.Error("netflow: listen failed", "addr", c.cfg.Addr, "err", err)
		return
	}
	defer conn.Close()
	c.logger.Info("netflow: UDP listening", "addr", c.cfg.Addr)

	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n < 24 {
			continue
		}

		version := binary.BigEndian.Uint16(buf[0:2])
		switch version {
		case 5:
			c.parseV5(ctx, buf[:n])
		case 9:
			// NetFlow v9 — simplified: extract src/dst/bytes from fixed offsets
			c.parseV9Simple(ctx, buf[:n])
		case 10:
			// IPFIX has a 16-byte header and template-defined sets; the fixed-offset
			// v9 shortcut would read garbage and raise bogus scan/lateral alerts.
			ipfixOnce.Do(func() {
				c.logger.Warn("netflow: IPFIX (v10) is not supported; packets are ignored. Export NetFlow v5/v9 or use a template-aware collector.")
			})
		}
	}
}

// ipfixOnce logs the unsupported-IPFIX warning a single time.
var ipfixOnce sync.Once

func (c *NetFlowCollector) parseV5(ctx context.Context, buf []byte) {
	if len(buf) < 24 {
		return
	}
	count := int(binary.BigEndian.Uint16(buf[2:4]))
	sysUptime := binary.BigEndian.Uint32(buf[4:8])
	unixSecs := binary.BigEndian.Uint32(buf[8:12])
	_ = sysUptime

	for i := 0; i < count; i++ {
		offset := 24 + i*48
		if offset+48 > len(buf) {
			break
		}
		rec := buf[offset : offset+48]

		srcIP := intToIP(binary.BigEndian.Uint32(rec[0:4]))
		dstIP := intToIP(binary.BigEndian.Uint32(rec[4:8]))
		srcPort := int(binary.BigEndian.Uint16(rec[32:34]))
		dstPort := int(binary.BigEndian.Uint16(rec[34:36]))
		proto := protoToStr(rec[38])
		bytes := int64(binary.BigEndian.Uint32(rec[20:24]))
		packets := int64(binary.BigEndian.Uint32(rec[16:20]))
		firstMS := int64(binary.BigEndian.Uint32(rec[24:28]))
		lastMS := int64(binary.BigEndian.Uint32(rec[28:32]))
		durationMS := lastMS - firstMS

		ts := time.Unix(int64(unixSecs), 0).UTC()

		flow := store.Flow{
			SrcIP: srcIP, DstIP: dstIP,
			SrcPort: srcPort, DstPort: dstPort,
			Proto: proto, Bytes: bytes, Packets: packets,
			DurationMS: durationMS, Time: ts,
		}
		c.db.InsertFlow(ctx, flow)
		c.analyzeFlow(ctx, flow)
	}
}

func (c *NetFlowCollector) parseV9Simple(ctx context.Context, buf []byte) {
	// Simplified v9/IPFIX: just extract what we can from common template fields
	// A full implementation would parse template records first
	// For now we extract known offsets from common Cisco/Juniper templates
	if len(buf) < 20 {
		return
	}
	// Skip header (20 bytes) and try to find flow sets
	// This handles the most common v9 format where template 0 has
	// src/dst at fixed positions
	count := int(binary.BigEndian.Uint16(buf[2:4]))
	unixSecs := binary.BigEndian.Uint32(buf[8:12])
	ts := time.Unix(int64(unixSecs), 0).UTC()

	_ = count
	// Walk flowsets after 20-byte header
	offset := 20
	for offset+4 < len(buf) {
		flowSetID := binary.BigEndian.Uint16(buf[offset : offset+2])
		length := int(binary.BigEndian.Uint16(buf[offset+2 : offset+4]))
		if length < 4 || offset+length > len(buf) {
			break
		}
		// Only process data flowsets (ID >= 256)
		if flowSetID >= 256 && length >= 52 {
			data := buf[offset+4 : offset+length]
			// Try to extract src/dst from common 52-byte record format
			if len(data) >= 48 {
				srcIP := intToIP(binary.BigEndian.Uint32(data[0:4]))
				dstIP := intToIP(binary.BigEndian.Uint32(data[4:8]))
				bytes := int64(binary.BigEndian.Uint32(data[16:20]))
				packets := int64(binary.BigEndian.Uint32(data[20:24]))
				srcPort := int(binary.BigEndian.Uint16(data[32:34]))
				dstPort := int(binary.BigEndian.Uint16(data[34:36]))
				proto := protoToStr(data[38])

				flow := store.Flow{
					SrcIP: srcIP, DstIP: dstIP,
					SrcPort: srcPort, DstPort: dstPort,
					Proto: proto, Bytes: bytes, Packets: packets,
					Time: ts,
				}
				c.db.InsertFlow(ctx, flow)
				c.analyzeFlow(ctx, flow)
			}
		}
		offset += length
	}
}

func (c *NetFlowCollector) analyzeFlow(ctx context.Context, f store.Flow) {
	// ── Port scan detection ────────────────────────────────────────────────
	portCount, _ := c.db.TrackPortScan(ctx, f.SrcIP, f.DstIP, c.det.PortScanWindow)
	if portCount == c.det.PortScanThreshold {
		c.emit(schema.ProbeEvent{
			ID:        eventID("portscan", f.SrcIP, f.DstIP),
			Time:      f.Time,
			AgentID:   c.probeID,
			Host:      c.host,
			OS:        "network-probe",
			EventType: schema.EventPortScan,
			Severity:  schema.SevHigh,
			Source:    "netflow",
			SrcIP:     f.SrcIP,
			DstIP:     f.DstIP,
			Proto:     f.Proto,
			Raw: toRaw(map[string]interface{}{
				"src": f.SrcIP, "dst": f.DstIP,
				"ports_scanned": portCount,
				"window_sec":    c.det.PortScanWindow,
			}),
		})
	}

	// ── Lateral movement: east-west new connection ─────────────────────────
	if c.det.LateralMovementEnabled && isInternal(f.SrcIP) && isInternal(f.DstIP) {
		// Emit as lateral event for high-port dst (SMB, RDP, WinRM, SSH)
		if isDangerousPort(f.DstPort) {
			c.emit(schema.ProbeEvent{
				ID:        eventID("lateral", f.SrcIP, f.DstIP),
				Time:      f.Time,
				AgentID:   c.probeID,
				Host:      c.host,
				OS:        "network-probe",
				EventType: schema.EventLateralMove,
				Severity:  schema.SevMedium,
				Source:    "netflow",
				SrcIP:     f.SrcIP,
				DstIP:     f.DstIP,
				DstPort:   f.DstPort,
				Proto:     f.Proto,
				Raw: toRaw(map[string]interface{}{
					"src": f.SrcIP, "dst": f.DstIP,
					"dst_port": f.DstPort, "proto": f.Proto,
					"bytes": f.Bytes,
				}),
			})
		}
	}

	// ── Bandwidth spike detection ──────────────────────────────────────────
	baseline := c.baseline[f.SrcIP]
	if baseline > 0 && float64(f.Bytes) > baseline*c.det.BandwidthSpikeMultiplier {
		c.emit(schema.ProbeEvent{
			ID:        eventID("bw-spike", f.SrcIP),
			Time:      f.Time,
			AgentID:   c.probeID,
			Host:      c.host,
			OS:        "network-probe",
			EventType: schema.EventBandwidth,
			Severity:  schema.SevMedium,
			Source:    "netflow",
			SrcIP:     f.SrcIP,
			Raw: toRaw(map[string]interface{}{
				"src": f.SrcIP, "bytes": f.Bytes,
				"baseline_bytes": baseline, "multiplier": c.det.BandwidthSpikeMultiplier,
			}),
		})
	}
}

func (c *NetFlowCollector) runRollup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.db.RollupHourlyBandwidth(ctx)
			c.sendBandwidthSummary(ctx)
		}
	}
}

func (c *NetFlowCollector) sendBandwidthSummary(ctx context.Context) {
	talkers, err := c.db.GetTopTalkers(ctx, 1, 20)
	if err != nil || len(talkers) == 0 {
		return
	}
	// Update baseline
	for _, t := range talkers {
		ip, _ := t["src_ip"].(string)
		bytes, _ := t["total_bytes"].(int64)
		if c.baseline[ip] == 0 {
			c.baseline[ip] = float64(bytes)
		} else {
			c.baseline[ip] = c.baseline[ip]*0.9 + float64(bytes)*0.1 // EMA
		}
	}
	c.emit(schema.ProbeEvent{
		ID:        eventID("bw-summary", c.host),
		Time:      time.Now().UTC(),
		AgentID:   c.probeID,
		Host:      c.host,
		OS:        "network-probe",
		EventType: schema.EventTopTalker,
		Severity:  schema.SevInfo,
		Source:    "netflow",
		Raw:       toRaw(map[string]interface{}{"top_talkers": talkers, "period": "1h"}),
	})
}

func (c *NetFlowCollector) emit(ev schema.ProbeEvent) {
	select {
	case c.out <- ev:
	default:
	}
}

// Helpers
func intToIP(n uint32) string {
	return net.IP{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}.String()
}

func protoToStr(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	default:
		return "other"
	}
}

func isInternal(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, cidr := range private {
		_, net, _ := net.ParseCIDR(cidr)
		if net.Contains(parsed) {
			return true
		}
	}
	return false
}

func isDangerousPort(port int) bool {
	dangerous := map[int]bool{
		22: true, 23: true, 445: true, 3389: true,
		5985: true, 5986: true, 135: true, 139: true,
		1433: true, 3306: true, 5432: true,
	}
	return dangerous[port]
}

var _ = json.Marshal // ensure json is used
