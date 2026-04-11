package collector

// syslog.go — UDP/TCP syslog listener
// Receives syslog from any network device, parses, detects threats,
// and emits ProbeEvents via the out channel.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"time"

	"obsidianwatch/network-probe/internal/config"
	"obsidianwatch/network-probe/internal/parser"
	"obsidianwatch/network-probe/internal/store"
	"obsidianwatch/network-probe/pkg/schema"
)

type SyslogCollector struct {
	cfg    config.SyslogConfig
	det    config.DetectionConfig
	db     *store.DB
	out    chan<- schema.ProbeEvent
	logger *slog.Logger
	probeID string
	host    string
}

func NewSyslogCollector(cfg config.SyslogConfig, det config.DetectionConfig, db *store.DB,
	probeID, host string, out chan<- schema.ProbeEvent, logger *slog.Logger) *SyslogCollector {
	return &SyslogCollector{cfg: cfg, det: det, db: db, out: out,
		logger: logger, probeID: probeID, host: host}
}

func (c *SyslogCollector) Run(ctx context.Context) error {
	c.logger.Info("syslog: starting", "udp", c.cfg.UDPAddr, "tcp", c.cfg.TCPAddr)

	// Start UDP listener
	go c.listenUDP(ctx)
	// Start TCP listener
	go c.listenTCP(ctx)

	<-ctx.Done()
	return nil
}

func (c *SyslogCollector) listenUDP(ctx context.Context) {
	addr, err := net.ResolveUDPAddr("udp", c.cfg.UDPAddr)
	if err != nil {
		c.logger.Error("syslog UDP: resolve failed", "err", err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		c.logger.Error("syslog UDP: listen failed", "addr", c.cfg.UDPAddr, "err", err)
		return
	}
	defer conn.Close()
	c.logger.Info("syslog: UDP listening", "addr", c.cfg.UDPAddr)

	buf := make([]byte, c.cfg.BufferSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		line := strings.TrimSpace(string(buf[:n]))
		if line == "" {
			continue
		}
		msg := parser.ParseSyslog(line, src.IP)
		c.process(ctx, msg)
	}
}

func (c *SyslogCollector) listenTCP(ctx context.Context) {
	ln, err := net.Listen("tcp", c.cfg.TCPAddr)
	if err != nil {
		c.logger.Error("syslog TCP: listen failed", "addr", c.cfg.TCPAddr, "err", err)
		return
	}
	defer ln.Close()
	c.logger.Info("syslog: TCP listening", "addr", c.cfg.TCPAddr)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go c.handleTCPConn(ctx, conn)
	}
}

func (c *SyslogCollector) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	ip := net.ParseIP(srcIP)
	buf := make([]byte, 65536)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			msg := parser.ParseSyslog(line, ip)
			c.process(ctx, msg)
		}
	}
}

func (c *SyslogCollector) process(ctx context.Context, msg parser.SyslogMessage) {
	events := parser.ExtractEvents(msg)
	for _, ev := range events {
		c.analyze(ctx, ev)
	}
}

func (c *SyslogCollector) analyze(ctx context.Context, ev parser.NetworkEvent) {
	// Check auth failures for brute force
	if ev.Type == "net.auth_failure" && ev.SrcIP != "" {
		count, _ := c.db.TrackAuthFailure(ctx, ev.SrcIP, ev.Device, ev.Proto, 60)
		if count >= c.det.BruteForceThreshold {
			ev.Severity = schema.SevHigh
			c.emit(schema.ProbeEvent{
				ID:        eventID("bf", ev.SrcIP, ev.Device),
				Time:      ev.Time,
				AgentID:   c.probeID,
				Host:      c.host,
				OS:        "network-probe",
				EventType: "net.brute_force",
				Severity:  schema.SevHigh,
				Source:    "syslog",
				SrcIP:     ev.SrcIP,
				DstIP:     ev.Device,
				Raw:       toRaw(map[string]interface{}{
					"src": ev.SrcIP, "device": ev.Device, "failures": count,
					"proto": ev.Proto, "message": ev.Message,
				}),
			})
		}
	}

	// DHCP lease → device discovery
	if ev.Type == "net.dhcp_lease" && ev.Extra["mac"] != "" {
		dev := store.Device{
			MAC: ev.Extra["mac"], IP: ev.DstIP,
			FirstSeen: ev.Time, LastSeen: ev.Time,
		}
		dev.Vendor = store.VendorFromMAC(dev.MAC)
		isNew, _ := c.db.UpsertDevice(ctx, dev)
		if isNew {
			ev.Severity = schema.SevMedium
			c.emit(schema.ProbeEvent{
				ID:        eventID("new-dev", ev.Extra["mac"], ev.DstIP),
				Time:      ev.Time,
				AgentID:   c.probeID,
				Host:      c.host,
				OS:        "network-probe",
				EventType: schema.EventNewDevice,
				Severity:  schema.SevMedium,
				Source:    "syslog-dhcp",
				SrcIP:     ev.DstIP,
				Raw:       toRaw(map[string]interface{}{
					"mac": ev.Extra["mac"], "ip": ev.DstIP,
					"vendor": dev.Vendor, "via": "dhcp",
				}),
			})
		}
	}

	// Config change is always high severity
	if ev.Type == "net.config_change" {
		ev.Severity = schema.SevHigh
	}

	// Interface down
	if ev.Type == "net.iface_down" {
		ev.Severity = schema.SevMedium
	}

	// Emit the event
	c.emit(schema.ProbeEvent{
		ID:        eventID(ev.Type, ev.Device, ev.Time.String()),
		Time:      ev.Time,
		AgentID:   c.probeID,
		Host:      c.host,
		OS:        "network-probe",
		EventType: ev.Type,
		Severity:  ev.Severity,
		Source:    "syslog",
		SrcIP:     ev.SrcIP,
		DstIP:     ev.DstIP,
		SrcPort:   ev.SrcPort,
		DstPort:   ev.DstPort,
		Proto:     ev.Proto,
		UserName:  ev.User,
		Raw:       toRaw(map[string]interface{}{
			"device": ev.Device, "action": ev.Action,
			"interface": ev.Interface, "message": ev.Message,
			"extra": ev.Extra,
		}),
	})
}

func (c *SyslogCollector) emit(ev schema.ProbeEvent) {
	select {
	case c.out <- ev:
	default:
		c.logger.Warn("syslog: output channel full, dropping event")
	}
}

func eventID(parts ...string) string {
	return strings.Join(parts, ":") + ":" + time.Now().Format("20060102150405.000")
}

func toRaw(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
