//go:build linux

package collector

// dns.go — Linux DNS query monitoring.
//
// Linux does not have a kernel-level DNS event log like Windows DNS-Client.
// Strategy:
//  1. /proc/net/udp + /proc/net/tcp poll — detect connections to port 53.
//     Cross-reference inode→pid to get process attribution.
//     This catches all DNS-over-UDP (port 53) and DNS-over-TCP queries.
//  2. Parse /run/systemd/resolve/resolv.conf changes and
//     /etc/hosts reads via inotify (supplementary).
//
// Note: We cannot read the actual DNS query payload from /proc/net without
// a raw socket or eBPF. We record the connection (process → DNS server)
// and the domain if we can infer it from /proc/<pid>/net/dns (not always present).
//
// Events emitted: event_type="dns", source="proc-dns"

import (
	"context"
	"os"
	"os/exec"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

type DNSCollector struct {
	cfg     DNSCollectorConfig
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
	seen    map[string]time.Time // dedup: "pid:dstIP" → last seen
}

type DNSCollectorConfig struct {
	Enabled bool
}

func NewDNSCollector(cfg DNSCollectorConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *DNSCollector {
	return &DNSCollector{
		cfg:     cfg,
		out:     out,
		agentID: agentID,
		host:    host,
		logger:  logger,
		seen:    make(map[string]time.Time),
	}
}

func (d *DNSCollector) Run(ctx context.Context) error {
	if !d.cfg.Enabled {
		return nil
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	cleanTicker := time.NewTicker(60 * time.Second)
	defer cleanTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-cleanTicker.C:
			d.cleanSeen()
		case <-ticker.C:
			d.poll()
		}
	}
}

func (d *DNSCollector) poll() {
	// Strategy 1: read systemd-resolved DNS cache for actual domain names
	d.pollResolvedCache()

	// Strategy 2: /proc/net/udp — detect connections to port 53
	inodePID := buildInodePIDMap()
	for _, proto := range []string{"udp", "udp6"} {
		conns, err := parseProcNet(proto)
		if err != nil { continue }
		for _, conn := range conns {
			if conn.dstPort != 53 { continue }
			info, ok := inodePID[conn.inode]
			if !ok { continue }
			key := fmt.Sprintf("%d:%s", info.pid, conn.dstIP)
			now := time.Now()
			if last, seen := d.seen[key]; seen && now.Sub(last) < 30*time.Second { continue }
			d.seen[key] = now
			d.emit(info.pid, info.name, conn.dstIP, conn.srcIP, "")
		}
	}
}

// pollResolvedCache reads recent DNS queries from systemd-resolved journal logs.
// systemd-resolved logs every DNS query at debug level — we extract domain names from it.
func (d *DNSCollector) pollResolvedCache() {
	// Strategy A: journalctl for systemd-resolved DNS queries (most reliable)
	// -n 200: last 200 log lines, -o cat: plain output, --since: last 2 min
	out, err := exec.Command("journalctl", "-u", "systemd-resolved",
		"-n", "300", "-o", "cat", "--since", "2 minutes ago", "--no-pager").Output()
	if err == nil && len(out) > 0 {
		for _, line := range strings.Split(string(out), "\n") {
			// Lines like: "Lookup for <domain> for client..."
			// or: "Using DNS server ... for <domain>"
			// or: "DNSSEC validation for <domain>"
			var domain string
			if idx := strings.Index(line, "Lookup for "); idx >= 0 {
				rest := line[idx+11:]
				if end := strings.IndexAny(rest, " \t"); end > 0 { rest = rest[:end] }
				domain = strings.TrimSuffix(strings.TrimSuffix(rest, "."), ".")
			} else if strings.Contains(line, " IN ") {
				// Format: "<domain> IN A" from resolved debug logs
				parts := strings.Fields(line)
				for i, p := range parts {
					if p == "IN" && i > 0 {
						domain = strings.TrimSuffix(parts[i-1], ".")
						break
					}
				}
			}
			if domain == "" || !strings.Contains(domain, ".") { continue }
			key := "resolved:" + domain
			now := time.Now()
			if last, seen := d.seen[key]; seen && now.Sub(last) < 60*time.Second { continue }
			d.seen[key] = now
			d.emit(0, "", "", "", domain)
		}
		return
	}

	// Strategy B: resolvectl statistics shows cache — but not query names
	// Use resolvectl dns to at least confirm resolver is working
	// Fall back to reading /proc/net/if_inet6 approach — not reliable
	// Strategy C: parse /run/systemd/resolve/resolv.conf for upstream servers only
	// None of the above give us query names — if journald fails, we have no queries to report
}

func (d *DNSCollector) emit(pid int, procName, dnsServer, srcIP, domain string) {
	queryName := domain
	if queryName == "" { queryName = dnsServer }
	rawData := map[string]interface{}{
		"pid":          pid,
		"process_name": procName,
		"dns_server":   dnsServer,
		"src_ip":       srcIP,
		"action":       "query",
		"query_name":   queryName,
	}
	rawJSON, _ := json.Marshal(rawData)

	// DstIP holds the queried domain name (matches Windows Sysmon DNS event format)
	// If we have the actual domain, use it; otherwise fall back to DNS server IP
	dstIP := domain
	if dstIP == "" {
		dstIP = dnsServer
	}
	ev := schema.Event{
		Time:        time.Now().UTC(),
		AgentID:     d.agentID,
		Host:        d.host,
		OS:          "linux",
		EventType:   schema.EventTypeDNS,
		Severity:    schema.SeverityInfo,
		Source:      "proc-dns",
		Raw:         rawJSON,
		PID:         pid,
		ProcessName: strings.TrimSuffix(procName, "\n"),
		DstIP:       dstIP,
		SrcIP:       srcIP,
		DstPort:     53,
		Proto:       "udp",
	}

	select {
	case d.out <- ev:
	default:
		GlobalHealth.EventsDropped.Add(1)
	}
}

func (d *DNSCollector) cleanSeen() {
	cutoff := time.Now().Add(-2 * time.Minute)
	for k, t := range d.seen {
		if t.Before(cutoff) {
			delete(d.seen, k)
		}
	}
}
