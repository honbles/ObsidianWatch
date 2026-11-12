//go:build linux

package collector

// dns.go — Linux DNS query monitoring.
//
// Linux DNS collection strategy (in priority order):
//
//  1. resolvectl query / resolvectl statistics — reads systemd-resolved's
//     query cache directly. Gives real domain names with zero overhead.
//     Works on Ubuntu 18+, Debian 10+, any systemd >= 239.
//
//  2. systemd-resolved journal log parsing — parses journalctl output for
//     DNS lookup messages. Requires logging level >= debug on resolved.
//     Good fallback when resolvectl cache is not available.
//
//  3. /proc/net/udp poll — detects active connections to port 53.
//     Only captures domain names if we can correlate inode→pid→/proc/pid/net.
//     Falls back to recording the DNS server IP only when no domain is available.
//     Useful for non-systemd systems.
//
//  4. dnsmasq / bind log parsing — /var/log/syslog patterns.
//
// Events emitted: event_type="dns", source="proc-dns"

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
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
	seen    map[string]time.Time // dedup: domain/server → last emitted
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

	cleanTicker := time.NewTicker(5 * time.Minute)
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
	// Strategy 1: resolvectl query cache — best source, real domain names
	if d.pollResolvectl() {
		return
	}

	// Strategy 2: systemd-resolved journal logs
	if d.pollResolvedJournal() {
		return
	}

	// Strategy 3: /proc/net/udp — fallback, records DNS server IPs
	d.pollProcNet()

	// Strategy 4: dnsmasq/syslog
	d.pollSyslog()
}

// pollResolvectl reads DNS query cache from resolvectl.
// `resolvectl query` is not available, but `resolvectl statistics` and
// parsing the cache via `resolvectl --json=short` may work.
// Most reliable: run `resolvectl` and parse the DNS cache section.
func (d *DNSCollector) pollResolvectl() bool {
	// Try: resolvectl query --cache (systemd >= 248)
	out, err := exec.Command("resolvectl", "query", "--cache").Output()
	if err == nil && len(out) > 0 {
		found := false
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Format: "domain.example.com IN A 1.2.3.4 (TTL 300s)"
			// or just domain names
			parts := strings.Fields(line)
			if len(parts) < 1 {
				continue
			}
			domain := parts[0]
			domain = strings.TrimSuffix(domain, ".")
			if !strings.Contains(domain, ".") {
				continue
			}
			if d.dedup("resolvectl:"+domain, 30*time.Second) {
				continue
			}
			d.emit(0, "", "", "", domain, "resolvectl")
			found = true
		}
		return found
	}

	// Try: resolvectl statistics to verify it's available
	_, err = exec.Command("resolvectl", "statistics").Output()
	if err != nil {
		return false // resolvectl not available
	}

	// resolvectl is available but --cache flag not supported
	// Try parsing via dns-sd or nscd
	return false
}

// pollResolvedJournal reads recent DNS queries from systemd-resolved journal.
// systemd-resolved logs at info level: "Positive cache hit for <domain>"
// and at debug level: "Lookup for <domain>"
func (d *DNSCollector) pollResolvedJournal() bool {
	out, err := exec.Command("journalctl",
		"-u", "systemd-resolved",
		"-n", "500",
		"-o", "cat",
		"--since", "10 seconds ago",
		"--no-pager",
	).Output()
	if err != nil || len(out) == 0 {
		return false
	}

	found := false
	for _, line := range strings.Split(string(out), "\n") {
		domain := extractDomainFromResolvedLog(line)
		if domain == "" {
			continue
		}
		if d.dedup("journal:"+domain, 30*time.Second) {
			continue
		}
		d.emit(0, "", "", "", domain, "systemd-resolved")
		found = true
	}
	return found
}

// extractDomainFromResolvedLog parses a single line from systemd-resolved journal.
func extractDomainFromResolvedLog(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Pattern: "Positive cache hit for <domain> IN <type>"
	if idx := strings.Index(line, "Positive cache hit for "); idx >= 0 {
		rest := line[idx+23:]
		if end := strings.IndexAny(rest, " \t"); end > 0 {
			rest = rest[:end]
		}
		return strings.TrimSuffix(rest, ".")
	}

	// Pattern: "Lookup for <domain> for client..."
	if idx := strings.Index(line, "Lookup for "); idx >= 0 {
		rest := line[idx+11:]
		if end := strings.IndexAny(rest, " \t"); end > 0 {
			rest = rest[:end]
		}
		return strings.TrimSuffix(rest, ".")
	}

	// Pattern: "Using DNS server <ip> for <domain>"
	if idx := strings.Index(line, "for <domain>"); idx >= 0 {
		rest := line[idx+12:]
		if end := strings.IndexAny(rest, " \t>"); end > 0 {
			rest = rest[:end]
		}
		return strings.TrimSuffix(rest, ".")
	}

	// Pattern: "<domain> IN A/AAAA/CNAME" from debug logs
	if strings.Contains(line, " IN ") {
		parts := strings.Fields(line)
		for i, p := range parts {
			if p == "IN" && i > 0 {
				domain := strings.TrimSuffix(parts[i-1], ".")
				if strings.Contains(domain, ".") {
					return domain
				}
			}
		}
	}

	// Pattern: "Cache miss for <domain>"
	if idx := strings.Index(line, "Cache miss for "); idx >= 0 {
		rest := line[idx+15:]
		if end := strings.IndexAny(rest, " \t"); end > 0 {
			rest = rest[:end]
		}
		return strings.TrimSuffix(rest, ".")
	}

	return ""
}

// pollProcNet detects connections to port 53 via /proc/net/udp.
// This only gives us DNS server IPs, not domain names.
// Used as last resort on non-systemd systems.
func (d *DNSCollector) pollProcNet() {
	inodePID := buildInodePIDMap()
	for _, proto := range []string{"udp", "udp6"} {
		conns, err := parseProcNet(proto)
		if err != nil {
			continue
		}
		for _, conn := range conns {
			if conn.dstPort != 53 {
				continue
			}
			info, ok := inodePID[conn.inode]
			if !ok {
				continue
			}
			key := fmt.Sprintf("proc:%d:%s", info.pid, conn.dstIP)
			if d.dedup(key, 60*time.Second) {
				continue
			}
			d.emit(info.pid, info.name, conn.dstIP, conn.srcIP, "", "proc-net")
		}
	}
}

// pollSyslog parses /var/log/syslog or /var/log/messages for DNS queries.
// Covers dnsmasq ("query[A] <domain> from"), bind9, and unbound.
func (d *DNSCollector) pollSyslog() {
	candidates := []string{
		"/var/log/syslog",
		"/var/log/messages",
		"/var/log/dns.log",
	}

	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		// Read last 100 lines only — avoid processing the entire file
		lines := tailFile(f, 100)
		f.Close()

		for _, line := range lines {
			domain := extractDomainFromSyslog(line)
			if domain == "" {
				continue
			}
			if d.dedup("syslog:"+domain, 60*time.Second) {
				continue
			}
			d.emit(0, "", "", "", domain, "syslog")
		}
	}
}

// extractDomainFromSyslog parses syslog lines for DNS query domains.
func extractDomainFromSyslog(line string) string {
	// dnsmasq: "dnsmasq[1234]: query[A] example.com from 127.0.0.1"
	if idx := strings.Index(line, "query["); idx >= 0 {
		rest := line[idx:]
		// Find the domain after "] "
		if end := strings.Index(rest, "] "); end >= 0 {
			rest = rest[end+2:]
			if sp := strings.Index(rest, " "); sp > 0 {
				domain := rest[:sp]
				if strings.Contains(domain, ".") {
					return strings.TrimSuffix(domain, ".")
				}
			}
		}
	}

	// named/bind9: "named[1234]: client query: <domain> IN A +"
	if idx := strings.Index(line, "client query: "); idx >= 0 {
		rest := line[idx+14:]
		if sp := strings.Index(rest, " "); sp > 0 {
			return strings.TrimSuffix(rest[:sp], ".")
		}
	}

	// unbound: "unbound[1234]: info: example.com. A IN"
	if strings.Contains(line, "unbound[") && strings.Contains(line, " IN") {
		parts := strings.Fields(line)
		for i, p := range parts {
			if (p == "A" || p == "AAAA" || p == "CNAME" || p == "MX") && i > 0 {
				domain := strings.TrimSuffix(parts[i-1], ".")
				if strings.Contains(domain, ".") {
					return domain
				}
			}
		}
	}

	return ""
}

// tailWindow is how much of the end of a file tailFile will look at. Syslog
// files grow to gigabytes; scanning from the start on every poll made each pass
// cost O(file size).
const tailWindow = 1 << 20

// tailFile returns the last n lines of a file, reading only the final
// tailWindow bytes.
func tailFile(f *os.File, n int) []string {
	if st, err := f.Stat(); err == nil && st.Size() > tailWindow {
		if _, err := f.Seek(st.Size()-tailWindow, io.SeekStart); err == nil {
			// The seek likely landed mid-line: drop the partial first line.
			br := bufio.NewReader(f)
			if _, err := br.ReadString('\n'); err != nil {
				return nil
			}
			return lastLines(br, n)
		}
	}
	return lastLines(f, n)
}

func lastLines(r io.Reader, n int) []string {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20) // tolerate long lines instead of stopping at 64 KB
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > n*2 {
			lines = lines[len(lines)-n:]
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// dedup returns true if this key was seen within the given window (skip it).
func (d *DNSCollector) dedup(key string, window time.Duration) bool {
	now := time.Now()
	if last, seen := d.seen[key]; seen && now.Sub(last) < window {
		return true
	}
	d.seen[key] = now
	return false
}

func (d *DNSCollector) emit(pid int, procName, dnsServer, srcIP, domain, source string) {
	queryName := domain
	if queryName == "" {
		queryName = dnsServer
	}
	if queryName == "" {
		return
	}

	rawData := map[string]interface{}{
		"pid":          pid,
		"process_name": procName,
		"dns_server":   dnsServer,
		"src_ip":       srcIP,
		"action":       "query",
		"query_name":   queryName,
		"source":       source,
	}
	if g := linuxProcGUID(pid); g != "" && pid > 0 {
		rawData["process_guid"] = g
	}
	rawJSON, _ := json.Marshal(rawData)

	// dst_ip stores the queried domain name — matches how the backend queries DNS events
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
	cutoff := time.Now().Add(-10 * time.Minute)
	for k, t := range d.seen {
		if t.Before(cutoff) {
			delete(d.seen, k)
		}
	}
}
