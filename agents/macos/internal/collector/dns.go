//go:build darwin

package collector

// dns.go — macOS DNS query monitoring.
//
// Uses lsof to detect processes connecting to port 53 (DNS).
// Polls periodically and deduplicates by pid+destination.
//
// Events emitted: event_type="dns", source="lsof-dns"

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
)

type DNSCollectorConfig struct {
	Enabled bool
}

type DNSCollector struct {
	cfg     DNSCollectorConfig
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
	seen    map[string]time.Time
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

func (c *DNSCollector) Run(ctx context.Context) {
	if !c.cfg.Enabled {
		return
	}
	go c.runNames(ctx) // A-02: real query names via tcpdump
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.poll()
			now := time.Now()
			for k, t := range c.seen {
				if now.Sub(t) > 60*time.Second {
					delete(c.seen, k)
				}
			}
		}
	}
}

func (c *DNSCollector) poll() {
	// lsof -i UDP:53 -i TCP:53 -n -P -F pcn
	// -F field output: p=pid, c=command, n=name(addr)
	out, err := exec.Command("lsof", "-i", "UDP:53", "-i", "TCP:53", "-n", "-P", "-F", "pcn").Output()
	if err != nil {
		return
	}

	type entry struct{ pid, cmd, addr string }
	var cur entry
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			cur = entry{pid: line[1:]}
		case 'c':
			cur.cmd = line[1:]
		case 'n':
			cur.addr = line[1:]
			if strings.Contains(cur.addr, "->") {
				key := cur.pid + ":" + cur.addr
				if _, seen := c.seen[key]; !seen {
					c.seen[key] = time.Now()
					pidInt, _ := strconv.Atoi(cur.pid)
					// Parse DNS server IP from "localAddr->remoteAddr"
					parts := strings.SplitN(cur.addr, "->", 2)
					dstAddr := cur.addr
					if len(parts) == 2 {
						dstAddr = parts[1]
					}
					// Strip port from "ip:port"
					dstIP := dstAddr
					if idx := strings.LastIndex(dstAddr, ":"); idx > 0 {
						dstIP = dstAddr[:idx]
					}
					detail := map[string]interface{}{
						"pid":          cur.pid,
						"process_name": cur.cmd,
						"query":        cur.addr,
						"dns_server":   dstIP,
						"action":       "query",
					}
					raw, _ := json.Marshal(detail)
					c.out <- schema.Event{
						AgentID:     c.agentID,
						Host:        c.host,
						OS:          "darwin",
						EventType:   "dns",
						Source:      "lsof-dns",
						Severity:    1,
						Raw:         raw,
						Time:        time.Now().UTC(),
						PID:         pidInt,
						ProcessName: cur.cmd,
						DstIP:       dstIP,
						DstPort:     53,
						Proto:       "udp",
					}
				}
			}
		}
	}
}
