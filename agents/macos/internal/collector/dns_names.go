//go:build darwin

package collector

// dns_names.go — A-02: real DNS query names on macOS.
//
// The lsof poller only sees "process X talks to resolver Y", so domain
// categories, IOCs and DNS rules could never fire. mDNSResponder redacts
// names in the unified log, so instead we read the queries off the wire with
// tcpdump (ships with macOS; the agent runs as root). Limits, stated plainly:
// no PID (the packet has none), and encrypted DNS (DoH/DoT) is not visible.
//
// Events: event_type="dns", DstIP=<queried domain> (same convention as the
// Linux/Windows agents so existing rules apply), source="tcpdump-dns".

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
)

var dnsQueryRe = regexp.MustCompile(`IP6? (\S+)\.(\d+) > (\S+)\.53: .*?\b(A|AAAA|CNAME|MX|NS|TXT|SRV|PTR|ANY|HTTPS|SOA)\? (\S+?)\.? \(`)

func (c *DNSCollector) runNames(ctx context.Context) {
	backoff := 5 * time.Second
	for ctx.Err() == nil {
		started := time.Now()
		if err := c.tcpdumpOnce(ctx); err != nil && ctx.Err() == nil {
			c.logger.Warn("dns: tcpdump capture stopped", "err", err)
		}
		if time.Since(started) > time.Minute {
			backoff = 5 * time.Second
		} else if backoff < 5*time.Minute {
			backoff *= 2
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func (c *DNSCollector) tcpdumpOnce(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "tcpdump", "-l", "-n", "-i", "any", "-s", "512", "udp", "dst", "port", "53")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	recent := make(map[string]time.Time)
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		m := dnsQueryRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		src, server, qtype, name := m[1], m[3], m[4], strings.ToLower(m[5])
		if name == "" || strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
			continue
		}
		key := name + "|" + qtype
		now := time.Now()
		if t, ok := recent[key]; ok && now.Sub(t) < 10*time.Second {
			continue
		}
		recent[key] = now
		if len(recent) > 5000 {
			for k, t := range recent {
				if now.Sub(t) > 30*time.Second {
					delete(recent, k)
				}
			}
		}
		raw, _ := json.Marshal(map[string]interface{}{
			"query": name, "query_type": qtype, "client": src, "dns_server": server, "action": "query",
		})
		c.out <- schema.Event{
			AgentID: c.agentID, Host: c.host, OS: "darwin",
			EventType: "dns", Source: "tcpdump-dns", Severity: 1,
			Raw: raw, Time: now.UTC(),
			DstIP: name, DstPort: 53, Proto: "udp",
		}
	}
	return cmd.Wait()
}
