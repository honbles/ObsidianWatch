//go:build darwin

package collector

// network.go — macOS network connection monitoring.
//
// Uses `netstat -anp tcp` and `netstat -anp udp` to enumerate active
// connections. Diffs against previous snapshot to detect new connections.
// Process attribution via lsof when needed.
//
// Events emitted: event_type="network", source="netstat"

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

type NetworkCollectorConfig struct {
	Enabled      bool
	PollInterval time.Duration
}

type NetworkCollector struct {
	cfg     NetworkCollectorConfig
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
	seen    map[string]struct{}
	names   map[int32]string // pid -> process name, refreshed once per poll (A-06)
}

type connEntry struct {
	proto   string
	local   string
	remote  string
	state   string
	pid     string
	process string
}

func NewNetworkCollector(cfg NetworkCollectorConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *NetworkCollector {
	return &NetworkCollector{
		cfg:     cfg,
		out:     out,
		agentID: agentID,
		host:    host,
		logger:  logger,
		seen:    make(map[string]struct{}),
	}
}

func (c *NetworkCollector) Run(ctx context.Context) {
	if !c.cfg.Enabled {
		return
	}
	interval := c.cfg.PollInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}

	// Initial snapshot
	initial := c.getConnections()
	for _, conn := range initial {
		c.seen[connKey(conn)] = struct{}{}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conns := c.getConnections()
			newSeen := make(map[string]struct{})
			for _, conn := range conns {
				k := connKey(conn)
				newSeen[k] = struct{}{}
				if _, exists := c.seen[k]; !exists {
					c.emit(conn)
				}
			}
			c.seen = newSeen
		}
	}
}

// refreshNames rebuilds the pid->name map with one sysctl call instead of a
// `ps` fork per connection (A-06).
func (c *NetworkCollector) refreshNames() {
	procs, err := listProcesses()
	if err != nil {
		return
	}
	m := make(map[int32]string, len(procs))
	for _, p := range procs {
		m[p.pid] = p.name
	}
	c.names = m
}

func (c *NetworkCollector) getConnections() []connEntry {
	c.refreshNames()
	// netstat -anv -p tcp and udp
	// -a: all, -n: numeric, -v: verbose (includes pid on macOS)
	out, err := exec.Command("netstat", "-anvp", "tcp").Output()
	if err != nil {
		c.logger.Warn("network: netstat tcp failed", "err", err)
	}
	conns := parseNetstat(out, "tcp")

	out2, err := exec.Command("netstat", "-anvp", "udp").Output()
	if err != nil {
		c.logger.Warn("network: netstat udp failed", "err", err)
	}
	conns = append(conns, parseNetstat(out2, "udp")...)
	return conns
}

func parseNetstat(data []byte, proto string) []connEntry {
	var result []connEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		// macOS netstat -anv output:
		// Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)     rhiwat  shiwat    pid   epid ...
		if len(fields) < 9 {
			continue
		}
		if !strings.HasPrefix(fields[0], proto) {
			continue
		}
		state := ""
		if len(fields) >= 6 {
			state = fields[5]
		}
		pid := ""
		if len(fields) >= 9 {
			pid = fields[8]
		}
		result = append(result, connEntry{
			proto:  fields[0],
			local:  fields[3],
			remote: fields[4],
			state:  state,
			pid:    pid,
		})
	}
	return result
}

func (c *NetworkCollector) emit(conn connEntry) {
	// Try to get process name from pid
	procName := conn.process
	if procName == "" && conn.pid != "" && conn.pid != "0" {
		if n, err := strconv.Atoi(conn.pid); err == nil {
			procName = c.names[int32(n)]
		}
		if procName == "" {
			procName = pidToName(conn.pid) // process exited/not in sysctl list: one-off fallback
		}
	}

	detail := map[string]interface{}{
		"protocol":     conn.proto,
		"local_addr":   conn.local,
		"remote_addr":  conn.remote,
		"state":        conn.state,
		"pid":          conn.pid,
		"process_name": procName,
	}
	raw, _ := json.Marshal(detail)

	// Parse dst IP and port from remote addr (e.g. "1.2.3.4.443" or "1.2.3.4:443")
	dstIP, dstPort := parseAddr(conn.remote)

	pidInt, _ := strconv.Atoi(conn.pid)
	c.out <- schema.Event{
		AgentID:     c.agentID,
		Host:        c.host,
		OS:          "darwin",
		EventType:   "network",
		Source:      "netstat",
		Severity:    1,
		Time:        time.Now().UTC(),
		PID:         pidInt,
		DstIP:       dstIP,
		DstPort:     dstPort,
		Proto:       conn.proto,
		ProcessName: procName,
		Raw:         raw,
	}
}

func connKey(c connEntry) string {
	return c.proto + "|" + c.local + "|" + c.remote + "|" + c.state
}

// parseAddr splits "1.2.3.4.443" or "1.2.3.4:443" into ip and port.
func parseAddr(addr string) (string, int) {
	// macOS netstat uses dot notation: 1.2.3.4.80
	if addr == "" || addr == "*.*" || addr == "*:*" {
		return "", 0
	}
	// Try colon separator first
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		ip := addr[:idx]
		port, _ := strconv.Atoi(addr[idx+1:])
		return ip, port
	}
	// Dot notation: last segment is port
	parts := strings.Split(addr, ".")
	if len(parts) >= 2 {
		port, err := strconv.Atoi(parts[len(parts)-1])
		if err == nil {
			return strings.Join(parts[:len(parts)-1], "."), port
		}
	}
	return addr, 0
}

func pidToName(pid string) string {
	pidN, err := strconv.Atoi(pid)
	if err != nil || pidN <= 0 {
		return ""
	}
	out, err := exec.Command("ps", "-p", pid, "-o", "comm=").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
