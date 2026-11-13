//go:build linux

package collector

// network.go — Linux network connection monitoring via /proc/net/tcp|tcp6|udp|udp6.
//
// Equivalent to Windows iphlpapi TCP/UDP table poll.
// Diffs the connection table each PollInterval and emits events for
// new connections (open) and disappeared connections (close).
//
// PID enrichment: /proc/net/tcp doesn't include PID directly.
// We cross-reference inode numbers from /proc/<pid>/fd/* to find the owner.
//
// Events emitted: event_type="network", source="proc-net"

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

type NetworkCollector struct {
	cfg     NetworkCollectorConfig
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
	prev    map[string]netConn // key → conn
}

type NetworkCollectorConfig struct {
	Enabled      bool
	PollInterval time.Duration
}

type netConn struct {
	proto   string
	srcIP   string
	srcPort int
	dstIP   string
	dstPort int
	state   string
	inode   string
	pid     int
	name    string
}

func NewNetworkCollector(cfg NetworkCollectorConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *NetworkCollector {
	return &NetworkCollector{
		cfg:     cfg,
		out:     out,
		agentID: agentID,
		host:    host,
		logger:  logger,
		prev:    make(map[string]netConn),
	}
}

func (n *NetworkCollector) Run(ctx context.Context) error {
	if !n.cfg.Enabled {
		return nil
	}

	// Build initial snapshot silently
	n.prev = n.snapshot()

	ticker := time.NewTicker(n.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			n.diff()
		}
	}
}

func (n *NetworkCollector) diff() {
	current := n.snapshot()

	// New connections
	for key, conn := range current {
		if _, existed := n.prev[key]; !existed {
			n.emit(conn, "open")
		}
	}
	// Closed connections
	for key, conn := range n.prev {
		if _, still := current[key]; !still {
			n.emit(conn, "close")
		}
	}

	n.prev = current
}

func (n *NetworkCollector) snapshot() map[string]netConn {
	// Build inode → pid+name map
	inodePID := buildInodePIDMap()

	result := make(map[string]netConn)
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		conns, err := parseProcNet(proto)
		if err != nil {
			continue
		}
		for i := range conns {
			c := &conns[i]
			c.proto = strings.TrimSuffix(proto, "6")
			if info, ok := inodePID[c.inode]; ok {
				c.pid = info.pid
				c.name = info.name
			}
			// Only track established TCP or any UDP with a dst
			if c.dstIP == "0.0.0.0" || c.dstIP == "::" || c.dstPort == 0 {
				if c.proto == "tcp" {
					continue // listening socket, skip
				}
			}
			key := fmt.Sprintf("%s:%s:%d:%s:%d", c.proto, c.srcIP, c.srcPort, c.dstIP, c.dstPort)
			result[key] = *c
		}
	}
	return result
}

func (n *NetworkCollector) emit(conn netConn, action string) {
	rawData := map[string]interface{}{
		"action":   action,
		"proto":    conn.proto,
		"src_ip":   conn.srcIP,
		"src_port": conn.srcPort,
		"dst_ip":   conn.dstIP,
		"dst_port": conn.dstPort,
		"state":    conn.state,
		"pid":      conn.pid,
		"name":     conn.name,
	}
	// Alert Graph: tie the connection to the exact process instance.
	if g := linuxProcGUID(conn.pid); g != "" && conn.pid > 0 {
		rawData["process_guid"] = g
	}
	rawJSON, _ := json.Marshal(rawData)

	sev := schema.SeverityInfo
	if conn.dstPort == 4444 || conn.dstPort == 1337 || conn.dstPort == 31337 {
		sev = schema.SeverityHigh // classic reverse shell ports
	}

	ev := schema.Event{
		Time:        time.Now().UTC(),
		AgentID:     n.agentID,
		Host:        n.host,
		OS:          "linux",
		EventType:   schema.EventTypeNetwork,
		Severity:    sev,
		Source:      "proc-net",
		Raw:         rawJSON,
		PID:         conn.pid,
		ProcessName: conn.name,
		SrcIP:       conn.srcIP,
		SrcPort:     conn.srcPort,
		DstIP:       conn.dstIP,
		DstPort:     conn.dstPort,
		Proto:       conn.proto,
	}

	select {
	case n.out <- ev:
	default:
		GlobalHealth.EventsDropped.Add(1)
	}
}

// ---------------------------------------------------------------------------
// /proc/net/tcp parser
// ---------------------------------------------------------------------------

func parseProcNet(proto string) ([]netConn, error) {
	path := "/proc/net/" + proto
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var conns []netConn
	sc := bufio.NewScanner(f)
	sc.Scan() // skip header

	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// /proc/net/tcp columns:
		// sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
		if len(fields) < 10 {
			continue
		}
		srcIP, srcPort := parseHexAddr(fields[1], strings.HasSuffix(proto, "6"))
		dstIP, dstPort := parseHexAddr(fields[2], strings.HasSuffix(proto, "6"))
		state := fields[3]
		inode := fields[9]

		conns = append(conns, netConn{
			srcIP:   srcIP,
			srcPort: srcPort,
			dstIP:   dstIP,
			dstPort: dstPort,
			state:   state,
			inode:   inode,
		})
	}
	return conns, sc.Err()
}

// parseHexAddr converts "0101007F:0050" → "127.0.0.1", 80
func parseHexAddr(hexAddr string, isV6 bool) (string, int) {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return "", 0
	}
	port64, _ := strconv.ParseInt(parts[1], 16, 64)

	if isV6 {
		// IPv6: 32 hex chars
		raw := parts[0]
		if len(raw) != 32 {
			return raw, int(port64)
		}
		b := make([]byte, 16)
		for i := 0; i < 4; i++ {
			word, _ := strconv.ParseUint(raw[i*8:(i+1)*8], 16, 32)
			// kernel stores in little-endian 32-bit words
			b[i*4+0] = byte(word)
			b[i*4+1] = byte(word >> 8)
			b[i*4+2] = byte(word >> 16)
			b[i*4+3] = byte(word >> 24)
		}
		return net.IP(b).String(), int(port64)
	}

	// IPv4: 8 hex chars, little-endian
	raw, _ := strconv.ParseUint(parts[0], 16, 32)
	ip := net.IP{byte(raw), byte(raw >> 8), byte(raw >> 16), byte(raw >> 24)}
	return ip.String(), int(port64)
}

// ---------------------------------------------------------------------------
// Inode → PID map via /proc/<pid>/fd/*
// ---------------------------------------------------------------------------

type pidInfo struct {
	pid  int
	name string
}

func buildInodePIDMap() map[string]pidInfo {
	result := make(map[string]pidInfo)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result
	}

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // no permission for this pid
		}
		name := readProcName(pid)
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// Socket inodes look like: "socket:[12345]"
			if strings.HasPrefix(link, "socket:[") {
				inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				result[inode] = pidInfo{pid: pid, name: name}
			}
		}
	}
	return result
}

func readProcName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
