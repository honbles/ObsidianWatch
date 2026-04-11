//go:build linux

package collector

// process.go — Linux process monitoring.
//
// Strategy (two complementary sources):
//  1. Netlink proc connector (CN_IDX_PROC) — real-time kernel notifications for
//     exec/fork/exit events. Requires CAP_NET_ADMIN (i.e. root). This is the
//     Linux equivalent of Sysmon Event ID 1 (ProcessCreate).
//  2. /proc poll — fallback + enrichment. Scans /proc/*/status + /proc/*/cmdline
//     every PollInterval, detects new PIDs not yet seen via netlink, reads full
//     command line, username (uid→/etc/passwd lookup), parent PID.
//
// Events emitted: event_type="process", source="proc-connector" or "proc-poll"

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"obsidianwatch/linux-agent/pkg/schema"
)

// Netlink proc connector constants
const (
	NETLINK_CONNECTOR = 11
	CN_IDX_PROC       = 1
	CN_VAL_PROC       = 1
	PROC_CN_MCAST_LISTEN = 1

	// proc_event.what values
	PROC_EVENT_NONE = 0x00000000
	PROC_EVENT_FORK = 0x00000001
	PROC_EVENT_EXEC = 0x00000002
	PROC_EVENT_EXIT = 0x80000000
)

// ProcessCollector monitors Linux processes.
type ProcessCollector struct {
	cfg         ProcessCollectorConfig
	out         chan<- schema.Event
	agentID     string
	host        string
	logger      *slog.Logger
	seenPIDs    map[int]procEntry
	mu          sync.Mutex
	userCache   map[int]string // uid → username
}

type ProcessCollectorConfig struct {
	Enabled      bool
	PollInterval time.Duration
}

type procEntry struct {
	name    string
	cmdline string
	ppid    int
	uid     int
}

func NewProcessCollector(cfg ProcessCollectorConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *ProcessCollector {
	return &ProcessCollector{
		cfg:       cfg,
		out:       out,
		agentID:   agentID,
		host:      host,
		logger:    logger,
		seenPIDs:  make(map[int]procEntry),
		userCache: make(map[int]string),
	}
}

func (p *ProcessCollector) Run(ctx context.Context) error {
	if !p.cfg.Enabled {
		return nil
	}

	// Try netlink proc connector first (requires root/CAP_NET_ADMIN)
	go p.runNetlink(ctx)

	// Always run /proc poll as enrichment + fallback
	return p.runPoll(ctx)
}

// ---------------------------------------------------------------------------
// Netlink proc connector
// ---------------------------------------------------------------------------

func (p *ProcessCollector) runNetlink(ctx context.Context) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, NETLINK_CONNECTOR)
	if err != nil {
		p.logger.Debug("process: netlink socket failed (running as non-root?)", "err", err)
		return
	}
	defer syscall.Close(fd)

	addr := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: CN_IDX_PROC}
	if err := syscall.Bind(fd, addr); err != nil {
		p.logger.Debug("process: netlink bind failed", "err", err)
		return
	}

	// Subscribe to proc events
	if err := p.netlinkSubscribe(fd, PROC_CN_MCAST_LISTEN); err != nil {
		p.logger.Debug("process: netlink subscribe failed", "err", err)
		return
	}

	p.logger.Info("process: netlink proc connector active")

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read deadline so we can check ctx
		tv := syscall.Timeval{Sec: 1, Usec: 0}
		syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			p.logger.Debug("process: netlink recv error", "err", err)
			continue
		}

		p.parseNetlinkMessage(buf[:n])
	}
}

func (p *ProcessCollector) netlinkSubscribe(fd int, op uint32) error {
	// Build nlmsghdr + cn_msg + proc_cn_mcast_op
	type cnMsg struct {
		idx   uint32
		val   uint32
		seq   uint32
		ack   uint32
		len   uint16
		flags uint16
	}
	type nlMsg struct {
		length uint32
		mtype  uint16
		flags  uint16
		seq    uint32
		pid    uint32
	}

	buf := make([]byte, syscall.NLMSG_HDRLEN+24)
	// nlmsghdr
	binary.LittleEndian.PutUint32(buf[0:], uint32(len(buf)))
	binary.LittleEndian.PutUint16(buf[4:], uint16(syscall.NLMSG_DONE))
	binary.LittleEndian.PutUint16(buf[6:], 0)
	binary.LittleEndian.PutUint32(buf[8:], 0)
	binary.LittleEndian.PutUint32(buf[12:], uint32(os.Getpid()))
	// cn_msg
	off := syscall.NLMSG_HDRLEN
	binary.LittleEndian.PutUint32(buf[off:], CN_IDX_PROC)
	binary.LittleEndian.PutUint32(buf[off+4:], CN_VAL_PROC)
	binary.LittleEndian.PutUint32(buf[off+8:], uint32(rand.Int31()))
	binary.LittleEndian.PutUint32(buf[off+12:], 0)
	binary.LittleEndian.PutUint16(buf[off+16:], 4)
	binary.LittleEndian.PutUint16(buf[off+18:], 0)
	// op
	binary.LittleEndian.PutUint32(buf[off+20:], op)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	return syscall.Sendto(fd, buf, 0, sa)
}

func (p *ProcessCollector) parseNetlinkMessage(buf []byte) {
	if len(buf) < syscall.NLMSG_HDRLEN {
		return
	}
	msgs, err := syscall.ParseNetlinkMessage(buf)
	if err != nil {
		return
	}
	for _, msg := range msgs {
		if msg.Header.Type == syscall.NLMSG_DONE || msg.Header.Type == syscall.NLMSG_ERROR {
			continue
		}
		data := msg.Data
		// cn_msg header: idx(4) val(4) seq(4) ack(4) len(2) flags(2) = 20 bytes
		if len(data) < 20 {
			continue
		}
		idx := binary.LittleEndian.Uint32(data[0:])
		if idx != CN_IDX_PROC {
			continue
		}
		// proc_event header: what(4) cpu(4) timestamp(8) = 16 bytes
		payload := data[20:]
		if len(payload) < 16 {
			continue
		}
		what := binary.LittleEndian.Uint32(payload[0:])

		switch what {
		case PROC_EVENT_EXEC:
			// exec_proc_event: process_pid(4) process_tgid(4)
			if len(payload) < 24 {
				continue
			}
			pid := int(binary.LittleEndian.Uint32(payload[16:]))
			p.emitExec(pid)
		case PROC_EVENT_EXIT:
			// exit_proc_event: process_pid(4) process_tgid(4) exit_code(4) exit_signal(4)
			if len(payload) < 28 {
				continue
			}
			pid := int(binary.LittleEndian.Uint32(payload[16:]))
			p.emitExit(pid)
		}
	}
}

func (p *ProcessCollector) emitExec(pid int) {
	entry := p.readProc(pid)
	if entry.name == "" {
		return
	}
	p.mu.Lock()
	p.seenPIDs[pid] = entry
	p.mu.Unlock()

	p.emit(pid, entry, "exec", schema.SeverityInfo)
}

func (p *ProcessCollector) emitExit(pid int) {
	p.mu.Lock()
	entry, ok := p.seenPIDs[pid]
	if ok {
		delete(p.seenPIDs, pid)
	}
	p.mu.Unlock()
	if !ok {
		return
	}
	p.emit(pid, entry, "exit", schema.SeverityInfo)
}

// ---------------------------------------------------------------------------
// /proc poll — fallback + new process detection
// ---------------------------------------------------------------------------

func (p *ProcessCollector) runPoll(ctx context.Context) error {
	// Seed seen PIDs from current state at startup
	p.snapshotProc()

	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.pollProc()
		}
	}
}

func (p *ProcessCollector) snapshotProc() {
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		entry := p.readProc(pid)
		if entry.name != "" {
			p.mu.Lock()
			p.seenPIDs[pid] = entry
			p.mu.Unlock()
		}
	}
}

func (p *ProcessCollector) pollProc() {
	entries, _ := os.ReadDir("/proc")
	current := make(map[int]bool)

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		current[pid] = true

		p.mu.Lock()
		_, seen := p.seenPIDs[pid]
		p.mu.Unlock()

		if !seen {
			entry := p.readProc(pid)
			if entry.name == "" {
				continue
			}
			p.mu.Lock()
			p.seenPIDs[pid] = entry
			p.mu.Unlock()
			p.emit(pid, entry, "exec", schema.SeverityInfo)
		}
	}

	// Detect exited processes
	p.mu.Lock()
	for pid, entry := range p.seenPIDs {
		if !current[pid] {
			delete(p.seenPIDs, pid)
			p.mu.Unlock()
			p.emit(pid, entry, "exit", schema.SeverityInfo)
			p.mu.Lock()
		}
	}
	p.mu.Unlock()
}

// ---------------------------------------------------------------------------
// /proc reading helpers
// ---------------------------------------------------------------------------

func (p *ProcessCollector) readProc(pid int) procEntry {
	base := fmt.Sprintf("/proc/%d", pid)

	// Read /proc/<pid>/status for name, ppid, uid
	statusPath := filepath.Join(base, "status")
	statusData, err := os.ReadFile(statusPath)
	if err != nil {
		return procEntry{}
	}

	var entry procEntry
	sc := bufio.NewScanner(strings.NewReader(string(statusData)))
	for sc.Scan() {
		line := sc.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "Name":
			entry.name = val
		case "PPid":
			entry.ppid, _ = strconv.Atoi(val)
		case "Uid":
			// Uid: real effective saved filesystem
			fields := strings.Fields(val)
			if len(fields) > 0 {
				entry.uid, _ = strconv.Atoi(fields[0])
			}
		}
	}

	// Read /proc/<pid>/cmdline
	cmdlineData, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err == nil {
		// cmdline is null-separated
		args := strings.Split(strings.TrimRight(string(cmdlineData), "\x00"), "\x00")
		entry.cmdline = strings.Join(args, " ")
	}

	return entry
}

func (p *ProcessCollector) resolveUsername(uid int) string {
	p.mu.Lock()
	if name, ok := p.userCache[uid]; ok {
		p.mu.Unlock()
		return name
	}
	p.mu.Unlock()

	name := fmt.Sprintf("uid:%d", uid)
	f, err := os.Open("/etc/passwd")
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Split(sc.Text(), ":")
			if len(fields) < 3 {
				continue
			}
			if id, _ := strconv.Atoi(fields[2]); id == uid {
				name = fields[0]
				break
			}
		}
	}

	p.mu.Lock()
	p.userCache[uid] = name
	p.mu.Unlock()
	return name
}

func (p *ProcessCollector) resolveExePath(pid int) string {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return exePath
}

// ---------------------------------------------------------------------------
// Event emission
// ---------------------------------------------------------------------------

func (p *ProcessCollector) emit(pid int, entry procEntry, action string, sev schema.Severity) {
	username := p.resolveUsername(entry.uid)
	exePath := p.resolveExePath(pid)

	rawData := map[string]interface{}{
		"action":   action,
		"pid":      pid,
		"ppid":     entry.ppid,
		"name":     entry.name,
		"cmdline":  entry.cmdline,
		"exe":      exePath,
		"uid":      entry.uid,
		"username": username,
	}
	rawJSON, _ := json.Marshal(rawData)

	ev := schema.Event{
		Time:        time.Now().UTC(),
		AgentID:     p.agentID,
		Host:        p.host,
		OS:          "linux",
		EventType:   schema.EventTypeProcess,
		Severity:    sev,
		Source:      "proc",
		Raw:         rawJSON,
		PID:         pid,
		PPID:        entry.ppid,
		ProcessName: entry.name,
		CommandLine: entry.cmdline,
		ImagePath:   exePath,
		UserName:    username,
	}

	select {
	case p.out <- ev:
	default:
		GlobalHealth.EventsDropped.Add(1)
	}
}

// ---------------------------------------------------------------------------
// Shared health counter (mirrors Windows agent)
// ---------------------------------------------------------------------------

// Use unsafe to avoid circular import — identical to Windows agent HealthStats
var _ = unsafe.Sizeof(0) // keep import

// GlobalHealth is declared in health.go
