//go:build darwin

package collector

// process.go — macOS process monitoring.
//
// Strategy (two complementary sources):
//  1. Poll /proc equivalent via sysctl(KERN_PROC_ALL) — enumerates all running
//     processes with PID, PPID, name, UID. Diffs against previous snapshot to
//     detect new processes. This is the macOS equivalent of Linux /proc polling.
//  2. Process argv via sysctl(KERN_PROCARGS2) — retrieves full command line for
//     each process, equivalent to reading /proc/<pid>/cmdline.
//
// Events emitted: event_type="process", source="sysctl-poll"

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"obsidianwatch/macos-agent/pkg/schema"
	"golang.org/x/sys/unix"
)

type ProcessCollectorConfig struct {
	Enabled      bool
	PollInterval time.Duration
}

type ProcessCollector struct {
	cfg      ProcessCollectorConfig
	out      chan<- schema.Event
	agentID  string
	host     string
	logger   *slog.Logger
	seenPIDs map[int32]procEntry
	mu       sync.Mutex
}

type procEntry struct {
	name string
	ppid int32
	uid  uint32
	cmd  string
}

func NewProcessCollector(cfg ProcessCollectorConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *ProcessCollector {
	return &ProcessCollector{
		cfg:      cfg,
		out:      out,
		agentID:  agentID,
		host:     host,
		logger:   logger,
		seenPIDs: make(map[int32]procEntry),
	}
}

func (c *ProcessCollector) Run(ctx context.Context) {
	if !c.cfg.Enabled {
		return
	}
	interval := c.cfg.PollInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	// Initial snapshot
	c.mu.Lock()
	c.seenPIDs = c.snapshot()
	c.mu.Unlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			current := c.snapshot()
			for pid, entry := range current {
				if _, seen := c.seenPIDs[pid]; !seen {
					c.emit(pid, entry)
				}
			}
			c.seenPIDs = current
			c.mu.Unlock()
		}
	}
}

func (c *ProcessCollector) snapshot() map[int32]procEntry {
	result := make(map[int32]procEntry)
	procs, err := listProcesses()
	if err != nil {
		c.logger.Warn("process: sysctl list failed", "err", err)
		return result
	}
	for _, p := range procs {
		cmd := getArgv(p.pid)
		result[p.pid] = procEntry{
			name: p.name,
			ppid: p.ppid,
			uid:  p.uid,
			cmd:  cmd,
		}
	}
	return result
}

func (c *ProcessCollector) emit(pid int32, e procEntry) {
	username := uidToUsername(e.uid)
	detail := map[string]interface{}{
		"pid":      pid,
		"ppid":     e.ppid,
		"name":     e.name,
		"cmdline":  e.cmd,
		"username": username,
		"uid":      e.uid,
	}
	raw, _ := json.Marshal(detail)
	c.out <- schema.Event{
		AgentID:     c.agentID,
		Host:        c.host,
		OS:          "darwin",
		EventType:   "process",
		Source:      "sysctl-poll",
		Severity:    1,
		Time:        time.Now().UTC(),
		PID:         int(pid),
		PPID:        int(e.ppid),
		ProcessName: e.name,
		CommandLine: e.cmd,
		UserName:    username,
		Raw:         raw,
	}
}

// ── sysctl helpers ────────────────────────────────────────────────────────────

type bsdProc struct {
	pid  int32
	ppid int32
	uid  uint32
	name string
}

func listProcesses() ([]bsdProc, error) {
	// KERN_PROC_ALL = 0
	buf, err := unix.SysctlRaw("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("sysctl kern.proc.all: %w", err)
	}

	// Each entry is a kinfo_proc structure (648 bytes on arm64/amd64 macOS)
	const kinfoProcSize = 648
	if len(buf)%kinfoProcSize != 0 {
		return nil, fmt.Errorf("unexpected kern.proc.all size %d", len(buf))
	}

	var procs []bsdProc
	for i := 0; i+kinfoProcSize <= len(buf); i += kinfoProcSize {
		entry := buf[i : i+kinfoProcSize]
		// kinfo_proc layout (macOS):
		//   offset 0: extern_proc (struct proc fields)
		//     +24: p_pid  (int32)
		//     +28: p_ppid (int32) — actually in eproc, not extern_proc
		//   offset 440: eproc
		//     +440+8: e_ppid (int32)
		//     +440+52: e_ucred → cr_uid (uint32) at +440+52+4
		//   p_comm: offset 231 in extern_proc, 16 bytes (MAXCOMLEN+1)
		pid  := int32(readUint32LE(entry, 24))
		ppid := int32(readUint32LE(entry, 448)) // eproc.e_ppid
		uid  := readUint32LE(entry, 504)         // eproc.e_ucred.cr_uid (approximate)
		name := nullTermStr(entry[431:447])       // extern_proc.p_comm (MAXCOMLEN=16)
		if pid == 0 {
			continue
		}
		procs = append(procs, bsdProc{pid: pid, ppid: ppid, uid: uid, name: name})
	}
	return procs, nil
}

func getArgv(pid int32) string {
	// sysctl kern.procargs2.<pid>
	mib := []int32{1, 55, pid} // CTL_KERN=1, KERN_PROCARGS2=55
	buf, err := sysctlRawMIB(mib)
	if err != nil || len(buf) < 4 {
		return ""
	}
	// First 4 bytes = argc
	argc := int(readUint32LE(buf, 0))
	if argc <= 0 {
		return ""
	}
	// Skip argc int + executable path (null-terminated) + nulls
	pos := 4
	// Skip exec path
	for pos < len(buf) && buf[pos] != 0 {
		pos++
	}
	// Skip null padding
	for pos < len(buf) && buf[pos] == 0 {
		pos++
	}
	// Read argc null-terminated strings
	var args []string
	for i := 0; i < argc && pos < len(buf); i++ {
		start := pos
		for pos < len(buf) && buf[pos] != 0 {
			pos++
		}
		if pos > start {
			args = append(args, string(buf[start:pos]))
		}
		pos++
	}
	return strings.Join(args, " ")
}

func sysctlRawMIB(mib []int32) ([]byte, error) {
	// Get size first
	var n uintptr
	mibPtr := unsafe.Pointer(&mib[0])
	_, _, errno := unix.Syscall6(
		unix.SYS___SYSCTL,
		uintptr(mibPtr),
		uintptr(len(mib)),
		0, uintptr(unsafe.Pointer(&n)),
		0, 0,
	)
	if errno != 0 {
		return nil, errno
	}
	buf := make([]byte, n)
	_, _, errno = unix.Syscall6(
		unix.SYS___SYSCTL,
		uintptr(mibPtr),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&n)),
		0, 0,
	)
	if errno != 0 {
		return nil, errno
	}
	return buf[:n], nil
}

func readUint32LE(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

func nullTermStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func uidToUsername(uid uint32) string {
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return strconv.Itoa(int(uid))
	}
	return u.Username
}
