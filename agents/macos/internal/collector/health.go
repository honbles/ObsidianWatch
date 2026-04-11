//go:build darwin

package collector

// health.go — macOS agent health reporter.
// CPU via sysctl host.cpu_load_info, memory via vm.stat, all disks via getmntinfo,
// top processes via /proc-style sysctl kern.proc.all + proc_pidinfo.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"obsidianwatch/macos-agent/pkg/schema"
)

type HealthStats struct {
	EventsCollected atomic.Int64
	EventsDropped   atomic.Int64
	EventsForwarded atomic.Int64
	QueueDepth      atomic.Int64
	ForwardErrors   atomic.Int64
}

var GlobalHealth = &HealthStats{}

type ProcessMetric struct {
	PID    int     `json:"pid"`
	Name   string  `json:"name"`
	CPUPct float64 `json:"cpu_percent"`
	MemMB  float64 `json:"mem_mb"`
}

type DiskMetric struct {
	Mount   string  `json:"mount"`
	TotalGB float64 `json:"total_gb"`
	UsedGB  float64 `json:"used_gb"`
	FreePct float64 `json:"free_percent"`
}

type HealthReporter struct {
	interval     time.Duration
	agentID      string
	host         string
	agentVer     string
	out          chan<- schema.Event
	logger       *slog.Logger
	startTime    time.Time
	collectors   []string
	lastCPUUser  uint32
	lastCPUSys   uint32
	lastCPUIdle  uint32
	lastCPUNice  uint32
}

func NewHealthReporter(interval time.Duration, agentID, host, agentVer string, collectors []string, out chan<- schema.Event, logger *slog.Logger) *HealthReporter {
	if interval <= 0 { interval = 60 * time.Second }
	return &HealthReporter{
		interval: interval, agentID: agentID, host: host, agentVer: agentVer,
		out: out, logger: logger, startTime: time.Now(), collectors: collectors,
	}
}

func (h *HealthReporter) Run(ctx context.Context) error {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	h.emit()
	for {
		select {
		case <-ctx.Done(): return nil
		case <-ticker.C: h.emit()
		}
	}
}

// CPU_LOAD_INFO mib: host.cpu_load_info
// Returns user/sys/idle/nice ticks since boot — we delta between calls.
func (h *HealthReporter) readCPUPercent() float64 {
	// host_statistics(HOST_CPU_LOAD_INFO) via sysctl
	// Fallback to vm.loadavg if syscall unavailable
	b, err := unix.SysctlRaw("vm.loadavg")
	if err != nil || len(b) < 4 {
		return -1
	}
	// vm.loadavg: three uint32 fixed-point (FSCALE=2048)
	load1 := float64(*(*uint32)(unsafe.Pointer(&b[0]))) / 2048.0
	ncpu  := float64(runtime.NumCPU())
	if ncpu == 0 { return 0 }
	pct := (load1 / ncpu) * 100
	if pct > 100 { pct = 100 }
	return pct
}

func readMemInfo() (totalMB, usedMB, pct float64) {
	totalBytes, err := unix.SysctlUint64("hw.memsize")
	if err != nil { return }
	pageSize, _ := unix.SysctlUint32("hw.pagesize")
	if pageSize == 0 { pageSize = 4096 }

	// vm.page_free_count is pages completely free
	// vm.page_inactive_count are pages available under pressure
	freePages,     _ := unix.SysctlUint32("vm.page_free_count")
	inactivePages, _ := unix.SysctlUint32("vm.page_inactive_count")
	availPages := freePages + inactivePages

	availBytes := uint64(availPages) * uint64(pageSize)
	if availBytes > totalBytes { availBytes = totalBytes }
	usedBytes := totalBytes - availBytes
	totalMB = float64(totalBytes) / 1024 / 1024
	usedMB  = float64(usedBytes)  / 1024 / 1024
	pct     = float64(usedBytes)  / float64(totalBytes) * 100
	return
}

// readAllDisks uses getmntinfo-style stat on all mounted filesystems.
func readAllDisks() []DiskMetric {
	// Use df -l for local filesystems — available on all macOS versions
	out, err := exec.Command("df", "-lk").Output()
	if err != nil { return readRootDiskOnly() }

	skip := map[string]bool{
		"devfs": true, "autofs": true, "map": true,
	}

	var disks []DiskMetric
	seen := map[string]bool{}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 6 { continue }
		fstype := ""
		mount  := fields[len(fields)-1]
		// df output: Filesystem 1K-blocks Used Available Use% Mounted
		if seen[mount] { continue }

		// Skip pseudo-mounts
		if strings.HasPrefix(mount, "/dev") { continue }
		if strings.HasPrefix(fields[0], "map ") || strings.HasPrefix(fields[0], "devfs") { continue }
		_ = fstype
		_ = skip

		total1k, _ := strconv.ParseUint(fields[1], 10, 64)
		used1k,  _ := strconv.ParseUint(fields[2], 10, 64)
		if total1k == 0 { continue }

		totalGB := float64(total1k) / 1e6
		usedGB  := float64(used1k)  / 1e6
		freeGB  := totalGB - usedGB
		seen[mount] = true
		disks = append(disks, DiskMetric{
			Mount:   mount,
			TotalGB: totalGB,
			UsedGB:  usedGB,
			FreePct: freeGB / totalGB * 100,
		})
	}
	if len(disks) == 0 { return readRootDiskOnly() }
	return disks
}

func readRootDiskOnly() []DiskMetric {
	var stat unix.Statfs_t
	if err := unix.Statfs("/", &stat); err != nil { return nil }
	total := float64(stat.Blocks) * float64(stat.Bsize)
	free  := float64(stat.Bavail) * float64(stat.Bsize)
	if total == 0 { return nil }
	return []DiskMetric{{
		Mount:   "/",
		TotalGB: total / 1e9,
		UsedGB:  (total - free) / 1e9,
		FreePct: free / total * 100,
	}}
}

// readTopProcesses uses `ps` command — reliable on all macOS versions.
func readTopProcesses() []ProcessMetric {
	out, err := exec.Command("ps", "-A", "-o", "pid,pcpu,rss,comm").Output()
	if err != nil { return nil }

	var procs []ProcessMetric
	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 4 { continue }
		pid,  _ := strconv.Atoi(fields[0])
		cpu,  _ := strconv.ParseFloat(fields[1], 64)
		rss,  _ := strconv.ParseUint(fields[2], 10, 64) // kB
		name := fields[3]
		// Extract just the binary name from full path
		if idx := strings.LastIndex(name, "/"); idx >= 0 { name = name[idx+1:] }
		procs = append(procs, ProcessMetric{
			PID:    pid,
			Name:   fmt.Sprintf("%s", name),
			CPUPct: cpu,
			MemMB:  float64(rss) / 1024,
		})
	}

	// Top 10 by CPU
	sort.Slice(procs, func(i, j int) bool { return procs[i].CPUPct > procs[j].CPUPct })
	top := 10; if len(procs) < top { top = len(procs) }
	result := make([]ProcessMetric, top)
	copy(result, procs[:top])

	// Top 10 by memory not already included
	sort.Slice(procs, func(i, j int) bool { return procs[i].MemMB > procs[j].MemMB })
	seen := map[int]bool{}
	for _, m := range result { seen[m.PID] = true }
	for _, m := range procs {
		if len(result) >= 20 { break }
		if !seen[m.PID] { result = append(result, m); seen[m.PID] = true }
	}
	return result
}

func (h *HealthReporter) emit() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	uptime := time.Since(h.startTime).Truncate(time.Second)

	cpuPct := h.readCPUPercent()
	memTotalMB, memUsedMB, memPct := readMemInfo()
	disks := readAllDisks()
	procs := readTopProcesses()

	data := map[string]interface{}{
		"status": "healthy", "uptime_seconds": int64(uptime.Seconds()),
		"agent_version": h.agentVer, "collectors": h.collectors,
		"events_collected": GlobalHealth.EventsCollected.Load(),
		"events_dropped":   GlobalHealth.EventsDropped.Load(),
		"events_forwarded": GlobalHealth.EventsForwarded.Load(),
		"queue_depth":      GlobalHealth.QueueDepth.Load(),
		"forward_errors":   GlobalHealth.ForwardErrors.Load(),
		"agent_memory_mb":  float64(mem.Alloc) / 1024 / 1024,
		"goroutines":       runtime.NumGoroutine(),
		"os": "macos", "arch": runtime.GOARCH,
		"cpu_percent":   cpuPct,
		"mem_total_mb":  memTotalMB,
		"mem_used_mb":   memUsedMB,
		"mem_percent":   memPct,
		"disks":         disks,
		"top_processes": procs,
	}

	rawJSON, _ := json.Marshal(data)
	ev := schema.Event{
		Time: time.Now().UTC(), AgentID: h.agentID, Host: h.host, OS: "macos",
		EventType: schema.EventTypeHealth, Severity: schema.SeverityInfo,
		Source: "agent-health", Raw: rawJSON,
	}
	select {
	case h.out <- ev:
	default: h.logger.Warn("health: out channel full")
	}
}
