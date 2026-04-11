package collector

// health.go — Linux agent health reporter.
// Reports agent internals + system resource metrics + top processes every interval.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

type HealthStats struct {
	EventsCollected atomic.Int64
	EventsDropped   atomic.Int64
	EventsForwarded atomic.Int64
	QueueDepth      atomic.Int64
	ForwardErrors   atomic.Int64
}

var GlobalHealth = &HealthStats{}

type HealthReporter struct {
	interval     time.Duration
	agentID      string
	host         string
	agentVer     string
	out          chan<- schema.Event
	logger       *slog.Logger
	startTime    time.Time
	collectors   []string
	lastCPUIdle  uint64
	lastCPUTotal uint64
	lastProcStat map[int]procStat
}

type procStat struct {
	utime uint64
	stime uint64
}

type ProcessMetric struct {
	PID     int     `json:"pid"`
	Name    string  `json:"name"`
	CPUPct  float64 `json:"cpu_percent"`
	MemMB   float64 `json:"mem_mb"`
}

type DiskMetric struct {
	Mount     string  `json:"mount"`
	TotalGB   float64 `json:"total_gb"`
	UsedGB    float64 `json:"used_gb"`
	FreePct   float64 `json:"free_percent"`
}

func NewHealthReporter(interval time.Duration, agentID, host, agentVer string, collectors []string, out chan<- schema.Event, logger *slog.Logger) *HealthReporter {
	if interval <= 0 { interval = 60 * time.Second }
	return &HealthReporter{
		interval: interval, agentID: agentID, host: host, agentVer: agentVer,
		out: out, logger: logger, startTime: time.Now(), collectors: collectors,
		lastProcStat: make(map[int]procStat),
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

func (h *HealthReporter) readCPUPercent() float64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil { return -1 }
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") { continue }
		fields := strings.Fields(line)
		if len(fields) < 8 { return -1 }
		vals := make([]uint64, len(fields)-1)
		for i, f := range fields[1:] { vals[i], _ = strconv.ParseUint(f, 10, 64) }
		idle := vals[3] + vals[4]
		total := uint64(0)
		for _, v := range vals { total += v }
		dTotal := total - h.lastCPUTotal
		dIdle  := idle  - h.lastCPUIdle
		h.lastCPUTotal = total
		h.lastCPUIdle  = idle
		if dTotal == 0 { return 0 }
		return float64(dTotal-dIdle) / float64(dTotal) * 100
	}
	return -1
}

func readMemInfo() (totalMB, usedMB, pct float64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil { return }
	kv := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 { continue }
		k := strings.TrimSuffix(parts[0], ":")
		v, _ := strconv.ParseUint(parts[1], 10, 64)
		kv[k] = v
	}
	total := kv["MemTotal"]; avail := kv["MemAvailable"]
	if total == 0 { return }
	used := total - avail
	totalMB = float64(total) / 1024
	usedMB  = float64(used) / 1024
	pct     = float64(used) / float64(total) * 100
	return
}

// readAllDisks reads /proc/mounts and calls statfs on each real filesystem.
func readAllDisks() []DiskMetric {
	f, err := os.Open("/proc/mounts")
	if err != nil { return nil }
	defer f.Close()

	// Filesystems to skip
	skip := map[string]bool{
		"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
		"tmpfs": true, "cgroup": true, "cgroup2": true, "pstore": true,
		"securityfs": true, "debugfs": true, "hugetlbfs": true, "mqueue": true,
		"fusectl": true, "configfs": true, "bpf": true, "tracefs": true,
		"ramfs": true, "overlay": true, "squashfs": true,
	}

	seenMount := map[string]bool{}
	seenDev   := map[uint64]bool{} // deduplicate by device — bind mounts share same device
	var disks []DiskMetric
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 { continue }
		fstype := fields[2]
		mount  := fields[1]
		if skip[fstype] { continue }
		if !strings.HasPrefix(fields[0], "/") { continue }
		if seenMount[mount] { continue }
		seenMount[mount] = true

		var st syscallStatfs
		if err := statfs(mount, &st); err != nil { continue }
		if st.Blocks == 0 { continue }

		// Skip duplicate filesystems (bind mounts, overlayfs layers)
		fsKey := uint64(st.Fsid.Val[0])<<32 | uint64(st.Fsid.Val[1])
		if seenDev[fsKey] { continue }
		seenDev[fsKey] = true

		total := float64(st.Blocks) * float64(st.Bsize)
		free  := float64(st.Bavail) * float64(st.Bsize)
		used  := total - free
		disks = append(disks, DiskMetric{
			Mount:   mount,
			TotalGB: total / 1e9,
			UsedGB:  used  / 1e9,
			FreePct: free / total * 100,
		})
	}
	return disks
}

// readTopProcesses returns top 10 processes by CPU then top 10 by memory.
func (h *HealthReporter) readTopProcesses(hertzPerSec float64) []ProcessMetric {
	entries, err := filepath.Glob("/proc/[0-9]*/stat")
	if err != nil { return nil }

	type rawProc struct {
		pid    int
		name   string
		utime  uint64
		stime  uint64
		vmrss  uint64 // kB
	}

	procs := make([]rawProc, 0, len(entries))
	for _, path := range entries {
		data, err := os.ReadFile(path)
		if err != nil { continue }
		s := string(data)
		// format: pid (name) state ppid ...
		nameStart := strings.Index(s, "(")
		nameEnd   := strings.LastIndex(s, ")")
		if nameStart < 0 || nameEnd < 0 { continue }
		pid, _ := strconv.Atoi(strings.TrimSpace(s[:nameStart]))
		name := s[nameStart+1 : nameEnd]
		rest := strings.Fields(s[nameEnd+2:])
		if len(rest) < 13 { continue }
		utime, _ := strconv.ParseUint(rest[11], 10, 64)
		stime, _ := strconv.ParseUint(rest[12], 10, 64)

		// Read memory from /proc/<pid>/status
		vmrss := uint64(0)
		statusPath := fmt.Sprintf("/proc/%d/status", pid)
		statusData, err := os.ReadFile(statusPath)
		if err == nil {
			for _, line := range strings.Split(string(statusData), "\n") {
				if strings.HasPrefix(line, "VmRSS:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 { vmrss, _ = strconv.ParseUint(fields[1], 10, 64) }
					break
				}
			}
		}
		procs = append(procs, rawProc{pid: pid, name: name, utime: utime, stime: stime, vmrss: vmrss})
	}

	// Calculate CPU delta
	isFirstPoll := len(h.lastProcStat) == 0
	metrics := make([]ProcessMetric, 0, len(procs))
	for _, p := range procs {
		prev := h.lastProcStat[p.pid]
		dCPU := float64((p.utime+p.stime) - (prev.utime+prev.stime))
		// On first poll lastProcStat is empty — all deltas are since boot, skip CPU
		cpuPct := 0.0
		if !isFirstPoll && hertzPerSec > 0 {
			cpuPct = dCPU / hertzPerSec * 100
			if cpuPct > 100 { cpuPct = 100 }
		}
		h.lastProcStat[p.pid] = procStat{utime: p.utime, stime: p.stime}
		metrics = append(metrics, ProcessMetric{
			PID:    p.pid,
			Name:   p.name,
			CPUPct: cpuPct,
			MemMB:  float64(p.vmrss) / 1024,
		})
	}

	// Sort by CPU desc, take top 10
	sort.Slice(metrics, func(i, j int) bool { return metrics[i].CPUPct > metrics[j].CPUPct })
	top := 10
	if len(metrics) < top { top = len(metrics) }
	result := make([]ProcessMetric, top)
	copy(result, metrics[:top])

	// Also include top 10 by memory that aren't already in the list
	sort.Slice(metrics, func(i, j int) bool { return metrics[i].MemMB > metrics[j].MemMB })
	inResult := map[int]bool{}
	for _, m := range result { inResult[m.PID] = true }
	for _, m := range metrics {
		if len(result) >= 20 { break }
		if !inResult[m.PID] { result = append(result, m); inResult[m.PID] = true }
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
	procs := h.readTopProcesses(float64(h.interval.Seconds()) * 100) // approx HZ*interval

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
		"os": "linux", "arch": runtime.GOARCH,
		"cpu_percent":  cpuPct,
		"mem_total_mb": memTotalMB,
		"mem_used_mb":  memUsedMB,
		"mem_percent":  memPct,
		"disks":        disks,
		"top_processes": procs,
	}

	rawJSON, _ := json.Marshal(data)
	ev := schema.Event{
		Time: time.Now().UTC(), AgentID: h.agentID, Host: h.host, OS: "linux",
		EventType: schema.EventTypeHealth, Severity: schema.SeverityInfo,
		Source: "agent-health", Raw: rawJSON,
	}
	select {
	case h.out <- ev:
	default:
		h.logger.Warn("health: out channel full")
	}
}
