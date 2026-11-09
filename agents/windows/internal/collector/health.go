package collector

// health.go — Windows agent health reporter.
// Reports system metrics (CPU, memory, all drives, top processes) every interval.

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"sort"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"obsidianwatch/agent/pkg/schema"
)

type HealthStats struct {
	EventsCollected atomic.Int64
	EventsDropped   atomic.Int64
	RateLimitDrops  atomic.Int64
	EventsForwarded atomic.Int64
	QueueDepth      atomic.Int64
	ForwardErrors   atomic.Int64
	// SysmonStatus (W-01) is set by the agent's startup preflight
	// (sysmonpkg.Check(), see cmd/agent/main.go) and reported in every
	// health event so the management backend can alert when it's
	// anything other than "running". Without Sysmon, the ETW process
	// collector only has PID/TID/opcode to work with — no image path,
	// command line, parent process or user — so process detection is
	// effectively blind on that host even though the agent looks healthy
	// by every other measure. Holds "running", "installed_not_running",
	// "not_installed", or "" if preflight hasn't set it yet (e.g. non-
	// Windows build tags, or health emitted before preflight ran).
	SysmonStatus atomic.Value
}

var GlobalHealth = &HealthStats{}

// SetSysmonStatus is called once from preflight (cmd/agent/main.go) after
// it checks/attempts to install-and-start Sysmon. status should be one of
// "running", "installed_not_running", or "not_installed".
func SetSysmonStatus(status string) {
	GlobalHealth.SysmonStatus.Store(status)
}

// sysmonStatusString reads back what SetSysmonStatus stored, or "" if it
// hasn't been called yet.
func sysmonStatusString() string {
	v := GlobalHealth.SysmonStatus.Load()
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

type HealthReporter struct {
	interval       time.Duration
	agentID        string
	host           string
	agentVer       string
	out            chan<- schema.Event
	logger         *slog.Logger
	startTime      time.Time
	collectors     []string
	lastIdleTime   uint64
	lastKernelTime uint64
	lastUserTime   uint64
	lastProcTimes  map[uint32]uint64
}

type ProcessMetric struct {
	PID    uint32  `json:"pid"`
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

var (
	modKernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	modPsapi                    = windows.NewLazySystemDLL("psapi.dll")
	procGetSystemTimes          = modKernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx    = modKernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeSpaceExW     = modKernel32.NewProc("GetDiskFreeSpaceExW")
	procGetLogicalDriveStringsW = modKernel32.NewProc("GetLogicalDriveStringsW")
	procEnumProcesses           = modPsapi.NewProc("EnumProcesses")
	procGetProcessMemoryInfo    = modPsapi.NewProc("GetProcessMemoryInfo")
)

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

type processMemoryCounters struct {
	cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func NewHealthReporter(interval time.Duration, agentID, host, agentVer string, collectors []string, out chan<- schema.Event, logger *slog.Logger) *HealthReporter {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &HealthReporter{
		interval: interval, agentID: agentID, host: host, agentVer: agentVer,
		out: out, logger: logger, startTime: time.Now(), collectors: collectors,
		lastProcTimes: make(map[uint32]uint64),
	}
}

func (h *HealthReporter) Run(ctx context.Context) error {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	h.emit()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			h.emit()
		}
	}
}

func (h *HealthReporter) readCPUPercent() float64 {
	var idle, kernel, user windows.Filetime
	r, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r == 0 {
		return -1
	}
	idleV := uint64(idle.HighDateTime)<<32 | uint64(idle.LowDateTime)
	kernelV := uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)
	userV := uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
	dIdle := idleV - h.lastIdleTime
	dKernel := kernelV - h.lastKernelTime
	dUser := userV - h.lastUserTime
	h.lastIdleTime, h.lastKernelTime, h.lastUserTime = idleV, kernelV, userV
	total := dKernel + dUser
	if total == 0 {
		return 0
	}
	return float64(total-dIdle) / float64(total) * 100
}

func readMemStats() (totalMB, usedMB, pct float64) {
	var ms memoryStatusEx
	ms.dwLength = uint32(unsafe.Sizeof(ms))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if r == 0 {
		return
	}
	totalMB = float64(ms.ullTotalPhys) / 1024 / 1024
	usedMB = float64(ms.ullTotalPhys-ms.ullAvailPhys) / 1024 / 1024
	pct = float64(ms.dwMemoryLoad)
	return
}

func readAllDrives() []DiskMetric {
	buf := make([]uint16, 256)
	r, _, _ := procGetLogicalDriveStringsW.Call(uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	if r == 0 {
		return nil
	}
	var disks []DiskMetric
	for i := 0; i < int(r); {
		j := i
		for j < int(r) && buf[j] != 0 {
			j++
		}
		if j == i {
			i++
			continue
		}
		drive := windows.UTF16ToString(buf[i:j])
		i = j + 1
		drivePtr, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}
		var free, total, totalFree uint64
		ret, _, _ := procGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(drivePtr)),
			uintptr(unsafe.Pointer(&free)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&totalFree)),
		)
		if ret == 0 || total == 0 {
			continue
		}
		used := total - totalFree
		disks = append(disks, DiskMetric{
			Mount:   drive,
			TotalGB: float64(total) / 1e9,
			UsedGB:  float64(used) / 1e9,
			FreePct: float64(totalFree) / float64(total) * 100,
		})
	}
	return disks
}

func (h *HealthReporter) readTopProcesses() []ProcessMetric {
	pids := make([]uint32, 1024)
	var needed uint32
	r, _, _ := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(uint32(len(pids))*4),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r == 0 {
		return nil
	}
	count := needed / 4

	type raw struct {
		pid   uint32
		name  string
		cpu   uint64
		memWS uintptr
	}
	items := make([]raw, 0, count)

	for _, pid := range pids[:count] {
		if pid == 0 {
			continue
		}
		h, err := windows.OpenProcess(
			windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, pid)
		if err != nil {
			continue
		}

		// Name
		nameBuf := make([]uint16, windows.MAX_PATH)
		size := uint32(windows.MAX_PATH)
		name := "unknown"
		if windows.QueryFullProcessImageName(h, 0, &nameBuf[0], &size) == nil {
			full := windows.UTF16ToString(nameBuf[:size])
			// Extract just the exe name
			for i := len(full) - 1; i >= 0; i-- {
				if full[i] == '\\' || full[i] == '/' {
					full = full[i+1:]
					break
				}
			}
			name = full
		}

		// CPU times
		var ct, et, kt, ut windows.Filetime
		cpuTick := uint64(0)
		if windows.GetProcessTimes(h, &ct, &et, &kt, &ut) == nil {
			cpuTick = uint64(kt.HighDateTime)<<32 | uint64(kt.LowDateTime) +
				uint64(ut.HighDateTime)<<32 | uint64(ut.LowDateTime)
		}

		// Memory
		var pmc processMemoryCounters
		pmc.cb = uint32(unsafe.Sizeof(pmc))
		procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.cb))

		windows.CloseHandle(h)
		items = append(items, raw{pid: pid, name: name, cpu: cpuTick, memWS: pmc.WorkingSetSize})
	}

	intervalTicks := uint64(h.interval.Seconds() * 1e7) // 100-ns intervals
	metrics := make([]ProcessMetric, 0, len(items))
	for _, item := range items {
		prev := h.lastProcTimes[item.pid]
		delta := item.cpu - prev
		h.lastProcTimes[item.pid] = item.cpu
		cpuPct := 0.0
		if intervalTicks > 0 {
			cpuPct = float64(delta) / float64(intervalTicks) * 100
		}
		metrics = append(metrics, ProcessMetric{
			PID:    item.pid,
			Name:   item.name,
			CPUPct: cpuPct,
			MemMB:  float64(item.memWS) / 1024 / 1024,
		})
	}

	sort.Slice(metrics, func(i, j int) bool { return metrics[i].CPUPct > metrics[j].CPUPct })
	top := 10
	if len(metrics) < top {
		top = len(metrics)
	}
	result := make([]ProcessMetric, top)
	copy(result, metrics[:top])

	sort.Slice(metrics, func(i, j int) bool { return metrics[i].MemMB > metrics[j].MemMB })
	seen := map[uint32]bool{}
	for _, m := range result {
		seen[m.PID] = true
	}
	for _, m := range metrics {
		if len(result) >= 20 {
			break
		}
		if !seen[m.PID] {
			result = append(result, m)
			seen[m.PID] = true
		}
	}
	return result
}

func (h *HealthReporter) emit() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	uptime := time.Since(h.startTime).Truncate(time.Second)

	cpuPct := h.readCPUPercent()
	memTotalMB, memUsedMB, memPct := readMemStats()
	disks := readAllDrives()
	procs := h.readTopProcesses()

	data := map[string]interface{}{
		"status": "healthy", "uptime_seconds": int64(uptime.Seconds()),
		"agent_version": h.agentVer, "collectors": h.collectors,
		"events_collected": GlobalHealth.EventsCollected.Load(),
		"events_dropped":   GlobalHealth.EventsDropped.Load(),
		"rate_limit_drops": GlobalHealth.RateLimitDrops.Load(),
		"events_forwarded": GlobalHealth.EventsForwarded.Load(),
		"queue_depth":      GlobalHealth.QueueDepth.Load(),
		"forward_errors":   GlobalHealth.ForwardErrors.Load(),
		"sysmon_status":    sysmonStatusString(),
		"agent_memory_mb":  float64(mem.Alloc) / 1024 / 1024,
		"goroutines":       runtime.NumGoroutine(),
		"os":               "windows", "arch": runtime.GOARCH,
		"cpu_percent":   cpuPct,
		"mem_total_mb":  memTotalMB,
		"mem_used_mb":   memUsedMB,
		"mem_percent":   memPct,
		"disks":         disks,
		"top_processes": procs,
	}
	rawJSON, _ := json.Marshal(data)
	ev := schema.Event{
		Time: time.Now().UTC(), AgentID: h.agentID, Host: h.host, OS: "windows",
		EventType: schema.EventTypeHealth, Severity: schema.SeverityInfo,
		Source: "agent-health", Raw: rawJSON,
	}
	select {
	case h.out <- ev:
	default:
		h.logger.Warn("health: out channel full")
	}
}
