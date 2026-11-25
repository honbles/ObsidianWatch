//go:build linux

package collector

// process_bpf_linux.go - kernel tier of the endpoint process sensor.
//
// The program in bpf/proc.bpf.c reports every successful exec with its argv
// copied in the kernel, every process exit, and every outbound TCP connect
// with the pid that made it. Reading argv in the kernel matters: the proc
// connector only gives a pid, and a process that exits before /proc is read
// (id, whoami, curl | sh) was lost.
//
// The object is compiled ahead of time and embedded (see the build line in
// bpf/proc.bpf.c), so the agent builds without clang. Field offsets are
// relocated against the running kernel's BTF at load. When the kernel cannot
// load it (no BTF, no tracepoints, not root, locked down), the collector
// falls back to the proc connector and /proc polling, as before.

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"obsidianwatch/linux-agent/pkg/schema"
)

//go:generate sh bpf/build.sh
//go:embed bpf/proc_bpfel.o
var procBPFObject []byte

const (
	kevExec    = 1
	kevExit    = 2
	kevConnect = 3
	kArgsMax   = 1024
)

// Mirrors of the structs in bpf/proc.bpf.c, byte for byte.
type kExec struct {
	Type, PID, PPID, UID, GID, ArgsLen, ArgsTrunc, Pad uint32
	CgroupID, StartNs, PStartNs                        uint64
	Comm                                               [16]byte
	Filename                                           [256]byte
	Args                                               [kArgsMax]byte
}

type kExit struct {
	Type, PID, PPID, ExitCode uint32
	StartNs                   uint64
}

type kConn struct {
	Type, PID, UID       uint32
	Family, SPort, DPort uint16
	_                    uint16
	SAddr, DAddr         [16]byte
	_                    [4]byte
	StartNs              uint64
	Comm                 [16]byte
}

// KernelSensorActive reports whether the kernel tier is running (health
// events and the network collector read it).
var KernelSensorActive atomic.Bool

// kernelConnects remembers outbound connects the kernel reported, so the
// /proc/net poller does not report the same connection again.
var kernelConnects sync.Map // key: "tcp:<sport>:<dst>:<dport>" -> time.Time

func connKey(proto string, sport int, dst string, dport int) string {
	return fmt.Sprintf("%s:%d:%s:%d", proto, sport, dst, dport)
}

// userHZ is the kernel's clock-tick rate for /proc/<pid>/stat starttime. It
// is 100 on every architecture the agent supports.
const userHZ = 100

// guidFromStart builds the same process GUID as linuxProcGUID from the
// kernel's start time, so it works after the process has exited.
func guidFromStart(pid uint32, startNs uint64) string {
	if pid == 0 || startNs == 0 {
		return ""
	}
	return fmt.Sprintf("%s-%d-%d", bootID8(), pid, startNs/(1e9/userHZ))
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func splitArgs(b []byte) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	return strings.Split(string(b), "\x00")
}

// startKernel loads and attaches the kernel programs. It returns an error,
// and changes nothing, when the kernel tier cannot run.
func (p *ProcessCollector) startKernel(ctx context.Context) error {
	if os.Getenv("OW_DISABLE_EBPF") == "1" {
		return errors.New("disabled by OW_DISABLE_EBPF")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(procBPFObject))
	if err != nil {
		return fmt.Errorf("parse object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	var links []link.Link
	closeAll := func() {
		for _, l := range links {
			l.Close()
		}
		coll.Close()
	}
	for _, a := range []struct{ group, name, prog string }{
		{"sched", "sched_process_exec", "ow_exec"},
		{"sched", "sched_process_exit", "ow_exit"},
		{"sock", "inet_sock_set_state", "ow_connect"},
	} {
		l, err := link.Tracepoint(a.group, a.name, coll.Programs[a.prog], nil)
		if err != nil {
			closeAll()
			return fmt.Errorf("attach %s/%s: %w", a.group, a.name, err)
		}
		links = append(links, l)
	}
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		closeAll()
		return fmt.Errorf("ring buffer: %w", err)
	}
	p.drops = coll.Maps["drops"]
	KernelSensorActive.Store(true)

	work := make(chan []byte, 8192)
	go func() {
		<-ctx.Done()
		rd.Close()
		closeAll()
		KernelSensorActive.Store(false)
	}()
	go func() {
		defer close(work)
		for {
			rec, err := rd.Read()
			if err != nil {
				return
			}
			select {
			case work <- rec.RawSample:
			default:
				GlobalHealth.EventsDropped.Add(1)
			}
		}
	}()
	go func() {
		for raw := range work {
			p.onKernelRecord(raw)
		}
	}()
	go p.expireConnects(ctx)
	return nil
}

func (p *ProcessCollector) onKernelRecord(raw []byte) {
	if len(raw) < 4 {
		return
	}
	switch binary.LittleEndian.Uint32(raw) {
	case kevExec:
		var e kExec
		if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) == nil {
			p.onKernelExec(&e)
		}
	case kevExit:
		var e kExit
		if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) == nil {
			p.onKernelExit(&e)
		}
	case kevConnect:
		var e kConn
		if binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e) == nil {
			p.onKernelConnect(&e)
		}
	}
}

// kernelEntry turns a kernel exec record into the collector's procEntry.
func kernelEntry(e *kExec) procEntry {
	args := splitArgs(e.Args[:min(int(e.ArgsLen), kArgsMax)])
	entry := procEntry{
		name:       cstr(e.Comm[:]),
		cmdline:    strings.Join(args, " "),
		args:       capArgv(args),
		ppid:       int(e.PPID),
		uid:        int(e.UID),
		exe:        cstr(e.Filename[:]),
		guid:       guidFromStart(e.PID, e.StartNs),
		parentGUID: guidFromStart(e.PPID, e.PStartNs),
		source:     "ebpf",
		truncated:  e.ArgsTrunc != 0,
	}
	if e.CgroupID != 0 {
		entry.cgroupID = e.CgroupID
	}
	return entry
}

func (p *ProcessCollector) onKernelExec(e *kExec) {
	entry := kernelEntry(e)
	// The path passed to exec can be relative; /proc has the resolved one
	// while the process lives.
	if !filepath.IsAbs(entry.exe) {
		if real, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", e.PID)); err == nil {
			entry.exe = real
		}
	}
	p.mu.Lock()
	p.seenPIDs[int(e.PID)] = entry
	p.mu.Unlock()
	p.emit(int(e.PID), entry, "exec", schema.SeverityInfo)
}

func (p *ProcessCollector) onKernelExit(e *kExit) {
	p.mu.Lock()
	entry, ok := p.seenPIDs[int(e.PID)]
	if ok {
		delete(p.seenPIDs, int(e.PID))
	}
	p.mu.Unlock()
	if !ok {
		return
	}
	entry.exitCode = int(e.ExitCode>>8) & 0xff
	entry.exited = true
	if entry.guid == "" {
		entry.guid = guidFromStart(e.PID, e.StartNs)
	}
	p.emit(int(e.PID), entry, "exit", schema.SeverityInfo)
}

func (p *ProcessCollector) onKernelConnect(e *kConn) {
	var src, dst string
	if e.Family == 2 {
		src = net.IP(e.SAddr[:4]).String()
		dst = net.IP(e.DAddr[:4]).String()
	} else {
		src = net.IP(e.SAddr[:]).String()
		dst = net.IP(e.DAddr[:]).String()
	}
	kernelConnects.Store(connKey("tcp", int(e.SPort), dst, int(e.DPort)), time.Now())

	name := cstr(e.Comm[:])
	p.mu.Lock()
	entry, known := p.seenPIDs[int(e.PID)]
	p.mu.Unlock()
	rawData := map[string]any{
		"action":   "connect",
		"proto":    "tcp",
		"src_ip":   src,
		"src_port": int(e.SPort),
		"dst_ip":   dst,
		"dst_port": int(e.DPort),
		"state":    "SYN_SENT",
		"pid":      int(e.PID),
		"name":     name,
		"uid":      int(e.UID),
	}
	if g := guidFromStart(e.PID, e.StartNs); g != "" {
		rawData["process_guid"] = g
	}
	if known {
		if entry.exe != "" {
			rawData["exe"] = entry.exe
		}
		if entry.cmdline != "" {
			rawData["cmdline"] = entry.cmdline
		}
	}
	sev := schema.SeverityInfo
	switch e.DPort {
	case 4444, 1337, 31337:
		sev = schema.SeverityHigh // classic reverse shell ports
	}
	ev := schema.Event{
		Time:        time.Now().UTC(),
		AgentID:     p.agentID,
		Host:        p.host,
		OS:          "linux",
		EventType:   schema.EventTypeNetwork,
		Severity:    sev,
		Source:      "ebpf",
		Raw:         mustRaw(rawData),
		PID:         int(e.PID),
		ProcessName: name,
		UserName:    p.resolveUsername(int(e.UID)),
		SrcIP:       src,
		SrcPort:     int(e.SPort),
		DstIP:       dst,
		DstPort:     int(e.DPort),
		Proto:       "tcp",
	}
	if known {
		ev.CommandLine = entry.cmdline
		ev.ImagePath = entry.exe
	}
	select {
	case p.out <- ev:
	default:
		GlobalHealth.EventsDropped.Add(1)
	}
}

// expireConnects forgets kernel-reported connects after 15 minutes.
func (p *ProcessCollector) expireConnects(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			kernelConnects.Range(func(k, v any) bool {
				if now.Sub(v.(time.Time)) > 15*time.Minute {
					kernelConnects.Delete(k)
				}
				return true
			})
			p.reportDrops()
		}
	}
}

// reportDrops adds the kernel's ring-buffer drops to the health counters.
func (p *ProcessCollector) reportDrops() {
	if p.drops == nil {
		return
	}
	var total uint64
	for k := uint32(1); k <= 3; k++ {
		var per []uint64
		if p.drops.Lookup(k, &per) == nil {
			for _, n := range per {
				total += n
			}
		}
	}
	if d := total - p.dropsSeen; total > p.dropsSeen {
		GlobalHealth.EventsDropped.Add(int64(d))
		p.dropsSeen = total
	}
}
