//go:build linux

package ebpf

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"obsidianwatch/linux-agent/internal/otel"
	"obsidianwatch/linux-agent/pkg/schema"
)

const (
	maxEventsPerSecond = 300
	listenerRescan     = 60 * time.Second
)

// Sensor is the running host runtime sensor.
type Sensor struct {
	o          Options
	fs         *procFS
	reg        *Registry
	mode       atomic.Value // string
	containers *containerCache
	vcs        *vcsCache

	nProc, nNet, nFile, nPriv, nDrop atomic.Int64

	mu         sync.Mutex
	primed     bool
	seenSock   map[string]struct{}
	seenProc   map[int]uint64 // pid -> start ticks marker
	uidOf      map[int]int
	listenKey  string
	listenOwn  map[string]int
	listenAt   time.Time
	tokens     float64
	tokenAt    time.Time
	procActive bool // procevent supplies exec events, so the poller must not duplicate them
}

// New builds a sensor; call Run to start it.
func New(o Options) *Sensor {
	o.defaults()
	root := o.procRoot
	if root == "" {
		root = "/proc"
	}
	s := &Sensor{o: o, fs: newProcFS(root), reg: NewRegistry(), seenSock: map[string]struct{}{}, seenProc: map[int]uint64{},
		uidOf: map[int]int{}, tokens: maxEventsPerSecond, tokenAt: time.Now(), containers: newContainerCache(""), vcs: newVCSCache()}
	s.mode.Store(ModePoll)
	return s
}

// Mode reports the tier actually in use: ebpf, procevent or poll.
func (s *Sensor) Mode() string { return s.mode.Load().(string) }

// Stats returns counters for health output.
func (s *Sensor) Stats() Stats {
	return Stats{Process: s.nProc.Load(), Network: s.nNet.Load(), File: s.nFile.Load(), Priv: s.nPriv.Load(),
		Dropped: s.nDrop.Load(), Services: s.reg.Len(), Mode: s.Mode()}
}

// emit sends an event into the agent's normal channel under a per-second budget.
func (s *Sensor) emit(ev schema.Event, counter *atomic.Int64) {
	s.mu.Lock()
	now := time.Now()
	s.tokens += now.Sub(s.tokenAt).Seconds() * maxEventsPerSecond
	if s.tokens > maxEventsPerSecond {
		s.tokens = maxEventsPerSecond
	}
	s.tokenAt = now
	ok := s.tokens >= 1
	if ok {
		s.tokens--
	}
	s.mu.Unlock()
	if !ok || !s.o.Emit(ev) {
		s.nDrop.Add(1)
		return
	}
	counter.Add(1)
}

// watched reports whether a lineage contains a service process.
func (s *Sensor) watched(pids []int) bool { return s.reg.InLineage(pids) }

// Run starts the best available tier and blocks until ctx ends.
func (s *Sensor) Run(ctx context.Context) error {
	if s.o.Emit == nil {
		return errors.New("ebpf: Emit is required (events must use the agent's normal channel)")
	}
	mode := s.o.Mode
	started := false
	if mode == ModeAuto || mode == ModeEBPF {
		if err := startKernel(ctx, s); err == nil {
			s.mode.Store(ModeEBPF)
			started = true
		} else if mode == ModeEBPF {
			return err
		} else {
			s.o.Logger.Debug("host sensor: kernel programs unavailable, using the fallback tiers", "err", err)
		}
	}
	if !started && (mode == ModeAuto || mode == ModeProcEvent) {
		if err := s.startProcEvent(ctx); err == nil {
			s.mode.Store(ModeProcEvent)
			s.procActive = true
		} else {
			s.o.Logger.Debug("host sensor: proc connector unavailable, polling /proc", "err", err)
		}
	}
	if s.Mode() == ModePoll || s.Mode() == ModeProcEvent {
		go s.runFanotify(ctx) // file events; logs and stops quietly when the host does not allow it
	}
	s.o.Logger.Info("host sensor running", "mode", s.Mode())
	go s.runInventory(ctx) // runtime package inventory of service processes

	t := time.NewTicker(s.o.PollInterval)
	defer t.Stop()
	s.tick() // prime: existing processes and connections are recorded, not reported
	for {
		select {
		case <-t.C:
			s.tick()
		case <-ctx.Done():
			return nil
		}
	}
}

// ── one poll round ─────────────────────────────────────────────────────────

func (s *Sensor) tick() {
	instances := s.discover()
	s.pollNetwork()
	if !s.procActive && s.Mode() != ModeEBPF {
		s.pollProcesses()
	}
	s.mu.Lock()
	s.primed = true
	s.mu.Unlock()
	if len(instances) > 0 && s.o.Discovered != nil {
		s.o.Discovered(instances)
	}
}

// discover finds services by their listening TCP sockets and refreshes the registry.
func (s *Sensor) discover() []otel.BatchInstance {
	socks := s.fs.tcp()
	inodes := map[string]bool{}
	ports := map[string][]int{} // inode -> ports
	for _, k := range socks {
		if k.state == tcpListen {
			inodes[k.inode] = true
			ports[k.inode] = append(ports[k.inode], k.localPort)
		}
	}
	keys := make([]string, 0, len(inodes))
	for i := range inodes {
		keys = append(keys, i)
	}
	sort.Strings(keys)
	key := strings.Join(keys, ",")
	s.mu.Lock()
	if key != s.listenKey || time.Since(s.listenAt) > listenerRescan || s.listenOwn == nil {
		s.mu.Unlock()
		own := s.fs.inodePIDs(inodes) // the costly /proc/*/fd scan, only when the listeners changed
		s.mu.Lock()
		s.listenKey, s.listenOwn, s.listenAt = key, own, time.Now()
	}
	owners := s.listenOwn
	s.mu.Unlock()

	byPID := map[int][]int{}
	for ino, pid := range owners {
		byPID[pid] = append(byPID[pid], ports[ino]...)
	}
	type svc struct {
		d     procDetail
		name  string
		ports []int
		ci    ContainerInfo
		unit  string
		vcs   VCSInfo
	}
	found := map[int]*svc{}
	self := os.Getpid()
	for pid, ps := range byPID {
		if pid == self {
			continue
		}
		d, err := s.fs.info(pid)
		if err != nil || IgnoreListener(baseOf(d.Exe)) || IgnoreListener(d.Name) {
			continue
		}
		sort.Ints(ps)
		name := DiscoverName(d.Exe, d.Args, "")
		ci, haveCI := ContainerInfo{}, false
		if d.Container != "" && s.containers != nil {
			ci, haveCI = s.containers.Lookup(d.Container)
		}
		name = BetterName(name, d.Unit, ci, haveCI)
		var vi VCSInfo
		if s.vcs != nil {
			vi = s.vcs.lookup(s.fs.root, pid, d.Start, d.Exe, ci)
		}
		found[pid] = &svc{d: d, name: name, ports: ps, ci: ci, unit: d.Unit, vcs: vi}
	}
	// Workers that inherited their parent's listening socket are the same service.
	for pid, v := range found {
		if p, ok := found[v.d.PPID]; ok && p.name == v.name {
			delete(found, pid)
		}
	}
	reg := map[int]string{}
	var out []otel.BatchInstance
	pids := make([]int, 0, len(found))
	for pid := range found {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	for _, pid := range pids {
		v := found[pid]
		reg[pid] = v.name
		listen, _ := json.Marshal(v.ports)
		out = append(out, otel.BatchInstance{Service: v.name, Environment: s.o.Environment, Source: "discovered", PID: pid,
			ProcStart: v.d.Start, ContainerID: v.d.Container, Identity: "verified", Instrumented: false, Listen: listen,
			Exe: v.d.Exe, Sensor: s.Mode(), Unit: v.unit, ContainerName: v.ci.Name, Image: v.ci.Image,
			VCSRevision: v.vcs.Revision, VCSRepo: v.vcs.Repo, VCSBranch: v.vcs.Branch, VCSSource: v.vcs.Source})
	}
	if s.o.ServicePIDs != nil { // services known from OpenTelemetry are watched too
		for _, p := range s.o.ServicePIDs() {
			if _, ok := reg[p]; !ok && p > 0 {
				reg[p] = "otel"
			}
		}
	}
	s.reg.Set(reg)
	return out
}

// pollNetwork reports new outbound connections of watched processes.
func (s *Sensor) pollNetwork() {
	socks := s.fs.tcp()
	listenPorts := map[int]bool{}
	for _, k := range socks {
		if k.state == tcpListen {
			listenPorts[k.localPort] = true
		}
	}
	cur := map[string]struct{}{}
	var fresh []tcpSock
	s.mu.Lock()
	primed := s.primed
	for _, k := range socks {
		if k.state != tcpEstablished && k.state != tcpSynSent {
			continue
		}
		cur[k.inode] = struct{}{}
		if _, seen := s.seenSock[k.inode]; seen || !primed {
			continue
		}
		if listenPorts[k.localPort] { // an inbound connection to a service, not one it made
			continue
		}
		if appLoop(k.remoteIP) && !s.o.allowLoopback {
			continue
		}
		fresh = append(fresh, k)
	}
	s.seenSock = cur
	s.mu.Unlock()
	if len(fresh) == 0 {
		return
	}
	want := map[string]bool{}
	for _, k := range fresh {
		want[k.inode] = true
	}
	owners := s.fs.inodePIDs(want)
	for _, k := range fresh {
		pid, ok := owners[k.inode]
		if !ok {
			continue
		}
		d, err := s.fs.full(pid)
		if err != nil || !s.watched(d.Lineage()) {
			continue
		}
		s.emit(NetworkEvent(&s.o, "procfs", d.ProcInfo, k.remoteIP, k.remotePort, k.localIP, k.localPort, "", nil), &s.nNet)
	}
}

func appLoop(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127.")
}

// pollProcesses reports new processes (and uid changes) under watched services. Processes that start
// and exit between two rounds are missed; the procevent and ebpf tiers do not have that gap.
func (s *Sensor) pollProcesses() {
	pids := s.fs.pids()
	cur := make(map[int]uint64, len(pids))
	for _, pid := range pids {
		_, fs, err := s.fs.statFields(pid)
		if err != nil {
			continue
		}
		start, _ := strconv.ParseUint(fs[19], 10, 64)
		cur[pid] = start
	}
	s.mu.Lock()
	primed, prev := s.primed, s.seenProc
	s.seenProc = cur
	s.mu.Unlock()
	if !primed {
		return
	}
	for pid, start := range cur {
		if old, ok := prev[pid]; ok && old == start {
			if s.reg.Has(pid) || s.uidTracked(pid) { // watched processes: look for a uid change
				s.checkUID(pid)
			}
			continue
		}
		s.onExec(pid, "procfs")
	}
}

func (s *Sensor) uidTracked(pid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.uidOf[pid]
	return ok
}

func (s *Sensor) checkUID(pid int) {
	uid := s.fs.uidOf(pid)
	if uid < 0 {
		return
	}
	s.mu.Lock()
	old, had := s.uidOf[pid]
	s.uidOf[pid] = uid
	s.mu.Unlock()
	if had && old != uid {
		s.onUIDChange(pid, uid, "procfs")
	}
}

// onExec is the common path for a process that started under any source.
func (s *Sensor) onExec(pid int, source string) {
	d, err := s.fs.full(pid)
	if err != nil || !s.watched(d.Lineage()) {
		return
	}
	s.mu.Lock()
	s.uidOf[pid] = d.UID
	if len(s.uidOf) > 20000 {
		s.uidOf = map[int]int{pid: d.UID}
	}
	s.mu.Unlock()
	s.emit(ProcessEvent(&s.o, source, d.ProcInfo, nil), &s.nProc)
}

// onUIDChange reports a privilege change by a watched process (rule APP-H08).
func (s *Sensor) onUIDChange(pid, euid int, source string) {
	d, err := s.fs.full(pid)
	if err != nil || !s.watched(d.Lineage()) {
		return
	}
	s.emit(ProcessEvent(&s.o, source, d.ProcInfo, &Priv{Kind: "setuid", Detail: strconv.Itoa(euid)}), &s.nPriv)
}
