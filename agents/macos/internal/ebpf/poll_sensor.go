package ebpf

// poll_sensor.go - the host runtime sensor for platforms without /proc, eBPF or a proc connector
// (Windows, macOS). It takes a snapshot of the process table and the TCP table every poll
// interval and reports, for services only: new processes, new outbound connections, and the
// services themselves (a process with a listening port that is not a system daemon = Tier 0
// discovery). The snapshot source is a small interface so the logic is tested on any OS.
//
// Gaps compared with the Linux tiers, all stated in docs/app/sensor.md: processes and connections
// that start and end between two polls are missed, there are no file events and no uid-change
// (APP-H08) events.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"obsidianwatch/macos-agent/internal/otel"
	"obsidianwatch/macos-agent/pkg/schema"
)

const pollEventsPerSecond = 300

// procRec is one row of the process table.
type procRec struct {
	PID, PPID int
	Exe, Name string
	Args      []string
	Cmd, User string
	Start     time.Time
}

// connRec is one TCP table row with its owning process.
type connRec struct {
	State      string // LISTEN, ESTABLISHED, ...
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	PID        int
}

// hostProvider supplies the snapshots.
type hostProvider interface {
	Procs() (map[int]procRec, error)
	TCP() ([]connRec, error)
}

type pollSensor struct {
	o    Options
	host hostProvider
	reg  *Registry
	mode atomic.Value

	nProc, nNet, nDrop atomic.Int64

	mu       sync.Mutex
	primed   bool
	seenConn map[string]struct{}
	seenProc map[int]time.Time
	tokens   float64
	tokenAt  time.Time
}

func newPollSensor(o Options, h hostProvider) *pollSensor {
	o.defaults()
	s := &pollSensor{o: o, host: h, reg: NewRegistry(), seenConn: map[string]struct{}{}, seenProc: map[int]time.Time{},
		tokens: pollEventsPerSecond, tokenAt: time.Now()}
	s.mode.Store(ModePoll)
	return s
}

func (s *pollSensor) Mode() string { return s.mode.Load().(string) }

func (s *pollSensor) Stats() Stats {
	return Stats{Process: s.nProc.Load(), Network: s.nNet.Load(), Dropped: s.nDrop.Load(), Services: s.reg.Len(), Mode: s.Mode()}
}

func (s *pollSensor) emit(ev schema.Event, c *atomic.Int64) {
	s.mu.Lock()
	now := time.Now()
	s.tokens += now.Sub(s.tokenAt).Seconds() * pollEventsPerSecond
	if s.tokens > pollEventsPerSecond {
		s.tokens = pollEventsPerSecond
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
	c.Add(1)
}

func (s *pollSensor) Run(ctx context.Context) error {
	if s.o.Emit == nil {
		return errors.New("ebpf: Emit is required (events must use the agent's normal channel)")
	}
	if u, ok := s.host.(interface{ unsupported() bool }); ok && u.unsupported() {
		return ErrUnsupported
	}
	s.o.Logger.Info("host sensor running", "mode", s.Mode(), "note", "polling tier: no file events, short-lived processes can be missed")
	t := time.NewTicker(s.o.PollInterval)
	defer t.Stop()
	s.tick()
	for {
		select {
		case <-t.C:
			s.tick()
		case <-ctx.Done():
			return nil
		}
	}
}

// info builds the ProcInfo for pid with its ancestors (nearest first). A parent that started after
// its child is a reused pid and ends the chain.
func info(procs map[int]procRec, pid int) (ProcInfo, bool) {
	r, ok := procs[pid]
	if !ok {
		return ProcInfo{}, false
	}
	p := ProcInfo{PID: r.PID, PPID: r.PPID, Start: r.Start, Name: r.Name, Exe: r.Exe, Cmd: r.Cmd, User: r.User}
	cur := r
	for i := 0; i < 16; i++ {
		par, ok := procs[cur.PPID]
		if !ok || par.PID == cur.PID || (!par.Start.IsZero() && !cur.Start.IsZero() && par.Start.After(cur.Start)) {
			break
		}
		p.Ancestors = append(p.Ancestors, Anc{PID: par.PID, Name: par.Name, Exe: par.Exe})
		cur = par
	}
	return p, true
}

func (s *pollSensor) tick() {
	procs, err := s.host.Procs()
	if err != nil {
		s.o.Logger.Debug("host sensor: process snapshot failed", "err", err)
		return
	}
	conns, err := s.host.TCP()
	if err != nil {
		s.o.Logger.Debug("host sensor: tcp snapshot failed", "err", err)
		conns = nil
	}
	inst := s.discover(procs, conns)
	s.pollNetwork(procs, conns)
	s.pollProcesses(procs)
	s.mu.Lock()
	s.primed = true
	s.mu.Unlock()
	if len(inst) > 0 && s.o.Discovered != nil {
		s.o.Discovered(inst)
	}
}

func (s *pollSensor) discover(procs map[int]procRec, conns []connRec) []otel.BatchInstance {
	ports := map[int][]int{}
	for _, c := range conns {
		if c.State == "LISTEN" && c.PID > 0 {
			ports[c.PID] = append(ports[c.PID], c.LocalPort)
		}
	}
	type svc struct {
		r     procRec
		name  string
		ports []int
	}
	found := map[int]*svc{}
	self := os.Getpid()
	for pid, ps := range ports {
		r, ok := procs[pid]
		if !ok || pid == self || IgnoreListener(baseOf(r.Exe)) || IgnoreListener(r.Name) {
			continue
		}
		sort.Ints(ps)
		ps = uniqInts(ps)
		found[pid] = &svc{r: r, name: DiscoverName(r.Exe, r.Args, ""), ports: ps}
	}
	for pid, v := range found { // workers sharing the parent's listening socket are one service
		if p, ok := found[v.r.PPID]; ok && p.name == v.name {
			delete(found, pid)
		}
	}
	reg := map[int]string{}
	pids := make([]int, 0, len(found))
	for pid := range found {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	var out []otel.BatchInstance
	for _, pid := range pids {
		v := found[pid]
		reg[pid] = v.name
		listen, _ := json.Marshal(v.ports)
		out = append(out, otel.BatchInstance{Service: v.name, Environment: s.o.Environment, Source: "discovered", PID: pid,
			ProcStart: v.r.Start, Identity: "verified", Instrumented: false, Listen: listen, Exe: v.r.Exe, Sensor: s.Mode()})
	}
	if s.o.ServicePIDs != nil {
		for _, p := range s.o.ServicePIDs() {
			if _, ok := reg[p]; !ok && p > 0 {
				reg[p] = "otel"
			}
		}
	}
	s.reg.Set(reg)
	return out
}

func uniqInts(a []int) []int {
	out := a[:0]
	for i, v := range a {
		if i == 0 || v != a[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func isLoop(ip string) bool {
	return ip == "::1" || (len(ip) >= 4 && ip[:4] == "127.")
}

func (s *pollSensor) pollNetwork(procs map[int]procRec, conns []connRec) {
	listen := map[int]bool{}
	for _, c := range conns {
		if c.State == "LISTEN" {
			listen[c.LocalPort] = true
		}
	}
	cur := map[string]struct{}{}
	var fresh []connRec
	s.mu.Lock()
	primed := s.primed
	for _, c := range conns {
		if c.State != "ESTABLISHED" && c.State != "SYN_SENT" {
			continue
		}
		k := c.LocalIP + ":" + strconv.Itoa(c.LocalPort) + ">" + c.RemoteIP + ":" + strconv.Itoa(c.RemotePort) + "#" + strconv.Itoa(c.PID)
		cur[k] = struct{}{}
		if _, seen := s.seenConn[k]; seen || !primed || listen[c.LocalPort] || (isLoop(c.RemoteIP) && !s.o.allowLoopback) {
			continue
		}
		fresh = append(fresh, c)
	}
	s.seenConn = cur
	s.mu.Unlock()
	for _, c := range fresh {
		p, ok := info(procs, c.PID)
		if !ok || !s.reg.InLineage(p.Lineage()) {
			continue
		}
		s.emit(NetworkEvent(&s.o, "poll", p, c.RemoteIP, c.RemotePort, c.LocalIP, c.LocalPort, "", nil), &s.nNet)
	}
}

func (s *pollSensor) pollProcesses(procs map[int]procRec) {
	cur := make(map[int]time.Time, len(procs))
	for pid, r := range procs {
		cur[pid] = r.Start
	}
	s.mu.Lock()
	primed, prev := s.primed, s.seenProc
	s.seenProc = cur
	s.mu.Unlock()
	if !primed {
		return
	}
	for pid, start := range cur {
		if old, ok := prev[pid]; ok && old.Equal(start) {
			continue
		}
		p, ok := info(procs, pid)
		if !ok || !s.reg.InLineage(p.Lineage()) {
			continue
		}
		s.emit(ProcessEvent(&s.o, "poll", p, nil), &s.nProc)
	}
}
