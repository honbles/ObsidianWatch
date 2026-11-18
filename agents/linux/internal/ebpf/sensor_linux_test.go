//go:build linux

package ebpf

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"obsidianwatch/linux-agent/internal/otel"
	"obsidianwatch/linux-agent/pkg/schema"
)

type collected struct {
	mu     sync.Mutex
	events []schema.Event
	insts  []otel.BatchInstance
}

func (c *collected) emit(ev schema.Event) bool {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
	return true
}
func (c *collected) discovered(l []otel.BatchInstance) {
	c.mu.Lock()
	c.insts = append(c.insts, l...)
	c.mu.Unlock()
}
func (c *collected) find(typ, source string, pred func(schema.Event) bool) *schema.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.events {
		e := c.events[i]
		if string(e.EventType) == typ && (source == "" || e.Source == source) && pred(e) {
			return &c.events[i]
		}
	}
	return nil
}

func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func newTestSensor(mode string, c *collected, pids func() []int) *Sensor {
	return New(Options{AgentID: "a1", Hostname: "web-01", Mode: mode, PollInterval: 40 * time.Millisecond, Emit: c.emit, Discovered: c.discovered,
		ServicePIDs: pids, allowLoopback: true})
}

// TestHelperListener is not a test: it is the "service" the discovery test starts as a child process.
func TestHelperListener(t *testing.T) {
	if os.Getenv("EBPF_TEST_HELPER") != "listen" {
		t.Skip("helper")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(2)
	}
	os.Stdout.WriteString(strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) + "\n")
	time.Sleep(30 * time.Second)
}

func TestPollTierReportsChildOfAService(t *testing.T) {
	c := &collected{}
	self := os.Getpid()
	s := newTestSensor(ModePoll, c, func() []int { return []int{self} }) // this process plays the service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	time.Sleep(250 * time.Millisecond) // first round primes the process table
	child := exec.Command("sh", "-c", "sleep 3")
	if err := child.Start(); err != nil {
		t.Skip("cannot start a child")
	}
	defer func() { _ = child.Process.Kill(); _, _ = child.Process.Wait() }()

	waitFor(t, "a process event for the shell started under the service", 5*time.Second, func() bool {
		return c.find("process", "procfs", func(e schema.Event) bool { return e.PID == child.Process.Pid }) != nil
	})
	ev := c.find("process", "procfs", func(e schema.Event) bool { return e.PID == child.Process.Pid })
	if ev.PPID != self || ev.ProcessName != "sh" || !strings.Contains(string(ev.Raw), `"ancestors"`) || !strings.Contains(string(ev.Raw), `"pid":`+strconv.Itoa(self)) {
		t.Fatalf("%+v %s", ev, ev.Raw)
	}
	if s.Mode() != ModePoll || s.Stats().Process == 0 {
		t.Fatalf("%+v", s.Stats())
	}
	// A process that is NOT under the service is not reported at all.
	unrelated := c.find("process", "", func(e schema.Event) bool {
		return e.PPID != self && e.PID != child.Process.Pid && !strings.Contains(string(e.Raw), `"pid":`+strconv.Itoa(self))
	})
	if unrelated != nil {
		t.Fatalf("only service descendants are reported: %+v", unrelated)
	}
}

func TestPollTierReportsOutboundConnections(t *testing.T) {
	c := &collected{}
	self := os.Getpid()
	s := newTestSensor(ModePoll, c, func() []int { return []int{self} })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			cn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(2 * time.Second); cn.Close() }()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	time.Sleep(250 * time.Millisecond)
	cn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cn.Close()
	waitFor(t, "a network event for the service's own connection", 5*time.Second, func() bool {
		return c.find("network", "procfs", func(e schema.Event) bool { return e.DstPort == port }) != nil
	})
	ev := c.find("network", "procfs", func(e schema.Event) bool { return e.DstPort == port })
	if ev.PID != self || ev.DstIP != "127.0.0.1" || ev.Proto != "tcp" {
		t.Fatalf("%+v", ev)
	}
	// The inbound side of the same connection (local port == the listener's) is not reported as outbound.
	if c.find("network", "", func(e schema.Event) bool { return e.SrcPort == port }) != nil {
		t.Fatal("inbound connections to a service are not outbound events")
	}
}

func TestDiscoversAListeningServiceAndWatchesItsChildren(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperListener")
	cmd.Env = append(os.Environ(), "EBPF_TEST_HELPER=listen")
	out, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		t.Skip("cannot start the helper service")
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Skip("helper did not report a port")
	}
	port, _ := strconv.Atoi(strings.TrimSpace(line))

	c := &collected{}
	s := newTestSensor(ModePoll, c, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	waitFor(t, "the listening process to be discovered", 8*time.Second, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, i := range c.insts {
			if i.PID == cmd.Process.Pid {
				return true
			}
		}
		return false
	})
	var inst otel.BatchInstance
	c.mu.Lock()
	for _, i := range c.insts {
		if i.PID == cmd.Process.Pid {
			inst = i
		}
	}
	c.mu.Unlock()
	if inst.Source != "discovered" || inst.Instrumented || inst.Identity != "verified" || inst.Sensor != ModePoll || inst.Environment != "default" ||
		!strings.Contains(string(inst.Listen), strconv.Itoa(port)) || inst.Service == "" || inst.ProcStart.IsZero() {
		t.Fatalf("%+v", inst)
	}
	if !s.reg.Has(cmd.Process.Pid) {
		t.Fatal("a discovered service must be in the registry so its children are watched")
	}
}

func TestProcEventTierReportsExec(t *testing.T) {
	c := &collected{}
	self := os.Getpid()
	s := newTestSensor(ModeProcEvent, c, func() []int { return []int{self} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.startProcEvent(ctx); err != nil {
		t.Skipf("proc connector not available on this host: %v", err)
	}
	s.reg.Set(map[int]string{self: "svc"})
	time.Sleep(200 * time.Millisecond)
	child := exec.Command("sh", "-c", "sleep 2")
	if err := child.Start(); err != nil {
		t.Skip("cannot start a child")
	}
	defer func() { _ = child.Process.Kill(); _, _ = child.Process.Wait() }()
	waitFor(t, "an exec event from the proc connector", 5*time.Second, func() bool {
		return c.find("process", "procevent", func(e schema.Event) bool { return e.PPID == self }) != nil
	})
	ev := c.find("process", "procevent", func(e schema.Event) bool { return e.PPID == self })
	if !strings.Contains(string(ev.Raw), `"ancestors"`) || ev.PID == 0 {
		t.Fatalf("%+v %s", ev, ev.Raw)
	}
}

func TestFanotifyTierReportsWritesByAServiceDescendant(t *testing.T) {
	dir := t.TempDir()
	c := &collected{}
	self := os.Getpid()
	s := New(Options{AgentID: "a1", Hostname: "h", WatchDirs: []string{dir}, Emit: c.emit})
	s.reg.Set(map[int]string{self: "svc"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.runFanotify(ctx)
	time.Sleep(400 * time.Millisecond)
	target := filepath.Join(dir, "shell.php")
	// A child of this "service" writes the file and stays alive for a moment, as a server worker would.
	writer := exec.Command("sh", "-c", "echo '<?php' > "+target+"; sleep 2")
	if err := writer.Start(); err != nil {
		t.Skip("cannot run a shell")
	}
	defer func() { _ = writer.Process.Kill(); _, _ = writer.Process.Wait() }()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) && c.find("file", "fanotify", func(e schema.Event) bool { return e.FilePath == target }) == nil {
		time.Sleep(50 * time.Millisecond)
	}
	ev := c.find("file", "fanotify", func(e schema.Event) bool { return e.FilePath == target })
	if ev == nil {
		t.Skip("fanotify is not permitted or not supported on this host (no file events); the tier degrades by design")
	}
	if !strings.Contains(string(ev.Raw), `"op":"write"`) || ev.PPID != self || !strings.Contains(string(ev.Raw), `"mode":"0644"`) {
		t.Fatalf("%+v %s", ev, ev.Raw)
	}
}

func TestEmitBudgetAndRequiredEmit(t *testing.T) {
	s := New(Options{Emit: func(schema.Event) bool { return true }})
	for i := 0; i < maxEventsPerSecond*3; i++ {
		s.emit(schema.Event{}, &s.nProc)
	}
	if s.nDrop.Load() == 0 || s.nProc.Load() > maxEventsPerSecond+20 {
		t.Fatalf("a flood must be capped per second: emitted=%d dropped=%d", s.nProc.Load(), s.nDrop.Load())
	}
	if err := New(Options{}).Run(context.Background()); err == nil {
		t.Fatal("Emit is required: events must use the agent's normal channel")
	}
	full := New(Options{Emit: func(schema.Event) bool { return false }})
	full.emit(schema.Event{}, &full.nProc)
	if full.nDrop.Load() != 1 {
		t.Fatal("a full channel counts a drop and never blocks")
	}
	if _, err := New(Options{Mode: ModeEBPF, Emit: func(schema.Event) bool { return true }}), error(nil); err != nil {
		t.Fatal(err)
	}
	if err := New(Options{Mode: ModeEBPF, Emit: func(schema.Event) bool { return true }}).Run(context.Background()); err == nil {
		t.Fatal("requesting the kernel tier in a build without it must fail loudly, not fall back silently")
	}
}
