//go:build linux && bpflive

package collector

// Live test of the kernel tier. Needs root and a kernel with BTF:
//   go test -tags bpflive -run Kernel ./internal/collector

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

func TestKernelSensorLive(t *testing.T) {
	out := make(chan schema.Event, 100000)
	p := NewProcessCollector(ProcessCollectorConfig{Enabled: true, PollInterval: time.Second}, "ag", "h", out,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := p.startKernel(ctx); err != nil {
		t.Fatalf("kernel tier did not start: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	// A short-lived child with awkward arguments, and a connect from a child.
	marker := "ow-marker-" + strconv.Itoa(os.Getpid())
	if err := exec.Command("/bin/sh", "-c", "/bin/echo "+marker+" 'two words' >/dev/null").Run(); err != nil {
		t.Fatal(err)
	}
	py := exec.Command("/bin/sh", "-c", "exec 3<>/dev/tcp/127.0.0.1/"+strconv.Itoa(port)+" 2>/dev/null || true")
	py.Run()
	sleeper := exec.Command("/bin/sleep", "30")
	sleeper.Start()
	defer sleeper.Process.Kill()

	deadline := time.After(5 * time.Second)
	var gotEcho, gotConnect, gotExit, gotSleep bool
	var echoEv, sleepEv map[string]any
	for !(gotEcho && gotExit && gotSleep && gotConnect) {
		select {
		case ev := <-out:
			var raw map[string]any
			json.Unmarshal(ev.Raw, &raw)
			switch {
			case ev.EventType == schema.EventTypeProcess && raw["action"] == "exec" && strings.Contains(ev.CommandLine, marker):
				gotEcho, echoEv = true, raw
			case ev.EventType == schema.EventTypeProcess && raw["action"] == "exit" && strings.Contains(ev.CommandLine, marker):
				gotExit = true
			case ev.EventType == schema.EventTypeProcess && raw["action"] == "exec" && ev.PID == sleeper.Process.Pid:
				gotSleep, sleepEv = true, raw
			case ev.EventType == schema.EventTypeNetwork && ev.DstPort == port && ev.Source == "ebpf":
				gotConnect = true
			}
		case <-deadline:
			// /dev/tcp needs bash; sh may be dash. The connect check is then skipped.
			if gotEcho && gotExit && gotSleep && !gotConnect {
				if _, err := exec.LookPath("bash"); err != nil || !shIsBash() {
					t.Log("connect not exercised: /bin/sh has no /dev/tcp")
					gotConnect = true
					continue
				}
			}
			t.Fatalf("missing events: echo=%v exit=%v sleep=%v connect=%v", gotEcho, gotExit, gotSleep, gotConnect)
		}
	}

	argv, _ := echoEv["argv"].([]any)
	if len(argv) != 3 || argv[2] != "two words" {
		t.Errorf("argv not preserved from the kernel: %v", echoEv["argv"])
	}
	if echoEv["sensor"] != "ebpf" || echoEv["exe"] != "/bin/echo" && echoEv["exe"] != "/usr/bin/echo" {
		t.Errorf("exec event: %v", echoEv)
	}
	if echoEv["parent_process_guid"] == nil || echoEv["sha256"] == nil {
		t.Errorf("echo exited before /proc could be read, but parent guid and hash must still be set: %v", echoEv)
	}
	// The kernel-derived GUID must equal the /proc-derived one.
	if want := linuxProcGUID(sleeper.Process.Pid); sleepEv["process_guid"] != want {
		t.Errorf("guid from kernel %v, from /proc %v", sleepEv["process_guid"], want)
	}
}

func shIsBash() bool {
	target, _ := os.Readlink("/bin/sh")
	return strings.Contains(target, "bash")
}

// Connects made directly by the test process exercise the connect hook
// regardless of the shell.
func TestKernelConnectLive(t *testing.T) {
	out := make(chan schema.Event, 100000)
	p := NewProcessCollector(ProcessCollectorConfig{Enabled: true, PollInterval: time.Second}, "ag", "h", out,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := p.startKernel(ctx); err != nil {
		t.Fatalf("kernel tier did not start: %v", err)
	}
	network, loop := "tcp6", "::1"
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil { // no IPv6 here
		network, loop = "tcp4", "127.0.0.1"
		if ln, err = net.Listen("tcp4", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	c, err := net.Dial(network, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-out:
			if ev.EventType == schema.EventTypeNetwork && ev.DstPort == port {
				if ev.PID != os.Getpid() || ev.DstIP != loop {
					t.Fatalf("connect attributed wrongly: pid %d dst %s", ev.PID, ev.DstIP)
				}
				if _, ok := kernelConnects.Load(connKey("tcp", ev.SrcPort, loop, port)); !ok {
					t.Fatal("connect not remembered for the /proc/net dedup")
				}
				return
			}
		case <-deadline:
			t.Fatal("no connect event")
		}
	}
}
