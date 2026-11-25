package obi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"obsidianwatch/linux-agent/internal/otel"
)

func TestConfigAndPorts(t *testing.T) {
	c := Config([]int{8080, 9090}, "http://127.0.0.1:4318")
	for _, want := range []string{`open_ports: "8080,9090"`, `override_hostname: "ow"`, `endpoint: "http://127.0.0.1:4318/v1/traces"`, "unmatched: heuristic", "protocol: http/protobuf"} {
		if !strings.Contains(c, want) {
			t.Fatalf("config misses %q:\n%s", want, c)
		}
	}
	if got := ListenPorts([]byte(`[8080,"0.0.0.0:9090","[::]:443"]`)); len(got) != 3 || got[1] != 9090 || got[2] != 443 {
		t.Fatalf("ports %v", got)
	}
	if instancePID("ow:1234") != 1234 || instancePID("host") != 0 {
		t.Fatal("instance pid")
	}
}

func TestRewriteAndSDKExclusion(t *testing.T) {
	sdk := []int{20}
	r := New(Options{Instrumented: func() []int { return sdk }})
	start := time.Unix(100, 0)
	r.Update([]otel.BatchInstance{
		{Service: "orders", Environment: "prod", PID: 10, ProcStart: start, Exe: "/usr/bin/java", Listen: []byte(`[8080]`), VCSRevision: "abcdef1234567"},
		{Service: "billing", Environment: "prod", PID: 20, Listen: []byte(`[9090]`)}, // has its own SDK
	})
	if len(r.want) != 1 || r.want[0] != 8080 {
		t.Fatalf("ports to instrument: %v", r.want)
	}
	// not from OBI: untouched
	if _, _, handled, _ := r.Rewrite(otel.Peer{Resolved: true, PID: 55}, otel.Resource{}); handled {
		t.Fatal("other senders must pass through")
	}
	r.childPID, r.childExe = 99, "/usr/local/lib/obsidianwatch/obi"
	p, res, handled, keep := r.Rewrite(otel.Peer{Resolved: true, PID: 99, Exe: "/usr/local/lib/obsidianwatch/obi"},
		otel.Resource{Service: "java", InstanceRef: "ow:10", SDK: "opentelemetry-ebpf-instrumentation"})
	if !handled || !keep || res.Service != "orders" || res.Environment != "prod" || p.PID != 10 || !p.ProcStart.Equal(start) ||
		res.VCSRevision != "abcdef1234567" || !strings.HasPrefix(res.SDK, "ebpf") {
		t.Fatalf("rewrite: %+v %+v %v %v", p, res, handled, keep)
	}
	// unknown pid from OBI: dropped
	if _, _, handled, keep := r.Rewrite(otel.Peer{Resolved: true, PID: 99}, otel.Resource{InstanceRef: "ow:77"}); !handled || keep {
		t.Fatal("unknown process must be dropped")
	}
	// once OBI data arrived for pid 10, it stays instrumented by OBI even though it is now an otel pid
	sdk = []int{10, 20}
	r.Update([]otel.BatchInstance{{Service: "orders", Environment: "prod", PID: 10, Listen: []byte(`[8080]`)}, {Service: "billing", PID: 20, Listen: []byte(`[9090]`)}})
	if len(r.want) != 1 || r.want[0] != 8080 {
		t.Fatalf("ports after OBI data: %v", r.want)
	}
}

// The runner starts the binary with the generated configuration and restarts
// it when the ports change.
func TestRunnerSupervises(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "obi")
	script := "#!/bin/sh\ncp \"$2\" \"" + filepath.Join(dir, "seen-") + "$$.yaml\"\nexec sleep 30\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if !Available(bin) || Available(filepath.Join(dir, "none")) {
		t.Fatal("available")
	}
	r := New(Options{Path: bin, StateDir: filepath.Join(dir, "state"), OTLPEndpoint: "http://127.0.0.1:4318", MinRestart: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = r.Run(ctx); close(done) }()
	r.Update([]otel.BatchInstance{{Service: "a", PID: 1, Listen: []byte(`[8080]`)}})
	waitFor(t, func() bool { return len(seen(dir)) == 1 })
	if r.Status() != "running" {
		t.Fatalf("status %s", r.Status())
	}
	r.Update([]otel.BatchInstance{{Service: "a", PID: 1, Listen: []byte(`[8080]`)}, {Service: "b", PID: 2, Listen: []byte(`[9090]`)}})
	waitFor(t, func() bool { return len(seen(dir)) == 2 })
	files := seen(dir)
	var last string
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), `"8080,9090"`) {
			last = f
		}
	}
	if last == "" {
		t.Fatalf("no restart with the new ports: %v", files)
	}
	cancel()
	<-done
}

func seen(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "seen-*.yaml"))
	return m
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out")
}
