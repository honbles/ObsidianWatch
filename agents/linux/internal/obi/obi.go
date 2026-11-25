// Package obi runs OpenTelemetry eBPF Instrumentation (OBI) for the services the
// host sensor discovered, so they get request rate, errors, latency, routes and
// traces without any change to the application.
//
// The agent starts the bundled obi binary as a child process with a generated
// configuration: instrument the ports of discovered (not already instrumented)
// services and export OTLP/HTTP to the agent's own loopback receiver. OBI
// identifies a process as "ow:<pid>" in service.instance.id; the receiver asks
// this runner (Rewrite) to turn that into the discovered service and its
// process, so the telemetry joins the service the sensor already knows and is
// bound to the real process, not to OBI.
package obi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/linux-agent/internal/otel"
)

// instancePrefix is the host name OBI is told to use, so service.instance.id is
// "ow:<pid>" whatever the machine is called.
const instancePrefix = "ow"

type Options struct {
	Path         string        // obi binary
	StateDir     string        // where the generated configuration is written
	OTLPEndpoint string        // the agent's receiver, e.g. http://127.0.0.1:4318
	MinRestart   time.Duration // shortest time between configuration-driven restarts (default 10m)
	// Instrumented returns pids that already send OpenTelemetry. Pids whose
	// telemetry came through OBI are not counted as instrumented by an SDK.
	Instrumented func() []int
	Logger       *slog.Logger
}

type Runner struct {
	opt Options

	mu       sync.Mutex
	byPID    map[int]otel.BatchInstance // discovered instances by pid
	viaOBI   map[int]time.Time          // pids whose telemetry came through OBI
	ports    []int                      // ports in the running configuration
	want     []int                      // ports the next configuration should have
	childPID int
	childExe string
	status   string
	kick     chan struct{}
}

func New(opt Options) *Runner {
	if opt.MinRestart <= 0 {
		opt.MinRestart = 10 * time.Minute
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	return &Runner{opt: opt, byPID: map[int]otel.BatchInstance{}, viaOBI: map[int]time.Time{}, kick: make(chan struct{}, 1), status: "starting"}
}

// Available reports whether the obi binary is installed.
func Available(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}

// Update receives the sensor's discovered instances (every discovery round).
func (r *Runner) Update(list []otel.BatchInstance) {
	sdk := map[int]bool{}
	if r.opt.Instrumented != nil {
		for _, p := range r.opt.Instrumented() {
			sdk[p] = true
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	byPID := map[int]otel.BatchInstance{}
	portSet := map[int]bool{}
	for _, in := range list {
		if in.PID <= 0 || in.Service == "" {
			continue
		}
		byPID[in.PID] = in
		// a process instrumented with an SDK is left alone: OBI would count its requests twice
		if sdk[in.PID] {
			if _, ours := r.viaOBI[in.PID]; !ours {
				continue
			}
		}
		for _, p := range ListenPorts(in.Listen) {
			portSet[p] = true
		}
	}
	r.byPID = byPID
	want := make([]int, 0, len(portSet))
	for p := range portSet {
		want = append(want, p)
	}
	sort.Ints(want)
	changed := !equalInts(want, r.want)
	r.want = want
	for p, t := range r.viaOBI {
		if _, ok := byPID[p]; !ok && time.Since(t) > time.Hour {
			delete(r.viaOBI, p)
		}
	}
	if changed {
		select {
		case r.kick <- struct{}{}:
		default:
		}
	}
}

// Rewrite implements otel.ProxyRewriter.
func (r *Runner) Rewrite(sender otel.Peer, res otel.Resource) (otel.Peer, otel.Resource, bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.childPID == 0 || !sender.Resolved || sender.PID != r.childPID || (r.childExe != "" && sender.Exe != "" && sender.Exe != r.childExe) {
		return sender, res, false, true
	}
	pid := instancePID(res.InstanceRef)
	in, ok := r.byPID[pid]
	if !ok {
		return sender, res, true, false // OBI's own telemetry, or a process the sensor does not know
	}
	r.viaOBI[pid] = time.Now()
	out := res
	out.Service, out.Environment = in.Service, in.Environment
	out.InstanceRef = ""
	out.SDK = strings.TrimSpace("ebpf " + res.SDK)
	if out.Language == "" {
		out.Language = in.Language
	}
	if out.VCSRevision == "" {
		out.VCSRevision, out.VCSRepo, out.VCSBranch, out.VCSSource = in.VCSRevision, in.VCSRepo, in.VCSBranch, in.VCSSource
	}
	p := otel.Peer{Resolved: true, PID: in.PID, ProcStart: in.ProcStart, ContainerID: in.ContainerID, Exe: in.Exe}
	return p, out, true, true
}

// instancePID reads the pid from "ow:<pid>".
func instancePID(ref string) int {
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return 0
	}
	n, err := strconv.Atoi(ref[i+1:])
	if err != nil {
		return 0
	}
	return n
}

// Status is a one-word state for the agent's health report.
func (r *Runner) Status() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// Run supervises the obi process until ctx ends: it (re)starts it with the
// current ports, restarts it when the ports change (not more often than
// MinRestart) and after a crash (with backoff).
func (r *Runner) Run(ctx context.Context) error {
	exe, err := filepath.EvalSymlinks(r.opt.Path)
	if err != nil {
		r.setStatus("not installed")
		return fmt.Errorf("obi binary: %w", err)
	}
	if err := os.MkdirAll(r.opt.StateDir, 0o700); err != nil {
		return err
	}
	backoff := 10 * time.Second
	var lastStart time.Time
	for {
		// wait until there is something to instrument
		r.mu.Lock()
		want := append([]int(nil), r.want...)
		r.mu.Unlock()
		if len(want) == 0 {
			r.setStatus("idle")
			select {
			case <-ctx.Done():
				return nil
			case <-r.kick:
				continue
			case <-time.After(time.Minute):
				continue
			}
		}
		if wait := r.opt.MinRestart - time.Since(lastStart); !lastStart.IsZero() && wait > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
			continue
		}
		cfgPath := filepath.Join(r.opt.StateDir, "obi.yaml")
		if err := os.WriteFile(cfgPath, []byte(Config(want, r.opt.OTLPEndpoint)), 0o600); err != nil {
			return err
		}
		cctx, cancel := context.WithCancel(ctx)
		cmd := exec.CommandContext(cctx, exe, "-config", cfgPath)
		cmd.Env = childEnv()
		logf, _ := os.OpenFile(filepath.Join(r.opt.StateDir, "obi.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if logf != nil {
			cmd.Stdout, cmd.Stderr = logf, logf
		}
		lastStart = time.Now()
		if err := cmd.Start(); err != nil {
			cancel()
			if logf != nil {
				logf.Close()
			}
			r.setStatus("failed to start")
			r.opt.Logger.Warn("request tracing (OBI) could not start", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = minDur(backoff*2, 30*time.Minute)
			continue
		}
		r.mu.Lock()
		r.childPID, r.childExe, r.ports, r.status = cmd.Process.Pid, exe, want, "running"
		r.mu.Unlock()
		r.opt.Logger.Info("request tracing (OBI) running", "pid", cmd.Process.Pid, "ports", want)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		restart := false
	wait:
		for {
			select {
			case <-ctx.Done():
				cancel()
				<-done
				break wait
			case err := <-done:
				r.opt.Logger.Warn("request tracing (OBI) exited; restarting with backoff", "err", err,
					"log", filepath.Join(r.opt.StateDir, "obi.log"))
				r.setStatus("restarting")
				break wait
			case <-r.kick:
				r.mu.Lock()
				changed := !equalInts(r.want, r.ports)
				r.mu.Unlock()
				if changed {
					restart = true
					cancel()
					<-done
					break wait
				}
			}
		}
		cancel()
		if logf != nil {
			logf.Close()
		}
		r.mu.Lock()
		r.childPID, r.childExe = 0, ""
		r.mu.Unlock()
		if ctx.Err() != nil {
			return nil
		}
		if !restart {
			if time.Since(lastStart) > 10*time.Minute {
				backoff = 10 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = minDur(backoff*2, 30*time.Minute)
			lastStart = time.Time{}
		}
	}
}

func (r *Runner) setStatus(s string) {
	r.mu.Lock()
	r.status = s
	r.mu.Unlock()
}

// Config renders the OBI configuration (OBI config v1 keys): instrument these
// ports, name instances "ow:<pid>", template routes, send traces to the agent.
// Metrics are not exported: the agent derives request statistics from spans.
func Config(ports []int, endpoint string) string {
	ps := make([]string, len(ports))
	for i, p := range ports {
		ps[i] = strconv.Itoa(p)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by the ObsidianWatch agent. Changes are overwritten.\n")
	fmt.Fprintf(&b, "log_level: warn\n")
	fmt.Fprintf(&b, "discovery:\n  instrument:\n    - open_ports: %q\n", strings.Join(ps, ","))
	fmt.Fprintf(&b, "attributes:\n  instance_id:\n    dns: false\n    override_hostname: %q\n", instancePrefix)
	fmt.Fprintf(&b, "routes:\n  unmatched: heuristic\n")
	// A signal-specific endpoint is used as given, so the path is included.
	fmt.Fprintf(&b, "otel_traces_export:\n  endpoint: %q\n  protocol: http/protobuf\n", strings.TrimRight(endpoint, "/")+"/v1/traces")
	return b.String()
}

// childEnv is the environment of the obi process: no proxies, no Docker API
// (instance ids must stay "ow:<pid>"), and nothing else from the agent.
func childEnv() []string {
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "DOCKER_HOST=unix:///nonexistent/obsidianwatch-no-docker.sock"}
	if h := os.Getenv("HOME"); h != "" {
		env = append(env, "HOME="+h)
	}
	return env
}

// ListenPorts reads a listen array of numbers or "addr:port" strings.
func ListenPorts(raw []byte) []int {
	s := strings.Trim(strings.TrimSpace(string(raw)), "[]")
	if s == "" {
		return nil
	}
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.Trim(strings.TrimSpace(f), `"`)
		if i := strings.LastIndex(f, ":"); i >= 0 {
			f = f[i+1:]
		}
		if n, err := strconv.Atoi(f); err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}

// ConfigHash identifies a configuration (for logs and tests).
func ConfigHash(ports []int, endpoint string) string {
	h := sha256.Sum256([]byte(Config(ports, endpoint)))
	return hex.EncodeToString(h[:6])
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
