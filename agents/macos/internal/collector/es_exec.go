//go:build darwin

package collector

// es_exec.go — near-real-time process exec events via `eslogger` (A-01 interim).
//
// The sysctl poller (process.go) misses processes that start and exit between
// polls. On macOS 13+ Apple ships /usr/bin/eslogger, a CLI front end to the
// Endpoint Security framework that needs no entitlement of our own: run as
// root with Full Disk Access it streams every exec as JSON. This collector
// runs it and, while it is healthy, the poller stops emitting "new process"
// events so each exec is reported once. If eslogger is missing, denied (no Full
// Disk Access) or keeps crashing, collection falls back to the poller.
//
// The proper fix remains an Endpoint Security system extension (A-01); this is
// the interim path. Unverified on real hardware in CI: only the parser is
// unit-tested.
//
// Events emitted: event_type="process", source="eslogger"

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
)

const esloggerPath = "/usr/bin/eslogger"

// esExecActive is true while eslogger is streaming; process.go consults it.
var esExecActive atomic.Bool

type ESExecCollector struct {
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
}

func NewESExecCollector(agentID, host string, out chan<- schema.Event, logger *slog.Logger) *ESExecCollector {
	return &ESExecCollector{out: out, agentID: agentID, host: host, logger: logger}
}

func (c *ESExecCollector) Run(ctx context.Context) {
	if _, err := os.Stat(esloggerPath); err != nil {
		c.logger.Info("eslogger: not present (needs macOS 13+); using process polling only")
		return
	}
	quickFailures := 0
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		started := time.Now()
		c.runOnce(ctx)
		esExecActive.Store(false)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) < 30*time.Second {
			quickFailures++
		} else {
			quickFailures = 0
			backoff = 2 * time.Second
		}
		if quickFailures >= 3 {
			c.logger.Warn("eslogger: keeps exiting immediately (grant the agent Full Disk Access); staying on process polling")
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func (c *ESExecCollector) runOnce(ctx context.Context) {
	cmd := exec.CommandContext(ctx, esloggerPath, "exec")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		c.logger.Warn("eslogger: start failed", "err", err)
		return
	}
	esExecActive.Store(true)
	c.logger.Info("eslogger: streaming exec events")

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20) // exec records with large environments/args
	for sc.Scan() {
		ev, err := parseESExec(sc.Bytes())
		if err != nil {
			continue
		}
		c.emit(ev)
	}
	if err := sc.Err(); err != nil {
		c.logger.Warn("eslogger: read error", "err", err)
		cmd.Process.Kill()
	}
	cmd.Wait()
}

func (c *ESExecCollector) emit(e esExecEvent) {
	username := uidToUsername(e.UID)
	name := e.Exe
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	cmdline := strings.Join(e.Args, " ")
	sha := hashFileCached(e.Exe)
	detail := map[string]interface{}{
		"pid": e.PID, "ppid": e.PPID, "name": name, "cmdline": cmdline,
		"username": username, "uid": e.UID, "exe": e.Exe,
		"process_guid": fmt.Sprintf("%d-%d", e.PID, e.Time.UnixMicro()),
	}
	if sha != "" {
		detail["sha256"] = sha
	}
	raw, _ := json.Marshal(detail)
	ev := schema.Event{
		ImagePath: e.Exe, FileHash: sha,
		AgentID: c.agentID, Host: c.host, OS: "darwin",
		EventType: "process", Source: "eslogger", Severity: 1,
		Time: e.Time, PID: e.PID, PPID: e.PPID,
		ProcessName: name, CommandLine: cmdline, UserName: username, Raw: raw,
	}
	select {
	case c.out <- ev:
	default:
		GlobalHealth.EventsDropped.Add(1)
	}
}
