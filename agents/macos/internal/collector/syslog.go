//go:build darwin

package collector

// syslog.go — macOS system log monitoring via `log stream`.
//
// Replaces Linux journald collector.
// Uses the macOS `log` command to stream Unified Logging System (ULS) events.
// Captures: authentication, SSH, sudo, kernel security, launchd, and app crashes.
//
// Key predicates monitored:
//   - subsystem:com.apple.securityd       — auth, keychain, SecureToken
//   - subsystem:com.apple.OpenSSH         — SSH login/logout
//   - category:authorization              — sudo, privilege escalation
//   - process:sudo                        — sudo commands
//   - subsystem:com.apple.launchd         — service start/stop
//   - eventMessage contains "authentication" OR "failed" OR "denied"
//
// Events emitted: event_type="syslog", source="log-stream"

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
)

type SyslogConfig struct {
	Enabled bool
}

type SyslogCollector struct {
	cfg     SyslogConfig
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
}

func NewSyslogCollector(cfg SyslogConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *SyslogCollector {
	return &SyslogCollector{cfg: cfg, out: out, agentID: agentID, host: host, logger: logger}
}

// Run keeps `log stream` alive. The subprocess can exit (logd restart, memory
// pressure) or its pipe can break on an over-long line; without a restart that
// ended auth/sudo/ssh visibility until the agent itself restarted.
func (c *SyslogCollector) Run(ctx context.Context) {
	if !c.cfg.Enabled {
		return
	}
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		started := time.Now()
		if !c.runOnce(ctx) {
			return // could not start `log` at all
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > 30*time.Second {
			backoff = 2 * time.Second
		}
		c.logger.Warn("syslog: log stream ended, restarting", "after", backoff)
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

// runOnce runs one `log stream` process to completion. It returns false only
// when the process could not be started.
func (c *SyslogCollector) runOnce(ctx context.Context) bool {

	// log stream --style json --predicate filters for security-relevant events
	predicate := strings.Join([]string{
		`subsystem == "com.apple.securityd"`,
		`subsystem == "com.apple.OpenSSH"`,
		`subsystem == "com.apple.launchd"`,
		`process == "sudo"`,
		`process == "sshd"`,
		`process == "loginwindow"`,
		`process == "SecurityAgent"`,
		`eventMessage CONTAINS[c] "authentication"`,
		`eventMessage CONTAINS[c] "authorization"`,
		`eventMessage CONTAINS[c] "failed password"`,
		`eventMessage CONTAINS[c] "accepted password"`,
		`eventMessage CONTAINS[c] "invalid user"`,
		`eventMessage CONTAINS[c] "session opened"`,
		`eventMessage CONTAINS[c] "session closed"`,
		`eventMessage CONTAINS[c] "sudo"`,
	}, " OR ")

	args := []string{"stream", "--style", "ndjson", "--predicate", predicate}
	cmd := exec.CommandContext(ctx, "log", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.logger.Error("syslog: pipe failed", "err", err)
		return false
	}
	if err := cmd.Start(); err != nil {
		c.logger.Error("syslog: log stream start failed", "err", err)
		return false
	}

	c.logger.Info("syslog: log stream started")
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			cmd.Wait()
			return true
		default:
		}
		line := scanner.Text()
		if line == "" {
			continue
		}
		c.parseLine(line)
	}
	if err := scanner.Err(); err != nil {
		c.logger.Warn("syslog: read error", "err", err)
		cmd.Process.Kill()
	}
	cmd.Wait()
	return true
}

// logEntry is a minimal subset of the macOS ndjson log format
type logEntry struct {
	Timestamp   string `json:"timestamp"`
	ProcessID   int    `json:"processID"`
	Process     string `json:"process"`
	Subsystem   string `json:"subsystem"`
	Category    string `json:"category"`
	EventMessage string `json:"eventMessage"`
	MessageType string `json:"messageType"`
}

func (c *SyslogCollector) parseLine(line string) {
	var entry logEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return
	}

	msg := entry.EventMessage
	if msg == "" {
		return
	}

	severity := classifySeverity(msg, entry.MessageType)

	detail := map[string]interface{}{
		"timestamp":  entry.Timestamp,
		"pid":        entry.ProcessID,
		"process":    entry.Process,
		"subsystem":  entry.Subsystem,
		"category":   entry.Category,
		"message":    msg,
		"level":      entry.MessageType,
	}
	raw, _ := json.Marshal(detail)

	c.out <- schema.Event{
		AgentID:   c.agentID,
		Host:      c.host,
		EventType: "syslog",
		Source:    "log-stream",
		Severity:  severity,
		Raw:       raw,
		Time:      time.Now().UTC(),
	}
}

func classifySeverity(msg, level string) schema.Severity {
	msgLower := strings.ToLower(msg)
	switch {
	case strings.Contains(msgLower, "failed") ||
		strings.Contains(msgLower, "denied") ||
		strings.Contains(msgLower, "invalid") ||
		strings.Contains(msgLower, "error") ||
		level == "Fault" || level == "Error":
		return 3
	case strings.Contains(msgLower, "sudo") ||
		strings.Contains(msgLower, "authentication") ||
		strings.Contains(msgLower, "session opened"):
		return 2
	default:
		return 1
	}
}
