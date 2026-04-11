//go:build linux

package collector

// journald.go — Linux systemd journal reader.
//
// Equivalent to Windows EventLog (Security/System/Application channels).
// Reads from the systemd journal using the Journal Export Format
// via `journalctl --output=json --follow` subprocess.
//
// We use subprocess instead of cgo/libsystemd to keep the agent
// dependency-free and portable across distros.
//
// Monitors:
//   - Auth events: SSH logins, su/sudo, PAM (maps to event_type="logon")
//   - Kernel messages: suspicious module loads, OOM killer (event_type="raw")
//   - Syslog CRON: cron job execution (event_type="process")
//   - Audit log: if auditd is running, structured audit messages
//
// Events emitted: event_type="logon"|"process"|"raw", source="journald"

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

type JournaldCollector struct {
	cfg     JournaldConfig
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
}

type JournaldConfig struct {
	Enabled bool
}

func NewJournaldCollector(cfg JournaldConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *JournaldCollector {
	return &JournaldCollector{
		cfg:     cfg,
		out:     out,
		agentID: agentID,
		host:    host,
		logger:  logger,
	}
}

func (j *JournaldCollector) Run(ctx context.Context) error {
	if !j.cfg.Enabled {
		return nil
	}

	// Run journalctl in follow mode, output JSON, start from current cursor
	cmd := exec.CommandContext(ctx,
		"journalctl",
		"--output=json",
		"--follow",
		"--no-pager",
		"--since=now",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		j.logger.Warn("journald: journalctl not available, skipping", "err", err)
		return nil
	}

	j.logger.Info("journald: following systemd journal")

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 512*1024), 512*1024)

	for sc.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			return nil
		default:
		}

		line := sc.Text()
		if line == "" {
			continue
		}

		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		ev := j.mapEntry(entry)
		if ev == nil {
			continue
		}

		select {
		case j.out <- *ev:
		default:
			GlobalHealth.EventsDropped.Add(1)
		}
	}

	cmd.Wait()
	return nil
}

func (j *JournaldCollector) mapEntry(entry map[string]interface{}) *schema.Event {
	syslogID := getString(entry, "SYSLOG_IDENTIFIER")
	unit := getString(entry, "_SYSTEMD_UNIT")
	msg := getString(entry, "MESSAGE")
	priority := getString(entry, "PRIORITY")

	// Skip noisy low-priority messages
	if priority == "7" { // debug
		return nil
	}

	// Classify and extract fields
	eventType, sev, username, action := j.classify(syslogID, unit, msg)
	if eventType == "" {
		return nil
	}

	pid := 0
	if pidStr := getString(entry, "_PID"); pidStr != "" {
		for _, c := range pidStr {
			if c >= '0' && c <= '9' {
				pid = pid*10 + int(c-'0')
			}
		}
	}

	hostname := getString(entry, "_HOSTNAME")
	if hostname == "" {
		hostname = j.host
	}

	rawJSON, _ := json.Marshal(map[string]interface{}{
		"syslog_identifier": syslogID,
		"unit":              unit,
		"message":           msg,
		"priority":          priority,
		"action":            action,
		"pid":               pid,
		"username":          username,
		"hostname":          hostname,
	})

	ev := &schema.Event{
		Time:        j.parseTime(entry),
		AgentID:     j.agentID,
		Host:        j.host,
		OS:          "linux",
		EventType:   eventType,
		Severity:    sev,
		Source:      "journald",
		Raw:         rawJSON,
		PID:         pid,
		UserName:    username,
		ProcessName: syslogID,
		CommandLine: msg,
		Channel:     syslogID,
	}

	return ev
}

func (j *JournaldCollector) classify(syslogID, unit, msg string) (schema.EventType, schema.Severity, string, string) {
	msgLow := strings.ToLower(msg)
	id := strings.ToLower(syslogID)

	// ── SSH / authentication ────────────────────────────────────────────────
	if id == "sshd" || strings.Contains(id, "ssh") {
		user := extractSSHUser(msg)
		switch {
		case strings.Contains(msgLow, "accepted password") || strings.Contains(msgLow, "accepted publickey"):
			return schema.EventTypeLogon, schema.SeverityInfo, user, "ssh_login_success"
		case strings.Contains(msgLow, "failed password") || strings.Contains(msgLow, "authentication failure"):
			return schema.EventTypeLogon, schema.SeverityMedium, user, "ssh_login_failure"
		case strings.Contains(msgLow, "invalid user"):
			return schema.EventTypeLogon, schema.SeverityMedium, user, "ssh_invalid_user"
		case strings.Contains(msgLow, "connection closed") || strings.Contains(msgLow, "disconnected"):
			return schema.EventTypeLogon, schema.SeverityInfo, user, "ssh_logout"
		case strings.Contains(msgLow, "maximum authentication attempts"):
			return schema.EventTypeLogon, schema.SeverityHigh, user, "ssh_brute_force"
		}
		return schema.EventTypeLogon, schema.SeverityInfo, user, "ssh_event"
	}

	// ── sudo ────────────────────────────────────────────────────────────────
	if id == "sudo" {
		user := extractSudoUser(msg)
		if strings.Contains(msgLow, "authentication failure") || strings.Contains(msgLow, "incorrect password") {
			return schema.EventTypeLogon, schema.SeverityHigh, user, "sudo_failure"
		}
		return schema.EventTypeLogon, schema.SeverityMedium, user, "sudo_exec"
	}

	// ── su ──────────────────────────────────────────────────────────────────
	if id == "su" {
		user := ""
		if strings.Contains(msgLow, "successful") || strings.Contains(msgLow, "session opened") {
			return schema.EventTypeLogon, schema.SeverityMedium, user, "su_success"
		}
		return schema.EventTypeLogon, schema.SeverityMedium, user, "su_attempt"
	}

	// ── PAM ─────────────────────────────────────────────────────────────────
	if strings.HasPrefix(id, "pam") || strings.Contains(id, "login") {
		user := extractPAMUser(msg)
		if strings.Contains(msgLow, "session opened") {
			return schema.EventTypeLogon, schema.SeverityInfo, user, "pam_session_open"
		}
		if strings.Contains(msgLow, "session closed") {
			return schema.EventTypeLogon, schema.SeverityInfo, user, "pam_session_close"
		}
		if strings.Contains(msgLow, "authentication failure") {
			return schema.EventTypeLogon, schema.SeverityMedium, user, "pam_auth_failure"
		}
	}

	// ── CRON ────────────────────────────────────────────────────────────────
	if id == "cron" || id == "crond" || strings.Contains(unit, "cron") {
		user := extractCronUser(msg)
		return schema.EventTypeProcess, schema.SeverityInfo, user, "cron_exec"
	}

	// ── Kernel ──────────────────────────────────────────────────────────────
	if id == "kernel" || unit == "kernel" {
		switch {
		case strings.Contains(msgLow, "oom") || strings.Contains(msgLow, "killed process"):
			return schema.EventTypeRaw, schema.SeverityMedium, "", "kernel_oom"
		case strings.Contains(msgLow, "segfault"):
			return schema.EventTypeRaw, schema.SeverityLow, "", "kernel_segfault"
		case strings.Contains(msgLow, "module") && strings.Contains(msgLow, "load"):
			return schema.EventTypeRaw, schema.SeverityMedium, "", "kernel_module_load"
		case strings.Contains(msgLow, "rootkit") || strings.Contains(msgLow, "suspicious"):
			return schema.EventTypeRaw, schema.SeverityHigh, "", "kernel_suspicious"
		}
		return "", 0, "", ""
	}

	// ── useradd/userdel/groupadd ─────────────────────────────────────────────
	if id == "useradd" || id == "userdel" || id == "groupadd" || id == "usermod" {
		return schema.EventTypeLogon, schema.SeverityHigh, "", id + "_exec"
	}

	// ── systemd service start/stop ──────────────────────────────────────────
	if id == "systemd" && (strings.Contains(msgLow, "started") || strings.Contains(msgLow, "stopped") || strings.Contains(msgLow, "failed")) {
		return schema.EventTypeProcess, schema.SeverityInfo, "", "systemd_unit_change"
	}

	return "", 0, "", ""
}

func (j *JournaldCollector) parseTime(entry map[string]interface{}) time.Time {
	if tsStr := getString(entry, "__REALTIME_TIMESTAMP"); tsStr != "" {
		// Microseconds since epoch
		var ts int64
		for _, c := range tsStr {
			if c >= '0' && c <= '9' {
				ts = ts*10 + int64(c-'0')
			}
		}
		if ts > 0 {
			return time.Unix(ts/1_000_000, (ts%1_000_000)*1000).UTC()
		}
	}
	return time.Now().UTC()
}

// ---------------------------------------------------------------------------
// Field extraction helpers
// ---------------------------------------------------------------------------

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case string:
			return t
		}
	}
	return ""
}

func extractSSHUser(msg string) string {
	// "Accepted password for bob from 1.2.3.4"
	// "Failed password for invalid user eve from 1.2.3.4"
	parts := strings.Fields(msg)
	for i, p := range parts {
		if (p == "for") && i+1 < len(parts) {
			next := parts[i+1]
			if next != "invalid" {
				return next
			}
			if i+2 < len(parts) && parts[i+2] == "user" && i+3 < len(parts) {
				return parts[i+3]
			}
		}
	}
	return ""
}

func extractSudoUser(msg string) string {
	// "bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"
	parts := strings.Fields(msg)
	if len(parts) > 0 {
		return strings.TrimSuffix(parts[0], ":")
	}
	return ""
}

func extractPAMUser(msg string) string {
	// "pam_unix(sshd:session): session opened for user bob by (uid=0)"
	if i := strings.Index(msg, "user "); i >= 0 {
		rest := msg[i+5:]
		return strings.Fields(rest)[0]
	}
	return ""
}

func extractCronUser(msg string) string {
	// "(bob) CMD (/usr/bin/something)"
	if strings.HasPrefix(msg, "(") {
		end := strings.Index(msg, ")")
		if end > 1 {
			return msg[1:end]
		}
	}
	return ""
}
