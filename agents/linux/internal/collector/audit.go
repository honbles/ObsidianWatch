//go:build linux

package collector

// audit.go — Linux audit log collector.
//
// Tails /var/log/audit/audit.log and parses auditd records.
// This is the equivalent of the Windows Security event log (4624, 4625, 4688 etc).
//
// Parsed record types:
//   EXECVE    → process create (command line)
//   SYSCALL   → combined with EXECVE, gives PID/PPID/UID/exe
//   USER_AUTH / USER_LOGIN / USER_LOGOUT → logon events
//   USER_CMD  → sudo command execution
//   ADD_USER / DEL_USER / ADD_GROUP → user management
//   ANOM_ABEND → abnormal process termination (crash/signal)
//   NETFILTER_PKT → network (if netfilter auditing enabled)
//
// Auditd records come in "message groups" sharing a timestamp.serial.
// We collect them and emit once we see a record from a new timestamp.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

type AuditCollector struct {
	logPath  string
	agentID  string
	hostname string
	out      chan<- schema.Event
	logger   *slog.Logger
}

func NewAuditCollector(logPath, agentID, hostname string, out chan<- schema.Event, logger *slog.Logger) *AuditCollector {
	if logPath == "" {
		logPath = "/var/log/audit/audit.log"
	}
	return &AuditCollector{logPath: logPath, agentID: agentID, hostname: hostname, out: out, logger: logger}
}

func (c *AuditCollector) Run(ctx context.Context) error {
	// Check if audit log exists
	if _, err := os.Stat(c.logPath); os.IsNotExist(err) {
		c.logger.Warn("audit: log file not found, collector disabled", "path", c.logPath)
		c.logger.Warn("audit: install auditd: apt install auditd / yum install audit")
		// Block until ctx done rather than returning an error that restarts the goroutine
		<-ctx.Done()
		return nil
	}

	f, err := os.Open(c.logPath)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", c.logPath, err)
	}
	defer f.Close()

	// Seek to end — only process new entries
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("audit: seek: %w", err)
	}

	c.logger.Info("audit: tailing audit log", "path", c.logPath)

	// Group of records sharing the same audit serial
	type auditGroup struct {
		serial  string
		ts      time.Time
		records []auditRecord
	}

	current := auditGroup{}
	reader := bufio.NewReader(f)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// No new data — wait and retry
				time.Sleep(200 * time.Millisecond)

				// Check for log rotation
				if fi, err2 := os.Stat(c.logPath); err2 == nil {
					if curFi, err3 := f.Stat(); err3 == nil {
						if !os.SameFile(fi, curFi) {
							c.logger.Info("audit: log rotated, reopening")
							f.Close()
							if f, err = os.Open(c.logPath); err != nil {
								return fmt.Errorf("audit: reopen: %w", err)
							}
							reader = bufio.NewReader(f)
						}
					}
				}
				continue
			}
			return fmt.Errorf("audit: read: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		rec, ok := parseAuditLine(line)
		if !ok {
			continue
		}

		// Group records by serial
		if rec.Serial != current.serial {
			// Emit the previous group
			if current.serial != "" {
				c.emitGroup(current.records)
			}
			current = auditGroup{
				serial:  rec.Serial,
				ts:      rec.Time,
				records: []auditRecord{rec},
			}
		} else {
			current.records = append(current.records, rec)
		}
	}
}

type auditRecord struct {
	Type   string
	Time   time.Time
	Serial string
	Fields map[string]string
}

// parseAuditLine parses a line like:
// type=SYSCALL msg=audit(1741234567.123:456): arch=c000003e syscall=59 ...
func parseAuditLine(line string) (auditRecord, bool) {
	rec := auditRecord{Fields: make(map[string]string)}

	// Extract type
	if !strings.HasPrefix(line, "type=") {
		return rec, false
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return rec, false
	}
	rec.Type = strings.TrimPrefix(parts[0], "type=")

	// Extract timestamp and serial from msg=audit(ts.ms:serial):
	msgPart := parts[1]
	if strings.HasPrefix(msgPart, "msg=audit(") {
		inner := strings.TrimPrefix(msgPart, "msg=audit(")
		inner = strings.TrimSuffix(inner, "):")
		tsParts := strings.SplitN(inner, ":", 2)
		if len(tsParts) == 2 {
			rec.Serial = tsParts[1]
			if tsF, err := strconv.ParseFloat(tsParts[0], 64); err == nil {
				sec := int64(tsF)
				nsec := int64((tsF - float64(sec)) * 1e9)
				rec.Time = time.Unix(sec, nsec).UTC()
			}
		}
	}
	if rec.Time.IsZero() {
		rec.Time = time.Now().UTC()
	}

	// Parse remaining key=value pairs
	if len(parts) >= 3 {
		remainder := parts[2]
		for _, kv := range splitAuditKV(remainder) {
			if idx := strings.IndexByte(kv, '='); idx > 0 {
				k := kv[:idx]
				v := strings.Trim(kv[idx+1:], "\"")
				rec.Fields[k] = v
			}
		}
	}

	return rec, rec.Type != ""
}

// splitAuditKV splits "key=val key2=val2" handling quoted values.
func splitAuditKV(s string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '"' {
			inQuote = !inQuote
			cur.WriteByte(ch)
		} else if ch == ' ' && !inQuote {
			if cur.Len() > 0 {
				parts = append(parts, cur.String())
				cur.Reset()
			}
		} else {
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}

func (c *AuditCollector) emitGroup(records []auditRecord) {
	if len(records) == 0 {
		return
	}

	// Merge all fields from the group
	merged := make(map[string]string)
	recType := records[0].Type
	ts := records[0].Time

	// Look for SYSCALL record to get the best metadata
	for _, r := range records {
		if r.Type == "SYSCALL" {
			recType = "SYSCALL"
			ts = r.Time
		}
		for k, v := range r.Fields {
			if _, exists := merged[k]; !exists {
				merged[k] = v
			}
		}
	}

	// Collect all record types in group
	typeSet := make(map[string]bool)
	for _, r := range records {
		typeSet[r.Type] = true
	}

	switch {
	case typeSet["EXECVE"] || typeSet["SYSCALL"] && merged["syscall"] == "59":
		c.emitExecve(ts, merged)
	case typeSet["USER_AUTH"] || typeSet["USER_LOGIN"] || typeSet["USER_LOGOUT"]:
		c.emitLogon(ts, recType, merged)
	case typeSet["USER_CMD"]:
		c.emitSudo(ts, merged)
	case typeSet["ADD_USER"] || typeSet["DEL_USER"] || typeSet["ADD_GROUP"] || typeSet["DEL_GROUP"]:
		c.emitUserMgmt(ts, recType, merged)
	case typeSet["ANOM_ABEND"]:
		c.emitAnom(ts, merged)
	}
}

func (c *AuditCollector) emitExecve(ts time.Time, fields map[string]string) {
	pid, _ := strconv.Atoi(fields["pid"])
	ppid, _ := strconv.Atoi(fields["ppid"])
	exe := unquoteAudit(fields["exe"])
	if exe == "" {
		exe = fields["comm"]
	}
	name := filepath.Base(exe)

	// Build cmdline from a0, a1, a2... fields
	var args []string
	for i := 0; ; i++ {
		arg, ok := fields[fmt.Sprintf("a%d", i)]
		if !ok {
			break
		}
		args = append(args, unquoteAudit(arg))
	}
	cmdline := strings.Join(args, " ")

	uid := fields["uid"]
	username := resolveUID(atoiSafe(uid))

	sev := schema.SeverityInfo
	if isInterpreter(strings.ToLower(name)) {
		sev = schema.SeverityLow
	}
	if strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/dev/shm/") {
		sev = schema.SeverityHigh
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"source":   "audit",
		"type":     "EXECVE",
		"exe":      exe,
		"cmdline":  cmdline,
		"pid":      pid,
		"ppid":     ppid,
		"uid":      uid,
		"username": username,
		"fields":   fields,
	})

	ev := schema.Event{
		ID:          newID(),
		Time:        ts,
		AgentID:     c.agentID,
		Host:        c.hostname,
		OS:          "linux",
		EventType:   schema.EventTypeProcess,
		Severity:    sev,
		Source:      "auditd",
		Raw:         raw,
		PID:         pid,
		PPID:        ppid,
		ProcessName: name,
		CommandLine: cmdline,
		ImagePath:   exe,
		UserName:    username,
	}
	select {
	case c.out <- ev:
	default:
	}
}

func (c *AuditCollector) emitLogon(ts time.Time, recType string, fields map[string]string) {
	uid := fields["uid"]
	username := unquoteAudit(fields["acct"])
	if username == "" {
		username = resolveUID(atoiSafe(uid))
	}

	action := "logon"
	switch recType {
	case "USER_LOGOUT":
		action = "logoff"
	case "USER_AUTH":
		action = "auth"
		if fields["res"] == "failed" {
			action = "auth_failed"
		}
	}

	sev := schema.SeverityInfo
	if action == "auth_failed" {
		sev = schema.SeverityMedium
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"source":   "audit",
		"type":     recType,
		"action":   action,
		"uid":      uid,
		"username": username,
		"terminal": fields["terminal"],
		"addr":     fields["addr"],
		"hostname": fields["hostname"],
		"res":      fields["res"],
	})

	pid, _ := strconv.Atoi(fields["pid"])
	ev := schema.Event{
		ID:        newID(),
		Time:      ts,
		AgentID:   c.agentID,
		Host:      c.hostname,
		OS:        "linux",
		EventType: schema.EventTypeLogon,
		Severity:  sev,
		Source:    "auditd",
		Raw:       raw,
		PID:       pid,
		UserName:  username,
	}
	select {
	case c.out <- ev:
	default:
	}
}

func (c *AuditCollector) emitSudo(ts time.Time, fields map[string]string) {
	username := unquoteAudit(fields["acct"])
	cmd := unquoteAudit(fields["cmd"])

	sev := schema.SeverityMedium
	if fields["res"] == "failed" {
		sev = schema.SeverityHigh
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"source":   "audit",
		"type":     "USER_CMD",
		"username": username,
		"cmd":      cmd,
		"terminal": fields["terminal"],
		"res":      fields["res"],
	})

	pid, _ := strconv.Atoi(fields["pid"])
	ev := schema.Event{
		ID:          newID(),
		Time:        ts,
		AgentID:     c.agentID,
		Host:        c.hostname,
		OS:          "linux",
		EventType:   schema.EventTypeProcess,
		Severity:    sev,
		Source:      "auditd",
		Raw:         raw,
		PID:         pid,
		ProcessName: "sudo",
		CommandLine: cmd,
		UserName:    username,
	}
	select {
	case c.out <- ev:
	default:
	}
}

func (c *AuditCollector) emitUserMgmt(ts time.Time, recType string, fields map[string]string) {
	username := unquoteAudit(fields["acct"])

	raw, _ := json.Marshal(map[string]interface{}{
		"source":   "audit",
		"type":     recType,
		"username": username,
		"uid":      fields["uid"],
		"fields":   fields,
	})

	ev := schema.Event{
		ID:        newID(),
		Time:      ts,
		AgentID:   c.agentID,
		Host:      c.hostname,
		OS:        "linux",
		EventType: schema.EventTypeLogon,
		Severity:  schema.SeverityHigh,
		Source:    "auditd",
		Raw:       raw,
		UserName:  username,
	}
	select {
	case c.out <- ev:
	default:
	}
}

func (c *AuditCollector) emitAnom(ts time.Time, fields map[string]string) {
	pid, _ := strconv.Atoi(fields["pid"])
	exe := unquoteAudit(fields["exe"])
	name := filepath.Base(exe)

	raw, _ := json.Marshal(map[string]interface{}{
		"source": "audit",
		"type":   "ANOM_ABEND",
		"exe":    exe,
		"signal": fields["sig"],
		"pid":    pid,
	})

	ev := schema.Event{
		ID:          newID(),
		Time:        ts,
		AgentID:     c.agentID,
		Host:        c.hostname,
		OS:          "linux",
		EventType:   schema.EventTypeProcess,
		Severity:    schema.SeverityMedium,
		Source:      "auditd",
		Raw:         raw,
		PID:         pid,
		ProcessName: name,
		ImagePath:   exe,
	}
	select {
	case c.out <- ev:
	default:
	}
}

// unquoteAudit strips hex encoding like 2F62696E2F6261736820 → /bin/bash
// or quoted strings like "bash". Audit hex-encodes strings containing spaces.
func unquoteAudit(s string) string {
	if s == "" || s == "(null)" {
		return ""
	}
	// If it's a hex string (all hex chars, even length, no quotes)
	if len(s)%2 == 0 && isHexString(s) && len(s) > 2 {
		if decoded, err := hexDecodeString(s); err == nil {
			return decoded
		}
	}
	return strings.Trim(s, "\"")
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func hexDecodeString(s string) (string, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		val, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return "", err
		}
		b[i/2] = byte(val)
	}
	return string(b), nil
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
