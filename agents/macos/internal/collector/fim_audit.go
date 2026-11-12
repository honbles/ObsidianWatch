//go:build darwin

package collector

// fim_audit.go — macOS file activity with PID via OpenBSM audit trail.
//
// /dev/auditpipe is a kernel facility that streams BSM audit records
// including file operations with full PID attribution. This is the
// correct way to get "which process wrote this file" on macOS.
//
// Falls back to kqueue FIM (fim.go) if auditpipe is unavailable.
//
// Audit record types we care about:
//   AUE_OPEN_RWT / AUE_OPEN_WT / AUE_OPEN_WTC — file open for write
//   AUE_CREAT                                  — file create
//   AUE_UNLINK / AUE_RMDIR                    — file delete
//   AUE_RENAME                                 — file rename
//   AUE_TRUNCATE                               — file truncate

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
)

// BSM token types
const (
	auTokenHeader32   = 0x14
	auTokenHeader32Ex = 0x15
	auTokenSubject32  = 0x24
	auTokenPath       = 0x23
	auTokenReturn32   = 0x52
	auTokenText       = 0x28
)

// BSM event types for file operations
const (
	aueOpen     = 0x0006
	aueCreat    = 0x0008
	aueUnlink   = 0x000a
	aueRename   = 0x001c
	aueTruncate = 0x0030
	aueOpenRWT  = 0x0077
	aueOpenWT   = 0x0078
	aueOpenWTC  = 0x0079
	aueRmdir    = 0x00a7
	aueMkdir    = 0x0061
	aueLink     = 0x0009
	aueSymlink  = 0x0039
)

var auditFileEvents = map[uint16]string{
	aueOpen:     "open",
	aueCreat:    "create",
	aueUnlink:   "delete",
	aueRename:   "rename",
	aueTruncate: "modify",
	aueOpenRWT:  "write",
	aueOpenWT:   "write",
	aueOpenWTC:  "create",
	aueRmdir:    "delete",
	aueMkdir:    "create",
	aueLink:     "link",
	aueSymlink:  "symlink",
}

// AuditFIMCollector reads from /dev/auditpipe for PID-attributed file events.
type AuditFIMCollector struct {
	cfg     FIMCollectorConfig
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
}

func NewAuditFIMCollector(cfg FIMCollectorConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *AuditFIMCollector {
	return &AuditFIMCollector{
		cfg:     cfg,
		out:     out,
		agentID: agentID,
		host:    host,
		logger:  logger,
	}
}

// Run tries auditpipe first, falls back to kqueue FIM.
func (a *AuditFIMCollector) Run(ctx context.Context) {
	if !a.cfg.Enabled {
		return
	}

	if err := a.runAuditPipe(ctx); err != nil {
		a.logger.Warn("fim-audit: auditpipe unavailable, falling back to kqueue", "err", err)
		fim := NewFIMCollector(a.cfg, a.agentID, a.host, a.out, a.logger)
		fim.Run(ctx)
	}
}

func (a *AuditFIMCollector) runAuditPipe(ctx context.Context) error {
	// Configure audit class to capture file events
	// auditctl -s will show current state
	// We use praudit to parse the binary BSM stream into text
	// This avoids implementing full BSM parser in Go

	f, err := os.Open("/dev/auditpipe")
	if err != nil {
		return err
	}
	defer f.Close()

	a.logger.Info("fim-audit: reading from /dev/auditpipe")

	// Use praudit -x for XML output — easier to parse than raw BSM
	cmd := exec.CommandContext(ctx, "praudit", "-x")
	cmd.Stdin = f
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer cmd.Wait()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	// Parse praudit XML output — each record is wrapped in <record> tags
	var (
		inRecord   bool
		eventType  string
		pid        int
		procName   string
		path       string
		returnCode int
		recLines   []string
	)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "<record") {
			inRecord = true
			recLines = recLines[:0]
			// Extract event type: <record version="11" event="open(2)" modifier="..." ...>
			if idx := strings.Index(line, `event="`); idx >= 0 {
				rest := line[idx+7:]
				if end := strings.Index(rest, `"`); end >= 0 {
					eventType = rest[:end]
				}
			}
			pid, procName, path, returnCode = 0, "", "", 0
			continue
		}

		if !inRecord {
			continue
		}

		recLines = append(recLines, line)

		// Extract PID from subject token
		// <subject audit-uid="..." uid="..." gid="..." ruid="..." rgid="..." pid="1234" ...>
		if strings.HasPrefix(line, "<subject") {
			pid = extractXMLAttrInt(line, "pid")
			procName = extractXMLAttr(line, "process")
		}

		// Extract path
		// <path>/Users/user/Documents/secret.docx</path>
		if strings.HasPrefix(line, "<path>") && strings.HasSuffix(line, "</path>") {
			path = strings.TrimSuffix(strings.TrimPrefix(line, "<path>"), "</path>")
		}

		// Extract return code
		if strings.HasPrefix(line, "<return") {
			returnCode = extractXMLAttrInt(line, "errval")
		}

		if strings.HasPrefix(line, "</record>") {
			inRecord = false

			// Only process file events that succeeded (return 0)
			if returnCode != 0 || path == "" {
				continue
			}

			// Map event type to action
			action := a.mapEventType(eventType)
			if action == "" {
				continue
			}

			// Check if path matches watched dirs
			if !a.pathWatched(path) {
				continue
			}

			// Get process name if not in subject token
			if procName == "" && pid > 0 {
				procName = pidToProcessNameMac(pid)
			}

			a.emit(path, action, pid, procName)
		}
	}
	return scanner.Err()
}

func (a *AuditFIMCollector) mapEventType(eventType string) string {
	et := strings.ToLower(eventType)
	switch {
	case strings.Contains(et, "open") && (strings.Contains(et, "write") || strings.Contains(et, "wt") || strings.Contains(et, "rw")):
		return "write"
	case strings.Contains(et, "creat"), strings.Contains(et, "mkdir"), strings.Contains(et, "wtc"):
		return "create"
	case strings.Contains(et, "unlink"), strings.Contains(et, "rmdir"):
		return "delete"
	case strings.Contains(et, "rename"):
		return "rename"
	case strings.Contains(et, "truncate"):
		return "modify"
	case strings.Contains(et, "link"), strings.Contains(et, "symlink"):
		return "link"
	default:
		return ""
	}
}

func (a *AuditFIMCollector) pathWatched(path string) bool {
	if len(a.cfg.Dirs) == 0 {
		return true // watch everything if no dirs configured
	}
	for _, dir := range a.cfg.Dirs {
		if strings.HasPrefix(path, dir.Path) {
			return true
		}
	}
	return false
}

func (a *AuditFIMCollector) emit(path, action string, pid int, procName string) {
	sev := a.severityForPath(path, action)

	hash := ""
	if action != "delete" && action != "rename" {
		hash = hashFile(path)
	}

	fimDetail := map[string]interface{}{
		"path":         path,
		"action":       action,
		"pid":          pid,
		"process_name": procName,
		"hash":         hash,
		"source":       "auditpipe",
	}
	if g := macProcGUID(int32(pid)); g != "" {
		fimDetail["process_guid"] = g
	}
	raw, _ := json.Marshal(fimDetail)

	select {
	case a.out <- schema.Event{
		Time:        time.Now().UTC(),
		AgentID:     a.agentID,
		Host:        a.host,
		OS:          "darwin",
		EventType:   "file",
		Source:      "auditpipe",
		Severity:    sev,
		PID:         pid,
		ProcessName: procName,
		FilePath:    path,
		FileHash:    hash,
		Raw:         raw,
	}:
	default:
	}
}

func (a *AuditFIMCollector) severityForPath(path, action string) schema.Severity {
	critical := []string{
		"/etc/passwd", "/etc/sudoers", "/Library/LaunchDaemons",
		"/Library/LaunchAgents", "/System/Library", "/usr/bin", "/usr/sbin",
		"/private/etc",
	}
	for _, c := range critical {
		if strings.HasPrefix(path, c) {
			return schema.SeverityHigh
		}
	}
	if strings.HasPrefix(path, "/tmp/") || strings.Contains(path, "/Downloads/") {
		if action == "create" {
			return schema.SeverityMedium
		}
	}
	return schema.SeverityInfo
}

// ── XML helpers ──────────────────────────────────────────────────────────────

func extractXMLAttr(line, attr string) string {
	search := attr + `="`
	idx := strings.Index(line, search)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(search):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func extractXMLAttrInt(line, attr string) int {
	val := extractXMLAttr(line, attr)
	if val == "" {
		return 0
	}
	n := 0
	for _, c := range val {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}

// pidToProcessNameMac resolves PID to process name on macOS using ps.
func pidToProcessNameMac(pid int) string {
	if pid <= 0 {
		return ""
	}
	import_strconv_pid := strconv.Itoa(pid)
	out, err := exec.Command("ps", "-p", import_strconv_pid, "-o", "comm=").Output()
	if err != nil {
		// Fallback: read from /proc equivalent
		return ""
	}
	return strings.TrimSpace(string(out))
}
