//go:build linux

package collector

// software.go — P-12: package install / remove events.
//
// Tails /var/log/dpkg.log (Debian/Ubuntu) from the end of file; each "install"
// or "remove"/"purge" status line becomes one event. Hosts without dpkg.log
// (RPM family) are skipped. Events: event_type="software", source="software".

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

const dpkgLogPath = "/var/log/dpkg.log"

type softwareChange struct {
	Action  string `json:"action"` // software_installed | software_removed
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
}

// parseDpkgLine parses "2026-11-08 10:00:00 install nmap:amd64 <none> 7.94".
func parseDpkgLine(line string) (softwareChange, bool) {
	f := strings.Fields(line)
	if len(f) < 5 {
		return softwareChange{}, false
	}
	pkg := f[3]
	if i := strings.Index(pkg, ":"); i > 0 {
		pkg = pkg[:i]
	}
	switch f[2] {
	case "install":
		return softwareChange{Action: "software_installed", Package: pkg, Version: f[len(f)-1]}, true
	case "remove", "purge":
		return softwareChange{Action: "software_removed", Package: pkg, Version: f[4]}, true
	}
	return softwareChange{}, false
}

type SoftwareCollector struct {
	path    string
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
}

func NewSoftwareCollector(agentID, host string, out chan<- schema.Event, logger *slog.Logger) *SoftwareCollector {
	return &SoftwareCollector{path: dpkgLogPath, out: out, agentID: agentID, host: host, logger: logger}
}

func (c *SoftwareCollector) Run(ctx context.Context) error {
	st, err := os.Stat(c.path)
	if err != nil {
		return nil // not a dpkg system
	}
	offset := st.Size() // silent baseline: only new lines are reported
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		st, err := os.Stat(c.path)
		if err != nil {
			continue
		}
		if st.Size() < offset { // rotated
			offset = 0
		}
		if st.Size() == offset {
			continue
		}
		f, err := os.Open(c.path)
		if err != nil {
			continue
		}
		_, _ = f.Seek(offset, io.SeekStart)
		buf, _ := io.ReadAll(io.LimitReader(f, 4<<20))
		f.Close()
		// only consume complete lines
		if i := strings.LastIndexByte(string(buf), '\n'); i >= 0 {
			buf = buf[:i+1]
		} else {
			continue
		}
		offset += int64(len(buf))
		for _, ln := range strings.Split(string(buf), "\n") {
			if ch, ok := parseDpkgLine(ln); ok {
				c.emit(ch)
			}
		}
	}
}

func (c *SoftwareCollector) emit(ch softwareChange) {
	raw, _ := json.Marshal(map[string]interface{}{"action": ch.Action, "package": ch.Package, "version": ch.Version})
	ev := schema.Event{
		Time: time.Now().UTC(), AgentID: c.agentID, Host: c.host, OS: "linux",
		EventType: schema.EventType("software"), Severity: schema.SeverityInfo, Source: "software", Raw: raw,
		ProcessName: ch.Package,
	}
	select {
	case c.out <- ev:
	default:
		GlobalHealth.EventsDropped.Add(1)
	}
}
