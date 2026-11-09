//go:build darwin

package collector

// usb.go — P-12: USB / removable media attach events on macOS.
// Polls `system_profiler SPUSBDataType -json` every 15s; the first scan is a
// silent baseline. Mass-storage devices (those exposing Media) are Low.
//
// Events emitted: event_type="usb", source="system_profiler"

import (
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
)

type USBCollector struct {
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
}

func NewUSBCollector(agentID, host string, out chan<- schema.Event, logger *slog.Logger) *USBCollector {
	return &USBCollector{out: out, agentID: agentID, host: host, logger: logger}
}

func (c *USBCollector) scan(ctx context.Context) (map[string]usbDevice, bool) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	b, err := exec.CommandContext(cctx, "/usr/sbin/system_profiler", "SPUSBDataType", "-json").Output()
	if err != nil {
		return nil, false
	}
	return parseSPUSB(b), true
}

func (c *USBCollector) Run(ctx context.Context) error {
	known, ok := c.scan(ctx)
	if !ok {
		c.logger.Warn("usb collector: system_profiler unavailable")
		return nil
	}
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		cur, ok := c.scan(ctx)
		if !ok {
			continue
		}
		for k, d := range cur {
			if _, seen := known[k]; !seen {
				c.emit(d)
			}
		}
		known = cur
	}
}

func (c *USBCollector) emit(d usbDevice) {
	sev := schema.SeverityInfo
	if d.MassStorage {
		sev = schema.SeverityLow
	}
	raw, _ := json.Marshal(map[string]interface{}{"action": "usb_attached", "device": d})
	ev := schema.Event{
		Time: time.Now().UTC(), AgentID: c.agentID, Host: c.host, OS: "macos",
		EventType: schema.EventType("usb"), Severity: sev, Source: "system_profiler", Raw: raw,
		ProcessName: d.Name,
	}
	select {
	case c.out <- ev:
	default:
		GlobalHealth.EventsDropped.Add(1)
	}
}
