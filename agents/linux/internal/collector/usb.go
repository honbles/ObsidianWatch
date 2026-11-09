//go:build linux

package collector

// usb.go — P-12: USB / removable media attach events.
//
// Polls /sys/bus/usb/devices (no root, no udev dependency) and emits one
// event per newly attached device. The first scan is a silent baseline so an
// agent restart does not re-report devices that were already plugged in.
// Mass-storage devices (class 08) are reported at Low severity, others Info.
//
// Events emitted: event_type="usb", source="usb"

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

const usbSysfsRoot = "/sys/bus/usb/devices"

type usbDevice struct {
	Key          string `json:"key"` // sysfs name, e.g. 1-2
	VendorID     string `json:"vendor_id"`
	ProductID    string `json:"product_id"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
	Serial       string `json:"serial,omitempty"`
	Class        string `json:"class,omitempty"`
	MassStorage  bool   `json:"mass_storage"`
}

func readSysfs(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// scanUSB lists attached USB devices (not interfaces, not root hubs).
func scanUSB(root string) map[string]usbDevice {
	out := map[string]usbDevice{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if strings.Contains(name, ":") || strings.HasPrefix(name, "usb") {
			continue // interface entry or root hub
		}
		dir := filepath.Join(root, name)
		vid := readSysfs(dir, "idVendor")
		if vid == "" {
			continue
		}
		d := usbDevice{
			Key: name, VendorID: vid, ProductID: readSysfs(dir, "idProduct"),
			Manufacturer: readSysfs(dir, "manufacturer"), Product: readSysfs(dir, "product"),
			Serial: readSysfs(dir, "serial"), Class: readSysfs(dir, "bDeviceClass"),
		}
		d.MassStorage = d.Class == "08"
		if !d.MassStorage { // class is usually declared on the interface
			// Interfaces appear both inside the device dir and as siblings under root.
			ifs, _ := filepath.Glob(filepath.Join(dir, name+":*"))
			sib, _ := filepath.Glob(filepath.Join(root, name+":*"))
			ifs = append(ifs, sib...)
			for _, i := range ifs {
				if readSysfs(i, "bInterfaceClass") == "08" {
					d.MassStorage = true
					break
				}
			}
		}
		out[name+"|"+vid+":"+d.ProductID+"|"+d.Serial] = d
	}
	return out
}

type USBCollector struct {
	root    string
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
}

func NewUSBCollector(agentID, host string, out chan<- schema.Event, logger *slog.Logger) *USBCollector {
	return &USBCollector{root: usbSysfsRoot, out: out, agentID: agentID, host: host, logger: logger}
}

func (c *USBCollector) Run(ctx context.Context) error {
	if _, err := os.Stat(c.root); err != nil {
		return nil // no USB subsystem (container / VM without USB)
	}
	known := scanUSB(c.root)
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		cur := scanUSB(c.root)
		for k, d := range cur {
			if _, ok := known[k]; ok {
				continue
			}
			c.emit(d)
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
		Time: time.Now().UTC(), AgentID: c.agentID, Host: c.host, OS: "linux",
		EventType: schema.EventType("usb"), Severity: sev, Source: "usb", Raw: raw,
		ProcessName: d.Product,
	}
	select {
	case c.out <- ev:
	default:
		GlobalHealth.EventsDropped.Add(1)
	}
}
