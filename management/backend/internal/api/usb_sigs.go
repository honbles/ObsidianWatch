package api

import (
	"encoding/json"
	"strings"

	"obsidianwatch/management/internal/store"
)

// P-12: USB/removable media rules (events from the Linux usb collector).
var usbSignatures = []ThreatSig{
	{
		ID: "L-USB-001", Name: "USB Mass Storage Device Attached",
		Description: "A USB storage device was plugged into this host. Removable media is a common data-exfiltration and malware-delivery path; confirm the device and user are expected.",
		Severity: 2, MITRE: "T1052.001", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			if ev.EventType != "usb" {
				return false
			}
			var r struct {
				Device struct {
					MassStorage bool `json:"mass_storage"`
				} `json:"device"`
			}
			return json.Unmarshal(ev.Raw, &r) == nil && r.Device.MassStorage
		},
	},
}

// windowsUSBSignatures match PnP/driver events for USB storage. 6416 needs the
// "Audit PNP Activity" policy; DriverFrameworks 2003/2100 need that channel
// enabled (wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true).
var windowsUSBSignatures = []ThreatSig{
	{
		ID: "W-USB-001", Name: "USB Storage Device Connected",
		Description: "Windows recognised a USB mass-storage device (PnP event). Removable media is a common data-exfiltration and malware-delivery path.",
		Severity: 2, MITRE: "T1052.001", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			if ev.EventID == nil {
				return false
			}
			raw := strings.ToLower(rawStr(ev))
			switch *ev.EventID {
			case 6416:
				return strings.Contains(raw, "usbstor") || strings.Contains(raw, "usb\\") || strings.Contains(raw, "mass storage")
			case 2003, 2100:
				return strings.Contains(raw, "usbstor") || strings.Contains(raw, "mass storage")
			}
			return false
		},
	},
}
