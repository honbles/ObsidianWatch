package api

import (
	"encoding/json"

	"obsidianwatch/management/internal/store"
)

// P-12: rules for the Linux software-install and container collectors.
var softwareSignatures = []ThreatSig{
	{
		ID: "L-SW-001", Name: "Offensive Security Tool Installed",
		Description: "A reconnaissance or attack tool package was installed on this host. These tools are commonly installed by intruders after compromise; confirm the change was authorised.",
		Severity:    2, MITRE: "T1588.002", Category: "Resource Development",
		Match: func(ev store.Event) bool {
			if ev.EventType != "software" {
				return false
			}
			var r struct {
				Action  string `json:"action"`
				Package string `json:"package"`
			}
			return json.Unmarshal(ev.Raw, &r) == nil && r.Action == "software_installed" && offensiveToolPkgs[r.Package]
		},
	},
	{
		ID: "L-CTR-001", Name: "Risky Container Started",
		Description: "A container was started with privileged mode, host network/PID namespace, or the Docker socket mounted. These settings allow container escape to the host.",
		Severity:    3, MITRE: "T1611", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			if ev.EventType != "container" {
				return false
			}
			var r struct {
				Container struct {
					Risks []string `json:"risks"`
				} `json:"container"`
			}
			return json.Unmarshal(ev.Raw, &r) == nil && len(r.Container.Risks) > 0
		},
	},
}
