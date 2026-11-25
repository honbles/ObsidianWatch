package api

// prevention_sigs.go - alerts for the agents' prevention reports
// (event_type "prevention"). A match that was stopped is High; one that was
// only reported (audit) or that the agent failed to stop is Critical for
// files and processes, because the thing ran or is on disk.

import (
	"encoding/json"

	"obsidianwatch/management/internal/store"
)

type prevRaw struct {
	Kind   string `json:"kind"`
	Action string `json:"action"`
	Mode   string `json:"mode"`
}

func prevOf(ev store.Event) (prevRaw, bool) {
	var r prevRaw
	if ev.EventType != "prevention" || len(ev.Raw) == 0 || json.Unmarshal(ev.Raw, &r) != nil {
		return r, false
	}
	return r, true
}

func prevStopped(action string) bool {
	switch action {
	case "blocked", "ip_blocked", "killed", "quarantined", "killed+quarantined":
		return true
	}
	return false
}

func prevSig(id, name, desc, mitre string, sev int, kind string, stopped bool) ThreatSig {
	return ThreatSig{ID: id, Name: name, Description: desc, Severity: sev, MITRE: mitre, Category: "Prevention",
		Match: func(ev store.Event) bool {
			r, ok := prevOf(ev)
			return ok && r.Kind == kind && prevStopped(r.Action) == stopped
		}}
}

var preventionSignatures = []ThreatSig{
	prevSig("PREV-IP-1", "Connection to a Known Malicious Address Blocked",
		"The agent refused or blocked a connection to an address on the prevention list (C2 or malware infrastructure). Find out why the process tried.",
		"T1071", 4, "ip", true),
	prevSig("PREV-IP-0", "Connection to a Known Malicious Address",
		"A process connected to an address on the prevention list and nothing stopped it (audit mode, or the block failed).",
		"T1071", 4, "ip", false),
	prevSig("PREV-HASH-1", "Known Malicious File Stopped",
		"A file or process matching a listed SHA-256 was killed and/or quarantined by the agent.",
		"T1204", 4, "hash", true),
	prevSig("PREV-HASH-0", "Known Malicious File Present or Running",
		"A file or process matches a listed SHA-256 and was not stopped (audit mode, or the action failed).",
		"T1204", 5, "hash", false),
	prevSig("PREV-DNS-1", "Lookup of a Known Malicious Domain; Addresses Blocked",
		"A host resolved a domain on the prevention list; the agent blocked the addresses it resolved to. The lookup itself was not prevented.",
		"T1071.004", 3, "domain", true),
	prevSig("PREV-DNS-0", "Lookup of a Known Malicious Domain",
		"A host resolved a domain on the prevention list (audit mode, or the DNS event carried no addresses to block).",
		"T1071.004", 3, "domain", false),
}

func init() {
	RegisterSigProvider(func(ev store.Event) []ThreatSig {
		if ev.EventType == "prevention" {
			return preventionSignatures
		}
		return nil
	})
}
