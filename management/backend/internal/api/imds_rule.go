package api

// imds_rule.go - NET-IMDS-001/002: instance-metadata-service access by an
// unexpected process. Replaces the endpoint paths of C-NET-005, C-XCLOUD-010
// and L-T1078.004, which matched substrings of the raw event and alerted on
// the VM's own guest agents.

import (
	"strings"
	"sync"

	"obsidianwatch/management/internal/store"
)

var (
	imdsExtraMu sync.RWMutex
	imdsExtra   = map[string]bool{}
)

// setIMDSExtraAllowed loads the `imds_allowed_processes` setting (comma list).
func setIMDSExtraAllowed(csv string) {
	m := map[string]bool{}
	for _, p := range strings.Split(csv, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			m[p] = true
		}
	}
	imdsExtraMu.Lock()
	imdsExtra = m
	imdsExtraMu.Unlock()
}

func imdsExtraAllowedFor(ev store.Event) bool {
	imdsExtraMu.RLock()
	defer imdsExtraMu.RUnlock()
	if len(imdsExtra) == 0 {
		return false
	}
	return imdsExtra[exeBase(ev)] || imdsExtra[pathBase(proc(ev))]
}

// imdsDest matches on the destination field, not on a substring of the raw JSON.
func imdsDest(ev store.Event) bool {
	if ev.EventType != "network" || ev.DstIP == nil {
		return false
	}
	d := strings.ToLower(strings.TrimSpace(*ev.DstIP))
	return appMetadataIPs[d] || appMetadataNames[d]
}

var imdsRiskyExe = []string{"bash", "sh", "zsh", "dash", "ksh", "fish", "python", "python2", "python3",
	"perl", "ruby", "php", "node", "nc", "ncat", "socat"}

// imdsHighRisk: a shell or interpreter, or a binary running from a
// user-writable path.
func imdsHighRisk(ev store.Event) bool {
	if exeIn(ev, imdsRiskyExe...) {
		return true
	}
	p := strings.ToLower(rawStringField(ev, "exe"))
	if p == "" {
		p = img(ev)
	}
	for _, d := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/private/tmp/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

var imdsSignatures = []ThreatSig{
	{
		ID: "NET-IMDS-001", Name: "Instance Metadata Service Accessed by Unexpected Process",
		Description: "A process other than the cloud guest agents and CLIs connected to the instance metadata service (169.254.169.254 and equivalents). Possible credential theft.",
		Severity:    4, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return imdsDest(ev) && !imdsAllowedProcess(ev) && !imdsHighRisk(ev)
		},
	},
	{
		ID: "NET-IMDS-002", Name: "Instance Metadata Service Accessed by Shell, Interpreter or Temp-Path Binary",
		Description: "A shell, script interpreter or binary running from a user-writable path connected to the instance metadata service. Likely credential theft.",
		Severity:    5, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return imdsDest(ev) && !imdsAllowedProcess(ev) && imdsHighRisk(ev)
		},
	},
}
