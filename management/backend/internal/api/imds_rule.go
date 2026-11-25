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

// imdsGuestAgents are cloud guest components whose own processes and
// children (startup and OS Config scripts, which are shells and
// interpreters) use the metadata service by design.
var imdsGuestAgents = []string{"google_guest_agent", "google_osconfig_agent", "google_metadata_script_runner",
	"gce_workload_cert_refresh", "google_oslogin_nss", "google_authorized_keys", "otelopscol", "fluent-bit",
	"google_cloud_ops_agent_engine", "cloud-init", "amazon-ssm-agent", "ssm-agent-worker", "waagent", "walinuxagent"}

// imdsByGuestAgent: the process or one of its ancestors is a guest agent.
func imdsByGuestAgent(ev store.Event) bool {
	if exeIn(ev, imdsGuestAgents...) {
		return true
	}
	return ancestorIn(ev, lineageMaxDepth, imdsGuestAgents...)
}

// imdsSystemBinary: a non-interpreter program in a system directory. On GCP
// with OS Login, the NSS module makes ordinary programs (sshd, sudo, id, ls)
// ask the metadata server who a user is; a stolen-credential attempt uses a
// shell, an interpreter, curl or a dropped binary instead.
func imdsSystemBinary(ev store.Event) bool {
	if imdsHighRisk(ev) || exeIn(ev, "curl", "wget", "nc", "ncat", "socat", "busybox") {
		return false
	}
	p := strings.ToLower(rawStringField(ev, "exe"))
	if p == "" {
		p = img(ev)
	}
	for _, d := range []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/lib/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

func imdsExpected(ev store.Event) bool {
	return imdsAllowedProcess(ev) || imdsByGuestAgent(ev)
}

var imdsSignatures = []ThreatSig{
	{
		ID: "NET-IMDS-001", Name: "Instance Metadata Service Accessed by Unexpected Process",
		Description: "A process other than the cloud guest agents, their scripts, the cloud CLIs and system programs connected to the instance metadata service (169.254.169.254 and equivalents). Possible credential theft.",
		Severity:    4, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return imdsDest(ev) && !imdsExpected(ev) && !imdsHighRisk(ev) && !imdsSystemBinary(ev)
		},
	},
	{
		ID: "NET-IMDS-002", Name: "Instance Metadata Service Accessed by Shell, Interpreter or Temp-Path Binary",
		Description: "A shell, script interpreter or binary running from a user-writable path connected to the instance metadata service. Likely credential theft.",
		Severity:    5, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return imdsDest(ev) && !imdsExpected(ev) && imdsHighRisk(ev)
		},
	},
}
