package api

// zz_endpoint_rule_meta.go - RuleMeta for the built-in endpoint rules
// (Linux, macOS, Windows, domain controller, metadata service), so they can be
// disabled, allow-listed or put in observe mode through rule_settings.
// The file name sorts last so this init() runs after the signature tables and
// their own init()s are populated.
//
// A rule with no RuleMeta keeps its old behaviour; observe-mode rules are
// raised at Info severity, so they are stored and counted but not escalated.

// observeByDefault: rules whose single-event signal is too weak to open an
// alert. Promote one by setting observe=false in rule_settings once the
// observed volume looks right.
var observeByDefault = map[string]bool{
	"L-T1611b": true, "L-DLP-010": true, "L-T1087.001": true, "L-T1590": true, "L-T1560": true,
	"L-T1222.002": true, "L-T1105": true, "L-T1548.001b": true, "M-T1082": true,
	"W-T1110": true, "W-T1021.001": true, "W-T1570": true, "W-T1057": true, "W-T1016": true, "W-T1087": true,
	"DC-T1558.001": true,
}

// endpointFPNotes is the analyst-facing "what usually triggers this benignly".
var endpointFPNotes = map[string]string{
	"L-T1059.004a": "Health checks and installers using bash -c curl; installers from allow-listed hosts are L-T1059.004d.",
	"L-T1059.004b": "go run, AppImage, PyInstaller, pip/npm builds run from /tmp.",
	"L-T1110.001":  "Single failed logons are not brute force; thresholds live in CORR-AUTH.",
	"L-T1547.006":  "udev, dockerd and NetworkManager call modprobe routinely.",
	"L-T1003.008":  "passwd, useradd, adduser and other shadow-utils tools touch /etc/shadow by design.",
	"L-T1552.004":  "ssh, ssh-keygen, ssh-agent, git and rsync read and write key files.",
	"L-T1552.005":  "aws, az, gcloud, terraform and kubectl read their own credential stores.",
	"L-T1021.004":  "Developers use ssh -L/-R/-D for port forwards.",
	"L-T1572":      "IPv6 PTR lookups and DKIM TXT records have long names.",
	"L-T1611":      "Portainer, Traefik and Watchtower open docker.sock legitimately; only tool names alert here.",
	"W-T1059.001a": "SCCM, Intune and MDE live response run encoded PowerShell.",
	"W-T1059.001b": "Chocolatey and Scoop installers download and execute by design.",
	"W-T1218.011":  "Control Panel applets and url.dll,FileProtocolHandler use rundll32.",
	"W-T1053.005":  "Windows, Edge, Chrome, Office and OneDrive update tasks.",
	"W-T1486":      "Needs 20 renames to one extension within 60 s; single .enc files are ordinary.",
	"W-T1574.002":  "Installers and compilers drop DLLs; only Downloads, Desktop and Public are flagged.",
	"DC-T1003.006": "DC machine accounts, MSOL_*/AAD_* and Defender for Identity sensors replicate legitimately.",
	"DC-T1558.003": "Needs 5 distinct SPNs in 5 minutes; single RC4 tickets are DC-T1558.003b.",
	"NET-IMDS-001": "Cloud guest agents and CLIs read the metadata service; extend with imds_allowed_processes.",
}

func init() {
	sets := allSignatureSets()
	for _, fam := range []string{"linux", "macos", "windows", "windowsTamper", "dc", "imds", "endpoint", "winAccount", "linAccount", "remoteSession"} {
		for _, s := range sets[fam] {
			if _, exists := RuleMetaFor(s.ID); exists {
				continue
			}
			what := s.Description
			if what == "" {
				what = s.Name
			}
			RegisterRuleMeta(RuleMeta{
				ID:             s.ID,
				Family:         "endpoint-" + fam,
				Layer:          "host",
				ATTCK:          []string{s.MITRE},
				WhatToCheck:    what,
				FalsePositives: endpointFPNotes[s.ID],
				DefaultObserve: observeByDefault[s.ID],
			})
		}
	}
}
