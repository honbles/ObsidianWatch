package api

import (
	"net/http"
	"sort"
	"strings"

	"obsidianwatch/management/internal/store"
)

// P-05: ATT&CK coverage per platform, built from the live rule set (disabled
// rules excluded), plus the known telemetry gaps that cap what can fire.
type attackCell struct {
	Technique string   `json:"technique"`
	Rules     []string `json:"rules"`
}

type attackPlatform struct {
	Platform string       `json:"platform"`
	Rules    int          `json:"rules"`
	NoMITRE  int          `json:"rules_without_mitre"`
	Disabled int          `json:"rules_disabled"`
	Covered  []attackCell `json:"techniques"`
	DataGaps []string     `json:"data_gaps"`
}

// Known data-source gaps (kept next to the code so they are removed when the
// corresponding tracker item is fixed).
var platformDataGaps = map[string][]string{
	"macos":   {"DNS query names are not collected (A-02): domain, category and IOC rules cannot fire", "File events lack PID (A-03)", "No Endpoint Security / Network Extension telemetry (A-01)"},
	"windows": {"Process detections need Sysmon or 4688 (W-01)", "ETW collector has no image/command line (W-01)"},
	"linux":   {"DNS has no PID or per-query timing (L-04)", "No eBPF telemetry (L-01)"},
}

func buildAttackCoverage(disabled map[string]bool) []attackPlatform {
	groups := []struct {
		name string
		sets [][]ThreatSig
	}{
		{"linux", [][]ThreatSig{linuxSignatures, endpointAgentSignatures, dnsCatSignatures}},
		{"windows", [][]ThreatSig{windowsSignatures, windowsTamperSignatures, dcSignatures, endpointAgentSignatures, dnsCatSignatures}},
		{"macos", [][]ThreatSig{macosSignatures, endpointAgentSignatures, dnsCatSignatures}},
		{"aws", [][]ThreatSig{cloudSignaturesExtended, cloudReconSignatures, cloudNetworkSignatures, cloudLateralSignatures, cloudComputeAbuseSignatures, awsExtraSignatures}},
		{"gcp", [][]ThreatSig{gcpIAMSignatures, gcpCredentialSignatures, gcpComputeSignatures, gcpDataSignatures, gcpNetworkSignatures, gcpDefenseEvasionSignatures, gcpPersistenceSignatures, gcpSCCSignatures, gcpTelemetrySignatures, gcpPolicySignatures, gcpEscalationSignatures}},
		{"azure", [][]ThreatSig{azureIAMSignatures, azureComputeSignatures, azureDataSignatures, azureNetworkSignatures, azureDefenseEvasionSignatures, azureDefenderSignatures, azureResourceSignatures, azureAuditSignatures}},
		{"devops", [][]ThreatSig{devopsSignatures}},
	}
	var out []attackPlatform
	for _, g := range groups {
		p := attackPlatform{Platform: g.name, DataGaps: platformDataGaps[g.name]}
		cells := map[string][]string{}
		for _, set := range g.sets {
			for _, s := range set {
				if retiredSigIDs[s.ID] {
					continue
				}
				if disabled[s.ID] {
					p.Disabled++
					continue
				}
				p.Rules++
				m := strings.TrimSpace(s.MITRE)
				if m == "" || m == "-" {
					p.NoMITRE++
					continue
				}
				for _, t := range strings.FieldsFunc(m, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '/' }) {
					cells[t] = append(cells[t], s.ID)
				}
			}
		}
		keys := make([]string, 0, len(cells))
		for k := range cells {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p.Covered = append(p.Covered, attackCell{Technique: k, Rules: cells[k]})
		}
		out = append(out, p)
	}
	return out
}

func handleAttackCoverage(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		disabled := map[string]bool{}
		if states, err := db.GetSignatureStates(r.Context()); err == nil {
			for id, st := range states {
				if !st.Enabled {
					disabled[id] = true
				}
			}
		}
		writeJSON(w, 200, map[string]interface{}{"platforms": buildAttackCoverage(disabled)})
	}
}
