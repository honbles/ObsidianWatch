package api

// cloud_gcp_scc.go — Google Security Command Center (SCC) integration
//
// SCC is GCP's native CSPM/threat detection service.
// It aggregates findings from:
//   - Security Health Analytics (built-in CSPM checks)
//   - Web Security Scanner
//   - Container Threat Detection
//   - Event Threat Detection
//   - VM Threat Detection
//   - Third-party sources
//
// API: https://securitycenter.googleapis.com/v1
// Requires: Security Command Center API enabled + roles/securitycenter.findingsViewer
//
// We call SCC in addition to our own CSPM checks — this gives us:
//   1. GCP's own 500+ built-in checks (Security Health Analytics)
//   2. Threat detections (Event Threat Detection, Container Threat Detection)
//   3. Active vulnerabilities (OS vulnerability scanning)
//   4. Compliance posture (CIS, PCI-DSS, NIST, ISO 27001)

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"strings"
	"time"
)

// SCCFinding represents a finding from GCP Security Command Center
type SCCFinding struct {
	Name             string            `json:"name"`
	Parent           string            `json:"parent"`
	ResourceName     string            `json:"resource_name"`
	State            string            `json:"state"`
	Category         string            `json:"category"`
	ExternalURI      string            `json:"external_uri"`
	Severity         string            `json:"severity"`       // CRITICAL, HIGH, MEDIUM, LOW
	FindingClass     string            `json:"finding_class"`  // VULNERABILITY, MISCONFIGURATION, THREAT, etc.
	Description      string            `json:"description"`
	CreateTime       string            `json:"create_time"`
	EventTime        string            `json:"event_time"`
	SourceProperties map[string]interface{} `json:"source_properties"`
	Compliances      []SCCCompliance   `json:"compliances"`
	Indicator        *SCCIndicator     `json:"indicator"`
	Vulnerability    *SCCVulnerability `json:"vulnerability"`
}

type SCCCompliance struct {
	Standard string   `json:"standard"` // CIS, PCI-DSS, NIST, ISO-27001
	Version  string   `json:"version"`
	IDs      []string `json:"ids"`
}

type SCCIndicator struct {
	IPAddresses []string `json:"ip_addresses"`
	Domains     []string `json:"domains"`
	Signatures  []struct {
		MemoryHashSignature *struct {
			BinaryFamily string `json:"binary_family"`
		} `json:"memory_hash_signature"`
	} `json:"signatures"`
}

type SCCVulnerability struct {
	CVE struct {
		ID          string  `json:"id"`
		CVSSV3Score float64 `json:"cvssv3_score"`
		References  []struct {
			Source string `json:"source"`
			URI    string `json:"uri"`
		} `json:"references"`
	} `json:"cve"`
}

// SCCResult contains all SCC findings for a project
type SCCResult struct {
	ProjectID      string       `json:"project_id"`
	ScannedAt      time.Time    `json:"scanned_at"`
	Findings       []SCCFinding `json:"findings"`
	TotalFindings  int          `json:"total_findings"`
	Critical       int          `json:"critical"`
	High           int          `json:"high"`
	Medium         int          `json:"medium"`
	Low            int          `json:"low"`
	Threats        int          `json:"threats"`
	Misconfigs     int          `json:"misconfigs"`
	Vulnerabilities int         `json:"vulnerabilities"`
	Sources        []string     `json:"sources"`
	Errors         []string     `json:"errors,omitempty"`
	SCCEnabled     bool         `json:"scc_enabled"`
}

// RunSCC fetches all active findings from GCP Security Command Center
// Requires: Security Command Center API enabled + securitycenter.findingsViewer role
func RunSCC(ctx context.Context, saJSON, projectID string) (*SCCResult, error) {
	start := time.Now()
	result := &SCCResult{
		ProjectID: projectID,
		ScannedAt: start,
	}

	var sa gcpServiceAccount
	if err := parseGCPServiceAccount(saJSON, &sa); err != nil {
		return nil, fmt.Errorf("invalid service account JSON: %w", err)
	}
	if projectID == "" { projectID = sa.ProjectID }
	result.ProjectID = projectID

	// SCC needs the cloud-platform scope
	token, err := getGCPTokenWithScope(ctx, sa, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("auth failed: %w\n\nEnsure the service account JSON is complete and the Security Command Center API is enabled", err)
	}

	// Try project-level SCC first (v1 API)
	// SCC can be accessed at: organizations/*/sources/-/findings, folders/*/... or projects/*/...
	findings, sources, err := fetchSCCFindings(ctx, token, projectID)
	if err != nil {
		// scc_unavailable means API not enabled — not a real error, just unavailable
		if strings.HasPrefix(err.Error(), "scc_unavailable:") {
			result.SCCEnabled = false
			return result, nil
		}
		result.Errors = append(result.Errors, "scc: "+err.Error())
		result.SCCEnabled = false
		return result, nil
	}

	result.SCCEnabled = true
	result.Sources = sources
	result.Findings = findings

	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical": result.Critical++
		case "high":     result.High++
		case "medium":   result.Medium++
		case "low":      result.Low++
		}
		switch f.FindingClass {
		case "THREAT":          result.Threats++
		case "MISCONFIGURATION": result.Misconfigs++
		case "VULNERABILITY":   result.Vulnerabilities++
		}
	}

	result.TotalFindings = len(findings)
	return result, nil
}

// fetchSCCFindings lists all ACTIVE findings from SCC for a project
func fetchSCCFindings(ctx context.Context, token, projectID string) ([]SCCFinding, []string, error) {
	return fetchSCCFindingsFiltered(ctx, token, projectID, `state="ACTIVE" AND -mute="MUTED"`)
}

// fetchSCCFindingsFiltered lists SCC findings matching an SCC filter expression.
func fetchSCCFindingsFiltered(ctx context.Context, token, projectID, sccFilter string) ([]SCCFinding, []string, error) {
	// SCC v1 project-level findings endpoint
	// Filters: state="ACTIVE" (not muted, not closed)
	// G-43: exclude muted findings, and URL-escape the filter and the
	// project/page-token values.
	baseURL := fmt.Sprintf(
		"https://securitycenter.googleapis.com/v1/projects/%s/sources/-/findings?filter=%s&pageSize=1000",
		neturl.PathEscape(projectID),
		neturl.QueryEscape(sccFilter),
	)

	var allFindings []SCCFinding
	sourceSet := map[string]bool{}
	pageToken := ""

	for {
		url := baseURL
		if pageToken != "" {
			url += "&pageToken=" + neturl.QueryEscape(pageToken)
		}

		var resp struct {
			ListFindingsResults []struct {
				Finding SCCFinding `json:"finding"`
				Resource struct {
					Name         string `json:"name"`
					Type         string `json:"type"`
					DisplayName  string `json:"display_name"`
					ProjectName  string `json:"project_name"`
				} `json:"resource"`
				StateChange string `json:"state_change"`
			} `json:"listFindingsResults"`
			NextPageToken   string `json:"nextPageToken"`
			TotalSize       int    `json:"totalSize"`
		}

		if err := gcpCSPMGet(ctx, token, url, &resp); err != nil {
			// 403 means SCC API not enabled or SA lacks securitycenter permission —
			// treat as "SCC not available" rather than a hard error.
			errMsg := err.Error()
			if strings.Contains(errMsg, "403") ||
				strings.Contains(errMsg, "securitycenter") ||
				strings.Contains(errMsg, "not enabled") ||
				strings.Contains(errMsg, "disabled") ||
				strings.Contains(errMsg, "permission denied") {
				return nil, nil, fmt.Errorf("scc_unavailable: %w", err)
			}
			return nil, nil, err
		}

		for _, r := range resp.ListFindingsResults {
			f := r.Finding
			// Normalize severity to lowercase for consistency with our CSPM findings
			f.Severity = strings.ToLower(f.Severity)
			// Extract source display name from finding parent
			// parent looks like "projects/xxx/sources/yyy"
			parts := strings.Split(f.Parent, "/")
			if len(parts) >= 4 {
				sourceSet[parts[3]] = true
			}
			allFindings = append(allFindings, f)
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	sources := make([]string, 0, len(sourceSet))
	for s := range sourceSet {
		sources = append(sources, s)
	}

	return allFindings, sources, nil
}

// sccFindingToCSPM converts an SCC finding to our CSPMFinding format
// so both can be displayed in the same UI
func sccFindingToCSPM(f SCCFinding) CSPMFinding {
	category := sccCategoryToCSPMCategory(f.Category, f.FindingClass)
	return CSPMFinding{
		ID:           f.Name,
		Title:        sccCategoryToTitle(f.Category),
		Description:  f.Description,
		Severity:     f.Severity,
		Category:     category,
		Resource:     resourceShortName(f.ResourceName),
		ResourceType: sccResourceType(f.ResourceName),
		Remediation:  sccRemediation(f.Category),
		MITRE:        sccMITRE(f.Category, f.FindingClass),
		Status:       strings.ToLower(f.State),
	}
}

// MergeWithSCC merges our CSPM findings with SCC findings
// SCC findings take priority (dedup by resource+category)
func MergeWithSCC(cspm *CSPMResult, scc *SCCResult) *CSPMResult {
	if scc == nil || !scc.SCCEnabled {
		return cspm
	}

	// Convert SCC findings to CSPM format
	sccAsCSPM := make([]CSPMFinding, 0, len(scc.Findings))
	for _, f := range scc.Findings {
		cf := sccFindingToCSPM(f)
		cf.ScannedAt = scc.ScannedAt
		cf.Status = "open"
		sccAsCSPM = append(sccAsCSPM, cf)
	}

	// Build dedup key set from SCC findings
	sccKeys := map[string]bool{}
	for _, f := range sccAsCSPM {
		sccKeys[f.Resource+"|"+f.Category] = true
	}

	// Add our CSPM findings that aren't already covered by SCC
	var merged []CSPMFinding
	merged = append(merged, sccAsCSPM...)
	for _, f := range cspm.Findings {
		if !sccKeys[f.Resource+"|"+f.Category] {
			merged = append(merged, f)
		}
	}

	cspm.Findings = merged
	cspm.TotalFindings = len(merged)

	// Recount
	cspm.Critical, cspm.High, cspm.Medium, cspm.Low = 0, 0, 0, 0
	for _, f := range merged {
		switch f.Severity {
		case "critical": cspm.Critical++
		case "high":     cspm.High++
		case "medium":   cspm.Medium++
		case "low":      cspm.Low++
		}
	}

	return cspm
}

// ── Category/title helpers ────────────────────────────────────────────────────

func sccCategoryToCSPMCategory(cat, class string) string {
	cat = strings.ToLower(cat)
	switch {
	case strings.Contains(cat, "firewall") || strings.Contains(cat, "network") || strings.Contains(cat, "port"):
		return "network"
	case strings.Contains(cat, "iam") || strings.Contains(cat, "permission") || strings.Contains(cat, "service_account") || strings.Contains(cat, "admin") || strings.Contains(cat, "privilege"):
		return "iam"
	case strings.Contains(cat, "bucket") || strings.Contains(cat, "storage") || strings.Contains(cat, "object"):
		return "storage"
	case strings.Contains(cat, "sql") || strings.Contains(cat, "database") || strings.Contains(cat, "db"):
		return "sql"
	case strings.Contains(cat, "log") || strings.Contains(cat, "audit") || strings.Contains(cat, "monitor"):
		return "logging"
	case strings.Contains(cat, "kms") || strings.Contains(cat, "key") || strings.Contains(cat, "crypto") || strings.Contains(cat, "encrypt"):
		return "kms"
	case strings.Contains(cat, "compute") || strings.Contains(cat, "vm") || strings.Contains(cat, "instance"):
		return "compute"
	case class == "THREAT":
		return "threat"
	case class == "VULNERABILITY":
		return "vulnerability"
	default:
		return "security"
	}
}

func sccCategoryToTitle(cat string) string {
	// SCC categories are SCREAMING_SNAKE_CASE — convert to human readable
	words := strings.Split(cat, "_")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
		}
	}
	return strings.Join(words, " ")
}

func sccResourceType(resourceName string) string {
	// Resource names like "//compute.googleapis.com/projects/x/global/firewalls/y"
	if strings.Contains(resourceName, "firewalls") { return "firewall_rule" }
	if strings.Contains(resourceName, "instances") { return "compute_instance" }
	if strings.Contains(resourceName, "buckets")   { return "storage_bucket" }
	if strings.Contains(resourceName, "sql")       { return "cloud_sql" }
	if strings.Contains(resourceName, "serviceAccounts") { return "service_account" }
	if strings.Contains(resourceName, "subnetworks") { return "vpc_subnet" }
	if strings.Contains(resourceName, "cryptoKeys") { return "kms_key" }
	if strings.Contains(resourceName, "clusters")  { return "gke_cluster" }
	return "gcp_resource"
}

func resourceShortName(name string) string {
	if name == "" { return "—" }
	parts := strings.Split(name, "/")
	return parts[len(parts)-1]
}

func sccRemediation(category string) string {
	remediations := map[string]string{
		"OPEN_FIREWALL":              "Restrict firewall rules to specific IP ranges. Remove 0.0.0.0/0 source ranges.",
		"PUBLIC_BUCKET_ACL":         "Remove allUsers/allAuthenticatedUsers from bucket ACLs. Enable Public Access Prevention.",
		"PUBLIC_IP_ADDRESS":         "Remove public IP from VM. Use Cloud NAT + IAP for access.",
		"IAM_ADMIN_ROLES":           "Replace primitive roles with predefined roles following least privilege.",
		"OVER_PRIVILEGED_ACCOUNT":   "Review and reduce IAM permissions to minimum required.",
		"BUCKET_LOGGING_DISABLED":   "Enable storage access logging on the bucket.",
		"AUDIT_LOGGING_DISABLED":    "Enable DATA_READ/DATA_WRITE audit logs for this service in IAM → Audit Logs.",
		"LEGACY_AUTHORIZATION":      "Disable legacy authorization in GKE cluster settings.",
		"SQL_PUBLIC_IP":             "Disable public IP on Cloud SQL. Use Cloud SQL Auth Proxy or Private IP.",
		"SQL_NO_ROOT_PASSWORD":      "Set a strong root password on this Cloud SQL instance immediately.",
		"SQL_CONTAINED_DATABASE_AUTHENTICATION": "Disable contained database authentication flag.",
	}
	for key, rem := range remediations {
		if strings.Contains(strings.ToUpper(category), key) {
			return rem
		}
	}
	return "Review this finding in the GCP Security Command Center and follow the recommended remediation steps."
}

func sccMITRE(category, findingClass string) string {
	cat := strings.ToUpper(category)
	switch {
	case strings.Contains(cat, "FIREWALL") || strings.Contains(cat, "PUBLIC_IP"):
		return "T1190"
	case strings.Contains(cat, "IAM") || strings.Contains(cat, "PRIVILEGE") || strings.Contains(cat, "ACCOUNT"):
		return "T1078.004"
	case strings.Contains(cat, "BUCKET") || strings.Contains(cat, "STORAGE"):
		return "T1530"
	case strings.Contains(cat, "LOG") || strings.Contains(cat, "AUDIT"):
		return "T1562.008"
	case strings.Contains(cat, "KEY") || strings.Contains(cat, "KMS"):
		return "T1552"
	case findingClass == "THREAT":
		return "T1059"
	default:
		return ""
	}
}

func parseGCPServiceAccount(saJSON string, sa *gcpServiceAccount) error {
	return json.Unmarshal([]byte(saJSON), sa)
}


// ── SCC threat findings → detection events (G-11) ─────────────────────────────

// pullSCCThreatEvents turns ACTIVE, unmuted THREAT-class findings of medium
// severity or above into cloud.gcp_scc events so the C-SCC rules (and the
// alert pipeline) fire on Event Threat Detection / Container Threat
// Detection / VM Threat Detection, instead of threats only appearing as
// posture rows every 6 hours. Event IDs are derived from finding name +
// event time, so re-fetching the same finding is deduplicated at insert.
func pullSCCThreatEvents(ctx context.Context, token, projectID string, connID int64) ([]CloudEvent, error) {
	findings, _, err := fetchSCCFindingsFiltered(ctx, token, projectID,
		`state="ACTIVE" AND -mute="MUTED" AND finding_class="THREAT"`)
	if err != nil {
		return nil, err
	}
	var evs []CloudEvent
	for _, f := range findings {
		sev := 0
		switch strings.ToLower(f.Severity) {
		case "critical":
			sev = 5
		case "high":
			sev = 4
		case "medium":
			sev = 3
		default:
			continue
		}
		t := time.Now().UTC()
		for _, ts := range []string{f.EventTime, f.CreateTime} {
			if pt, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
				t = pt
				break
			}
		}
		sum := sha256.Sum256([]byte(f.Name + "|" + t.UTC().Format(time.RFC3339Nano)))
		raw, _ := json.Marshal(map[string]interface{}{
			"source":        "gcp_scc",
			"connector_id":  connID,
			"finding_name":  f.Name,
			"category":      f.Category,
			"finding_class": f.FindingClass,
			"severity":      f.Severity,
			"state":         f.State,
			"resource_name": f.ResourceName,
			"description":   f.Description,
			"external_uri":  f.ExternalURI,
			"indicator":     f.Indicator,
			"source_properties": f.SourceProperties,
		})
		ev := CloudEvent{
			ID:        "scc-" + hex.EncodeToString(sum[:8]),
			Time:      t,
			AgentID:   fmt.Sprintf("gcp-scc-%d", connID),
			Host:      projectID,
			OS:        "gcp",
			EventType: "cloud.gcp_scc",
			Severity:  sev,
			Source:    "gcp_scc",
			Username:  "",
			Raw:       raw,
		}
		if f.Indicator != nil && len(f.Indicator.IPAddresses) > 0 {
			ev.SrcIP = f.Indicator.IPAddresses[0]
		}
		evs = append(evs, ev)
	}
	return evs, nil
}
