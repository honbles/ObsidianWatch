package api

// cloud_gcp_cspm.go — GCP Cloud Security Posture Management — build v2
//
// Checks implemented:
//  1.  Firewall rules — 0.0.0.0/0 on risky ports (SSH, RDP, DB ports)
//  2.  IAM bindings — public bindings, primitive roles, external admin grants
//  3.  Storage buckets — public ACLs, uniform access, versioning, logging
//  4.  Compute VMs — OS Login, serial port, full-access scopes, public IPs
//  5.  Cloud SQL — public IP, 0.0.0.0/0, SSL, backups
//  6.  Audit logging — DATA_READ/WRITE for all critical GCP services
//  7.  Service accounts — key age >90 days, admin roles on external identities
//  8.  KMS key rotation — keys without rotation policy or rotation >90 days
//  9.  VPC flow logs — subnets without flow logging enabled
// 10.  Cloud DNS logging — DNS policies without logging enabled
// 11.  MFA/2SV enforcement — check org policy constraints

import (
	"log/slog"
	"crypto/sha256"
	"encoding/hex"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

// CSPMFinding represents a single misconfiguration finding
type CSPMFinding struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Severity     string    `json:"severity"` // critical, high, medium, low, info
	Category     string    `json:"category"` // iam, network, storage, compute, logging, sql, kms
	Resource     string    `json:"resource"`
	ResourceType string    `json:"resource_type"`
	Remediation  string    `json:"remediation"`
	MITRE        string    `json:"mitre"`
	Status       string    `json:"status"` // open, suppressed
	ScannedAt    time.Time `json:"scanned_at"`
}

// CSPMResult is the full scan result for a connector
type CSPMResult struct {
	ConnectorID   int64         `json:"connector_id"`
	ProjectID     string        `json:"project_id"`
	ScannedAt     time.Time     `json:"scanned_at"`
	Findings      []CSPMFinding `json:"findings"`
	TotalFindings int           `json:"total_findings"`
	Critical      int           `json:"critical"`
	High          int           `json:"high"`
	Medium        int           `json:"medium"`
	Low           int           `json:"low"`
	Passed        int           `json:"passed"`
	ScanDuration  string        `json:"scan_duration"`
	Errors        []string      `json:"errors,omitempty"`
	// SCC integration fields
	SCCEnabled    bool          `json:"scc_enabled"`
	SCCFindings   int           `json:"scc_findings"`
	SCCSources    []string      `json:"scc_sources,omitempty"`
	// G-36: checks that did not run, with the reason (coverage gaps).
	NotAssessed []NotAssessedCheck `json:"not_assessed,omitempty"`
}

// NotAssessedCheck records a posture check that was skipped or failed.
type NotAssessedCheck struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// gcpCSPMGet makes an authenticated GET to a GCP API and (G-35) follows
// nextPageToken, merging top-level array fields (and the "items" map used by
// aggregatedList) across pages so callers see the complete list.
func gcpCSPMGet(ctx context.Context, token, url string, out interface{}) error {
	if token == "" {
		return fmt.Errorf("no access token provided — authentication failed")
	}
	const maxPages = 20
	if strings.Contains(url, "iam.googleapis.com") &&
		strings.HasSuffix(strings.SplitN(url, "?", 2)[0], "/serviceAccounts") &&
		!strings.Contains(url, "pageSize=") {
		url += pageSep(url) + "pageSize=100"
	}
	var merged map[string]json.RawMessage
	pageToken := ""
	for page := 0; page < maxPages; page++ {
		u := url
		if pageToken != "" {
			u += pageSep(u) + "pageToken=" + neturl.QueryEscape(pageToken)
		}
		body, err := gcpCSPMGetRaw(ctx, token, u)
		if err != nil {
			return err
		}
		var cur map[string]json.RawMessage
		if err := json.Unmarshal(body, &cur); err != nil {
			// Not an object (or empty): fall back to direct decode, single page.
			return json.Unmarshal(body, out)
		}
		var next string
		if raw, ok := cur["nextPageToken"]; ok {
			json.Unmarshal(raw, &next)
		}
		if merged == nil {
			merged = cur
		} else {
			mergeGCPPage(merged, cur)
		}
		if next == "" {
			break
		}
		if page == maxPages-1 {
			// G-42: surface truncation instead of silently dropping resources.
			slog.Warn("gcp: result truncated at page limit", "max_pages", maxPages, "url", strings.SplitN(url, "?", 2)[0])
		}
		pageToken = next
	}
	delete(merged, "nextPageToken")
	buf, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, out)
}

func pageSep(u string) string {
	if strings.Contains(u, "?") {
		return "&"
	}
	return "?"
}

// mergeGCPPage appends array fields and merges the aggregatedList "items" map.
func mergeGCPPage(dst, src map[string]json.RawMessage) {
	for k, v := range src {
		if k == "nextPageToken" {
			continue
		}
		old, ok := dst[k]
		if !ok {
			dst[k] = v
			continue
		}
		var oa, na []json.RawMessage
		if json.Unmarshal(old, &oa) == nil && json.Unmarshal(v, &na) == nil {
			b, _ := json.Marshal(append(oa, na...))
			dst[k] = b
			continue
		}
		var om, nm map[string]json.RawMessage
		if k == "items" && json.Unmarshal(old, &om) == nil && json.Unmarshal(v, &nm) == nil {
			mergeGCPPage(om, nm)
			for nk, nv := range nm {
				if _, exists := om[nk]; !exists {
					om[nk] = nv
				}
			}
			b, _ := json.Marshal(om)
			dst[k] = b
		}
	}
}

// gcpCSPMGetRaw performs one authenticated GET and returns the body.
func gcpCSPMGetRaw(ctx context.Context, token, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 403 {
		msg := string(body)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("permission denied (403): %s", msg)
	}
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("not found (404)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body)[:minInt(200, len(body))])
	}
	return body, nil
}

func minInt(a, b int) int { if a < b { return a }; return b }

// RunGCPCSPM runs all CSPM checks for a GCP project
func RunGCPCSPM(ctx context.Context, saJSON, projectID string) (*CSPMResult, error) {
	start := time.Now()
	result := &CSPMResult{ProjectID: projectID, ScannedAt: start}

	var sa gcpServiceAccount
	if err := json.Unmarshal([]byte(saJSON), &sa); err != nil {
		return nil, fmt.Errorf("invalid service account JSON: %w", err)
	}
	if projectID == "" { projectID = sa.ProjectID }
	result.ProjectID = projectID

	token, err := getGCPTokenWithScope(ctx, sa, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil { return nil, fmt.Errorf("auth failed: %w\n\nMake sure the service account JSON is complete (includes token_uri, client_email, private_key) and the APIs are enabled in the project", err) }

	findings := []CSPMFinding{}
	passed := 0

	run := func(name string, fn func() ([]CSPMFinding, int, error)) {
		f, p, e := fn()
		if e != nil {
			result.Errors = append(result.Errors, name+": "+e.Error())
			result.NotAssessed = append(result.NotAssessed, NotAssessedCheck{Check: name, Reason: "check failed: " + e.Error()})
		} else {
			findings = append(findings, f...)
			passed += p
		}
	}

	run("firewall",         func() ([]CSPMFinding, int, error) { return checkFirewallRules(ctx, token, projectID) })
	run("iam",              func() ([]CSPMFinding, int, error) { return checkIAMBindings(ctx, token, projectID) })
	run("storage",          func() ([]CSPMFinding, int, error) { return checkStorageBuckets(ctx, token, projectID) })
	run("compute",          func() ([]CSPMFinding, int, error) { return checkComputeInstances(ctx, token, projectID) })
	run("sql",              func() ([]CSPMFinding, int, error) { return checkCloudSQL(ctx, token, projectID) })
	run("audit_logging",    func() ([]CSPMFinding, int, error) { return checkAuditLogging(ctx, token, projectID) })
	run("service_accounts", func() ([]CSPMFinding, int, error) { return checkServiceAccounts(ctx, token, projectID) })
	// Optional checks — skip silently if API not enabled in this project
	runOptional := func(name string, fn func() ([]CSPMFinding, int, error)) {
		f, p, e := fn()
		if e != nil {
			// 403 usually means API not enabled or missing role — skip silently
			// 404 means resource doesn't exist in this project — skip silently
			if strings.Contains(e.Error(), "403") || strings.Contains(e.Error(), "404") ||
				strings.Contains(e.Error(), "API not enabled") || strings.Contains(e.Error(), "disabled") {
				// G-36: never let a skipped check look like a clean result.
				reason := "API not enabled or not applicable in this project"
				if strings.Contains(e.Error(), "403") {
					reason = "permission denied or API disabled — grant the viewer role / enable the API"
				}
				result.NotAssessed = append(result.NotAssessed, NotAssessedCheck{Check: name, Reason: reason})
				return
			}
			result.Errors = append(result.Errors, name+": "+e.Error())
		} else {
			findings = append(findings, f...)
			passed += p
		}
	}
	runOptional("kms",            func() ([]CSPMFinding, int, error) { return checkKMSKeys(ctx, token, projectID) })
	runOptional("vpc_flow_logs",  func() ([]CSPMFinding, int, error) { return checkVPCFlowLogs(ctx, token, projectID) })
	runOptional("default_network", func() ([]CSPMFinding, int, error) { return checkDefaultNetwork(ctx, token, projectID) })
	runOptional("https_lb_tls", func() ([]CSPMFinding, int, error) { return checkHTTPSLBTLS(ctx, token, projectID) })
	runOptional("api_keys", func() ([]CSPMFinding, int, error) { return checkAPIKeys(ctx, token, projectID) })
	runOptional("vertex_workbench", func() ([]CSPMFinding, int, error) { return checkVertexWorkbench(ctx, token, projectID) })
	runOptional("dnssec", func() ([]CSPMFinding, int, error) { return checkDNSSEC(ctx, token, projectID) })
	runOptional("dns_logging",    func() ([]CSPMFinding, int, error) { return checkDNSLogging(ctx, token, projectID) })
	runOptional("gke",            func() ([]CSPMFinding, int, error) { return checkGKEClusters(ctx, token, projectID) })
	runOptional("bigquery",       func() ([]CSPMFinding, int, error) { return checkBigQuery(ctx, token, projectID) })
	runOptional("secret_manager", func() ([]CSPMFinding, int, error) { return checkSecretManager(ctx, token, projectID) })
	runOptional("org_policies",       func() ([]CSPMFinding, int, error) { return checkOrgPolicies(ctx, token, projectID) })
	runOptional("cloud_run",          func() ([]CSPMFinding, int, error) { return checkCloudRun(ctx, token, projectID) })
	runOptional("artifact_registry",  func() ([]CSPMFinding, int, error) { return checkArtifactRegistry(ctx, token, projectID) })
	runOptional("cloud_functions",    func() ([]CSPMFinding, int, error) { return checkCloudFunctions(ctx, token, projectID) })
	runOptional("pubsub",             func() ([]CSPMFinding, int, error) { return checkPubSub(ctx, token, projectID) })
	// Org-level IAM — works when SCC is enabled (SA has org visibility) or SA has resourcemanager.organizations.getIamPolicy
	runOptional("org_iam",            func() ([]CSPMFinding, int, error) { return checkOrgLevelIAM(ctx, token, projectID) })

	for i := range findings {
		// G-39: content-derived ID, stable across scans regardless of ordering.
		gsum := sha256.Sum256([]byte(projectID + "\x00" + findings[i].Title + "\x00" + findings[i].Resource))
		findings[i].ID = "gcp-" + hex.EncodeToString(gsum[:])[:12]
		findings[i].Status = "open"
		findings[i].ScannedAt = start
		switch findings[i].Severity {
		case "critical": result.Critical++
		case "high":     result.High++
		case "medium":   result.Medium++
		case "low":      result.Low++
		}
	}

	result.Findings = findings
	result.TotalFindings = len(findings)
	result.Passed = passed

	// ── Also pull from GCP Security Command Center if available ──────────────
	// SCC has 500+ built-in checks and threat detections beyond our manual checks.
	// If SCC API is not enabled or SA lacks permission, we gracefully skip it.
	sccResult, sccErr := RunSCC(ctx, saJSON, projectID)
	if sccErr == nil && sccResult != nil && sccResult.SCCEnabled {
		result = MergeWithSCC(result, sccResult)
		result.SCCEnabled = sccResult.SCCEnabled
		result.SCCFindings = sccResult.TotalFindings
		result.SCCSources = sccResult.Sources
	} else if sccErr == nil && sccResult != nil && !sccResult.SCCEnabled {
		// SCC not enabled - note it but don't error
		result.SCCEnabled = false
	} else if sccErr != nil {
		result.Errors = append(result.Errors, "scc (optional): "+sccErr.Error())
	}

	result.ScanDuration = time.Since(start).Round(time.Millisecond).String()
	return result, nil
}

func getGCPTokenWithScope(ctx context.Context, sa gcpServiceAccount, scope string) (string, error) {
	if sa.Type == "external_account" {
		return gcpExternalAccountToken(ctx, sa.gcpExternalAccount, scope)
	}
	if sa.TokenURI == "" {
		return "", fmt.Errorf("service account JSON is missing token_uri field")
	}
	if sa.ClientEmail == "" {
		return "", fmt.Errorf("service account JSON is missing client_email field")
	}
	if sa.PrivateKey == "" {
		return "", fmt.Errorf("service account JSON is missing private_key field")
	}
	jwt, err := gcpJWT(sa, scope)
	if err != nil { return "", fmt.Errorf("failed to create JWT: %w", err) }
	body := "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + jwt
	req, err := http.NewRequestWithContext(ctx, "POST", sa.TokenURI, strings.NewReader(body))
	if err != nil { return "", err }
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return "", fmt.Errorf("token request to %s failed: %w", sa.TokenURI, err) }
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("auth failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("token error: %s — %s", result.Error, result.ErrorDesc)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("token response did not contain an access_token (response: %s)", string(respBody)[:minInt(300, len(respBody))])
	}
	return result.AccessToken, nil
}

// ── 1. FIREWALL RULES ─────────────────────────────────────────────────────────
func checkFirewallRules(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/global/firewalls", projectID)
	var resp struct {
		Items []struct {
			Name         string   `json:"name"`
			Direction    string   `json:"direction"`
			Disabled     bool     `json:"disabled"`
			SourceRanges []string `json:"sourceRanges"`
			TargetTags   []string `json:"targetTags"`
			Allowed      []struct {
				IPProtocol string   `json:"IPProtocol"`
				Ports      []string `json:"ports"`
			} `json:"allowed"`
		} `json:"items"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil { return nil, 0, err }

	var findings []CSPMFinding
	passed := 0
	riskyPorts := map[string]struct{ label, sev string }{
		"22":    {"SSH", "critical"},
		"3389":  {"RDP", "critical"},
		"23":    {"Telnet", "high"},
		"3306":  {"MySQL", "high"},
		"5432":  {"PostgreSQL", "high"},
		"1433":  {"MSSQL", "high"},
		"27017": {"MongoDB", "high"},
		"6379":  {"Redis", "high"},
		"9200":  {"Elasticsearch", "high"},
		"2375":  {"Docker daemon (unauthenticated)", "critical"},
		"2376":  {"Docker daemon TLS", "high"},
		"8080":  {"HTTP Alt", "medium"},
		"8443":  {"HTTPS Alt", "medium"},
	}

	for _, fw := range resp.Items {
		if fw.Disabled || fw.Direction != "INGRESS" { continue }

		isOpenToAll := false
		for _, r := range fw.SourceRanges {
			if r == "0.0.0.0/0" || r == "::/0" { isOpenToAll = true; break }
		}
		if !isOpenToAll { passed++; continue }

		for _, allow := range fw.Allowed {
			if allow.IPProtocol == "all" {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Firewall '%s' allows ALL traffic from internet", fw.Name),
					Description:  "This firewall rule allows all protocols and all ports from 0.0.0.0/0. Any service on any port is reachable from the internet.",
					Severity:     "critical",
					Category:     "network",
					Resource:     fw.Name,
					ResourceType: "firewall_rule",
					Remediation:  "Restrict source ranges to specific IPs. Delete catch-all allow rules. Use IAP for admin access.",
					MITRE:        "T1190",
				})
				continue
			}
			for _, port := range allow.Ports {
				// Handle port ranges like "0-65535"
				if strings.Contains(port, "-") {
					parts := strings.SplitN(port, "-", 2)
					if parts[0] == "0" || parts[0] == "1" {
						findings = append(findings, CSPMFinding{
							Title:        fmt.Sprintf("Firewall '%s' allows all ports (%s) from internet", fw.Name, port),
							Description:  fmt.Sprintf("Port range %s open to 0.0.0.0/0 effectively allows all traffic.", port),
							Severity:     "critical",
							Category:     "network",
							Resource:     fw.Name,
							ResourceType: "firewall_rule",
							Remediation:  "Replace wide port ranges with specific port allowances for required services only.",
							MITRE:        "T1190",
						})
					}
					continue
				}
				if info, risky := riskyPorts[port]; risky {
					findings = append(findings, CSPMFinding{
						Title:        fmt.Sprintf("Firewall '%s' exposes %s (port %s) to internet", fw.Name, info.label, port),
						Description:  fmt.Sprintf("Port %s (%s) is open to 0.0.0.0/0. Anyone can attempt connections from the internet.", port, info.label),
						Severity:     info.sev,
						Category:     "network",
						Resource:     fw.Name,
						ResourceType: "firewall_rule",
						Remediation:  fmt.Sprintf("Restrict port %s to known IP ranges. Use Cloud IAP or a VPN for %s access.", port, info.label),
						MITRE:        "T1190",
					})
				} else { passed++ }
			}
		}
	}
	return findings, passed, nil
}

// ── 2. IAM BINDINGS ───────────────────────────────────────────────────────────
func checkIAMBindings(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s:getIamPolicy", projectID)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, 0, err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 { return nil, 0, fmt.Errorf("IAM API %d: %s", resp.StatusCode, string(body)[:minInt(200, len(body))]) }

	var policy struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	json.Unmarshal(body, &policy)

	var findings []CSPMFinding
	passed := 0

	primitiveRoles := map[string]string{
		"roles/owner":  "Owner (full control)",
		"roles/editor": "Editor (read/write all resources)",
	}
	adminRoles := map[string]string{
		"roles/iam.securityAdmin":                    "Security Admin",
		"roles/resourcemanager.projectIamAdmin":      "IAM Admin",
		"roles/iam.serviceAccountAdmin":              "Service Account Admin",
		"roles/compute.admin":                        "Compute Admin",
		"roles/storage.admin":                        "Storage Admin",
		"roles/cloudsql.admin":                       "Cloud SQL Admin",
	}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			// Public bindings — anyone on internet
			if member == "allUsers" || member == "allAuthenticatedUsers" {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("IAM role '%s' granted to %s (public)", binding.Role, member),
					Description:  fmt.Sprintf("The role %s is granted to %s — anyone on the internet has this access.", binding.Role, member),
					Severity:     "critical",
					Category:     "iam",
					Resource:     binding.Role,
					ResourceType: "iam_binding",
					Remediation:  "Remove allUsers/allAuthenticatedUsers from all IAM bindings immediately.",
					MITRE:        "T1078.004",
				})
				continue
			}

			// Primitive roles (owner/editor) on any identity
			if label, isPrimitive := primitiveRoles[binding.Role]; isPrimitive {
				sev := "high"
				if binding.Role == "roles/owner" { sev = "critical" }
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Primitive role '%s' assigned to %s", label, member),
					Description:  fmt.Sprintf("Primitive roles grant overly broad permissions. %s has %s on the entire project.", member, label),
					Severity:     sev,
					Category:     "iam",
					Resource:     member,
					ResourceType: "iam_binding",
					Remediation:  "Replace primitive roles with predefined roles that grant only necessary permissions (principle of least privilege).",
					MITRE:        "T1078.004",
				})
				continue
			}

			// Admin roles granted to external identities (outside the org)
			if label, isAdmin := adminRoles[binding.Role]; isAdmin {
				isExternal := strings.HasPrefix(member, "user:") || strings.HasPrefix(member, "group:")
				if isExternal {
					findings = append(findings, CSPMFinding{
						Title:        fmt.Sprintf("Admin role '%s' granted to external identity: %s", label, member),
						Description:  fmt.Sprintf("%s has been granted the %s role. Admin roles should be granted only to internal service accounts, not external users/groups.", member, label),
						Severity:     "high",
						Category:     "iam",
						Resource:     member,
						ResourceType: "iam_binding",
						Remediation:  "Review whether this admin access is necessary. Use service accounts with minimal permissions for automation.",
						MITRE:        "T1078.004",
					})
					continue
				}
			}
			passed++
		}
	}
	// ── Privilege escalation: SA impersonation chains ────────────────────────
	// Build map: serviceAccount email → roles it holds
	saRoles := map[string][]string{} // sa email → roles
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if strings.HasPrefix(member, "serviceAccount:") {
				email := strings.TrimPrefix(member, "serviceAccount:")
				saRoles[email] = append(saRoles[email], binding.Role)
			}
		}
	}
	// Roles that allow impersonating / acting-as another SA
	impersonationRoles := map[string]bool{
		"roles/iam.serviceAccountTokenCreator": true,
		"roles/iam.serviceAccountUser":         true,
		"roles/iam.workloadIdentityUser":        true,
	}
	// High-privilege roles that make a SA a valuable target
	highPrivRoles := map[string]bool{
		"roles/owner":                                  true,
		"roles/editor":                                 true,
		"roles/iam.securityAdmin":                      true,
		"roles/resourcemanager.projectIamAdmin":        true,
		"roles/iam.serviceAccountAdmin":                true,
	}
	for _, binding := range policy.Bindings {
		if !impersonationRoles[binding.Role] { continue }
		for _, member := range binding.Members {
			// Find all SAs that this member can impersonate (any SA in the project)
			for targetSA, targetRoles := range saRoles {
				_ = targetSA
				for _, r := range targetRoles {
					if highPrivRoles[r] {
						findings = append(findings, CSPMFinding{
							Title:        fmt.Sprintf("Privilege escalation path: %s can impersonate high-privilege SA", member),
							Description:  fmt.Sprintf("%s has %s, allowing it to act as a service account that holds '%s'. This creates a privilege escalation path — the identity can gain elevated access without being directly granted high-privilege roles.", member, binding.Role, r),
							Severity:     "critical",
							Category:     "iam",
							Resource:     member,
							ResourceType: "iam_binding",
							Remediation:  "Remove iam.serviceAccountTokenCreator/User from identities that do not explicitly require SA impersonation. Audit all SA impersonation grants regularly.",
							MITRE:        "T1548.005",
						})
						break
					}
				}
			}
		}
	}

	// ── Cross-project SA access (lateral movement path) ───────────────────
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if !strings.HasPrefix(member, "serviceAccount:") { continue }
			email := strings.TrimPrefix(member, "serviceAccount:")
			if !strings.Contains(email, ".iam.gserviceaccount.com") { continue }
			parts := strings.Split(email, "@")
			if len(parts) != 2 { continue }
			saProject := strings.TrimSuffix(parts[1], ".iam.gserviceaccount.com")
			if saProject != "" && saProject != projectID {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Cross-project SA '%s' has role '%s' in this project", email, binding.Role),
					Description:  fmt.Sprintf("Service account from project '%s' has '%s' in project '%s'. Cross-project SA grants create implicit trust — compromise of the source project yields access here.", saProject, binding.Role, projectID),
					Severity:     "medium",
					Category:     "iam",
					Resource:     email,
					ResourceType: "iam_binding",
					Remediation:  "Review cross-project SA grants. Prefer Workload Identity Federation with explicit audience restrictions.",
					MITRE:        "T1078.004",
				})
			}
		}
	}

	return findings, passed, nil
}

// ── 3. STORAGE BUCKETS ────────────────────────────────────────────────────────
func checkStorageBuckets(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s&projection=full", projectID)
	var resp struct {
		Items []struct {
			Name string `json:"name"`
			IamConfiguration struct {
				UniformBucketLevelAccess struct { Enabled bool `json:"enabled"` } `json:"uniformBucketLevelAccess"`
				PublicAccessPrevention   string `json:"publicAccessPrevention"`
			} `json:"iamConfiguration"`
			Acl []struct {
				Entity string `json:"entity"`
				Role   string `json:"role"`
			} `json:"acl"`
			DefaultObjectAcl []struct {
				Entity string `json:"entity"`
			} `json:"defaultObjectAcl"`
			Versioning struct { Enabled bool `json:"enabled"` } `json:"versioning"`
			Logging    struct { LogBucket string `json:"logBucket"` } `json:"logging"`
			RetentionPolicy *struct {
				RetentionPeriod string `json:"retentionPeriod"`
			} `json:"retentionPolicy"`
		} `json:"items"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil { return nil, 0, err }

	var findings []CSPMFinding
	passed := 0

	for _, bucket := range resp.Items {
		bucketPassed := true

		// Public ACL check
		for _, acl := range bucket.Acl {
			if acl.Entity == "allUsers" || acl.Entity == "allAuthenticatedUsers" {
				sev := "critical"
				if acl.Entity == "allAuthenticatedUsers" { sev = "high" }
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Storage bucket '%s' is publicly accessible (%s)", bucket.Name, acl.Entity),
					Description:  fmt.Sprintf("Bucket ACL grants %s access to %s. All objects in this bucket may be readable/writable by the public.", acl.Role, acl.Entity),
					Severity:     sev,
					Category:     "storage",
					Resource:     bucket.Name,
					ResourceType: "gcs_bucket",
					Remediation:  "Enable Public Access Prevention and remove allUsers/allAuthenticatedUsers from bucket ACLs immediately.",
					MITRE:        "T1530",
				})
				bucketPassed = false
			}
		}

		// Default object ACL check
		for _, acl := range bucket.DefaultObjectAcl {
			if acl.Entity == "allUsers" || acl.Entity == "allAuthenticatedUsers" {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Storage bucket '%s' default object ACL grants public access", bucket.Name),
					Description:  fmt.Sprintf("New objects uploaded to this bucket are automatically accessible by %s.", acl.Entity),
					Severity:     "critical",
					Category:     "storage",
					Resource:     bucket.Name,
					ResourceType: "gcs_bucket",
					Remediation:  "Remove public default object ACLs. Enable uniform bucket-level access.",
					MITRE:        "T1530",
				})
				bucketPassed = false
			}
		}

		// Public Access Prevention not enforced
		pap := bucket.IamConfiguration.PublicAccessPrevention
		if pap == "" || pap == "inherited" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Bucket '%s' does not enforce Public Access Prevention", bucket.Name),
				Description:  "Public Access Prevention is set to 'inherited' or not configured. An IAM change could accidentally make this bucket public.",
				Severity:     "medium",
				Category:     "storage",
				Resource:     bucket.Name,
				ResourceType: "gcs_bucket",
				Remediation:  "Set publicAccessPrevention to 'enforced' on all buckets not intentionally public.",
				MITRE:        "T1530",
			})
			bucketPassed = false
		}

		// Uniform bucket-level access
		if !bucket.IamConfiguration.UniformBucketLevelAccess.Enabled {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Bucket '%s' does not use uniform bucket-level access", bucket.Name),
				Description:  "Object-level ACLs are enabled. This allows inconsistent access control — individual objects can be more permissive than the bucket.",
				Severity:     "low",
				Category:     "storage",
				Resource:     bucket.Name,
				ResourceType: "gcs_bucket",
				Remediation:  "Enable uniform bucket-level access to enforce consistent IAM policies across all objects.",
				MITRE:        "T1530",
			})
			bucketPassed = false
		}

		// Versioning
		if !bucket.Versioning.Enabled {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Bucket '%s' has object versioning disabled", bucket.Name),
				Description:  "Without versioning, deleted or overwritten objects cannot be recovered. This increases ransomware and accidental deletion risk.",
				Severity:     "low",
				Category:     "storage",
				Resource:     bucket.Name,
				ResourceType: "gcs_bucket",
				Remediation:  "Enable object versioning on buckets containing important data.",
				MITRE:        "T1485",
			})
			bucketPassed = false
		}

		// Access logging
		if bucket.Logging.LogBucket == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Bucket '%s' does not have access logging enabled", bucket.Name),
				Description:  "Access logging is not configured. There is no record of who read or modified objects in this bucket.",
				Severity:     "medium",
				Category:     "logging",
				Resource:     bucket.Name,
				ResourceType: "gcs_bucket",
				Remediation:  "Enable bucket access logs and send them to a dedicated logging bucket.",
				MITRE:        "T1562.008",
			})
			bucketPassed = false
		}

		if bucketPassed { passed++ }
	}
	return findings, passed, nil
}

// ── 4. COMPUTE INSTANCES ──────────────────────────────────────────────────────
func checkComputeInstances(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/aggregated/instances", projectID)
	var resp struct {
		Items map[string]struct {
			Instances []struct {
				Name   string `json:"name"`
				Zone   string `json:"zone"`
				Status string `json:"status"`
				NetworkInterfaces []struct {
					AccessConfigs []struct {
						NatIP string `json:"natIP"`
						Type  string `json:"type"`
					} `json:"accessConfigs"`
				} `json:"networkInterfaces"`
				Disks []struct {
					DiskEncryptionKey *struct{} `json:"diskEncryptionKey"`
					Boot              bool      `json:"boot"`
				} `json:"disks"`
				Metadata struct {
					Items []struct {
						Key   string `json:"key"`
						Value string `json:"value"`
					} `json:"items"`
				} `json:"metadata"`
				ServiceAccounts []struct {
					Email  string   `json:"email"`
					Scopes []string `json:"scopes"`
				} `json:"serviceAccounts"`
				ShieldedInstanceConfig struct {
					EnableVtpm               bool `json:"enableVtpm"`
					EnableIntegrityMonitoring bool `json:"enableIntegrityMonitoring"`
				} `json:"shieldedInstanceConfig"`
			} `json:"instances"`
		} `json:"items"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil { return nil, 0, err }

	var findings []CSPMFinding
	passed := 0

	for _, zone := range resp.Items {
		for _, vm := range zone.Instances {
			if vm.Status != "RUNNING" { continue }
			vmPassed := true
			zoneName := vm.Zone[strings.LastIndex(vm.Zone, "/")+1:]

			// OS Login
			osLoginEnabled := false
			serialPortEnabled := false
			for _, meta := range vm.Metadata.Items {
				if meta.Key == "enable-oslogin" && strings.ToLower(meta.Value) == "true" { osLoginEnabled = true }
				if meta.Key == "serial-port-enable" && meta.Value == "true" { serialPortEnabled = true }
			}
			if !osLoginEnabled {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("VM '%s' does not have OS Login enabled", vm.Name),
					Description:  "OS Login is not enabled. SSH keys stored in instance metadata are harder to audit and rotate than OS Login managed keys.",
					Severity:     "medium",
					Category:     "compute",
					Resource:     fmt.Sprintf("%s (%s)", vm.Name, zoneName),
					ResourceType: "compute_instance",
					Remediation:  "Set 'enable-oslogin=TRUE' in project metadata to enforce OS Login across all VMs.",
					MITRE:        "T1078",
				})
				vmPassed = false
			}
			if serialPortEnabled {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("VM '%s' has serial port access enabled", vm.Name),
					Description:  "Serial port access allows interactive console connections and can be used to bypass firewall rules.",
					Severity:     "high",
					Category:     "compute",
					Resource:     fmt.Sprintf("%s (%s)", vm.Name, zoneName),
					ResourceType: "compute_instance",
					Remediation:  "Disable serial port access: set 'serial-port-enable=false' in instance metadata.",
					MITRE:        "T1133",
				})
				vmPassed = false
			}

			// Public IP
			hasPublicIP := false
			for _, nic := range vm.NetworkInterfaces {
				for _, ac := range nic.AccessConfigs {
					if ac.NatIP != "" { hasPublicIP = true; break }
				}
			}
			if hasPublicIP {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("VM '%s' has a public IP address", vm.Name),
					Description:  "This VM is directly reachable from the internet. Any open firewall rules increase attack surface significantly.",
					Severity:     "medium",
					Category:     "compute",
					Resource:     fmt.Sprintf("%s (%s)", vm.Name, zoneName),
					ResourceType: "compute_instance",
					Remediation:  "Remove public IPs where possible. Use Cloud NAT for outbound traffic and IAP for SSH/RDP access.",
					MITRE:        "T1190",
				})
				vmPassed = false
			}

			// Full-access service account scope
			for _, sa := range vm.ServiceAccounts {
				for _, scope := range sa.Scopes {
					if scope == "https://www.googleapis.com/auth/cloud-platform" {
						findings = append(findings, CSPMFinding{
							Title:        fmt.Sprintf("VM '%s' uses cloud-platform (full access) scope", vm.Name),
							Description:  fmt.Sprintf("Service account %s uses the cloud-platform scope which grants full GCP API access. A compromised VM gets full project access.", sa.Email),
							Severity:     "high",
							Category:     "compute",
							Resource:     fmt.Sprintf("%s (%s)", vm.Name, zoneName),
							ResourceType: "compute_instance",
							Remediation:  "Use a dedicated service account with minimal IAM roles. Replace cloud-platform scope with specific API scopes.",
							MITRE:        "T1078.004",
						})
						vmPassed = false
					}
				}
			}

			// Shielded VM
			if !vm.ShieldedInstanceConfig.EnableVtpm || !vm.ShieldedInstanceConfig.EnableIntegrityMonitoring {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("VM '%s' does not have Shielded VM fully enabled", vm.Name),
					Description:  "Shielded VM (vTPM + Integrity Monitoring) is not fully enabled. This reduces boot integrity guarantees.",
					Severity:     "low",
					Category:     "compute",
					Resource:     fmt.Sprintf("%s (%s)", vm.Name, zoneName),
					ResourceType: "compute_instance",
					Remediation:  "Enable Shielded VM with vTPM and Integrity Monitoring for all production VMs.",
					MITRE:        "T1542",
				})
				vmPassed = false
			}

			if vmPassed { passed++ }
		}
	}
	return findings, passed, nil
}

// ── 5. CLOUD SQL ──────────────────────────────────────────────────────────────
func checkCloudSQL(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://sqladmin.googleapis.com/sql/v1beta4/projects/%s/instances", projectID)
	var resp struct {
		Items []struct {
			Name            string `json:"name"`
			DatabaseVersion string `json:"databaseVersion"`
			Settings        struct {
				IpConfiguration struct {
					Ipv4Enabled        bool `json:"ipv4Enabled"`
					RequireSsl         bool `json:"requireSsl"`
					AuthorizedNetworks []struct {
						Value string `json:"value"`
						Name  string `json:"name"`
					} `json:"authorizedNetworks"`
					PrivateNetwork string `json:"privateNetwork"`
				} `json:"ipConfiguration"`
				BackupConfiguration struct {
					Enabled                    bool `json:"enabled"`
					PointInTimeRecoveryEnabled bool `json:"pointInTimeRecoveryEnabled"`
				} `json:"backupConfiguration"`
				DatabaseFlags []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"databaseFlags"`
			} `json:"settings"`
		} `json:"items"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil { return nil, 0, err }

	var findings []CSPMFinding
	passed := 0

	for _, instance := range resp.Items {
		instancePassed := true
		cfg := instance.Settings.IpConfiguration

		// Public IP + 0.0.0.0/0
		if cfg.Ipv4Enabled {
			for _, net := range cfg.AuthorizedNetworks {
				if net.Value == "0.0.0.0/0" {
					findings = append(findings, CSPMFinding{
						Title:        fmt.Sprintf("Cloud SQL '%s' is accessible from any IP (0.0.0.0/0)", instance.Name),
						Description:  "The database allows connections from 0.0.0.0/0. Anyone on the internet can attempt to authenticate.",
						Severity:     "critical",
						Category:     "sql",
						Resource:     instance.Name,
						ResourceType: "cloud_sql",
						Remediation:  "Remove 0.0.0.0/0 from authorized networks. Use Cloud SQL Auth Proxy or Private IP connections.",
						MITRE:        "T1190",
					})
					instancePassed = false
				}
			}
			// SSL not required
			if !cfg.RequireSsl {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Cloud SQL '%s' does not require SSL/TLS", instance.Name),
					Description:  "SSL is not enforced. Database credentials and query results can be intercepted in transit.",
					Severity:     "high",
					Category:     "sql",
					Resource:     instance.Name,
					ResourceType: "cloud_sql",
					Remediation:  "Enable 'Require SSL' in Cloud SQL → Connections. Regenerate server and client certificates.",
					MITRE:        "T1040",
				})
				instancePassed = false
			}
		}

		// No Private IP (public only)
		if cfg.Ipv4Enabled && cfg.PrivateNetwork == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Cloud SQL '%s' uses public IP only (no private IP)", instance.Name),
				Description:  "This database has only a public IP and no private VPC connection. It should be accessible only via Private IP.",
				Severity:     "medium",
				Category:     "sql",
				Resource:     instance.Name,
				ResourceType: "cloud_sql",
				Remediation:  "Configure a Private IP for the Cloud SQL instance and disable the public IP.",
				MITRE:        "T1190",
			})
			instancePassed = false
		}

		// Backups
		if !instance.Settings.BackupConfiguration.Enabled {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Cloud SQL '%s' has automated backups disabled", instance.Name),
				Description:  "Automated backups are not enabled. Data loss from corruption, deletion, or ransomware cannot be recovered.",
				Severity:     "medium",
				Category:     "sql",
				Resource:     instance.Name,
				ResourceType: "cloud_sql",
				Remediation:  "Enable automated backups and point-in-time recovery for all production databases.",
				MITRE:        "T1485",
			})
			instancePassed = false
		}

		// Check database flags for dangerous settings
		for _, flag := range instance.Settings.DatabaseFlags {
			if flag.Name == "log_checkpoints" && flag.Value == "off" {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Cloud SQL '%s' has log_checkpoints disabled", instance.Name),
					Description:  "Database checkpoint logging is disabled, reducing audit trail.",
					Severity:     "low",
					Category:     "sql",
					Resource:     instance.Name,
					ResourceType: "cloud_sql",
					Remediation:  "Enable log_checkpoints flag in Cloud SQL database flags.",
					MITRE:        "T1562.008",
				})
				instancePassed = false
			}
		}

		if instancePassed { passed++ }
	}
	return findings, passed, nil
}

// ── 6. AUDIT LOGGING ──────────────────────────────────────────────────────────
// Checks DATA_READ and DATA_WRITE audit logs for ALL critical GCP services,
// not just iam and sqladmin.
func checkAuditLogging(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s:getIamPolicy", projectID)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(`{"options":{"requestedPolicyVersion":3}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, 0, err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 { return nil, 0, fmt.Errorf("IAM policy API %d", resp.StatusCode) }

	var policy struct {
		AuditConfigs []struct {
			Service         string `json:"service"`
			AuditLogConfigs []struct {
				LogType         string   `json:"logType"`
				ExemptedMembers []string `json:"exemptedMembers"`
			} `json:"auditLogConfigs"`
		} `json:"auditConfigs"`
	}
	json.Unmarshal(body, &policy)

	// Services that must have DATA_READ + DATA_WRITE audit logging
	criticalServices := []struct{ svc, label string }{
		{"storage.googleapis.com",              "Cloud Storage"},
		{"sqladmin.googleapis.com",             "Cloud SQL"},
		{"iam.googleapis.com",                  "IAM"},
		{"compute.googleapis.com",              "Compute Engine"},
		{"cloudkms.googleapis.com",             "Cloud KMS"},
		{"container.googleapis.com",            "Google Kubernetes Engine"},
		{"bigquery.googleapis.com",             "BigQuery"},
		{"secretmanager.googleapis.com",        "Secret Manager"},
		{"cloudresourcemanager.googleapis.com", "Resource Manager"},
	}

	// Build map of service → log types enabled
	enabledLogs := map[string]map[string]bool{}
	for _, ac := range policy.AuditConfigs {
		if enabledLogs[ac.Service] == nil {
			enabledLogs[ac.Service] = map[string]bool{}
		}
		for _, lc := range ac.AuditLogConfigs {
			enabledLogs[ac.Service][lc.LogType] = true
		}
	}

	var findings []CSPMFinding
	passed := 0

	for _, svc := range criticalServices {
		logs := enabledLogs[svc.svc]
		dataRead := logs["DATA_READ"]
		dataWrite := logs["DATA_WRITE"]

		if !dataRead && !dataWrite {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Audit logging not enabled for %s", svc.label),
				Description:  fmt.Sprintf("Neither DATA_READ nor DATA_WRITE audit logs are configured for %s. Read/write operations on sensitive resources are not recorded.", svc.svc),
				Severity:     "medium",
				Category:     "logging",
				Resource:     svc.svc,
				ResourceType: "audit_config",
				Remediation:  fmt.Sprintf("Enable DATA_READ and DATA_WRITE audit logs for %s via IAM → Audit Logs.", svc.label),
				MITRE:        "T1562.008",
			})
		} else if !dataRead || !dataWrite {
			missing := "DATA_READ"
			if !dataWrite { missing = "DATA_WRITE" }
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Incomplete audit logging for %s (missing %s)", svc.label, missing),
				Description:  fmt.Sprintf("%s audit log type is not configured for %s.", missing, svc.svc),
				Severity:     "low",
				Category:     "logging",
				Resource:     svc.svc,
				ResourceType: "audit_config",
				Remediation:  fmt.Sprintf("Enable %s audit logs for %s.", missing, svc.label),
				MITRE:        "T1562.008",
			})
		} else {
			passed++
		}
	}

	// ── Log sink export check — ensure at least one sink exports outside project ──
	sinksURL := fmt.Sprintf("https://logging.googleapis.com/v2/projects/%s/sinks", projectID)
	var sinksResp struct {
		Sinks []struct {
			Name        string `json:"name"`
			Destination string `json:"destination"` // storage.googleapis.com/bucket, bigquery.googleapis.com/..., pubsub.googleapis.com/...
			Filter      string `json:"filter"`
			Disabled    bool   `json:"disabled"`
		} `json:"sinks"`
	}
	if err := gcpCSPMGet(ctx, token, sinksURL, &sinksResp); err == nil {
		hasExportSink := false
		hasUnfilteredSink := false
		for _, sink := range sinksResp.Sinks {
			if sink.Disabled { continue }
			// Any sink to storage, bigquery, or pubsub is an export
			if strings.Contains(sink.Destination, "storage.googleapis.com") ||
				strings.Contains(sink.Destination, "bigquery.googleapis.com") ||
				strings.Contains(sink.Destination, "pubsub.googleapis.com") {
				hasExportSink = true
			}
			if sink.Filter == "" || sink.Filter == "true" {
				hasUnfilteredSink = true
			}
		}
		if !hasExportSink {
			findings = append(findings, CSPMFinding{
				Title:        "No log sink exports audit logs to external destination",
				Description:  "No active log sink exports to Cloud Storage, BigQuery, or Pub/Sub. Audit logs are only available in Cloud Logging with a default 30-day retention. If an attacker deletes logs, there is no external copy.",
				Severity:     "high",
				Category:     "logging",
				Resource:     projectID,
				ResourceType: "log_sink",
				Remediation:  "Create a log sink to Cloud Storage (for long-term archive) or BigQuery (for analysis) with no filter to export all audit logs. Target retention: ≥365 days.",
				MITRE:        "T1562.008",
			})
		} else if !hasUnfilteredSink {
			findings = append(findings, CSPMFinding{
				Title:        "Log sinks use filters — some audit events may not be exported",
				Description:  "All configured log sinks have filter expressions. Filtered sinks may miss audit events that fall outside the filter criteria. An unfiltered sink ensures complete log retention.",
				Severity:     "medium",
				Category:     "logging",
				Resource:     projectID,
				ResourceType: "log_sink",
				Remediation:  "Add an unfiltered log sink (no filter expression) to capture all log entries including future new service audit events.",
				MITRE:        "T1562.008",
			})
		} else {
			passed++
		}
	}

	return findings, passed, nil
}
func checkServiceAccounts(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://iam.googleapis.com/v1/projects/%s/serviceAccounts", projectID)
	var resp struct {
		Accounts []struct {
			Name        string `json:"name"`
			Email       string `json:"email"`
			Disabled    bool   `json:"disabled"`
			DisplayName string `json:"displayName"`
		} `json:"accounts"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil { return nil, 0, err }

	var findings []CSPMFinding
	passed := 0

	for _, sa := range resp.Accounts {
		if sa.Disabled { continue }
		saPassed := true

		// Check user-managed keys and their age
		keysURL := fmt.Sprintf("https://iam.googleapis.com/v1/%s/keys?keyTypes=USER_MANAGED", sa.Name)
		var keysResp struct {
			Keys []struct {
				Name           string `json:"name"`
				ValidAfterTime string `json:"validAfterTime"`
				KeyAlgorithm   string `json:"keyAlgorithm"`
			} `json:"keys"`
		}
		if err := gcpCSPMGet(ctx, token, keysURL, &keysResp); err == nil {
			for _, key := range keysResp.Keys {
				// Flag any user-managed key older than 90 days
				if key.ValidAfterTime != "" {
					created, err := time.Parse(time.RFC3339, key.ValidAfterTime)
					if err == nil {
						ageDays := int(time.Since(created).Hours() / 24)
						if ageDays > 60 {
							sev := "low"
							if ageDays > 90  { sev = "medium" }
							if ageDays > 180 { sev = "high" }
							findings = append(findings, CSPMFinding{
								Title:        fmt.Sprintf("Service account '%s' has a key older than %d days", sa.Email, ageDays),
								Description:  fmt.Sprintf("User-managed key created %d days ago. Long-lived keys increase the risk of compromise through leakage or theft. Keys should be rotated every 90 days at most.", ageDays),
								Severity:     sev,
								Category:     "iam",
								Resource:     sa.Email,
								ResourceType: "service_account_key",
								Remediation:  "Rotate service account keys every 90 days. Better yet, use Workload Identity Federation to eliminate long-lived keys entirely.",
								MITRE:        "T1552.004",
							})
							saPassed = false
						}
					}
				}

				// Default SA should have no user-managed keys at all
				defaultSAPatterns := []string{"compute@developer", "appspot.gserviceaccount"}
				isDefault := false
				for _, pat := range defaultSAPatterns {
					if strings.Contains(sa.Email, pat) { isDefault = true; break }
				}
				if isDefault {
					findings = append(findings, CSPMFinding{
						Title:        fmt.Sprintf("Default service account '%s' has a user-managed key", sa.Email),
						Description:  "Default service accounts should not have user-managed keys. These are difficult to rotate and create persistent access risks if leaked.",
						Severity:     "high",
						Category:     "iam",
						Resource:     sa.Email,
						ResourceType: "service_account_key",
						Remediation:  "Delete user-managed keys from default service accounts. Use Workload Identity or short-lived tokens.",
						MITRE:        "T1552.004",
					})
					saPassed = false
				}
			}
		}

		if saPassed { passed++ }
	}
	return findings, passed, nil
}

// ── 8. KMS KEY ROTATION ───────────────────────────────────────────────────────
func checkKMSKeys(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	// List key rings first
	locationsURL := fmt.Sprintf("https://cloudkms.googleapis.com/v1/projects/%s/locations", projectID)
	var locsResp struct {
		Locations []struct {
			LocationID string `json:"locationId"`
		} `json:"locations"`
	}
	if err := gcpCSPMGet(ctx, token, locationsURL, &locsResp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, loc := range locsResp.Locations {
		ringsURL := fmt.Sprintf("https://cloudkms.googleapis.com/v1/projects/%s/locations/%s/keyRings", projectID, loc.LocationID)
		var ringsResp struct {
			KeyRings []struct { Name string `json:"name"` } `json:"keyRings"`
		}
		if err := gcpCSPMGet(ctx, token, ringsURL, &ringsResp); err != nil { continue }

		for _, ring := range ringsResp.KeyRings {
			keysURL := ring.Name + "/cryptoKeys"
			var keysResp struct {
				CryptoKeys []struct {
					Name            string `json:"name"`
					Purpose         string `json:"purpose"`
					RotationPeriod  string `json:"rotationPeriod"`
					NextRotationTime string `json:"nextRotationTime"`
					Primary         struct {
						State      string `json:"state"`
						CreateTime string `json:"createTime"`
					} `json:"primary"`
				} `json:"cryptoKeys"`
			}
			if err := gcpCSPMGet(ctx, token, "https://cloudkms.googleapis.com/v1/"+keysURL, &keysResp); err != nil { continue }

			for _, key := range keysResp.CryptoKeys {
				if key.Purpose != "ENCRYPT_DECRYPT" { continue }
				keyName := key.Name[strings.LastIndex(key.Name, "/")+1:]
				keyPassed := true

				// No rotation policy
				if key.RotationPeriod == "" {
					findings = append(findings, CSPMFinding{
						Title:        fmt.Sprintf("KMS key '%s' has no rotation policy", keyName),
						Description:  "This Cloud KMS encryption key has no automatic rotation configured. Keys should be rotated at least every 90 days.",
						Severity:     "medium",
						Category:     "kms",
						Resource:     key.Name,
						ResourceType: "kms_key",
						Remediation:  "Set a rotation period of 90 days or less on all ENCRYPT_DECRYPT keys in Cloud KMS.",
						MITRE:        "T1552",
					})
					keyPassed = false
				} else {
					// Check if rotation period is > 90 days (in seconds)
					// RotationPeriod is like "7776000s" (90 days)
					periodSecs := 0
					fmt.Sscanf(strings.TrimSuffix(key.RotationPeriod, "s"), "%d", &periodSecs)
					if periodSecs > 90*24*3600 {
						days := periodSecs / 86400
						findings = append(findings, CSPMFinding{
							Title:        fmt.Sprintf("KMS key '%s' rotation period is %d days (>90 days)", keyName, days),
							Description:  fmt.Sprintf("Key rotation is configured but at %d days, which exceeds the recommended 90-day maximum.", days),
							Severity:     "low",
							Category:     "kms",
							Resource:     key.Name,
							ResourceType: "kms_key",
							Remediation:  "Reduce the key rotation period to 90 days or less.",
							MITRE:        "T1552",
						})
						keyPassed = false
					}
				}

				if keyPassed { passed++ }
			}
		}
	}
	return findings, passed, nil
}

// ── 9. VPC FLOW LOGS ──────────────────────────────────────────────────────────
func checkVPCFlowLogs(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/aggregated/subnetworks", projectID)
	var resp struct {
		Items map[string]struct {
			Subnetworks []struct {
				Name               string `json:"name"`
				Region             string `json:"region"`
				EnableFlowLogs     bool   `json:"enableFlowLogs"`
				LogConfig          *struct {
					Enable bool `json:"enable"`
				} `json:"logConfig"`
				Purpose            string `json:"purpose"`
				PrivateIpGoogleAccess bool `json:"privateIpGoogleAccess"`
			} `json:"subnetworks"`
		} `json:"items"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil { return nil, 0, err }

	var findings []CSPMFinding
	passed := 0

	for _, region := range resp.Items {
		for _, subnet := range region.Subnetworks {
			// Skip proxy-only and managed subnets
			if subnet.Purpose == "REGIONAL_MANAGED_PROXY" ||
				subnet.Purpose == "GLOBAL_MANAGED_PROXY" ||
				subnet.Purpose == "INTERNAL_HTTPS_LOAD_BALANCER" {
				continue
			}

			flowLogsEnabled := subnet.EnableFlowLogs
			if subnet.LogConfig != nil { flowLogsEnabled = subnet.LogConfig.Enable }
			regionName := subnet.Region[strings.LastIndex(subnet.Region, "/")+1:]

			if !flowLogsEnabled {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Subnet '%s' (%s) does not have VPC flow logs enabled", subnet.Name, regionName),
					Description:  "VPC flow logs are not enabled on this subnet. Network traffic to and from VMs on this subnet is not recorded, making it impossible to investigate network incidents.",
					Severity:     "medium",
					Category:     "logging",
					Resource:     fmt.Sprintf("%s (%s)", subnet.Name, regionName),
					ResourceType: "vpc_subnet",
					Remediation:  "Enable VPC flow logs on all subnets. Set sampling rate to at least 0.5 and include metadata.",
					MITRE:        "T1562.008",
				})
			} else {
				passed++
			}
		}
	}
	return findings, passed, nil
}

// ── 10. CLOUD DNS LOGGING ──────────────────────────────────────────────────────
func checkDNSLogging(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	// Get all managed zones
	zonesURL := fmt.Sprintf("https://dns.googleapis.com/dns/v1/projects/%s/managedZones", projectID)
	var zonesResp struct {
		ManagedZones []struct {
			Name string `json:"name"`
			DNSName string `json:"dnsName"`
		} `json:"managedZones"`
	}
	if err := gcpCSPMGet(ctx, token, zonesURL, &zonesResp); err != nil {
		return nil, 0, err
	}

	// Get DNS policies
	policiesURL := fmt.Sprintf("https://dns.googleapis.com/dns/v1/projects/%s/policies", projectID)
	var policiesResp struct {
		Policies []struct {
			Name         string `json:"name"`
			EnableLogging bool  `json:"enableLogging"`
			Networks     []struct {
				NetworkURL string `json:"networkURL"`
			} `json:"networks"`
		} `json:"policies"`
	}
	_ = gcpCSPMGet(ctx, token, policiesURL, &policiesResp)

	var findings []CSPMFinding
	passed := 0

	// Check if any DNS policy has logging enabled
	loggingEnabled := false
	for _, policy := range policiesResp.Policies {
		if policy.EnableLogging { loggingEnabled = true; break }
	}

	if len(zonesResp.ManagedZones) > 0 && !loggingEnabled {
		findings = append(findings, CSPMFinding{
			Title:        "Cloud DNS logging is not enabled",
			Description:  fmt.Sprintf("This project has %d managed DNS zones but no DNS policy with logging enabled. DNS queries are not being recorded, which makes it impossible to detect DNS-based data exfiltration or C2 communication.", len(zonesResp.ManagedZones)),
			Severity:     "medium",
			Category:     "logging",
			Resource:     projectID,
			ResourceType: "dns_policy",
			Remediation:  "Create a Cloud DNS policy with logging enabled and attach it to all VPC networks. This captures DNS query logs for security analysis.",
			MITRE:        "T1071.004",
		})
	} else if loggingEnabled {
		passed++
	}

	return findings, passed, nil
}

// ── 11. GKE CLUSTERS ──────────────────────────────────────────────────────────
func checkGKEClusters(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/-/clusters", projectID)
	var resp struct {
		Clusters []struct {
			Name                  string `json:"name"`
			Location              string `json:"location"`
			CurrentMasterVersion  string `json:"currentMasterVersion"`
			LegacyAbac            struct{ Enabled bool `json:"enabled"` } `json:"legacyAbac"`
			NetworkPolicy         struct{ Enabled bool `json:"enabled"` } `json:"networkPolicy"`
			MasterAuthorizedNetworksConfig struct {
				Enabled bool `json:"enabled"`
			} `json:"masterAuthorizedNetworksConfig"`
			PrivateClusterConfig struct {
				EnablePrivateNodes    bool `json:"enablePrivateNodes"`
				EnablePrivateEndpoint bool `json:"enablePrivateEndpoint"`
			} `json:"privateClusterConfig"`
			WorkloadIdentityConfig struct {
				WorkloadPool string `json:"workloadPool"`
			} `json:"workloadIdentityConfig"`
			NodePools []struct {
				Name   string `json:"name"`
				Config struct {
					OauthScopes    []string `json:"oauthScopes"`
					ServiceAccount string   `json:"serviceAccount"`
					ShieldedInstanceConfig struct {
						EnableSecureBoot          bool `json:"enableSecureBoot"`
						EnableIntegrityMonitoring bool `json:"enableIntegrityMonitoring"`
					} `json:"shieldedInstanceConfig"`
				} `json:"config"`
				Management struct {
					AutoUpgrade bool `json:"autoUpgrade"`
					AutoRepair  bool `json:"autoRepair"`
				} `json:"management"`
			} `json:"nodePools"`
			DatabaseEncryption struct{ State string `json:"state"` } `json:"databaseEncryption"`
			EnableKubernetesAlpha bool `json:"enableKubernetesAlpha"`
			BinaryAuthorization struct {
				EvaluationMode string `json:"evaluationMode"` // DISABLED, PROJECT_SINGLETON_POLICY_ENFORCE
			} `json:"binaryAuthorization"`
			ReleaseChannel struct {
				Channel string `json:"channel"` // RAPID, REGULAR, STABLE, UNSPECIFIED
			} `json:"releaseChannel"`
			NetworkConfig struct {
				EnableIntraNodeVisibility bool `json:"enableIntraNodeVisibility"`
			} `json:"networkConfig"`
			MonitoringConfig struct {
				ComponentConfig struct {
					EnableComponents []string `json:"enableComponents"`
				} `json:"componentConfig"`
			} `json:"monitoringConfig"`
		} `json:"clusters"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, cluster := range resp.Clusters {
		name := fmt.Sprintf("%s/%s", cluster.Location, cluster.Name)

		if cluster.LegacyAbac.Enabled {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("GKE cluster '%s': Legacy ABAC enabled", name),
				Description:  "Legacy ABAC (Attribute-Based Access Control) is enabled. It overrides RBAC policies and grants broad permissions, undermining fine-grained access control.",
				Severity:     "high",
				Category:     "compute",
				Resource:     name,
				ResourceType: "gke_cluster",
				Remediation:  "Disable legacy ABAC: gcloud container clusters update <CLUSTER> --no-enable-legacy-authorization",
				MITRE:        "T1078.004",
			})
		} else { passed++ }

		if !cluster.NetworkPolicy.Enabled {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("GKE cluster '%s': Network policy not enabled", name),
				Description:  "No Kubernetes NetworkPolicy is enforced. All pods can communicate freely, enabling lateral movement if a pod is compromised.",
				Severity:     "medium",
				Category:     "network",
				Resource:     name,
				ResourceType: "gke_cluster",
				Remediation:  "Enable network policy: gcloud container clusters update <CLUSTER> --enable-network-policy",
				MITRE:        "T1210",
			})
		} else { passed++ }

		if !cluster.MasterAuthorizedNetworksConfig.Enabled {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("GKE cluster '%s': Master authorized networks not configured", name),
				Description:  "The Kubernetes API server is accessible from any IP address. Restricting access to known CIDRs reduces the attack surface.",
				Severity:     "high",
				Category:     "network",
				Resource:     name,
				ResourceType: "gke_cluster",
				Remediation:  "Configure authorized networks: gcloud container clusters update <CLUSTER> --enable-master-authorized-networks --master-authorized-networks <CIDR>",
				MITRE:        "T1190",
			})
		} else { passed++ }

		if !cluster.PrivateClusterConfig.EnablePrivateNodes {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("GKE cluster '%s': Nodes have public IPs", name),
				Description:  "Cluster nodes are not configured as private. Public IPs on nodes expose them directly to the internet.",
				Severity:     "medium",
				Category:     "network",
				Resource:     name,
				ResourceType: "gke_cluster",
				Remediation:  "Use private nodes to ensure nodes only have internal IP addresses.",
				MITRE:        "T1190",
			})
		} else { passed++ }

		if cluster.WorkloadIdentityConfig.WorkloadPool == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("GKE cluster '%s': Workload Identity not enabled", name),
				Description:  "Workload Identity is not enabled. Without it, pods use the node service account, which may have overly broad permissions and creates a lateral movement risk.",
				Severity:     "medium",
				Category:     "iam",
				Resource:     name,
				ResourceType: "gke_cluster",
				Remediation:  "Enable Workload Identity to bind Kubernetes service accounts to GCP service accounts with minimal permissions.",
				MITRE:        "T1078.004",
			})
		} else { passed++ }

		if cluster.DatabaseEncryption.State != "ENCRYPTED" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("GKE cluster '%s': etcd not encrypted with customer-managed key", name),
				Description:  "Kubernetes secrets stored in etcd are not encrypted with a customer-managed encryption key (CMEK). Application-layer secrets encryption adds a layer of defense.",
				Severity:     "low",
				Category:     "kms",
				Resource:     name,
				ResourceType: "gke_cluster",
				Remediation:  "Enable application-layer secrets encryption with a Cloud KMS key.",
				MITRE:        "T1552.001",
			})
		} else { passed++ }

		for _, np := range cluster.NodePools {
			if !np.Management.AutoUpgrade {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("GKE cluster '%s', node pool '%s': Auto-upgrade disabled", name, np.Name),
					Description:  "Node auto-upgrade is disabled. Nodes may run outdated Kubernetes versions with known vulnerabilities.",
					Severity:     "medium",
					Category:     "compute",
					Resource:     fmt.Sprintf("%s/nodePools/%s", name, np.Name),
					ResourceType: "gke_node_pool",
					Remediation:  "Enable auto-upgrade for all node pools to keep nodes on a supported Kubernetes version.",
					MITRE:        "T1190",
				})
			} else { passed++ }
			// Check for default SA or cloud-platform scope
			for _, scope := range np.Config.OauthScopes {
				if scope == "https://www.googleapis.com/auth/cloud-platform" {
					findings = append(findings, CSPMFinding{
						Title:        fmt.Sprintf("GKE cluster '%s', node pool '%s': Full cloud-platform scope", name, np.Name),
						Description:  "Nodes have the full cloud-platform OAuth scope, granting access to all GCP APIs. This is overly permissive.",
						Severity:     "high",
						Category:     "iam",
						Resource:     fmt.Sprintf("%s/nodePools/%s", name, np.Name),
						ResourceType: "gke_node_pool",
						Remediation:  "Use Workload Identity and restrict node OAuth scopes to only those APIs the nodes need directly.",
						MITRE:        "T1078.004",
					})
					break
				}
			}
			if np.Config.ServiceAccount == "default" || np.Config.ServiceAccount == "" {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("GKE cluster '%s', node pool '%s': Using default Compute service account", name, np.Name),
					Description:  "Node pool uses the default Compute Engine service account, which has broad Editor permissions across the project.",
					Severity:     "high",
					Category:     "iam",
					Resource:     fmt.Sprintf("%s/nodePools/%s", name, np.Name),
					ResourceType: "gke_node_pool",
					Remediation:  "Create a dedicated, minimally-permissioned service account for this node pool.",
					MITRE:        "T1078.004",
				})
			}

			// Auto-repair check
			if !np.Management.AutoRepair {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("GKE cluster '%s', node pool '%s': Auto-repair disabled", name, np.Name),
					Description:  "Node auto-repair is disabled. Unhealthy nodes are not automatically replaced, leading to degraded cluster capacity and potential security gaps from misconfigured nodes.",
					Severity:     "low",
					Category:     "compute",
					Resource:     fmt.Sprintf("%s/nodePools/%s", name, np.Name),
					ResourceType: "gke_node_pool",
					Remediation:  "Enable auto-repair for all node pools to ensure unhealthy nodes are automatically recreated.",
					MITRE:        "T1499",
				})
			}
		}

		// Binary Authorization check
		if cluster.BinaryAuthorization.EvaluationMode != "PROJECT_SINGLETON_POLICY_ENFORCE" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("GKE cluster '%s': Binary Authorization not enforced", name),
				Description:  "Binary Authorization is not set to enforcement mode. Without it, any container image — including unscanned, unsigned, or malicious images — can be deployed to this cluster. This is the primary supply chain control for GKE.",
				Severity:     "high",
				Category:     "compute",
				Resource:     name,
				ResourceType: "gke_cluster",
				Remediation:  "Enable Binary Authorization in enforcement mode and create attestation policies requiring images to be scanned and signed before deployment.",
				MITRE:        "T1195.001",
			})
		} else { passed++ }

		// Release channel — RAPID in production is risky
		if cluster.ReleaseChannel.Channel == "UNSPECIFIED" || cluster.ReleaseChannel.Channel == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("GKE cluster '%s': Not enrolled in a release channel", name),
				Description:  "The cluster is not enrolled in a GKE release channel. Without a channel, automatic security patch upgrades are not applied. Clusters on manual versions accumulate CVEs over time.",
				Severity:     "medium",
				Category:     "compute",
				Resource:     name,
				ResourceType: "gke_cluster",
				Remediation:  "Enroll the cluster in the REGULAR or STABLE release channel to receive automatic security patches.",
				MITRE:        "T1190",
			})
		} else if cluster.ReleaseChannel.Channel == "RAPID" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("GKE cluster '%s': On RAPID release channel (pre-production only)", name),
				Description:  "The RAPID channel receives new Kubernetes versions before they are production-ready. It is intended for testing only and may introduce instability or unvalidated security changes.",
				Severity:     "low",
				Category:     "compute",
				Resource:     name,
				ResourceType: "gke_cluster",
				Remediation:  "Move production clusters to REGULAR or STABLE release channel.",
				MITRE:        "T1190",
			})
		} else { passed++ }

		// Intranode visibility — needed for VPC flow logs to capture pod traffic
		if !cluster.NetworkConfig.EnableIntraNodeVisibility {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("GKE cluster '%s': Intranode visibility disabled", name),
				Description:  "Intranode visibility is off. Traffic between pods on the same node bypasses VPC flow logs entirely, creating a blind spot for network forensics and east-west threat detection.",
				Severity:     "low",
				Category:     "logging",
				Resource:     name,
				ResourceType: "gke_cluster",
				Remediation:  "Enable intranode visibility so all pod-to-pod traffic is captured in VPC flow logs.",
				MITRE:        "T1562.008",
			})
		} else { passed++ }
	}
	return findings, passed, nil
}

// ── 12. BIGQUERY ──────────────────────────────────────────────────────────────
func checkBigQuery(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://bigquery.googleapis.com/bigquery/v2/projects/%s/datasets", projectID)
	var resp struct {
		Datasets []struct {
			DatasetReference struct {
				DatasetID string `json:"datasetId"`
				ProjectID string `json:"projectId"`
			} `json:"datasetReference"`
		} `json:"datasets"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, ds := range resp.Datasets {
		dsID := ds.DatasetReference.DatasetID
		// Get full dataset metadata including ACL and encryption
		detailURL := fmt.Sprintf("https://bigquery.googleapis.com/bigquery/v2/projects/%s/datasets/%s", projectID, dsID)
		var detail struct {
			Access []struct {
				Role         string `json:"role"`
				SpecialGroup string `json:"specialGroup"`
				UserByEmail  string `json:"userByEmail"`
				GroupByEmail string `json:"groupByEmail"`
			} `json:"access"`
			DefaultEncryptionConfiguration struct {
				KmsKeyName string `json:"kmsKeyName"`
			} `json:"defaultEncryptionConfiguration"`
		}
		if err := gcpCSPMGet(ctx, token, detailURL, &detail); err != nil {
			continue
		}

		publicAccess := false
		for _, acl := range detail.Access {
			if acl.SpecialGroup == "allUsers" || acl.SpecialGroup == "allAuthenticatedUsers" {
				publicAccess = true
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("BigQuery dataset '%s': Public access (%s)", dsID, acl.SpecialGroup),
					Description:  fmt.Sprintf("Dataset '%s' is accessible to %s. This exposes potentially sensitive data to anyone on the internet.", dsID, acl.SpecialGroup),
					Severity:     "critical",
					Category:     "storage",
					Resource:     fmt.Sprintf("%s:%s", projectID, dsID),
					ResourceType: "bigquery_dataset",
					Remediation:  "Remove allUsers/allAuthenticatedUsers from the dataset ACL immediately.",
					MITRE:        "T1530",
				})
			}
		}
		if !publicAccess { passed++ }

		if detail.DefaultEncryptionConfiguration.KmsKeyName == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("BigQuery dataset '%s': No customer-managed encryption key", dsID),
				Description:  "Dataset uses Google-managed encryption. Customer-managed keys (CMEK) provide additional control over data access and the ability to revoke access by disabling the key.",
				Severity:     "low",
				Category:     "kms",
				Resource:     fmt.Sprintf("%s:%s", projectID, dsID),
				ResourceType: "bigquery_dataset",
				Remediation:  "Configure a Cloud KMS key as the default encryption key for the dataset.",
				MITRE:        "T1552.001",
			})
		} else { passed++ }

		// Check for no row-level access policies (informational — indicates no fine-grained data control)
		rlsURL := fmt.Sprintf("https://bigquery.googleapis.com/bigquery/v2/projects/%s/datasets/%s/tables", projectID, dsID)
		var tablesResp struct {
			Tables []struct {
				TableReference struct{ TableID string `json:"tableId"` } `json:"tableReference"`
			} `json:"tables"`
		}
		_ = gcpCSPMGet(ctx, token, rlsURL, &tablesResp)
		if len(tablesResp.Tables) > 5 {
			// Large dataset with no row-level security check — note it
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("BigQuery dataset '%s': Row-level security not verified (%d tables)", dsID, len(tablesResp.Tables)),
				Description:  fmt.Sprintf("Dataset '%s' has %d tables. Row-level security policies were not found. Without row-level access controls, all users with dataset access can read all rows.", dsID, len(tablesResp.Tables)),
				Severity:     "info",
				Category:     "storage",
				Resource:     fmt.Sprintf("%s:%s", projectID, dsID),
				ResourceType: "bigquery_dataset",
				Remediation:  "Review whether row-level security policies are needed to limit data access based on user identity.",
				MITRE:        "T1530",
			})
		}
	}
	return findings, passed, nil
}

// ── 13. SECRET MANAGER ────────────────────────────────────────────────────────
func checkSecretManager(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets", projectID)
	var resp struct {
		Secrets []struct {
			Name       string            `json:"name"`
			Labels     map[string]string `json:"labels"`
			Replication struct {
				Automatic *struct{} `json:"automatic"`
				UserManaged *struct {
					Replicas []struct {
						CustomerManagedEncryption *struct {
							KmsKeyName string `json:"kmsKeyName"`
						} `json:"customerManagedEncryption"`
					} `json:"replicas"`
				} `json:"userManaged"`
			} `json:"replication"`
			Rotation *struct {
				NextRotationTime string `json:"nextRotationTime"`
				RotationPeriod   string `json:"rotationPeriod"`
			} `json:"rotation"`
		} `json:"secrets"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, secret := range resp.Secrets {
		parts := strings.Split(secret.Name, "/")
		shortName := secret.Name
		if len(parts) > 0 { shortName = parts[len(parts)-1] }

		// Check for public IAM on the secret
		iamURL := fmt.Sprintf("https://secretmanager.googleapis.com/v1/%s:getIamPolicy", secret.Name)
		var iamResp struct {
			Bindings []struct {
				Role    string   `json:"role"`
				Members []string `json:"members"`
			} `json:"bindings"`
		}
		if err := gcpCSPMGet(ctx, token, iamURL, &iamResp); err == nil {
			for _, binding := range iamResp.Bindings {
				for _, member := range binding.Members {
					if member == "allUsers" || member == "allAuthenticatedUsers" {
						findings = append(findings, CSPMFinding{
							Title:        fmt.Sprintf("Secret '%s': Public IAM access (%s)", shortName, member),
							Description:  fmt.Sprintf("The secret '%s' has IAM role '%s' granted to %s. This exposes sensitive secret data to anyone.", shortName, binding.Role, member),
							Severity:     "critical",
							Category:     "storage",
							Resource:     secret.Name,
							ResourceType: "secret",
							Remediation:  "Remove allUsers/allAuthenticatedUsers from all Secret Manager IAM policies immediately.",
							MITRE:        "T1552.001",
						})
					}
				}
			}
		}

		// Check rotation policy
		if secret.Rotation == nil {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Secret '%s': No rotation policy configured", shortName),
				Description:  "This secret has no automatic rotation policy. Long-lived secrets increase the risk of compromise going undetected.",
				Severity:     "medium",
				Category:     "storage",
				Resource:     secret.Name,
				ResourceType: "secret",
				Remediation:  "Configure a rotation schedule and a Pub/Sub topic to trigger rotation. Target rotation period: 90 days or less.",
				MITRE:        "T1552.001",
			})
		} else { passed++ }

		// Check CMEK
		cmekConfigured := false
		if secret.Replication.UserManaged != nil {
			for _, replica := range secret.Replication.UserManaged.Replicas {
				if replica.CustomerManagedEncryption != nil && replica.CustomerManagedEncryption.KmsKeyName != "" {
					cmekConfigured = true
					break
				}
			}
		}
		if !cmekConfigured {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Secret '%s': No customer-managed encryption key", shortName),
				Description:  "Secret is encrypted with Google-managed keys. CMEK provides the ability to revoke access to all secret versions by disabling the KMS key.",
				Severity:     "low",
				Category:     "kms",
				Resource:     secret.Name,
				ResourceType: "secret",
				Remediation:  "Configure a Cloud KMS key for customer-managed encryption on this secret.",
				MITRE:        "T1552.001",
			})
		} else { passed++ }
	}

	// Check for excessive number of enabled versions (potential secret sprawl)
	for _, secret := range resp.Secrets {
		parts := strings.Split(secret.Name, "/")
		shortName := secret.Name
		if len(parts) > 0 { shortName = parts[len(parts)-1] }

		versionsURL := fmt.Sprintf("https://secretmanager.googleapis.com/v1/%s/versions?filter=state%%3DENABLED", secret.Name)
		var versResp struct {
			Versions []struct{ Name string `json:"name"` } `json:"versions"`
		}
		if err := gcpCSPMGet(ctx, token, versionsURL, &versResp); err == nil {
			if len(versResp.Versions) > 3 {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Secret '%s': %d enabled versions (excessive)", shortName, len(versResp.Versions)),
					Description:  fmt.Sprintf("Secret '%s' has %d active versions. Excessive enabled versions increase exposure — old secret values remain accessible to anyone with secretAccessor permission.", shortName, len(versResp.Versions)),
					Severity:     "low",
					Category:     "storage",
					Resource:     secret.Name,
					ResourceType: "secret",
					Remediation:  "Disable all secret versions except the latest. Implement version cleanup as part of your rotation procedure.",
					MITRE:        "T1552.001",
				})
			} else { passed++ }
		}
	}

	return findings, passed, nil
}

// ── 14. ORG POLICIES ──────────────────────────────────────────────────────────
func checkOrgPolicies(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	// Key org policy constraints and their security impact
	type policyCheck struct {
		Constraint  string
		Title       string
		Description string
		Remediation string
		Severity    string
		MITRE       string
		WantEnforce bool // true = finding if NOT enforced
	}
	checks := []policyCheck{
		{
			Constraint:  "constraints/iam.disableServiceAccountKeyCreation",
			Title:       "Service account key creation not restricted",
			Description: "User-managed service account keys can be created. These long-lived credentials are a common attack vector. The org policy constraint/iam.disableServiceAccountKeyCreation should be enforced.",
			Remediation: "Enable constraints/iam.disableServiceAccountKeyCreation at the project or org level. Use Workload Identity instead of key files.",
			Severity:    "high",
			MITRE:       "T1552.004",
			WantEnforce: true,
		},
		{
			Constraint:  "constraints/compute.requireOsLogin",
			Title:       "OS Login not enforced on Compute instances",
			Description: "The requireOsLogin constraint is not enforced. SSH keys can be set per-instance or per-project without OS Login, making it harder to track and revoke SSH access centrally.",
			Remediation: "Enforce constraints/compute.requireOsLogin to use IAM for SSH access management.",
			Severity:    "medium",
			MITRE:       "T1078.004",
			WantEnforce: true,
		},
		{
			Constraint:  "constraints/compute.restrictPublicIpAccess",
			Title:       "Public IP creation not restricted",
			Description: "No org policy restricts creation of public IP addresses on Compute instances. Any project member with Compute permissions can create internet-facing VMs.",
			Remediation: "Enforce constraints/compute.restrictPublicIpAccess or use VPC Service Controls to limit public IP creation.",
			Severity:    "medium",
			MITRE:       "T1190",
			WantEnforce: true,
		},
		{
			Constraint:  "constraints/storage.uniformBucketLevelAccess",
			Title:       "Uniform bucket-level access not enforced",
			Description: "The org policy constraints/storage.uniformBucketLevelAccess is not enforced. Buckets can use legacy ACLs in addition to IAM, creating complex permission models that are difficult to audit.",
			Remediation: "Enforce constraints/storage.uniformBucketLevelAccess to disable legacy ACLs across all buckets.",
			Severity:    "low",
			MITRE:       "T1530",
			WantEnforce: true,
		},
		{
			Constraint:  "constraints/iam.allowedPolicyMemberDomains",
			Title:       "IAM domain restriction not configured",
			Description: "No org policy restricts which domains can be granted IAM roles. External identities from any domain can be added to IAM policies.",
			Remediation: "Configure constraints/iam.allowedPolicyMemberDomains to restrict IAM grants to your organization's domain(s).",
			Severity:    "high",
			MITRE:       "T1078.004",
			WantEnforce: true,
		},
	}

	var findings []CSPMFinding
	passed := 0

	for _, check := range checks {
		url := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s:getEffectiveOrgPolicy", projectID)
		reqBody := fmt.Sprintf(`{"constraint": "%s"}`, check.Constraint)
		req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(reqBody))
		if err != nil { continue }
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil { continue }
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 403 || resp.StatusCode == 404 {
			// Not accessible — skip silently
			continue
		}

		var policy struct {
			BooleanPolicy *struct {
				Enforced bool `json:"enforced"`
			} `json:"booleanPolicy"`
			ListPolicy *struct {
				AllowedValues []string `json:"allowedValues"`
				DeniedValues  []string `json:"deniedValues"`
				AllValues     string   `json:"allValues"`
			} `json:"listPolicy"`
			RestoreDefault *struct{} `json:"restoreDefault"`
		}
		if err := json.Unmarshal(body, &policy); err != nil { continue }

		enforced := false
		if policy.BooleanPolicy != nil {
			enforced = policy.BooleanPolicy.Enforced
		} else if policy.ListPolicy != nil && len(policy.ListPolicy.AllowedValues) > 0 {
			enforced = true
		} else if policy.RestoreDefault != nil {
			enforced = false
		}

		if check.WantEnforce && !enforced {
			findings = append(findings, CSPMFinding{
				Title:        check.Title,
				Description:  check.Description,
				Severity:     check.Severity,
				Category:     "iam",
				Resource:     projectID,
				ResourceType: "org_policy",
				Remediation:  check.Remediation,
				MITRE:        check.MITRE,
			})
		} else {
			passed++
		}
	}
	return findings, passed, nil
}

// ── CLOUD RUN ────────────────────────────────────────────────────────────────
func checkCloudRun(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://run.googleapis.com/v2/projects/%s/locations/-/services", projectID)
	var resp struct {
		Services []struct {
			Name   string `json:"name"`
			Labels map[string]string `json:"labels"`
			Ingress string `json:"ingress"` // INGRESS_TRAFFIC_ALL, INGRESS_TRAFFIC_INTERNAL_ONLY, INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER
			Template struct {
				ServiceAccount string `json:"serviceAccount"`
				Containers []struct {
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"template"`
		} `json:"services"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, svc := range resp.Services {
		shortName := svc.Name[strings.LastIndex(svc.Name, "/")+1:]
		svcClean := true

		// Check IAM policy for allUsers (unauthenticated invocations)
		iamURL := fmt.Sprintf("https://run.googleapis.com/v2/%s:getIamPolicy", svc.Name)
		var iamResp struct {
			Bindings []struct {
				Role    string   `json:"role"`
				Members []string `json:"members"`
			} `json:"bindings"`
		}
		if err := gcpCSPMGet(ctx, token, iamURL, &iamResp); err == nil {
			for _, b := range iamResp.Bindings {
				if b.Role == "roles/run.invoker" {
					for _, m := range b.Members {
						if m == "allUsers" || m == "allAuthenticatedUsers" {
							sev := "critical"
							if m == "allAuthenticatedUsers" { sev = "high" }
							findings = append(findings, CSPMFinding{
								Title:        fmt.Sprintf("Cloud Run service '%s' allows unauthenticated invocations (%s)", shortName, m),
								Description:  fmt.Sprintf("The Cloud Run service grants roles/run.invoker to %s — anyone on the internet can invoke this service without authentication. This is the highest-severity serverless misconfiguration.", m),
								Severity:     sev,
								Category:     "compute",
								Resource:     shortName,
								ResourceType: "cloud_run_service",
								Remediation:  "Remove allUsers/allAuthenticatedUsers from roles/run.invoker. Require authentication via Google identity or use Cloud Endpoints/API Gateway for controlled access.",
								MITRE:        "T1190",
							})
							svcClean = false
						}
					}
				}
			}
		}

		// Ingress check — INGRESS_TRAFFIC_ALL means public internet can reach it
		if svc.Ingress == "INGRESS_TRAFFIC_ALL" || svc.Ingress == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Cloud Run service '%s' ingress allows all traffic (internet-facing)", shortName),
				Description:  "Ingress is set to allow all traffic from the internet. Services that only need internal or load-balancer access should restrict ingress to reduce attack surface.",
				Severity:     "medium",
				Category:     "compute",
				Resource:     shortName,
				ResourceType: "cloud_run_service",
				Remediation:  "Set ingress to INGRESS_TRAFFIC_INTERNAL_ONLY or INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER unless the service must be publicly accessible.",
				MITRE:        "T1190",
			})
			svcClean = false
		}

		// Default compute SA check
		if strings.Contains(svc.Template.ServiceAccount, "-compute@developer.gserviceaccount.com") ||
			svc.Template.ServiceAccount == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Cloud Run service '%s' uses default Compute service account", shortName),
				Description:  "The service runs as the default Compute Engine service account which has Editor-level permissions across the project. A compromised service gets full project access.",
				Severity:     "high",
				Category:     "iam",
				Resource:     shortName,
				ResourceType: "cloud_run_service",
				Remediation:  "Create a dedicated service account with only the IAM roles this service actually requires.",
				MITRE:        "T1078.004",
			})
			svcClean = false
		}

		if svcClean { passed++ }
	}
	return findings, passed, nil
}

// ── ARTIFACT REGISTRY / GCR ──────────────────────────────────────────────────
func checkArtifactRegistry(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://artifactregistry.googleapis.com/v1/projects/%s/locations/-/repositories", projectID)
	var resp struct {
		Repositories []struct {
			Name   string `json:"name"`
			Format string `json:"format"` // DOCKER, MAVEN, NPM, etc.
			KmsKeyName string `json:"kmsKeyName"`
		} `json:"repositories"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, repo := range resp.Repositories {
		shortName := repo.Name[strings.LastIndex(repo.Name, "/")+1:]
		repoClean := true

		// Check IAM for public access
		iamURL := fmt.Sprintf("https://artifactregistry.googleapis.com/v1/%s:getIamPolicy", repo.Name)
		var iamResp struct {
			Bindings []struct {
				Role    string   `json:"role"`
				Members []string `json:"members"`
			} `json:"bindings"`
		}
		if err := gcpCSPMGet(ctx, token, iamURL, &iamResp); err == nil {
			for _, b := range iamResp.Bindings {
				for _, m := range b.Members {
					if m == "allUsers" || m == "allAuthenticatedUsers" {
						findings = append(findings, CSPMFinding{
							Title:        fmt.Sprintf("Artifact Registry '%s' is publicly accessible (%s)", shortName, m),
							Description:  fmt.Sprintf("Registry %s grants access to %s. Public registries allow anyone to pull (and potentially push) container images, enabling supply chain attacks.", shortName, m),
							Severity:     "critical",
							Category:     "storage",
							Resource:     shortName,
							ResourceType: "artifact_registry",
							Remediation:  "Remove allUsers/allAuthenticatedUsers from all Artifact Registry IAM bindings. Use private registries with explicit IAM grants.",
							MITRE:        "T1195.001",
						})
						repoClean = false
					}
				}
			}
		}

		// CMEK check for DOCKER repositories
		if repo.Format == "DOCKER" && repo.KmsKeyName == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Artifact Registry '%s' (Docker) has no customer-managed encryption key", shortName),
				Description:  "Docker image layers are encrypted with Google-managed keys. CMEK provides control over key lifecycle and the ability to revoke access to all stored images.",
				Severity:     "low",
				Category:     "kms",
				Resource:     shortName,
				ResourceType: "artifact_registry",
				Remediation:  "Configure a Cloud KMS key for this Artifact Registry repository.",
				MITRE:        "T1552.001",
			})
			repoClean = false
		}

		if repoClean { passed++ }
	}
	return findings, passed, nil
}

// ── CLOUD FUNCTIONS ──────────────────────────────────────────────────────────
func checkCloudFunctions(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	// Cloud Functions Gen2 uses run.googleapis.com under the hood; Gen1 has its own API
	url := fmt.Sprintf("https://cloudfunctions.googleapis.com/v2/projects/%s/locations/-/functions", projectID)
	var resp struct {
		Functions []struct {
			Name        string `json:"name"`
			Environment string `json:"environment"` // GEN_1 or GEN_2
			BuildConfig struct {
				Runtime string `json:"runtime"`
			} `json:"buildConfig"`
			ServiceConfig struct {
				ServiceAccountEmail   string `json:"serviceAccountEmail"`
				IngressSettings       string `json:"ingressSettings"` // ALLOW_ALL, ALLOW_INTERNAL_AND_GCLB, ALLOW_INTERNAL_ONLY
				MaxInstanceCount      int    `json:"maxInstanceCount"`
				VpcConnector          string `json:"vpcConnector"`
			} `json:"serviceConfig"`
		} `json:"functions"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, fn := range resp.Functions {
		shortName := fn.Name[strings.LastIndex(fn.Name, "/")+1:]
		fnClean := true

		// Check IAM for unauthenticated invocation
		iamURL := fmt.Sprintf("https://cloudfunctions.googleapis.com/v2/%s:getIamPolicy", fn.Name)
		var iamResp struct {
			Bindings []struct {
				Role    string   `json:"role"`
				Members []string `json:"members"`
			} `json:"bindings"`
		}
		if err := gcpCSPMGet(ctx, token, iamURL, &iamResp); err == nil {
			for _, b := range iamResp.Bindings {
				if b.Role == "roles/cloudfunctions.invoker" || b.Role == "roles/run.invoker" {
					for _, m := range b.Members {
						if m == "allUsers" || m == "allAuthenticatedUsers" {
							findings = append(findings, CSPMFinding{
								Title:        fmt.Sprintf("Cloud Function '%s' allows unauthenticated invocations", shortName),
								Description:  fmt.Sprintf("Function grants invoker role to %s — publicly callable without any authentication. Functions with sensitive logic or data access are a critical attack surface when unauthenticated.", m),
								Severity:     "critical",
								Category:     "compute",
								Resource:     shortName,
								ResourceType: "cloud_function",
								Remediation:  "Remove allUsers from invoker role. Require authentication via Google identity tokens or use Cloud Endpoints for API key control.",
								MITRE:        "T1190",
							})
							fnClean = false
						}
					}
				}
			}
		}

		// Ingress — ALLOW_ALL means callable from internet
		if fn.ServiceConfig.IngressSettings == "ALLOW_ALL" || fn.ServiceConfig.IngressSettings == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Cloud Function '%s' ingress allows all traffic", shortName),
				Description:  "Ingress is set to ALLOW_ALL — the function endpoint is reachable from the public internet. Restrict to internal or load-balancer traffic where possible.",
				Severity:     "medium",
				Category:     "compute",
				Resource:     shortName,
				ResourceType: "cloud_function",
				Remediation:  "Set ingressSettings to ALLOW_INTERNAL_ONLY or ALLOW_INTERNAL_AND_GCLB unless public access is intentional.",
				MITRE:        "T1190",
			})
			fnClean = false
		}

		// Default SA check
		if strings.Contains(fn.ServiceConfig.ServiceAccountEmail, "-compute@developer.gserviceaccount.com") ||
			fn.ServiceConfig.ServiceAccountEmail == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Cloud Function '%s' uses default Compute service account", shortName),
				Description:  "Using the default Compute Engine service account gives the function Editor-level permissions across the entire project — far more than any function should need.",
				Severity:     "high",
				Category:     "iam",
				Resource:     shortName,
				ResourceType: "cloud_function",
				Remediation:  "Assign a dedicated service account with only the roles this function requires.",
				MITRE:        "T1078.004",
			})
			fnClean = false
		}

		if fnClean { passed++ }
	}
	return findings, passed, nil
}

// ── PUB/SUB ──────────────────────────────────────────────────────────────────
func checkPubSub(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://pubsub.googleapis.com/v1/projects/%s/topics", projectID)
	var resp struct {
		Topics []struct {
			Name               string `json:"name"`
			KmsKeyName         string `json:"kmsKeyName"`
			MessageRetentionDuration string `json:"messageRetentionDuration"`
		} `json:"topics"`
	}
	if err := gcpCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, topic := range resp.Topics {
		shortName := topic.Name[strings.LastIndex(topic.Name, "/")+1:]
		// Skip GCP internal topics
		if strings.HasPrefix(shortName, "goog") { continue }
		topicClean := true

		// Check IAM for public access
		iamURL := fmt.Sprintf("https://pubsub.googleapis.com/v1/%s:getIamPolicy", topic.Name)
		var iamResp struct {
			Bindings []struct {
				Role    string   `json:"role"`
				Members []string `json:"members"`
			} `json:"bindings"`
		}
		if err := gcpCSPMGet(ctx, token, iamURL, &iamResp); err == nil {
			for _, b := range iamResp.Bindings {
				for _, m := range b.Members {
					if m == "allUsers" || m == "allAuthenticatedUsers" {
						sev := "critical"
						if strings.Contains(b.Role, "viewer") || strings.Contains(b.Role, "subscriber") {
							sev = "high"
						}
						findings = append(findings, CSPMFinding{
							Title:        fmt.Sprintf("Pub/Sub topic '%s' grants public access (%s → %s)", shortName, b.Role, m),
							Description:  fmt.Sprintf("Topic '%s' has role %s granted to %s. Public publish access enables message injection attacks; public subscribe access enables data exfiltration of all messages on this topic.", shortName, b.Role, m),
							Severity:     sev,
							Category:     "storage",
							Resource:     shortName,
							ResourceType: "pubsub_topic",
							Remediation:  "Remove allUsers/allAuthenticatedUsers from all Pub/Sub IAM bindings. Grant access only to specific service accounts.",
							MITRE:        "T1530",
						})
						topicClean = false
					}
				}
			}
		}

		// CMEK check
		if topic.KmsKeyName == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Pub/Sub topic '%s' has no customer-managed encryption key", shortName),
				Description:  "Messages are encrypted with Google-managed keys. CMEK allows revoking access to message data by disabling the KMS key.",
				Severity:     "low",
				Category:     "kms",
				Resource:     shortName,
				ResourceType: "pubsub_topic",
				Remediation:  "Configure a Cloud KMS key for this Pub/Sub topic using the kmsKeyName field.",
				MITRE:        "T1552.001",
			})
			topicClean = false
		}

		if topicClean { passed++ }
	}

	// Check subscriptions for public access
	subURL := fmt.Sprintf("https://pubsub.googleapis.com/v1/projects/%s/subscriptions", projectID)
	var subResp struct {
		Subscriptions []struct {
			Name string `json:"name"`
			ExpirationPolicy *struct {
				Ttl string `json:"ttl"`
			} `json:"expirationPolicy"`
		} `json:"subscriptions"`
	}
	if err := gcpCSPMGet(ctx, token, subURL, &subResp); err == nil {
		for _, sub := range subResp.Subscriptions {
			shortSubName := sub.Name[strings.LastIndex(sub.Name, "/")+1:]
			subIAMURL := fmt.Sprintf("https://pubsub.googleapis.com/v1/%s:getIamPolicy", sub.Name)
			var subIAM struct {
				Bindings []struct {
					Role    string   `json:"role"`
					Members []string `json:"members"`
				} `json:"bindings"`
			}
			if err := gcpCSPMGet(ctx, token, subIAMURL, &subIAM); err == nil {
				for _, b := range subIAM.Bindings {
					for _, m := range b.Members {
						if m == "allUsers" || m == "allAuthenticatedUsers" {
							findings = append(findings, CSPMFinding{
								Title:        fmt.Sprintf("Pub/Sub subscription '%s' grants public access", shortSubName),
								Description:  fmt.Sprintf("Subscription '%s' has role %s granted to %s. Anyone can pull all messages from this subscription, enabling complete data exfiltration of the message stream.", shortSubName, b.Role, m),
								Severity:     "critical",
								Category:     "storage",
								Resource:     shortSubName,
								ResourceType: "pubsub_subscription",
								Remediation:  "Remove allUsers/allAuthenticatedUsers from subscription IAM. Grant pull access only to specific service accounts.",
								MITRE:        "T1530",
							})
						}
					}
				}
			}
		}
	}

	return findings, passed, nil
}

// ── ORG-LEVEL IAM ─────────────────────────────────────────────────────────────
// Works when SCC is enabled (SA has org-level securitycenter.findingsViewer which implies
// cloudresourcemanager.organizations.getIamPolicy) or when SA has resourcemanager.organizationAdmin.
// Gracefully skips with no error if the SA lacks org-level visibility.
func checkOrgLevelIAM(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	// Step 1: resolve org ID from project ancestry
	ancestryURL := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s:getAncestry", projectID)
	req, err := http.NewRequestWithContext(ctx, "POST", ancestryURL, strings.NewReader("{}"))
	if err != nil { return nil, 0, err }
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, 0, err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 403 { return nil, 0, fmt.Errorf("403: no org ancestry visibility") }
	if resp.StatusCode != 200 { return nil, 0, fmt.Errorf("ancestry API %d", resp.StatusCode) }

	var ancestry struct {
		Ancestor []struct {
			ResourceID struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"resourceId"`
		} `json:"ancestor"`
	}
	if err := json.Unmarshal(body, &ancestry); err != nil { return nil, 0, err }

	orgID := ""
	for _, a := range ancestry.Ancestor {
		if a.ResourceID.Type == "organization" {
			orgID = a.ResourceID.ID
			break
		}
	}
	if orgID == "" {
		// Project is not part of an org (personal/standalone project) — not an error
		return nil, 0, fmt.Errorf("404: project has no parent organization")
	}

	// Step 2: get org-level IAM policy
	orgIAMURL := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/organizations/%s:getIamPolicy", orgID)
	orgReq, _ := http.NewRequestWithContext(ctx, "POST", orgIAMURL, strings.NewReader(`{"options":{"requestedPolicyVersion":3}}`))
	orgReq.Header.Set("Authorization", "Bearer "+token)
	orgReq.Header.Set("Content-Type", "application/json")
	orgResp, err := http.DefaultClient.Do(orgReq)
	if err != nil { return nil, 0, err }
	defer orgResp.Body.Close()
	orgBody, _ := io.ReadAll(orgResp.Body)
	if orgResp.StatusCode == 403 { return nil, 0, fmt.Errorf("403: no org IAM visibility") }
	if orgResp.StatusCode != 200 { return nil, 0, fmt.Errorf("org IAM API %d", orgResp.StatusCode) }

	var orgPolicy struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(orgBody, &orgPolicy); err != nil { return nil, 0, err }

	var findings []CSPMFinding
	passed := 0

	primitiveRoles := map[string]string{
		"roles/owner":  "Owner",
		"roles/editor": "Editor",
	}
	adminRoles := map[string]string{
		"roles/resourcemanager.organizationAdmin": "Organization Admin",
		"roles/iam.organizationRoleAdmin":         "Organization Role Admin",
		"roles/billing.admin":                     "Billing Admin",
		"roles/iam.securityAdmin":                 "Security Admin",
	}

	for _, b := range orgPolicy.Bindings {
		for _, member := range b.Members {
			// Primitive roles at org scope — catastrophic
			if label, isPrim := primitiveRoles[b.Role]; isPrim {
				sev := "critical"
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Org-level: primitive role '%s' granted to %s (org: %s)", label, member, orgID),
					Description:  fmt.Sprintf("The %s role is granted to %s at the organization level. This grants unrestricted access to ALL projects, ALL resources, and ALL data in the entire organization — the highest possible blast radius.", label, member),
					Severity:     sev,
					Category:     "iam",
					Resource:     fmt.Sprintf("organizations/%s", orgID),
					ResourceType: "org_iam_binding",
					Remediation:  "Remove primitive roles from org-level IAM immediately. Use specific predefined roles scoped to the minimum required resource.",
					MITRE:        "T1078.004",
				})
				continue
			}

			// Highly privileged org-level roles granted to external users
			if label, isAdmin := adminRoles[b.Role]; isAdmin {
				isExternal := strings.HasPrefix(member, "user:") || strings.HasPrefix(member, "group:")
				if isExternal {
					findings = append(findings, CSPMFinding{
						Title:        fmt.Sprintf("Org-level: '%s' role granted to external identity %s", label, member),
						Description:  fmt.Sprintf("%s has %s at the organization level. Org admin roles should only be assigned to service accounts used for automation, not external users or groups.", member, label),
						Severity:     "high",
						Category:     "iam",
						Resource:     fmt.Sprintf("organizations/%s", orgID),
						ResourceType: "org_iam_binding",
						Remediation:  "Review whether org-level admin access is justified. Use just-in-time access (short-lived tokens) rather than permanent org admin assignments.",
						MITRE:        "T1078.004",
					})
					continue
				}
			}

			// allUsers / allAuthenticatedUsers at org scope
			if member == "allUsers" || member == "allAuthenticatedUsers" {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Org-level: role '%s' granted to %s — ENTIRE ORG IS PUBLIC", b.Role, member),
					Description:  fmt.Sprintf("The role %s is granted to %s at the organization level. This exposes all resources in all projects in this organization to the public internet.", b.Role, member),
					Severity:     "critical",
					Category:     "iam",
					Resource:     fmt.Sprintf("organizations/%s", orgID),
					ResourceType: "org_iam_binding",
					Remediation:  "Remove allUsers/allAuthenticatedUsers from all organization-level IAM bindings immediately.",
					MITRE:        "T1078.004",
				})
				continue
			}
			passed++
		}
	}
	return findings, passed, nil
}
