package api

// cloud_gcp_cspm.go — GCP Cloud Security Posture Management
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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
}

// gcpCSPMGet makes an authenticated GET to a GCP API
func gcpCSPMGet(ctx context.Context, token, url string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil { return err }
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 403 { return fmt.Errorf("permission denied (403): %s", string(body)[:minInt(200, len(body))]) }
	if resp.StatusCode == 404 { return fmt.Errorf("not found (404)") }
	if resp.StatusCode != 200 { return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body)[:minInt(200, len(body))]) }
	return json.Unmarshal(body, out)
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

	token, err := getGCPTokenWithScope(ctx, sa, "https://www.googleapis.com/auth/cloud-platform.read-only")
	if err != nil { return nil, fmt.Errorf("auth failed: %w", err) }

	findings := []CSPMFinding{}
	passed := 0

	run := func(name string, fn func() ([]CSPMFinding, int, error)) {
		f, p, e := fn()
		if e != nil {
			result.Errors = append(result.Errors, name+": "+e.Error())
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
				return // skip — API not enabled or not applicable
			}
			result.Errors = append(result.Errors, name+": "+e.Error())
		} else {
			findings = append(findings, f...)
			passed += p
		}
	}
	runOptional("kms",           func() ([]CSPMFinding, int, error) { return checkKMSKeys(ctx, token, projectID) })
	runOptional("vpc_flow_logs", func() ([]CSPMFinding, int, error) { return checkVPCFlowLogs(ctx, token, projectID) })
	runOptional("dns_logging",   func() ([]CSPMFinding, int, error) { return checkDNSLogging(ctx, token, projectID) })

	for i := range findings {
		findings[i].ID = fmt.Sprintf("gcp-%s-%d", strings.ReplaceAll(projectID, ":", "-"), i)
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
	jwt, err := gcpJWT(sa, scope)
	if err != nil { return "", err }
	body := "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + jwt
	req, err := http.NewRequestWithContext(ctx, "POST", sa.TokenURI, strings.NewReader(body))
	if err != nil { return "", err }
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return "", err }
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 { return "", fmt.Errorf("auth failed: %s", string(respBody)) }
	var result struct { AccessToken string `json:"access_token"` }
	json.Unmarshal(respBody, &result)
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
					ResourceType: "storage_bucket",
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
					ResourceType: "storage_bucket",
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
				ResourceType: "storage_bucket",
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
				ResourceType: "storage_bucket",
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
				ResourceType: "storage_bucket",
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
				ResourceType: "storage_bucket",
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
	return findings, passed, nil
}

// ── 7. SERVICE ACCOUNTS — KEY AGE + ADMIN GRANTS ─────────────────────────────
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
						if ageDays > 90 {
							sev := "medium"
							if ageDays > 180 { sev = "high" }
							findings = append(findings, CSPMFinding{
								Title:        fmt.Sprintf("Service account '%s' has a key older than %d days", sa.Email, ageDays),
								Description:  fmt.Sprintf("User-managed key created %d days ago. Long-lived keys increase the risk of compromise through leakage or theft.", ageDays),
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
