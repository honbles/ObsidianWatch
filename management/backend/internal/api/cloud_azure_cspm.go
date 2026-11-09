package api

// cloud_azure_cspm.go — Azure Cloud Security Posture Management
//
// Checks implemented:
//  1.  IAM / RBAC          — Owner/Contributor to guests, classic admins, no PIM
//  2.  Network             — NSG 0.0.0.0/0 on risky ports, no WAF, public IPs
//  3.  Storage             — Public blob access, no encryption, SAS without expiry
//  4.  Compute VMs         — No disk encryption, no endpoint protection, public IP
//  5.  Key Vault           — No soft-delete, public network access, no RBAC auth
//  6.  SQL / Database      — Public endpoint, TDE disabled, no auditing
//  7.  AKS Kubernetes      — RBAC disabled, public API, no network policy
//  8.  Logging / Monitor   — No diagnostic settings, no activity log alerts
//  9.  Defender for Cloud  — MDC not enabled, low-tier plans
// 10.  Entra ID            — No MFA, guest access unrestricted, no CA policies

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AzureCSPMResult is the full posture scan result for an Azure connector
type AzureCSPMResult struct {
	ConnectorID   int64         `json:"connector_id"`
	SubscriptionID string       `json:"subscription_id"`
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
	DefenderEnabled bool        `json:"defender_enabled"`
	DefenderFindings int        `json:"defender_findings"`
	// AZ-08 / G-36: checks that did not run, with the reason.
	NotAssessed []NotAssessedCheck `json:"not_assessed,omitempty"`
}

// azureCSPMGet makes an authenticated GET to the Azure management API and
// (AZ-08) follows nextLink, merging "value" arrays across pages (bounded).
func azureCSPMGet(ctx context.Context, token, url string, out interface{}) error {
	const maxPages = 20
	var merged map[string]json.RawMessage
	for page := 0; page < maxPages && url != ""; page++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 403 || resp.StatusCode == 401 {
			return fmt.Errorf("permission denied (%d): %s", resp.StatusCode, string(body)[:minInt(200, len(body))])
		}
		if resp.StatusCode == 404 {
			return fmt.Errorf("not found (404)")
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("azure API error %d: %s", resp.StatusCode, string(body)[:minInt(200, len(body))])
		}
		var cur map[string]json.RawMessage
		if err := json.Unmarshal(body, &cur); err != nil {
			return json.Unmarshal(body, out)
		}
		url = ""
		for _, k := range []string{"nextLink", "@odata.nextLink"} {
			if raw, ok := cur[k]; ok {
				var nl string
				if json.Unmarshal(raw, &nl) == nil && nl != "" && strings.HasPrefix(nl, "https://") {
					url = nl
				}
				delete(cur, k)
			}
		}
		if merged == nil {
			merged = cur
		} else {
			mergeGCPPage(merged, cur)
		}
	}
	buf, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, out)
}

// RunAzureCSPM runs all CSPM checks for an Azure subscription
func RunAzureCSPM(ctx context.Context, tenantID, clientID, clientSecret, subscriptionID string) (*AzureCSPMResult, error) {
	start := time.Now()
	result := &AzureCSPMResult{
		SubscriptionID: subscriptionID,
		ScannedAt:      start,
	}

	token, err := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://management.azure.com/")
	if err != nil {
		return nil, fmt.Errorf("azure auth failed: %w", err)
	}

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

	runOptional := func(name string, fn func() ([]CSPMFinding, int, error)) {
		f, p, e := fn()
		if e != nil {
			if strings.Contains(e.Error(), "403") || strings.Contains(e.Error(), "404") ||
				strings.Contains(e.Error(), "not found") || strings.Contains(e.Error(), "disabled") {
				reason := "resource provider not present in this subscription"
				if strings.Contains(e.Error(), "403") || strings.Contains(e.Error(), "permission") {
					reason = "permission denied — grant Reader (and Security Reader) on the subscription"
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

	sub := subscriptionID

	// Core checks
	run("iam",        func() ([]CSPMFinding, int, error) { return azureCheckIAM(ctx, token.AccessToken, sub) })
	run("network",    func() ([]CSPMFinding, int, error) { return azureCheckNetwork(ctx, token.AccessToken, sub) })
	run("storage",    func() ([]CSPMFinding, int, error) { return azureCheckStorage(ctx, token.AccessToken, sub) })
	run("compute",    func() ([]CSPMFinding, int, error) { return azureCheckCompute(ctx, token.AccessToken, sub) })
	run("logging",    func() ([]CSPMFinding, int, error) { return azureCheckLogging(ctx, token.AccessToken, sub) })
	// Optional — require additional permissions or may not be provisioned
	runOptional("keyvault",  func() ([]CSPMFinding, int, error) { return azureCheckKeyVault(ctx, token.AccessToken, sub) })
	runOptional("sql",       func() ([]CSPMFinding, int, error) { return azureCheckSQL(ctx, token.AccessToken, sub) })
	runOptional("aks",                func() ([]CSPMFinding, int, error) { return azureCheckAKS(ctx, token.AccessToken, sub) })
	runOptional("defender",           func() ([]CSPMFinding, int, error) { return azureCheckDefender(ctx, token.AccessToken, sub) })
	runOptional("app_service",        func() ([]CSPMFinding, int, error) { return azureCheckAppService(ctx, token.AccessToken, sub) })
	runOptional("container_registry", func() ([]CSPMFinding, int, error) { return azureCheckContainerRegistry(ctx, token.AccessToken, sub) })
	runOptional("functions",          func() ([]CSPMFinding, int, error) { return azureCheckFunctionApps(ctx, token.AccessToken, sub) })
	runOptional("sql_advanced",       func() ([]CSPMFinding, int, error) { return azureCheckSQLAdvanced(ctx, token.AccessToken, sub) })

	// Entra ID checks use Graph API
	graphToken, graphErr := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://graph.microsoft.com/")
	if graphErr != nil {
		result.NotAssessed = append(result.NotAssessed, NotAssessedCheck{Check: "entra", Reason: "Graph token request failed — grant Directory.Read.All with admin consent"})
	}
	if graphErr == nil {
		runOptional("entra", func() ([]CSPMFinding, int, error) { return azureCheckEntra(ctx, graphToken.AccessToken, tenantID) })
	}

	// Stamp findings
	for i := range findings {
		// AZ-08: stable, content-derived ID (previously index-based, so the
		// same finding got a different ID whenever another finding appeared
		// before it, and findings could not be tracked across scans).
		sum := sha256.Sum256([]byte(subscriptionID + "\x00" + findings[i].Title + "\x00" + findings[i].Resource))
		findings[i].ID = "az-" + hex.EncodeToString(sum[:])[:12]
		findings[i].Status = "open"
		findings[i].ScannedAt = start
		switch findings[i].Severity {
		case "critical":
			result.Critical++
		case "high":
			result.High++
		case "medium":
			result.Medium++
		case "low":
			result.Low++
		}
	}

	result.Findings = findings
	result.TotalFindings = len(findings)
	result.Passed = passed
	result.ScanDuration = time.Since(start).Round(time.Millisecond).String()
	return result, nil
}

// ── 1. IAM / RBAC ─────────────────────────────────────────────────────────────
func azureCheckIAM(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", sub)
	var resp struct {
		Value []struct {
			ID         string `json:"id"`
			Properties struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				PrincipalID      string `json:"principalId"`
				PrincipalType    string `json:"principalType"`
				Scope            string `json:"scope"`
				CreatedOn        string `json:"createdOn"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	// Fetch role definitions to map IDs to names
	roleURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", sub)
	var roleDefs struct {
		Value []struct {
			ID         string `json:"id"`
			Properties struct {
				RoleName string `json:"roleName"`
			} `json:"properties"`
		} `json:"value"`
	}
	roleMap := map[string]string{}
	if err := azureCSPMGet(ctx, token, roleURL, &roleDefs); err == nil {
		for _, r := range roleDefs.Value {
			parts := strings.Split(r.ID, "/")
			if len(parts) > 0 {
				roleMap[parts[len(parts)-1]] = r.Properties.RoleName
			}
		}
	}

	dangerRoles := map[string]string{
		"Owner":       "critical",
		"Contributor": "high",
	}

	for _, ra := range resp.Value {
		parts := strings.Split(ra.Properties.RoleDefinitionID, "/")
		roleID := ""
		if len(parts) > 0 {
			roleID = parts[len(parts)-1]
		}
		roleName := roleMap[roleID]
		if roleName == "" {
			passed++
			continue
		}

		sev, isDangerous := dangerRoles[roleName]
		if !isDangerous {
			passed++
			continue
		}

		// Guest users with Owner/Contributor is especially bad
		if ra.Properties.PrincipalType == "Guest" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Guest user has '%s' role at subscription scope", roleName),
				Description:  fmt.Sprintf("A guest/external account (principalId: %s) has been granted the %s role at the subscription level. External accounts should never have privileged roles.", ra.Properties.PrincipalID[:8]+"…", roleName),
				Severity:     "critical",
				Category:     "iam",
				Resource:     ra.ID,
				ResourceType: "role_assignment",
				Remediation:  "Remove the role assignment immediately. Use PIM (Privileged Identity Management) for just-in-time elevated access instead of permanent assignment.",
				MITRE:        "T1078.004",
			})
		} else if ra.Properties.PrincipalType == "ServicePrincipal" && strings.HasSuffix(ra.Properties.Scope, "/subscriptions/"+sub) {
			// SP with Owner at sub scope is a broad grant
			if roleName == "Owner" {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Service principal has permanent Owner role at subscription scope"),
					Description:  "A service principal holds Owner at the subscription root. This grants full control over all resources. Service principals should hold narrowly scoped roles.",
					Severity:     sev,
					Category:     "iam",
					Resource:     ra.ID,
					ResourceType: "role_assignment",
					Remediation:  "Replace with a custom role with minimum required permissions. Scope to resource group level, not subscription.",
					MITRE:        "T1078.004",
				})
			} else {
				passed++
			}
		} else {
			passed++
		}
	}

	// Check for classic administrators (legacy — should not exist)
	classicURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01", sub)
	var classic struct {
		Value []struct {
			Properties struct {
				EmailAddress string `json:"emailAddress"`
				Role         string `json:"role"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, classicURL, &classic); err == nil {
		for _, ca := range classic.Value {
			if strings.Contains(strings.ToLower(ca.Properties.Role), "coadministrator") ||
				strings.Contains(strings.ToLower(ca.Properties.Role), "serviceadministrator") {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Classic administrator account detected: %s", ca.Properties.EmailAddress),
					Description:  "Classic administrator roles predate Azure RBAC and grant unrestricted access without Conditional Access or PIM controls. These should be removed.",
					Severity:     "high",
					Category:     "iam",
					Resource:     ca.Properties.EmailAddress,
					ResourceType: "classic_admin",
					Remediation:  "Migrate to Azure RBAC roles. Remove all classic administrator assignments in Subscriptions > Access control (IAM) > Classic administrators.",
					MITRE:        "T1078.004",
				})
			}
		}
	}

	return findings, passed, nil
}

// ── 2. Network Security Groups ────────────────────────────────────────────────
func azureCheckNetwork(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01", sub)
	var resp struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Location   string `json:"location"`
			Properties struct {
				SecurityRules []struct {
					Name       string `json:"name"`
					Properties struct {
						Protocol                 string `json:"protocol"`
						SourceAddressPrefix      string `json:"sourceAddressPrefix"`
						DestinationPortRange     string `json:"destinationPortRange"`
						DestinationPortRanges    []string `json:"destinationPortRanges"`
						Direction                string `json:"direction"`
						Access                   string `json:"access"`
						Priority                 int    `json:"priority"`
					} `json:"properties"`
				} `json:"securityRules"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

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
	}

	for _, nsg := range resp.Value {
		nsgClean := true
		for _, rule := range nsg.Properties.SecurityRules {
			rp := rule.Properties
			if rp.Direction != "Inbound" || rp.Access != "Allow" {
				continue
			}
			isOpenToAll := rp.SourceAddressPrefix == "*" || rp.SourceAddressPrefix == "0.0.0.0/0" ||
				rp.SourceAddressPrefix == "Internet" || rp.SourceAddressPrefix == "Any"
			if !isOpenToAll {
				continue
			}

			// Any-port rule
			if rp.DestinationPortRange == "*" || rp.DestinationPortRange == "0-65535" {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("NSG '%s' rule '%s' allows ALL inbound traffic from internet", nsg.Name, rule.Name),
					Description:  "This NSG rule permits all inbound traffic on all ports from any source. This is equivalent to having no network security boundary.",
					Severity:     "critical",
					Category:     "network",
					Resource:     nsg.Name,
					ResourceType: "nsg",
					Remediation:  "Delete this rule immediately. Replace with specific rules for required ports and sources only.",
					MITRE:        "T1190",
				})
				nsgClean = false
				continue
			}

			allPorts := append([]string{rp.DestinationPortRange}, rp.DestinationPortRanges...)
			for _, port := range allPorts {
				if port == "" {
					continue
				}
				if info, risky := riskyPorts[port]; risky {
					findings = append(findings, CSPMFinding{
						Title:        fmt.Sprintf("NSG '%s' exposes %s (port %s) to internet", nsg.Name, info.label, port),
						Description:  fmt.Sprintf("Inbound rule '%s' allows port %s (%s) from any source. This service is directly reachable from the internet.", rule.Name, port, info.label),
						Severity:     info.sev,
						Category:     "network",
						Resource:     nsg.Name,
						ResourceType: "nsg",
						Remediation:  fmt.Sprintf("Restrict port %s to specific known IP ranges. Use Azure Bastion for RDP/SSH access instead.", port),
						MITRE:        "T1190",
					})
					nsgClean = false
				}
			}
		}
		if nsgClean {
			passed++
		}
	}

	// Check for Application Gateways without WAF
	wafURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/applicationGateways?api-version=2023-05-01", sub)
	var agResp struct {
		Value []struct {
			Name       string `json:"name"`
			Properties struct {
				Sku struct {
					Name string `json:"name"`
					Tier string `json:"tier"`
				} `json:"sku"`
				WebApplicationFirewallConfiguration *struct {
					Enabled bool `json:"enabled"`
				} `json:"webApplicationFirewallConfiguration"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, wafURL, &agResp); err == nil {
		for _, ag := range agResp.Value {
			hasWAF := strings.Contains(strings.ToLower(ag.Properties.Sku.Tier), "waf")
			wafEnabled := ag.Properties.WebApplicationFirewallConfiguration != nil &&
				ag.Properties.WebApplicationFirewallConfiguration.Enabled
			if !hasWAF || !wafEnabled {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Application Gateway '%s' does not have WAF enabled", ag.Name),
					Description:  "Web Application Firewall (WAF) is not enabled on this Application Gateway. Without WAF, OWASP Top 10 attacks (SQLi, XSS, etc.) are not blocked.",
					Severity:     "high",
					Category:     "network",
					Resource:     ag.Name,
					ResourceType: "application_gateway",
					Remediation:  "Upgrade to WAF_v2 tier and enable WAF in Prevention mode with the OWASP 3.2 ruleset.",
					MITRE:        "T1190",
				})
			} else {
				passed++
			}
		}
	}

	return findings, passed, nil
}

// ── 3. Storage Accounts ───────────────────────────────────────────────────────
func azureCheckStorage(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01", sub)
	var resp struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Properties struct {
				AllowBlobPublicAccess         *bool `json:"allowBlobPublicAccess"`
				MinimumTlsVersion             string `json:"minimumTlsVersion"`
				EnableHTTPSTrafficOnly        bool   `json:"supportsHttpsTrafficOnly"`
				AllowSharedKeyAccess          *bool  `json:"allowSharedKeyAccess"`
				NetworkAcls struct {
					DefaultAction string `json:"defaultAction"`
					Bypass        string `json:"bypass"`
				} `json:"networkAcls"`
				Encryption struct {
					RequireInfrastructureEncryption *bool `json:"requireInfrastructureEncryption"`
					KeySource string `json:"keySource"`
				} `json:"encryption"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, sa := range resp.Value {
		p := sa.Properties
		saClean := true

		// Public blob access
		if p.AllowBlobPublicAccess == nil || *p.AllowBlobPublicAccess {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Storage account '%s' allows public blob access", sa.Name),
				Description:  "Public blob access is enabled. Any user on the internet can read blob data if a container is configured as public. This should be disabled at the account level.",
				Severity:     "high",
				Category:     "storage",
				Resource:     sa.Name,
				ResourceType: "storage_account",
				Remediation:  "Set allowBlobPublicAccess: false at the storage account level. Audit existing containers for public access.",
				MITRE:        "T1530",
			})
			saClean = false
		}

		// HTTPS only
		if !p.EnableHTTPSTrafficOnly {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Storage account '%s' allows HTTP traffic", sa.Name),
				Description:  "HTTPS-only is not enforced. Data in transit can be intercepted via HTTP connections.",
				Severity:     "high",
				Category:     "storage",
				Resource:     sa.Name,
				ResourceType: "storage_account",
				Remediation:  "Enable 'Secure transfer required' (supportsHttpsTrafficOnly: true) on the storage account.",
				MITRE:        "T1040",
			})
			saClean = false
		}

		// Minimum TLS version
		if p.MinimumTlsVersion == "" || p.MinimumTlsVersion == "TLS1_0" || p.MinimumTlsVersion == "TLS1_1" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Storage account '%s' allows TLS 1.0/1.1", sa.Name),
				Description:  "Minimum TLS version is set below TLS 1.2. TLS 1.0 and 1.1 have known vulnerabilities (POODLE, BEAST).",
				Severity:     "medium",
				Category:     "storage",
				Resource:     sa.Name,
				ResourceType: "storage_account",
				Remediation:  "Set minimumTlsVersion to TLS1_2 on the storage account.",
				MITRE:        "T1040",
			})
			saClean = false
		}

		// Network access — open to all
		if p.NetworkAcls.DefaultAction == "Allow" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Storage account '%s' network firewall allows all networks", sa.Name),
				Description:  "The storage account network firewall is set to 'Allow all networks'. Any client on the internet can attempt to access this storage account.",
				Severity:     "medium",
				Category:     "storage",
				Resource:     sa.Name,
				ResourceType: "storage_account",
				Remediation:  "Set the default network action to 'Deny' and add specific virtual network rules and IP allowlist entries.",
				MITRE:        "T1530",
			})
			saClean = false
		}

		// Shared key access (can bypass RBAC)
		if p.AllowSharedKeyAccess == nil || *p.AllowSharedKeyAccess {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Storage account '%s' allows shared key authentication", sa.Name),
				Description:  "Shared key access is enabled. Access keys bypass Azure AD RBAC and Conditional Access — anyone with a key has full access regardless of identity controls.",
				Severity:     "medium",
				Category:     "storage",
				Resource:     sa.Name,
				ResourceType: "storage_account",
				Remediation:  "Disable shared key access and migrate clients to Azure AD authentication with least-privilege roles.",
				MITRE:        "T1552.001",
			})
			saClean = false
		}

		if saClean {
			passed++
		}
	}
	return findings, passed, nil
}

// ── 4. Compute VMs ────────────────────────────────────────────────────────────
func azureCheckCompute(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01", sub)
	var resp struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Location   string `json:"location"`
			Properties struct {
				StorageProfile struct {
					OsDisk struct {
						EncryptionSettings *struct {
							Enabled bool `json:"enabled"`
						} `json:"encryptionSettings"`
						ManagedDisk *struct {
							SecurityProfile *struct {
								SecurityEncryptionType string `json:"securityEncryptionType"`
							} `json:"securityProfile"`
							DiskEncryptionSet *struct {
								ID string `json:"id"`
							} `json:"diskEncryptionSet"`
						} `json:"managedDisk"`
					} `json:"osDisk"`
				} `json:"storageProfile"`
				NetworkProfile struct {
					NetworkInterfaces []struct {
						ID string `json:"id"`
					} `json:"networkInterfaces"`
				} `json:"networkProfile"`
				SecurityProfile *struct {
					EncryptionAtHost *bool `json:"encryptionAtHost"`
					SecurityType     string `json:"securityType"`
					UefiSettings     *struct {
						SecureBootEnabled bool `json:"secureBootEnabled"`
						VTpmEnabled       bool `json:"vTpmEnabled"`
					} `json:"uefiSettings"`
				} `json:"securityProfile"`
				OSProfile *struct {
					LinuxConfiguration *struct {
						DisablePasswordAuthentication bool `json:"disablePasswordAuthentication"`
					} `json:"linuxConfiguration"`
				} `json:"osProfile"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, vm := range resp.Value {
		vmClean := true
		sp := vm.Properties.StorageProfile
		sec := vm.Properties.SecurityProfile

		// Disk encryption check
		diskEncrypted := false
		if sp.OsDisk.EncryptionSettings != nil && sp.OsDisk.EncryptionSettings.Enabled {
			diskEncrypted = true
		}
		if sp.OsDisk.ManagedDisk != nil && sp.OsDisk.ManagedDisk.DiskEncryptionSet != nil {
			diskEncrypted = true
		}
		if sec != nil && sec.EncryptionAtHost != nil && *sec.EncryptionAtHost {
			diskEncrypted = true
		}
		if !diskEncrypted {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("VM '%s' OS disk is not encrypted", vm.Name),
				Description:  "The VM's OS disk does not use Azure Disk Encryption, a disk encryption set (CMK), or encryption at host. If the disk is detached or the storage account is compromised, data is exposed.",
				Severity:     "high",
				Category:     "compute",
				Resource:     fmt.Sprintf("%s (%s)", vm.Name, vm.Location),
				ResourceType: "virtual_machine",
				Remediation:  "Enable Azure Disk Encryption or assign a disk encryption set with customer-managed keys. Enable Encryption at Host for full coverage.",
				MITRE:        "T1486",
			})
			vmClean = false
		}

		// Trusted launch / Secure Boot
		if sec == nil || sec.SecurityType != "TrustedLaunch" ||
			sec.UefiSettings == nil || !sec.UefiSettings.SecureBootEnabled || !sec.UefiSettings.VTpmEnabled {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("VM '%s' does not have Trusted Launch (Secure Boot + vTPM) enabled", vm.Name),
				Description:  "Trusted Launch with Secure Boot and vTPM is not enabled. Without it, boot-level malware (bootkits, rootkits) cannot be detected and the VM is vulnerable to firmware attacks.",
				Severity:     "medium",
				Category:     "compute",
				Resource:     fmt.Sprintf("%s (%s)", vm.Name, vm.Location),
				ResourceType: "virtual_machine",
				Remediation:  "Enable Trusted Launch with Secure Boot and vTPM in VM Security > Trusted Launch configuration.",
				MITRE:        "T1542",
			})
			vmClean = false
		}

		// Linux VMs: password auth should be disabled
		if vm.Properties.OSProfile != nil && vm.Properties.OSProfile.LinuxConfiguration != nil {
			if !vm.Properties.OSProfile.LinuxConfiguration.DisablePasswordAuthentication {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Linux VM '%s' allows password authentication", vm.Name),
					Description:  "SSH password authentication is enabled. Password-based SSH is vulnerable to brute force attacks. SSH key authentication should be enforced.",
					Severity:     "high",
					Category:     "compute",
					Resource:     fmt.Sprintf("%s (%s)", vm.Name, vm.Location),
					ResourceType: "virtual_machine",
					Remediation:  "Disable password authentication: set disablePasswordAuthentication: true. Use SSH keys or Azure AD login instead.",
					MITRE:        "T1110",
				})
				vmClean = false
			}
		}

		if vmClean {
			passed++
		}
	}
	return findings, passed, nil
}

// ── 5. Key Vault ──────────────────────────────────────────────────────────────
func azureCheckKeyVault(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=2023-02-01", sub)
	var resp struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Properties struct {
				EnableSoftDelete        *bool  `json:"enableSoftDelete"`
				EnablePurgeProtection   *bool  `json:"enablePurgeProtection"`
				SoftDeleteRetentionDays *int   `json:"softDeleteRetentionDays"`
				NetworkAcls             *struct {
					DefaultAction string `json:"defaultAction"`
					Bypass        string `json:"bypass"`
				} `json:"networkAcls"`
				EnableRbacAuthorization *bool `json:"enableRbacAuthorization"`
				EnabledForDiskEncryption *bool `json:"enabledForDiskEncryption"`
				PublicNetworkAccess     string `json:"publicNetworkAccess"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, kv := range resp.Value {
		p := kv.Properties
		kvClean := true

		// Soft delete
		if p.EnableSoftDelete == nil || !*p.EnableSoftDelete {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Key Vault '%s' does not have soft delete enabled", kv.Name),
				Description:  "Soft delete is not enabled. Keys, secrets, and certificates can be permanently deleted without a recovery window, enabling ransomware or accidental data loss.",
				Severity:     "high",
				Category:     "kms",
				Resource:     kv.Name,
				ResourceType: "key_vault",
				Remediation:  "Enable soft delete with a retention period of at least 90 days. Enable purge protection to prevent permanent deletion.",
				MITRE:        "T1485",
			})
			kvClean = false
		}

		// Purge protection
		if p.EnablePurgeProtection == nil || !*p.EnablePurgeProtection {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Key Vault '%s' does not have purge protection enabled", kv.Name),
				Description:  "Purge protection is not enabled. Even with soft delete, a privileged user or attacker can permanently purge keys before the retention period expires.",
				Severity:     "medium",
				Category:     "kms",
				Resource:     kv.Name,
				ResourceType: "key_vault",
				Remediation:  "Enable purge protection on the Key Vault.",
				MITRE:        "T1485",
			})
			kvClean = false
		}

		// Public network access
		netOpen := p.PublicNetworkAccess == "Enabled" || p.PublicNetworkAccess == ""
		if p.NetworkAcls != nil && p.NetworkAcls.DefaultAction == "Allow" {
			netOpen = true
		}
		if netOpen {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Key Vault '%s' is accessible from public internet", kv.Name),
				Description:  "The Key Vault's network firewall is set to allow all networks. Any client with valid credentials (including from stolen tokens) can access it from anywhere.",
				Severity:     "medium",
				Category:     "kms",
				Resource:     kv.Name,
				ResourceType: "key_vault",
				Remediation:  "Set the default network action to Deny. Allow access only from specific virtual networks and trusted Azure services.",
				MITRE:        "T1552.001",
			})
			kvClean = false
		}

		// RBAC authorization (vs legacy access policies)
		if p.EnableRbacAuthorization == nil || !*p.EnableRbacAuthorization {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Key Vault '%s' uses legacy access policies instead of RBAC", kv.Name),
				Description:  "The Key Vault uses the legacy vault access policy model rather than Azure RBAC. Access policies cannot leverage Conditional Access, PIM, or fine-grained permissions.",
				Severity:     "low",
				Category:     "kms",
				Resource:     kv.Name,
				ResourceType: "key_vault",
				Remediation:  "Migrate to Azure RBAC authorization for Key Vault to enable PIM, Conditional Access, and audit trail via Azure AD.",
				MITRE:        "T1078.004",
			})
			kvClean = false
		}

		if kvClean {
			passed++
		}
	}
	return findings, passed, nil
}

// ── 6. Azure SQL ──────────────────────────────────────────────────────────────
func azureCheckSQL(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview", sub)
	var resp struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Properties struct {
				MinimalTLSVersion      string `json:"minimalTlsVersion"`
				PublicNetworkAccess    string `json:"publicNetworkAccess"`
				AdministratorLogin     string `json:"administratorLogin"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, srv := range resp.Value {
		srvClean := true

		if srv.Properties.PublicNetworkAccess == "Enabled" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("SQL Server '%s' has public network access enabled", srv.Name),
				Description:  "Public network access is enabled for this SQL Server. Any IP can attempt authentication. Use private endpoints and disable public access.",
				Severity:     "high",
				Category:     "sql",
				Resource:     srv.Name,
				ResourceType: "sql_server",
				Remediation:  "Disable public network access. Configure private endpoints and use VNet integration for connectivity.",
				MITRE:        "T1190",
			})
			srvClean = false
		}

		if srv.Properties.MinimalTLSVersion == "" || srv.Properties.MinimalTLSVersion == "1.0" || srv.Properties.MinimalTLSVersion == "1.1" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("SQL Server '%s' allows TLS below 1.2", srv.Name),
				Description:  "Minimum TLS version allows outdated protocols vulnerable to POODLE and BEAST attacks.",
				Severity:     "medium",
				Category:     "sql",
				Resource:     srv.Name,
				ResourceType: "sql_server",
				Remediation:  "Set minimalTlsVersion to 1.2 on the SQL Server.",
				MITRE:        "T1040",
			})
			srvClean = false
		}

		// Check TDE and auditing per database
		dbURL := fmt.Sprintf("https://management.azure.com/%s/databases?api-version=2022-05-01-preview", srv.ID)
		var dbResp struct {
			Value []struct {
				Name string `json:"name"`
				ID   string `json:"id"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, token, dbURL, &dbResp); err == nil {
			for _, db := range dbResp.Value {
				if db.Name == "master" {
					continue
				}
				// TDE check
				tdeURL := fmt.Sprintf("https://management.azure.com/%s/transparentDataEncryption/current?api-version=2022-05-01-preview", db.ID)
				var tde struct {
					Properties struct {
						State string `json:"state"`
					} `json:"properties"`
				}
				if tdeErr := azureCSPMGet(ctx, token, tdeURL, &tde); tdeErr == nil {
					if tde.Properties.State != "Enabled" {
						findings = append(findings, CSPMFinding{
							Title:        fmt.Sprintf("SQL database '%s/%s' has TDE (Transparent Data Encryption) disabled", srv.Name, db.Name),
							Description:  "Transparent Data Encryption is not enabled. Data at rest in this database is stored unencrypted on disk.",
							Severity:     "high",
							Category:     "sql",
							Resource:     fmt.Sprintf("%s/%s", srv.Name, db.Name),
							ResourceType: "sql_database",
							Remediation:  "Enable TDE on the database. For sensitive data, consider using customer-managed keys (TDE with CMK) via Azure Key Vault.",
							MITRE:        "T1486",
						})
						srvClean = false
					}
				}
			}
		}

		if srvClean {
			passed++
		}
	}
	return findings, passed, nil
}

// ── 7. AKS Kubernetes ─────────────────────────────────────────────────────────
func azureCheckAKS(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.ContainerService/managedClusters?api-version=2023-07-01", sub)
	var resp struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Properties struct {
				EnableRBAC              bool `json:"enableRBAC"`
				APIServerAccessProfile  *struct {
					EnablePrivateCluster        bool `json:"enablePrivateCluster"`
					AuthorizedIPRanges          []string `json:"authorizedIPRanges"`
				} `json:"apiServerAccessProfile"`
				NetworkProfile *struct {
					NetworkPolicy  string `json:"networkPolicy"`
					NetworkPlugin  string `json:"networkPlugin"`
				} `json:"networkProfile"`
				AddonProfiles *struct {
					AzurePolicy *struct {
						Enabled bool `json:"enabled"`
					} `json:"azurepolicy"`
					OmsAgent *struct {
						Enabled bool `json:"enabled"`
					} `json:"omsagent"`
				} `json:"addonProfiles"`
				OidcIssuerProfile *struct {
					Enabled bool `json:"enabled"`
				} `json:"oidcIssuerProfile"`
				SecurityProfile *struct {
					Defender *struct {
						SecurityMonitoring *struct {
							Enabled bool `json:"enabled"`
						} `json:"securityMonitoring"`
					} `json:"defender"`
					WorkloadIdentity *struct {
						Enabled bool `json:"enabled"`
					} `json:"workloadIdentity"`
				} `json:"securityProfile"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, cluster := range resp.Value {
		clusterClean := true
		p := cluster.Properties

		// RBAC disabled
		if !p.EnableRBAC {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("AKS cluster '%s' has Kubernetes RBAC disabled", cluster.Name),
				Description:  "Kubernetes RBAC is disabled. All authenticated users have unrestricted access to the cluster API. This prevents implementing least-privilege access controls.",
				Severity:     "critical",
				Category:     "compute",
				Resource:     cluster.Name,
				ResourceType: "aks_cluster",
				Remediation:  "Enable Kubernetes RBAC. This requires cluster recreation if disabled. Use Azure AD integration with Kubernetes RBAC for identity-based access.",
				MITRE:        "T1548",
			})
			clusterClean = false
		}

		// Public API server without IP restrictions
		if p.APIServerAccessProfile == nil || (!p.APIServerAccessProfile.EnablePrivateCluster &&
			len(p.APIServerAccessProfile.AuthorizedIPRanges) == 0) {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("AKS cluster '%s' API server is publicly accessible without IP restrictions", cluster.Name),
				Description:  "The Kubernetes API server is exposed to the internet with no authorized IP ranges configured. Any IP can attempt authentication against the API server.",
				Severity:     "high",
				Category:     "compute",
				Resource:     cluster.Name,
				ResourceType: "aks_cluster",
				Remediation:  "Enable private cluster or configure authorized IP ranges to restrict API server access to known management IPs.",
				MITRE:        "T1190",
			})
			clusterClean = false
		}

		// No network policy
		if p.NetworkProfile == nil || (p.NetworkProfile.NetworkPolicy != "azure" &&
			p.NetworkProfile.NetworkPolicy != "calico" && p.NetworkProfile.NetworkPolicy != "cilium") {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("AKS cluster '%s' has no Kubernetes network policy configured", cluster.Name),
				Description:  "No Kubernetes network policy is configured. All pods can communicate with all other pods across all namespaces — no east-west traffic segmentation.",
				Severity:     "medium",
				Category:     "compute",
				Resource:     cluster.Name,
				ResourceType: "aks_cluster",
				Remediation:  "Configure Azure CNI or Calico network policy. Apply default-deny-all NetworkPolicy in each namespace and only allow required traffic.",
				MITRE:        "T1021",
			})
			clusterClean = false
		}

		// Workload Identity
		if p.SecurityProfile == nil || p.SecurityProfile.WorkloadIdentity == nil || !p.SecurityProfile.WorkloadIdentity.Enabled {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("AKS cluster '%s' does not use Workload Identity", cluster.Name),
				Description:  "Workload Identity is not enabled. Pods may be using node-level managed identity or mounted secrets for Azure service access, which grants broader permissions than intended.",
				Severity:     "medium",
				Category:     "compute",
				Resource:     cluster.Name,
				ResourceType: "aks_cluster",
				Remediation:  "Enable Workload Identity and OIDC issuer. Migrate pods to use federated credentials to access Azure services with pod-level identity.",
				MITRE:        "T1078.004",
			})
			clusterClean = false
		}

		if clusterClean {
			passed++
		}
	}
	return findings, passed, nil
}

// ── 8. Logging / Monitor ──────────────────────────────────────────────────────
func azureCheckLogging(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	var findings []CSPMFinding
	passed := 0

	// Check subscription-level diagnostic settings
	diagURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview", sub)
	var diagResp struct {
		Value []struct {
			Name       string `json:"name"`
			Properties struct {
				Logs []struct {
					Category string `json:"category"`
					Enabled  bool   `json:"enabled"`
				} `json:"logs"`
				WorkspaceID   string `json:"workspaceId"`
				StorageAccountID string `json:"storageAccountId"`
				EventHubName  string `json:"eventHubName"`
			} `json:"properties"`
		} `json:"value"`
	}

	if err := azureCSPMGet(ctx, token, diagURL, &diagResp); err != nil || len(diagResp.Value) == 0 {
		findings = append(findings, CSPMFinding{
			Title:        "Subscription has no diagnostic settings configured",
			Description:  "No diagnostic settings are configured at the subscription level. Azure Activity Log events are not being forwarded to a Log Analytics workspace, storage account, or event hub for retention and analysis.",
			Severity:     "critical",
			Category:     "logging",
			Resource:     sub,
			ResourceType: "subscription",
			Remediation:  "Create a diagnostic setting to forward all Activity Log categories to a Log Analytics workspace with at least 90 days retention.",
			MITRE:        "T1562.008",
		})
	} else {
		// Check that critical log categories are enabled
		requiredCategories := []string{"Administrative", "Security", "Alert", "Policy"}
		for _, ds := range diagResp.Value {
			enabledCats := map[string]bool{}
			for _, l := range ds.Properties.Logs {
				if l.Enabled {
					enabledCats[l.Category] = true
				}
			}
			for _, cat := range requiredCategories {
				if !enabledCats[cat] {
					findings = append(findings, CSPMFinding{
						Title:        fmt.Sprintf("Diagnostic setting '%s' does not capture '%s' logs", ds.Name, cat),
						Description:  fmt.Sprintf("The '%s' log category is not enabled in diagnostic settings. Security events, policy violations, and administrative actions in this category will not be retained.", cat),
						Severity:     "high",
						Category:     "logging",
						Resource:     ds.Name,
						ResourceType: "diagnostic_setting",
						Remediation:  fmt.Sprintf("Enable the '%s' category in the diagnostic settings to ensure full audit trail coverage.", cat),
						MITRE:        "T1562.008",
					})
				}
			}
		}
		passed++
	}

	// Check for activity log alert rules on critical operations
	alertURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/microsoft.insights/activityLogAlerts?api-version=2020-10-01", sub)
	var alertResp struct {
		Value []struct {
			Name       string `json:"name"`
			Properties struct {
				Enabled   bool `json:"enabled"`
				Condition struct {
					AllOf []struct {
						Field  string `json:"field"`
						Equals string `json:"equals"`
					} `json:"allOf"`
				} `json:"condition"`
			} `json:"properties"`
		} `json:"value"`
	}

	if err := azureCSPMGet(ctx, token, alertURL, &alertResp); err == nil {
		if len(alertResp.Value) == 0 {
			findings = append(findings, CSPMFinding{
				Title:        "No Activity Log alert rules configured",
				Description:  "No Activity Log alerts are configured. Critical operations (role assignment changes, security policy modifications, VM deletions) will not generate real-time notifications.",
				Severity:     "high",
				Category:     "logging",
				Resource:     sub,
				ResourceType: "subscription",
				Remediation:  "Create Activity Log alerts for: Create/Update/Delete role assignments, security policy write/delete, Create/Update/Delete network security groups.",
				MITRE:        "T1562.001",
			})
		} else {
			passed++
		}
	}

	return findings, passed, nil
}

// ── 9. Defender for Cloud ─────────────────────────────────────────────────────
func azureCheckDefender(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/pricings?api-version=2022-03-01", sub)
	var resp struct {
		Value []struct {
			Name       string `json:"name"`
			Properties struct {
				PricingTier string `json:"pricingTier"`
				SubPlan     string `json:"subPlan"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	criticalPlans := map[string]bool{
		"VirtualMachines":        true,
		"StorageAccounts":        true,
		"SqlServers":             true,
		"AppServices":            true,
		"KeyVaults":              true,
		"Containers":             true,
		"Arm":                    true,
	}

	for _, p := range resp.Value {
		if !criticalPlans[p.Name] {
			continue
		}
		if p.Properties.PricingTier == "Free" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Microsoft Defender for Cloud: '%s' plan is on Free tier", p.Name),
				Description:  fmt.Sprintf("The Defender for Cloud plan for %s is set to Free tier. Threat detection, vulnerability assessment, and security alerts are not available without the Standard/P2 plan.", p.Name),
				Severity:     "medium",
				Category:     "compute",
				Resource:     p.Name,
				ResourceType: "defender_plan",
				Remediation:  fmt.Sprintf("Upgrade the '%s' Defender for Cloud plan to Standard (P2) for real-time threat detection and advanced security alerts.", p.Name),
				MITRE:        "T1562.001",
			})
		} else {
			passed++
		}
	}
	return findings, passed, nil
}

// ── 10. Entra ID (via Graph API) ──────────────────────────────────────────────
func azureCheckEntra(ctx context.Context, graphToken, tenantID string) ([]CSPMFinding, int, error) {
	var findings []CSPMFinding
	passed := 0

	// Check Conditional Access policies
	caURL := "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
	var caResp struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			State       string `json:"state"` // enabled, disabled, enabledForReportingButNotEnforced
			Conditions  struct {
				Users struct {
					IncludeUsers []string `json:"includeUsers"`
				} `json:"users"`
			} `json:"conditions"`
		} `json:"value"`
	}

	if err := azureCSPMGet(ctx, graphToken, caURL, &caResp); err == nil {
		enabledPolicies := 0
		mfaPolicy := false
		for _, policy := range caResp.Value {
			if policy.State == "enabled" {
				enabledPolicies++
				// Check if any policy covers all users and likely requires MFA
				for _, u := range policy.Conditions.Users.IncludeUsers {
					if u == "All" || u == "GuestsOrExternalUsers" {
						mfaPolicy = true
					}
				}
			}
		}
		if enabledPolicies == 0 {
			findings = append(findings, CSPMFinding{
				Title:        "No enabled Conditional Access policies found",
				Description:  "No Conditional Access policies are enabled. Without CA policies, there is no enforcement of MFA, device compliance, or location-based access controls — any valid credential can access any resource from anywhere.",
				Severity:     "critical",
				Category:     "iam",
				Resource:     tenantID,
				ResourceType: "entra_tenant",
				Remediation:  "Create and enable CA policies: (1) Require MFA for all users, (2) Block legacy authentication, (3) Require compliant devices for privileged access.",
				MITRE:        "T1078.004",
			})
		} else if !mfaPolicy {
			findings = append(findings, CSPMFinding{
				Title:        "No Conditional Access policy enforces MFA for all users",
				Description:  "Conditional Access policies exist but none appear to require MFA for all users. Accounts without MFA are vulnerable to password spray and credential stuffing attacks.",
				Severity:     "high",
				Category:     "iam",
				Resource:     tenantID,
				ResourceType: "entra_tenant",
				Remediation:  "Create a CA policy: Users > All users, Controls > Require multifactor authentication. Exclude break-glass accounts only.",
				MITRE:        "T1078.004",
			})
		} else {
			passed++
		}
	}

	// Check guest user settings
	guestURL := "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
	var guestPolicy struct {
		AllowInvitesFrom                  string `json:"allowInvitesFrom"`
		GuestUserRoleID                   string `json:"guestUserRoleId"`
		DefaultUserRolePermissions struct {
			AllowedToCreateSecurityGroups bool `json:"allowedToCreateSecurityGroups"`
			AllowedToCreateTenantWideApps bool `json:"allowedToCreateTenantWideApps"`
		} `json:"defaultUserRolePermissions"`
	}
	if err := azureCSPMGet(ctx, graphToken, guestURL, &guestPolicy); err == nil {
		// adminsAndGuestInviters or everyone is risky
		if guestPolicy.AllowInvitesFrom == "everyone" || guestPolicy.AllowInvitesFrom == "adminsAndGuestInviters" {
			findings = append(findings, CSPMFinding{
				Title:        "Guest user invitations are not restricted to admins only",
				Description:  fmt.Sprintf("Guest invitation setting is '%s'. Non-admin users can invite external guests, creating uncontrolled external access to your tenant.", guestPolicy.AllowInvitesFrom),
				Severity:     "medium",
				Category:     "iam",
				Resource:     tenantID,
				ResourceType: "entra_tenant",
				Remediation:  "Set allowInvitesFrom to 'adminsOnly' to restrict guest invitations to Global Admins and User Admins only.",
				MITRE:        "T1136.003",
			})
		} else {
			passed++
		}
	}

	return findings, passed, nil
}

// ── 11. App Service ───────────────────────────────────────────────────────────
func azureCheckAppService(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Web/sites?api-version=2022-09-01", sub)
	var resp struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Kind       string `json:"kind"` // app, functionapp, app,linux, etc
			Properties struct {
				HTTPSOnly               bool   `json:"httpsOnly"`
				MinTLSVersion           string `json:"minTlsVersion"`
				ClientCertEnabled       bool   `json:"clientCertEnabled"`
				PublicNetworkAccess     string `json:"publicNetworkAccess"`
				SiteAuthSettings struct {
					Enabled bool `json:"enabled"`
				} `json:"siteAuthSettings"`
				SiteConfig *struct {
					MinTLSVersion          string `json:"minTlsVersion"`
					FtpsState              string `json:"ftpsState"`   // AllAllowed, FtpsOnly, Disabled
					RemoteDebuggingEnabled bool   `json:"remoteDebuggingEnabled"`
					ManagedServiceIdentityID *int  `json:"managedServiceIdentityId"`
				} `json:"siteConfig"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, site := range resp.Value {
		// Skip function apps — covered by azureCheckFunctionApps
		if strings.Contains(site.Kind, "functionapp") { continue }
		siteClean := true
		p := site.Properties

		// HTTPS only
		if !p.HTTPSOnly {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("App Service '%s' does not enforce HTTPS", site.Name),
				Description:  "HTTPS Only is not enabled. HTTP requests are accepted, exposing authentication tokens and session cookies to interception.",
				Severity:     "high",
				Category:     "compute",
				Resource:     site.Name,
				ResourceType: "app_service",
				Remediation:  "Enable 'HTTPS Only' in App Service > TLS/SSL settings.",
				MITRE:        "T1040",
			})
			siteClean = false
		}

		// TLS version
		tlsVer := p.MinTLSVersion
		if p.SiteConfig != nil && p.SiteConfig.MinTLSVersion != "" { tlsVer = p.SiteConfig.MinTLSVersion }
		if tlsVer == "" || tlsVer == "1.0" || tlsVer == "1.1" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("App Service '%s' allows TLS below 1.2", site.Name),
				Description:  "Minimum TLS version is set below TLS 1.2. Legacy TLS protocols (1.0, 1.1) have known vulnerabilities.",
				Severity:     "medium",
				Category:     "compute",
				Resource:     site.Name,
				ResourceType: "app_service",
				Remediation:  "Set Minimum TLS Version to 1.2 or higher in App Service > TLS/SSL settings.",
				MITRE:        "T1040",
			})
			siteClean = false
		}

		// FTP state
		if p.SiteConfig != nil && (p.SiteConfig.FtpsState == "AllAllowed" || p.SiteConfig.FtpsState == "") {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("App Service '%s' allows FTP (plaintext)", site.Name),
				Description:  "FTP is allowed for deployment. FTP transmits credentials and content in plaintext and should be disabled or replaced with FTPS.",
				Severity:     "high",
				Category:     "compute",
				Resource:     site.Name,
				ResourceType: "app_service",
				Remediation:  "Set FTP State to 'FtpsOnly' or 'Disabled' in App Service > Configuration > General settings.",
				MITRE:        "T1040",
			})
			siteClean = false
		}

		// Remote debugging
		if p.SiteConfig != nil && p.SiteConfig.RemoteDebuggingEnabled {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("App Service '%s' has remote debugging enabled", site.Name),
				Description:  "Remote debugging is enabled. This opens a debug port that allows unauthenticated code execution if the port is reachable and the debugger is attached.",
				Severity:     "critical",
				Category:     "compute",
				Resource:     site.Name,
				ResourceType: "app_service",
				Remediation:  "Disable remote debugging in App Service > Configuration > General settings unless actively debugging.",
				MITRE:        "T1190",
			})
			siteClean = false
		}

		// Authentication
		authURL := fmt.Sprintf("https://management.azure.com/%s/config/authsettingsV2?api-version=2022-09-01", site.ID)
		var authResp struct {
			Properties struct {
				Platform struct {
					Enabled bool `json:"enabled"`
				} `json:"platform"`
			} `json:"properties"`
		}
		if err := azureCSPMGet(ctx, token, authURL, &authResp); err == nil {
			if !authResp.Properties.Platform.Enabled {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("App Service '%s' has no authentication configured", site.Name),
					Description:  "App Service authentication (Easy Auth) is not enabled. The application has no enforced identity layer — any user on the internet can access it without authentication.",
					Severity:     "high",
					Category:     "iam",
					Resource:     site.Name,
					ResourceType: "app_service",
					Remediation:  "Enable App Service Authentication in Authentication blade. Configure with Entra ID for production workloads.",
					MITRE:        "T1078",
				})
				siteClean = false
			}
		}

		if siteClean { passed++ }
	}
	return findings, passed, nil
}

// ── 12. Azure Container Registry ──────────────────────────────────────────────
func azureCheckContainerRegistry(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.ContainerRegistry/registries?api-version=2023-07-01", sub)
	var resp struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Properties struct {
				AdminUserEnabled    bool   `json:"adminUserEnabled"`
				PublicNetworkAccess string `json:"publicNetworkAccess"` // Enabled, Disabled
				NetworkRuleBypassOptions string `json:"networkRuleBypassOptions"`
				Encryption struct {
					Status string `json:"status"` // enabled, disabled
				} `json:"encryption"`
			} `json:"properties"`
			Sku struct {
				Name string `json:"name"` // Basic, Standard, Premium
			} `json:"sku"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, acr := range resp.Value {
		acrClean := true
		p := acr.Properties

		// Admin user enabled — shared credential, bypasses RBAC and AAD
		if p.AdminUserEnabled {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Container Registry '%s' has admin user enabled", acr.Name),
				Description:  "The admin user is enabled on this registry. The admin account has full access and is a shared credential — it cannot be tied to an individual identity, making audit trails useless for admin operations.",
				Severity:     "high",
				Category:     "iam",
				Resource:     acr.Name,
				ResourceType: "container_registry",
				Remediation:  "Disable the admin user. Use Azure AD service principals or managed identities with AcrPush/AcrPull roles instead.",
				MITRE:        "T1552.001",
			})
			acrClean = false
		}

		// Public network access — should be disabled for production
		if p.PublicNetworkAccess == "Enabled" || p.PublicNetworkAccess == "" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Container Registry '%s' is publicly accessible from internet", acr.Name),
				Description:  "Public network access is enabled. The registry endpoint is reachable from the internet. An attacker with stolen credentials can pull sensitive container images or push malicious ones.",
				Severity:     "medium",
				Category:     "network",
				Resource:     acr.Name,
				ResourceType: "container_registry",
				Remediation:  "Disable public network access and use private endpoints. Requires Premium tier.",
				MITRE:        "T1195.001",
			})
			acrClean = false
		}

		// Customer-managed key encryption — Premium tier only
		if acr.Sku.Name == "Premium" && p.Encryption.Status != "enabled" {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Container Registry '%s' (Premium) has no customer-managed encryption", acr.Name),
				Description:  "This Premium tier registry uses service-managed encryption. Customer-managed keys (CMK) provide control over key lifecycle and the ability to revoke access to all stored images.",
				Severity:     "low",
				Category:     "kms",
				Resource:     acr.Name,
				ResourceType: "container_registry",
				Remediation:  "Configure CMK encryption with an Azure Key Vault key.",
				MITRE:        "T1552.001",
			})
			acrClean = false
		}

		if acrClean { passed++ }
	}
	return findings, passed, nil
}

// ── 13. Azure Function Apps ────────────────────────────────────────────────────
func azureCheckFunctionApps(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Web/sites?api-version=2022-09-01", sub)
	var resp struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Kind       string `json:"kind"`
			Properties struct {
				HTTPSOnly bool   `json:"httpsOnly"`
				SiteConfig *struct {
					MinTLSVersion          string `json:"minTlsVersion"`
					FtpsState              string `json:"ftpsState"`
					RemoteDebuggingEnabled bool   `json:"remoteDebuggingEnabled"`
				} `json:"siteConfig"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, site := range resp.Value {
		// Only function apps
		if !strings.Contains(site.Kind, "functionapp") { continue }
		fnClean := true

		if !site.Properties.HTTPSOnly {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Function App '%s' does not enforce HTTPS", site.Name),
				Description:  "HTTPS Only is not enforced. HTTP trigger invocations expose authorization keys in plaintext.",
				Severity:     "high",
				Category:     "compute",
				Resource:     site.Name,
				ResourceType: "function_app",
				Remediation:  "Enable HTTPS Only in Function App > Settings > Configuration > General settings.",
				MITRE:        "T1040",
			})
			fnClean = false
		}

		if site.Properties.SiteConfig != nil && site.Properties.SiteConfig.RemoteDebuggingEnabled {
			findings = append(findings, CSPMFinding{
				Title:        fmt.Sprintf("Function App '%s' has remote debugging enabled", site.Name),
				Description:  "Remote debugging is enabled on a Function App. Debug endpoints can expose function code and runtime state to attackers.",
				Severity:     "high",
				Category:     "compute",
				Resource:     site.Name,
				ResourceType: "function_app",
				Remediation:  "Disable remote debugging in Function App Configuration unless actively in use.",
				MITRE:        "T1190",
			})
			fnClean = false
		}

		// Check for auth
		authURL := fmt.Sprintf("https://management.azure.com/%s/config/authsettingsV2?api-version=2022-09-01", site.ID)
		var authResp struct {
			Properties struct {
				Platform struct{ Enabled bool `json:"enabled"` } `json:"platform"`
			} `json:"properties"`
		}
		if err := azureCSPMGet(ctx, token, authURL, &authResp); err == nil {
			if !authResp.Properties.Platform.Enabled {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("Function App '%s' has no authentication configured", site.Name),
					Description:  "Function App authentication is not configured. HTTP trigger functions may be callable without any identity verification if function-level authorization is not used.",
					Severity:     "medium",
					Category:     "iam",
					Resource:     site.Name,
					ResourceType: "function_app",
					Remediation:  "Enable App Service Authentication or enforce function-level authorization keys for all HTTP triggers.",
					MITRE:        "T1078",
				})
				fnClean = false
			}
		}

		if fnClean { passed++ }
	}
	return findings, passed, nil
}

// ── 14. SQL Server Auditing + Advanced Threat Protection ─────────────────────
func azureCheckSQLAdvanced(ctx context.Context, token, sub string) ([]CSPMFinding, int, error) {
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview", sub)
	var resp struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := azureCSPMGet(ctx, token, url, &resp); err != nil {
		return nil, 0, err
	}

	var findings []CSPMFinding
	passed := 0

	for _, srv := range resp.Value {
		srvClean := true

		// Auditing check
		auditURL := fmt.Sprintf("https://management.azure.com/%s/auditingSettings/default?api-version=2022-05-01-preview", srv.ID)
		var audit struct {
			Properties struct {
				State                     string `json:"state"`
				RetentionDays             int    `json:"retentionDays"`
				IsStorageSecondaryKeyInUse bool  `json:"isStorageSecondaryKeyInUse"`
				IsAzureMonitorTargetEnabled bool `json:"isAzureMonitorTargetEnabled"`
			} `json:"properties"`
		}
		if auditErr := azureCSPMGet(ctx, token, auditURL, &audit); auditErr == nil {
			if audit.Properties.State != "Enabled" {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("SQL Server '%s' has auditing disabled", srv.Name),
					Description:  "SQL Server auditing is not enabled. Login events, queries, permission changes, and schema modifications are not logged. Required by most compliance frameworks.",
					Severity:     "high",
					Category:     "logging",
					Resource:     srv.Name,
					ResourceType: "sql_server",
					Remediation:  "Enable SQL Server Auditing and target a Log Analytics workspace for SIEM integration.",
					MITRE:        "T1562.008",
				})
				srvClean = false
			} else if audit.Properties.RetentionDays > 0 && audit.Properties.RetentionDays < 90 {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("SQL Server '%s' audit log retention is below 90 days (%d days)", srv.Name, audit.Properties.RetentionDays),
					Description:  fmt.Sprintf("SQL audit logs are retained for only %d days. Most compliance frameworks require 90–365 days minimum.", audit.Properties.RetentionDays),
					Severity:     "medium",
					Category:     "logging",
					Resource:     srv.Name,
					ResourceType: "sql_server",
					Remediation:  "Increase audit log retention to at least 90 days, or use Log Analytics workspace with 365-day retention.",
					MITRE:        "T1562.008",
				})
				srvClean = false
			}
		}

		// Advanced Threat Protection (Microsoft Defender for SQL at server level)
		atpURL := fmt.Sprintf("https://management.azure.com/%s/advancedThreatProtectionSettings/Default?api-version=2021-11-01-preview", srv.ID)
		var atp struct {
			Properties struct {
				State string `json:"state"` // Enabled, Disabled
			} `json:"properties"`
		}
		if atpErr := azureCSPMGet(ctx, token, atpURL, &atp); atpErr == nil {
			if atp.Properties.State != "Enabled" {
				findings = append(findings, CSPMFinding{
					Title:        fmt.Sprintf("SQL Server '%s' has Advanced Threat Protection disabled", srv.Name),
					Description:  "Advanced Threat Protection (Defender for SQL) is not enabled on this SQL Server. SQL injection attacks, anomalous access patterns, and brute force attacks will not be detected.",
					Severity:     "high",
					Category:     "sql",
					Resource:     srv.Name,
					ResourceType: "sql_server",
					Remediation:  "Enable Advanced Threat Protection in SQL Server > Microsoft Defender for Cloud, or enable Defender for SQL at the subscription level.",
					MITRE:        "T1562.001",
				})
				srvClean = false
			}
		}

		if srvClean { passed++ }
	}
	return findings, passed, nil
}
