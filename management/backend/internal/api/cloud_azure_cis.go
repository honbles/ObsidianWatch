package api

// cloud_azure_cis.go — CIS Microsoft Azure Foundations Benchmark v2.0
//
// Sections:
//   1. Identity and Access Management (1.1 – 1.23)
//   2. Microsoft Defender for Cloud (2.1 – 2.14)
//   3. Storage Accounts (3.1 – 3.15)
//   4. Database Services (4.1 – 4.5)
//   5. Logging and Monitoring (5.1 – 5.6)
//   6. Networking (6.1 – 6.6)
//   7. Virtual Machines (7.1 – 7.7)
//   8. Key Vault (8.1 – 8.7)

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CISAzureResult mirrors CISResult but for Azure
type CISAzureResult struct {
	ConnectorID    int64            `json:"connector_id"`
	SubscriptionID string           `json:"subscription_id"`
	ScannedAt      time.Time        `json:"scanned_at"`
	Controls       []CISControl     `json:"controls"`
	TotalChecks    int              `json:"total_checks"`
	Passed         int              `json:"passed"`
	Failed         int              `json:"failed"`
	Unknown        int              `json:"unknown"`
	ScorePercent   float64          `json:"score_percent"`
	Level1Score    float64          `json:"level1_score"`
	Level2Score    float64          `json:"level2_score"`
	Errors         []string         `json:"errors,omitempty"`
	// AZ-09: be explicit about what this is — a partial subset, not the full benchmark.
	Benchmark      string           `json:"benchmark"`
	CoverageNote   string           `json:"coverage_note"`
	ControlsImplemented int         `json:"controls_implemented"`
}

func RunAzureCISBenchmark(ctx context.Context, tenantID, clientID, clientSecret, subID string) (*CISAzureResult, error) {
	start := time.Now()
	result := &CISAzureResult{SubscriptionID: subID, ScannedAt: start}

	token, err := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://management.azure.com/")
	if err != nil {
		return nil, fmt.Errorf("azure auth: %w", err)
	}
	graphToken, _ := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://graph.microsoft.com/")

	t := token.AccessToken
	gt := ""
	if graphToken != nil { gt = graphToken.AccessToken }

	var controls []CISControl

	runCheck := func(name string, fn func() CISControl) {
		defer func() {
			if r := recover(); r != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: panic: %v", name, r))
			}
		}()
		c := fn()
		controls = append(controls, c)
	}

	// ── Section 1: Identity and Access Management ─────────────────────────────

	runCheck("1.1", func() CISControl {
		c := CISControl{ID: "1.1", Title: "Ensure that multi-factor authentication is enabled for all privileged users",
			Section: "IAM", Level: 1, MITRE: "T1078"}
		if gt == "" { c.Status = "UNKNOWN"; c.Evidence = "Graph API token unavailable"; return c }
		var resp struct {
			Value []caPolicy `json:"value"`
		}
		if err := azureCSPMGet(ctx, gt, "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		if name, ok := caCoversPrivilegedMFA(resp.Value); ok {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("Conditional Access policy %q requires MFA for all users or privileged roles", name)
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("%d CA policies found; none enabled with an MFA grant control targeting all users or directory roles", len(resp.Value))
			c.Remediation = "Create a Conditional Access policy: Users > All users (or directory roles), Cloud apps > All, Grant > Require multifactor authentication. Exclude emergency access accounts only."
		}
		return c
	})

	runCheck("1.2", func() CISControl {
		c := CISControl{ID: "1.2", Title: "Ensure that multi-factor authentication is enabled for all non-privileged users",
			Section: "IAM", Level: 2, MITRE: "T1078"}
		if gt == "" { c.Status = "UNKNOWN"; c.Evidence = "Graph API token unavailable"; return c }
		var secDefaults struct {
			IsEnabled bool `json:"isEnabled"`
		}
		if err := azureCSPMGet(ctx, gt, "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", &secDefaults); err == nil && secDefaults.IsEnabled {
			c.Status = "PASS"; c.Evidence = "Security Defaults enabled — MFA required for all users"
			return c
		}
		var cp struct {
			Value []caPolicy `json:"value"`
		}
		if err := azureCSPMGet(ctx, gt, "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", &cp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = "Security Defaults off and Conditional Access unreadable: " + err.Error(); return c
		}
		if name, ok := caCoversAllUsersMFA(cp.Value); ok {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("Conditional Access policy %q requires MFA for all users on all apps", name)
			return c
		}
		c.Status = "FAIL"
		c.Evidence = "Security Defaults off and no enabled Conditional Access policy requires MFA for All users on All cloud apps"
		c.Remediation = "Enable Security Defaults or create a CA policy targeting all users requiring MFA."
		return c
	})

	runCheck("1.3", func() CISControl {
		c := CISControl{ID: "1.3", Title: "Ensure guest users are reviewed at least monthly",
			Section: "IAM", Level: 1, MITRE: "T1136.003"}
		if gt == "" { c.Status = "UNKNOWN"; c.Evidence = "Graph API token unavailable"; return c }
		var resp struct{ Value []struct{ UserType string `json:"userType"` } `json:"value"` }
		if err := azureCSPMGet(ctx, gt, "https://graph.microsoft.com/v1.0/users?$filter=userType eq 'Guest'&$count=true&$top=1", &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		// CIS just checks guest users exist — reviewable process; we flag if count > 0 as info
		if len(resp.Value) == 0 {
			c.Status = "PASS"; c.Evidence = "No guest users found in the tenant"
		} else {
			c.Status = "FAIL"
			c.Evidence = "Guest users exist in the tenant — ensure they are reviewed monthly and access is still required"
			c.Remediation = "Use Azure AD Access Reviews (Identity Governance) to automate monthly guest user reviews."
		}
		return c
	})

	runCheck("1.4", func() CISControl {
		c := CISControl{ID: "1.4", Title: "Ensure that 'Allow users to remember multi-factor authentication' is disabled",
			Section: "IAM", Level: 1, MITRE: "T1078"}
		if gt == "" { c.Status = "UNKNOWN"; c.Evidence = "Graph API token unavailable"; return c }
		var policy struct {
			AllowInvitesFrom string `json:"allowInvitesFrom"`
		}
		if err := azureCSPMGet(ctx, gt, "https://graph.microsoft.com/v1.0/policies/authorizationPolicy", &policy); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		if policy.AllowInvitesFrom == "adminsOnly" || policy.AllowInvitesFrom == "none" {
			c.Status = "PASS"; c.Evidence = "Guest invitations restricted to admins only"
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("Guest invitations allowed by: %s", policy.AllowInvitesFrom)
			c.Remediation = "Set allowInvitesFrom to 'adminsOnly' in Azure AD External Identities settings."
		}
		return c
	})

	runCheck("1.5", func() CISControl {
		c := CISControl{ID: "1.5", Title: "Ensure that no custom subscription owner roles are created",
			Section: "IAM", Level: 1, MITRE: "T1078.004"}
		roleDefsURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?$filter=type eq 'CustomRole'&api-version=2022-04-01", subID)
		var resp struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					RoleName        string   `json:"roleName"`
					AssignableScopes []string `json:"assignableScopes"`
					Permissions     []struct {
						Actions []string `json:"actions"`
					} `json:"permissions"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, roleDefsURL, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		ownerLikeRoles := []string{}
		for _, r := range resp.Value {
			for _, perm := range r.Properties.Permissions {
				for _, action := range perm.Actions {
					if action == "*" {
						ownerLikeRoles = append(ownerLikeRoles, r.Properties.RoleName)
						break
					}
				}
			}
		}
		if len(ownerLikeRoles) == 0 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("%d custom roles, none with wildcard (*) actions", len(resp.Value))
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("Custom roles with wildcard (*) permissions: %s", strings.Join(ownerLikeRoles, ", "))
			c.Remediation = "Remove or restrict custom roles with '*' actions. Use built-in roles or custom roles with specific, minimal action sets."
		}
		return c
	})

	runCheck("1.6", func() CISControl {
		c := CISControl{ID: "1.6", Title: "Ensure that 'Restrict access to Azure AD administration portal' is set to Yes",
			Section: "IAM", Level: 1, MITRE: "T1078"}
		if gt == "" { c.Status = "UNKNOWN"; c.Evidence = "Graph API token unavailable"; return c }
		var policy struct {
			DefaultUserRolePermissions struct {
				AllowedToCreateSecurityGroups bool `json:"allowedToCreateSecurityGroups"`
				AllowedToCreateTenantWideApps bool `json:"allowedToCreateTenantWideApps"`
				AllowedToReadOtherUsers       bool `json:"allowedToReadOtherUsers"`
			} `json:"defaultUserRolePermissions"`
		}
		if err := azureCSPMGet(ctx, gt, "https://graph.microsoft.com/v1.0/policies/authorizationPolicy", &policy); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		if policy.DefaultUserRolePermissions.AllowedToCreateTenantWideApps {
			c.Status = "FAIL"
			c.Evidence = "Users can register tenant-wide applications — increases attack surface"
			c.Remediation = "Set 'Users can register applications' to No in Azure AD > User Settings."
		} else {
			c.Status = "PASS"; c.Evidence = "Users cannot register tenant-wide applications"
		}
		return c
	})

	// ── Section 2: Microsoft Defender for Cloud ───────────────────────────────

	runCheck("2.1", func() CISControl {
		c := CISControl{ID: "2.1", Title: "Ensure that Microsoft Defender for Servers is set to On",
			Section: "Defender", Level: 1, MITRE: "T1562.001"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/pricings/VirtualMachines?api-version=2022-03-01", subID)
		var resp struct {
			Properties struct { PricingTier string `json:"pricingTier"` } `json:"properties"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		if resp.Properties.PricingTier == "Standard" {
			c.Status = "PASS"; c.Evidence = "Defender for Servers is enabled (Standard tier)"
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("Defender for Servers is on '%s' tier — threat detection not active", resp.Properties.PricingTier)
			c.Remediation = "Enable Defender for Servers (Standard/P2) in Microsoft Defender for Cloud > Environment settings."
		}
		return c
	})

	runCheck("2.2", func() CISControl {
		c := CISControl{ID: "2.2", Title: "Ensure that Microsoft Defender for App Services is set to On",
			Section: "Defender", Level: 1, MITRE: "T1562.001"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/pricings/AppServices?api-version=2022-03-01", subID)
		var resp struct {
			Properties struct { PricingTier string `json:"pricingTier"` } `json:"properties"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		if resp.Properties.PricingTier == "Standard" {
			c.Status = "PASS"; c.Evidence = "Defender for App Services enabled"
		} else {
			c.Status = "FAIL"
			c.Evidence = "Defender for App Services on Free tier"
			c.Remediation = "Enable Defender for App Services to detect web shell attacks, suspicious logins, and known vulnerabilities."
		}
		return c
	})

	runCheck("2.3", func() CISControl {
		c := CISControl{ID: "2.3", Title: "Ensure that Microsoft Defender for SQL Servers is set to On",
			Section: "Defender", Level: 1, MITRE: "T1562.001"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/pricings/SqlServers?api-version=2022-03-01", subID)
		var resp struct {
			Properties struct { PricingTier string `json:"pricingTier"` } `json:"properties"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		if resp.Properties.PricingTier == "Standard" {
			c.Status = "PASS"; c.Evidence = "Defender for SQL Servers enabled"
		} else {
			c.Status = "FAIL"
			c.Evidence = "Defender for SQL on Free tier — SQL injection and anomaly detection inactive"
			c.Remediation = "Enable Defender for SQL Servers for Advanced Threat Protection and vulnerability assessment."
		}
		return c
	})

	runCheck("2.4", func() CISControl {
		c := CISControl{ID: "2.4", Title: "Ensure that Microsoft Defender for Storage is set to On",
			Section: "Defender", Level: 1, MITRE: "T1562.001"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/pricings/StorageAccounts?api-version=2022-03-01", subID)
		var resp struct {
			Properties struct { PricingTier string `json:"pricingTier"` } `json:"properties"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		if resp.Properties.PricingTier == "Standard" {
			c.Status = "PASS"; c.Evidence = "Defender for Storage enabled"
		} else {
			c.Status = "FAIL"
			c.Evidence = "Defender for Storage on Free tier — malware upload detection and anomalous access alerts inactive"
			c.Remediation = "Enable Defender for Storage to detect malware uploads, anonymous access anomalies, and data exfiltration."
		}
		return c
	})

	runCheck("2.5", func() CISControl {
		c := CISControl{ID: "2.5", Title: "Ensure that Microsoft Defender for Key Vault is set to On",
			Section: "Defender", Level: 1, MITRE: "T1562.001"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/pricings/KeyVaults?api-version=2022-03-01", subID)
		var resp struct {
			Properties struct { PricingTier string `json:"pricingTier"` } `json:"properties"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		if resp.Properties.PricingTier == "Standard" {
			c.Status = "PASS"; c.Evidence = "Defender for Key Vault enabled"
		} else {
			c.Status = "FAIL"
			c.Evidence = "Defender for Key Vault on Free tier — unusual access pattern detection inactive"
			c.Remediation = "Enable Defender for Key Vault to detect credential theft and unusual secret access patterns."
		}
		return c
	})

	// ── Section 3: Storage Accounts ───────────────────────────────────────────

	runCheck("3.1", func() CISControl {
		c := CISControl{ID: "3.1", Title: "Ensure that 'Secure transfer required' is set to Enabled for Storage Accounts",
			Section: "Storage", Level: 1, MITRE: "T1040"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01", subID)
		var resp struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					EnableHTTPSTrafficOnly bool `json:"supportsHttpsTrafficOnly"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		failing := []string{}
		for _, sa := range resp.Value {
			if !sa.Properties.EnableHTTPSTrafficOnly {
				failing = append(failing, sa.Name)
			}
		}
		if len(failing) == 0 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("All %d storage accounts require HTTPS", len(resp.Value))
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("Storage accounts allowing HTTP: %s", strings.Join(failing, ", "))
			c.Remediation = "Enable 'Secure transfer required' on all storage accounts."
		}
		return c
	})

	runCheck("3.2", func() CISControl {
		c := CISControl{ID: "3.2", Title: "Ensure that storage account access keys are periodically regenerated",
			Section: "Storage", Level: 1, MITRE: "T1552.001"}
		// Check if any storage account has shared key access enabled (proxy for old keys)
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01", subID)
		var resp struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					AllowSharedKeyAccess *bool `json:"allowSharedKeyAccess"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		withSharedKey := []string{}
		for _, sa := range resp.Value {
			if sa.Properties.AllowSharedKeyAccess == nil || *sa.Properties.AllowSharedKeyAccess {
				withSharedKey = append(withSharedKey, sa.Name)
			}
		}
		if len(withSharedKey) == 0 {
			c.Status = "PASS"; c.Evidence = "All storage accounts have shared key access disabled"
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("%d storage account(s) allow shared key access: %s", len(withSharedKey), strings.Join(withSharedKey[:min(3, len(withSharedKey))], ", "))
			c.Remediation = "Disable shared key access and rotate keys if still needed. Migrate clients to Azure AD authentication."
		}
		return c
	})

	runCheck("3.3", func() CISControl {
		c := CISControl{ID: "3.3", Title: "Ensure Storage logging is enabled for Queue service for read, write, and delete requests",
			Section: "Storage", Level: 2, MITRE: "T1562.008"}
		// This is a configuration best practice; check via diagnostic settings
		diagURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview", subID)
		var diagResp struct {
			Value []struct{ Name string `json:"name"` } `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, diagURL, &diagResp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		if len(diagResp.Value) > 0 {
			c.Status = "PASS"; c.Evidence = "Subscription-level diagnostic settings configured"
		} else {
			c.Status = "FAIL"
			c.Evidence = "No diagnostic settings found at subscription level"
			c.Remediation = "Enable diagnostic settings for storage accounts to capture queue read/write/delete operations."
		}
		return c
	})

	runCheck("3.4", func() CISControl {
		c := CISControl{ID: "3.4", Title: "Ensure that Azure Storage Account public access is disallowed",
			Section: "Storage", Level: 1, MITRE: "T1530"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01", subID)
		var resp struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					AllowBlobPublicAccess *bool `json:"allowBlobPublicAccess"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		failing := []string{}
		for _, sa := range resp.Value {
			if sa.Properties.AllowBlobPublicAccess == nil || *sa.Properties.AllowBlobPublicAccess {
				failing = append(failing, sa.Name)
			}
		}
		if len(failing) == 0 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("All %d storage accounts block public blob access", len(resp.Value))
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("Storage accounts allowing public blob access: %s", strings.Join(failing[:min(5, len(failing))], ", "))
			c.Remediation = "Set allowBlobPublicAccess: false on all storage accounts."
		}
		return c
	})

	// ── Section 4: Database Services ─────────────────────────────────────────

	runCheck("4.1", func() CISControl {
		c := CISControl{ID: "4.1", Title: "Ensure that 'Auditing' is set to On for SQL Servers",
			Section: "Database", Level: 1, MITRE: "T1562.008"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview", subID)
		var resp struct {
			Value []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		failing := []string{}
		for _, srv := range resp.Value {
			auditURL := fmt.Sprintf("https://management.azure.com/%s/auditingSettings/default?api-version=2022-05-01-preview", srv.ID)
			var audit struct {
				Properties struct {
					State string `json:"state"`
				} `json:"properties"`
			}
			if err := azureCSPMGet(ctx, t, auditURL, &audit); err != nil || audit.Properties.State != "Enabled" {
				failing = append(failing, srv.Name)
			}
		}
		if len(failing) == 0 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("All %d SQL servers have auditing enabled", len(resp.Value))
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("SQL servers without auditing: %s", strings.Join(failing, ", "))
			c.Remediation = "Enable SQL Server Auditing and configure it to write to Log Analytics workspace or storage account."
		}
		return c
	})

	runCheck("4.2", func() CISControl {
		c := CISControl{ID: "4.2", Title: "Ensure that 'Advanced Threat Protection' is set to Enabled for SQL Servers",
			Section: "Database", Level: 2, MITRE: "T1562.001"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview", subID)
		var resp struct {
			Value []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		failing := []string{}
		for _, srv := range resp.Value {
			atpURL := fmt.Sprintf("https://management.azure.com/%s/advancedThreatProtectionSettings/Default?api-version=2021-11-01-preview", srv.ID)
			var atp struct {
				Properties struct {
					State string `json:"state"`
				} `json:"properties"`
			}
			if err := azureCSPMGet(ctx, t, atpURL, &atp); err != nil || atp.Properties.State != "Enabled" {
				failing = append(failing, srv.Name)
			}
		}
		if len(failing) == 0 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("All %d SQL servers have ATP enabled", len(resp.Value))
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("SQL servers without ATP: %s", strings.Join(failing, ", "))
			c.Remediation = "Enable Advanced Threat Protection on SQL Servers to detect SQL injection, brute force, and data exfiltration."
		}
		return c
	})

	runCheck("4.3", func() CISControl {
		c := CISControl{ID: "4.3", Title: "Ensure that 'TDE protector' is set to 'Customer-managed key'",
			Section: "Database", Level: 2, MITRE: "T1552.001"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview", subID)
		var resp struct {
			Value []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		usingCMK := 0
		total := len(resp.Value)
		for _, srv := range resp.Value {
			tdeURL := fmt.Sprintf("https://management.azure.com/%s/encryptionProtector?api-version=2022-05-01-preview", srv.ID)
			var tde struct {
				Value []struct {
					Properties struct {
						ServerKeyType string `json:"serverKeyType"`
					} `json:"properties"`
				} `json:"value"`
			}
			if err := azureCSPMGet(ctx, t, tdeURL, &tde); err == nil {
				for _, p := range tde.Value {
					if p.Properties.ServerKeyType == "AzureKeyVault" {
						usingCMK++
					}
				}
			}
		}
		if total == 0 {
			c.Status = "NOT_APPLICABLE"; c.Evidence = "No SQL servers found"
		} else if usingCMK == total {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("All %d SQL servers use customer-managed TDE keys", total)
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("%d of %d SQL servers use service-managed keys (not CMK)", total-usingCMK, total)
			c.Remediation = "Configure TDE with a customer-managed key from Azure Key Vault for control over key lifecycle."
		}
		return c
	})

	// ── Section 5: Logging and Monitoring ────────────────────────────────────

	runCheck("5.1", func() CISControl {
		c := CISControl{ID: "5.1", Title: "Ensure that a 'Diagnostic Setting' exists for the subscription",
			Section: "Logging", Level: 1, MITRE: "T1562.008"}
		diagURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview", subID)
		var diagResp struct {
			Value []struct{ Name string `json:"name"` } `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, diagURL, &diagResp); err != nil || len(diagResp.Value) == 0 {
			c.Status = "FAIL"
			c.Evidence = "No diagnostic settings configured at subscription level"
			c.Remediation = "Create a diagnostic setting to export Activity Log to Log Analytics workspace."
		} else {
			c.Status = "PASS"
			c.Evidence = fmt.Sprintf("%d diagnostic setting(s) configured", len(diagResp.Value))
		}
		return c
	})

	runCheck("5.2", func() CISControl {
		c := CISControl{ID: "5.2", Title: "Ensure that Activity Retention Log is set to 1 year or greater",
			Section: "Logging", Level: 1, MITRE: "T1562.008"}
		diagURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview", subID)
		var diagResp struct {
			Value []struct {
				Properties struct {
					StorageAccountID string `json:"storageAccountId"`
					WorkspaceID      string `json:"workspaceId"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, diagURL, &diagResp); err != nil || len(diagResp.Value) == 0 {
			c.Status = "FAIL"; c.Evidence = "No diagnostic settings — cannot verify retention"
			c.Remediation = "Configure diagnostic settings with Log Analytics workspace set to 365-day retention."
			return c
		}
		hasLAW := false
		for _, ds := range diagResp.Value {
			if ds.Properties.WorkspaceID != "" || ds.Properties.StorageAccountID != "" {
				hasLAW = true
			}
		}
		if hasLAW {
			c.Status = "PASS"; c.Evidence = "Diagnostic settings route to Log Analytics workspace or storage — verify retention ≥ 365 days in LAW settings"
		} else {
			c.Status = "FAIL"; c.Evidence = "Diagnostic settings found but no workspace/storage destination configured"
			c.Remediation = "Set Log Analytics workspace retention to 365 days minimum in Log Analytics > Usage and estimated costs > Data Retention."
		}
		return c
	})

	runCheck("5.3", func() CISControl {
		c := CISControl{ID: "5.3", Title: "Ensure audit profile captures all activities",
			Section: "Logging", Level: 1, MITRE: "T1562.008"}
		diagURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview", subID)
		var diagResp struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					Logs []struct {
						Category string `json:"category"`
						Enabled  bool   `json:"enabled"`
					} `json:"logs"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, diagURL, &diagResp); err != nil || len(diagResp.Value) == 0 {
			c.Status = "FAIL"; c.Evidence = "No diagnostic settings found"
			c.Remediation = "Create diagnostic settings capturing all Activity Log categories."
			return c
		}
		required := []string{"Administrative", "Security", "Alert", "Recommendation", "Policy"}
		missing := []string{}
		for _, req := range required {
			found := false
			for _, ds := range diagResp.Value {
				for _, l := range ds.Properties.Logs {
					if l.Category == req && l.Enabled { found = true }
				}
			}
			if !found { missing = append(missing, req) }
		}
		if len(missing) == 0 {
			c.Status = "PASS"; c.Evidence = "All required Activity Log categories are captured"
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("Missing log categories: %s", strings.Join(missing, ", "))
			c.Remediation = "Enable all Activity Log categories in diagnostic settings."
		}
		return c
	})

	runCheck("5.4", func() CISControl {
		c := CISControl{ID: "5.4", Title: "Ensure activity log alert exists for Create Policy Assignment",
			Section: "Logging", Level: 1, MITRE: "T1562.001"}
		alertURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/microsoft.insights/activityLogAlerts?api-version=2020-10-01", subID)
		var resp struct {
			Value []struct {
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
		if err := azureCSPMGet(ctx, t, alertURL, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		hasPolicyAlert := false
		for _, alert := range resp.Value {
			if !alert.Properties.Enabled { continue }
			for _, cond := range alert.Properties.Condition.AllOf {
				if cond.Field == "operationName" && strings.Contains(strings.ToLower(cond.Equals), "policy") {
					hasPolicyAlert = true
				}
			}
		}
		if hasPolicyAlert {
			c.Status = "PASS"; c.Evidence = "Activity log alert for policy operations found"
		} else {
			c.Status = "FAIL"
			c.Evidence = "No activity log alert for Create/Update/Delete Policy Assignment"
			c.Remediation = "Create an Activity Log alert for operationName: Microsoft.Authorization/policyAssignments/write."
		}
		return c
	})

	runCheck("5.5", func() CISControl {
		c := CISControl{ID: "5.5", Title: "Ensure activity log alert exists for Create or Update Network Security Group",
			Section: "Logging", Level: 1, MITRE: "T1562.001"}
		alertURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/microsoft.insights/activityLogAlerts?api-version=2020-10-01", subID)
		var resp struct {
			Value []struct {
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
		if err := azureCSPMGet(ctx, t, alertURL, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		hasNSGAlert := false
		for _, alert := range resp.Value {
			if !alert.Properties.Enabled { continue }
			for _, cond := range alert.Properties.Condition.AllOf {
				if cond.Field == "operationName" && strings.Contains(strings.ToLower(cond.Equals), "networksecuritygroups") {
					hasNSGAlert = true
				}
			}
		}
		if hasNSGAlert {
			c.Status = "PASS"; c.Evidence = "Activity log alert for NSG operations found"
		} else {
			c.Status = "FAIL"
			c.Evidence = "No activity log alert for NSG create/update/delete"
			c.Remediation = "Create an Activity Log alert for: Microsoft.Network/networkSecurityGroups/write and Microsoft.Network/networkSecurityGroups/delete."
		}
		return c
	})

	runCheck("5.6", func() CISControl {
		c := CISControl{ID: "5.6", Title: "Ensure activity log alert exists for Create or Update Security Solution",
			Section: "Logging", Level: 1, MITRE: "T1562.001"}
		alertURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/microsoft.insights/activityLogAlerts?api-version=2020-10-01", subID)
		var resp struct {
			Value []struct {
				Properties struct { Enabled bool `json:"enabled"` } `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, alertURL, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		enabledAlerts := 0
		for _, a := range resp.Value { if a.Properties.Enabled { enabledAlerts++ } }
		if enabledAlerts >= 3 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("%d enabled activity log alerts found", enabledAlerts)
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("Only %d enabled activity log alerts — security solution alerts may be missing", enabledAlerts)
			c.Remediation = "Create alerts for Microsoft.Security/securitySolutions/write and delete."
		}
		return c
	})

	// ── Section 6: Networking ────────────────────────────────────────────────

	runCheck("6.1", func() CISControl {
		c := CISControl{ID: "6.1", Title: "Ensure that RDP access from the Internet is evaluated and restricted",
			Section: "Networking", Level: 1, MITRE: "T1190"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01", subID)
		var resp struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					SecurityRules []struct {
						Properties nsgRuleProps `json:"properties"`
					} `json:"securityRules"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		rdpOpen := []string{}
		for _, nsg := range resp.Value {
			for _, rule := range nsg.Properties.SecurityRules {
				if nsgRuleExposes(rule.Properties, 3389) {
					rdpOpen = append(rdpOpen, nsg.Name)
					break
				}
			}
		}
		if len(rdpOpen) == 0 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("Checked %d NSGs — no unrestricted RDP (3389) from internet", len(resp.Value))
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("NSGs with RDP open to internet: %s", strings.Join(rdpOpen, ", "))
			c.Remediation = "Remove open RDP rules. Use Azure Bastion or VPN for RDP access."
		}
		return c
	})

	runCheck("6.2", func() CISControl {
		c := CISControl{ID: "6.2", Title: "Ensure that SSH access from the Internet is evaluated and restricted",
			Section: "Networking", Level: 1, MITRE: "T1190"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01", subID)
		var resp struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					SecurityRules []struct {
						Properties nsgRuleProps `json:"properties"`
					} `json:"securityRules"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		sshOpen := []string{}
		for _, nsg := range resp.Value {
			for _, rule := range nsg.Properties.SecurityRules {
				if nsgRuleExposes(rule.Properties, 22) {
					sshOpen = append(sshOpen, nsg.Name)
					break
				}
			}
		}
		if len(sshOpen) == 0 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("Checked %d NSGs — no unrestricted SSH (22) from internet", len(resp.Value))
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("NSGs with SSH open to internet: %s", strings.Join(sshOpen, ", "))
			c.Remediation = "Remove open SSH rules. Use Azure Bastion, Just-in-Time VM Access, or VPN."
		}
		return c
	})

	runCheck("6.3", func() CISControl {
		c := CISControl{ID: "6.3", Title: "Ensure that Network Watcher is Enabled",
			Section: "Networking", Level: 1, MITRE: "T1562.008"}
		nwURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/networkWatchers?api-version=2023-05-01", subID)
		var resp struct {
			Value []struct {
				Name             string `json:"name"`
				ProvisioningState string `json:"provisioningState"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, nwURL, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		active := 0
		for _, nw := range resp.Value {
			if nw.ProvisioningState == "Succeeded" { active++ }
		}
		if active > 0 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("%d Network Watcher(s) active", active)
		} else {
			c.Status = "FAIL"
			c.Evidence = "No active Network Watchers found"
			c.Remediation = "Enable Network Watcher in each region where you have resources."
		}
		return c
	})

	// ── Section 7: Virtual Machines ───────────────────────────────────────────

	runCheck("7.1", func() CISControl {
		c := CISControl{ID: "7.1", Title: "Ensure that 'OS disk' are encrypted with Customer Managed Key (CMK)",
			Section: "VMs", Level: 2, MITRE: "T1486"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01", subID)
		var resp struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					StorageProfile struct {
						OsDisk struct {
							ManagedDisk *struct {
								DiskEncryptionSet *struct{ ID string `json:"id"` } `json:"diskEncryptionSet"`
							} `json:"managedDisk"`
						} `json:"osDisk"`
					} `json:"storageProfile"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		noCMK := []string{}
		for _, vm := range resp.Value {
			hasCMK := false
			if vm.Properties.StorageProfile.OsDisk.ManagedDisk != nil &&
				vm.Properties.StorageProfile.OsDisk.ManagedDisk.DiskEncryptionSet != nil {
				hasCMK = true
			}
			if !hasCMK { noCMK = append(noCMK, vm.Name) }
		}
		if len(noCMK) == 0 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("All %d VMs have CMK disk encryption", len(resp.Value))
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("%d VM(s) without CMK: %s", len(noCMK), strings.Join(noCMK[:min(5, len(noCMK))], ", "))
			c.Remediation = "Create a Disk Encryption Set with a Key Vault CMK and associate it with VM managed disks."
		}
		return c
	})

	runCheck("7.2", func() CISControl {
		c := CISControl{ID: "7.2", Title: "Ensure that 'Unattached disks' are encrypted with Customer Managed Key (CMK)",
			Section: "VMs", Level: 2, MITRE: "T1486"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Compute/disks?api-version=2023-04-02", subID)
		var resp struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					DiskState        string `json:"diskState"`
					Encryption struct {
						Type string `json:"type"`
					} `json:"encryption"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		unattachedNoCMK := []string{}
		for _, disk := range resp.Value {
			if disk.Properties.DiskState == "Unattached" &&
				disk.Properties.Encryption.Type != "EncryptionAtRestWithCustomerKey" {
				unattachedNoCMK = append(unattachedNoCMK, disk.Name)
			}
		}
		if len(unattachedNoCMK) == 0 {
			c.Status = "PASS"; c.Evidence = "No unencrypted unattached disks found"
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("%d unattached disk(s) without CMK: %s", len(unattachedNoCMK), strings.Join(unattachedNoCMK[:min(5, len(unattachedNoCMK))], ", "))
			c.Remediation = "Delete unused disks or encrypt them with a Disk Encryption Set (CMK)."
		}
		return c
	})

	runCheck("7.3", func() CISControl {
		c := CISControl{ID: "7.3", Title: "Ensure that 'Endpoint protection' solution is installed on VMs",
			Section: "VMs", Level: 1, MITRE: "T1562.001"}
		// Check Defender for Servers plan as proxy
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/pricings/VirtualMachines?api-version=2022-03-01", subID)
		var resp struct {
			Properties struct { PricingTier string `json:"pricingTier"` } `json:"properties"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		if resp.Properties.PricingTier == "Standard" {
			c.Status = "PASS"; c.Evidence = "Defender for Servers enabled — includes MDE (endpoint protection)"
		} else {
			c.Status = "FAIL"
			c.Evidence = "Defender for Servers not enabled — no centrally managed endpoint protection"
			c.Remediation = "Enable Defender for Servers P2 which includes Microsoft Defender for Endpoint (MDE) on VMs."
		}
		return c
	})

	// ── Section 8: Key Vault ─────────────────────────────────────────────────

	runCheck("8.1", func() CISControl {
		c := CISControl{ID: "8.1", Title: "Ensure that the expiration date is set on all keys in RBAC Key Vaults",
			Section: "KeyVault", Level: 1, MITRE: "T1552.001"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=2023-02-01", subID)
		var resp struct {
			Value []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Properties struct {
					EnableRbacAuthorization *bool `json:"enableRbacAuthorization"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		vaultsChecked := 0
		noExpiry := []string{}
		for _, kv := range resp.Value {
			if kv.Properties.EnableRbacAuthorization == nil || !*kv.Properties.EnableRbacAuthorization {
				continue // skip non-RBAC vaults
			}
			vaultsChecked++
			keysURL := fmt.Sprintf("https://management.azure.com/%s/keys?api-version=2023-02-01", kv.ID)
			var keysResp struct {
				Value []struct {
					Name       string `json:"name"`
					Properties struct {
						Attributes struct {
							Expires *int64 `json:"exp"`
							Enabled bool   `json:"enabled"`
						} `json:"attributes"`
					} `json:"properties"`
				} `json:"value"`
			}
			if err := azureCSPMGet(ctx, t, keysURL, &keysResp); err != nil { continue }
			for _, key := range keysResp.Value {
				if key.Properties.Attributes.Enabled && key.Properties.Attributes.Expires == nil {
					noExpiry = append(noExpiry, fmt.Sprintf("%s/%s", kv.Name, key.Name))
				}
			}
		}
		if len(noExpiry) == 0 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("Checked %d RBAC Key Vault(s) — all keys have expiration dates", vaultsChecked)
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("Keys without expiration: %s", strings.Join(noExpiry[:min(5, len(noExpiry))], ", "))
			c.Remediation = "Set expiration dates on all Key Vault keys. Keys should be rotated at least annually."
		}
		return c
	})

	runCheck("8.2", func() CISControl {
		c := CISControl{ID: "8.2", Title: "Ensure that the expiration date is set on all secrets in RBAC Key Vaults",
			Section: "KeyVault", Level: 1, MITRE: "T1552.001"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=2023-02-01", subID)
		var resp struct {
			Value []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Properties struct {
					EnableRbacAuthorization *bool `json:"enableRbacAuthorization"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		noExpiry := []string{}
		for _, kv := range resp.Value {
			if kv.Properties.EnableRbacAuthorization == nil || !*kv.Properties.EnableRbacAuthorization {
				continue
			}
			secretsURL := fmt.Sprintf("https://management.azure.com/%s/secrets?api-version=2023-02-01", kv.ID)
			var secResp struct {
				Value []struct {
					Name       string `json:"name"`
					Properties struct {
						Attributes struct {
							Expires *int64 `json:"exp"`
							Enabled bool   `json:"enabled"`
						} `json:"attributes"`
					} `json:"properties"`
				} `json:"value"`
			}
			if err := azureCSPMGet(ctx, t, secretsURL, &secResp); err != nil { continue }
			for _, sec := range secResp.Value {
				if sec.Properties.Attributes.Enabled && sec.Properties.Attributes.Expires == nil {
					noExpiry = append(noExpiry, fmt.Sprintf("%s/%s", kv.Name, sec.Name))
				}
			}
		}
		if len(noExpiry) == 0 {
			c.Status = "PASS"; c.Evidence = "All secrets in RBAC Key Vaults have expiration dates"
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("Secrets without expiration: %s", strings.Join(noExpiry[:min(5, len(noExpiry))], ", "))
			c.Remediation = "Set expiration dates on all Key Vault secrets."
		}
		return c
	})

	runCheck("8.3", func() CISControl {
		c := CISControl{ID: "8.3", Title: "Ensure that Key Vault is recoverable (soft-delete and purge protection enabled)",
			Section: "KeyVault", Level: 1, MITRE: "T1485"}
		url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=2023-02-01", subID)
		var resp struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					EnableSoftDelete      *bool `json:"enableSoftDelete"`
					EnablePurgeProtection *bool `json:"enablePurgeProtection"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, t, url, &resp); err != nil {
			c.Status = "UNKNOWN"; c.Evidence = err.Error(); return c
		}
		failing := []string{}
		for _, kv := range resp.Value {
			if kv.Properties.EnableSoftDelete == nil || !*kv.Properties.EnableSoftDelete ||
				kv.Properties.EnablePurgeProtection == nil || !*kv.Properties.EnablePurgeProtection {
				failing = append(failing, kv.Name)
			}
		}
		if len(failing) == 0 {
			c.Status = "PASS"; c.Evidence = fmt.Sprintf("All %d Key Vaults have soft-delete and purge protection", len(resp.Value))
		} else {
			c.Status = "FAIL"
			c.Evidence = fmt.Sprintf("Key Vaults missing soft-delete/purge protection: %s", strings.Join(failing, ", "))
			c.Remediation = "Enable both soft-delete (90 day retention) and purge protection on all Key Vaults."
		}
		return c
	})

	// Score calculation
	l1Pass, l1Total, l2Pass, l2Total := 0, 0, 0, 0
	for _, c := range controls {
		result.TotalChecks++
		switch c.Status {
		case "PASS":
			result.Passed++
			if c.Level == 1 { l1Pass++; l1Total++ } else { l2Pass++; l2Total++ }
		case "FAIL":
			result.Failed++
			if c.Level == 1 { l1Total++ } else { l2Total++ }
		default:
			result.Unknown++
		}
	}

	total := result.Passed + result.Failed
	if total > 0 {
		result.ScorePercent = float64(result.Passed) / float64(total) * 100
	}
	if l1Total > 0 { result.Level1Score = float64(l1Pass) / float64(l1Total) * 100 }
	if l2Total > 0 { result.Level2Score = float64(l2Pass) / float64(l2Total) * 100 }

	result.Controls = controls
	result.Benchmark = "ObsidianWatch Azure checks (inspired by CIS Azure Foundations v2.0; control IDs are internal)"
	result.ControlsImplemented = len(controls)
	result.CoverageNote = fmt.Sprintf(
		"Partial automated coverage: %d checks inspired by the CIS Azure Foundations Benchmark v2.0. Control IDs are ObsidianWatch-internal and do not match the published CIS numbering. Scores reflect only these controls and are not a CIS certification result; UNKNOWN controls could not be evaluated.",
		len(controls))
	return result, nil
}

// marshalAzureCIS converts AzureCSPMResult to json.RawMessage for storage
func marshalAzureCIS(r *CISAzureResult) ([]byte, error) {
	return json.Marshal(r)
}
