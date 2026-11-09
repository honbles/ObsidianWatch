package api

// cloud_azure_sigs.go — Azure-specific threat detection rules (50+ rules)
//
// Covers:
//   Entra ID / Identity  (C-AZ-IAM-001 to C-AZ-IAM-015) — PIM, MFA, CA, Guest
//   Compute / AKS        (C-AZ-COMP-001 to C-AZ-COMP-010)
//   Data & Storage       (C-AZ-DATA-001 to C-AZ-DATA-010)
//   Network              (C-AZ-NET-001 to C-AZ-NET-008)
//   Defense Evasion      (C-AZ-EVA-001 to C-AZ-EVA-008)
//   Defender SIGs        (C-AZ-DEF-001 to C-AZ-DEF-008) — cloud.azure_defender
//   Entra Audit SIGs     (C-AZ-AUDIT-001 to C-AZ-AUDIT-006) — cloud.entra_audit

import (
	"strings"
	"obsidianwatch/management/internal/store"
)

// ── Entra ID / Identity ───────────────────────────────────────────────────────

var azureIAMSignatures = []ThreatSig{
	{
		ID: "C-AZ-IAM-001", Name: "Azure PIM Privileged Role Activated",
		Description: "A privileged role was activated via Azure AD PIM (Privileged Identity Management). Legitimate PIM activations should have a business justification — monitor for unusual timing, unknown users, or repeated activations.",
		Severity: 3, MITRE: "T1548", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.aad/privilegedroleassignments",
					"roleeligibilityschedulerequests", "roleassignmentschedulerequests",
					"pimroleactivation", "privilegedidentitymanagement") &&
				containsAny(raw, "write", "create", "activated")
		},
	},
	{
		ID: "C-AZ-IAM-002", Name: "Azure Global Administrator Role Assigned",
		Description: "Global Administrator role (the highest privilege in Entra ID / Azure AD) was assigned. Any account with this role can read all data, reset all passwords, and modify all security settings.",
		Severity: 5, MITRE: "T1098.003", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return (ev.EventType == "cloud.azure_activity" || ev.EventType == "cloud.entra_audit") &&
				containsAny(raw, "roleassignments/write", "add member to role") &&
				containsAny(raw, "globaladministrator", "global administrator",
					"company administrator", "62e90394-69f5-4237-9190-012177145e10")
		},
	},
	{
		ID: "C-AZ-IAM-003", Name: "Azure Service Principal Password/Certificate Added",
		Description: "New credentials (password or certificate) added to an application service principal. This is a classic backdoor persistence technique — the attacker maintains access even after a password reset on the underlying user account.",
		Severity: 5, MITRE: "T1098.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return (ev.EventType == "cloud.azure_activity" || ev.EventType == "cloud.entra_audit") &&
				containsAny(raw, "serviceprincipals/credentials/write",
					"add service principal credentials", "addpassword", "addkey",
					"updateapplication-certificates")
		},
	},
	{
		ID: "C-AZ-IAM-004", Name: "Entra Conditional Access Policy Deleted or Disabled",
		Description: "A Conditional Access policy was deleted or set to disabled/report-only. CA policies enforce MFA, device compliance, and location controls. Disabling them removes critical authentication controls.",
		Severity: 5, MITRE: "T1556", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return (ev.EventType == "cloud.azure_activity" || ev.EventType == "cloud.entra_audit") &&
				containsAny(raw, "conditionalaccesspolicies", "update conditional access policy",
					"delete conditional access policy") &&
				containsAny(raw, "delete", "disabled", "report-only", "\"state\":\"disabled\"")
		},
	},
	{
		ID: "C-AZ-IAM-005", Name: "Azure AD Application Created with Wide Permissions",
		Description: "New Azure AD application registered. Applications can be used for persistent API access that bypasses user CA policies. Broad API permissions (Graph API Directory.ReadWrite.All etc.) should be reviewed.",
		Severity: 3, MITRE: "T1550.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return (ev.EventType == "cloud.azure_activity" || ev.EventType == "cloud.entra_audit") &&
				containsAny(raw, "microsoft.aad/applications/write", "add application",
					"applications/create", "registrations/create")
		},
	},
	{
		ID: "C-AZ-IAM-006", Name: "Azure AD User Created Outside Business Hours",
		Description: "New Azure AD user account created at an unusual hour. Backdoor accounts are frequently created in off-hours to avoid detection.",
		Severity: 3, MITRE: "T1136.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			hour := ev.Time.UTC().Hour()
			offHours := hour < 6 || hour >= 22
			return offHours &&
				(ev.EventType == "cloud.azure_activity" || ev.EventType == "cloud.entra_audit") &&
				containsAny(raw, "microsoft.aad/users/write", "microsoft.directory/users/create",
					"add user")
		},
	},
	{
		ID: "C-AZ-IAM-007", Name: "Azure Subscription Owner Role Assigned",
		Description: "Owner role assigned at subscription scope — full control over all resources in the subscription. Owner can create/delete resources, assign roles, access all data, and modify security controls.",
		Severity: 5, MITRE: "T1098.003", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.authorization/roleassignments/write") &&
				containsAny(raw, "owner") &&
				containsAny(raw, "subscriptions/")
		},
	},
	{
		ID: "C-AZ-IAM-008", Name: "Azure AD Tenant-Wide Federation Settings Modified",
		Description: "Federated domain settings modified. An attacker with Global Admin access can add a rogue federated domain, creating a Golden SAML backdoor that allows them to forge authentication tokens for any user.",
		Severity: 5, MITRE: "T1606.002", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return (ev.EventType == "cloud.azure_activity" || ev.EventType == "cloud.entra_audit") &&
				containsAny(raw, "set federation settings on domain", "setdomainauthentication",
					"trustedcasfordelegation", "domain federation")
		},
	},
	{
		ID: "C-AZ-IAM-009", Name: "MFA Disabled for Azure AD User",
		Description: "MFA registration or enforcement disabled for an Azure AD user. Removing MFA makes the account vulnerable to password spray, phishing, and credential stuffing.",
		Severity: 4, MITRE: "T1556.006", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return (ev.EventType == "cloud.azure_activity" || ev.EventType == "cloud.entra_audit") &&
				containsAny(raw, "strongauthenticationmethods", "mfaregistration",
					"authentication methods policy", "peruser mfa") &&
				containsAny(raw, "delete", "disable", "disabled")
		},
	},
	{
		ID: "C-AZ-IAM-010", Name: "Azure Managed Identity Assigned to High-Privilege Role",
		Description: "A managed identity (system or user-assigned) was granted a high-privilege role. Managed identities with Owner/Contributor can be exploited from any VM or service with that identity attached.",
		Severity: 4, MITRE: "T1548.005", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.authorization/roleassignments/write") &&
				containsAny(raw, "managedidentity", "systemassigned", "userassigned") &&
				containsAny(raw, "owner", "contributor")
		},
	},
	{
		ID: "C-AZ-IAM-011", Name: "Azure AD Guest Invited with Admin Role",
		Description: "External guest user invited and immediately granted an administrative role. Guests should never hold admin roles — they bypass many compliance controls.",
		Severity: 4, MITRE: "T1136.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return (ev.EventType == "cloud.azure_activity" || ev.EventType == "cloud.entra_audit") &&
				containsAny(raw, "inviteexternaluser", "invitations/write", "invite external user") &&
				containsAny(raw, "admin", "owner", "contributor", "operator")
		},
	},
	{
		ID: "C-AZ-IAM-012", Name: "Azure RBAC Custom Role with * (Wildcard) Permission Created",
		Description: "A custom RBAC role was created with wildcard (*) actions permission. Custom roles with * effectively grant the same access as Contributor and are often created to bypass policy restrictions.",
		Severity: 4, MITRE: "T1078.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.authorization/roledefinitions/write") &&
				containsAny(raw, "\"actions\":[\"*\"]", "actions\": [\"*\"]", "\"*\"")
		},
	},
	{
		ID: "C-AZ-IAM-013", Name: "Entra ID Break-Glass Account Used",
		Description: "An emergency access account (break-glass) was used. These accounts bypass Conditional Access and should only be used during identity system outages. Usage should trigger immediate investigation.",
		Severity: 4, MITRE: "T1078.004", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return (ev.EventType == "cloud.azure_activity" || ev.EventType == "cloud.entra_signin") &&
				containsAny(raw, "breakglass", "break-glass", "emergency", "emergencyaccess") &&
				containsAny(raw, "signin", "login", "authentication")
		},
	},
	{
		ID: "C-AZ-IAM-014", Name: "Azure AD Authorization Policy Modified",
		Description: "Tenant-wide authorization policy changed. This controls who can consent to apps, create groups, and invite guests — changes here affect the entire tenant's security posture.",
		Severity: 4, MITRE: "T1556", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return (ev.EventType == "cloud.azure_activity" || ev.EventType == "cloud.entra_audit") &&
				containsAny(raw, "update authorization policy", "authorizationpolicy",
					"defaultuserpermissions")
		},
	},
	{
		ID: "C-AZ-IAM-015", Name: "Azure Security Defaults Disabled",
		Description: "Entra ID Security Defaults were disabled. Security Defaults enforce MFA for all users, block legacy authentication, and protect privileged actions. Disabling them significantly weakens the tenant's default security posture.",
		Severity: 5, MITRE: "T1556", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return (ev.EventType == "cloud.azure_activity" || ev.EventType == "cloud.entra_audit") &&
				containsAny(raw, "identitysecuritydefaultsenablementpolicy", "securitydefaults",
					"security defaults") &&
				containsAny(raw, "disabled", "false", "\"isenabled\":false")
		},
	},
}

// ── Compute / AKS ─────────────────────────────────────────────────────────────

var azureComputeSignatures = []ThreatSig{
	{
		ID: "C-AZ-COMP-001", Name: "Azure VM Custom Script Extension Executed",
		Description: "CustomScriptExtension or run-command executed on a VM — remote code execution without RDP/SSH. Legitimate use exists but this is also a primary persistence and lateral movement technique.",
		Severity: 4, MITRE: "T1059", Category: "Execution",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "virtualmachines/extensions/write",
					"customscriptextension", "customscript",
					"virtualmachines/runcommand", "runshellscript", "runpowershellscript")
		},
	},
	{
		ID: "C-AZ-COMP-002", Name: "Azure VM Disk Snapshot Exported to SAS URL",
		Description: "A managed disk or VM snapshot was granted a SAS access URI. This allows downloading the full disk contents — operating system, credentials, application data — to any internet-accessible location.",
		Severity: 4, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "snapshots/begingetaccess", "disks/begingetaccess",
					"grantaccess", "sastoken") &&
				containsAny(raw, "snapshots", "disks")
		},
	},
	{
		ID: "C-AZ-COMP-003", Name: "AKS kubectl exec into Running Pod",
		Description: "Interactive shell opened in a running Kubernetes pod via exec. Legitimate for debugging but a significant lateral movement vector if executed on production pods.",
		Severity: 3, MITRE: "T1609", Category: "Execution",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "managedclusters/pods/exec", "pods/exec",
					"io.k8s.core.v1.pods.exec")
		},
	},
	{
		ID: "C-AZ-COMP-004", Name: "AKS ClusterRoleBinding Grants cluster-admin",
		Description: "A ClusterRoleBinding was created granting cluster-admin access — unrestricted access to all Kubernetes API operations. This is the highest privilege in a Kubernetes cluster.",
		Severity: 5, MITRE: "T1548", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "clusterrolebindings", "rbac.authorization.k8s.io") &&
				containsAny(raw, "cluster-admin") &&
				containsAny(raw, "create", "write")
		},
	},
	{
		ID: "C-AZ-COMP-005", Name: "Azure Container Registry Admin Account Enabled",
		Description: "The admin account on Azure Container Registry was enabled. The admin account provides full push/pull access using a username/password that bypasses Azure AD RBAC.",
		Severity: 3, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "containerregistries/write") &&
				containsAny(raw, "adminuserenabled\":true", "adminuser", "admin_user")
		},
	},
	{
		ID: "C-AZ-COMP-006", Name: "Azure Automation Runbook Created or Modified",
		Description: "Automation Runbook created or updated — can run PowerShell/Python with the Automation Account's managed identity permissions. Used for legitimate automation but also as a persistence or lateral movement mechanism.",
		Severity: 3, MITRE: "T1053.005", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "automationaccounts/runbooks/write",
					"automationaccounts/runbooks/draft/write")
		},
	},
	{
		ID: "C-AZ-COMP-007", Name: "Azure Function App with Managed Identity Modified",
		Description: "Azure Function App with a managed identity was created or updated. Functions can execute code with Azure AD credentials and are hard to detect when used as persistence mechanisms.",
		Severity: 3, MITRE: "T1525", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.web/sites/write", "sites/functions/write") &&
				containsAny(raw, "identity", "managedidentity", "principalid")
		},
	},
	{
		ID: "C-AZ-COMP-008", Name: "Azure Logic App Workflow with HTTP Action Created",
		Description: "Logic App workflow containing an HTTP action was created or updated. Logic Apps can exfiltrate data by posting to external URLs and are often missed by endpoint detection.",
		Severity: 3, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "workflows/write", "logicapps/write") &&
				containsAny(raw, "http", "webhook")
		},
	},
	{
		ID: "C-AZ-COMP-009", Name: "Azure VM High-Performance Size Launched (Cryptomining Risk)",
		Description: "VM created using a GPU or high-compute SKU (NV, NC, ND, HB, HC series). These instance types are expensive and are frequently abused for cryptomining after account compromise.",
		Severity: 3, MITRE: "T1496", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "virtualmachines/write", "microsoft.compute/virtualmachines") &&
				containsAny(raw, "standard_nv", "standard_nc", "standard_nd",
					"standard_hb", "standard_hc", "standard_h", "standard_nca",
					"standard_ncv", "standard_nds")
		},
	},
	{
		ID: "C-AZ-COMP-010", Name: "Azure Compute Quota Increase Requested",
		Description: "Compute quota increase submitted via support request. Attackers who have compromised a subscription often request quota increases before large-scale resource deployment for cryptomining or DDoS infrastructure.",
		Severity: 2, MITRE: "T1496", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "supporttickets/write", "microsoft.support") &&
				containsAny(raw, "quota", "cores", "vcpu", "compute")
		},
	},
}

// ── Data & Storage ────────────────────────────────────────────────────────────

var azureDataSignatures = []ThreatSig{
	{
		ID: "C-AZ-DATA-001", Name: "Azure Storage Account SAS Token with Full Permissions",
		Description: "Shared Access Signature (SAS) token generated with full permissions (read, write, delete, list) and no IP restriction. SAS tokens are permanent if not time-bounded and bypass Azure AD authentication.",
		Severity: 4, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "storageaccounts/listsastoken", "listsas",
					"generatesharedaccesssignature")
		},
	},
	{
		ID: "C-AZ-DATA-002", Name: "Azure Key Vault Secret Bulk Accessed",
		Description: "Multiple Key Vault secrets retrieved in rapid succession — likely automated credential harvesting.",
		Severity: 4, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "vaults/secrets/read", "getsecret", "listsecrets") &&
				ev.Severity >= 3
		},
	},
	{
		ID: "C-AZ-DATA-003", Name: "Azure Key Vault Key Deleted or Purged",
		Description: "Key Vault key deleted or purged. Key deletion prevents decryption of any data encrypted under that key — equivalent to ransomware if the data hasn't been backed up.",
		Severity: 5, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "vaults/keys/delete", "purgekey", "deletedkeys/purge",
					"keyvaults/keys/delete")
		},
	},
	{
		ID: "C-AZ-DATA-004", Name: "Azure SQL Database Exported to Storage",
		Description: "SQL database export (.bacpac) operation initiated. This creates a full copy of the database that can be downloaded from storage — a common data exfiltration technique.",
		Severity: 4, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.sql/servers/databases/export",
					"databases/export", "exportdatabase", "bacpac")
		},
	},
	{
		ID: "C-AZ-DATA-005", Name: "Azure Cosmos DB Firewall Disabled",
		Description: "Cosmos DB network firewall set to allow all networks. Any client with credentials can reach the database from the internet.",
		Severity: 4, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.documentdb/databaseaccounts/write",
					"databaseaccounts/write") &&
				containsAny(raw, "publicnetworkaccess\":\"enabled\"", "iprangefilter\":\"\"",
					"isVirtualNetworkFilterEnabled\":false")
		},
	},
	{
		ID: "C-AZ-DATA-006", Name: "Azure Blob Container Set to Public Access",
		Description: "Azure Blob container access level changed to Blob or Container (public). All objects in this container are readable by anyone on the internet without authentication.",
		Severity: 5, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "blobcontainers/write", "blobservices/write",
					"storageaccounts/blobservices") &&
				containsAny(raw, "publicaccess", "blob", "container") &&
				!containsAny(raw, "\"publicaccess\":\"none\"", "publicaccess\":\"None\"")
		},
	},
	{
		ID: "C-AZ-DATA-007", Name: "Azure Storage Account Access Key Regenerated",
		Description: "Storage account access key rotated. This is a normal operation but immediately after a security incident it may indicate an attacker re-establishing access with a new key they control.",
		Severity: 2, MITRE: "T1098.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "storageaccounts/regeneratekey",
					"storageaccounts/listkeys/action")
		},
	},
	{
		ID: "C-AZ-DATA-008", Name: "Azure SQL Auditing Disabled",
		Description: "SQL Server or Database auditing configuration removed or disabled. SQL audit logs capture all queries, schema changes, and authentication events — disabling them creates a forensic blind spot.",
		Severity: 4, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.sql/servers/auditingsettings/write",
					"databases/auditingsettings/write") &&
				containsAny(raw, "disabled", "\"state\":\"disabled\"", "none")
		},
	},
	{
		ID: "C-AZ-DATA-009", Name: "Azure Data Factory Pipeline with Copy to External Sink",
		Description: "Azure Data Factory pipeline created or modified with a copy activity pointing to an external destination. Data Factory can silently exfiltrate large volumes of data from Azure SQL, Blob, or Cosmos DB.",
		Severity: 3, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.datafactory/factories/pipelines/write",
					"datafactories/pipelines") &&
				containsAny(raw, "copy", "sink", "linkedservice")
		},
	},
	{
		ID: "C-AZ-DATA-010", Name: "Azure Backup Vault Soft Delete Disabled",
		Description: "Backup vault soft delete disabled. Disabling soft delete allows immediate permanent deletion of backups — a prerequisite for ransomware attacks that target backup data.",
		Severity: 5, MITRE: "T1490", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.recoveryservices/vaults",
					"backupconfig/write", "backuppolicies/write") &&
				containsAny(raw, "softdeletefeaturestate\":\"disabled\"",
					"issoftdeletedisabled", "softdelete")
		},
	},
}

// ── Network ───────────────────────────────────────────────────────────────────

var azureNetworkSignatures = []ThreatSig{
	{
		ID: "C-AZ-NET-001", Name: "Azure Firewall Policy Deleted",
		Description: "Azure Firewall policy deleted — centralized network filtering removed. Without Azure Firewall, east-west traffic between VNets and outbound internet traffic are unrestricted.",
		Severity: 5, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "azurefirewalls/delete", "firewallpolicies/delete",
					"microsoft.network/azurefirewalls")
		},
	},
	{
		ID: "C-AZ-NET-002", Name: "Azure DDoS Protection Plan Removed",
		Description: "DDoS Protection plan removed from a virtual network — volumetric DDoS protection disabled.",
		Severity: 3, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "ddosprotectionplans/delete", "ddoscustompolicies/delete",
					"enableddosprotection\":false")
		},
	},
	{
		ID: "C-AZ-NET-003", Name: "Azure Private DNS Zone Modified",
		Description: "Private DNS zone record set modified. Modifying private DNS records can redirect internal service traffic — databases, APIs, authentication endpoints — to attacker-controlled infrastructure.",
		Severity: 4, MITRE: "T1584.002", Category: "Resource Development",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "privatednszones/a/write", "privatednszones/cname/write",
					"privatednszones/ns/write", "privatednszones/mx/write",
					"dnsresolverpolicies")
		},
	},
	{
		ID: "C-AZ-NET-004", Name: "Azure VPN Gateway Connection Modified",
		Description: "VPN Gateway connection created, modified, or deleted — corporate WAN connectivity to Azure changed.",
		Severity: 3, MITRE: "T1572", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "virtualnetworkgateways/write", "vpngateways/write",
					"vpnconnections/write", "localnetworkgateways/write")
		},
	},
	{
		ID: "C-AZ-NET-005", Name: "Azure Front Door WAF Policy Disabled or Bypassed",
		Description: "Azure Front Door or CDN WAF policy set to detection mode or disabled. WAF in detection mode logs attacks but does not block them.",
		Severity: 4, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "frontdoor", "cdnwebapplicationfirewallpolicies",
					"frontdoorwebapplicationfirewallpolicies") &&
				containsAny(raw, "detection", "disabled", "\"policymode\":\"detection\"")
		},
	},
	{
		ID: "C-AZ-NET-006", Name: "Azure Private Endpoint Deleted",
		Description: "Private endpoint deleted — resource may now only be accessible via public endpoint. Services previously hidden behind private endpoints may be re-exposed to the internet.",
		Severity: 3, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "privateendpoints/delete",
					"microsoft.network/privateendpoints")
		},
	},
	{
		ID: "C-AZ-NET-007", Name: "Azure ExpressRoute Circuit Modified",
		Description: "ExpressRoute circuit or peering configuration changed — direct private connectivity between on-premises and Azure modified.",
		Severity: 3, MITRE: "T1557", Category: "Collection",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "expressroutecircuits/write", "expressroutecircuits/delete",
					"expressroutepeerings/write")
		},
	},
	{
		ID: "C-AZ-NET-008", Name: "Azure NSG Rule Added to Allow Internet Inbound",
		Description: "NSG rule added that allows inbound traffic from the internet (0.0.0.0/0 or Internet tag). Immediate review required to ensure this was intentional.",
		Severity: 4, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "networksecuritygroups/write",
					"networksecuritygroups/securityrules/write") &&
				containsAny(raw, "0.0.0.0/0", "internet", "::/0") &&
				containsAny(raw, "inbound", "allow")
		},
	},
}

// ── Defense Evasion ───────────────────────────────────────────────────────────

var azureDefenseEvasionSignatures = []ThreatSig{
	{
		ID: "C-AZ-EVA-001", Name: "Azure Monitor Diagnostic Settings Deleted",
		Description: "Diagnostic settings removed — audit log forwarding to Log Analytics, Storage, or Event Hub stopped. This creates a detection blind spot.",
		Severity: 5, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "diagnosticsettings/delete",
					"microsoft.insights/diagnosticsettings")
		},
	},
	{
		ID: "C-AZ-EVA-002", Name: "Azure Monitor Alert Rule Deleted",
		Description: "Metric or activity log alert rule deleted — monitoring notification for a critical condition removed.",
		Severity: 3, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "alertrules/delete", "metricalerts/delete",
					"scheduledqueryrules/delete", "activitylogalerts/delete")
		},
	},
	{
		ID: "C-AZ-EVA-003", Name: "Azure Policy Assignment Deleted",
		Description: "Azure Policy assignment removed — compliance enforcement for one or more resource types disabled.",
		Severity: 4, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "policyassignments/delete",
					"microsoft.authorization/policyassignments")
		},
	},
	{
		ID: "C-AZ-EVA-004", Name: "Microsoft Defender for Cloud Plan Downgraded",
		Description: "Defender for Cloud pricing tier downgraded from Standard to Free. This disables threat detection, just-in-time VM access, adaptive application controls, and vulnerability assessment.",
		Severity: 5, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.security/pricings/write") &&
				containsAny(raw, "free", "\"pricingtier\":\"free\"")
		},
	},
	{
		ID: "C-AZ-EVA-005", Name: "Azure Activity Log Export Disabled",
		Description: "Log profile or diagnostic setting for Activity Logs deleted or modified to stop export. Without exported logs, incident response loses visibility into subscription-level operations.",
		Severity: 4, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "logprofiles/delete", "logprofiles/write",
					"microsoft.insights/logprofiles") &&
				containsAny(raw, "delete", "disabled", "retentiondisabled")
		},
	},
	{
		ID: "C-AZ-EVA-006", Name: "Azure Resource Lock Removed",
		Description: "Delete or ReadOnly resource lock removed. Resource locks prevent accidental or malicious deletion of critical resources — removing them is a precursor to infrastructure destruction.",
		Severity: 4, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.authorization/locks/delete",
					"locks/delete") &&
				containsAny(raw, "cannotdelete", "readonly")
		},
	},
	{
		ID: "C-AZ-EVA-007", Name: "Azure Subscription Moved to Different Management Group",
		Description: "Subscription transferred to a different management group. This can be used to move a subscription outside the scope of organizational Azure Policies and compliance controls.",
		Severity: 4, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "managementgroups/subscriptions/write",
					"microsoft.management/managementgroups") &&
				containsAny(raw, "move", "subscription")
		},
	},
	{
		ID: "C-AZ-EVA-008", Name: "Azure Sentinel Analytics Rule Disabled",
		Description: "Microsoft Sentinel analytics rule (detection rule) disabled. This creates a blind spot in SIEM detection coverage for the affected threat scenario.",
		Severity: 4, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(raw, "microsoft.securityinsights/alertrules",
					"operationalinsights/workspaces/providers/alertrules") &&
				containsAny(raw, "disabled", "\"enabled\":false")
		},
	},
}

// ── Defender for Cloud alert signatures (cloud.azure_defender) ────────────────

var azureDefenderSignatures = []ThreatSig{
	{
		ID: "C-AZ-DEF-001", Name: "Defender: High/Critical Security Alert",
		Description: "Microsoft Defender for Cloud raised a high or critical severity security alert. These are based on Microsoft's threat intelligence and behavioral analytics.",
		Severity: 5, MITRE: "T1078", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_defender" && ev.Severity >= 4
		},
	},
	{
		ID: "C-AZ-DEF-002", Name: "Defender: Cryptomining Detected",
		Description: "Defender for Cloud detected cryptomining activity on a compute resource.",
		Severity: 4, MITRE: "T1496", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_defender" &&
				containsAny(raw, "crypto", "mining", "miner", "xmrig", "stratum",
					"bitcoin", "monero", "coin")
		},
	},
	{
		ID: "C-AZ-DEF-003", Name: "Defender: SQL Injection Attack Detected",
		Description: "Defender for Cloud detected a SQL injection attempt against an Azure SQL database.",
		Severity: 4, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_defender" &&
				containsAny(raw, "sql injection", "sqli", "sqlinjection",
					"sql_injection", "potentialsqli")
		},
	},
	{
		ID: "C-AZ-DEF-004", Name: "Defender: Malware Detected on VM",
		Description: "Defender for Cloud (Endpoint integration) detected malware executing on an Azure VM.",
		Severity: 5, MITRE: "T1059", Category: "Execution",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_defender" &&
				containsAny(raw, "malware", "virus", "trojan", "ransomware",
					"backdoor", "rootkit", "exploit")
		},
	},
	{
		ID: "C-AZ-DEF-005", Name: "Defender: Brute Force Attack Detected",
		Description: "Defender for Cloud detected brute force authentication attempts against RDP, SSH, or a service endpoint.",
		Severity: 3, MITRE: "T1110", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_defender" &&
				containsAny(raw, "bruteforce", "brute force", "brute_force",
					"multiple_failed", "rdp_brute", "ssh_brute")
		},
	},
	{
		ID: "C-AZ-DEF-006", Name: "Defender: Anomalous Azure Resource Deletion",
		Description: "Defender for Cloud detected anomalous resource deletion activity — unusual volume, timing, or principal.",
		Severity: 4, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_defender" &&
				containsAny(raw, "anomalous", "deletion", "delete") &&
				ev.Severity >= 3
		},
	},
	{
		ID: "C-AZ-DEF-007", Name: "Defender: Identity Threat — Suspicious Activity",
		Description: "Defender for Identity or Defender for Cloud Apps detected suspicious identity activity (impossible travel, anomalous token use, password spray).",
		Severity: 4, MITRE: "T1078.004", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_defender" &&
				containsAny(raw, "impossibletravel", "impossible travel",
					"anomalous_signin", "suspicious_login", "password_spray",
					"anonymousip", "unfamiliar_features")
		},
	},
	{
		ID: "C-AZ-DEF-008", Name: "Defender: Container Escape or AKS Threat",
		Description: "Defender for Containers detected a container escape attempt or anomalous AKS activity.",
		Severity: 5, MITRE: "T1611", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.azure_defender" &&
				containsAny(raw, "container_escape", "privileged_container",
					"aks_", "k8s_", "kubernetes", "exposed_kubernetes_dashboard")
		},
	},
}

// ── Entra Directory Audit event signatures (cloud.entra_audit) ─────────────────

var azureAuditSignatures = []ThreatSig{
	{
		ID: "C-AZ-AUDIT-001", Name: "Entra Audit: High-Impact Admin Operation",
		Description: "High-impact administrative operation recorded in Entra Directory Audit: role assignment, user deletion, password reset, application credential change.",
		Severity: 4, MITRE: "T1098", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.entra_audit" &&
				containsAny(raw,
					"add member to role", "remove member from role",
					"reset user password", "delete user",
					"add service principal credentials",
					"add owner to application") &&
				ev.Severity >= 3
		},
	},
	{
		ID: "C-AZ-AUDIT-002", Name: "Entra Audit: Application Consent Granted",
		Description: "OAuth2 admin consent granted to an application. Attackers use illicit consent grant attacks to give their applications persistent API access to tenant data without MFA or Conditional Access.",
		Severity: 4, MITRE: "T1550.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.entra_audit" &&
				containsAny(raw, "consent to application", "add oauth2permissiongrant",
					"adminconsent", "admin_consent")
		},
	},
	{
		ID: "C-AZ-AUDIT-003", Name: "Entra Audit: Group Membership Bulk Change",
		Description: "Large number of members added to or removed from a group in a short window — may indicate privilege escalation or account provisioning for lateral movement.",
		Severity: 3, MITRE: "T1098", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.entra_audit" &&
				containsAny(raw, "add member to group", "remove member from group") &&
				ev.Severity >= 3
		},
	},
	{
		ID: "C-AZ-AUDIT-004", Name: "Entra Audit: Named Location or Trusted IP Modified",
		Description: "Conditional Access named locations (trusted IP ranges) modified. Attacker may add a malicious IP to the trusted list to bypass location-based CA policies.",
		Severity: 4, MITRE: "T1556", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.entra_audit" &&
				containsAny(raw, "namedlocation", "named location",
					"trustedips", "ipnamedlocation", "countrynamedlocation")
		},
	},
	{
		ID: "C-AZ-AUDIT-005", Name: "Entra Audit: Authentication Method Policy Changed",
		Description: "Authentication methods policy modified at the tenant level — controls which MFA methods are available to users. Weakening this policy reduces authentication strength.",
		Severity: 4, MITRE: "T1556", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.entra_audit" &&
				containsAny(raw, "update authentication methods policy",
					"authenticationmethodspolicy", "authentication method") &&
				containsAny(raw, "update", "write", "delete")
		},
	},
	{
		ID: "C-AZ-AUDIT-006", Name: "Entra Audit: Privileged Role Permanently Assigned (No PIM)",
		Description: "Privileged Azure AD role assigned permanently without PIM just-in-time activation. Permanent role assignment means the account is always elevated — a larger blast radius if compromised.",
		Severity: 4, MITRE: "T1078.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.entra_audit" &&
				containsAny(raw, "add member to role") &&
				!containsAny(raw, "eligible", "pim", "privilegedidentitymanagement",
					"roleeligibility")
		},
	},
}
