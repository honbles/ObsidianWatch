package api

import (
	"strings"
	"obsidianwatch/management/internal/store"
)

// cloudSignaturesExtended adds 80 more cloud detection rules covering:
// AWS (30), Azure (25), GCP (15), cross-cloud (10)
// Combined with cloudSignatures (20) = 100 total cloud rules.
// See cloud_gcp_sigs.go for an additional 61 GCP-specific rules (C-GCP-021 to C-GCP-073, C-SCC-001 to C-SCC-008).
// Grand total: 161+ cloud detection rules.
var cloudSignaturesExtended = []ThreatSig{

	// ══════════════════════════════════════════════════════════════════════════
	// AWS — 30 additional rules
	// ══════════════════════════════════════════════════════════════════════════

	// ── Storage / Data Exfiltration ───────────────────────────────────────────
	{
		ID: "C-AWS-011", Name: "S3 Bucket Replication to External Account",
		Description: "S3 replication configured to an external AWS account — possible data exfiltration.",
		Severity: 4, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "putbucketreplication") &&
				containsAny(strings.ToLower(rawStr(ev)), "destinationbucketarn")
		},
	},
	{
		ID: "C-AWS-012", Name: "S3 Bucket Versioning Disabled",
		Description: "S3 versioning disabled — could be preparation for ransomware (delete all versions).",
		Severity: 3, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "putbucketversioning") &&
				containsAny(strings.ToLower(rawStr(ev)), "suspended")
		},
	},
	{
		ID: "C-AWS-013", Name: "S3 Server Access Logging Disabled",
		Description: "S3 access logging disabled — attacker hiding data access activity.",
		Severity: 3, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			// Only fire when logging is being REMOVED (LoggingEnabled absent = disabled)
			// PutBucketLogging with an empty body disables logging
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "putbucketlogging") &&
				!containsAny(strings.ToLower(rawStr(ev)), "loggingenabled", "targetbucket")
		},
	},
	{
		ID: "C-AWS-014", Name: "Large S3 Data Download",
		Description: "Bulk S3 object retrieval — possible data theft. Requires S3 Data Events enabled in CloudTrail.",
		Severity: 3, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "getobject") &&
				ev.Severity >= 3
		},
	},
	{
		ID: "C-AWS-015", Name: "S3 Bucket Encryption Removed",
		Description: "S3 bucket default encryption removed or weakened.",
		Severity: 3, MITRE: "T1486", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "deletebucketencryption")
		},
	},

	// ── Identity & Access Management ─────────────────────────────────────────
	{
		ID: "C-AWS-016", Name: "IAM User Created",
		Description: "New IAM user created — monitor for backdoor accounts.",
		Severity: 2, MITRE: "T1136.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "createuser") &&
				!containsAny(strings.ToLower(rawStr(ev)), "errorcode")
		},
	},
	{
		ID: "C-AWS-017", Name: "IAM User Added to Admin Group",
		Description: "User added to admin or privileged group.",
		Severity: 4, MITRE: "T1078.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "addusertogroup") &&
				containsAny(strings.ToLower(rawStr(ev)), "admin", "administrator", "poweruser")
		},
	},
	{
		ID: "C-AWS-018", Name: "IAM Password Policy Weakened",
		Description: "IAM account password policy relaxed — reduced authentication security.",
		Severity: 3, MITRE: "T1556", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "updateaccountpasswordpolicy", "deleteaccountpasswordpolicy")
		},
	},
	{
		ID: "C-AWS-019", Name: "MFA Device Deregistered",
		Description: "MFA device removed from IAM user — reduces account security.",
		Severity: 4, MITRE: "T1556.006", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "deactivatemfadevice", "deletevirtualmfadevice")
		},
	},
	{
		ID: "C-AWS-020", Name: "STS AssumeRole Cross-Account",
		Description: "IAM role assumed from a different AWS account — verify legitimacy.",
		Severity: 3, MITRE: "T1199", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "assumerole") &&
				containsAny(strings.ToLower(rawStr(ev)), "rolearn") &&
				!containsAny(strings.ToLower(rawStr(ev)), "errorcode")
		},
	},

	// ── Network & Compute ─────────────────────────────────────────────────────
	{
		ID: "C-AWS-021", Name: "EC2 Instance Created with Public IP",
		Description: "EC2 instance launched with a public IP — check if intentional.",
		Severity: 2, MITRE: "T1583.003", Category: "Resource Development",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "runinstances") &&
				containsAny(strings.ToLower(rawStr(ev)), "publicipaddress", "associatepublicipaddress\":true")
		},
	},
	{
		ID: "C-AWS-022", Name: "EC2 Snapshot Made Public",
		Description: "EC2 snapshot shared publicly — data exposure risk.",
		Severity: 4, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "modifysnapshotattribute") &&
				containsAny(strings.ToLower(rawStr(ev)), "group", "all")
		},
	},
	{
		ID: "C-AWS-023", Name: "EC2 AMI Made Public",
		Description: "EC2 AMI shared publicly — may expose sensitive data in the image.",
		Severity: 4, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "modifyimageattribute") &&
				containsAny(strings.ToLower(rawStr(ev)), "launchpermission", "all")
		},
	},
	{
		ID: "C-AWS-024", Name: "VPC Flow Logs Disabled",
		Description: "VPC flow logs deleted or disabled — network visibility lost.",
		Severity: 4, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "deleteflowlogs")
		},
	},
	{
		ID: "C-AWS-025", Name: "EC2 SSH Key Pair Created",
		Description: "New EC2 key pair created — possible backdoor access.",
		Severity: 3, MITRE: "T1098", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "createkeypair", "importkeypair")
		},
	},

	// ── Secrets & Credentials ─────────────────────────────────────────────────
	{
		ID: "C-AWS-026", Name: "Secrets Manager Secret Accessed",
		Description: "AWS Secrets Manager secret retrieved — monitor for credential harvesting. Requires Secrets Manager Data Events in CloudTrail.",
		Severity: 3, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "getsecretvalue")
		},
	},
	{
		ID: "C-AWS-027", Name: "Secrets Manager Secret Deleted",
		Description: "AWS Secrets Manager secret deleted — possible sabotage or cleanup after exfiltration.",
		Severity: 4, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "deletesecret")
		},
	},
	{
		ID: "C-AWS-028", Name: "Parameter Store Sensitive Value Accessed",
		Description: "SSM Parameter Store SecureString parameter accessed. Requires SSM Data Events enabled in CloudTrail.",
		Severity: 3, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "getparameter") &&
				containsAny(strings.ToLower(rawStr(ev)), "withdecryption\":true", "securestring")
		},
	},

	// ── GuardDuty & Threat Intelligence ──────────────────────────────────────
	{
		ID: "C-AWS-029", Name: "GuardDuty Threat Intelligence Feed Match",
		Description: "GuardDuty detected activity matching known threat intelligence.",
		Severity: 4, MITRE: "T1071", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.guardduty" &&
				containsAny(strings.ToLower(rawStr(ev)), "trojan", "backdoor", "cryptomining", "pentest", "scanner")
		},
	},
	{
		ID: "C-AWS-030", Name: "GuardDuty Cryptocurrency Mining",
		Description: "GuardDuty detected cryptocurrency mining activity.",
		Severity: 4, MITRE: "T1496", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.guardduty" &&
				containsAny(strings.ToLower(rawStr(ev)), "cryptomining", "bitcoin", "monero", "coinminer")
		},
	},
	{
		ID: "C-AWS-031", Name: "GuardDuty Tor Exit Node Activity",
		Description: "Connection to/from a Tor exit node detected by GuardDuty.",
		Severity: 4, MITRE: "T1090.003", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.guardduty" &&
				containsAny(strings.ToLower(rawStr(ev)), "tor")
		},
	},
	{
		ID: "C-AWS-032", Name: "GuardDuty Port Scan Detected",
		Description: "GuardDuty detected port scanning from an EC2 instance.",
		Severity: 3, MITRE: "T1046", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.guardduty" &&
				containsAny(strings.ToLower(rawStr(ev)), "portscan", "recon:ec2")
		},
	},

	// ── Security Hub ─────────────────────────────────────────────────────────
	{
		ID: "C-AWS-048", Name: "Security Hub Critical Finding",
		Description: "AWS Security Hub reported an active CRITICAL finding from an integrated product or standard.",
		Severity: 5, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.securityhub" && strings.Contains(rawStr(ev), `"severity_label":"critical"`)
		},
	},
	{
		ID: "C-AWS-049", Name: "Security Hub High Finding",
		Description: "AWS Security Hub reported an active HIGH finding from an integrated product or standard.",
		Severity: 4, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.securityhub" && strings.Contains(rawStr(ev), `"severity_label":"high"`)
		},
	},

	// ── Lambda / Serverless ───────────────────────────────────────────────────
	{
		ID: "C-AWS-033", Name: "Lambda Function Policy Made Public",
		Description: "Lambda function resource policy allows invocation from any principal.",
		Severity: 4, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "addpermission") &&
				containsAny(strings.ToLower(rawStr(ev)), "lambda") &&
				containsAny(strings.ToLower(rawStr(ev)), "principal\":\"*\"", "principal\": \"*\"")
		},
	},
	{
		ID: "C-AWS-034", Name: "Lambda Environment Variables Modified",
		Description: "Lambda function environment variables updated — could inject malicious config.",
		Severity: 3, MITRE: "T1525", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "updatefunctionconfiguration") &&
				containsAny(strings.ToLower(rawStr(ev)), "environment", "variables")
		},
	},

	// ── CloudFormation / Infrastructure ──────────────────────────────────────
	{
		ID: "C-AWS-035", Name: "CloudFormation Stack Deleted",
		Description: "CloudFormation stack deleted — infrastructure destruction.",
		Severity: 3, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "deletestack")
		},
	},
	{
		ID: "C-AWS-036", Name: "AWS Config Recorder Stopped",
		Description: "AWS Config recorder stopped — compliance and change tracking disabled.",
		Severity: 4, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "stopconfigurationrecorder", "deleteconfigurationrecorder")
		},
	},
	{
		ID: "C-AWS-037", Name: "Route53 DNS Record Modified",
		Description: "DNS record modified — possible DNS hijacking.",
		Severity: 4, MITRE: "T1584.002", Category: "Resource Development",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "changeresourcerecordsets")
		},
	},
	{
		ID: "C-AWS-038", Name: "CloudWatch Alarm Deleted",
		Description: "CloudWatch alarm deleted — monitoring gap created.",
		Severity: 3, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "deletealarms")
		},
	},
	{
		ID: "C-AWS-039", Name: "ECR Image Pushed with Latest Tag",
		Description: "Container image pushed to ECR. Requires ECR Data Events enabled in CloudTrail.",
		Severity: 2, MITRE: "T1525", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				containsAny(strings.ToLower(rawStr(ev)), "initiatelayerupload", "completelayerupload") &&
				containsAny(strings.ToLower(rawStr(ev)), "ecr")
		},
	},
	{
		ID: "C-AWS-040", Name: "RDS Snapshot Made Public",
		Description: "RDS database snapshot shared publicly — database contents exposed.",
		Severity: 5, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "modifydbsnapshotattribute") &&
				containsAny(strings.ToLower(rawStr(ev)), "valuestoadd", "valuetoadd")
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// Azure — 25 additional rules
	// ══════════════════════════════════════════════════════════════════════════

	// ── Storage ───────────────────────────────────────────────────────────────
	{
		ID: "C-AZ-006", Name: "Azure Blob Storage Container Made Public",
		Description: "Azure Blob container access level set to public — data exposure risk.",
		Severity: 4, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "blobcontainers/write", "blobservices/write")
		},
	},
	{
		ID: "C-AZ-007", Name: "Azure Storage Account Firewall Disabled",
		Description: "Storage account network rules removed — storage accessible from internet.",
		Severity: 4, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "storageaccounts/write") &&
				containsAny(strings.ToLower(rawStr(ev)), "allowblobpublicaccess\":true", "defaultaction\":\"allow\"")
		},
	},
	{
		ID: "C-AZ-008", Name: "Azure Storage SAS Token with Full Access",
		Description: "Shared Access Signature created with full read/write/delete permissions.",
		Severity: 3, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(strings.ToLower(rawStr(ev)), "storageaccounts/listsastoken", "listsas")
		},
	},
	{
		ID: "C-AZ-009", Name: "Azure Storage Account Encryption Disabled",
		Description: "Storage account encryption key rotated or infrastructure encryption disabled.",
		Severity: 3, MITRE: "T1486", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(strings.ToLower(rawStr(ev)), "storageaccounts") &&
				containsAny(strings.ToLower(rawStr(ev)), "requireinfrastructureencryption\":false")
		},
	},

	// ── Identity & Access ─────────────────────────────────────────────────────
	{
		ID: "C-AZ-010", Name: "Azure AD User Created",
		Description: "New Azure AD user account created — monitor for backdoor accounts.",
		Severity: 2, MITRE: "T1136.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "microsoft.aad/users/write", "microsoft.directory/users/create")
		},
	},
	{
		ID: "C-AZ-011", Name: "Azure AD User MFA Disabled",
		Description: "MFA disabled for an Azure AD user — reduces account security.",
		Severity: 4, MITRE: "T1556.006", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(strings.ToLower(rawStr(ev)), "strongauthenticationmethods", "mfaregistration") &&
				containsAny(strings.ToLower(rawStr(ev)), "delete", "disable")
		},
	},
	{
		ID: "C-AZ-012", Name: "Azure AD Application Created",
		Description: "New Azure AD app registration created — could be used for persistence.",
		Severity: 3, MITRE: "T1550.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "microsoft.aad/applications/write", "applications/create")
		},
	},
	{
		ID: "C-AZ-013", Name: "Azure Service Principal Credentials Added",
		Description: "New credential added to service principal — backdoor access path.",
		Severity: 4, MITRE: "T1098.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(strings.ToLower(rawStr(ev)), "serviceprincipals/credentials/write", "addpassword", "addkey")
		},
	},
	{
		ID: "C-AZ-014", Name: "Azure Entra ID Conditional Access Policy Disabled",
		Description: "Conditional Access policy deleted or disabled — security control bypassed.",
		Severity: 4, MITRE: "T1556", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(strings.ToLower(rawStr(ev)), "conditionalaccesspolicies") &&
				containsAny(strings.ToLower(rawStr(ev)), "delete", "\"state\":\"disabled\"")
		},
	},
	{
		ID: "C-AZ-015", Name: "Entra ID Guest Account Added",
		Description: "External guest user invited — verify legitimacy.",
		Severity: 2, MITRE: "T1136.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(strings.ToLower(rawStr(ev)), "inviteexternaluser", "invitations/write")
		},
	},

	// ── Network ───────────────────────────────────────────────────────────────
	{
		ID: "C-AZ-016", Name: "Azure Firewall Deleted",
		Description: "Azure Firewall resource deleted — network security boundary removed.",
		Severity: 5, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "azurefirewalls/delete", "firewalls/delete")
		},
	},
	{
		ID: "C-AZ-017", Name: "Azure DDoS Protection Disabled",
		Description: "DDoS protection plan removed from virtual network.",
		Severity: 3, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "ddosprotectionplans/delete", "ddoscustompolicies/delete")
		},
	},
	{
		ID: "C-AZ-018", Name: "Azure VPN Gateway Configuration Changed",
		Description: "VPN gateway modified — network routing change.",
		Severity: 3, MITRE: "T1572", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "virtualnetworkgateways/write", "vpngateways/write")
		},
	},
	{
		ID: "C-AZ-019", Name: "Azure Public IP Allocated",
		Description: "New public IP address allocated — new internet-exposed surface.",
		Severity: 2, MITRE: "T1583.003", Category: "Resource Development",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "publicipaddresses/write")
		},
	},

	// ── Compute ───────────────────────────────────────────────────────────────
	{
		ID: "C-AZ-020", Name: "Azure VM Extension Installed",
		Description: "VM extension installed — could be used to execute code on VM.",
		Severity: 3, MITRE: "T1059", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "virtualmachines/extensions/write")
		},
	},
	{
		ID: "C-AZ-021", Name: "Azure Disk Snapshot Exported",
		Description: "Managed disk snapshot exported to storage — possible data exfiltration.",
		Severity: 3, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "snapshots/write", "snapshots/begingetaccess")
		},
	},
	{
		ID: "C-AZ-022", Name: "Azure Automation Runbook Created",
		Description: "New automation runbook created — could execute code in Azure environment.",
		Severity: 3, MITRE: "T1053.005", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "automationaccounts/runbooks/write")
		},
	},

	// ── Monitoring & Audit ────────────────────────────────────────────────────
	{
		ID: "C-AZ-023", Name: "Azure Diagnostic Settings Deleted",
		Description: "Diagnostic settings removed — audit log forwarding stopped.",
		Severity: 4, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "diagnosticsettings/delete")
		},
	},
	{
		ID: "C-AZ-024", Name: "Azure Monitor Alert Rule Deleted",
		Description: "Azure Monitor alert rule deleted — monitoring blind spot created.",
		Severity: 3, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "alertrules/delete", "metricalerts/delete")
		},
	},
	{
		ID: "C-AZ-025", Name: "Azure Policy Assignment Deleted",
		Description: "Azure Policy assignment removed — compliance enforcement disabled.",
		Severity: 3, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "policyassignments/delete")
		},
	},
	{
		ID: "C-AZ-026", Name: "Azure SQL Database Firewall Rule Modified",
		Description: "SQL database firewall rule changed — potential database exposure.",
		Severity: 3, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "firewallrules/write") &&
				containsAny(strings.ToLower(rawStr(ev)), "sql", "servers")
		},
	},
	{
		ID: "C-AZ-027", Name: "Azure Subscription Ownership Transferred",
		Description: "Subscription ownership or management group changed.",
		Severity: 5, MITRE: "T1078.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				azureOpHas(ev, "roleassignments/write") &&
				containsAny(strings.ToLower(rawStr(ev)), "owner", "subscriptions/")
		},
	},
	{
		ID: "C-AZ-028", Name: "Azure Defender for Cloud Alert",
		Description: "Microsoft Defender for Cloud raised a security alert.",
		Severity: 4, MITRE: "T1078", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(strings.ToLower(rawStr(ev)), "microsoft.security/locations/alerts", "securitycenter") &&
				ev.Severity >= 3
		},
	},
	{
		ID: "C-AZ-029", Name: "Azure Logic App Workflow Modified",
		Description: "Logic App workflow created or modified — potential code execution path.",
		Severity: 3, MITRE: "T1053", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(strings.ToLower(rawStr(ev)), "workflows/write", "logicapps")
		},
	},
	{
		ID: "C-AZ-030", Name: "Azure Container Registry Image Pushed",
		Description: "Container image pushed to Azure Container Registry.",
		Severity: 2, MITRE: "T1525", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(strings.ToLower(rawStr(ev)), "containerregistry", "repositories/write")
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// GCP — 15 additional rules
	// ══════════════════════════════════════════════════════════════════════════

	{
		ID: "C-GCP-006", Name: "GCP Cloud Storage Bucket Made Public",
		Description: "GCP storage bucket IAM policy grants access to allUsers or allAuthenticatedUsers.",
		Severity: 4, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(strings.ToLower(rawStr(ev)), "storage.setiampermissions", "storage.buckets.setIamPolicy") &&
				containsAny(strings.ToLower(rawStr(ev)), "allusers", "allauthenticatedusers")
		},
	},
	{
		ID: "C-GCP-007", Name: "GCP Compute Firewall Rule Opens All Ports",
		Description: "Firewall rule created allowing all traffic (0.0.0.0/0 with no port restriction).",
		Severity: 4, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				gcpMethodHas(ev, "compute.firewalls.insert", "compute.firewalls.update") &&
				containsAny(strings.ToLower(rawStr(ev)), "0.0.0.0/0", "::/0") &&
				containsAny(strings.ToLower(rawStr(ev)), "all", "ipprotocol")
		},
	},
	{
		ID: "C-GCP-008", Name: "GCP VPC Firewall Rule Deleted",
		Description: "Firewall rule deleted — network security boundary change.",
		Severity: 3, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				gcpMethodHas(ev, "compute.firewalls.delete")
		},
	},
	{
		ID: "C-GCP-009", Name: "GCP Project Deleted",
		Description: "GCP project deleted — catastrophic data and infrastructure loss.",
		Severity: 5, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(strings.ToLower(rawStr(ev)), "cloudresourcemanager.projects.delete", "deleteproject")
		},
	},
	{
		ID: "C-GCP-010", Name: "GCP Service Account Disabled",
		Description: "Service account disabled — could cause service disruption.",
		Severity: 3, MITRE: "T1531", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(strings.ToLower(rawStr(ev)), "disableserviceaccount", "iam.serviceaccounts.disable")
		},
	},
	{
		ID: "C-GCP-011", Name: "GCP SQL Instance Made Public",
		Description: "Cloud SQL instance network configuration changed to allow public access.",
		Severity: 4, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				gcpMethodHas(ev, "cloudsql.instances.update") &&
				containsAny(strings.ToLower(rawStr(ev)), "authorizednetworks", "0.0.0.0/0", "requiressl\":false")
		},
	},
	{
		ID: "C-GCP-012", Name: "GCP Compute Instance Created with Default Service Account",
		Description: "VM created using the default compute service account with editor permissions.",
		Severity: 3, MITRE: "T1078.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				gcpMethodHas(ev, "compute.instances.insert") &&
				containsAny(strings.ToLower(rawStr(ev)), "developer.gserviceaccount.com") &&
				containsAny(strings.ToLower(rawStr(ev)), "cloud-platform")
		},
	},
	{
		ID: "C-GCP-013", Name: "GCP Pub/Sub Subscription Made Public",
		Description: "Pub/Sub subscription IAM grants access to allUsers — message data exposed.",
		Severity: 3, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				gcpMethodHas(ev, "pubsub.subscriptions.setiampolicy") &&
				containsAny(strings.ToLower(rawStr(ev)), "allusers")
		},
	},
	{
		ID: "C-GCP-014", Name: "GCP BigQuery Dataset Made Public",
		Description: "BigQuery dataset IAM policy grants access to all users — data exposure.",
		Severity: 4, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				gcpMethodHas(ev, "bigquery.datasets.update", "bigquery.setiampolicy") &&
				containsAny(strings.ToLower(rawStr(ev)), "allusers", "allauthenticatedusers")
		},
	},
	{
		ID: "C-GCP-015", Name: "GCP Secret Manager Secret Accessed",
		Description: "GCP Secret Manager secret version accessed — credential monitoring.",
		Severity: 3, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(strings.ToLower(rawStr(ev)), "secretmanager.versions.access", "accesssecretversion")
		},
	},
	{
		ID: "C-GCP-016", Name: "GCP Cloud Function Created or Updated",
		Description: "Cloud Function created or updated — serverless code execution.",
		Severity: 2, MITRE: "T1525", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				gcpMethodHas(ev, "cloudfunctions.functions.create", "cloudfunctions.functions.update")
		},
	},
	{
		ID: "C-GCP-017", Name: "GCP Cloud Scheduler Job Created",
		Description: "Cloud Scheduler job created — scheduled code execution.",
		Severity: 2, MITRE: "T1053", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				gcpMethodHas(ev, "cloudscheduler.jobs.create")
		},
	},
	{
		ID: "C-GCP-018", Name: "GCP Kubernetes Cluster Created with Legacy Auth",
		Description: "GKE cluster created with basic auth or legacy ABAC enabled.",
		Severity: 4, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				gcpMethodHas(ev, "container.clusters.create") &&
				containsAny(strings.ToLower(rawStr(ev)), "masterauth", "legacyabac", "enabled\":true")
		},
	},
	{
		ID: "C-GCP-019", Name: "GCP Cloud Run Service Made Public",
		Description: "Cloud Run service IAM allows unauthenticated invocations.",
		Severity: 3, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				gcpMethodHas(ev, "run.services.setiampolicy") &&
				containsAny(strings.ToLower(rawStr(ev)), "allusers", "run.invoker")
		},
	},
	{
		ID: "C-GCP-020", Name: "GCP Organization Policy Constraint Disabled",
		Description: "Organization policy constraint disabled — guardrails removed.",
		Severity: 4, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(strings.ToLower(rawStr(ev)), "orgpolicies.policy.set", "updateorgpolicy", "google.cloud.orgpolicy.v2")
		},
	},

	// ══════════════════════════════════════════════════════════════════════════
	// Cross-Cloud — 10 rules matching across all providers
	// ══════════════════════════════════════════════════════════════════════════

	{
		ID: "C-XCLOUD-001", Name: "Cloud API Calls from Unexpected Country",
		Description: "Cloud management API called from a country outside your normal operating regions.",
		Severity: 3, MITRE: "T1078.004", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			// CC-02: disabled until a real GeoIP source exists. The old
			// match fired on any sev>=3 cloud event whose raw JSON merely
			// contained "location" (every Azure resource property bag).
			return false
		},
	},
	{
		ID: "C-XCLOUD-002", Name: "Critical Cloud Resource Deleted",
		Description: "High-severity cloud resource deleted — database, firewall, vault, or logging infrastructure.",
		Severity: 4, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			return isCloudEvent(ev) && ev.Severity >= 4 &&
				containsAny(strings.ToLower(rawStr(ev)), "delete") &&
				containsAny(strings.ToLower(rawStr(ev)),
					"rds", "dynamodb", "firewall", "vault", "keyvault",
					"guardduty", "cloudtrail", "flowlogs", "auditlog", "kms",
					"sql", "postgres", "mysql", "cosmos", "spanner")
		},
	},
	{
		ID: "C-XCLOUD-003", Name: "Cloud Logging Disabled",
		Description: "Audit or diagnostic logging disabled across any cloud provider.",
		Severity: 5, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return isCloudEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"stoploggin", "deletetrail", "diagnosticsettings/delete",
					"updateauditconfig", "deleteconfigurationrecorder", "disableflowlogs")
		},
	},
	{
		ID: "C-XCLOUD-004", Name: "Cloud Root or Global Admin Activity",
		Description: "Root account (AWS), Global Administrator (Azure), or Owner (GCP) performed an action.",
		Severity: 4, MITRE: "T1078.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return isCloudEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"\"type\":\"root\"", "globaladministrator", "owner role")
		},
	},
	{
		ID: "C-XCLOUD-005", Name: "Cloud Encryption Key Destroyed",
		Description: "Encryption key deleted or destroyed across any cloud — ransomware or sabotage.",
		Severity: 5, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			return isCloudEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"schedulekeydeletion", "disablekey", "destroycryptokey",
					"keyvaults/delete", "schedulecryptokeyversion")
		},
	},
	{
		ID: "C-XCLOUD-006", Name: "Cloud Data Store Made Publicly Accessible",
		Description: "Storage bucket, blob container, or database made publicly accessible.",
		Severity: 4, MITRE: "T1530", Category: "Collection",
		Match: func(ev store.Event) bool {
			return isCloudEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)), "allusers", "allauthenticatedusers") &&
				containsAny(strings.ToLower(rawStr(ev)), "bucket", "blob", "container", "storage", "bigquery", "sql")
		},
	},
	{
		ID: "C-XCLOUD-007", Name: "Cloud Identity Created Outside Business Hours",
		Description: "New cloud user or service account created outside normal business hours.",
		Severity: 3, MITRE: "T1136.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			if !isCloudEvent(ev) {
				return false
			}
			hour := ev.Time.UTC().Hour()
			isOutsideHours := hour < 6 || hour >= 22
			return isOutsideHours &&
				containsAny(strings.ToLower(rawStr(ev)),
					"createuser", "adduser", "serviceaccounts/write", "users/write", "createserviceaccount")
		},
	},
	{
		ID: "C-XCLOUD-008", Name: "Cloud Security Tool Disabled",
		Description: "Security service disabled across any cloud — GuardDuty, Defender, Security Command Center.",
		Severity: 5, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return isCloudEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"deletedetector", "disableguarddutyv2",
					"securitycenter/pricings", "microsoft.security",
					"scc.findings.setState")
		},
	},
	{
		ID: "C-XCLOUD-009", Name: "Cloud Network Perimeter Modified After Hours",
		Description: "Firewall or security group modified outside business hours.",
		Severity: 3, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			if !isCloudEvent(ev) {
				return false
			}
			hour := ev.Time.UTC().Hour()
			isOutsideHours := hour < 6 || hour >= 22
			return isOutsideHours &&
				containsAny(strings.ToLower(rawStr(ev)),
					"authorizesecuritygroup", "firewallrules/write", "compute.firewalls",
					"networksecuritygroups/write")
		},
	},
	{
		ID: "C-XCLOUD-010", Name: "Cloud Credentials Exfiltration Attempt",
		Description: "Cloud metadata endpoint or credential file accessed — possible credential theft.",
		Severity: 4, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return (isCloudEvent(ev) || ev.EventType == "network" || ev.EventType == "file") &&
				containsAny(rawStr(ev),
					"169.254.169.254",
					"metadata.google.internal",
					"instance/service-accounts",
					".aws/credentials", "accesstokens.json")
		},
	},
}

// ══════════════════════════════════════════════════════════════════════════════
// Cloud — Reconnaissance / Discovery signatures
// ══════════════════════════════════════════════════════════════════════════════
var cloudReconSignatures = []ThreatSig{
	{
		ID: "C-RECON-001", Name: "AWS Cloud Enumeration — ListBuckets/DescribeInstances Burst",
		Description: "Rapid succession of AWS list/describe API calls — consistent with automated enumeration (prowler, ScoutSuite, Pacu, CloudMapper).",
		Severity: 3, MITRE: "T1526", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				containsAny(strings.ToLower(rawStr(ev)),
					"listbuckets", "describeinstances", "listusers", "listgroups",
					"listpolicies", "describedbinstances", "listfunctions",
					"getaccountauthorizationdetails", "listattacheduserpolicies")
		},
	},
	{
		ID: "C-RECON-002", Name: "AWS IAM Credential Report Generated",
		Description: "IAM credential report generated — maps all users, password ages, access keys, MFA status. Commonly used by attackers to identify weak accounts.",
		Severity: 3, MITRE: "T1087.004", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				awsActionHas(ev, "generatecredentialreport", "getcredentialreport")
		},
	},
	{
		ID: "C-RECON-003", Name: "Cloud Account Metadata Enumeration",
		Description: "Cloud account or organization structure enumerated — consistent with attacker mapping the environment.",
		Severity: 2, MITRE: "T1526", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return isCloudEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"getaccountsummary", "listaccounts", "describeorganization",
					"tenants/read", "subscriptions/list", "projects.list",
					"resourcemanager.projects.list")
		},
	},
	{
		ID: "C-RECON-004", Name: "Azure Subscription and Resource Enumeration",
		Description: "Mass resource listing across an Azure subscription — possible recon with az CLI or automated tool.",
		Severity: 2, MITRE: "T1526", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(strings.ToLower(rawStr(ev)),
					"microsoft.resources/resources/read",
					"microsoft.resources/subscriptions/resourcegroups/read",
					"microsoft.authorization/roledefinitions/read")
		},
	},
	{
		ID: "C-RECON-005", Name: "GCP Service Account Keys Listed",
		Description: "All service account keys enumerated — attacker mapping credential exposure.",
		Severity: 3, MITRE: "T1087.004", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(strings.ToLower(rawStr(ev)),
					"iam.serviceaccountkeys.list", "iam.serviceaccounts.list")
		},
	},
}

// ══════════════════════════════════════════════════════════════════════════════
// Cloud — Network anomaly signatures
// ══════════════════════════════════════════════════════════════════════════════
var cloudNetworkSignatures = []ThreatSig{
	{
		ID: "C-NET-001", Name: "Cloud Security Group Opens SSH/RDP to Internet",
		Description: "Security group or firewall rule created allowing SSH (22) or RDP (3389) from 0.0.0.0/0 — critical exposure.",
		Severity: 5, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return isCloudEvent(ev) &&
				containsAny(raw, "authorizesecuritygroupingress", "compute.firewalls.insert",
					"compute.firewalls.update", "networksecuritygroups/write",
					"securityrules/write") &&
				containsAny(raw, "0.0.0.0/0", "::/0") &&
				containsAny(raw, ":22", ":3389", "port22", "port3389", "ssh", "rdp",
					"fromport\":\"22", "fromport\":\"3389")
		},
	},
	{
		ID: "C-NET-002", Name: "AWS Security Group Opens All Ports to Internet",
		Description: "Security group rule allows all traffic (port range -1 or 0-65535) from 0.0.0.0/0.",
		Severity: 5, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.cloudtrail" &&
				containsAny(raw, "authorizesecuritygroupingress") &&
				containsAny(raw, "0.0.0.0/0", "::/0") &&
				containsAny(raw, "fromport\":-1", "fromport\":0", "alltraffic", "ipprotocol\":\"-1\"")
		},
	},
	{
		ID: "C-NET-003", Name: "Cloud VPN Tunnel Deleted",
		Description: "VPN tunnel or connection deleted — corporate network connectivity severed.",
		Severity: 4, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return isCloudEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"deletevpnconnection", "deletecustomergateway",
					"virtualnetworkgateways/delete", "vpnconnections/delete",
					"compute.vpntunnels.delete", "compute.interconnects.delete")
		},
	},
	{
		ID: "C-NET-004", Name: "AWS Direct Connect or Transit Gateway Modified",
		Description: "Core network routing infrastructure modified — possible traffic interception.",
		Severity: 3, MITRE: "T1557", Category: "Collection",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				containsAny(strings.ToLower(rawStr(ev)),
					"createtransitgateway", "modifytransitgateway",
					"createdirectconnect", "deletedirectconnect",
					"associatetransitgatewayroutablecidr")
		},
	},
	{
		ID: "C-NET-005", Name: "Cloud Metadata Service Accessed from Unexpected IP",
		Description: "Cloud instance metadata endpoint (169.254.169.254) queried from a source that is not the instance itself — SSRF or credential theft attempt.",
		Severity: 5, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "network" || ev.EventType == "cloud.cloudtrail") &&
				containsAny(rawStr(ev), "169.254.169.254", "metadata.google.internal",
					"instance/service-accounts", "latest/meta-data/iam")
		},
	},
}

// ══════════════════════════════════════════════════════════════════════════════
// Cloud — Lateral Movement signatures
// ══════════════════════════════════════════════════════════════════════════════
var cloudLateralSignatures = []ThreatSig{
	{
		ID: "C-LAT-001", Name: "AWS EC2 Instance Connect Used",
		Description: "EC2 Instance Connect used to push an SSH public key — agentless shell access to EC2 without a persistent key pair.",
		Severity: 3, MITRE: "T1021.004", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				containsAny(strings.ToLower(rawStr(ev)), "sendsshpublickey", "ec2instanceconnect")
		},
	},
	{
		ID: "C-LAT-002", Name: "AWS SSM RunCommand Executed on Multiple Instances",
		Description: "AWS Systems Manager RunCommand executed — remote code execution on EC2 instances without SSH.",
		Severity: 4, MITRE: "T1021.006", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				containsAny(strings.ToLower(rawStr(ev)), "sendcommand", "ssm:sendcommand") &&
				containsAny(strings.ToLower(rawStr(ev)), "aws-runshellscript", "aws-runpowershellscript", "documentname")
		},
	},
	{
		ID: "C-LAT-003", Name: "AWS Role Chaining Detected",
		Description: "IAM role assumed then used to assume another role (role chaining) — escalating privilege across trust boundaries.",
		Severity: 4, MITRE: "T1548.005", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.cloudtrail" &&
				containsAny(raw, "assumerole") &&
				containsAny(raw, "assumed-role") && // caller was already a role
				!containsAny(raw, "errorcode")
		},
	},
	{
		ID: "C-LAT-004", Name: "Azure VM Run Command Executed",
		Description: "Azure VM Run Command used — remote code execution on VM without RDP/SSH.",
		Severity: 4, MITRE: "T1021.006", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_activity" &&
				containsAny(strings.ToLower(rawStr(ev)),
					"virtualmachines/runcommand", "virtualmachines/extensions/write") &&
				containsAny(strings.ToLower(rawStr(ev)), "customscriptextension", "runshellscript", "runpowershellscript")
		},
	},
	{
		ID: "C-LAT-005", Name: "GCP OS Login SSH Key Added",
		Description: "SSH key added via GCP OS Login — persistent remote access to GCE instances.",
		Severity: 3, MITRE: "T1098.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(strings.ToLower(rawStr(ev)),
					"oslogin.users.importSshPublicKey", "oslogin.sshPublicKeys.create",
					"compute.projects.setCommonInstanceMetadata") &&
				containsAny(strings.ToLower(rawStr(ev)), "ssh-rsa", "ssh-ed25519", "sshkeys")
		},
	},
}

// ══════════════════════════════════════════════════════════════════════════════
// Cloud — Compute abuse / Cryptomining signatures
// ══════════════════════════════════════════════════════════════════════════════
var cloudComputeAbuseSignatures = []ThreatSig{
	{
		ID: "C-ABUSE-001", Name: "Unusual EC2 Instance Type Launched",
		Description: "High-compute EC2 instance launched (GPU/HPC family) — possible cryptomining or abuse.",
		Severity: 3, MITRE: "T1496", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.cloudtrail" &&
				containsAny(raw, "runinstances") &&
				containsAny(raw, "p3.", "p4.", "g4.", "g5.", "p2.", "hpc6a", "inf1.", "trn1.",
					"p3.16xlarge", "p4d.", "g4dn.", "g5.")
		},
	},
	{
		ID: "C-ABUSE-002", Name: "Cloud Compute Quota Increase Requested",
		Description: "Cloud compute quota increase requested — may precede large-scale resource abuse.",
		Severity: 2, MITRE: "T1496", Category: "Impact",
		Match: func(ev store.Event) bool {
			return isCloudEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"requestservicequotaincrease", "quotas/write",
					"serviceusage.quotas.update", "supporttickets/write")
		},
	},
	{
		ID: "C-ABUSE-003", Name: "AWS Spot Instance Fleet or Batch Job Created",
		Description: "Spot fleet or Batch compute environment created — common pattern for cost-effective cryptomining.",
		Severity: 3, MITRE: "T1496", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.cloudtrail" &&
				containsAny(strings.ToLower(rawStr(ev)),
					"requestspotfleet", "createspotdatafeedsubscription",
					"registerjobtypedetector", "createcomputeenvironment")
		},
	},
}

// isCloudEvent returns true if the event came from a cloud provider
func isCloudEvent(ev store.Event) bool {
	return strings.HasPrefix(string(ev.EventType), "cloud.")
}
