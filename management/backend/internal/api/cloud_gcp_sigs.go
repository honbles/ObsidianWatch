package api

import (
	"encoding/json"
	"strings"
	"obsidianwatch/management/internal/store"
)

// cloud_gcp_sigs.go — GCP-specific threat detection rules
//
// Covers 50 additional GCP rules across:
//   - IAM & Privilege Escalation (C-GCP-021 to C-GCP-030)
//   - Credential & Token Theft   (C-GCP-031 to C-GCP-038)
//   - Compute & Container        (C-GCP-039 to C-GCP-047)
//   - Data & Storage             (C-GCP-048 to C-GCP-054)
//   - Network & Perimeter        (C-GCP-055 to C-GCP-061)
//   - Defense Evasion            (C-GCP-062 to C-GCP-068)
//   - Persistence                (C-GCP-069 to C-GCP-073)
//   - SCC Findings               (C-SCC-001 to C-SCC-008)
//
// Naming convention: C-GCP-XXX for direct GCP Audit Log rules,
// C-SCC-XXX for Security Command Center finding rules.


// ── IAM & Privilege Escalation ────────────────────────────────────────────────

var gcpIAMSignatures = []ThreatSig{
	{
		ID: "C-GCP-021", Name: "GCP Owner Role Granted to External User",
		Description: "Project Owner role (roles/owner) granted to a non-serviceAccount identity — highest privilege escalation. Any user gaining Owner can create backdoor SAs, delete audit logs, and exfiltrate all data.",
		Severity: 5, MITRE: "T1098.003", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return gcpExternalRoleGrant(ev, "roles/owner")
		},
	},
	{
		ID: "C-GCP-022", Name: "GCP Editor Role Granted to External User",
		Description: "Project Editor role granted to an external user or group — near-owner access to all GCP APIs.",
		Severity: 4, MITRE: "T1098.003", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return gcpExternalRoleGrant(ev, "roles/editor")
		},
	},
	{
		ID: "C-GCP-023", Name: "GCP Service Account Token Creator Granted",
		Description: "iam.serviceAccountTokenCreator role granted — allows the grantee to impersonate any service account in the project, creating a privilege escalation path to any SA's permissions.",
		Severity: 5, MITRE: "T1548.005", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "setiampolicy") &&
				containsAny(raw, "roles/iam.serviceaccounttokencreator", "serviceaccounttokencreator")
		},
	},
	{
		ID: "C-GCP-024", Name: "GCP Service Account Created Outside Automation",
		Description: "New service account created by a human user identity (not a CI/CD SA). Human-created SAs are often assigned over-broad permissions and long-lived keys, and are harder to audit.",
		Severity: 3, MITRE: "T1136.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "iam.serviceaccounts.create", "createserviceaccount") &&
				containsAny(raw, "user:")
		},
	},
	{
		ID: "C-GCP-025", Name: "GCP Service Account Key Created",
		Description: "New long-lived service account key created. SA keys are credentials that never expire by default, persist outside GCP, and are a top target for credential theft. Key creation by a human identity is especially suspicious.",
		Severity: 4, MITRE: "T1552.004", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "iam.serviceaccounts.createkey", "createserviceaccountkey")
		},
	},
	{
		ID: "C-GCP-026", Name: "GCP IAM Policy Modified on High-Value Resource",
		Description: "IAM policy changed on a sensitive resource — KMS keyring, Secret Manager secret, Cloud SQL instance, or GCS bucket containing audit logs.",
		Severity: 4, MITRE: "T1078.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "setiampolicy") &&
				containsAny(raw, "cloudkms", "secretmanager", "cloudsql", "cloudresourcemanager")
		},
	},
	{
		ID: "C-GCP-027", Name: "GCP Workload Identity Pool Created",
		Description: "Workload Identity Pool created — allows external identities (AWS, Azure, GitHub Actions, Kubernetes) to impersonate GCP service accounts. Misconfigured pools are an initial access vector.",
		Severity: 3, MITRE: "T1199", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "workloadidentitypools", "workloadidentitypool") &&
				containsAny(raw, "create", "update", "patch")
		},
	},
	{
		ID: "C-GCP-028", Name: "GCP Service Account Impersonation via generateAccessToken",
		Description: "generateAccessToken or signJWT called against a service account — SA impersonation in progress. Legitimate use is rare outside Workload Identity flows.",
		Severity: 4, MITRE: "T1548.005", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw,
					"generateaccesstoken", "signjwt", "signblob",
					"iam.serviceaccounts.actAs",
					"iam.serviceaccounts.signjwt")
		},
	},
	{
		ID: "C-GCP-029", Name: "GCP IAM Deny Policy Deleted",
		Description: "IAM Deny policy deleted — an explicit deny guardrail was removed. Deny policies take precedence over allow policies and are used to enforce mandatory access controls.",
		Severity: 4, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "iampolicies.delete", "denypolicies", "policies.delete") &&
				containsAny(raw, "deny")
		},
	},
	{
		ID: "C-GCP-030", Name: "GCP allUsers or allAuthenticatedUsers IAM Binding",
		Description: "IAM policy binding added granting access to allUsers or allAuthenticatedUsers at the project, folder, or organization level — public access to project-level resources.",
		Severity: 5, MITRE: "T1078.004", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "setiampolicy", "getsetiampolicy") &&
				containsAny(raw, "allusers", "allauthenticatedusers")
		},
	},
}

// ── Credential & Token Theft ──────────────────────────────────────────────────

var gcpCredentialSignatures = []ThreatSig{
	{
		ID: "C-GCP-031", Name: "GCP OAuth Token Introspection",
		Description: "OAuth token introspection endpoint queried — attacker may be validating stolen access tokens before use.",
		Severity: 3, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "cloud.gcp_audit" || ev.EventType == "network") &&
				containsAny(rawStr(ev),
					"oauth2.googleapis.com/tokeninfo",
					"www.googleapis.com/oauth2/v1/tokeninfo",
					"tokeninfo")
		},
	},
	{
		ID: "C-GCP-032", Name: "GCP Service Account Key Uploaded (External Key)",
		Description: "External (user-managed) key uploaded to a service account — attacker may be inserting a backdoor credential they control.",
		Severity: 5, MITRE: "T1098.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "uploadserviceaccountkey", "iam.serviceaccounts.uploadkey") &&
				containsAny(raw, "user:")
		},
	},
	{
		ID: "C-GCP-033", Name: "GCP Secret Manager Bulk Access",
		Description: "Multiple Secret Manager secrets accessed in a short window — indicates automated credential harvesting, not normal application access.",
		Severity: 4, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "secretmanager.versions.access", "accesssecretversion") &&
				// Fire on high-severity events — engine should correlate volume
				ev.Severity >= 3
		},
	},
	{
		ID: "C-GCP-034", Name: "GCP Compute Metadata Endpoint Queried via HTTP",
		Description: "GCP instance metadata endpoint (metadata.google.internal or 169.254.169.254) queried directly — SSRF or credential theft. Valid SDKs use this endpoint internally but raw HTTP queries are suspicious.",
		Severity: 4, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "network" || ev.EventType == "cloud.gcp_audit") &&
				containsAny(rawStr(ev),
					"metadata.google.internal",
					"metadata/computeMetadata",
					"instance/service-accounts/default/token",
					"service-accounts/default/token")
		},
	},
	{
		ID: "C-GCP-035", Name: "GCP KMS CryptoKey Destroyed or Scheduled for Destruction",
		Description: "KMS crypto key version scheduled for destruction or destroyed — could be ransomware preparation or deliberate sabotage. Key destruction is irreversible after the scheduled window.",
		Severity: 5, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw,
					"destroycryptokeyversion", "cloudkms.cryptokeyversions.destroy",
					"scheduledfordestruction", "schedulecryptokeyversion")
		},
	},
	{
		ID: "C-GCP-036", Name: "GCP KMS Key Disabled",
		Description: "KMS encryption key disabled — disabling a key with active data encrypted under it effectively ransoms that data.",
		Severity: 4, MITRE: "T1486", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "cloudkms.cryptokeys.update", "updatecryptokey") &&
				containsAny(raw, "disabled", "\"state\":\"disabled\"")
		},
	},
	{
		ID: "C-GCP-037", Name: "GCP Cloud KMS Key Material Exported",
		Description: "KMS key wrapping or import operation — key material may have been exported from the GCP boundary.",
		Severity: 4, MITRE: "T1552", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "importcryptokeyversion", "cloudkms.importjobs", "wrappedkey")
		},
	},
	{
		ID: "C-GCP-038", Name: "GCP Cloud Identity Password Reset",
		Description: "Google Cloud Identity / Workspace account password reset by an admin — could be account takeover preparation.",
		Severity: 4, MITRE: "T1098", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "admin.users.update", "directory.users.update") &&
				containsAny(raw, "password", "recoveryemail", "recoveryphone")
		},
	},
}

// ── Compute & Container ───────────────────────────────────────────────────────

var gcpComputeSignatures = []ThreatSig{
	{
		ID: "C-GCP-039", Name: "GCP Compute Instance Serial Console Enabled",
		Description: "Serial console access enabled on a GCE instance — allows interactive console access that bypasses firewall rules and IAP. Often used for debugging but is a persistent backdoor when left on.",
		Severity: 3, MITRE: "T1133", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "compute.instances.setmetadata", "compute.projects.setcommoninstancemetadata") &&
				containsAny(raw, "serial-port-enable", "serialportaccessenabled") &&
				containsAny(raw, "true", "\"value\":\"1\"")
		},
	},
	{
		ID: "C-GCP-040", Name: "GCP GKE Cluster Master Authorized Networks Removed",
		Description: "GKE cluster master authorized networks cleared — Kubernetes API server now accessible from any IP. Combined with any credential leak this is full cluster takeover.",
		Severity: 5, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "container.clusters.update", "updatecluster") &&
				containsAny(raw, "masterauthorizednetworksconfig") &&
				containsAny(raw, "enabled\":false", "\"cidrblocks\":[]")
		},
	},
	{
		ID: "C-GCP-041", Name: "GKE Cluster Node Pool Created with Default SA",
		Description: "GKE node pool created using the default compute service account — all pods on these nodes inherit Editor-equivalent permissions via the metadata endpoint, enabling container escape to full project access.",
		Severity: 4, MITRE: "T1078.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "container.clusters.create", "container.nodepools.create") &&
				containsAny(raw, "developer.gserviceaccount.com")
		},
	},
	{
		ID: "C-GCP-042", Name: "GKE Kubernetes exec into Pod",
		Description: "kubectl exec used to open a shell in a running pod — interactive access to container internals. Legitimate for debugging but a significant lateral movement vector if done to non-test pods.",
		Severity: 3, MITRE: "T1609", Category: "Execution",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			m := gkeMethod(ev)
			return ev.EventType == "cloud.gcp_gke_audit" &&
				(strings.HasSuffix(m, "pods.exec.create") || strings.HasSuffix(m, "pods.exec.get") ||
					strings.Contains(raw, "pods/exec")) && gkeSucceeded(ev)
		},
	},
	{
		ID: "C-GCP-043", Name: "GKE Privileged Container Created",
		Description: "Kubernetes pod created with securityContext.privileged=true — privileged containers have full access to the host kernel and are a standard container escape vector.",
		Severity: 5, MITRE: "T1611", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			m := gkeMethod(ev)
			return ev.EventType == "cloud.gcp_gke_audit" &&
				(strings.HasSuffix(m, "pods.create") || strings.HasSuffix(m, "pods.update") || strings.HasSuffix(m, "pods.patch")) &&
				strings.Contains(raw, "\"privileged\":true") && gkeSucceeded(ev)
		},
	},
	{
		ID: "C-GCP-044", Name: "GKE ClusterRoleBinding Created for cluster-admin",
		Description: "ClusterRoleBinding created granting cluster-admin — full unrestricted access to the Kubernetes API across all namespaces. This is the Kubernetes equivalent of IAM Owner.",
		Severity: 5, MITRE: "T1548", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			m := gkeMethod(ev)
			return ev.EventType == "cloud.gcp_gke_audit" &&
				strings.Contains(m, "clusterrolebindings") &&
				(strings.HasSuffix(m, ".create") || strings.HasSuffix(m, ".update") || strings.HasSuffix(m, ".patch")) &&
				strings.Contains(raw, "\"cluster_admin_binding\":true") && gkeSucceeded(ev)
		},
	},
	{
		ID: "C-GCP-045", Name: "GCP Cloud Build Trigger Modified",
		Description: "Cloud Build trigger created or updated — CI/CD pipeline changes can inject malicious build steps that exfiltrate secrets, deploy backdoored containers, or modify infrastructure.",
		Severity: 3, MITRE: "T1195.002", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "cloudbuild.builds.create", "cloudbuild.triggers.create",
					"cloudbuild.triggers.update", "cloudbuild.triggers.run")
		},
	},
	{
		ID: "C-GCP-046", Name: "GCP Artifact Registry Repository Made Public",
		Description: "Artifact Registry or Container Registry IAM policy grants allUsers access — container images or packages exposed publicly, enabling supply chain attacks.",
		Severity: 4, MITRE: "T1195.001", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "artifactregistry", "containerregistry", "gcr.io") &&
				containsAny(raw, "setiampolicy") &&
				containsAny(raw, "allusers", "allauthenticatedusers")
		},
	},
	{
		ID: "C-GCP-047", Name: "GCP Compute Instance Metadata Modified to Disable OS Login",
		Description: "OS Login disabled on a GCE instance or project — fallback to SSH key metadata auth which is harder to centrally revoke and audit.",
		Severity: 3, MITRE: "T1556", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "compute.instances.setmetadata", "compute.projects.setcommoninstancemetadata") &&
				containsAny(raw, "enable-oslogin") &&
				containsAny(raw, "false", "\"value\":\"false\"")
		},
	},
}

// ── Data & Storage ────────────────────────────────────────────────────────────

var gcpDataSignatures = []ThreatSig{
	{
		ID: "C-GCP-048", Name: "GCP Storage Bucket Retention Policy Locked or Removed",
		Description: "GCS bucket retention policy locked (preventing future deletion/modification) or removed. Removing a retention policy may precede data deletion or ransomware.",
		Severity: 3, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "storage.buckets.update") &&
				containsAny(raw, "retentionpolicy", "retention_policy")
		},
	},
	{
		ID: "C-GCP-049", Name: "GCP BigQuery Table Data Exported",
		Description: "BigQuery extract job created — large data export from BigQuery to GCS or external location. A common exfiltration pattern: query → extract job → copy bucket to external account.",
		Severity: 3, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "bigquery.jobs.create") &&
				containsAny(raw, "extract", "jobtype\":\"extract\"", "destinationuris")
		},
	},
	{
		ID: "C-GCP-050", Name: "GCP BigQuery Dataset Deleted",
		Description: "BigQuery dataset deleted — data destruction or post-exfiltration cleanup.",
		Severity: 4, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "bigquery.datasets.delete", "deletedataset")
		},
	},
	{
		ID: "C-GCP-051", Name: "GCP Cloud Spanner Database Deleted",
		Description: "Cloud Spanner instance or database deleted — catastrophic data loss for mission-critical systems.",
		Severity: 5, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "spanner.databases.delete", "spanner.instances.delete",
					"deletedatabase", "deleteinstance")
		},
	},
	{
		ID: "C-GCP-052", Name: "GCP Cloud SQL Backup Deleted",
		Description: "Cloud SQL automated or manual backup deleted — precedes ransomware or data destruction to eliminate recovery options.",
		Severity: 4, MITRE: "T1490", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "cloudsql.backupruns.delete", "deletebackuprun")
		},
	},
	{
		ID: "C-GCP-053", Name: "GCP GCS Bucket Transferred to External Project",
		Description: "Storage Transfer Service job or GCS bucket CORS/ACL modified to allow cross-project access — possible data staging for exfiltration.",
		Severity: 3, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "storagetransfer.transferjobs.create",
					"storagetransfer.transferjobs.update")
		},
	},
	{
		ID: "C-GCP-054", Name: "GCP Dataflow Job Created with External Sink",
		Description: "Dataflow pipeline created — batch or streaming jobs can silently exfiltrate data to external BigQuery, GCS, or PubSub destinations outside the project.",
		Severity: 2, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "dataflow.jobs.create", "dataflowjobs.create")
		},
	},
}

// ── Network & Perimeter ───────────────────────────────────────────────────────

var gcpNetworkSignatures = []ThreatSig{
	{
		ID: "C-GCP-055", Name: "GCP VPC Service Control Perimeter Modified",
		Description: "VPC Service Control perimeter updated — access policy to restrict GCP APIs by network changed. Weakening or deleting a perimeter exposes APIs to exfiltration from outside the VPC.",
		Severity: 4, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "accesscontextmanager.accesspolicies",
					"updateserviceperimeter", "deleteserviceperimeter",
					"servicerestrictions")
		},
	},
	{
		ID: "C-GCP-056", Name: "GCP Cloud Armor Security Policy Deleted",
		Description: "Cloud Armor WAF/DDoS policy deleted — application-layer protection removed from load balancer.",
		Severity: 4, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "compute.securitypolicies.delete", "deletesecuritypolicy")
		},
	},
	{
		ID: "C-GCP-057", Name: "GCP Private Google Access Disabled on Subnet",
		Description: "Private Google Access disabled on a VPC subnet — VMs without public IPs can no longer reach Google APIs, but also indicates network configuration tampering.",
		Severity: 2, MITRE: "T1562.007", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "compute.subnetworks.update", "patchsubnetwork") &&
				containsAny(raw, "privateipgoogleaccess", "privateipgoogleaccess\":false")
		},
	},
	{
		ID: "C-GCP-058", Name: "GCP Cloud NAT Gateway Deleted",
		Description: "Cloud NAT configuration deleted — outbound internet connectivity for private VMs lost, or network topology deliberately modified.",
		Severity: 3, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "compute.routers.delete", "deleterouter") &&
				containsAny(raw, "nat", "router")
		},
	},
	{
		ID: "C-GCP-059", Name: "GCP Interconnect or VPN Peer Config Changed",
		Description: "Dedicated Interconnect or Cloud VPN peer tunnel configuration modified — corporate WAN connectivity tampered with.",
		Severity: 3, MITRE: "T1557", Category: "Collection",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw,
					"compute.interconnectattachments", "compute.vpntunnels",
					"compute.externalvpngateways", "updatevpntunnel",
					"deleteinterconnectattachment")
		},
	},
	{
		ID: "C-GCP-060", Name: "GCP DNS Zone Modified",
		Description: "Cloud DNS managed zone record modified — DNS hijacking vector. Changing NS, A, or MX records can redirect traffic.",
		Severity: 4, MITRE: "T1584.002", Category: "Resource Development",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "dns.changes.create", "dns.managedzones.delete",
					"dns.resourcerecordsets", "changednszone")
		},
	},
	{
		ID: "C-GCP-061", Name: "GCP Shared VPC Host Project Association Changed",
		Description: "Shared VPC host project association added or removed — changes which projects share network resources, a lateral movement path between projects.",
		Severity: 3, MITRE: "T1078.004", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "compute.organizations.enablexpnhost",
					"compute.organizations.enablexpnresource",
					"enablesharedvpchost", "disablesharedvpc")
		},
	},
}

// ── Defense Evasion ───────────────────────────────────────────────────────────

var gcpDefenseEvasionSignatures = []ThreatSig{
	{
		ID: "C-GCP-062", Name: "GCP Audit Log Configuration Modified",
		Description: "Cloud Audit Log configuration changed — DATA_READ or DATA_WRITE audit logging disabled for one or more GCP services. Attackers disable audit logging to hide subsequent activity.",
		Severity: 5, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "setiampolicy", "resourcemanager.projects.setiampolicy",
					"updateauditconfig") &&
				containsAny(raw, "auditlogconfigs", "auditconfigs") &&
				containsAny(raw, "none", "log_none")
		},
	},
	{
		ID: "C-GCP-063", Name: "GCP Cloud Logging Sink Deleted",
		Description: "Log sink (export) deleted — audit log forwarding to SIEM, GCS, or BigQuery stopped. An attacker clearing evidence or creating a detection blind spot.",
		Severity: 4, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "logging.sinks.delete", "deletelogsink", "deletesink")
		},
	},
	{
		ID: "C-GCP-064", Name: "GCP Cloud Logging Exclusion Created",
		Description: "Log exclusion filter created — specific log entries will now be silently dropped before reaching Cloud Logging. Used to hide specific operation types.",
		Severity: 4, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "logging.exclusions.create", "createexclusion",
					"logging.sinks.create") &&
				containsAny(raw, "exclusion", "filter")
		},
	},
	{
		ID: "C-GCP-065", Name: "GCP Security Command Center Notification Deleted",
		Description: "SCC notification config deleted — real-time SCC finding alerts to Pub/Sub stopped. An attacker may disable SCC notifications to prevent alerting on their subsequent actions.",
		Severity: 4, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "securitycenter.notificationconfigs.delete",
					"deletenotificationconfig", "securitycenter")
		},
	},
	{
		ID: "C-GCP-066", Name: "GCP Binary Authorization Policy Weakened",
		Description: "Binary Authorization policy changed to allow unverified images or set to dry-run mode — container image integrity enforcement weakened.",
		Severity: 3, MITRE: "T1195.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "binaryauthorization.policy.update",
					"binaryauthorization") &&
				containsAny(raw, "dryrun", "dry_run", "allow", "unverified")
		},
	},
	{
		ID: "C-GCP-067", Name: "GCP Asset Inventory Feed Deleted",
		Description: "Cloud Asset Inventory feed deleted — real-time resource change notifications stopped. Used for continuous compliance monitoring.",
		Severity: 3, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "cloudasset.feeds.delete", "deletefeed")
		},
	},
	{
		ID: "C-GCP-068", Name: "GCP Project Lien Removed",
		Description: "Project lien (deletion protection) removed — project can now be deleted. Removal of liens is a prerequisite for catastrophic project-level data destruction.",
		Severity: 4, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "resourcemanager.liens.delete", "deletelien")
		},
	},
}

// ── Persistence ───────────────────────────────────────────────────────────────

var gcpPersistenceSignatures = []ThreatSig{
	{
		ID: "C-GCP-069", Name: "GCP Cloud Function Deployed with Broad IAM Role",
		Description: "Cloud Function deployed and its service account has Owner, Editor, or other broad role. Serverless functions are a stealthy persistence mechanism — they survive VM reboots and are often overlooked in IR.",
		Severity: 4, MITRE: "T1525", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "cloudfunctions.functions.create", "cloudfunctions.functions.update") &&
				containsAny(raw, "serviceaccountname", "service_account_email")
		},
	},
	{
		ID: "C-GCP-070", Name: "GCP Cloud Run Service Deployed Outside CI/CD",
		Description: "Cloud Run service deployed by a human user identity (not a build SA) — manual production deployments bypass CI/CD controls and may contain unreviewed code.",
		Severity: 3, MITRE: "T1525", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "run.services.create", "run.services.update",
					"run.services.replaceservice") &&
				containsAny(raw, "user:")
		},
	},
	{
		ID: "C-GCP-071", Name: "GCP Cloud Workflow Created",
		Description: "Google Cloud Workflow created or updated — orchestration workflows can chain API calls and are a persistence or automation mechanism for attackers with compromised credentials.",
		Severity: 2, MITRE: "T1053", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "workflows.create", "workflows.update",
					"workflows.workflows.create")
		},
	},
	{
		ID: "C-GCP-072", Name: "GCP SSH Key Added to Project Metadata",
		Description: "SSH key added to GCE project-wide metadata — affects all VMs in the project without OS Login. A single key injection grants SSH access to every instance.",
		Severity: 4, MITRE: "T1098.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "compute.projects.setcommoninstancemetadata") &&
				containsAny(raw, "ssh-keys", "sshkeys", "ssh-rsa", "ssh-ed25519")
		},
	},
	{
		ID: "C-GCP-073", Name: "GCP Pub/Sub Push Subscription to External Endpoint",
		Description: "Pub/Sub push subscription configured to forward messages to an external HTTPS endpoint — live data exfiltration pipeline established.",
		Severity: 3, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "pubsub.subscriptions.create", "pubsub.subscriptions.update") &&
				containsAny(raw, "pushconfig", "pushendpoint") &&
				!containsAny(raw, ".googleapis.com", ".google.com", ".run.app")
		},
	},
}

// ── Security Command Center (SCC) findings ────────────────────────────────────
// These rules match on cloud.gcp_scc event type — SCC finding events
// pushed via Pub/Sub and ingested by the GCP sync connector.

var gcpSCCSignatures = []ThreatSig{
	{
		ID: "C-SCC-001", Name: "SCC: Active Threat Finding (High/Critical)",
		Description: "Google Security Command Center raised a high or critical severity threat finding. SCC threat detections are based on network traffic, activity logs, and Google threat intelligence.",
		Severity: 5, MITRE: "T1078", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_scc" &&
				ev.Severity >= 4 &&
				containsAny(raw, "threat", "active", "malware", "exploit", "attack", "compromise")
		},
	},
	{
		ID: "C-SCC-002", Name: "SCC: Cryptomining Detected",
		Description: "SCC detected cryptocurrency mining activity — compromised compute resources being abused for financial gain.",
		Severity: 4, MITRE: "T1496", Category: "Impact",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_scc" &&
				containsAny(raw, "cryptomining", "miner", "xmrig", "stratum", "bitcoin", "monero", "coin")
		},
	},
	{
		ID: "C-SCC-003", Name: "SCC: Anomalous IAM Grant Detected",
		Description: "SCC detected an anomalous IAM grant — identity access patterns deviate from baseline, indicating potential account compromise or insider threat.",
		Severity: 4, MITRE: "T1078.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_scc" &&
				containsAny(raw, "anomalous_iam_grant", "anomalous", "iam_anomaly",
					"persistence_iam_anomalous_grant")
		},
	},
	{
		ID: "C-SCC-004", Name: "SCC: Exfiltration Finding",
		Description: "SCC detected a data exfiltration attempt — data copied to external resources or unusual egress patterns observed.",
		Severity: 5, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_scc" &&
				containsAny(raw, "exfiltration", "data_exfiltration", "bigquery_exfiltration",
					"cloudsql_exfiltration", "cloudstorage_exfiltration")
		},
	},
	{
		ID: "C-SCC-005", Name: "SCC: Malware Detected on GCE Instance",
		Description: "SCC / VM Threat Detection identified malware executing on a GCE instance — kernel-level detection of in-memory malware.",
		Severity: 5, MITRE: "T1059", Category: "Execution",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_scc" &&
				containsAny(raw, "malware", "vmthreatdetection", "added_malicious_binary",
					"malicious_script", "rootkit", "malicious_url")
		},
	},
	{
		ID: "C-SCC-006", Name: "SCC: Container Escape / Breakout Detected",
		Description: "SCC detected a container escape attempt — containerized workload accessing host resources outside its expected scope.",
		Severity: 5, MITRE: "T1611", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_scc" &&
				containsAny(raw, "container_escape", "privilege_escalation",
					"execution_tainted_image", "unexpected_container_run")
		},
	},
	{
		ID: "C-SCC-007", Name: "SCC: Initial Access — SSH/RDP Brute Force",
		Description: "SCC detected brute force authentication attempts against SSH or RDP on a GCE instance.",
		Severity: 3, MITRE: "T1110", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_scc" &&
				containsAny(raw, "bruteforce", "brute_force", "ssh_brute_force",
					"initial_access_bruteforce")
		},
	},
	{
		ID: "C-SCC-008", Name: "SCC: Dormant Service Account Activity",
		Description: "SCC detected activity from a service account that had been dormant — suggests credential theft and delayed use.",
		Severity: 4, MITRE: "T1078.004", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_scc" &&
				containsAny(raw, "dormant_service_account", "inactive_sa",
					"persistence_dormant_service_account_used")
		},
	},
}

// ── New GCP Signatures (C-GCP-074 to C-GCP-083) ──────────────────────────────

var gcpNewSignatures = []ThreatSig{
	{
		ID: "C-GCP-074", Name: "Cloud Run Deployed with Unauthenticated Access",
		Description: "A Cloud Run service was deployed or updated allowing unauthenticated invocations (allUsers granted roles/run.invoker). Any internet user can now invoke this service — this is the serverless equivalent of a public RCE endpoint.",
		Severity: 4, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "run.services.setiampolicy", "google.cloud.run.v1.services.replaceroute",
					"run.googleapis.com") &&
				containsAny(raw, "allusers", "allAuthenticatedUsers", "roles/run.invoker")
		},
	},
	{
		ID: "C-GCP-075", Name: "Artifact Registry / GCR Made Publicly Accessible",
		Description: "allUsers or allAuthenticatedUsers was granted access to an Artifact Registry repository or Container Registry. Public container registries allow anyone to pull images (potential data exposure) and possibly push malicious images (supply chain attack).",
		Severity: 5, MITRE: "T1195.001", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "artifactregistry.googleapis.com", "containerregistry.googleapis.com",
					"artifactregistry.repositories.setiampolicy") &&
				containsAny(raw, "allusers", "allauthenticatedusers")
		},
	},
	{
		ID: "C-GCP-076", Name: "GCS Bucket Made Public via IAM SetIAMPolicy",
		Description: "A Cloud Storage bucket IAM policy was updated to include allUsers or allAuthenticatedUsers via setIamPolicy (not legacy ACL). This is distinct from ACL-based public access and requires a separate rule to catch.",
		Severity: 5, MITRE: "T1530", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "storage.buckets.setiampolicy", "storage.googleapis.com") &&
				containsAny(raw, "allusers", "allauthenticatedusers") &&
				containsAny(raw, "setiampolicy", "storage.objectviewer", "storage.admin")
		},
	},
	{
		ID: "C-GCP-077", Name: "Org Policy Constraint Deleted or Overridden",
		Description: "A restrictive organization policy constraint was deleted, set to restore-default, or overridden. Org policies are guardrails that prevent misconfigurations at scale — removing them enables attacks that the policy was blocking (e.g., re-enabling SA key creation after iam.disableServiceAccountKeyCreation was enforced).",
		Severity: 4, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "orgpolicies.delete", "orgpolicies.patch",
					"cloudresourcemanager.organizations.setorgpolicy",
					"cloudresourcemanager.projects.setorgpolicy",
					"setorgpolicy") &&
				containsAny(raw, "delete", "restoredefault", "inherit", "disable")
		},
	},
	{
		ID: "C-GCP-078", Name: "VPC Peering Created to External / Unknown Project",
		Description: "A new VPC peering connection was created. Peering creates bidirectional network paths between projects — a compromised peer project can reach internal services. Peering to unknown projects is a lateral movement enabler.",
		Severity: 3, MITRE: "T1599", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "compute.networks.addpeering", "networkpeerings",
					"compute.networks.updatepeering") &&
				containsAny(raw, "insert", "create", "add")
		},
	},
	{
		ID: "C-GCP-079", Name: "Cloud Scheduler Job Targeting Metadata Endpoint (SSRF)",
		Description: "A Cloud Scheduler job was created or updated with a target URL pointing to the GCE metadata endpoint (169.254.169.254) or metadata.google.internal. This creates a server-side request forgery path to steal service account tokens on a schedule.",
		Severity: 5, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "cloudscheduler.googleapis.com", "scheduler.jobs.create",
					"scheduler.jobs.update") &&
				containsAny(raw, "169.254.169.254", "metadata.google.internal",
					"computemetadata", "instance/service-accounts")
		},
	},
	{
		ID: "C-GCP-080", Name: "BigQuery Dataset Shared with External Domain",
		Description: "A BigQuery dataset IAM policy was updated to grant access to a user or group outside the organization's domain. Sharing datasets with external identities is a common insider threat exfiltration vector — entire datasets can be queried and exported.",
		Severity: 4, MITRE: "T1530", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "bigquery.datasets.setiampolicy",
					"bigquery.googleapis.com/datasets") &&
				containsAny(raw, "user:", "group:") &&
				containsAny(raw, "gmail.com", "outlook.com", "yahoo.com", "hotmail.com",
					"roles/bigquery.dataviewer", "roles/bigquery.dataeditor",
					"roles/bigquery.admin")
		},
	},
	{
		ID: "C-GCP-081", Name: "VM Startup Script Contains Credential Patterns",
		Description: "A Compute Engine instance was created or updated with a startup-script metadata value containing patterns that match API keys, service account JSON, or passwords. Embedding credentials in startup scripts is a secrets sprawl pattern that exposes credentials to anyone with VM metadata access.",
		Severity: 4, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "compute.instances.insert", "compute.instances.setmetadata",
					"instances.setmetadata") &&
				containsAny(raw, "startup-script") &&
				containsAny(raw, "private_key", "client_secret", "api_key", "password",
					"-----begin rsa", "-----begin ec", "access_token", "service_account_key")
		},
	},
	{
		ID: "C-GCP-082", Name: "Project-Level SSH Key Added to Metadata",
		Description: "SSH keys were added to project metadata (ssh-keys key). Project-level SSH keys grant SSH access to ALL running VMs in the project. An attacker adding a key here gains lateral movement to every Linux VM instantly.",
		Severity: 4, MITRE: "T1098.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "compute.projects.setcommoninstancemetadata",
					"setcommoninstancemetadata", "projects.setMetadata") &&
				containsAny(raw, "ssh-keys", "sshkeys", "ssh_keys")
		},
	},
	{
		ID: "C-GCP-083", Name: "Binary Authorization Policy Deleted or Bypass Added",
		Description: "Binary Authorization enforcement was disabled, or a breakglass/allowlist exemption was added. Binary Authorization prevents deployment of unscanned or unsigned container images. Disabling it or adding bypass rules removes the primary supply chain control for GKE.",
		Severity: 4, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			raw := strings.ToLower(rawStr(ev))
			return ev.EventType == "cloud.gcp_audit" &&
				containsAny(raw, "binaryauthorization.googleapis.com",
					"binaryauthorization.policy.update",
					"binaryauthorization.attestors") &&
				containsAny(raw, "delete", "disabled", "dryrun", "always_allow",
					"breakglass", "allow_all", "admissionwhitelistpattern")
		},
	},
}

// gkeMethod returns the lower-cased methodName of a GKE audit event.
func gkeMethod(ev store.Event) string {
	var r struct {
		M string `json:"method_name"`
	}
	if ev.Raw != nil {
		_ = json.Unmarshal(ev.Raw, &r)
	}
	return strings.ToLower(r.M)
}

// gkeSucceeded is true when the audited K8s call returned status code 0.
func gkeSucceeded(ev store.Event) bool {
	var r struct {
		C int `json:"status_code"`
	}
	if ev.Raw != nil {
		_ = json.Unmarshal(ev.Raw, &r)
	}
	return r.C == 0
}

// gcpTelemetrySignatures cover the telemetry sources that were ingested but
// never alerted (G-09): Cloud IDS findings, Cloud DNS queries, VPC Flow Logs.
var gcpTelemetrySignatures = []ThreatSig{
	{
		ID: "C-GCP-IDS-001", Name: "Cloud IDS Threat Detected (High/Critical)",
		Description: "Google Cloud IDS reported a high or critical severity threat. The IDS finding is itself a detection and alerts directly.",
		Severity: 4, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_ids" && ev.Severity >= 4
		},
	},
	{
		ID: "C-GCP-IDS-002", Name: "Cloud IDS Threat Detected (Medium)",
		Description: "Google Cloud IDS reported a medium severity threat.",
		Severity: 3, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.gcp_ids" && ev.Severity == 3
		},
	},
	{
		ID: "C-GCP-POL-001", Name: "VPC Service Controls / Org Policy Denial",
		Description: "A request was denied by VPC Service Controls or an organisation policy (policy audit log). Repeated denials from one principal can indicate data-exfiltration probing from outside the service perimeter.",
		Severity: 3, MITRE: "T1567", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			if ev.EventType != "cloud.gcp_audit" {
				return false
			}
			var r struct {
				LogType string `json:"log_type"`
			}
			return json.Unmarshal(ev.Raw, &r) == nil && r.LogType == "policy_denied"
		},
	},
	{
		ID: "C-GCP-DNS-001", Name: "Possible DNS Tunnelling (Long Query Name)",
		Description: "A Cloud DNS query had an unusually long name or label, or used a TXT/NULL record type with a long name — common in DNS tunnelling and C2-over-DNS.",
		Severity: 4, MITRE: "T1071.004", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			if ev.EventType != "cloud.gcp_dns" {
				return false
			}
			var r struct {
				Q string `json:"query_name"`
				T string `json:"query_type"`
			}
			if json.Unmarshal(ev.Raw, &r) != nil {
				return false
			}
			q := strings.TrimSuffix(strings.ToLower(r.Q), ".")
			longLabel := false
			for _, l := range strings.Split(q, ".") {
				if len(l) > 52 {
					longLabel = true
				}
			}
			tt := strings.ToUpper(r.T)
			return longLabel || len(q) > 120 || ((tt == "TXT" || tt == "NULL") && len(q) > 80)
		},
	},
	{
		ID: "C-GCP-NET-001", Name: "Outbound Admin/SMB Protocol to the Internet",
		Description: "An allowed VPC flow from an internal address to a public IP on SSH, RDP, SMB, WinRM or Telnet ports — exposure or lateral/exfil staging.",
		Severity: 3, MITRE: "T1021", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			if ev.EventType != "cloud.gcp_vpc_flow" {
				return false
			}
			var r struct {
				Dst  string `json:"dst_ip"`
				Port int    `json:"dst_port"`
				Disp string `json:"disposition"`
			}
			if json.Unmarshal(ev.Raw, &r) != nil || strings.EqualFold(r.Disp, "DENIED") {
				return false
			}
			switch r.Port {
			case 22, 23, 445, 3389, 5985, 5986:
			default:
				return false
			}
			_, public := publicLookupIP(r.Dst)
			return public
		},
	},
}

// retiredSigIDs are rules superseded by an equivalent earlier rule (G-26).
// They would raise a second, identical alert for the same event, so the
// detection engine skips them. C-GCP-082 duplicates C-GCP-072 (project SSH
// key metadata) and C-GCP-075 duplicates C-GCP-046 (public Artifact Registry).
var retiredSigIDs = map[string]bool{
	"C-GCP-082": true,
	"C-GCP-075": true,
}
