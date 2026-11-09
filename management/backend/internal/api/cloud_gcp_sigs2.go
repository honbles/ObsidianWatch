package api

import (
	"strings"

	"obsidianwatch/management/internal/store"
)

// G-34: additional GCP escalation / exfiltration detections. Rules match on
// method_name and only fire for succeeded calls.

func gcpSucceeded(ev store.Event, methods ...string) (string, bool) {
	if ev.EventType != "cloud.gcp_audit" {
		return "", false
	}
	raw := strings.ToLower(rawStr(ev))
	if !strings.Contains(raw, `"outcome":"succeeded"`) {
		return raw, false
	}
	for _, m := range methods {
		if strings.Contains(raw, `"method_name":"`) && strings.Contains(raw, strings.ToLower(m)) {
			return raw, true
		}
	}
	return raw, false
}

var gcpEscalationSignatures = []ThreatSig{
	{
		ID: "C-GCP-084", Name: "GCP Service Account Key Created",
		Description: "A user-managed service account key was created — long-lived credential commonly used for persistence and exfiltration of access.",
		Severity: 3, MITRE: "T1098.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			_, ok := gcpSucceeded(ev, "CreateServiceAccountKey", "iam.serviceaccountkeys.create")
			return ok
		},
	},
	{
		ID: "C-GCP-085", Name: "GCP Service Account Impersonation Token/Sign",
		Description: "GenerateAccessToken, SignBlob, SignJwt or implicit delegation used to act as another service account — privilege escalation path.",
		Severity: 3, MITRE: "T1548.005", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			_, ok := gcpSucceeded(ev, "GenerateAccessToken", "SignBlob", "SignJwt", "GenerateIdToken", "implicitDelegation")
			return ok
		},
	},
	{
		ID: "C-GCP-086", Name: "GCP Custom IAM Role Created or Updated",
		Description: "Custom IAM role created or modified — can be used to quietly grant powerful permissions.",
		Severity: 3, MITRE: "T1098", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			_, ok := gcpSucceeded(ev, "iam.roles.create", "iam.roles.update", "CreateRole", "UpdateRole")
			return ok
		},
	},
	{
		ID: "C-GCP-087", Name: "GCP Compute Metadata SSH/Startup Script Changed",
		Description: "Project or instance metadata modified (ssh-keys / startup-script) — enables code execution or persistent access on VMs.",
		Severity: 4, MITRE: "T1098.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			raw, ok := gcpSucceeded(ev, "compute.instances.setMetadata", "compute.projects.setCommonInstanceMetadata")
			return ok && containsAny(raw, "ssh-keys", "startup-script", "enable-oslogin")
		},
	},
	{
		ID: "C-GCP-088", Name: "GCP Org Policy Changed",
		Description: "Organization policy constraint set or deleted — can disable guardrails (e.g. external IP, SA key creation restrictions).",
		Severity: 4, MITRE: "T1562", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			_, ok := gcpSucceeded(ev, "SetOrgPolicy", "orgpolicy.policy.set", "DeleteOrgPolicy", "orgpolicy.policy.delete", "UpdatePolicy")
			return ok
		},
	},
	{
		ID: "C-GCP-089", Name: "GCP Disk/Snapshot/Image Exported or Shared",
		Description: "Disk snapshot, image or backup shared or exported — possible data exfiltration of full volumes.",
		Severity: 4, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw, ok := gcpSucceeded(ev, "compute.snapshots.setIamPolicy", "compute.images.setIamPolicy", "compute.images.export", "compute.disks.createSnapshot")
			if !ok {
				return false
			}
			return !strings.Contains(raw, "createsnapshot") || containsAny(raw, "allusers", "allauthenticatedusers")
		},
	},
	{
		ID: "C-GCP-090", Name: "GCP BigQuery Dataset Exported or Made Public",
		Description: "BigQuery extract job to Cloud Storage or dataset IAM granted to allUsers/allAuthenticatedUsers.",
		Severity: 4, MITRE: "T1567", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			raw, ok := gcpSucceeded(ev, "jobservice.insert", "bigquery.jobs.create", "SetIamPolicy", "datasets.patch", "datasets.update")
			if !ok || !strings.Contains(raw, "bigquery") {
				return false
			}
			return containsAny(raw, "allusers", "allauthenticatedusers") ||
				containsAny(raw, `"extract"`, "destinationuris")
		},
	},
}
