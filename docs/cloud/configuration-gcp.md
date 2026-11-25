# GCP connector: configuration

This page covers how to create GCP credentials for ObsidianWatch, the roles and APIs they need, what each connector field does, and how to check and troubleshoot the connection. See [deployment.md](deployment.md) for the shared setup and [capability-gcp.md](capability-gcp.md) for what is collected.

> Not verified against a real GCP project. Roles are taken from `docs/cloud/gcp/main.tf` and from `cloud_gcp_permcheck.go`.

*Implemented in:* `internal/api/cloud_gcp.go`, `cloud_gcp_wif.go`, `cloud_gcp_projects.go`, `cloud_gcp_permcheck.go`, `cloud_gcp_logs.go`, `cloud_gcp_cspm*.go`, `cloud_gcp_cis.go`, `cloud_gcp_assets.go`, `cloud_gcp_blast*.go`, `cloud_gcp_scc.go`; Terraform `docs/cloud/gcp/main.tf`; UI `pages/cloud/shared.jsx` (`PROVIDERS.gcp`).

## 1. Credential model

Two credential types are accepted in the same field:

| Type | JSON `type` | How tokens are obtained |
|---|---|---|
| Service-account key | `service_account` | A signed JWT is exchanged at the key's `token_uri`. The host must be `oauth2.googleapis.com`, `accounts.google.com` or `www.googleapis.com` over HTTPS. |
| Workload Identity Federation (keyless, preferred) | `external_account` | A subject token is read from a **file under `/var/run/secrets/`** (for example a Kubernetes projected token). It is exchanged at `https://sts.googleapis.com/`, then optionally used to impersonate a service account via `https://iamcredentials.googleapis.com/`. The audience must start with `//iam.googleapis.com/`. URL-based and other file sources are rejected. |

Token scopes: `logging.read` for audit-log ingestion; `cloud-platform` for posture, SCC, inventory and blast radius; `cloud-platform.read-only` for project discovery.

## 2. Required roles and APIs

### Terraform (recommended)

`docs/cloud/gcp/main.tf` creates a read-only service account, grants it the roles below on the project (or on the organisation when `org_id` is set), and enables the APIs listed:

```hcl
# GR-01: onboard a GCP project (or, with org_id, an organisation) to ObsidianWatch.
# Creates a read-only service account and grants least-privilege roles.
# Usage:
#   terraform init && terraform apply -var project_id=my-proj
#   (org-wide)  terraform apply -var project_id=my-proj -var org_id=1234567890
# Then create a key (or, preferably, use Workload Identity Federation) and
# paste it into Cloud -> Add connector -> GCP.

variable "project_id" { type = string }
variable "org_id" {
  type    = string
  default = ""
}
variable "account_id" {
  type    = string
  default = "obsidianwatch-reader"
}

provider "google" { project = var.project_id }

resource "google_service_account" "reader" {
  account_id   = var.account_id
  display_name = "ObsidianWatch read-only collector"
}

locals {
  project_roles = [
    "roles/logging.viewer",              # Cloud Audit Logs (admin activity)
    "roles/logging.privateLogViewer",    # Data Access audit logs
    "roles/iam.securityReviewer",        # IAM / CSPM / CIS checks
    "roles/cloudasset.viewer",           # asset inventory + blast radius
    "roles/securitycenter.findingsViewer", # SCC findings (needs SCC API enabled)
  ]
}

resource "google_project_iam_member" "project" {
  for_each = var.org_id == "" ? toset(local.project_roles) : toset([])
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.reader.email}"
}

resource "google_organization_iam_member" "org" {
  for_each = var.org_id != "" ? toset(local.project_roles) : toset([])
  org_id   = var.org_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.reader.email}"
}

resource "google_project_service" "apis" {
  for_each = toset([
    "logging.googleapis.com", "cloudasset.googleapis.com",
    "iam.googleapis.com", "cloudresourcemanager.googleapis.com",
    "securitycenter.googleapis.com", "compute.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

output "service_account_email" { value = google_service_account.reader.email }
output "next_step" {
  value = "gcloud iam service-accounts keys create key.json --iam-account=${google_service_account.reader.email}   # then upload key.json in ObsidianWatch (prefer Workload Identity Federation where possible)"
}
```

Run it:

```bash
cd docs/cloud/gcp
terraform init && terraform apply -var project_id=my-proj
# organisation-wide:
terraform apply -var project_id=my-proj -var org_id=1234567890
```

Notes on the Terraform:

- The "next step" text says "Cloud -> Add connector -> GCP". In the current console this is **Cloud → Posture → Connect account → Google Cloud Platform**.
- It does **not** grant `roles/browser`. The connector test recommends `roles/browser`, and project discovery with `project_id = *` needs `resourcemanager.projects.list` / `folders.list` on the org or folder. Add `roles/browser` (or `roles/resourcemanager.folderViewer` plus project list rights) at the org or folder if you use discovery.
- Enable each service API you want assessed (Container, BigQuery, Secret Manager, Cloud Run, Cloud Functions, Pub/Sub, DNS, KMS, SQL Admin, API Keys, Notebooks, Artifact Registry). If an API is disabled, its check is shown as *not assessed*.

### Permissions the connector test checks

**Test Connection** runs `projects.testIamPermissions` on the first project. It reports per feature (in the API response; the form shows only success or failure):

| Feature | Permissions |
|---|---|
| `audit_logs` | `logging.logEntries.list` |
| `posture_core` | `compute.firewalls.list`, `compute.instances.list`, `storage.buckets.list`, `storage.buckets.getIamPolicy`, `iam.serviceAccounts.list`, `resourcemanager.projects.getIamPolicy`, `cloudsql.instances.list` |
| `posture_extended` | `container.clusters.list`, `cloudkms.keyRings.list`, `bigquery.datasets.get`, `secretmanager.secrets.list`, `run.services.list`, `cloudfunctions.functions.list`, `pubsub.topics.list`, `dns.managedZones.list` |
| `asset_inventory` | `cloudasset.assets.listResource` |
| `scc_findings` | `securitycenter.findings.list` |
| `service_account_keys` | `iam.serviceAccountKeys.list` |

Recommended roles returned by the test: `roles/logging.viewer`, `roles/cloudasset.viewer`, `roles/iam.securityReviewer`, `roles/securitycenter.findingsViewer`, `roles/browser`.

Data Access audit logs also need `roles/logging.privateLogViewer`, and Data Access logging must be turned on in the project's audit configuration.

## 3. Connector fields

| Field (UI label) | Key | Required | Effect |
|---|---|---|---|
| Service Account JSON or Workload Identity config | `service_account` | Yes | The full key file or `external_account` config. Encrypted at rest. Masked in the UI. |
| Project ID(s) (optional) | `project_id` | See below | Empty: the key's own `project_id`. Comma (or space, `;`, newline) separated list: those projects. `*`: discover all active projects under the org or folder below. This text is also the connector key. |
| Organization ID (optional) | `org_id` | For `*` | `123456789012` or `organizations/…`. Discovery root, and org-level IAM checks. |
| Folder ID (optional) | `folder_id` | No | Limits discovery to this folder tree. Takes priority over `org_id`. |

If `project_id` is empty but an org or folder is set, discovery also runs. Discovery returns at most **100** active projects and walks at most **200** folders.

Workload Identity configs contain no `project_id`. With an `external_account` credential, always fill in **Project ID(s)**. Otherwise the sync fails with "project_id required".

### How project scoping works

| Feature | Projects used |
|---|---|
| Audit-log ingestion | All resolved projects. A failing project holds the cursor back so nothing is skipped. |
| VPC flow, DNS, IDS, Cloud Run, GKE audit, policy-denied, Cloud Armor, SCC threat events | **First listed project only.** With `*` or empty: the key's own project (none for Workload Identity). |
| CSPM scan | All resolved projects, at most **25** per run (4-minute timeout each) |
| CIS benchmark | All resolved projects (merged, controls prefixed by project) |
| Scheduled asset inventory | First listed project, otherwise the connector's `account_id` |
| Blast radius | All resolved projects, at most **10** per run |

With `project_id = *` the connector's `account_id` is stored as `*`. The scheduled asset inventory then runs against project `*` and fails. Run **Full Inventory** only with an explicit project list. This is a suspected gap and has not been verified.

## 4. Verification

1. **Test Connection.** Success means a token could be minted. Call the API directly (`POST /api/v1/cloud-connectors/test`) to see the per-feature `features` list and `recommended_roles`.
2. Save, then **Sync now**. The status becomes `connected`. If `account_id` was empty, it is filled with the first project (plus `(+N)`), and the label is set to the service-account email.
3. **Event Timeline**: `cloud.gcp_audit` events (first run: the last 24 hours), plus extended sources if they are enabled in the project.
4. **Overview → Run Scan.** "SCC (N findings)" appears when Security Command Center returned data. Failed checks list a role hint (for example `gke` → `roles/container.viewer + enable container.googleapis.com`).
5. **CIS Benchmark → Run Assessment**, **Compliance → Remap Compliance**, **Asset Graph → Full Inventory**, **Blast Radius → Run Analysis**.
6. Optional: `GET /api/v1/cloud-connectors/{id}/sources` shows `gcp_audit`, `gcp_vpc_flow`, `gcp_dns`, `gcp_ids`, `gcp_cloud_run`, `gcp_policy_denied`, `gcp_lb_armor`, `gcp_gke_audit`, `gcp_scc`.

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "invalid service account JSON" / "expected service_account or external_account type" | Pasted something else | Paste the full JSON |
| "token_uri host … is not a Google OAuth endpoint" | Edited key file | Use the original key |
| "credential_source.file must be a path under /var/run/secrets/" | WIF config uses a URL or another path | Mount the token under `/var/run/secrets/` |
| "project_id required" | WIF credential with no project list | Fill in Project ID(s) |
| "project_id \"*\" needs an org_id or folder_id" | `*` without an org or folder | Add Organization ID or Folder ID |
| `gcp_audit` = `permission_missing` (403) | No `logging.viewer` | Grant it |
| No Data Access events | Data Access logs disabled, or no `privateLogViewer` | Enable audit config and grant the role |
| `gcp_vpc_flow` / `gcp_dns` / `gcp_ids` = `not_enabled` (404) or no events | Flow logs, DNS logging or Cloud IDS not configured | Configure them. Expected otherwise. |
| `gcp_scc` = `not_enabled` | SCC not activated or API disabled | Activate SCC (optional) |
| CSPM `not_assessed`: "permission denied or API disabled" | 403 from an optional check | Enable the API or grant the viewer role |
| Org-policy findings missing | `getEffectiveOrgPolicy` 403/404 is skipped silently (no not-assessed entry) | Grant `orgpolicy.policy.get` / `roles/orgpolicy.policyViewer` |
| Sync error "Logging API 429" | Read quota | Fewer projects per connector. Extended pulls retry with `Retry-After`. |
