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
