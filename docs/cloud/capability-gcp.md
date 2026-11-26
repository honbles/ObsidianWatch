# GCP: capability reference

This page describes, end to end, what ObsidianWatch does with a GCP connector: ingestion, normalisation, posture checks (including Security Command Center), the CIS subset, compliance mapping, detections, correlation, baselines, inventory, blast radius and the console pages. Shared behaviour is in [capability.md](capability.md). Setup is in [configuration-gcp.md](configuration-gcp.md).

## 1. Log sources and polling

All sources are pulled by the 5-minute connector sync through Cloud Logging `entries:list`, except the SCC threat events.

| Source | Filter | Projects | Window | Event type | `agent_id` |
|---|---|---|---|---|---|
| Cloud Audit Logs | `cloudaudit.googleapis.com/activity`, `…/policy`, and `…/data_access` excluding principals containing `gcp-sa-` or `@cloudservices.gserviceaccount.com`. **System Event logs are excluded.** | All resolved projects | `receiveTimestamp ≥` cursor − 30 s (first run: 24 h). Oldest first, 100 per page, 200 ms between pages. | `cloud.gcp_audit` | `gcp-auditlog-<id>` |
| VPC Flow Logs | `compute.googleapis.com/vpc_flows` | First project | `timestamp ≥ last_sync − 2 min` (first run: 10 min) | `cloud.gcp_vpc_flow` | `gcp-vpcflow-<id>` |
| Cloud DNS | `dns.googleapis.com/dns_queries` | First project | same | `cloud.gcp_dns` | `gcp-dns-<id>` |
| Cloud IDS | `ids.googleapis.com/threat`, `…/traffic` | First project | same | `cloud.gcp_ids` | `gcp-ids-<id>` |
| Cloud Run requests | `run.googleapis.com/requests` | First project | same | `cloud.gcp_cloud_run` | `gcp-cloudrun-<id>` |
| Policy denials | `cloudaudit.googleapis.com/policy` | First project | same | `cloud.gcp_policy_denied` | `gcp-policy-<id>` |
| Cloud Armor | `http_load_balancer` entries with enforced or preview outcome `DENY` | First project | same | `cloud.gcp_lb_armor` | `gcp-armor-<id>` |
| GKE audit | activity or data_access with `resource.type="k8s_cluster"` | First project | same | `cloud.gcp_gke_audit` | `gcp-gkeaudit-<id>` |
| SCC threat findings | SCC `findings` with `state="ACTIVE" AND -mute="MUTED" AND finding_class="THREAT"`. No time filter: every sync relists them. | First project | – | `cloud.gcp_scc` | `gcp-scc-<id>` |

Extended (non-audit) pulls ask for 1 000 entries per page, newest first, at most 10 pages per source per sync. Rate-limited responses are retried using `Retry-After`. A source that returns 404 is recorded as `not_enabled`, and 403 as `permission_missing`.

**Duplicate-key problem (suspected).** The GKE audit and policy-denied pulls read entries that the main audit pull has already stored. They use the same `insertId` and timestamp. Events are inserted with `ON CONFLICT (id, time) DO NOTHING`, so these rows are normally dropped. `cloud.gcp_gke_audit` and `cloud.gcp_policy_denied` events, and the rules that need them (C-GCP-042, -043, -044, C-GCP-PLC-001), will rarely or never appear. The same records are still stored as `cloud.gcp_audit`. C-GCP-POL-001 covers policy denials through that path.

*Implemented in:* `cloud_gcp.go` (`syncGCP`, `pullGCPLogs`, `gcpEntryToCloudEvent`), `cloud_gcp_logs.go`, `cloud_gcp_scc.go` (`pullSCCThreatEvents`), `cloud_gcp_projects.go`.

## 2. Normalisation

### Audit log → `cloud.gcp_audit`

| Column | Value |
|---|---|
| `id` | `insertId` |
| `time` | `timestamp` |
| `host` | `resource.labels.zone` if present, else `project_id` |
| `user_name` | `protoPayload.authenticationInfo.principalEmail` |
| `src_ip` | `requestMetadata.callerIp` |
| `raw` | `log_name`, `log_type` (`audit`, `data_access`, `system_event`, `policy_denied`), `resource`, `severity`, `method_name`, `status_code`, `outcome` (`succeeded`/`failed`), `iam_grants` (parsed ADD/REMOVE binding deltas of SetIamPolicy), full `proto_payload`, `json_payload`, `text_payload`, `labels`, `operation` |

Severity rules, applied in order:

1. Log severity: EMERGENCY, ALERT or CRITICAL → 5; ERROR → 4; WARNING or NOTICE → 3; otherwise 1.
2. Successful `SetIamPolicy`, `DeleteBucket`, `DeleteProject`, `DeleteServiceAccount`, `CreateServiceAccountKey`, `DisableServiceAccount`, `DeleteCryptoKey` → at least 4.
3. Successful read-only methods (final verb starts with get, list, describe, read, lookup, query, search, test or check) → 1, unless already 4 or more.
4. Failed calls are capped at 3. `PERMISSION_DENIED` (7) and `UNAUTHENTICATED` (16) are at least 3.

### Extended sources

| Event type | Severity | Notable fields |
|---|---|---|
| `cloud.gcp_vpc_flow` | 3 if disposition DENIED, else 1 | `src_ip`, `dst_ip`, `dst_port`, `proto`, disposition, bytes |
| `cloud.gcp_dns` | 1 | `src_ip` = client, `dst_ip` = query name, query type, response code |
| `cloud.gcp_ids` | IDS severity: CRITICAL 5, HIGH 4, MEDIUM 3, LOW 1 | threat name, category, direction |
| `cloud.gcp_cloud_run` | 3 for HTTP 5xx, 401 or 403; else 1 | service, method, status, remote IP |
| `cloud.gcp_gke_audit` | 3 for exec, portforward, (cluster)rolebinding methods or any error; else 1 | method, resource name |
| `cloud.gcp_policy_denied` | 3 | principal, caller IP, violation reason |
| `cloud.gcp_lb_armor` | 3 if enforced, 1 for preview-only | policy, outcome, client IP |
| `cloud.gcp_scc` | critical 5, high 4, medium 3. Low and others are skipped. | category, state, resource. `id` = `scc-` + hash |

## 3. Posture checks (CSPM)

The scan runs at startup, every 6 hours, and on **Run Scan**. It covers every resolved project, at most 25, each with a 4-minute timeout. Token scope: `cloud-platform`.

- Core checks (`firewall`, `iam`, `storage`, `compute`, `sql`, `audit_logging`, `service_accounts`): errors go to `errors` and `not_assessed`.
- Optional checks: 403, 404 or "disabled" errors become `not_assessed`.
- Finding IDs are `gcp-` + hash(project, title, resource).
- After the built-in checks, **Security Command Center** findings for the project are fetched. If SCC is enabled, they are merged in. Where SCC and a built-in finding share the same resource and category, the SCC finding replaces the built-in one, and counts are recalculated. SCC findings keep the SCC finding name as ID.
- There is no CSPM finding suppression for GCP.

| Check key | Finding title (pattern) | Severity | Category / resource type |
|---|---|---|---|
| firewall | Firewall 'F' allows ALL traffic from internet | critical | network / firewall_rule |
| firewall | Firewall 'F' allows all ports (…) from internet | critical | network / firewall_rule |
| firewall | Firewall 'F' exposes SVC (port P) to internet | per-port table (sensitive ports high or critical) | network / firewall_rule |
| iam | IAM role 'R' granted to allUsers/allAuthenticatedUsers (public) | critical | iam / iam_binding |
| iam | Primitive role 'R' assigned to M | per role (Owner higher than Editor/Viewer) | iam / iam_binding |
| iam | Admin role 'R' granted to external identity: M | high | iam / iam_binding |
| iam | Privilege escalation path: M can impersonate high-privilege SA | critical | iam / iam_binding |
| iam | Cross-project SA 'S' has role 'R' in this project | medium | iam / iam_binding |
| storage | Storage bucket 'B' is publicly accessible (…) | critical or high | storage / gcs_bucket |
| storage | Storage bucket 'B' default object ACL grants public access | critical | storage / gcs_bucket |
| storage | Bucket 'B' does not enforce Public Access Prevention | medium | storage / gcs_bucket |
| storage | Bucket 'B' does not use uniform bucket-level access | low | storage / gcs_bucket |
| storage | Bucket 'B' has object versioning disabled | low | storage / gcs_bucket |
| storage | Bucket 'B' does not have access logging enabled | medium | logging / gcs_bucket |
| compute | VM 'V' does not have OS Login enabled | medium | compute / compute_instance |
| compute | VM 'V' has serial port access enabled | high | compute / compute_instance |
| compute | VM 'V' has a public IP address | medium | compute / compute_instance |
| compute | VM 'V' uses cloud-platform (full access) scope | high | compute / compute_instance |
| compute | VM 'V' does not have Shielded VM fully enabled | low | compute / compute_instance |
| sql | Cloud SQL 'I' is accessible from any IP (0.0.0.0/0) | critical | sql / cloud_sql |
| sql | Cloud SQL 'I' does not require SSL/TLS | high | sql / cloud_sql |
| sql | Cloud SQL 'I' uses public IP only (no private IP) | medium | sql / cloud_sql |
| sql | Cloud SQL 'I' has automated backups disabled | medium | sql / cloud_sql |
| sql | Cloud SQL 'I' has log_checkpoints disabled | low | sql / cloud_sql |
| audit_logging | Audit logging not enabled for SVC | medium | logging / audit_config |
| audit_logging | Incomplete audit logging for SVC (missing TYPES) | low | logging / audit_config |
| audit_logging | No log sink exports audit logs to external destination | high | logging / log_sink |
| audit_logging | Log sinks use filters – some audit events may not be exported | medium | logging / log_sink |
| service_accounts | Service account 'S' has a key older than N days | by age | iam / service_account_key |
| service_accounts | Default service account 'S' has a user-managed key | high | iam / service_account_key |
| kms | KMS key 'K' has no rotation policy | medium | kms / kms_key |
| kms | KMS key 'K' rotation period is N days (>90 days) | low | kms / kms_key |
| vpc_flow_logs | Subnet 'S' (region) does not have VPC flow logs enabled | medium | logging / vpc_subnet |
| default_network | The default VPC network exists | medium | network / vpc_network |
| https_lb_tls | HTTPS load balancer proxy 'P' accepts TLS older than 1.2 | medium | network / target_https_proxy |
| api_keys | API key 'K' is unrestricted | high | iam / api_key |
| api_keys | API key 'K' has no API target restriction | medium | iam / api_key |
| api_keys | API key 'K' is older than 90 days | low | iam / api_key |
| vertex_workbench | Vertex AI Workbench instance 'W' has a public IP | high | compute / workbench_instance |
| vertex_workbench | Vertex AI Workbench instance 'W' runs as the default compute service account | medium | iam / workbench_instance |
| dnssec | DNSSEC is not enabled on public zone 'Z' | medium | network / dns_zone |
| dns_logging | Cloud DNS logging is not enabled | medium | logging / dns_policy |
| gke | GKE cluster 'C': Legacy ABAC enabled | high | compute / gke_cluster |
| gke | GKE cluster 'C': Network policy not enabled | medium | network / gke_cluster |
| gke | GKE cluster 'C': Master authorized networks not configured | high | network / gke_cluster |
| gke | GKE cluster 'C': Nodes have public IPs | medium | network / gke_cluster |
| gke | GKE cluster 'C': Workload Identity not enabled | medium | iam / gke_cluster |
| gke | GKE cluster 'C': etcd not encrypted with customer-managed key | low | kms / gke_cluster |
| gke | GKE cluster 'C', node pool 'P': Auto-upgrade disabled | medium | compute / gke_node_pool |
| gke | GKE cluster 'C', node pool 'P': Full cloud-platform scope | high | iam / gke_node_pool |
| gke | GKE cluster 'C', node pool 'P': Using default Compute service account | high | iam / gke_node_pool |
| gke | GKE cluster 'C', node pool 'P': Auto-repair disabled | low | compute / gke_node_pool |
| gke | GKE cluster 'C': Binary Authorization not enforced | high | compute / gke_cluster |
| gke | GKE cluster 'C': Not enrolled in a release channel | medium | compute / gke_cluster |
| gke | GKE cluster 'C': On RAPID release channel (pre-production only) | low | compute / gke_cluster |
| gke | GKE cluster 'C': Intranode visibility disabled | low | logging / gke_cluster |
| bigquery | BigQuery dataset 'D': Public access (…) | critical | storage / bigquery_dataset |
| bigquery | BigQuery dataset 'D': No customer-managed encryption key | low | kms / bigquery_dataset |
| bigquery | BigQuery dataset 'D': Row-level security not verified (N tables) | info | storage / bigquery_dataset |
| secret_manager | Secret 'S': Public IAM access (…) | critical | storage / secret |
| secret_manager | Secret 'S': No rotation policy configured | medium | storage / secret |
| secret_manager | Secret 'S': No customer-managed encryption key | low | kms / secret |
| secret_manager | Secret 'S': N enabled versions (excessive) | low | storage / secret |
| org_policies | Service account key creation not restricted | high | iam / org_policy |
| org_policies | OS Login not enforced on Compute instances | medium | iam / org_policy |
| org_policies | Public IP creation not restricted | medium | iam / org_policy |
| org_policies | Uniform bucket-level access not enforced | low | iam / org_policy |
| org_policies | IAM domain restriction not configured | high | iam / org_policy |
| cloud_run | Cloud Run service 'S' allows unauthenticated invocations (…) | critical or high | compute / cloud_run_service |
| cloud_run | Cloud Run service 'S' ingress allows all traffic (internet-facing) | medium | compute / cloud_run_service |
| cloud_run | Cloud Run service 'S' uses default Compute service account | high | iam / cloud_run_service |
| artifact_registry | Artifact Registry 'R' is publicly accessible (…) | critical | storage / artifact_registry |
| artifact_registry | Artifact Registry 'R' (Docker) has no customer-managed encryption key | low | kms / artifact_registry |
| cloud_functions | Cloud Function 'F' allows unauthenticated invocations | critical | compute / cloud_function |
| cloud_functions | Cloud Function 'F' ingress allows all traffic | medium | compute / cloud_function |
| cloud_functions | Cloud Function 'F' uses default Compute service account | high | iam / cloud_function |
| pubsub | Pub/Sub topic 'T' grants public access (…) | critical or high | storage / pubsub_topic |
| pubsub | Pub/Sub topic 'T' has no customer-managed encryption key | low | kms / pubsub_topic |
| pubsub | Pub/Sub subscription 'S' grants public access | critical | storage / pubsub_subscription |
| org_iam | Org-level: primitive role 'R' granted to M (org: O) | by role | iam / org_iam_binding |
| org_iam | Org-level: 'R' role granted to external identity M | high | iam / org_iam_binding |
| org_iam | Org-level: role 'R' granted to M – ENTIRE ORG IS PUBLIC | critical | iam / org_iam_binding |

The org-policy checks read `getEffectiveOrgPolicy` for each constraint. A 403 or 404 on one constraint is skipped silently: it is neither a pass nor a not-assessed entry.

SCC findings take the SCC category mapped to an ObsidianWatch category. The title, remediation and MITRE technique are derived from the SCC category.

*Implemented in:* `cloud_gcp_cspm.go`, `gcp_cspm_extra.go`, `cloud_gcp_cspm_apikeys.go`, `cloud_gcp_cspm_vertex.go`, `cloud_gcp_cspm_multi.go`, `cloud_gcp_scc.go`.

## 4. CIS benchmark (subset of CIS GCP Foundation v2.0)

**Run Assessment** only. It is not scheduled. Each control calls the APIs itself. With several projects, results are merged and titles are prefixed with `[<project>]`.

| ID | Section | Title | Level |
|---|---|---|---|
| 1.1 | IAM | Ensure that corporate login credentials are used | 1 |
| 1.2 | IAM | Ensure multi-factor authentication is enabled for all non-service accounts | 1 |
| 1.3 | IAM | Ensure that Security Key Enforcement is enabled for all admin accounts | 2 |
| 1.4 | IAM | Ensure that service account keys are rotated within 90 days | 1 |
| 1.5 | IAM | Ensure that Service Account does not have admin privileges | 1 |
| 1.6 | IAM | Ensure that Service Account has no user-managed keys | 2 |
| 1.7 | IAM | Ensure Separation of Duties is enforced | 2 |
| 2.1 | Logging | Ensure that Cloud Audit Logging is configured properly across all services | 1 |
| 2.2 | Logging | Ensure log metric filter for project ownership assignments/changes | 1 |
| 2.3 | Logging | Ensure log metric filter for audit configuration changes | 1 |
| 2.4 | Logging | Ensure log metric filter for custom role creation/changes | 1 |
| 2.5 | Logging | Ensure a log sink is created for all log entries | 1 |
| 2.6 | Logging | Ensure log metric filter for VPC network route changes | 2 |
| 2.7 | Logging | Ensure log metric filter for VPC firewall rule changes | 2 |
| 3.1 | Networking | Ensure the default network does not exist | 2 |
| 3.2 | Networking | Ensure legacy networks do not exist | 1 |
| 3.3 | Networking | Ensure that DNS logging is enabled for all VPC networks | 1 |
| 3.4 | Networking | Ensure that SSH access is restricted from the internet | 1 |
| 3.5 | Networking | Ensure that RDP access is restricted from the internet | 1 |
| 3.6 | Networking | Ensure VPC firewall rule logging is enabled | 2 |
| 3.7 | Networking | Ensure Private Google Access is enabled for all subnets | 2 |
| 4.1 | VM | Ensure that OS login is enabled for all instances | 1 |
| 4.2 | VM | Ensure that 'Enable connecting to serial ports' is not enabled | 1 |
| 4.3 | VM | Ensure that project-wide SSH keys are not used in project metadata | 1 |
| 4.4 | VM | Ensure Compute instances do not use the default service account with full API access | 2 |
| 4.5 | VM | Ensure Shielded VM is enabled on all instances (vTPM + Integrity Monitoring) | 2 |
| 5.1 | Storage | Ensure Cloud Storage buckets have uniform bucket-level access enabled | 1 |
| 5.2 | Storage | Ensure that logging is enabled for Cloud Storage buckets | 2 |
| 5.3 | Storage | Ensure that retention policies on Cloud Storage buckets are configured | 2 |
| 6.1 | CloudSQL | Ensure Cloud SQL instances require all connections to use SSL (NOT_APPLICABLE if no instances) | 1 |
| 6.2 | CloudSQL | Ensure that Cloud SQL database instances do not have public IPs | 1 |
| 6.3 | CloudSQL | Ensure that Cloud SQL instances do not allow 0.0.0.0/0 in authorized networks | 1 |
| 6.4 | CloudSQL | Ensure that Cloud SQL database instances have automated backups enabled | 1 |
| 6.5 | CloudSQL | Ensure MySQL Cloud SQL instances do not allow anyone to connect with administrative privileges | 1 |
| 7.1 | BigQuery | Ensure that BigQuery datasets are not anonymously or publicly accessible | 1 |
| 7.3 | BigQuery | Ensure a default customer-managed encryption key is specified for datasets | 2 |

When the IAM policy or the instance list cannot be read, fallback controls are added with status UNKNOWN:

- 1.4 "Ensure that service account keys are rotated within 90 days", 1.5, 1.6 "Ensure IAM users are not assigned Service Account User or Token Creator at project level", 2.1 (IAM section)
- 4.1 "Ensure instances are not configured to use the default service account", 4.3 "Ensure Block Project-wide SSH keys is enabled", 4.9 "Ensure instances do not have public IP addresses" (VM section)

Some of these reuse an ID with a different title (1.6, 4.1).

**Score.** For one project: passed ÷ **all** controls, so UNKNOWN and NOT_APPLICABLE lower the score. For several projects: passed ÷ (passed + failed), computed by the shared tally. The same environment can therefore show a different score depending on how many projects are configured.

*Implemented in:* `cloud_gcp_cis.go`, `cloud_cis_multi.go`.

## 5. Compliance mapping

The report is generated after each scheduled CSPM scan and by **Remap Compliance**, using `MapToCompliance`. The same catalogue is used for Azure.

- A control is **FAIL** when any open finding with a listed category or resource type has a listed severity.
- It is **NOT_ASSESSED** when a check that feeds one of its categories or types appears in `not_assessed`.
- Otherwise it is **PASS**.

| Framework | Control | Categories | Resource types | Failing severities |
|---|---|---|---|---|
| SOC2 | CC6.1 | iam | – | critical, high |
| SOC2 | CC6.2 | iam | service_account_key, iam_binding | critical, high, medium |
| SOC2 | CC6.3 | – | iam_binding, org_iam_binding, role_assignment | critical, high |
| SOC2 | CC6.6 | network | firewall_rule, nsg | critical, high |
| SOC2 | CC6.7 | storage, sql | – | critical, high |
| SOC2 | CC6.8 | – | artifact_registry, gke_cluster, cloud_run_service | critical, high |
| SOC2 | CC7.1 | logging | – | critical, high, medium |
| SOC2 | CC7.2 | logging, compute | – | critical, high |
| SOC2 | CC8.1 | iam | org_policy | critical, high |
| SOC2 | A1.1 | – | cloud_sql, compute_instance | critical |
| PCI-DSS | PCI-1.3 | network | – | critical, high |
| PCI-DSS | PCI-2.2 | compute, sql | compute_instance, cloud_sql, gke_cluster | critical, high |
| PCI-DSS | PCI-6.3 | – | gke_cluster, artifact_registry, cloud_run_service | critical, high |
| PCI-DSS | PCI-7.2 | iam | – | critical, high, medium |
| PCI-DSS | PCI-8.2 | – | service_account_key, iam_binding | critical, high |
| PCI-DSS | PCI-8.3 | iam | – | critical, high |
| PCI-DSS | PCI-10.2 | logging | – | critical, high, medium |
| PCI-DSS | PCI-10.5 | – | log_sink, audit_config | critical, high, medium |
| ISO27001 | A.5.15 | iam | – | critical, high |
| ISO27001 | A.5.16 | – | service_account_key, iam_binding, org_iam_binding | critical, high, medium |
| ISO27001 | A.5.10 | storage | – | critical, high |
| ISO27001 | A.8.15 | logging | – | critical, high, medium |
| ISO27001 | A.8.20 | network | – | critical, high |
| ISO27001 | A.8.24 | kms | – | critical, high, medium |
| ISO27001 | A.8.25 | – | artifact_registry, gke_cluster | critical, high |
| NIST-800-53 | AC-2 | iam | – | critical, high |
| NIST-800-53 | AC-3 | – | iam_binding, org_iam_binding, service_account_key | critical, high, medium |
| NIST-800-53 | AC-17 | network, compute | firewall_rule, compute_instance | critical, high |
| NIST-800-53 | AU-2 | logging | – | critical, high, medium |
| NIST-800-53 | AU-9 | – | log_sink, audit_config | critical, high |
| NIST-800-53 | CM-6 | compute, sql, network | – | critical, high, medium |
| NIST-800-53 | IA-5 | – | service_account_key, kms_key | critical, high, medium |
| NIST-800-53 | SC-7 | network | – | critical, high |
| NIST-800-53 | SC-28 | kms, storage | kms_key, gcs_bucket, cloud_sql, bigquery_dataset | critical, high, medium |
| NIST-800-53 | SI-3 | – | gke_cluster, artifact_registry, cloud_run_service | critical, high |

GCP check keys map to categories and types like this:

- `firewall` → network, firewall_rule
- `iam` → iam, iam_binding
- `storage` → storage, gcs_bucket
- `compute` → compute, compute_instance
- `sql` → sql, cloud_sql
- `audit_logging` → logging, log_sink, audit_config
- `service_accounts` → iam, service_account_key
- `kms` → kms, kms_key
- `vpc_flow_logs` → logging, network
- `dns_logging` → logging
- `gke` → gke_cluster
- `bigquery` → bigquery_dataset
- `secret_manager` → secret
- `org_policies` → org_policy
- `cloud_run` → cloud_run_service
- `artifact_registry` → artifact_registry
- `cloud_functions` → cloud_function
- `pubsub` → pubsub
- `org_iam` → org_iam_binding

As with Azure, merged multi-project results prefix `not_assessed` check names with the project. Those entries then no longer produce NOT_ASSESSED.

Framework score = passed ÷ (controls − not assessed). The UI cards show "% compliant", passed and failed per framework.

*Implemented in:* `cloud_gcp_compliance.go`.

## 6. Detections on GCP events

GCP rule sets run on events with `os = gcp`. Many rules search the lower-cased raw JSON ("raw text") or the parsed `method_name` (`gcpMethodHas`).

### 6.1 Audit-log rules

| ID | Name | Sev | MITRE |
|---|---|---|---|
| C-GCP-006 | GCP Cloud Storage Bucket Made Public | 4 | T1530 |
| C-GCP-007 | GCP Compute Firewall Rule Opens All Ports | 4 | T1562.007 |
| C-GCP-008 | GCP VPC Firewall Rule Deleted | 3 | T1562.007 |
| C-GCP-009 | GCP Project Deleted | 5 | T1485 |
| C-GCP-010 | GCP Service Account Disabled | 3 | T1531 |
| C-GCP-011 | GCP SQL Instance Made Public | 4 | T1190 |
| C-GCP-012 | GCP Compute Instance Created with Default Service Account | 3 | T1078.004 |
| C-GCP-013 | GCP Pub/Sub Subscription Made Public | 3 | T1530 |
| C-GCP-014 | GCP BigQuery Dataset Made Public | 4 | T1530 |
| C-GCP-015 | GCP Secret Manager Secret Accessed | 3 | T1552.001 |
| C-GCP-016 | GCP Cloud Function Created or Updated | 2 | T1525 |
| C-GCP-017 | GCP Cloud Scheduler Job Created | 2 | T1053 |
| C-GCP-018 | GCP Kubernetes Cluster Created with Legacy Auth | 4 | T1190 |
| C-GCP-019 | GCP Cloud Run Service Made Public | 3 | T1190 |
| C-GCP-020 | GCP Organization Policy Constraint Disabled | 4 | T1562.001 |
| C-GCP-021 | GCP Owner Role Granted to External User | 5 | T1098.003 |
| C-GCP-022 | GCP Editor Role Granted to External User | 4 | T1098.003 |
| C-GCP-023 | GCP Service Account Token Creator Granted | 5 | T1548.005 |
| C-GCP-024 | GCP Service Account Created Outside Automation | 3 | T1136.003 |
| C-GCP-025 | GCP Service Account Key Created | 4 | T1552.004 |
| C-GCP-026 | GCP IAM Policy Modified on High-Value Resource | 4 | T1078.004 |
| C-GCP-027 | GCP Workload Identity Pool Created | 3 | T1199 |
| C-GCP-028 | GCP Service Account Impersonation via generateAccessToken | 4 | T1548.005 |
| C-GCP-029 | GCP IAM Deny Policy Deleted | 4 | T1562.001 |
| C-GCP-030 | GCP allUsers or allAuthenticatedUsers IAM Binding | 5 | T1078.004 |
| C-GCP-031 | GCP OAuth Token Introspection | 3 | T1552.001 |
| C-GCP-032 | GCP Service Account Key Uploaded (External Key) | 5 | T1098.001 |
| C-GCP-033 | GCP Secret Manager Bulk Access | 4 | T1552.001 |
| C-GCP-034 | GCP Compute Metadata Endpoint Queried via HTTP | 4 | T1552.005 |
| C-GCP-035 | GCP KMS CryptoKey Destroyed or Scheduled for Destruction | 5 | T1485 |
| C-GCP-036 | GCP KMS Key Disabled | 4 | T1486 |
| C-GCP-037 | GCP Cloud KMS Key Material Exported | 4 | T1552 |
| C-GCP-038 | GCP Cloud Identity Password Reset | 4 | T1098 |
| C-GCP-039 | GCP Compute Instance Serial Console Enabled | 3 | T1133 |
| C-GCP-040 | GCP GKE Cluster Master Authorized Networks Removed | 5 | T1190 |
| C-GCP-041 | GKE Cluster Node Pool Created with Default SA | 4 | T1078.004 |
| C-GCP-045 | GCP Cloud Build Trigger Modified | 3 | T1195.002 |
| C-GCP-046 | GCP Artifact Registry Repository Made Public | 4 | T1195.001 |
| C-GCP-047 | GCP Compute Instance Metadata Modified to Disable OS Login | 3 | T1556 |
| C-GCP-048 | GCP Storage Bucket Retention Policy Locked or Removed | 3 | T1485 |
| C-GCP-049 | GCP BigQuery Table Data Exported | 3 | T1537 |
| C-GCP-050 | GCP BigQuery Dataset Deleted | 4 | T1485 |
| C-GCP-051 | GCP Cloud Spanner Database Deleted | 5 | T1485 |
| C-GCP-052 | GCP Cloud SQL Backup Deleted | 4 | T1490 |
| C-GCP-053 | GCP GCS Bucket Transferred to External Project | 3 | T1537 |
| C-GCP-054 | GCP Dataflow Job Created with External Sink | 2 | T1537 |
| C-GCP-055 | GCP VPC Service Control Perimeter Modified | 4 | T1562.007 |
| C-GCP-056 | GCP Cloud Armor Security Policy Deleted | 4 | T1562.007 |
| C-GCP-057 | GCP Private Google Access Disabled on Subnet | 2 | T1562.007 |
| C-GCP-058 | GCP Cloud NAT Gateway Deleted | 3 | T1485 |
| C-GCP-059 | GCP Interconnect or VPN Peer Config Changed | 3 | T1557 |
| C-GCP-060 | GCP DNS Zone Modified | 4 | T1584.002 |
| C-GCP-061 | GCP Shared VPC Host Project Association Changed | 3 | T1078.004 |
| C-GCP-062 | GCP Audit Log Configuration Modified | 5 | T1562.008 |
| C-GCP-063 | GCP Cloud Logging Sink Deleted | 4 | T1562.008 |
| C-GCP-064 | GCP Cloud Logging Exclusion Created | 4 | T1562.008 |
| C-GCP-065 | GCP Security Command Center Notification Deleted | 4 | T1562.001 |
| C-GCP-066 | GCP Binary Authorization Policy Weakened | 3 | T1195.001 |
| C-GCP-067 | GCP Asset Inventory Feed Deleted | 3 | T1562.001 |
| C-GCP-068 | GCP Project Lien Removed | 4 | T1485 |
| C-GCP-069 | GCP Cloud Function Deployed with Broad IAM Role | 4 | T1525 |
| C-GCP-070 | GCP Cloud Run Service Deployed Outside CI/CD | 3 | T1525 |
| C-GCP-071 | GCP Cloud Workflow Created | 2 | T1053 |
| C-GCP-072 | GCP SSH Key Added to Project Metadata | 4 | T1098.004 |
| C-GCP-073 | GCP Pub/Sub Push Subscription to External Endpoint | 3 | T1537 |
| C-GCP-074 | Cloud Run Deployed with Unauthenticated Access | 4 | T1190 |
| C-GCP-076 | GCS Bucket Made Public via IAM SetIAMPolicy | 5 | T1530 |
| C-GCP-077 | Org Policy Constraint Deleted or Overridden | 4 | T1562.001 |
| C-GCP-078 | VPC Peering Created to External / Unknown Project | 3 | T1599 |
| C-GCP-079 | Cloud Scheduler Job Targeting Metadata Endpoint (SSRF) | 5 | T1552.005 |
| C-GCP-080 | BigQuery Dataset Shared with External Domain | 4 | T1530 |
| C-GCP-081 | VM Startup Script Contains Credential Patterns | 4 | T1552.001 |
| C-GCP-083 | Binary Authorization Policy Deleted or Bypass Added | 4 | T1562.001 |
| C-GCP-084 | GCP Service Account Key Created | 3 | T1098.001 |
| C-GCP-085 | GCP Service Account Impersonation Token/Sign | 3 | T1548.005 |
| C-GCP-086 | GCP Custom IAM Role Created or Updated | 3 | T1098 |
| C-GCP-087 | GCP Compute Metadata SSH/Startup Script Changed | 4 | T1098.004 |
| C-GCP-088 | GCP Org Policy Changed | 4 | T1562 |
| C-GCP-089 | GCP Disk/Snapshot/Image Exported or Shared | 4 | T1537 |
| C-GCP-090 | GCP BigQuery Dataset Exported or Made Public | 4 | T1567 |
| C-GCP-POL-001 | VPC Service Controls / Org Policy Denial | 3 | T1567 |
| C-RECON-005 | GCP Service Account Keys Listed | 3 | T1087.004 |
| C-LAT-005 | GCP OS Login SSH Key Added | 3 | T1098.004 |

Each rule's trigger is the API operation in its name. The rule descriptions in `cloud_gcp_sigs.go`, `cloud_gcp_sigs2.go` and `cloud_sigs.go` give the full wording. Notes:

- The Owner and Editor rules (C-GCP-021, -022) use the parsed `iam_grants` ADD deltas. Removals and the caller's own identity are ignored.
- C-GCP-084 to C-GCP-090 (`gcpSucceeded`) fire only on successful calls.
- C-GCP-075 and C-GCP-082 exist but are retired as duplicates of C-GCP-046 and C-GCP-072.
- Several pairs overlap and raise separate alerts for one event, for example C-GCP-025 and C-GCP-084 (SA key created), C-GCP-028 and C-GCP-085 (impersonation), C-GCP-020, C-GCP-077 and C-GCP-088 (org policy).

### 6.2 Rules on other GCP event types

| ID | Name | Sev | Event type | Fires when |
|---|---|---|---|---|
| C-GCP-042 | GKE Kubernetes exec into Pod | 3 | `cloud.gcp_gke_audit` | Successful pods/exec |
| C-GCP-043 | GKE Privileged Container Created | 5 | `cloud.gcp_gke_audit` | Pod create, update or patch with privileged security context |
| C-GCP-044 | GKE ClusterRoleBinding Created for cluster-admin | 5 | `cloud.gcp_gke_audit` | ClusterRoleBinding create, update or patch to cluster-admin |
| C-GCP-IDS-001 | Cloud IDS Threat Detected (High/Critical) | 4 | `cloud.gcp_ids` | Severity ≥ 4 |
| C-GCP-IDS-002 | Cloud IDS Threat Detected (Medium) | 3 | `cloud.gcp_ids` | Severity = 3 |
| C-GCP-DNS-001 | Possible DNS Tunnelling (Long Query Name) | 4 | `cloud.gcp_dns` | Long query name or label, or TXT/NULL with a long name |
| C-GCP-NET-001 | Outbound Admin/SMB Protocol to the Internet | 3 | `cloud.gcp_vpc_flow` | Allowed flow from a private source to a public IP on SSH, RDP, SMB, WinRM or Telnet ports |
| C-GCP-PLC-001 | GCP: Request Blocked by VPC Service Controls / Org Policy | 3 | `cloud.gcp_policy_denied` | Any such event |
| C-SCC-001 | SCC: Active Threat Finding (High/Critical) | 5 | `cloud.gcp_scc` | High or critical SCC threat |
| C-SCC-002 … 008 | SCC: Cryptomining / Anomalous IAM Grant / Exfiltration / Malware on GCE / Container Escape / SSH-RDP Brute Force / Dormant Service Account | 3–5 | `cloud.gcp_scc` | SCC category keywords |

The GKE rules and C-GCP-PLC-001 depend on event types that are normally dropped on insert (section 1).

Cross-cloud rules that match GCP events: C-XCLOUD-002, -003 (`updateauditconfig`), -005 (`destroycryptokey`), -006 (`allusers`), -007 (`createserviceaccount` off-hours), -008, -009 (`compute.firewalls` off-hours), -010, plus C-RECON-003, C-NET-001, C-NET-003, C-ABUSE-002.

*Implemented in:* `cloud_gcp_sigs.go`, `cloud_gcp_sigs2.go`, `cloud_gcp_logs.go` (`gcpPolicySignatures`), `cloud_sigs.go`, `gcp_iam_delta.go`.

### 6.3 Correlation (`CORR-GCP-*`)

Input is `cloud.gcp_audit` events read through an ingestion cursor every 30 seconds, so late logs are included. State is kept per (project, principal). Alerts have event type `cloud.gcp_correlation` and dedup key `corr:<id>:host:<host>:principal:<p>:h:<hour>`.

| ID | Title | Pattern |
|---|---|---|
| CORR-GCP-001 | [CORR] SA Key Created then Used from New IP | SA key created, then used from a new IP within 10 min |
| CORR-GCP-002 | [CORR] Rapid Admin Role Grant Sequence | 3 or more admin role grants within 1 h |
| CORR-GCP-003 | [CORR] GCP Reconnaissance Burst Detected | 5 or more list or describe calls within 2 min |
| CORR-GCP-004 | [CORR] Sensitive Operation After Audit Log Disabled | Audit config change, then a sensitive operation within 15 min |
| CORR-GCP-006 | [CORR] First-Seen IP Performing IAM Change | IAM change within 5 min of a new IP |
| CORR-GCP-007 | [CORR] Mass Resource Deletion Sequence | 3 or more deletes within 5 min |
| CORR-GCP-008 | [CORR] SA Impersonation Followed by High-Privilege Operation | Impersonation, then a high-privilege call |
| CORR-GCP-009 | [CORR] Cloud Run Deployed Then Immediately Invoked from New IP | Deploy, then invocation from a new IP |
| CORR-GCP-010 | [CORR] Credential Exfiltration Chain: Secret → GCS Write → New IP | Secret access, GCS write, new IP |
| CORR-GCP-011 | [CORR] Org Policy Guardrail Removed Then IAM Change | Org policy removal, then an IAM change |

CORR-GCP-005 is described in the file header but has no alert of its own.

### 6.4 Behavioural baseline (`ANOM-GCP-*`)

Learns every 15 minutes and detects every 2 minutes through a cursor. Requires 20 learned events per principal.

| ID | Title | Sev | Fires when |
|---|---|---|---|
| ANOM-GCP-001 | [ANOM] GCP Principal Activity from Unknown IP | 3 | New public source IP |
| ANOM-GCP-002 | [ANOM] GCP Principal Using New API Service | 2 | New method category for the principal |
| ANOM-GCP-003 | [ANOM] GCP High-Severity Action Outside Normal Working Hours | 3 | High-severity event in an hour with no history |
| ANOM-GCP-004 | [ANOM] Service Account Used from Multiple IPs (more than 3 in 1 hour) | 4 | Service account only |
| ANOM-GCP-005 | [ANOM] Concurrent Use from Two Different Networks | 3 | Two IPs in different /16s within 30 min (human principals only; Google-internal ranges ignored) |
| ANOM-GCP-006 | [ANOM] Large Data Read – Possible Exfiltration | 4 | One event reporting more than 10 GiB read |
| ANOM-GCP-007 | [ANOM] Principal Accessing New GCP Service for First Time | 2 | New service category |

Event type `cloud.gcp_anomaly`. Dedup per rule, principal and hour.

*Implemented in:* `cloud_gcp_correlation.go`, `cloud_gcp_baseline.go`.

## 7. Asset inventory

Runs after every scheduled CSPM scan (first project, 5-minute timeout) and on **Full Inventory**. It uses Cloud Asset Inventory `assets` (content type RESOURCE, 500 per page, at most 40 pages per type). A type that exceeds this limit is "not assessed".

Asset types:

| Area | Types |
|---|---|
| Compute | Instance, Firewall, Network, Subnetwork, Disk |
| Storage and data | Storage Bucket, Cloud SQL Instance, BigQuery Dataset, BigQuery Table, Secret Manager Secret |
| Platform | GKE Cluster, Cloud Run Service, Cloud Function, Pub/Sub Topic, Pub/Sub Subscription |
| Identity and keys | IAM Service Account, KMS CryptoKey |
| Operations | DNS ManagedZone, Log Sink, Monitoring AlertPolicy |

Results are stored in `assets:gcp:<id>` with first-seen dates, plus lists of new and deleted assets compared with the previous inventory.

When a deleted asset's name contains `cluster`, `sql`, `kms`, `cryptokey`, `bucket`, `secret` or `logsink`, the alert **"[T1485] GCP Critical Asset Disappeared from Inventory"** is raised (severity 4, once per resource per day, event type `cloud.gcp_assets`).

*Implemented in:* `cloud_gcp_assets.go`, `cloud_engine.go`.

## 8. Blast radius and attack paths

Runs on demand (**Run Analysis**). It covers each resolved project, at most 10. It reads:

- aggregated VM instances
- the project IAM policy
- buckets with full projection
- firewalls
- Cloud SQL instances
- Secret Manager secrets
- the stored CSPM result

Graph edges:

- service account ↔ VM, Cloud Function, Cloud Run
- service account → project IAM role
- VM → subnet → VPC → firewall
- bucket → public (allUsers)
- SQL → authorized networks
- KMS key → encrypted resources
- secret ← service account

The VM-side node `sa:<email>` and the IAM-side node `principal:serviceAccount:<email>` are linked by an `is_identity` edge. This lets a path such as *internet → public VM → its service account → roles/owner* be found. Path end states include `project_owner`, `all_data` and `public`.

*Implemented in:* `cloud_gcp_blast_radius.go`, `cloud_gcp_blast_multi.go`, `cloud_gcp_attackpath.go`.

## 9. What the user sees (GCP specifics)

- **Overview**: "✓ SCC (N findings)" next to the last-scan line and "SCC Active" under the gauge when SCC data was merged. The Security Command Center block shows "Connected · N findings" or "Not enabled · Enable SCC →". Failed checks show role hints such as `kms` → `roles/cloudkms.viewer + enable cloudkms.googleapis.com`.
- **Event Timeline** queries `gcp-auditlog-`, `gcp-vpcflow-`, `gcp-dns-`, `gcp-ids-`, `gcp-cloudrun-` and `gcp-gkeaudit-<id>`. Policy-denied, Cloud Armor and SCC events (`gcp-policy-`, `gcp-armor-`, `gcp-scc-<id>`) are not queried by this tab. Rows show friendly labels such as "VPC Flow · src → dst (ALLOWED)" or "DNS Query · name [A]".
- **Deep Dive** IAM groups: Public Access (allUsers), Primitive Roles (Owner/Editor), Privilege Escalation Paths, Admin Roles on External Identities, Old Service Account Keys, Default SA with Broad Scope, Cross-Project SA Access, Other IAM Issues.
- **Rules page**: GCP signature-suppression rules (sig ID prefix, principal, IP prefix, method, expiry). They apply to all cloud events.

## 10. Limits

| Item | Limit |
|---|---|
| Projects per discovery / CSPM / blast | 100 / 25 / 10 |
| Extended log sources | First project only; 10 pages × 1 000 entries per source per sync, newest first. Excess older entries in the window are lost. |
| Asset listing | 40 pages × 500 per type |
| SCC findings | 1 000 per page; all pages |

## 11. Known gaps

- GKE audit and policy-denied events collide with audit-log rows on `(id, time)` and are normally discarded (section 1).
- Extended sources, SCC threat events and the scheduled inventory use only the first listed project. With `project_id = *` the scheduled inventory targets the literal project `*`.
- Workload Identity connectors with `project_id = *` have no key project, so extended sources are skipped.
- Org-policy checks that get 403 or 404 disappear silently instead of being marked not assessed.
- The single-project CIS score counts UNKNOWN and NOT_APPLICABLE against the score; the multi-project score does not.
- The README says System Event logs are ingested. The audit filter excludes them.
- Manual **Run Scan** does not refresh compliance, inventory or new-critical alerts, and does not set `connector_id` in the stored result.
