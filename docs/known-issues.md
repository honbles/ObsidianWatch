# Known issues

Defects found by reading the code while writing these docs (November 2026). None is fixed yet unless marked. Paths are relative to the repository root; line numbers are approximate.

Fixed since: the agent queue is at-least-once with fsync and health reports its depth; Linux has an eBPF process sensor; Windows enables 4688 auditing; detection is woken by ingest and sees process lineage. Already fixed in the same pass: APM batches dropped queries, errors, metrics, jobs and N+1 sections; OTLP attribute values were cut at 4 KiB; the APM route cap never reset; `PUT /api/v1/rules/settings` without `enabled` disabled the rule; the Linux unit's sandbox made live response and response actions read-only; SAST deduplication merged findings across repositories. Code (November 2026): GitHub sync and SAST list only the connector's own repositories; the `organization` webhook is handled; Azure DevOps honours `base_url` and `project` and its audit events reach the rules (new DEV-022); GitLab lists are paged, paths encoded and audit entries parsed from `details`; re-saving keeps the webhook secret; deleting a connector removes its posture result; CodeQL severity uses `security-severity` then the SARIF level; the job lock includes the query; the Code overview reads the latest SAST row of every repository; the base URL check also runs on the resolved address; each webhook route checks the connector type and the UI shows the right URL; DEV-005 and DEV-007 match what their names say; DevOps events go through one detection path with a per-repository key; the code-scan dedup key includes the repository.

## Endpoint

- FIM hashes only the first 10 MiB of a file.
- The install-key marker file stops an upgraded agent from registering a new key, and the server's `SetInstallKey` does not replace an existing key.
- macOS `config_change` events have a type no rule matches.
- The network probe's dependencies are commented out in the management Dockerfile.
- Windows and macOS uninstall leave files behind.
- Windows logon events (4624, 4625, 4648 and similar) take the user from `SubjectUserName` before `TargetUserName` (`agents/windows/internal/collector/eventlog.go`, about line 335). For a logon, the subject is usually the machine account or the calling service, so `user:` searches and user-based rules see that account rather than the user who logged on.
- Installing the Windows agent overwrites an existing Sysmon configuration.
- Analysts can edit alert rules and suppressions (should be admin only).
- The tamper-lock toggle in the UI has no effect.
- The Linux agent ignores `rate_limit.enabled`.
- Backend `GET /api/v1/events`, `/agents` and `/metrics` cannot be used: they need an agent certificate and then refuse it.

## Application monitoring

- `backend/internal/api/app_batch.go` and `app_agentconfig.go` still refuse (403) when `agent_id` differs from the certificate, unlike event ingest, which re-attributes. Low impact: agents send the certificate's id.
- The retention purge in management runs against the management database, so it fails when `backend_db` is a separate database (the bundled compose uses one).
- `/api/v1/app/agent-config` sends every service's settings and reviewed field names to every agent.
- Builder-built agents cannot set the sensor's `watch_dirs` or `secret_files`.
- Migrations 064 and 066 both add `db_statement_mode` (harmless: `IF NOT EXISTS`).

## Cloud

- `store/cloud_connectors.go`: a second AWS connector saved without an account id overwrites the first one's credentials.
- `pages/cloud/connectors.jsx`: AWS results do not show on Overview unless an account id was entered.
- `cloud_gcp_logs.go`: GKE audit and policy-denied events reuse ids from the main audit pull and are dropped, so C-GCP-042/043/044 and C-GCP-PLC-001 rarely fire.
- `cloud_azure_correlation.go`: correlation and baselines look only at the last 2 minutes, but Azure logs arrive later. CORR-AZ-004 is listed but not implemented; CORR-AZ-006 does not check that the location is new.
- Azure Defender alerts and resource logs are stored under ids the Event Timeline does not query.
- `cloud_azure_suppress.go`: suppression is applied after counting; subscription- or resource-scoped rules fail on multi-subscription results.
- `cloud_azure_cspm.go`: `DefenderEnabled` is never set, so the UI always shows "Free tier".
- `cloud_azure_cis.go`: controls 1.4, 1.6, 3.2, 3.3 and 7.3 check a different setting than their titles; 8.1 and 8.2 pass when keys or secrets cannot be read.
- `cloud_aws_cis.go`: STO-06 matches "is public", so a public RDS instance fails it too.
- `cloud_aws.go`: Test Connection signs the global STS call with the connector's region.
- AWS bucket checks are signed for us-east-1; buckets elsewhere may be skipped silently.
- `cloud_sigs.go`: C-AWS-014 cannot fire; C-AWS-031 matches "tor" inside words like "storage"; C-RECON-001 has no burst threshold and fires on our own scans.
- `cloud_gcp_cis.go`: the single-project score counts UNKNOWN and NOT_APPLICABLE as failures.
- Manual AWS scans time out after 3 minutes and do not refresh compliance, inventory or new-critical alerts.
- Sync, scans and Azure/GCP suppression rules are not limited to admins (AWS suppression is).
- GCP org-policy 403/404 responses are skipped instead of marked not assessed.
- A GCP connector with project `*` runs scheduled inventory against the literal project `*`.
- Disconnecting a connector leaves its scan, CIS, compliance, inventory and blast-radius results.
- The GCP Terraform does not grant `roles/browser`, which project discovery needs.
- Azure NSG flow logs are not ingested.
- `CSPMDashboard` and `CloudEventsAlerts` are unused frontend components.

## Codebase

- The **Code Scan** tab still reads the redacted and truncated stored patches. The SAST scan now covers secrets over the full history of a cloned branch, so prefer it; the Code Scan tab is kept for connectors where cloning is not possible.
- Runtime reachability comes from Linux agents only; Windows and macOS agents do not report runtime inventories yet. Pure Python and JavaScript modules can only be shown as deployed, not loaded, and APM stack traces are not yet used as evidence of execution.
- SAST runs scanners in the management container, as the same user, with its network access (no separate sandbox).
