# Azure: capability reference

This page describes, end to end, what ObsidianWatch does with an Azure connector: ingestion, normalisation, posture checks, benchmark and compliance mapping, detections, correlation, inventory, blast radius and the console pages. Shared behaviour is in [capability.md](capability.md). Setup is in [configuration-azure.md](configuration-azure.md).

> Derived from source code. Nothing here has been verified against a real Azure tenant.

## 1. Log sources and polling

All sources are pulled by the 5-minute connector sync. Activity Log and Entra sign-ins are pulled in `syncAzure`. The rest are pulled in `syncAzureExtendedLogs`, which runs after it even if `syncAzure` failed.

| Source | API | Scope | Window | Event type | `agent_id` |
|---|---|---|---|---|---|
| Activity Log | ARM `microsoft.insights/eventtypes/management/values` (api 2022-06-01), follows `nextLink`, 200 ms between pages | Each resolved subscription | `eventTimestamp ≥` cursor − 2 min (first run: 24 h). Cursor = newest `eventTimestamp` seen. | `cloud.azure_activity` | `azure-activitylog-<id>` |
| Entra sign-ins (users) | Graph v1.0 `auditLogs/signIns`, 100 per page | Tenant | Same `since` as the Activity Log | `cloud.entra_signin` | `azure-entra-<id>` |
| Entra sign-ins (service principals, managed identities) | Graph **beta** `auditLogs/signIns` filtered on `signInEventTypes` | Tenant | Same | `cloud.entra_signin` | `azure-entra-<id>` |
| Entra directory audit | Graph v1.0 `auditLogs/directoryAudits`, newest first, 200 per page, **at most 2 000 per sync** | Tenant | `last_sync` − 2 min (first run: 10 min) | `cloud.entra_audit` | `azure-entra-audit-<id>` |
| Defender for Cloud alerts | ARM `Microsoft.Security/alerts` (api 2022-01-01). All alerts are listed and filtered on the client by `timeGeneratedUtc > since`. | Each resolved subscription | `last_sync` − 2 min | `cloud.azure_defender` | `azure-defender-<first 8 chars of subscription>` |
| Resource (diagnostic) logs | Log Analytics query API, KQL on `AzureDiagnostics`, **at most 5 000 rows per workspace per sync** | Each `workspace_id` | `last_sync` − 2 min | `cloud.azure_resource` | `azure-resource-log` |
| NSG / VNet flow logs | **Not ingested.** The source status is always set to `not_enabled`. | – | – | – | – |

Activity Log records with an intermediate status (Started, Accepted, In Progress, Updated, Resolved) are dropped. Only final outcomes are stored.

Resource-log KQL keeps only:

- Key Vault `AuditEvent`
- AKS `kube-audit-admin` and `guard`
- Azure Firewall network and application rule logs
- App Service `AppServiceAuditLogs`

*Implemented in:* `cloud_azure.go`, `cloud_azure_logs.go`, `cloud_azure_resource_logs.go`.

## 2. Normalisation

### Activity Log → `cloud.azure_activity`

| Column | Value |
|---|---|
| `id` | `<event id>-<yyyymmddhhmmss>` |
| `host` | `<first 8 chars of subscription>/<resource group>` (else `azure`) |
| `user_name` | `caller` |
| `src_ip` | `httpRequest.clientIpAddress` |
| `raw` | `operation_name`, `event_name`, `category`, `status`, `level`, `resource_id`, `resource_group`, `subscription_id`, `resource_provider`, `caller`, `correlation_id`, `description`, `http_request`, `properties` |

Severity starts from the Azure level: Critical → 5, Error → 4, Warning → 3, Informational or Verbose → 1. It is raised to 4 for these operations:

- `roleAssignments/write`, `roleDefinitions/write`
- Key Vault delete, secret write
- NSG write
- VM, storage account and SQL server delete
- `Microsoft.AAD/users/delete`, `strongAuthenticationMethods/delete`

A `Failed` status gives at least 3.

### Entra sign-in → `cloud.entra_signin`

`host` = lower-case UPN, or `sp:<service principal name>` for service-principal sign-ins. `user_name` = UPN. `src_ip` = IP address.

Severity: 1 by default, 3 if the error code ≠ 0, raised to the risk level (high → 4, medium → 3), and 4 if the risk state is `atRisk` or `confirmedCompromised`.

`raw` includes app, client app, Conditional Access status and applied policies, status, location, risk, device, MFA detail, interactive flag, authentication requirement, sign-in kind and service-principal ID.

### Entra audit → `cloud.entra_audit`

`host` = `azure-ad`. `user_name` = initiating UPN or app name. `src_ip` = initiator IP.

Severity: 4 for these activities, 3 for any result = `failure`, 1 otherwise:

- Add/remove member to role, add/delete user, reset user password
- Update/delete conditional access policy
- Add application, add service principal credentials, add owner to application
- Update authorization policy, set federation settings on domain

### Defender alert → `cloud.azure_defender`

`id` = `<alert id>-<time>`. `host` = compromised entity. `raw` includes the alert type, display name, description, severity, status, intent, first MITRE technique, remediation steps, resource ID and extended properties. Severity: Fatal → 5, High → 4, Medium → 3, Low → 1 (default 3).

### Resource log → `cloud.azure_resource`

`id` = `azres-` + hash of the row's key fields. `host` = last segment of the resource ID. `user_name` = UPN claim or app ID.

Severity: 3 when the result contains forbidden, unauthorized, denied, 401 or 403, and for every AKS `guard` row. Otherwise 1. Free-text columns are cut to 4 000 characters.

## 3. Posture checks (CSPM)

The scan runs at startup, every 6 hours, and on **Run Scan**. It covers each resolved subscription, at most 25, each with a 4-minute timeout.

- Core checks (`iam`, `network`, `storage`, `compute`, `logging`): any error is shown in `errors` and in `not_assessed`.
- Optional checks: 403 or 404 errors become `not_assessed` with the reason "permission denied – grant Reader (and Security Reader)" or "resource provider not present in this subscription".
- Finding IDs are `az-` + hash(subscription, title, resource).

| Check key | Finding title (pattern) | Severity | Category / resource type | CIS section shown in UI |
|---|---|---|---|---|
| iam | Guest user has 'Owner'/'Contributor' role at subscription scope | critical | iam / role_assignment | 1.x Identity & Access |
| iam | Service principal has permanent Owner role at subscription scope | critical (Owner) | iam / role_assignment | 1.x |
| iam | Classic administrator account detected: X | high | iam / classic_admin | 1.x |
| network | NSG 'N' rule 'R' allows ALL inbound traffic from internet | critical | network / nsg | 6.x Networking |
| network | NSG 'N' exposes SVC (port P) to internet | critical (22, 3389), high (23, 3306, 5432, 1433, 27017, 6379, 9200) | network / nsg | 6.x |
| network | Application Gateway 'G' does not have WAF enabled | high | network / application_gateway | – |
| storage | Storage account 'S' allows public blob access | high | storage / storage_account | 3.x Storage Accounts |
| storage | Storage account 'S' allows HTTP traffic | high | storage / storage_account | 3.x |
| storage | Storage account 'S' allows TLS 1.0/1.1 | medium | storage / storage_account | 3.x |
| storage | Storage account 'S' network firewall allows all networks | medium | storage / storage_account | 3.x |
| storage | Storage account 'S' allows shared key authentication | medium | storage / storage_account | 3.x |
| compute | VM 'V' OS disk is not encrypted | high | compute / virtual_machine | 7.x Virtual Machines |
| compute | VM 'V' does not have Trusted Launch (Secure Boot + vTPM) enabled | medium | compute / virtual_machine | 7.x |
| compute | Linux VM 'V' allows password authentication | high | compute / virtual_machine | 7.x |
| keyvault | Key Vault 'K' does not have soft delete enabled | high | kms / key_vault | 8.x Key Vault |
| keyvault | Key Vault 'K' does not have purge protection enabled | medium | kms / key_vault | 8.x |
| keyvault | Key Vault 'K' is accessible from public internet | medium | kms / key_vault | 8.x |
| keyvault | Key Vault 'K' uses legacy access policies instead of RBAC | low | kms / key_vault | 8.x |
| sql | SQL Server 'S' has public network access enabled | high | sql / sql_server | 4.x Database |
| sql | SQL Server 'S' allows TLS below 1.2 | medium | sql / sql_server | 4.x |
| sql | SQL database 'S/D' has TDE (Transparent Data Encryption) disabled | high | sql / sql_database | 4.x |
| aks | AKS cluster 'C' has Kubernetes RBAC disabled | critical | compute / aks_cluster | 5.x Containers |
| aks | AKS cluster 'C' API server is publicly accessible without IP restrictions | high | compute / aks_cluster | 5.x |
| aks | AKS cluster 'C' has no Kubernetes network policy configured | medium | compute / aks_cluster | 5.x |
| aks | AKS cluster 'C' does not use Workload Identity | medium | compute / aks_cluster | 5.x |
| logging | Subscription has no diagnostic settings configured | critical | logging / subscription | – |
| logging | Diagnostic setting 'D' does not capture 'Administrative'/'Security'/'Alert'/'Policy' logs | high | logging / diagnostic_setting | 5.x Logging |
| logging | No Activity Log alert rules configured | high | logging / subscription | – |
| defender | Microsoft Defender for Cloud: 'P' plan is on Free tier | medium | compute / defender_plan | 2.x Defender |
| entra | No enabled Conditional Access policies found | critical | iam / entra_tenant | 1.x Conditional Access |
| entra | No Conditional Access policy enforces MFA for all users | high | iam / entra_tenant | 1.x |
| entra | Guest user invitations are not restricted to admins only | medium | iam / entra_tenant | 1.x |
| app_service | App Service 'A' does not enforce HTTPS | high | compute / app_service | 9.x App Service |
| app_service | App Service 'A' allows TLS below 1.2 | medium | compute / app_service | 9.x |
| app_service | App Service 'A' allows FTP (plaintext) | high | compute / app_service | 9.x |
| app_service | App Service 'A' has remote debugging enabled | critical | compute / app_service | 9.x |
| app_service | App Service 'A' has no authentication configured | high | iam / app_service | 9.x |
| container_registry | Container Registry 'R' has admin user enabled | high | iam / container_registry | 5.x Containers |
| container_registry | Container Registry 'R' is publicly accessible from internet | medium | network / container_registry | 5.x |
| container_registry | Container Registry 'R' (Premium) has no customer-managed encryption | low | kms / container_registry | 5.x |
| functions | Function App 'F' does not enforce HTTPS | high | compute / function_app | 9.x |
| functions | Function App 'F' has remote debugging enabled | high | compute / function_app | 9.x |
| functions | Function App 'F' has no authentication configured | medium | iam / function_app | 9.x |
| sql_advanced | SQL Server 'S' has auditing disabled | high | logging / sql_server | 4.x |
| sql_advanced | SQL Server 'S' audit log retention is below 90 days (N days) | medium | logging / sql_server | 4.x |
| sql_advanced | SQL Server 'S' has Advanced Threat Protection disabled | high | sql / sql_server | 4.x |

The "CIS section shown in UI" column comes from a fixed resource-type map in `shared.jsx` (hover text in the **Findings** table, "Benchmark" row on the finding page). It is not a verified CIS mapping.

NSG port matching compares exact single-port strings, such as `"22"`. A rule with a range such as `20-25` or `*`-like port lists other than `*` and `0-65535` is not flagged by this CSPM check. The CIS check (6.1 and 6.2) evaluates ranges.

**Suppression.** Azure rules mark matching findings `suppressed` **after** the counts are calculated. Suppressed findings are therefore still included in `critical`, `high`, … and `total_findings`, in the Overview tiles and risk gauge, and in the new-critical comparison input. The Posture page recomputes its counts from open findings only. When several subscriptions are scanned, the merged result's subscription is `"<sub> (+N more)"` and each resource is prefixed with `<sub> / `. Subscription-scoped and resource-prefix rules therefore do not match merged results.

*Implemented in:* `cloud_azure_cspm.go`, `cloud_azure_cspm_multi.go`, `cloud_azure_suppress.go`.

## 4. CIS benchmark

**Run Assessment** only; Azure CIS is not scheduled. The benchmark is labelled "ObsidianWatch Azure checks (inspired by CIS Azure Foundations v2.0; control IDs are internal)". Each control calls the API itself; it does not reuse the CSPM result. Controls that need Graph are UNKNOWN when there is no Graph token. With several subscriptions, the results are merged and each title is prefixed with `[<subscription>]`.

| ID | Section | Title | Level | What the code actually evaluates |
|---|---|---|---|---|
| 1.1 | IAM | MFA enabled for all privileged users | 1 | An enabled CA policy requiring MFA for all users or directory roles |
| 1.2 | IAM | MFA enabled for all non-privileged users | 2 | Security Defaults on, or a CA policy requiring MFA for all users on all apps |
| 1.3 | IAM | Guest users are reviewed at least monthly | 1 | FAIL if any guest user exists |
| 1.4 | IAM | 'Allow users to remember MFA' is disabled | 1 | **Guest invitation setting** (`authorizationPolicy.allowInvitesFrom`) |
| 1.5 | IAM | No custom subscription owner roles are created | 1 | Custom role definitions with wildcard `*` actions |
| 1.6 | IAM | 'Restrict access to Azure AD administration portal' is Yes | 1 | **Whether users can register applications** (`authorizationPolicy`) |
| 2.1–2.5 | Defender | Defender for Servers / App Services / SQL Servers / Storage / Key Vault is On | 1 | Pricing tier of `VirtualMachines`, `AppServices`, `SqlServers`, `StorageAccounts`, `KeyVaults` ≠ Free |
| 3.1 | Storage | 'Secure transfer required' is Enabled | 1 | `supportsHttpsTrafficOnly` on every storage account |
| 3.2 | Storage | Storage account access keys are periodically regenerated | 1 | **Shared key access allowed** |
| 3.3 | Storage | Storage logging for Queue service | 2 | **A subscription diagnostic setting exists** |
| 3.4 | Storage | Storage account public access is disallowed | 1 | `allowBlobPublicAccess` |
| 4.1 | Database | 'Auditing' is On for SQL Servers | 1 | Server auditing settings |
| 4.2 | Database | Advanced Threat Protection is Enabled | 2 | Server ATP settings |
| 4.3 | Database | TDE protector is Customer-managed key | 2 | Server encryption protector type |
| 5.1 | Logging | A Diagnostic Setting exists for the subscription | 1 | Subscription diagnostic settings |
| 5.2 | Logging | Activity log retention ≥ 1 year | 1 | Retention on diagnostic settings |
| 5.3 | Logging | Audit profile captures all activities | 1 | Categories on diagnostic settings |
| 5.4 | Logging | Activity log alert for Create Policy Assignment | 1 | Activity log alerts |
| 5.5 | Logging | Activity log alert for Create or Update NSG | 1 | Activity log alerts |
| 5.6 | Logging | Activity log alert for Create or Update Security Solution | 1 | Count of enabled activity log alerts |
| 6.1 / 6.2 | Networking | RDP / SSH access from the internet is restricted | 1 | NSG inbound allow from an internet source covering 3389 / 22 (ranges evaluated) |
| 6.3 | Networking | Network Watcher is enabled | 1 | Any network watcher |
| 7.1 | VMs | OS disks encrypted with CMK | 2 | VM OS disk encryption set |
| 7.2 | VMs | Unattached disks encrypted with CMK | 2 | Unattached managed disks |
| 7.3 | VMs | Endpoint protection installed on VMs | 1 | **Defender for Servers plan** (not the VM extension) |
| 8.1 / 8.2 | KeyVault | Expiration date set on all keys / secrets in RBAC Key Vaults | 1 | ARM list of keys and secrets in RBAC-mode vaults |
| 8.3 | KeyVault | Key Vault is recoverable (soft delete + purge protection) | 1 | Vault properties |

Score = passed ÷ (passed + failed), plus Level 1 and Level 2 scores. The CIS tab's section filter buttons are fixed to GCP-style names (IAM, Logging, Networking, VM, Storage, CloudSQL). The per-section score tiles use the real Azure section names.

Accuracy notes:

- Controls 1.4, 1.6, 3.2, 3.3 and 7.3 evaluate a different setting from the one their title names (see the last column).
- 8.1 and 8.2 skip any vault whose key or secret list cannot be read and still report PASS ("Checked N RBAC Key Vault(s)").

*Implemented in:* `cloud_azure_cis.go`, `cloud_azure_cis_checks.go`, `cloud_cis_multi.go`.

## 5. Compliance mapping

A compliance report is generated after each scheduled CSPM scan and by **Remap Compliance**. It uses the shared category and resource-type catalogue (`MapToCompliance`) over the Azure CSPM findings. Suppressed findings are ignored.

Azure check keys map to finding categories and resource types for the NOT_ASSESSED logic:

| Check key | Categories and resource types |
|---|---|
| network | network, nsg |
| logging | logging, diagnostic_setting |
| keyvault | kms, key_vault |
| aks | aks_cluster |
| defender | defender_plan |
| app_service | app_service |
| container_registry | container_registry |
| functions | function_app |
| sql_advanced | sql, sql_server, sql_database |
| entra | entra_tenant |

The 35 controls (SOC2, PCI-DSS, ISO27001, NIST-800-53) and their category and resource-type rules are listed in [capability-gcp.md §5](capability-gcp.md#5-compliance-mapping). Azure uses the same table. Controls keyed only on GCP resource types, such as `artifact_registry`, `gke_cluster`, `cloud_sql` or `log_sink`, can only PASS or be NOT_ASSESSED for Azure.

When several subscriptions are scanned, `not_assessed` entries are prefixed with the subscription (`"<sub>: <check>"`). They then no longer match the check-key table, so skipped checks in merged results do not make controls NOT_ASSESSED.

## 6. Detections on Azure events

Azure rule sets run on events with `os = azure`. Rules marked "raw text" search the whole lower-cased raw JSON. The Activity Log outcome gate applies: a `Failed` operation triggers only rules whose name contains fail, denied, brute or unauthor.

### 6.1 Activity Log rules

| ID | Name | Sev | MITRE | Triggers on |
|---|---|---|---|---|
| C-AZ-IAM-001 | Azure PIM Privileged Role Activated | 3 | T1548 | PIM role assignment or eligibility requests written or activated |
| C-AZ-IAM-002 | Azure Global Administrator Role Assigned | 5 | T1098.003 | Role assignment or "add member to role" + Global Administrator name or role ID (also Entra audit) |
| C-AZ-IAM-003 | Azure Service Principal Password/Certificate Added | 5 | T1098.001 | Service principal credentials write, addPassword, addKey (also Entra audit) |
| C-AZ-IAM-004 | Entra Conditional Access Policy Deleted or Disabled | 5 | T1556 | CA policy op + delete, disabled or report-only (also Entra audit) |
| C-AZ-IAM-005 | Azure AD Application Created with Wide Permissions | 3 | T1550.001 | Application create or write (also Entra audit). Permissions are not checked. |
| C-AZ-IAM-006 | Azure AD User Created Outside Business Hours | 3 | T1136.003 | User create between 22:00 and 06:00 UTC |
| C-AZ-IAM-007 | Azure Subscription Owner Role Assigned | 5 | T1098.003 | `roleAssignments/write` + "owner" + "subscriptions/" |
| C-AZ-IAM-008 | Azure AD Tenant-Wide Federation Settings Modified | 5 | T1606.002 | Domain federation changes |
| C-AZ-IAM-009 | MFA Disabled for Azure AD User | 4 | T1556.006 | strongAuthenticationMethods or MFA registration + delete or disable |
| C-AZ-IAM-010 | Azure Managed Identity Assigned to High-Privilege Role | 4 | T1548.005 | Role assignment + managed identity + owner or contributor |
| C-AZ-IAM-011 | Azure AD Guest Invited with Admin Role | 4 | T1136.003 | Guest invitation + admin, owner, contributor or operator |
| C-AZ-IAM-012 | Azure RBAC Custom Role with * Permission Created | 4 | T1078.004 | `roleDefinitions/write` + any `"*"` in raw text |
| C-AZ-IAM-013 | Entra ID Break-Glass Account Used | 4 | T1078.004 | Raw text breakglass, break-glass, emergency + signin, login or authentication |
| C-AZ-IAM-014 | Azure AD Authorization Policy Modified | 4 | T1556 | Authorization policy, default user permissions |
| C-AZ-IAM-015 | Azure Security Defaults Disabled | 5 | T1556 | Security defaults policy + disabled or false |
| C-AZ-COMP-001 | Azure VM Custom Script Extension Executed | 4 | T1059 | VM extension write, custom script, run command |
| C-AZ-COMP-002 | Azure VM Disk Snapshot Exported to SAS URL | 4 | T1537 | Disk or snapshot `beginGetAccess`, grantaccess |
| C-AZ-COMP-003 | AKS kubectl exec into Running Pod | 3 | T1609 | pods/exec in Activity Log |
| C-AZ-COMP-004 | AKS ClusterRoleBinding Grants cluster-admin | 5 | T1548 | clusterrolebindings + cluster-admin + create or write |
| C-AZ-COMP-005 | Azure Container Registry Admin Account Enabled | 3 | T1552.001 | Registry write + adminUserEnabled |
| C-AZ-COMP-006 | Azure Automation Runbook Created or Modified | 3 | T1053.005 | Runbook write or draft write |
| C-AZ-COMP-007 | Azure Function App with Managed Identity Modified | 3 | T1525 | `Microsoft.Web/sites/write` + identity |
| C-AZ-COMP-008 | Azure Logic App Workflow with HTTP Action Created | 3 | T1537 | Workflow write + http or webhook |
| C-AZ-COMP-009 | Azure VM High-Performance Size Launched | 3 | T1496 | VM write + NV, NC, ND, HB, HC, H sizes |
| C-AZ-COMP-010 | Azure Compute Quota Increase Requested | 2 | T1496 | Support ticket + quota, cores, vcpu |
| C-AZ-DATA-001 | Azure Storage Account SAS Token with Full Permissions | 4 | T1530 | listSas / listSasToken |
| C-AZ-DATA-002 | Azure Key Vault Secret Bulk Accessed | 4 | T1552.001 | Secret read or list with event severity ≥ 3 |
| C-AZ-DATA-003 | Azure Key Vault Key Deleted or Purged | 5 | T1485 | Key delete or purge |
| C-AZ-DATA-004 | Azure SQL Database Exported to Storage | 4 | T1537 | Database export, bacpac |
| C-AZ-DATA-005 | Azure Cosmos DB Firewall Disabled | 4 | T1190 | Cosmos account write + public network enabled or empty IP filter |
| C-AZ-DATA-006 | Azure Blob Container Set to Public Access | 5 | T1530 | Blob container or service write without `publicAccess: none` |
| C-AZ-DATA-007 | Azure Storage Account Access Key Regenerated | 2 | T1098.001 | regenerateKey, listKeys |
| C-AZ-DATA-008 | Azure SQL Auditing Disabled | 4 | T1562.008 | Auditing settings write + disabled or none |
| C-AZ-DATA-009 | Azure Data Factory Pipeline with Copy to External Sink | 3 | T1537 | ADF pipeline write + copy, sink or linkedservice |
| C-AZ-DATA-010 | Azure Backup Vault Soft Delete Disabled | 5 | T1490 | Recovery Services or backup config + soft delete |
| C-AZ-NET-001 | Azure Firewall Policy Deleted | 5 | T1562.007 | Firewall or firewall-policy delete, **or any** `microsoft.network/azurefirewalls` operation |
| C-AZ-NET-002 | Azure DDoS Protection Plan Removed | 3 | T1562.001 | DDoS plan delete or protection disabled |
| C-AZ-NET-003 | Azure Private DNS Zone Modified | 4 | T1584.002 | Private DNS A, CNAME, NS, MX writes |
| C-AZ-NET-004 | Azure VPN Gateway Connection Modified | 3 | T1572 | VPN, VNet and local gateway writes |
| C-AZ-NET-005 | Azure Front Door WAF Policy Disabled or Bypassed | 4 | T1562.007 | Front Door or WAF + detection or disabled |
| C-AZ-NET-006 | Azure Private Endpoint Deleted | 3 | T1562.007 | Private endpoint delete, **or any** private-endpoint operation |
| C-AZ-NET-007 | Azure ExpressRoute Circuit Modified | 3 | T1557 | Circuit or peering write or delete |
| C-AZ-NET-008 | Azure NSG Rule Added to Allow Internet Inbound | 4 | T1190 | NSG or rule write + 0.0.0.0/0, internet or ::/0 + inbound or allow |
| C-AZ-EVA-001 | Azure Monitor Diagnostic Settings Deleted | 5 | T1562.008 | Diagnostic settings delete, **or any** diagnostic-settings operation |
| C-AZ-EVA-002 | Azure Monitor Alert Rule Deleted | 3 | T1562.001 | Alert, metric, scheduled-query and activity-log alert delete |
| C-AZ-EVA-003 | Azure Policy Assignment Deleted | 4 | T1562.001 | Policy assignment delete, **or any** policy-assignment operation |
| C-AZ-EVA-004 | Defender for Cloud Plan Downgraded | 5 | T1562.001 | `Microsoft.Security/pricings/write` + "free" |
| C-AZ-EVA-005 | Azure Activity Log Export Disabled | 4 | T1562.008 | Log profile delete or disable |
| C-AZ-EVA-006 | Azure Resource Lock Removed | 4 | T1485 | Lock delete + CanNotDelete or ReadOnly |
| C-AZ-EVA-007 | Subscription Moved to Different Management Group | 4 | T1562.001 | Management-group subscription write + move |
| C-AZ-EVA-008 | Azure Sentinel Analytics Rule Disabled | 4 | T1562.001 | Sentinel alert rule + disabled |
| C-AZ-006 … C-AZ-030 | (cross-provider set, see table below) | 2–5 | various | Activity Log operations |
| C-RECON-004 | Azure Subscription and Resource Enumeration | 2 | T1526 | Any resource, resource-group or role-definition read in the Activity Log |
| C-LAT-004 | Azure VM Run Command Executed | 4 | T1021.006 | Run command or extension write + script names |

`cloudSignaturesExtended` rules for Azure:

| ID | Name | Sev | Triggers on |
|---|---|---|---|
| C-AZ-006 | Azure Blob Storage Container Made Public | 4 | Operation blobContainers or blobServices write |
| C-AZ-007 | Azure Storage Account Firewall Disabled | 4 | storageAccounts write + allowBlobPublicAccess true or defaultAction Allow |
| C-AZ-008 | Azure Storage SAS Token with Full Access | 3 | listSas |
| C-AZ-009 | Azure Storage Account Encryption Disabled | 3 | requireInfrastructureEncryption false |
| C-AZ-010 | Azure AD User Created | 2 | Operation `Microsoft.AAD/users/write`, `Microsoft.Directory/users/create` |
| C-AZ-011 | Azure AD User MFA Disabled | 4 | MFA methods + delete or disable |
| C-AZ-012 | Azure AD Application Created | 3 | Application write or create |
| C-AZ-013 | Azure Service Principal Credentials Added | 4 | SP credentials write |
| C-AZ-014 | Entra ID Conditional Access Policy Disabled | 4 | CA policies + delete or disabled |
| C-AZ-015 | Entra ID Guest Account Added | 2 | Invitations |
| C-AZ-016 | Azure Firewall Deleted | 5 | Firewall delete |
| C-AZ-017 | Azure DDoS Protection Disabled | 3 | DDoS plan delete |
| C-AZ-018 | Azure VPN Gateway Configuration Changed | 3 | Gateway write |
| C-AZ-019 | Azure Public IP Allocated | 2 | `publicIPAddresses/write` |
| C-AZ-020 | Azure VM Extension Installed | 3 | Extension write |
| C-AZ-021 | Azure Disk Snapshot Exported | 3 | Snapshot write or beginGetAccess |
| C-AZ-022 | Azure Automation Runbook Created | 3 | Runbook write |
| C-AZ-023 | Azure Diagnostic Settings Deleted | 4 | Diagnostic settings delete |
| C-AZ-024 | Azure Monitor Alert Rule Deleted | 3 | Alert or metric-alert delete |
| C-AZ-025 | Azure Policy Assignment Deleted | 3 | Policy assignment delete |
| C-AZ-026 | Azure SQL Database Firewall Rule Modified | 3 | firewallRules write + sql or servers |
| C-AZ-027 | Azure Subscription Ownership Transferred | 5 | Role assignment write + owner or subscriptions/ |
| C-AZ-028 | Azure Defender for Cloud Alert | 4 | Activity Log security-alert record, severity ≥ 3 |
| C-AZ-029 | Azure Logic App Workflow Modified | 3 | Workflow write, logicapps |
| C-AZ-030 | Azure Container Registry Image Pushed | 2 | containerregistry or repositories/write |

Several rules overlap. For example, C-AZ-023, C-AZ-EVA-001 and C-XCLOUD-003 all fire on one diagnostic-settings delete. They have different titles, so they produce separate alerts.

Entra operations such as `Microsoft.AAD/users/write` are matched against `cloud.azure_activity` events. Most Entra directory changes appear in the Entra audit log, not in the ARM Activity Log. Rules limited to `cloud.azure_activity` may therefore rarely fire for them (not verified).

### 6.2 Entra sign-in rules (typed fields)

| ID | Name | Sev | MITRE | Fires when |
|---|---|---|---|---|
| C-AZ-ID-001 | Entra Sign-in Flagged Risky | 4 | T1078.004 | Successful sign-in with risk state `atRisk` or `confirmedCompromised` |
| C-AZ-ID-002 | Entra Legacy Authentication Succeeded | 3 | T1078.004 | Successful sign-in with a legacy client (IMAP, POP, SMTP, EAS, "Other clients", …) |
| C-AZ-ID-003 | Entra Sign-in Bypassed Conditional Access | 2 | T1556 | Successful sign-in with CA status `notApplied` |
| C-AZ-ID-004 | Entra High-Risk Sign-in Blocked or Failed | 3 | T1110 | Failed sign-in with risk level high |
| C-AZ-ID-005 | Entra Service Principal Sign-in With Invalid Credential | 3 | T1078.004 | Service-principal sign-in with error 7000215, 7000222, 7000112 or 700027 |

### 6.3 Entra audit rules

| ID | Name | Sev | Fires when |
|---|---|---|---|
| C-AZ-AUDIT-001 | Entra Audit: High-Impact Admin Operation | 4 | Role membership, password reset, user delete, SP credential or app owner change, with event severity ≥ 3 |
| C-AZ-AUDIT-002 | Entra Audit: Application Consent Granted | 4 | Consent to application, OAuth2 permission grant, admin consent |
| C-AZ-AUDIT-003 | Entra Audit: Group Membership Bulk Change | 3 | Add or remove group member with severity ≥ 3. Group changes are not in the high-impact list, so this fires only on failures. |
| C-AZ-AUDIT-004 | Entra Audit: Named Location or Trusted IP Modified | 4 | Named-location changes |
| C-AZ-AUDIT-005 | Entra Audit: Authentication Method Policy Changed | 4 | Authentication method policy update, write or delete |
| C-AZ-AUDIT-006 | Entra Audit: Privileged Role Permanently Assigned (No PIM) | 4 | "Add member to role" without PIM or eligibility markers |

### 6.4 Defender and resource-log rules

| ID | Name | Sev | Fires when |
|---|---|---|---|
| C-AZ-DEF-001 | Defender: High/Critical Security Alert | 5 | Defender event with severity ≥ 4 |
| C-AZ-DEF-002 | Defender: Cryptomining Detected | 4 | Raw text crypto, mining, miner, xmrig, stratum, bitcoin, monero, coin |
| C-AZ-DEF-003 | Defender: SQL Injection Attack Detected | 4 | SQL injection markers |
| C-AZ-DEF-004 | Defender: Malware Detected on VM | 5 | malware, virus, trojan, ransomware, backdoor, rootkit, exploit |
| C-AZ-DEF-005 | Defender: Brute Force Attack Detected | 3 | Brute-force markers |
| C-AZ-DEF-006 | Defender: Anomalous Azure Resource Deletion | 4 | anomalous, deletion or delete with severity ≥ 3 |
| C-AZ-DEF-007 | Defender: Identity Threat – Suspicious Activity | 4 | Impossible travel, anonymous IP, password spray markers |
| C-AZ-DEF-008 | Defender: Container Escape or AKS Threat | 5 | Container escape, privileged container, kubernetes markers |
| C-AZ-RES-001 | Key Vault: Access Denied | 3 | Vault resource log with result forbidden, unauthorized, 401 or 403 |
| C-AZ-RES-002 | AKS: Anonymous Kubernetes API Access | 4 | Resource log containing `system:anonymous` |

Cross-cloud rules that can match Azure events: C-XCLOUD-002, -003 (`diagnosticsettings/delete`), -005 (`keyvaults/delete`), -006, -007 (`users/write` off-hours), -008 (`microsoft.security`, which matches any Microsoft.Security operation), -009 (`networksecuritygroups/write` off-hours), C-RECON-003, C-NET-001, C-NET-003, C-ABUSE-002.

*Implemented in:* `cloud_azure_sigs.go`, `azure_identity_sigs.go`, `cloud_azure_resource_logs.go`, `cloud_sigs.go`.

### 6.5 Correlation (`CORR-AZ-*`)

State is kept in memory per principal and pruned after 2 hours idle. Alerts have event type `cloud.azure_correlation` and are deduplicated per rule, host, principal and hour.

| ID | Title | Logic |
|---|---|---|
| CORR-AZ-001 | [CORR] Service Principal Credentials Added Then Used from New IP | SP credential added, then activity from a different IP within 10 min |
| CORR-AZ-002 | [CORR] Rapid Privileged Role Assignment Sequence | 3 or more Owner/Contributor role assignments by one principal within 1 h |
| CORR-AZ-003 | [CORR] Audit Logging Disabled Then Sensitive Operation Performed | Diagnostic setting or log profile delete, then role assignment, storage delete, … within 15 min |
| CORR-AZ-005 | [CORR] Mass Azure Resource Deletion | 5 or more delete operations within 5 min |
| CORR-AZ-006 | [CORR] Conditional Access Disabled Then Sign-In from New Location | A CA policy change containing disabled, delete or reportonly, then any Entra sign-in by the same principal within 30 min. Every sign-in record contains a `location` field, so newness of the location is not actually checked. |
| CORR-AZ-007 | [CORR] First-Seen IP Performing Role Assignment | Role assignment within 5 min of the principal's first use of an IP |
| CORR-AZ-008 | [CORR] Service Principal Created Then Immediately Assigned Owner Role | SP created, then Owner assignment within 5 min |

CORR-AZ-004 (GPU VM plus quota increase) is listed in the file header but not implemented.

**Input window.** The engine reads events whose **event time** is in the last 2 minutes, every 30 seconds. Activity Log and Entra records usually arrive several minutes after they happen, and they are pulled only every 5 minutes. Most records are therefore older than 2 minutes when they are stored and are never seen by this engine. The GCP engine uses an ingestion cursor instead. This is a suspected defect (not verified on a live tenant).

### 6.6 Behavioural baseline (`ANOM-AZ-*`)

Learns every 15 minutes from Activity Log and Entra audit events. Detects every 2 minutes, with the same 2-minute event-time window limitation.

| ID | Fires when |
|---|---|
| ANOM-AZ-001 | First-ever source IP for a principal |
| ANOM-AZ-002 | Admin action outside the principal's normal hours |
| ANOM-AZ-003 | Service principal used from more than 3 IPs in 1 hour |

Event type `cloud.azure_anomaly`.

*Implemented in:* `cloud_azure_correlation.go`.

## 7. Asset inventory

Runs on demand (**Asset Graph → Full Inventory**). It is not scheduled. It uses one Azure Resource Graph query per subscription (`Microsoft.ResourceGraph/resources`) and covers at most 100 subscriptions. Results are stored in `assets:azure:<id>` with first-seen and last-seen times.

When a resource of one of these types disappears between two inventories, the alert **"[T1485] Azure Critical Resource Disappeared from Inventory"** is raised (severity 4, once per resource per day, event type `cloud.azure_assets`):

- SQL servers
- Key Vaults
- AKS clusters
- storage accounts
- Recovery Services vaults
- Azure Firewalls
- managed disks
- Cosmos DB accounts

*Implemented in:* `cloud_azure_assets.go`.

## 8. Blast radius

Runs on demand (**Run Analysis**). It covers each resolved subscription, at most 10. It reads role assignments and definitions, VMs, NSGs, storage accounts and Key Vaults, plus the stored CSPM result.

Relationships modelled:

- service principal → role → scope
- VM → managed identity → role assignments
- open NSG → internet → VM
- public storage → internet
- Key Vault without private endpoint → internet

Paths end in `project_owner` (Owner over the subscription) or `all_data`. The summary uses the same four counters as the other providers.

*Implemented in:* `cloud_azure_blast_radius.go`, `cloud_gcp_blast_multi.go` (`RunAzureBlastRadiusForConnector`).

## 9. What the user sees (Azure specifics)

- **Overview**: the Defender block always reads "Plans on Free tier · Upgrade Defender →". `defender_enabled` is never set to true by the scan code. The KPI tiles count suppressed findings (section 3).
- **Event Timeline** queries `azure-activitylog-<id>`, `azure-entra-<id>`, `azure-entra-audit-<id>`, `azure-defender-<id>` and `azure-nsgflow-<id>`. Defender events are stored under `azure-defender-<subscription prefix>` and resource logs under `azure-resource-log`, so **neither appears in this tab**. NSG flow events are not produced. Use **Search** instead.
- **Attack Surface** cards are labelled "Open NSG Rules", "Exposed VMs", "Public Storage", "Exposed Databases".
- **Deep Dive** IAM groups: Public Access / Guest Users, Owner / Contributor Assignments, Classic Administrator Accounts, No Conditional Access / MFA, Service Principal Over-Privileged, Custom Roles with Wildcard, Other IAM Issues.

## 10. Limits

| Item | Limit |
|---|---|
| Subscriptions per CSPM / inventory / blast run | 25 / 100 / 10 |
| Entra audit per sync | 2 000 newest. Older records in the window are lost if there are more. |
| Resource-log rows per workspace per sync | 5 000 oldest first. The window moves on after the sync, so excess rows are lost. |
| ARM pagination in CSPM | 20 pages per list |
| Defender alerts | All pages listed on every sync, then filtered by time |

## 11. Not verified / known gaps

- Nothing here has been checked against a live tenant.
- The Azure correlation and baseline engines use a 2-minute event-time window (section 6.5).
- Defender and resource-log events are not visible in the connector Event Timeline (section 9).
- NSG and VNet flow logs are not ingested. The README lists NSG flow logs as a source.
- `defender_enabled` is never set, so the UI's Defender status is always "Free tier".
- Azure CSPM suppression does not change counts (section 3).
- Several CIS control titles do not match what is evaluated (section 4).
- Defender alerts and Entra audit use `last_sync` − 2 min. `last_sync` also advances on failed syncs.
