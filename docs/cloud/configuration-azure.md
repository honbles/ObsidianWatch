# Azure connector: configuration

This page covers how to create the Entra app registration for ObsidianWatch, the roles and API permissions it needs, what each connector field does, and how to check and troubleshoot the connection. See [deployment.md](deployment.md) for the shared setup and [capability-azure.md](capability-azure.md) for what is collected.

> Not verified against a real Azure tenant. The roles and Graph permissions below are derived from the endpoints the code calls.

*Implemented in:* `internal/api/cloud_azure.go`, `cloud_azure_logs.go`, `cloud_azure_resource_logs.go`, `cloud_azure_cspm*.go`, `cloud_azure_cis*.go`, `cloud_azure_assets.go`, `cloud_azure_blast_radius.go`; UI `pages/cloud/shared.jsx` (`PROVIDERS.azure`).

## 1. Credential model

The connector authenticates as an **Entra ID app registration** using the client-credentials flow (tenant ID, client ID, client secret). It requests tokens from `login.microsoftonline.com/<tenant>/oauth2/token` for three resources:

- `https://management.azure.com/` (ARM)
- `https://graph.microsoft.com/` (Entra logs and policies)
- `https://api.loganalytics.io/` (only if workspace IDs are set)

Certificates and managed identity are not supported.

## 2. Create the app registration

1. **Entra ID → App registrations → New registration.** Single tenant. No redirect URI.
2. **Certificates & secrets → New client secret.** Copy the value. You cannot see it again.
3. **API permissions → Add a permission → Microsoft Graph → Application permissions.** Add the permissions below, then click **Grant admin consent**.
4. On **each subscription** to monitor: **Access control (IAM) → Add role assignment** for the app (roles below).
5. Optional: on each Log Analytics workspace that receives diagnostic logs, assign **Log Analytics Reader**.

### Azure RBAC roles (per subscription)

| Role | Needed for |
|---|---|
| **Reader** | Activity Log, all ARM reads used by CSPM, CIS, Resource Graph inventory and blast radius, Defender alerts and pricing reads |
| **Security Reader** | Recommended for Defender for Cloud alerts and plans (`Microsoft.Security/*`). The UI hint for the `defender` check says "Security Reader role". |
| Monitoring Reader | Listed in the README. Reader already includes the Activity Log read used here. |
| **Log Analytics Reader** (on the workspace) | Resource logs (Key Vault, AKS, Firewall, App Service) |

### Microsoft Graph application permissions

| Permission | Endpoints that need it |
|---|---|
| `AuditLog.Read.All` | `auditLogs/signIns` (v1.0 and beta), `auditLogs/directoryAudits` |
| `Directory.Read.All` | `users` (guest-user checks). The scan's not-assessed reason names this permission. Sign-in log reads usually also require it. |
| `Policy.Read.All` | `identity/conditionalAccess/policies`, `policies/authorizationPolicy`, `policies/identitySecurityDefaultsEnforcementPolicy` |

Sign-in logs need an **Entra ID P1 or P2** licence. Without it the source is recorded as `license_missing`.

## 3. Connector fields

| Field (UI label) | Key | Required | Effect |
|---|---|---|---|
| Tenant ID | `tenant_id` | Yes | Token endpoint tenant |
| Client ID | `client_id` | Yes | App (client) ID |
| Client Secret | `client_secret` | Yes | Encrypted at rest. Masked in the UI. |
| Subscription ID(s) | `subscription_id` | Yes | One ID, a comma list, or `*` for every subscription the app can read with state `Enabled`. This text is also the connector key (`account_id`). |
| Log Analytics workspace ID(s) (optional) | `workspace_id` | No | One or more workspace GUIDs, separated by commas, spaces, `;` or newlines. Enables resource-log ingestion. |

### How subscription scoping works

| Feature | Subscriptions used |
|---|---|
| Activity Log ingestion | Every resolved subscription. One failing subscription marks the source `partial`. All failing makes the sync an error. |
| Defender for Cloud alerts | Every resolved subscription |
| Entra sign-ins and directory audit | Tenant-wide (not per subscription) |
| CSPM scan | Every resolved subscription, at most **25** per run (4-minute timeout each). The rest are listed in errors. |
| CIS benchmark | Every resolved subscription (merged, controls prefixed by subscription) |
| Asset inventory | Every resolved subscription, at most **100** |
| Blast radius | Every resolved subscription, at most **10** per run |
| Test Connection | Only the **first** subscription in the list. With `*`, the subscription ID is empty and the test requests `/subscriptions/?api-version=…`. Whether that proves access is not verified, so test with an explicit ID. |

When several subscriptions are scanned, the merged CSPM result shows `"<first-sub> (+N more)"` as its subscription. Each finding's resource is prefixed with `<subscription> / `.

## 4. Verification

1. Click **Test Connection**. It checks the token and read access to the first subscription.
2. Save and click **Sync now**. The status should become `connected`.
3. **Event Timeline** tab: `cloud.azure_activity` events (first run: last 24 hours), `cloud.entra_signin`, `cloud.entra_audit`. Defender alerts and resource logs are ingested but do **not** appear in this tab (see capability page). Use **Search** with `event_type:cloud.azure_defender` or `cloud.azure_resource`.
4. **Overview → Run Scan.** Expand "N checks failed" to see checks that did not run. The UI shows a role hint for known check names (for example `entra` → `AuditLog.Read.All + Policy.Read.All`).
5. **CIS Benchmark → Run Assessment.** Controls that need Graph show `UNKNOWN` with the reason if Graph is not consented.
6. Optional: `GET /api/v1/cloud-connectors/{id}/sources` shows `azure_activity`, `entra_signins`, `entra_signins_sp`, `entra_audit`, `defender_alerts`, `azure_resource_logs`, `network_flow_logs` states.

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "missing Azure credentials (tenant_id, client_id, client_secret, subscription_id required)" | Empty field | Fill in all four |
| "Azure auth: … invalid_client" | Wrong or expired secret. Not retried (auth error). | Create a new secret and save again |
| "subscription access denied (403)" on test | App lacks Reader on that subscription | Assign Reader |
| `entra_signins` = `license_missing` | Tenant has no P1/P2 | Licence the tenant, or accept no sign-in data |
| `entra_*` = `permission_missing` | Graph permission missing or admin consent not granted | Grant consent |
| `defender_alerts` = `permission_missing` | 403/404 on `Microsoft.Security/alerts` | Assign Security Reader. Defender may not be enabled. |
| `azure_resource_logs` error | App lacks Log Analytics Reader, wrong workspace GUID, or the workspace has no `AzureDiagnostics` table | Fix the role or ID. Route diagnostic settings to the workspace in Azure Diagnostics mode. |
| `network_flow_logs` = `not_enabled` | Always set. NSG and VNet flow data is not ingested. | Expected |
| CSPM `not_assessed` "resource provider not present in this subscription" | 404 or "not found" from an optional check (Key Vault, SQL, AKS, …) | Expected if the service is unused |
| CSPM `not_assessed` "permission denied – grant Reader (and Security Reader)" | 403 from an optional check | Assign the roles |
| Defender block on Overview always says "Plans on Free tier" | The code never sets `defender_enabled` | Known UI gap; see capability page |
