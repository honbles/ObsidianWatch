# Cloud monitoring: deployment

This page explains how cloud monitoring is set up and how it runs, end to end. It covers all three supported providers: AWS, Azure and GCP. No other provider is supported. The backend files are `cloud_aws*.go`, `cloud_azure*.go` and `cloud_gcp*.go`. The test endpoint rejects any other provider with `unsupported provider`.

Related pages:

- Provider setup: [configuration-aws.md](configuration-aws.md), [configuration-azure.md](configuration-azure.md), [configuration-gcp.md](configuration-gcp.md)
- What the product does with the data: [capability.md](capability.md), plus one capability page per provider

## 1. Architecture in one paragraph

No agent or collector is deployed into the cloud account. The management server (`management/backend`) calls the provider APIs directly over HTTPS. It uses credentials that you enter in the console. The `CloudConnectorEngine` goroutine pulls logs and findings every 5 minutes and writes them to the `events` table as normal events (`event_type` prefix `cloud.`). The detection engine evaluates those events. Separate background loops run posture scans (CSPM) every 6 hours, behavioural baselines and correlation. They store results in the `settings` table and raise alerts in the `alerts` table.

```
 Cloud provider APIs  <--HTTPS (read-only)--  management server
                                              |- CloudConnectorEngine (sync every 5 min, CSPM every 6 h)
                                              |- DetectionEngine (signatures, every 10 s by default)
                                              |- GCP / Azure correlation engines, GCP / Azure / AWS baselines
                                              v
                                    PostgreSQL: cloud_connectors, events, alerts, settings, cloud_scan_history
```

*Implemented in:* `internal/api/cloud_engine.go`, `internal/api/server.go` (routes), `internal/api/detection_engine.go`.

## 2. Prerequisites on the server

| Requirement | Why | Where |
|---|---|---|
| `OW_SECRET_KEY` (or `OW_SECRET_KEY_FILE`) set | Connector secrets are encrypted at rest with AES-256-GCM. Without a key the server refuses to start unless `OW_ALLOW_PLAINTEXT_SECRETS=true`. | `internal/store/secrets.go` |
| Outbound HTTPS to the provider endpoints (section 7) | All collection is pull-based | provider files |
| An admin account in the console | Creating, testing, deleting connectors and the AWS org import are admin-only | `server.go` (`adminOnly`) |
| Accurate server clock | AWS SigV4 requests fail with a skewed clock. The AWS client learns the skew from the `Date` header and corrects for it. Azure and GCP tokens also depend on time. | `cloud_aws_http.go` |

The key can be a 32-byte base64 value, which is used directly, or any passphrase. A passphrase is stretched with Argon2id using a fixed application salt. **If you lose the key, encrypted credentials cannot be recovered.** You must then re-enter them in the UI. Back the key up separately from the database.

## 3. Creating a connector in the console

1. In the rail, open **Cloud → Posture**.
2. Click **Connect account** in the page header, or open the **Accounts and scans** tab.
3. In the left sidebar, under **Add account**, choose **Amazon Web Services**, **Microsoft Azure** or **Google Cloud Platform**.
4. Fill in the form. The fields are listed per provider in the configuration pages. Secret fields are password inputs with a show/hide toggle.
5. Click **Test Connection**. This calls `POST /api/v1/cloud-connectors/test` and does not save anything:
   - AWS: resolves the credentials (and runs AssumeRole if a role ARN is set), then calls `sts:GetCallerIdentity`.
   - Azure: gets an ARM token and reads the first subscription in the list.
   - GCP: mints a token, then runs `projects.testIamPermissions` for each feature. The JSON response lists missing permissions per feature and the recommended roles. The form itself shows only "Connection successful!" or the error text.
6. Click **Save & Connect**. This calls `POST /api/v1/cloud-connectors`. The connector is stored with status `pending`. The first sync runs at the next 5-minute tick, or right away if you click **Sync now** on the connector.

The form also lists "What will be pulled" and states "Polled every 5 minutes · Read-only credentials required".

### How a connector is identified

`UpsertCloudConnector` derives the connector's `account_id` from the credentials. It uses the first non-empty value of `account_id`, then `project_id`, then `subscription_id`. The table has a unique index on `(provider, account_id)`. Saving again with the same provider and the same derived account ID **updates the credentials of the existing connector**. It does not create a second connector.

Consequences:

- **AWS:** fill in **Account ID**. If you leave it empty, every AWS connector without an account ID gets the key `(aws, "")`. Saving a second one silently overwrites the first one's credentials. Several AWS features also rely on the account ID (section 4 of [capability-aws.md](capability-aws.md)).
- **GCP:** the key comes from the **Project ID(s)** text as typed (for example `*` or `a,b`). If the field is empty, the first sync fills in the project and uses the service-account email as the label.
- **Azure:** the key is the **Subscription ID(s)** text as typed (for example `*`).

*Implemented in:* `management/frontend/src/pages/Cloud.jsx`, `pages/cloud/connectors.jsx` (`ConnectorForm`), `pages/cloud/shared.jsx` (`PROVIDERS`), `internal/api/handlers_cloud.go`, `internal/store/cloud_connectors.go`, `internal/store/migrations/012_cloud_connectors.sql`, `028_connector_uniqueness.sql`.

## 4. Credential storage

| Aspect | Behaviour |
|---|---|
| Encrypted fields | `secret_access_key`, `session_token`, `external_id`, `client_secret`, `service_account`, `token`, `pat`, `password`, `api_key`, `private_key`. Each is stored as `enc:v1:<base64(nonce‖ciphertext)>` inside the `credentials` JSON column (`sealCreds`). |
| Plain fields | Everything else, for example `access_key_id`, `region`, `role_arn`, `tenant_id`, `client_id`, `subscription_id`, `project_id`, `org_id`, `workspace_id`, `s3_*`. |
| Reading back | `GetCloudConnectorRaw` decrypts for internal use. If a value cannot be decrypted (wrong or missing key), it becomes an empty string. A ciphertext is never used as a credential. |
| Returned to the browser | `ListCloudConnectors` masks every field whose name looks secret (`credmask.go`: contains `secret`, `token`, `password`, `private`, `credential`, `service_account`, `api_key`, `access_key`, …, but not names ending in `_id`). Masked values are shown as `••••••••`. `external_id` ends in `_id`, so it is decrypted and returned in clear text to the console. |
| Legacy rows | A value without the `enc:v1:` prefix is treated as plaintext. It is re-encrypted the next time the connector is saved. |

To rotate a credential, save the connector again with the same identifying field (section 3). There is no edit form: you re-enter all fields.

*Implemented in:* `internal/store/secrets.go`, `internal/store/credmask.go`, `internal/store/cloud_connectors.go`.

## 5. The polling engine (`CloudConnectorEngine`)

| Loop | Cadence | What it does |
|---|---|---|
| Log sync | At startup, then every **5 minutes** | Each connector gets its own goroutine (`syncConnector`). |
| Posture scan (CSPM) | At startup, then every **6 hours** | `runCSPMAll`. Runs connectors one after another, with a 30-minute timeout each. |
| GCP signature-suppression refresh | Every 5 minutes | Reloads the rules managed on the Rules page. |

### Per-connector sync rules

- **Overlap guard:** if a sync for the same connector is still running, the new one is skipped and logged.
- **Retries:** up to 3 attempts. The backoff is 5 s, then 10 s. Each attempt has a **3-minute** timeout. Authentication errors (401/403, `invalid_client`, `invalid_grant`, "unauthorized", …) are not retried. Throttling and quota errors (messages containing `quota`, `rate limit`, `throttl`, `too many requests`) are never treated as auth errors.
- **Status:** after the run, `status` is set to `connected` or `error`, `last_error` to the error text, `last_sync` to now, and `event_count` is increased by the number inserted.
- **Error cool-down:** a connector in `error` is skipped for 30 minutes after its last attempt.
- **Cursor:** each provider keeps a time watermark in `sync_cursor`: the newest log timestamp actually ingested. An empty cursor value never overwrites a stored one, so a failed or partial run does not lose progress. Several secondary sources use `last_sync - 2 min` instead of the cursor (see the capability pages).

### Event insertion

Events are inserted in batches of 200 with `ON CONFLICT (id, time) DO NOTHING`. If a batch fails, it is retried row by row. NUL characters are removed from the raw JSON. A raw payload over 256 KiB (or invalid after cleaning) is replaced by a stub: `{"truncated":true,"original_bytes":…,"source":…}`.

### Background assessment jobs

| Job | Scheduled? | Manual trigger (console) | API |
|---|---|---|---|
| CSPM scan | Yes, every 6 h | **Run Scan** (Overview tab) | `POST /api/v1/cloud-connectors/{id}/cspm` |
| CIS benchmark | AWS only (derived from the scheduled CSPM) | **Run Assessment** (CIS Benchmark tab) | `POST …/{id}/cis` |
| Compliance mapping | Yes, after each scheduled CSPM | **Remap Compliance** / **Generate Compliance Report** | `POST …/{id}/compliance` |
| Asset inventory | GCP only, after each scheduled CSPM | **Full Inventory** (Asset Graph tab, GCP and Azure only) | `POST …/{id}/assets` |
| Blast radius | No | **Run Analysis** (Blast Radius tab) | `POST …/{id}/blast` |
| New-critical alerting | After each scheduled CSPM only | – | – |

Manual scans run as asynchronous jobs. The console adds `?async=1` and polls `GET /api/v1/jobs/{id}`. A second request for the same job while one is running returns the running job. Manual CSPM runs time out after 15 minutes for GCP and Azure, but after **3 minutes for AWS** (`handlers_cloud.go`). Manual CSPM runs do **not** refresh the compliance report, the AWS CIS result, the GCP inventory, or new-critical alerts. Those are refreshed only by the 6-hour scheduled run, or by their own buttons.

*Implemented in:* `internal/api/cloud_engine.go`, `handlers_cloud.go`, `async_jobs.go`, `cspm_newcritical.go`.

## 6. Permissions model summary

Every connector needs read-only access only. Nothing in the code writes to the cloud account. All calls are `List*`, `Describe*`, `Get*`, Log queries, or `testIamPermissions`. AWS `GenerateCredentialReport` is the one exception: it asks AWS to build the IAM credential report.

| Provider | Identity | Minimum for logs | For posture, CIS and blast radius |
|---|---|---|---|
| AWS | IAM user access key, optionally used to assume a role (recommended) | `cloudtrail:LookupEvents`, GuardDuty and Security Hub read | `SecurityAudit` managed policy (or `ReadOnlyAccess`) |
| Azure | Entra app registration with a client secret | **Reader** (Activity Log), Graph `AuditLog.Read.All` | **Reader** + **Security Reader** on each subscription. Graph `Policy.Read.All` and `Directory.Read.All`. **Log Analytics Reader** for resource logs. |
| GCP | Service-account key or Workload Identity Federation config | `roles/logging.viewer` (+ `roles/logging.privateLogViewer` for Data Access logs) | `roles/iam.securityReviewer`, `roles/cloudasset.viewer`, `roles/securitycenter.findingsViewer`, `roles/browser` |

Exact lists are in the configuration pages. A check that fails for lack of permission is recorded as **not assessed** with a reason. It is never counted as a pass (with exceptions noted per provider).

Inside ObsidianWatch:

| Action | Role required |
|---|---|
| List connectors, view results, view events | Any signed-in user |
| Add or test connector, delete connector, AWS org import, create or delete AWS CSPM suppression rules | Admin |
| Sync now, run CSPM, CIS, compliance, inventory or blast radius, create or delete Azure and GCP suppression rules | Any signed-in user (not admin-gated in `server.go`) |
| AI summary of a scan (`/ai-explain`) | Any signed-in user. Rate-limited to 20 calls per IP per 10 minutes. Needs a Groq or Anthropic key in Settings → AI. |

## 7. Outbound network requirements

All traffic is HTTPS (443) from the management server. The AWS client uses a guarded transport. If `HTTPS_PROXY` is set, the standard Go proxy settings apply to all three providers.

| Provider | Hosts |
|---|---|
| AWS | `sts.amazonaws.com`, `iam.amazonaws.com`, `s3.amazonaws.com`, `<bucket>.s3.amazonaws.com`, `<bucket>.s3.<region>.amazonaws.com` (S3 mode), `organizations.us-east-1.amazonaws.com` (org import), and for each scanned region: `cloudtrail.`, `guardduty.`, `securityhub.`, `ec2.`, `rds.`, `kms.`, `config.`, `lambda.` `<region>.amazonaws.com` |
| Azure | `login.microsoftonline.com`, `management.azure.com`, `graph.microsoft.com`, `api.loganalytics.io` (only if workspace IDs are set) |
| GCP | `oauth2.googleapis.com` (token URI; `accounts.google.com` and `www.googleapis.com` are also accepted), `sts.googleapis.com` and `iamcredentials.googleapis.com` (Workload Identity), `logging.googleapis.com`, `cloudresourcemanager.googleapis.com`, `compute.googleapis.com`, `storage.googleapis.com`, `sqladmin.googleapis.com`, `iam.googleapis.com`, `cloudkms.googleapis.com`, `container.googleapis.com`, `bigquery.googleapis.com`, `secretmanager.googleapis.com`, `run.googleapis.com`, `cloudfunctions.googleapis.com`, `pubsub.googleapis.com`, `dns.googleapis.com`, `apikeys.googleapis.com`, `artifactregistry.googleapis.com`, `notebooks.googleapis.com`, `securitycenter.googleapis.com`, `cloudasset.googleapis.com` |

No inbound connectivity from the cloud is needed.

## 8. Health and troubleshooting at deployment level

- **Connector status** appears in the sidebar of **Accounts and scans** (dot plus `connected` / `error` / `pending`). It also appears in the **State** column of the **Accounts** tab (hover shows `last_error`).
- **Per-source status** (for example CloudTrail OK but GuardDuty `not_enabled`) is kept in memory. It is exposed only through `GET /api/v1/cloud-connectors/{id}/sources`. It is not shown in the console and is reset when the server restarts. States are `ok`, `permission_missing`, `license_missing`, `not_enabled`, `partial` and `error`.
- **Server logs** use messages starting `cloud sync`, `cspm:`, `compliance:`, `azure extended:`, `gcp extended:`, `securityhub:`, `cloudtrail:`.
- **Scan coverage gaps** appear on the connector **Overview** tab as "N checks failed – show". They are also stored as `errors` and `not_assessed` in the scan result.

## 9. Removing a connector

Select the account in **Accounts and scans** and click **Disconnect**, then confirm. This calls `DELETE /api/v1/cloud-connectors/{id}` (admin only). It deletes the `cloud_connectors` row, including the stored credentials.

It does **not** delete:

- events already ingested (they stay in the events store);
- alerts;
- stored results in `settings` (`cspm:<provider>:<id>`, `cis:…`, `compliance:…`, `blast:…`, `assets:…`) and rows in `cloud_scan_history`;
- AWS, Azure and GCP baselines and suppression rules;
- the in-memory source status.

These leftovers are not shown in the console, because every view starts from the connector list. Revoke the credentials on the cloud side as well: delete the access key, client secret or service-account key, or remove the role trust.
