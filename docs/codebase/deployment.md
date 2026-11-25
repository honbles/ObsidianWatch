# Codebase security: deployment

This guide covers the "Code" feature of ObsidianWatch from start to finish. The feature connects to Git platforms, collects activity, and scans repositories. Topics: connecting a platform, credentials, webhooks, the polling engine, the scanners and their sandbox, credential storage, outbound network needs, and removing a connector.

Related documents: [configuration.md](configuration.md) (every field and setting) and [capability.md](capability.md) (what is collected, every rule, what each page shows).

> **Verification status.** This document was written from the source code. The connectors have **not** been checked against live GitHub, GitLab or Azure DevOps accounts during this documentation pass. Token scopes, API response fields and webhook payload fields come from the code and from the providers' public API shapes. Items marked *(unverified)* need a check against a real account before you rely on them.

---

## 1. Supported platforms

| Provider value | Platform | Polling | Webhook route | Posture check | SAST / SCA |
|---|---|---|---|---|---|
| `github` | GitHub.com (organisation or personal account) | yes | `POST /api/v1/devops/webhook/{id}` | yes | yes |
| `gitlab` | GitLab.com or self-managed GitLab | yes | `POST /api/v1/devops/webhook-gitlab/{id}` | yes | yes |
| `azuredevops` | Azure DevOps Services (`dev.azure.com`) | yes | `POST /api/v1/devops/webhook-azuredevops/{id}` | yes | yes |

There is no other provider. `DevOpsEngine.doSync` rejects any other value with `unknown provider`. GitHub Enterprise Server is not supported: every GitHub URL is hard-coded to `https://api.github.com`. Azure DevOps Server (on-premises) is not supported for polling: the sync always uses `https://dev.azure.com/{org}` (see section 3.3).

Implemented in: `management/backend/internal/api/devops_engine.go`, `devops_github.go`, `devops_gitlab.go`, `devops_azuredevops.go`, `server.go` (routes, lines 83-85 and 261-282).

---

## 2. Before you start

1. The management service must run with `OW_SECRET_KEY` (or `OW_SECRET_KEY_FILE`) set. Connector tokens and webhook secrets are encrypted with it (section 7). Without a key the server refuses to start, unless `OW_ALLOW_PLAINTEXT_SECRETS=true` is set.
2. You need the **admin** role to add, test or delete a connector. Analysts can run a sync, a code scan, a SAST scan and a posture check. Viewers can only read (see section 9).
3. For webhooks, the platform must reach the management API over HTTPS. Polling works without inbound access.
4. For self-managed GitLab on a private (RFC 1918) address, set `OW_ALLOW_PRIVATE_DEVOPS=true` on the management service (section 3.2).

---

## 3. Connect a platform

In the dashboard, open the rail section **Code → Repositories** (route `/devops`). Select the tab **Connectors and scans**, or press **Connect source** in the page header. In the left sidebar, under **Add connector**, choose **GitHub**, **GitLab** or **Azure DevOps**.

The form has the same flow for every provider:

1. Enter the organisation / group name and the token.
2. Press **Test Connection**. This calls `POST /api/v1/devops-connectors/test` with a 15 second timeout. **Save & Connect** stays disabled until the test passes.
3. Press **Save & Connect**. This calls `POST /api/v1/devops-connectors`. The response holds the connector ID and a newly generated webhook secret (32 hex characters, from `crypto/rand`).
4. The form shows a webhook URL and the secret. **Copy the secret now.** It is not shown again: list responses always blank it.
5. The first sync runs at the next engine tick (within 5 minutes). To start it at once, select the connector and press **Sync**.

> **Known UI defect.** After saving, the form always shows `https://<host>/api/v1/devops/webhook/{id}`, which is the GitHub route, for every provider. For GitLab use `/api/v1/devops/webhook-gitlab/{id}`. For Azure DevOps use `/api/v1/devops/webhook-azuredevops/{id}`. Source: `management/frontend/src/pages/DevOps.jsx` line 98.

### 3.1 GitHub

| Field | Value |
|---|---|
| Organization or Username | The GitHub organisation login, or a user login for a personal account |
| Personal Access Token | A classic PAT or a fine-grained token |

**Test.** The server tries `GET /orgs/{org}`, then `GET /users/{org}`, then `GET /user`, to tell an invalid token apart from a wrong name.

**Token permissions.** The form asks for `repo`, `read:org`, `admin:org` (audit log), `read:user`. Here is what each call in the code needs:

| What the code calls | Why | Classic PAT scope *(unverified)* |
|---|---|---|
| `GET /orgs/{org}/audit-log` | Organisation audit stream | `read:audit_log` (or `admin:org`). The org must be on GitHub Enterprise Cloud, and the token owner must be an org owner. |
| `GET /orgs/{org}/repos`, `GET /user/repos` | Repository list | `repo` for private repositories |
| `GET /repos/{r}/commits`, `GET /repos/{r}/commits/{sha}` | Commits and diffs | `repo` |
| `GET /repos/{r}/branches/{b}/protection` | Posture | `repo`. Repository admin rights are needed, otherwise GitHub answers 403/404 |
| `GET /orgs/{org}` (`two_factor_requirement_enabled`) | Posture | The field is only returned to org owners |
| `GET /repos/{r}/tarball/{ref}`, `GET /repos/{r}/git/trees/...`, `/contents/...` | SAST | `repo` |
| `GET /users/{login}/events` | Fallback for personal accounts | none (public events) |

If the audit log call fails for any reason, the connector falls back to the public user-events feed. The connector then stores this note in its status field: "Limited coverage: org audit log unavailable (...)". The note shows as the connector's last error even when the status is `connected`.

**Scope warning.** The sync lists `GET /user/repos` in addition to the organisation's repositories. Every repository the token owner can reach is polled and is offered for SAST, including personal repositories and those of other organisations. Use a dedicated machine account or a fine-grained token limited to the target organisation if this is not wanted.

### 3.2 GitLab

| Field | Value |
|---|---|
| Group Path or Project | A group path (`my-group`), or a user name for a personal namespace |
| Access Token | A personal, group or project access token |
| GitLab URL (optional) | Blank for `https://gitlab.com`, or the HTTPS root of a self-managed instance |

**Test.** The server tries `GET /api/v4/groups/{group}`, then `GET /api/v4/projects/{path}`.

**Token scopes.** The form asks for `api`, `read_api`, `read_audit_log`. All calls are GET requests, so `read_api` is enough for every call the code makes *(unverified)*. Group audit events (`/groups/{g}/audit_events`) need GitLab Premium or Ultimate and an Owner role on the group. When that call fails, the sync carries on silently with pipelines, project events and commits.

**Base URL rules** (`validateDevOpsBaseURL`, `devops_engine.go` line 300). The URL is checked when you test and when you save:

- It must use `https`. It must not contain user credentials.
- `localhost`, `*.localhost`, loopback, link-local (including cloud metadata `169.254.169.254`), multicast and unspecified IP literals are refused.
- Private RFC 1918 IP literals are refused unless `OW_ALLOW_PRIVATE_DEVOPS=true`.
- The check applies to IP literals only. A host name that resolves to a private or loopback address is not refused.

**Subgroups.** The group path goes into the URL without encoding. A nested path such as `parent/child` may fail on the group calls *(unverified)*. Use the top-level group: the project list already includes subgroups (`include_subgroups=true`).

### 3.3 Azure DevOps

| Field | Value |
|---|---|
| Organization Name | The name in `https://dev.azure.com/{org}` |
| Personal Access Token | An Azure DevOps PAT |
| Project (Optional) | Stored, but **not used** by the server. Every project in the organisation is synced. |
| Azure DevOps URL (Optional) | Used only by **Test Connection**. Sync, posture and SAST always use `https://dev.azure.com/{org}`. |

**PAT scopes** derived from the calls in the code *(unverified)*:

| Call | Scope |
|---|---|
| `_apis/projects`, `_apis/git/repositories`, `.../commits`, `.../changes`, `.../items` | Code (Read), Project and Team (Read) |
| `_apis/build/builds` | Build (Read). The UI help text does not list this scope. |
| `auditservice.dev.azure.com/.../auditlog` | Auditing (Read). Auditing must also be turned on for the organisation. |
| `_apis/policy/configurations` (posture) | Code (Read) *(unverified)* |

When the audit or build calls fail, the sync continues without them and records no note.

---

## 4. Webhooks

Polling covers all collection. Webhooks add near real-time events. They are optional.

### 4.1 Common behaviour

All three routes are public (no session), and they all behave the same way:

- **Fail closed.** If the connector has no webhook secret, the route answers 401. A missing or wrong signature or token also gets 401.
- **Rate limit.** 60 requests per minute per connector ID (`webhookLimiter`). Excess requests get 429.
- **Body cap.** The first 1 MB of the body is read.
- **Replay protection.** The delivery ID is remembered for 24 hours in memory: GitHub `X-GitHub-Delivery`, GitLab `X-Gitlab-Event-UUID` or `Idempotency-Key`, Azure DevOps the payload `id`. A repeat gets 204 and is not processed. The memory is cleared on restart and capped at about 20 000 entries.
- **Success** is `204 No Content`.
- **Webhook secret rotation.** Saving the connector again (same provider and organisation) generates a **new** webhook secret. Update the secret on the platform after every re-save.

### 4.2 GitHub

On the organisation (or repository) open **Settings → Webhooks → Add webhook**:

| Setting | Value |
|---|---|
| Payload URL | `https://<management-host>/api/v1/devops/webhook/{id}` |
| Content type | `application/json` (the body is parsed as JSON; form-encoded payloads are rejected with 400) |
| Secret | The webhook secret shown at save time |
| Events | At least `push`, `repository`, `member`, `organization`, `workflow_run`, `team`. Any other event type is also accepted (see capability.md section 3.1). |

Authentication: HMAC-SHA256 of the raw body, compared against `X-Hub-Signature-256` in constant time. The GitHub route does not check that the connector is a GitHub connector. It accepts any connector ID whose secret matches.

### 4.3 GitLab

On the group (Premium) or project open **Settings → Webhooks**:

| Setting | Value |
|---|---|
| URL | `https://<management-host>/api/v1/devops/webhook-gitlab/{id}` |
| Secret token | The webhook secret. GitLab sends it in `X-Gitlab-Token`. It is compared in constant time. |
| Triggers | Push events, Tag push events, Merge request events, Pipeline events. On group hooks also Member events and Project events. |

The connector must have provider `gitlab`, otherwise the route answers 404.

### 4.4 Azure DevOps

In **Project settings → Service hooks**, create a **Web Hooks** subscription for each event:

| Setting | Value |
|---|---|
| URL | `https://<management-host>/api/v1/devops/webhook-azuredevops/{id}` |
| Authentication | Either HTTP basic authentication with any user name and the webhook secret as the password, or an HTTP header `X-Webhook-Token: <secret>`. The header wins when both are present. |
| Events | Code pushed (`git.push`), Pull request merge attempted (`git.pullrequest.merged`), Build completed (`build.complete`), Run state changed (`ms.vss-pipelines.run-state-changed-event`) |

The connector must have provider `azuredevops`, otherwise the route answers 404.

Implemented in: `devops_github.go` (`handleGitHubWebhook`, `webhookDeliverySeen`), `devops_gitlab_webhook.go`, `devops_ado_webhook.go`.

---

## 5. The polling engine (DevOpsEngine)

`DevOpsEngine.Run` starts with the management server (`server.go` line 405).

| Property | Value |
|---|---|
| First run | Immediately at start-up |
| Interval | Every 5 minutes (fixed, not configurable) |
| Concurrency | One goroutine per connector per tick |
| Overlap guard | A connector whose previous sync is still running is skipped (`tryAcquireSync`) |
| Timeout per sync | 3 minutes. On timeout the sync stops where it is, and the remaining work is picked up by later ticks. |
| Manual sync | **Sync** button → `POST /api/v1/devops-connectors/{id}/sync`. It runs in the background and responds `sync started` at once. |
| Look-back on first sync | 30 days of commits |
| Look-back afterwards | From the last sync time minus 2 minutes |
| Status | `pending` after save, `connected` after a successful sync, `error` with the message after a failed one |

A sync fails (status `error`) only when the first required call fails: a missing token, or the Azure DevOps project list. Most other API errors are skipped silently, so a `connected` status does not prove full coverage. Check the **Events** tab.

Polled events are written to the events table of the agent-ingest database. The detection engine reads them through a dedicated cursor with a 7-day first look-back (see capability.md section 6).

Implemented in: `devops_engine.go`, `sync_guard.go`, `detection_engine.go` (`runDevOpsCursor`).

---

## 6. Scanning engines and sandboxing

Scans run on demand only. Nothing scans on a schedule.

| Scan | Trigger | Runs where |
|---|---|---|
| Code scan | **Code Scan** tab → `POST .../code-scan` | In process, over stored commit diffs. No source is downloaded. |
| SAST + SCA | **SAST** tab → `POST .../sast?async=1` | Downloads source to a temporary directory, then runs Semgrep, the OSV lookup, the built-in rules and CodeQL |
| Posture | **Posture** tab → `POST .../posture?async=1` | In process, API calls only |

### 6.1 Scanner binaries in the image

`management/docker/Dockerfile` installs, best effort:

- **Semgrep** from PyPI (`pip3 install semgrep`). If the install fails, the build continues.
- **CodeQL** bundle `v2.20.5` from GitHub releases. Set build argument `CODEQL_SHA256` to verify the download. If the install fails, the build continues.
- **OpenJDK 17**, with `JAVA_HOME` set for CodeQL.

**Semgrep rules.** The code uses `/semgrep-rules` when that directory exists. Otherwise it uses the registry pack `p/default`, which Semgrep downloads from `semgrep.dev` at scan time. The script `management/docker/download-semgrep-rules.sh` would fill `/semgrep-rules`, but the Dockerfile **does not run it**. In the shipped image Semgrep therefore needs outbound access to the Semgrep registry. To scan offline, run the script in a derived image, or mount a rules directory at `/semgrep-rules`.

### 6.2 Subprocess isolation

Semgrep and CodeQL run as child processes of the management server with these limits:

| Control | Detail |
|---|---|
| Minimal environment | `scannerEnv()` passes only `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `TZ`, `JAVA_HOME`, proxy variables (`HTTP(S)_PROXY`, `NO_PROXY`, lower-case forms), `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and every `SEMGREP_*` and `CODEQL_*` variable. `OW_SECRET_KEY`, the JWT secret, the database password and API keys are not passed. |
| Telemetry | Semgrep runs with `--metrics=off` |
| Resource flags | Semgrep `--max-memory 1000` (MB), `--timeout 30` (seconds per file), `--jobs 2` |
| Wall-clock limits | Semgrep 3 minutes per repository. CodeQL 5 minutes for `database create`, 5 minutes for `analyze`, 10 minutes overall per repository. The async job is capped at 10 minutes in total. |
| Path safety | Files from the provider API or tarball are written only inside the scan directory. Paths that escape it (`..`, absolute paths) are skipped. |
| Tarball limits | 512 MB compressed, 2 GiB uncompressed, 5 minute download timeout. Only regular files that the file filter selected are extracted. |
| Clean-up | The temporary directory (`$TMPDIR/sast-{connector}-{nanotime}*`) and the CodeQL database directory are deleted when the scan ends |

What the sandbox does **not** do: the scanners run as the same OS user, in the same container, with the same network access as the management server. There is no seccomp profile, no namespace and no separate container. CodeQL runs with `--no-tracing`, so no project build is executed. Semgrep does not execute repository code.

Implemented in: `sast_env.go`, `sast_engine.go` (`runSemgrep`, `runCodeQL`), `sast_tarball.go`, `management/docker/Dockerfile`.

---

## 7. Credential storage

| Item | Where | Protection |
|---|---|---|
| Token (`token`) | `devops_connectors.credentials` (JSONB) | AES-256-GCM, stored as `enc:v1:<base64>`. Key from `OW_SECRET_KEY`: a 32-byte base64 key is used directly; any other value is passed through Argon2id. |
| `base_url`, `project` | same column | Plain text (not secret) |
| Webhook secret | `devops_connectors.webhook_secret` | Same AES-GCM sealing |
| API responses | `GET /api/v1/devops-connectors` | Secret fields are replaced by `••••••••`. The webhook secret is blanked. |

If the key is lost or changed, sealed values decrypt to an empty string. Syncs then fail with `missing ... token`, and webhooks fail closed with 401. Re-enter the token, which also issues a new webhook secret. Back up the key separately from the database.

Tokens are sent only to the provider host: `api.github.com`, the validated GitLab base URL, or `dev.azure.com` / `auditservice.dev.azure.com`. The GitHub tarball redirect to `codeload.github.com` drops the `Authorization` header (standard Go client behaviour for a cross-host redirect).

Implemented in: `management/backend/internal/store/secrets.go`, `store/credmask.go`, `store/devops.go`.

---

## 8. Outbound network requirements

From the management container:

| Destination | Port | Used for |
|---|---|---|
| `api.github.com` | 443 | GitHub polling, posture, SAST |
| `codeload.github.com` | 443 | GitHub tarball download (redirect target) |
| `gitlab.com` or your GitLab host | 443 | GitLab polling, posture, SAST |
| `dev.azure.com` | 443 | Azure DevOps polling, posture, SAST |
| `auditservice.dev.azure.com` | 443 | Azure DevOps audit log |
| `api.osv.dev` | 443 | Dependency vulnerability lookup (SCA) |
| `semgrep.dev` (registry) | 443 | Only when `/semgrep-rules` is absent, which is the case in the shipped image |
| `api.groq.com` / `api.anthropic.com` / your model host | 443 | Only for **AI** summaries, when an AI key is configured |

Proxy variables are honoured by Go's default HTTP client and are passed on to Semgrep and CodeQL.

Inbound (optional, for webhooks): the platform must reach `https://<management-host>/api/v1/devops/webhook*/{id}`.

---

## 9. Access control

| Action | Route | Role |
|---|---|---|
| List connectors | `GET /api/v1/devops-connectors` | any signed-in user |
| Test / save / delete connector | `POST .../test`, `POST`, `DELETE .../{id}` | admin |
| Sync, code scan, SAST scan, posture check, AI summaries | `POST .../{id}/sync`, `/code-scan`, `/sast`, `/posture`, `.../ai` | admin or analyst (viewer is read-only) |
| Read results, list repositories | `GET .../{id}/code-scan`, `/sast`, `/sast/repos`, `/posture`, `/commits`, `GET /api/v1/findings` | any signed-in user |

`GET .../sast/repos` calls the provider API on every request, so viewers also cause provider API traffic.

---

## 10. Removing a connector

Select the connector in **Code → Repositories → Connectors and scans** and press **Disconnect**, then confirm. This calls `DELETE /api/v1/devops-connectors/{id}` (admin only).

| Data | Removed? |
|---|---|
| Connector row, encrypted token, webhook secret | yes |
| Stored commits (`devops_commits`) | yes (`ON DELETE CASCADE`) |
| Code scan results (`code_scan_results`) | yes (cascade) |
| SAST results (`sast_results`) | yes (cascade) |
| Last posture result (setting `devops.posture.last.{id}`) | **no**. It stays in the settings table and keeps appearing in **Insights → Code findings** (`GET /api/v1/findings`). |
| `devops.*` events already ingested | no. They age out with the event retention (see configuration.md section 8). |
| Alerts already raised | no |

Then, on the platform:

1. Delete the webhook or service hook. Deliveries to a deleted connector get 404.
2. Revoke the token.

A sync that is running when you delete finishes its current pass. Its writes for the deleted connector fail on the foreign key.
