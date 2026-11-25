# Codebase security: deployment

This guide covers the "Code" feature of ObsidianWatch from start to finish. The feature connects to Git platforms, collects activity for platform threat detection, scans repositories (secrets over history, pattern rules, CodeQL, dependencies, IaC, licences, SBOM), runs those scans automatically and on pull requests, tells which vulnerable dependencies are running, and supports triage and fix suggestions. Topics: a setup checklist, building the image with the scanners, connecting a platform, credentials, webhooks, automation and PR checks, runtime reachability, AI features, the polling engine, the scanners and their sandbox, credential storage, environment variables, outbound network needs, access control, and removing a connector.

Related documents: [configuration.md](configuration.md) (every field and setting) and [capability.md](capability.md) (what is collected, every rule, what each page shows).

> **Verification status.** This document was written from the source code. The connectors have **not** been checked against live GitHub, GitLab or Azure DevOps accounts during this documentation pass. Token scopes, API response fields and webhook payload fields come from the code and from the providers' public API shapes. Items marked *(unverified)* need a check against a real account before you rely on them.

---

## 0. Setup checklist

Follow these steps once per deployment, then once per platform organisation. Each step says which capability it switches on (capability.md has the details).

**Once per deployment**

1. **Secrets key.** Run the management service with `OW_SECRET_KEY` (or `OW_SECRET_KEY_FILE`). Tokens and webhook secrets are encrypted with it (section 7).
2. **Build the image with the scanners** (section 6.1): `docker build -f management/docker/Dockerfile` from the repository root, passing `GITLEAKS_SHA256`, `TRIVY_SHA256`, `OPENGREP_SHA256` and `CODEQL_SHA256` with known-good hashes. Without the scanners, SAST runs only the built-in rules and the OSV lookup.
3. **Outbound access** from the management container to the provider hosts and, if wanted, the Trivy database registry and AI provider (section 8). For a fully offline scanner set, also set `OW_SCANNER_DB_UPDATE=false`.
4. **Inbound access** for webhooks: the platforms must reach `https://<management-host>/api/v1/devops/webhook*/{id}`. Without webhooks you get polling (5-minute delay) but no PR checks and no on-push scans.
5. **Public URL** (optional): `OW_PUBLIC_URL=https://<management-host>` so PR statuses link back to the console.
6. **AI** (optional, for AI triage and code fix suggestions): add a Groq or Anthropic key in Settings → AI and, to allow sending code, set `ai.send_source_snippets` to `true` (section 6c).
7. **Runtime reachability** (optional): Linux agents on the application servers with the host sensor on (section 6a).

**Once per platform organisation**

1. **Create a token** with the permissions in section 3 (read) and section 4.5 (write, for PR checks). A dedicated machine account is best.
2. **Connect** in Code → Repositories → Connect source (section 3). Copy the webhook URL and secret shown after saving.
3. **Add the webhook** at the platform with the events in section 4 (include pull request events for PR checks).
4. **Turn on automation** in the connector's **Automation** tab: PR checks, comments, blocking level, scan on push, schedule (section 6b).
5. **Require the status** in the platform's branch protection to block merges (section 6b).
6. **Run a first SAST scan** from the SAST tab, or press **Scan all repositories now**.
7. **Check coverage**: the connector's status note (audit log available?), the SAST engine chips (every engine ran?), and the Events tab.

---

## 1. Supported platforms

| Provider value | Platform | Polling | Webhook route | Posture check | SAST / SCA |
|---|---|---|---|---|---|
| `github` | GitHub.com (organisation or personal account) | yes | `POST /api/v1/devops/webhook/{id}` | yes | yes |
| `gitlab` | GitLab.com or self-managed GitLab | yes | `POST /api/v1/devops/webhook-gitlab/{id}` | yes | yes |
| `azuredevops` | Azure DevOps Services (`dev.azure.com`), or Azure DevOps Server through the connector's URL | yes | `POST /api/v1/devops/webhook-azuredevops/{id}` | yes | yes |

There is no other provider; saving any other value is refused. GitHub Enterprise Server is not supported: every GitHub URL is `https://api.github.com`. Azure DevOps Server works by entering its collection URL as the connector URL (section 3.3); it has no audit log API, so the audit-based detections do not apply there.

Implemented in: `management/backend/internal/api/devops_engine.go`, `devops_github.go`, `devops_gitlab.go`, `devops_azuredevops.go`, `server.go`.

---

## 2. Before you start

1. The management service must run with `OW_SECRET_KEY` (or `OW_SECRET_KEY_FILE`) set. Connector tokens and webhook secrets are encrypted with it (section 7). Without a key the server refuses to start, unless `OW_ALLOW_PLAINTEXT_SECRETS=true` is set.
2. You need the **admin** role to add, test or delete a connector, change the automation policy and manage triage rules. Analysts can run a sync, a code scan, a SAST scan and a posture check, record triage decisions and request fix suggestions. Viewers can only read (see section 9).
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

> After saving, the form shows the webhook URL for the provider (`webhook`, `webhook-gitlab` or `webhook-azuredevops`) and where to enter the secret.

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
| `GET /orgs/{org}/repos`, `GET /user/repos?affiliation=owner` | Repository list | `repo` for private repositories |
| `GET /repos/{r}/commits`, `GET /repos/{r}/commits/{sha}` | Commits and diffs | `repo` |
| `GET /repos/{r}/branches/{b}/protection` | Posture | `repo`. Repository admin rights are needed, otherwise GitHub answers 403/404 |
| `GET /orgs/{org}` (`two_factor_requirement_enabled`) | Posture | The field is only returned to org owners |
| `git clone https://github.com/{r}.git` (token as `x-access-token`) | SAST source and history | `repo` (fine-grained: Contents read) |
| `GET /repos/{r}/tarball/{ref}`, `GET /repos/{r}/git/trees/...`, `/contents/...` | SAST fallback; file for an AI fix suggestion | `repo` |
| `GET /users/{login}/events` | Fallback for personal accounts | none (public events) |

If the audit log call fails for any reason, the connector falls back to the public user-events feed. The connector then stores this note in its status field: "Limited coverage: org audit log unavailable (...)". The note shows as the connector's last error even when the status is `connected`.

**Scope.** Only repositories owned by the connector's organisation (or, for a personal account, by that user) are polled, checked and offered for SAST. Repositories of other organisations the token can see are ignored.

### 3.2 GitLab

| Field | Value |
|---|---|
| Group Path or Project | A group path (`my-group`), or a user name for a personal namespace |
| Access Token | A personal, group or project access token |
| GitLab URL (optional) | Blank for `https://gitlab.com`, or the HTTPS root of a self-managed instance |

**Test.** The server tries `GET /api/v4/groups/{group}`, then `GET /api/v4/projects/{path}`.

**Token scopes.** The form asks for `api`, `read_api`, `read_audit_log`. Reading (sync, posture, SAST API fallback) needs `read_api`; cloning for SAST needs `read_repository` (or `api`); PR checks need `api` (section 4.5) *(unverified)*. Group audit events (`/groups/{g}/audit_events`) need GitLab Premium or Ultimate and an Owner role on the group. When that call fails, the sync carries on silently with pipelines, project events and commits.

**Base URL rules** (`validateDevOpsBaseURL`, `devops_engine.go` line 300). The URL is checked when you test and when you save:

- It must use `https`. It must not contain user credentials.
- `localhost`, `*.localhost`, loopback, link-local (including cloud metadata `169.254.169.254`), multicast and unspecified IP literals are refused.
- Private RFC 1918 IP literals are refused unless `OW_ALLOW_PRIVATE_DEVOPS=true`.
- The same rules are applied again to the address actually dialled, after DNS resolution and on every redirect (`devops_http.go`), so a host name that resolves to a private, loopback or metadata address is refused too. Redirects to another host or to plain HTTP are not followed. Behind an outbound proxy (`HTTPS_PROXY`) only the host-name check applies, because the connection goes to the proxy.

**Subgroups.** The group path is URL-encoded as one segment, so a nested group such as `parent/child` works. The project list includes subgroups (`include_subgroups=true`) and follows every page (up to 2 000 projects).

### 3.3 Azure DevOps

| Field | Value |
|---|---|
| Organization Name | The name in `https://dev.azure.com/{org}` |
| Personal Access Token | An Azure DevOps PAT |
| Project (Optional) | When set, only this project is synced, checked and offered for SAST. Blank: every project. |
| Azure DevOps URL (Optional) | The full organisation or collection URL. Blank: `https://dev.azure.com/{org}`. For Azure DevOps Server use the collection URL (for example `https://tfs.example.com/tfs/DefaultCollection`); the audit log is not available there and the connector shows a coverage note. |

**PAT scopes** derived from the calls in the code *(unverified)*:

| Call | Scope |
|---|---|
| `_apis/projects`, `_apis/git/repositories`, `.../commits`, `.../changes`, `.../items`, `git clone …/_git/{repo}` | Code (Read), Project and Team (Read) |
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
- **Webhook secret.** Saving the connector again (same provider and organisation) keeps the existing secret, so configured webhooks keep working. Delete and re-create the connector to get a new one.

### 4.2 GitHub

On the organisation (or repository) open **Settings → Webhooks → Add webhook**:

| Setting | Value |
|---|---|
| Payload URL | `https://<management-host>/api/v1/devops/webhook/{id}` |
| Content type | `application/json` (the body is parsed as JSON; form-encoded payloads are rejected with 400) |
| Secret | The webhook secret shown at save time |
| Events | At least `push`, `pull_request`, `repository`, `member`, `organization`, `workflow_run`, `team`, `deploy_key`, `branch_protection_rule`, `repository_ruleset`, `public`, `create`, `delete`. Any other event type is also accepted (see capability.md section 3.1). |

Authentication: HMAC-SHA256 of the raw body, compared against `X-Hub-Signature-256` in constant time. The route answers 404 for a connector that is not a GitHub connector.

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
| Events | Code pushed (`git.push`), Pull request created (`git.pullrequest.created`), Pull request updated (`git.pullrequest.updated`), Pull request merge attempted (`git.pullrequest.merged`), Build completed (`build.complete`), Run state changed (`ms.vss-pipelines.run-state-changed-event`) |

The connector must have provider `azuredevops`, otherwise the route answers 404.

### 4.5 Token permissions for PR checks

PR checks write back to the provider. Read-only tokens still run the scan, but the status and comments fail (the job shows why).

| Provider | Needed for status and comments *(unverified)* |
|---|---|
| GitHub | Classic: `repo` (or `repo:status` + `public_repo` for public repositories). Fine-grained: Commit statuses (read and write), Pull requests (read and write), Contents (read) |
| GitLab | `api` scope, Developer role or higher on the project |
| Azure DevOps | Code (Read & write) and Code (Status) |

Implemented in: `devops_github.go` (`handleGitHubWebhook`, `webhookDeliverySeen`), `devops_gitlab_webhook.go`, `devops_ado_webhook.go`, `code_reporters.go` (`*CodeTriggers`).

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

Polled events are written to the events table of the agent-ingest database. The detection engine reads them through a dedicated DevOps cursor with a 7-day first look-back (capability.md section 6, Platform threat detection).

Implemented in: `devops_engine.go`, `sync_guard.go`, `detection_engine.go` (`runDevOpsCursor`).

---

## 6. Scanning engines and sandboxing

| Scan | Trigger | Runs where |
|---|---|---|
| Code scan | **Code Scan** tab → `POST .../code-scan` | In process, over stored commit diffs. No source is downloaded. |
| SAST + SCA | **SAST** tab → `POST .../sast?async=1`; or an automated job (on push, schedule, PR, **Scan all repositories now**; section 6b) | Clones the repository to a temporary directory (provider API download as the fallback), then runs history secrets, pattern rules, Trivy (or OSV), the built-in rules and CodeQL |
| Posture | **Posture** tab → `POST .../posture?async=1` | In process, API calls only |

### 6.1 Scanner binaries in the image

`management/docker/Dockerfile` installs, best effort:

- **gitleaks** `8.30.1`, **Trivy** `0.71.2` and the **opengrep** engine `v1.31.0` from their GitHub releases (`management/docker/install-scanners.sh`). Each archive is checked against the release's checksum list, and against the build arguments `GITLEAKS_SHA256`, `TRIVY_SHA256`, `OPENGREP_SHA256` when set. **Set them.** Trivy's release channel was compromised in March 2026 (v0.69.4 and some images, CVE-2026-33634); pinning a version and its hash is the protection.
- **opengrep-rules** (LGPL-2.1) cloned at `OPENGREP_RULES_REF` into `/opt/obsidianwatch/rules/opengrep`, rule files only.
- **Semgrep CE** engine `1.100.0` from PyPI, only when the opengrep binary did not install.
- **Trivy databases** (vulnerability DB and Java DB) downloaded at build time into `/var/cache/trivy`.
- **CodeQL** bundle `v2.23.3` (needed for C/C++ build-mode none and Rust). Set `CODEQL_SHA256` to verify the download.
- **OpenJDK 17**, with `JAVA_HOME` set for CodeQL.

Any tool that fails to install is skipped and reported as missing at scan time.

**Rules licensing.** The Semgrep registry rules (`p/default`) and the `semgrep/semgrep-rules` repository are under the Semgrep Rules License v1.0 (internal, non-competing, non-SaaS use only). The product does not use them. The earlier `download-semgrep-rules.sh` script, which fetched them, has been removed. If you mount your own rules at `/semgrep-rules` or point `OW_SEMGREP_RULES` at them, their licence is your responsibility.

Semgrep and CodeQL run as child processes of the management server with these limits:

| Control | Detail |
|---|---|
| Minimal environment | `scannerEnv()` passes only `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `TZ`, `JAVA_HOME`, proxy variables (`HTTP(S)_PROXY`, `NO_PROXY`, lower-case forms), `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`, and every `SEMGREP_*` and `CODEQL_*` variable. `OW_SECRET_KEY`, the JWT secret, the database password and API keys are not passed. git additionally gets the provider token as an `http.extraHeader` through `GIT_CONFIG_*` variables, no user or system git config, no prompts and no LFS download. |
| Telemetry | Semgrep runs with `--metrics=off --disable-version-check`; opengrep has no telemetry; Trivy runs with telemetry disabled |
| Resource flags | Pattern rules `--max-memory 1000` (MB), `--timeout 30` (seconds per file), `--jobs 2`; CodeQL `--threads=2` |
| Wall-clock limits | Clone 5 min; history secrets 5 min; pattern rules 4 min; Trivy 9 min; CodeQL 12 min for all languages of a repository. The SAST async job is capped at 40 minutes. |
| Path safety | Files from the provider API or tarball are written only inside the scan directory. Paths that escape it (`..`, absolute paths) are skipped. |
| Clone hardening | Hooks off, symlinks checked out as plain files, HTTPS only, no submodules, no redirects to another host; 5 minutes and `OW_SAST_MAX_REPO_MB` (default 2 048 MB) |
| Tarball limits (API fallback) | 512 MB compressed, 2 GiB uncompressed, 5 minute download timeout. Only regular files that the file filter selected are extracted. |
| Clean-up | The temporary directory (`$TMPDIR/sast-{connector}-*`, `codejob-{id}-*`, `codepr-{id}-*`) and the CodeQL database directories are deleted when the scan ends |

What the sandbox does **not** do: the scanners run as the same OS user, in the same container, with the same network access as the management server. There is no seccomp profile, no namespace and no separate container. CodeQL uses build-mode none for every language except Go, so no project build runs; Go is built with `go build ./...` (cgo off, local toolchain), which runs no repository code but may download Go modules. git checks out symlinks as plain files and runs no hooks. Pattern rules, gitleaks and Trivy do not execute repository code.

Implemented in: `sast_env.go`, `sast_engine.go`, `sast_engines.go`, `sast_tarball.go`, `management/docker/Dockerfile`, `management/docker/install-scanners.sh`.

---

## 6a. Runtime reachability

Runtime reachability (capability.md section 4.11) needs no Code setting. It needs:

1. The **Linux agent** on the hosts that run the services, with the application profile's host sensor on (`app_monitoring.ebpf.enabled: true`, any `mode`). The agent must run as root to read other processes' memory maps and files under `/proc/<pid>/root`.
2. The services to be running: inventories cover processes found by their listening ports, plus processes sending OpenTelemetry to the agent.

The first inventory arrives about 2 minutes after the agent starts, then every 15 minutes. Until any host reports one, dependency findings show "Runtime unknown". Windows and macOS agents do not report inventories yet.

To see what a host reports, search the events for `event_type: runtime_inventory`.

## 6b. Automation and pull-request checks

1. **Webhook events.** Add pull request events to the webhook: GitHub `pull_request` (and `push`); GitLab Merge request events (and Push events); Azure DevOps service hooks "Pull request created" and "Pull request updated" (and "Code pushed"). Section 4 has the full lists.
2. **Token write access** (section 4.5). Without it the scan still runs but the status and comments fail; the job in the Automation tab shows the provider's error.
3. **Policy.** In Code → Repositories → Connectors and scans → *connector* → **Automation** (admin): tick **Scan every pull request**, **Post comments**, optionally **Run CodeQL on pull requests** and **AI fix suggestions in comments**; choose **Fail the check on**; tick **Scan on every push to the default branch**; choose a **Scheduled scan** and hour (UTC); optionally list repositories for scheduled scans. Save.
4. **Block merges** by making the status required at the platform:

| Provider | Status | Where |
|---|---|---|
| GitHub | `ObsidianWatch / code scan` | Settings → Branches (or Rules → Rulesets) → require status checks → add the status (it appears after the first PR check) |
| GitLab | `ObsidianWatch code scan` | Settings → Merge requests → "Pipelines must succeed" (the external status is part of the pipeline) |
| Azure DevOps | genre `obsidianwatch`, name `code-scan` | Project settings → Repositories → *repo* → Policies → *branch* → Status checks → add, required |

5. **Check it works.** Open or update a pull request. The **Automated scans** list shows the job (queued, running, passed / blocking / failed) and, when opened, what was posted and why anything failed.

Jobs survive restarts (a job running during a restart is marked failed). `OW_CODE_SCAN_WORKERS` (1-4, default 1) runs more jobs in parallel; each job can use several CPU cores and gigabytes of disk while CodeQL runs.

## 6c. AI features

| Feature | Needs |
|---|---|
| AI Triage summary (SAST, Code Scan tabs) | An AI key in Settings → AI (Groq or Anthropic). Snippets are only sent when `ai.send_source_snippets` is `true`. |
| AI fix suggestions for code findings (SAST tab, PR comments) | An AI key **and** `ai.send_source_snippets = true` (a fix needs the code). Otherwise the button answers with the missing setting. |
| Dependency fix suggestions | Nothing (no AI) |

Code sent to the model is at most 30 lines around a finding, fenced as untrusted input. Requests share a rate limit of 6 per 10 minutes. Suggestions are cached for 30 days and never applied to a repository.

## 7. Credential storage

| Item | Where | Protection |
|---|---|---|
| Token (`token`) | `devops_connectors.credentials` (JSONB) | AES-256-GCM, stored as `enc:v1:<base64>`. Key from `OW_SECRET_KEY`: a 32-byte base64 key is used directly; any other value is passed through Argon2id. |
| `base_url`, `project` | same column | Plain text (not secret) |
| Webhook secret | `devops_connectors.webhook_secret` | Same AES-GCM sealing |
| Token during a scan | git process environment only (`GIT_CONFIG_VALUE_0`), never in the URL, the command line or on disk | – |
| API responses | `GET /api/v1/devops-connectors` | Secret fields are replaced by `••••••••`. The webhook secret is blanked. |

If the key is lost or changed, sealed values decrypt to an empty string. Syncs then fail with `missing ... token`, and webhooks fail closed with 401. Re-enter the token. The unreadable webhook secret is kept as is, so delete and re-create the connector to issue a new one. Back up the key separately from the database.

Tokens are sent only to the provider host: `api.github.com` and `github.com` (clone), the validated GitLab base URL, or the Azure DevOps URL / `auditservice.dev.azure.com`. Every provider call goes through one client (`devops_http.go`): redirects to plain HTTP are refused, and a redirect to another host (the GitHub tarball redirect to `codeload.github.com`) is followed without the `Authorization` or `PRIVATE-TOKEN` header.

Implemented in: `management/backend/internal/store/secrets.go`, `store/credmask.go`, `store/devops.go`.

---

## 7a. Environment variables

| Variable | Default | Effect |
|---|---|---|
| `OW_SECRET_KEY` / `OW_SECRET_KEY_FILE` | – (required) | Encryption key for tokens and webhook secrets |
| `OW_ALLOW_PRIVATE_DEVOPS` | `false` | Allow provider URLs on private (RFC 1918) addresses, for self-managed GitLab or Azure DevOps Server |
| `OW_PUBLIC_URL` | – | Console URL used as the link of PR statuses |
| `OW_SAST_SECRET_HISTORY` | `true` | `false`: shallow clone, no history secrets |
| `OW_SAST_MAX_REPO_MB` | `2048` | Largest checkout scanned |
| `OW_SEMGREP_RULES` | – | Directory of pattern rules to use instead of the bundled opengrep-rules |
| `OW_TRIVY_CACHE_DIR` | `/var/cache/trivy` | Trivy databases |
| `OW_SCANNER_DB_UPDATE` | `true` | `false`: never refresh the Trivy databases (fully offline) |
| `OW_CODE_SCAN_WORKERS` | `1` | Automated scan jobs run in parallel (1-4) |
| `HTTPS_PROXY`, `NO_PROXY` | – | Outbound proxy for the API clients, git and the scanners |

Settings (Settings → AI, or the settings table): `ai.send_source_snippets` (`true` to allow code to the AI provider), `detection.business_hours`, `detection.business_tz`, `ioc_otx_min_confidence`.

---

## 8. Outbound network requirements

From the management container:

| Destination | Port | Used for |
|---|---|---|
| `api.github.com` | 443 | GitHub polling, posture, PR statuses and comments, SAST API fallback |
| `github.com` | 443 | Cloning GitHub repositories |
| `codeload.github.com` | 443 | GitHub tarball download (API fallback only) |
| `gitlab.com` or your GitLab host | 443 | GitLab polling, posture, cloning, MR statuses and comments |
| `dev.azure.com` or your Azure DevOps Server | 443 | Azure DevOps polling, posture, cloning, PR statuses and threads |
| `auditservice.dev.azure.com` | 443 | Azure DevOps audit log |
| `mirror.gcr.io` / `ghcr.io` (Trivy databases) | 443 | Only to refresh the Trivy databases; not needed with `OW_SCANNER_DB_UPDATE=false` |
| `proxy.golang.org` | 443 | CodeQL's Go build may download modules |
| `api.osv.dev` | 443 | Only when Trivy is missing |
| `api.groq.com` / `api.anthropic.com` | 443 | Only for AI triage and AI fix suggestions, when a key is configured |

Proxy variables are honoured by the API clients and passed on to git, the pattern engine, Trivy and CodeQL.

Inbound (for webhooks, PR checks and on-push scans): the platform must reach `https://<management-host>/api/v1/devops/webhook*/{id}`.

---

## 9. Access control

Viewers are read-only everywhere (every mutating request is refused for them). Analysts and admins can do everything below that is not marked admin.

| Action | Route | Role |
|---|---|---|
| List connectors | `GET /api/v1/devops-connectors` | any signed-in user |
| Test / save / delete connector | `POST .../test`, `POST`, `DELETE .../{id}` | admin |
| Sync, code scan, SAST scan, posture check, AI summaries | `POST .../{id}/sync`, `/code-scan`, `/sast`, `/posture`, `.../ai` | analyst, admin |
| Read results, list repositories, SBOM | `GET .../{id}/code-scan`, `/sast`, `/sast/repos`, `/sast/sbom`, `/posture`, `/commits`, `GET /api/v1/findings` | any signed-in user |
| Automation policy | `GET .../{id}/scan-policy` (any), `PUT` (admin) | |
| Automated scan jobs | `GET .../{id}/scan-jobs`, `GET /api/v1/scan-jobs/{job}` (any); `POST .../{id}/scan-jobs` "scan now" (admin) | |
| Triage a finding | `POST .../{id}/findings/triage` | analyst, admin |
| Triage rules | `GET .../{id}/triage-rules` (any); `POST`, `DELETE .../triage-rules/{rule}` (admin) | |
| Fix suggestion | `POST .../{id}/sast/fix` | analyst, admin |
| Runtime package lookup | `GET /api/v1/runtime-packages` | any signed-in user |

`GET .../sast/repos` calls the provider API on every request, so viewers also cause provider API traffic.

---

## 10. Removing a connector

Select the connector in **Code → Repositories → Connectors and scans** and press **Disconnect**, then confirm. This calls `DELETE /api/v1/devops-connectors/{id}` (admin only).

| Data | Removed? |
|---|---|
| Connector row, encrypted token, webhook secret | yes |
| Stored commits (`devops_commits`) | yes (`ON DELETE CASCADE`) |
| Code scan results (`code_scan_results`) | yes (cascade) |
| SAST results (`sast_results`, with engines and SBOM) | yes (cascade) |
| Automated scan jobs and PR check state (`code_scan_jobs`, `code_pr_checks`) | yes (cascade) |
| Triage decisions and rules (`code_finding_triage`, `code_triage_rules`) | yes (cascade) |
| Last posture result, automation policy, last scheduled run (settings `devops.posture.last.{id}`, `code.policy.{id}`, `code.schedule.last.{id}`) | yes |
| Cached AI fix suggestions (`code_fix_cache`) | no; they expire after 30 days |
| Runtime package index (`runtime_packages`) | no; it belongs to the agents, not the connector |
| `devops.*` events already ingested | no. They age out with the event retention (see configuration.md section 8). |
| Alerts already raised | no |

Then, on the platform:

1. Delete the webhook or service hook. Deliveries to a deleted connector get 404.
2. Remove the required status `ObsidianWatch / code scan` (or the GitLab / Azure DevOps equivalent) from branch protection, or merges stay blocked waiting for it.
3. Revoke the token.

A sync that is running when you delete finishes its current pass. Its writes for the deleted connector fail on the foreign key.
