# Codebase security: configuration

This document lists every connector field, every setting that changes the behaviour of the Code feature, and the fixed values in the code that you cannot change. For setup steps, see [deployment.md](deployment.md). For detection content, see [capability.md](capability.md).

> **Verification status.** Written from the source code. None of the settings below have been exercised against live GitHub, GitLab or Azure DevOps accounts during this documentation pass.

---

## 1. Connector record

A connector is one row in `devops_connectors`. Exactly one connector can exist per `(provider, org)` pair (unique index from migration `028_connector_uniqueness.sql`). Saving the same pair again updates the existing row: new credentials, new label, a **new webhook secret**, and status reset to `pending`.

| Field | Set by | Meaning |
|---|---|---|
| `id` | server | Numeric ID. Appears in webhook URLs and page URLs. |
| `provider` | form | `github`, `gitlab` or `azuredevops` |
| `org` | form | GitHub org or user login; GitLab group path or user name; Azure DevOps organisation |
| `label` | form | The text returned by **Test Connection** (for example `Connected: Acme Inc`), or `org` |
| `credentials.token` | form | PAT or access token. Encrypted at rest. Masked in responses. |
| `credentials.base_url` | form | GitLab: instance root. Azure DevOps: used only by the connection test. Validated (HTTPS, no credentials, no loopback / link-local / private IP literals unless `OW_ALLOW_PRIVATE_DEVOPS=true`). Normalised to `scheme://host[:port][/path]` with no trailing slash. |
| `credentials.project` | form (Azure DevOps) | Stored but not read by any server code |
| `webhook_secret` | server | 16 random bytes as hex. Shown once, at save time. |
| `status` | server | `pending`, `connected`, `error` |
| `last_sync` | server | Time of the last finished sync (success or error) |
| `last_error` | server | The error of the last failed sync, or a coverage note (GitHub audit-log fallback) |
| `event_count` | server | Running total of items written by syncs. It counts commits and events together, so it is not an event count. |
| `sync_cursor` | server | GitHub only: the audit-log `@cursor` of the last entry read |

Implemented in: `store/devops.go`, `store/migrations/015_devops_connectors.sql`, `api/devops_engine.go`.

---

## 2. Differences between providers

| Aspect | GitHub | GitLab | Azure DevOps |
|---|---|---|---|
| `org` means | Organisation, or user account | Group path, or user name | Organisation |
| API root | `https://api.github.com` (fixed) | `base_url` or `https://gitlab.com` | `https://dev.azure.com/{org}` (fixed for sync) |
| Auth header | `Authorization: Bearer <token>` | `PRIVATE-TOKEN: <token>` | HTTP Basic, empty user, PAT as password |
| Repository discovery | `/orgs/{org}/repos` **plus** `/user/repos` (all repositories the token can see), up to 10 pages of 100 each | `/groups/{g}/projects` (with subgroups), else `/users/{u}/projects`; first 50 only | Every project, then every Git repository in it |
| Audit source | Org audit log (Enterprise Cloud), else the public user-events feed | Group audit events (Premium) | Organisation audit log (auditing must be on) |
| Audit paging | Up to 10 pages of 100, resumed from a cursor | One page of 100 since the last sync | Up to 10 pages of 200 since the last sync |
| Pipeline runs (polled) | not polled (webhook `workflow_run` only) | `/projects/{id}/pipelines`, 50 per project | `_apis/build/builds`, 50 per project |
| Project / member events (polled) | via the audit log | `/projects/{id}/events` (any tier) | via the audit log |
| Commits per repository per sync | up to 5 pages of 100 | 20 (one page) | 20 (`$top=20`) |
| Branch read | Default branch only | Default branch only | Default branch only |
| Commit diff content | yes (patch text) | yes (diff text) | **no**. Only file paths and change types are fetched. |
| Secret check on commits | Added lines of the patch | Added lines of the diff | **File paths only**, matched against the provider-specific secret patterns. In practice this almost never matches. |
| Sensitive-file event | yes | yes | computed, then discarded (no event) |
| Mass-deletion and dependency-change events | yes | no | no |
| Signature / committer integrity fields | yes (`verified`, `committer_mismatch`) | no | no |
| Webhook auth | HMAC-SHA256 (`X-Hub-Signature-256`) | Shared token (`X-Gitlab-Token`) | Basic password or `X-Webhook-Token` |
| Posture checks | Org 2FA, secret scanning, push protection, branch protection | Group 2FA, protected default branch, developer push, force push | Required-reviewer policy on default branch |
| SAST source download | One tarball per repository (per-file API fallback) | Per-file API (tree capped at 2 000 entries) | Per-file API |
| Event `host` value | Org, or repository for audit entries with a repo | Group | Organisation |

---

## 3. Scan scoping

There is no setting to include or exclude organisations, repositories or branches. Scope follows from the token and from the code:

| Scope | Polling | SAST | Code scan | Posture |
|---|---|---|---|---|
| Organisations | One per connector. GitHub also polls the token owner's other repositories (`/user/repos`). | Same as the repository list | Repositories with stored commits | One per connector |
| Repositories | All repositories found (see section 2) | All repositories that appear in the last 500 stored commits, or one selected repository | Repositories in the last 500 stored commits | First 100 non-archived, non-fork (GitHub) / non-empty (GitLab) / enabled (Azure DevOps) repositories |
| Branches | Default branch | Default branch, or the branch typed in the **Branch** field (one repository at a time) | Whatever was polled (default branch) | Default branch |

**Narrowing the scope.** Use a token that sees only the wanted repositories, for example a GitHub fine-grained token restricted to selected repositories, or a GitLab group or project access token.

**SAST: one repository or all.** On the **SAST** tab of a connector:

- **Repository** = `All repos`: scans every repository that appears in the last 500 stored commits. Results are saved under repository `''`.
- A specific repository: calls `POST .../sast?repo=<full name>&branch=<branch>`. The list comes from `GET .../sast/repos`, which queries the provider live. For GitLab it lists `projects?membership=true` (first 100), which can include projects outside the connector's group.
- **Branch**: free text. Blank or `HEAD` means the default branch.

Only one SAST job per connector can run at a time when started from the UI: the job lock key is the route path without the query string. A second request (even for another repository) returns the running job's ID.

---

## 4. Schedules

| Activity | Schedule | Configurable |
|---|---|---|
| Connector polling | At start-up, then every 5 minutes | no |
| Sync timeout | 3 minutes per connector per run | no |
| Detection on `devops.*` events | Every detection-engine cycle (`detectionInterval()`) | Detection-engine setting, not specific to Code |
| Code scan, SAST, SCA, posture | Manual only | no scheduler exists |
| Webhook replay memory | 24 hours, in memory | no |

---

## 5. Scanner toggles

There are no per-scanner switches in the UI or the settings table. What runs is decided by what is installed:

| Engine | Runs when | Notes |
|---|---|---|
| Semgrep | `semgrep` is on `PATH` | Rules from `/semgrep-rules` if the directory exists, else the registry pack `p/default` |
| CodeQL | `codeql` is on `PATH` (and Semgrep is present; `engine` is labelled `semgrep+codeql+builtin`) | The language is picked from the most common file type: Go, JavaScript/TypeScript, Python, Java, C#, Ruby. One language per repository. |
| Built-in regex rules | Always | 208 rules (see capability.md section 4.4). See the warning below. |
| OSV dependency lookup | Always | Network failure gives no SCA findings and is only logged |
| AI summaries | Only when the user presses the AI button, and an AI key (Groq or Anthropic) is set in config or in settings `ai.*` | Rate limited per scanner. SAST snippets are sent only when the AI source-snippet setting allows it (`aiSourceSnippetsAllowed`). |

To disable Semgrep or CodeQL, remove the binary from the image. To force offline Semgrep rules, mount a directory at `/semgrep-rules`.

> **Warning: results from built-in rules and OSV are currently discarded.** `deduplicateSASTFindings` (`sast_engine.go` line 1259) keeps only findings whose engine is `semgrep` or `codeql`. Built-in (`builtin`) and OSV (`osv`) findings are counted in logs but never stored or shown. With CodeQL installed, the same function can panic with an index-out-of-range error, which fails the scan request. See capability.md section 4.7.

Built-in SAST rules cannot be turned off one by one. `GET /api/v1/sast-rules` lists them, read-only. The DevOps detection signatures (`DEV-001` … `DEV-021`) follow the general detection toggles. However, the dedicated DevOps detection pass (`runDevOpsCursor`) does not consult them. See capability.md section 6.

---

## 6. Suppression and false-positive handling

There is no finding status (open / resolved / ignored) and no suppression list for code findings. The available controls are:

| Mechanism | Applies to | How |
|---|---|---|
| Inline ignore marker | Commit secret scanner only (the one that raises `devops.secret_push`) | A line containing any of `ow:ignore`, `pragma: allowlist secret`, `nosec`, `gitleaks:allow`, `noqa: secret` (case-insensitive) is skipped |
| Placeholder and entropy filter | Commit secret scanner, generic `key = value` patterns only | Values containing `example`, `changeme`, `test`, `todo`, `password`, `secret`, `token`, `${`, `{{`, `process.env`, `os.getenv`, `null`, `none` and similar are ignored. So are values with Shannon entropy below 3.0 bits per character, and values that repeat one character. |
| Safe file suffixes | Sensitive-file events | `.pub`, `.example`, `.sample`, `.template`, `.dist` are never treated as secret files. Deleted files are ignored. |
| Vendor paths | SAST | Path segments `vendor`, `node_modules`, `.git`, `__pycache__`, `.venv`, `venv`, `.gradle`, `site-packages`, `bower_components`, and files ending `.min.js` / `.bundle.js`, are not scanned |
| Semgrep `nosemgrep` comments | Semgrep findings | Native Semgrep behaviour |
| Re-scan | All scanners | A finding disappears from the pages when the latest scan no longer reports it |
| Detection allow-lists / rule toggles | `DEV-*` alerts from the main detection pass | General detection settings (`engineGate`) |
| Business hours | `DEV-017`, `DEV-018` | Settings `detection.business_hours` (for example `07-19`) and `detection.business_tz` (IANA zone). Default 06-22 UTC. |

The code-scan secret patterns, the built-in SAST rules and the sensitive-file finder in the code scan do **not** honour the inline ignore markers.

---

## 7. Fixed limits

| Limit | Value | Source |
|---|---|---|
| Sync timeout | 3 min | `devops_engine.go` |
| First-sync look-back | 30 days | provider sync files |
| GitHub audit pages per sync | 10 × 100 | `devops_github.go` |
| GitHub repository-list pages | 10 × 100 per endpoint | `devops_github.go` |
| GitHub commit pages per repository | 5 × 100 | `devops_github.go` |
| Rate-limit wait (GitHub) | up to 90 s, 2 retries; longer waits fail the call | `devops_github.go` |
| Stored patch per file | 2 000 characters, after redaction | `truncatePatch` |
| Webhook body | 1 MB | webhook handlers |
| Webhook rate | 60 / min / connector | `webhookLimiter` |
| Code scan input | last 500 stored commits of the connector | `codescan.go` |
| SAST files per repository | 1 000 (highest-risk first) | `maxFilesPerRepo` |
| SAST file size | 300 000 bytes; lockfiles 5 MiB | `maxFileBytes`, `sastSizeLimit` |
| GitLab tree | 20 pages × 100 entries | `fetchGitLabTree` |
| Semgrep | 3 min per repository, 30 s per file, 1 000 MB memory, 2 jobs | `runSemgrep` |
| CodeQL | 5 + 5 min, 10 min per repository | `runCodeQL` |
| Async scan job | 10 min total; job state kept 30 min | `async_jobs.go` |
| SCA | 50 manifests, 8 MiB each, 2 000 unique packages, 150 advisory look-ups, 60 s | `sast_sca.go` |
| Posture | 100 repositories per run (GitHub: first 200 repositories listed) | `devops_posture.go` |
| Unified findings API | 1 000 rows returned (total still counted) | `findings_unified.go` |
| Repositories table | 300 rows shown; Findings table 500 rows | `CodeOverview.jsx` |

---

## 8. Retention

| Data | Kept | Control |
|---|---|---|
| `devops.*` events | Event retention of the events hypertable, default 90 days | `retention_days` in the agent-ingest backend `server.yaml` (7-3650), applied by `applyRetention` in `backend/cmd/server/main.go` |
| Stored commits and redacted patches (`devops_commits`) | Until the connector is deleted | none |
| Code scan results (`code_scan_results`) | **Every run is kept** (one new row per run). Pages show only the latest. | none; delete by hand if needed |
| SAST results (`sast_results`) | One row per (connector, repository, branch). A re-scan overwrites it and clears the AI summary. | none |
| Posture result | Last result per connector, in settings key `devops.posture.last.{id}` (maximum 4 MB). Survives connector deletion. | none |
| Alerts | Alert retention of the platform | platform setting |
| Webhook delivery IDs, async job state | In memory only | lost on restart |
