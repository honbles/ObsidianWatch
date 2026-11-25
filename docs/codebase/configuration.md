# Codebase security: configuration

This document lists every connector field, every setting that changes the behaviour of the Code feature, and the fixed values in the code that you cannot change. For setup steps, see [deployment.md](deployment.md). For detection content, see [capability.md](capability.md).

> **Verification status.** Written from the source code. None of the settings below have been exercised against live GitHub, GitLab or Azure DevOps accounts during this documentation pass.

---

## 1. Connector record

A connector is one row in `devops_connectors`. Exactly one connector can exist per `(provider, org)` pair (unique index from migration `028_connector_uniqueness.sql`). Saving the same pair again updates the existing row: new credentials, new label, and status reset to `pending`. The webhook secret is kept (a new one is generated only when the connector has none), so webhooks already configured at the provider keep verifying.

| Field | Set by | Meaning |
|---|---|---|
| `id` | server | Numeric ID. Appears in webhook URLs and page URLs. |
| `provider` | form | `github`, `gitlab` or `azuredevops` |
| `org` | form | GitHub org or user login; GitLab group path or user name; Azure DevOps organisation |
| `label` | form | The text returned by **Test Connection** (for example `Connected: Acme Inc`), or `org` |
| `credentials.token` | form | PAT or access token. Encrypted at rest. Masked in responses. |
| `credentials.base_url` | form | GitLab: instance root. Azure DevOps: the full organisation or collection URL, used by sync, posture and SAST (Azure DevOps Server works this way). Validated (HTTPS, no credentials, no loopback / link-local / private IP literals unless `OW_ALLOW_PRIVATE_DEVOPS=true`); the same address rules are applied again to the resolved address at connect time and on redirects. Normalised to `scheme://host[:port][/path]` with no trailing slash. |
| `credentials.project` | form (Azure DevOps) | When set, only this project is synced, checked by posture and offered for SAST |
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
| API root | `https://api.github.com` (fixed) | `base_url` or `https://gitlab.com` | `base_url` or `https://dev.azure.com/{org}` |
| Auth header | `Authorization: Bearer <token>` | `PRIVATE-TOKEN: <token>` | HTTP Basic, empty user, PAT as password |
| Repository discovery | `/orgs/{org}/repos`, plus `/user/repos?affiliation=owner` for personal accounts; only repositories owned by the connector's org are kept; up to 10 pages of 100 each | `/groups/{g}/projects` (with subgroups), else `/users/{u}/projects`, else the single project; up to 20 pages of 100 | Every project (or only `project`), then every Git repository in it |
| Audit source | Org audit log (Enterprise Cloud), else the public user-events feed | Group audit events (Premium) | Organisation audit log (auditing must be on) |
| Audit paging | Up to 10 pages of 100, resumed from a cursor | Up to 20 pages of 100 since the last sync | Up to 10 pages of 200 since the last sync |
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
| SAST source | `git clone` (API tarball fallback) | `git clone` (per-file API fallback) | `git clone` (per-file API fallback) |
| Event `host` value | Org, or repository for audit entries with a repo | Group | Organisation |

---

## 3. Scan scoping

There is no setting to include or exclude organisations, repositories or branches. Scope follows from the token and from the code:

| Scope | Polling | SAST | Code scan | Posture |
|---|---|---|---|---|
| Organisations | One per connector. Repositories of other organisations or users visible to the token are ignored. | Same as the repository list | Repositories with stored commits | One per connector |
| Repositories | All repositories found (see section 2) | All repositories that appear in the last 500 stored commits, or one selected repository | Repositories in the last 500 stored commits | First 100 non-archived, non-fork (GitHub) / non-empty (GitLab) / enabled (Azure DevOps) repositories |
| Branches | Default branch | Default branch, or the branch typed in the **Branch** field (one repository at a time) | Whatever was polled (default branch) | Default branch |

**Narrowing the scope.** Use a token that sees only the wanted repositories, for example a GitHub fine-grained token restricted to selected repositories, or a GitLab group or project access token.

**SAST: one repository or all.** On the **SAST** tab of a connector:

- **Repository** = `All repos`: scans every repository that appears in the last 500 stored commits. Results are saved under repository `''`.
- A specific repository: calls `POST .../sast?repo=<full name>&branch=<branch>`. The list comes from `GET .../sast/repos`, which queries the provider live. For GitLab it lists the connector's group (with subgroups) or namespace, all pages.
- **Branch**: free text. Blank or `HEAD` means the default branch.

One SAST job per connector **and repository/branch** can run at a time when started from the UI: the job lock key is the method, route path and query string (without `async`). Starting the same scan again returns the running job's ID; another repository starts its own job.

---

## 4. Schedules

| Activity | Schedule | Configurable |
|---|---|---|
| Connector polling | At start-up, then every 5 minutes | no |
| Sync timeout | 3 minutes per connector per run | no |
| Detection on `devops.*` events | Every detection-engine cycle (`detectionInterval()`) | Detection-engine setting, not specific to Code |
| SAST (all engines) | Manual; on push to the default branch; daily or weekly; on every pull/merge request update | **Automation** tab, per connector (capability.md section 4.10) |
| Code scan, posture | Manual only | no |
| Automation schedule check | Every 10 minutes | no |
| Webhook replay memory | 24 hours, in memory | no |

---

## 4a. Automation policy

Per connector, Automation tab (setting `code.policy.{id}`): `pr_checks`, `pr_comments`, `pr_codeql`, `pr_ai_fixes`, `block_on` (none/critical/high/medium/low, default critical), `max_comments` (1-100, default 20), `scan_on_push`, `schedule` (off/daily/weekly), `schedule_hour` (UTC, default 2), `repos`. All off by default except comments. See capability.md 4.10 and deployment.md 6b.

---

## 5. Scanner toggles

There are no per-scanner switches in the UI or the settings table. What runs is decided by what is installed:

| Engine | Runs when | Notes |
|---|---|---|
| Source | always | `git clone` of the branch; whole history unless `OW_SAST_SECRET_HISTORY=false`; limit `OW_SAST_MAX_REPO_MB` (default 2048). Falls back to the provider API download. |
| History secrets | full clone | `gitleaks` on `PATH`, else the built-in patterns |
| Pattern rules | `opengrep` or `semgrep` on `PATH` **and** a rules directory | Rules from `OW_SEMGREP_RULES`, `/opt/obsidianwatch/rules/opengrep` (bundled), or `/semgrep-rules` (mounted). Never the Semgrep registry. |
| Trivy | `trivy` on `PATH` | Cache `OW_TRIVY_CACHE_DIR` (default `/var/cache/trivy`). `OW_SCANNER_DB_UPDATE=false` never refreshes the databases. |
| OSV | Trivy missing or its vulnerability scan unavailable | Online lookup at `api.osv.dev` |
| CodeQL | `codeql` on `PATH` | Every supported language with 3+ files (up to 4), `security-extended` suite |

To disable an engine, remove its binary from the image. The SAST tab and the stored `engines` report show which engines ran.


Built-in SAST rules cannot be turned off one by one. `GET /api/v1/sast-rules` lists them, read-only. The platform detection rules (`DEV-001` … `DEV-031`, `CODE-RT-001`) follow the general detection toggles, severity overrides and allow-lists. See capability.md section 6.

---

## 6. Suppression and false-positive handling

SAST findings have triage decisions and triage rules (capability.md section 4.12): false positive, accepted risk, confirmed; dismissed findings are hidden, never block PR checks and raise no CODE-RT-001 alert. Other controls:

| Mechanism | Applies to | How |
|---|---|---|
| Inline ignore marker | Commit secret scanner only (the one that raises `devops.secret_push`) | A line containing any of `ow:ignore`, `pragma: allowlist secret`, `nosec`, `gitleaks:allow`, `noqa: secret` (case-insensitive) is skipped |
| Placeholder and entropy filter | Commit secret scanner, generic `key = value` patterns only | Values containing `example`, `changeme`, `test`, `todo`, `password`, `secret`, `token`, `${`, `{{`, `process.env`, `os.getenv`, `null`, `none` and similar are ignored. So are values with Shannon entropy below 3.0 bits per character, and values that repeat one character. |
| Safe file suffixes | Sensitive-file events | `.pub`, `.example`, `.sample`, `.template`, `.dist` are never treated as secret files. Deleted files are ignored. |
| Vendor paths | SAST | Path segments `vendor`, `node_modules`, `.git`, `__pycache__`, `.venv`, `venv`, `.gradle`, `site-packages`, `bower_components`, and files ending `.min.js` / `.bundle.js`, are not scanned |
| Semgrep `nosemgrep` comments | Semgrep findings | Native Semgrep behaviour |
| Re-scan | All scanners | A finding disappears from the pages when the latest scan no longer reports it |
| Detection allow-lists / rule toggles | `DEV-*` alerts | General detection settings (`engineGate`) |
| Triage rules | SAST findings: a rule for a repository or all, optional path prefix and expiry | Automation tab / SAST tab hint (admin) |
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
| Clone | 5 min, 2 048 MB | `cloneRepo` |
| History secrets | 5 min (gitleaks) / 4 min and 5 000 commits (built-in) | `runHistorySecrets` |
| Pattern rules | 10 min per repository (`OW_SEMGREP_TIMEOUT_MIN`), 30 s per file, 1 000 MB memory, 2 jobs; one pattern-rule or CodeQL run at a time across scans (`OW_SAST_HEAVY_SLOTS`) | `runSemgrep` |
| Trivy | 9 min | `runTrivy` |
| CodeQL | 12 min per repository for all languages, 2 threads | `runCodeQLAll` |
| SAST job | 40 min | `jobRuntimeFor` |
| Async scan job | 10 min total (SAST 40 min); job state kept 30 min | `async_jobs.go` |
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
| Posture result | Last result per connector, in settings key `devops.posture.last.{id}` (maximum 4 MB). Removed with the connector. | none |
| Automated scan jobs (`code_scan_jobs`) | Until the connector is deleted | none |
| Triage decisions and rules | Until deleted or the connector is deleted; rules may expire | Automation tab |
| Runtime package index (`runtime_packages`) | 14 days after last seen | none |
| AI fix cache (`code_fix_cache`) | 30 days | none |
| Alerts | Alert retention of the platform | platform setting |
| Webhook delivery IDs, async job state | In memory only | lost on restart |
