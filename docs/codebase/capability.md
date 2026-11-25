# Codebase security: capability reference

This document describes, end to end, what the Code feature collects from each Git platform, every scanning layer and its rules, how findings are identified and merged, which alerts DevOps activity raises, and what each page shows. Everything here is derived from the source code at the time of writing. Rule tables are generated from the rule definitions.

See also [deployment.md](deployment.md) and [configuration.md](configuration.md).

> **Verification status.** Nothing in this document has been verified against a live GitHub, GitLab or Azure DevOps account. Field names that the code reads from provider responses (audit-log actions, webhook payload fields) are taken from the code. Where the code expects a field the provider may not send, the text says so and marks it *(unverified)*. Section 10 lists the open points.

---

## 1. Data flow overview

```
 GitHub / GitLab / Azure DevOps
   │  poll every 5 min (DevOpsEngine)         │  webhooks (optional)
   ▼                                          ▼
 commits + redacted diffs ──► devops_commits   devops.* events ──► events table
 audit / pipeline / member events ─────────────────────────────►  (agent-ingest DB)
                                                                     │
                                       detection engine (DEV-001…021) ──► alerts
 manual scans:
   Code scan  ── over stored diffs ──────────► code_scan_results
   SAST + SCA ── downloads source ───────────► sast_results
   Posture    ── provider settings APIs ─────► settings: devops.posture.last.{id}
                                                     │
                     Code → Repositories pages, Insights → Code findings, GET /api/v1/findings
```

Two separate result paths exist:

- **Events and alerts.** Activity from polling and webhooks becomes `devops.*` events. Detection signatures turn them into alerts.
- **Findings.** Results of the three manual scanners (code scan, SAST/SCA, posture). They are shown on the Repositories pages. They are not alerts.

Implemented in: `devops_engine.go`, `devops_*.go`, `codescan.go`, `sast_*.go`, `devops_posture.go`, `findings_unified.go`, `detection_engine.go`.

---

## 2. What is collected by polling

Every polled item becomes a row in the events table with `os = "devops"`, `agent_id = "devops:{connector id}"`, and an event type starting with `devops.`. Commits are also stored in `devops_commits`.

### 2.1 GitHub

| Source | API | What is kept | Event type | Severity |
|---|---|---|---|---|
| Org audit log | `GET /orgs/{org}/audit-log?include=all` (cursor `after=`) | Every entry except `git.*` (clone/fetch) and entries without an action | `devops.<action with . replaced by _>`, for example `devops.repo_destroy` | From the table in 2.1.1; unrated actions get 1 |
| Public user events (fallback when the audit log fails) | `GET /users/{org}/events` | All event types except Watch, Issues, IssueComment, CommitComment, Gollum | `devops.push`, `devops.repo_create`, `devops.delete_<reftype>`, `devops.repo_make_public`, `devops.member_<action>`, `devops.fork`, `devops.release_<action>`, `devops.pull_request_<action>`, other `devops.<type>` | 1 by default; repo create 4; delete 2 (4 on a protected branch); make public 5; member 4; fork 2; release 2 |
| Repository list | `/orgs/{org}/repos` and `/user/repos` | Name, private flag, default branch | none (used to drive commit polling) | – |
| Commits | `/repos/{r}/commits?since=` then `/repos/{r}/commits/{sha}` per commit | Author name, e-mail and login, message, URL, file list with additions, deletions and status, patch (secrets redacted, first 2 000 characters per file), signature verification, committer e-mail | `devops.push` per commit, plus the commit-derived events in 2.4 | 1 |

"Protected branch" in this document always means the name-based check `isProtectedBranch`: `main`, `master`, `develop`, `development`, `trunk`, `production`, `prod`, and names starting with `release/` or `release-`. It does not query the platform's real branch protection.

#### 2.1.1 GitHub audit-log severity

Matching is exact or by dotted prefix (`hook` matches `hook.create`, not `hookup`).

| Severity | Actions |
|---|---|
| 5 (critical) | `repo.destroy`, `audit_log_streaming.destroy`, `audit_log_streaming.update`, `audit_log_streaming.disable`, `org.disable_two_factor_requirement`, `business.disable_two_factor_requirement`, `org.disable_saml`, `org.disable_oauth_app_restrictions`, `repository_visibility_change.enable`, and any action ending in `.make_public` or `.set_public` |
| 4 (high) | `org.add_member`, `org.remove_member`, `org.update_member`, `org.add_billing_manager`, `org.invite_member`, `org.update_actions_secret`, `org.remove_actions_secret`, `repo.create`, `repo.access`, `repo.transfer`, `protected_branch.destroy`, `protected_branch.update_admin_enforcement`, `protected_branch.update_require_code_owner_reviews`, `protected_branch.policy_override`, `repository_ruleset.destroy`, `repository_ruleset.update`, `hook.create`, `hook.destroy`, `hook.config_changed`, `oauth_application.create`, `integration_installation.create`, `repository_secret_scanning.disable`, `repository_secret_scanning_push_protection.disable`, `repository_vulnerability_alerts.disable`, `dependabot_alerts.disable`, `deploy_key.create`, `public_key.create`, `personal_access_token.create`, `audit_log_streaming.create` |
| 3 (medium) | `repo.rename`, `repo.archived`, `repo.unarchived`, `team.add_member`, `team.remove_member`, `team.add_repository`, `org.update_default_repository_permission`, `protected_branch.create`, `protected_branch.update`, `repository_ruleset.create`, `personal_access_token.created`, `personal_access_token_request`, `runners.create`, `org.runner_group_created`, `workflows.approve_workflow_job` |
| 1 (info) | Everything else |

### 2.2 GitLab

| Source | API | What is kept | Event type | Severity |
|---|---|---|---|---|
| Group audit events (Premium) | `GET /groups/{g}/audit_events?created_after=` | Entries whose `action_name` is rated (below) | `devops.<action_name with spaces replaced by _>` | 4 or 2 |
| Project list | `/groups/{g}/projects?include_subgroups=true` (first 50), else `/users/{u}/projects` | ID, path, default branch | none | – |
| Pipelines | `/projects/{id}/pipelines?updated_after=` (50) | ID, status, source, ref, SHA, URL | `devops.pipeline_run` | 1; failed 2 |
| Project events (any tier) | `/projects/{id}/events?after=` (100) | `joined`, `left`, `expired`, `removed` → member change; `created`, `destroyed` of the project | `devops.member_change`, `devops.project_created`, `devops.project_destroyed` | 3 |
| Commits | `/projects/{id}/repository/commits?since=` (20) then `/commits/{sha}/diff` | As GitHub, without login, signature and committer | `devops.push` and the events in 2.4 | 1 |

GitLab audit severity (substring match on `action_name`):

| Severity | Contains |
|---|---|
| 4 | `added user`, `removed user`, `destroyed`, `transferred`, `made public`, `changed visibility`, `enabled two-factor`, `disabled two-factor`, `added deploy key`, `created personal access token` |
| 2 | `added`, `removed`, `changed`, `updated`, `created` |
| dropped | anything else |

*(unverified)* The GitLab audit-events API documents the action inside `details` (for example `details.custom_message`, `event_name`). The code reads a top-level `action_name`. If that field is absent, every group audit entry is dropped.

### 2.3 Azure DevOps

| Source | API | What is kept | Event type | Severity |
|---|---|---|---|---|
| Projects | `_apis/projects` | Name | none | – |
| Audit log | `auditservice.dev.azure.com/{org}/_apis/audit/auditlog?startTime=` (10 × 200) | Rated entries, with actor display name and IP address | `devops.audit` | 4 or 2 |
| Builds | `{project}/_apis/build/builds?minTime=` (50) | ID, number, pipeline name, repository, branch, status, result, reason, requested-for | `devops.pipeline_run` | 1; failed 2 |
| Repositories | `{project}/_apis/git/repositories` | ID, name, default branch | none | – |
| Commits | `.../commits?searchCriteria.fromDate=&$top=20` then `.../commits/{id}/changes` | Author, message, file paths and change types (no content) | `devops.push`, plus `devops.secret_push` (path match only) and `devops.cicd_modified` | 1 |

Azure DevOps audit severity (substring match on `actionId`, case-insensitive):

| Severity | Contains |
|---|---|
| 4 | `modifypermission`, `removepermission`, `projectcollectionadmin`, `addmember`, `removemember`, `grouprenamed`, `serviceconnection`, `token.pat`, `token.ssh`, `token.delete`, `policy.policyconfigremoved`, `policy.policyconfigmodified`, `bypassed`, `repositorydeleted`, `project.delete`, `organization.`, `extension.`, `agentpool`, `securefile`, `library.variablegroup` |
| 2 | `create`, `modif`, `delete`, `remove`, `add`, `update`, `change` |
| dropped | anything else |

All Azure DevOps audit entries share the event type `devops.audit`. The action is in the raw `actionId` field. No DEV signature matches `devops.audit` by action (see section 6), so these events are searchable but raise no DevOps alert.

### 2.4 Events derived from each polled commit

| Event type | Condition | Severity | GitHub | GitLab | Azure DevOps |
|---|---|---|---|---|---|
| `devops.push` | Always, one per commit | 1 | yes | yes | yes |
| `devops.secret_push` | An added diff line matches the commit secret scanner (section 4.1). Azure DevOps: a file **path** matches a provider-specific pattern. | 5 (Azure DevOps 4) | yes | yes | path only |
| `devops.cicd_modified` | A changed file is a CI/CD file: path starts with `.github/workflows/`, or equals `.gitlab-ci.yml`, `azure-pipelines.yml`, `Jenkinsfile`, `.circleci/config.yml`, `.travis.yml`, `bitbucket-pipelines.yml`, `cloudbuild.yaml`. GitLab and Azure DevOps use a substring match on the path. | GitHub 3, or 4 with a risky addition; GitLab 4; Azure DevOps 3 | yes | yes | yes |
| `devops.sensitive_file` | A non-deleted file matches a sensitive name (section 4.1.1) | 3 | yes | yes | no |
| `devops.mass_deletion` | ≥ 1 000 deleted lines and deletions > 5 × additions | 3 | yes | no | no |
| `devops.dependency_change` | A non-deleted dependency manifest changed (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.mod`, `go.sum`, `requirements.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`, `pom.xml`, `build.gradle`, `Gemfile`, `Gemfile.lock`, `Cargo.toml`, `Cargo.lock`, `composer.json`, `composer.lock`) | 2 | yes | no | no |

**Risky pipeline additions** (GitHub only, on `+` lines of a CI/CD file; the first match is recorded in `risky`):

| Pattern | Reason recorded |
|---|---|
| `pull_request_target` | `pull_request_target trigger` |
| `secrets: inherit` | `secrets: inherit` |
| `self-hosted` | `self-hosted runner` |
| `curl` or `wget` together with `\| bash`, `\|bash` or `\| sh` | `download piped to shell` |

**Event IDs and timestamps.** Commit events have stable IDs such as `devops:{sha}:push`, `devops:gl:{sha}:secret` or `devops:az:{sha}:cicd`. Their time is the commit time; zero or future times fall back to the receive time. Because events are inserted with `ON CONFLICT (id, time) DO NOTHING`, the 2-minute overlap and manual re-syncs do not create duplicates. Exception: GitLab `secret_push`, `cicd_modified` and `sensitive_file` events use the raw commit time without the future-date guard.

**Stored commits.** The commit key is `{connector}:{first 4 bytes of sha256(repo) as hex}:{sha}`. Identical SHAs in forks or in two connectors therefore stay separate. The branch stored is the repository's default branch, because only the default branch is polled.

---

## 3. What is collected by webhooks

Webhook events have `time` = receive time.

### 3.1 GitHub (`X-GitHub-Event`)

| Event | Event type produced | Severity |
|---|---|---|
| `push` | `devops.push` with `ref`, `branch`, `pusher`, `commits` (count), `forced`, `deleted`, `created`. No diff is fetched; polling handles content. | 1; force push or deletion 2; on a protected branch 4 |
| `repository` | `devops.repo_<action>` (for example `repo_publicized`, `repo_deleted`, `repo_transferred`) | 2; `publicized` 5; `deleted`, `transferred` 4 |
| `member` | `devops.member_<action>` | 3; `added` 4 |
| `workflow_run` | `devops.workflow_run` with `conclusion`, `branch` | 1 |
| `org` | `devops.org_<action>` | Audit severity of `org.<action>`, else 2. GitHub sends this event as `organization`, so this branch is not reached in practice; see the next row. |
| `organization`, `team`, `team_add`, `membership`, `deploy_key`, `installation`, `installation_repositories`, `github_app_authorization` | `devops.<event>_<action>` | 3; `created` or `added` 4 |
| `branch_protection_rule`, `branch_protection_configuration`, `repository_ruleset`, `security_and_analysis`, `repository_import` | `devops.<event>_<action>` | 3; `deleted` or `disabled` 4 |
| `secret_scanning_alert`, `secret_scanning_alert_location`, `code_scanning_alert`, `dependabot_alert`, `repository_vulnerability_alert`, `repository_advisory`, `security_advisory` | `devops.<event>_<action>` | 3; `created` or `reopened` 4 |
| `create`, `delete` | `devops.create_<ref_type>`, `devops.delete_<ref_type>` | create 1; delete 2; delete of a protected branch 4 |
| `public` | `devops.repo_publicized` | 5 |
| `fork`, `release` | `devops.<event>_<action>` | 2 |
| `pull_request` (closed and merged) | `devops.pull_request_merged` with `base` | 1; into a protected branch 2 |
| other `pull_request`, `pull_request_review`, `pull_request_review_comment`, `workflow_job` | `devops.<event>_<action>` | 1 |
| `personal_access_token_request` | `devops.personal_access_token_request_<action>` | 3 |
| `ping`, `star`, `watch`, `issues`, `issue_comment`, `status`, `check_run`, `check_suite`, `gollum`, `label`, `milestone`, `project`, `projects_v2`, `discussion`, `discussion_comment`, `sponsorship` | dropped | – |
| any other event | `devops.<event>[_<action>]` | 1 |

### 3.2 GitLab (`object_kind` or `event_name`)

| Event | Event type | Severity |
|---|---|---|
| `push`, `tag_push` | `devops.push` (deleted = `after` is all zeros; created = `before` is all zeros). GitLab does not report force pushes, so `forced` is absent. | 1; deletion 2; deletion of a protected branch 4 |
| `project_create`, `project_destroy`, `project_transfer`, `project_rename`, `project_update` | `devops.repo_create`, `devops.repo_deleted`, `devops.repo_transfer`, `devops.repo_rename`, `devops.repo_update` | 2; destroy and transfer 4 |
| `user_add_to_team`, `user_add_to_group` | `devops.member_added` with `role` | 4 |
| `user_remove_from_team`, `user_remove_from_group` | `devops.member_removed` | 3 |
| `user_update_for_team`, `user_update_for_group` | `devops.member_updated` | 3 |
| `merge_request` with action `merge` | `devops.merge` | 1 |
| `pipeline` | `devops.workflow_run` | 1 |
| anything else | dropped | – |

### 3.3 Azure DevOps (`eventType`)

| Event | Event type | Severity |
|---|---|---|
| `git.push` | One `devops.push` per ref update (deleted / created from the all-zero object IDs) | 1; deletion 2; on a protected branch 4 |
| `git.pullrequest.merged` | `devops.merge` | 1 |
| `build.complete`, `ms.vss-pipelines.run-state-changed-event` | `devops.workflow_run` with conclusion and pipeline name | 1 |
| anything else | dropped | – |

### 3.4 Event IDs

With a delivery ID, webhook events get the ID `gh-wh:{delivery}:{n}`, `gl-wh:{uuid}:{n}` or `ado-wh:{id}:{n}`. Without one, the ID includes the receive time in nanoseconds, so a retried delivery creates a second event.

---

## 4. Scanning layers

| Layer | Input | Trigger | Stored in | Engine label |
|---|---|---|---|---|
| 4.1 Commit secret scanner | Added lines of polled diffs | Every sync | `devops.secret_push` events | – |
| 4.2 Code scan | Stored, redacted commit diffs (last 500 commits) | **Code Scan** tab | `code_scan_results` | – |
| 4.4 Built-in SAST rules | Downloaded source (4.3) | **SAST** tab | `sast_results` (but see 4.7) | `builtin` |
| 4.5 Semgrep / CodeQL | Downloaded source (4.3) | **SAST** tab | `sast_results` | `semgrep`, `codeql`, `semgrep+codeql` |
| 4.6 Dependency scan (SCA, OSV) | Lockfiles in the downloaded source | **SAST** tab | `sast_results` (but see 4.7) | `osv` |
| 4.8 IaC checks | Downloaded source | **SAST** tab (part of 4.4 / 4.5) | `sast_results` | `builtin` / `semgrep` |
| 4.9 Pipeline-change detection | Polled commits | Every sync | `devops.cicd_modified` events | – |
| 5 Posture | Provider settings APIs | **Posture** tab | settings `devops.posture.last.{id}` | – |

### 4.1 Commit secret scanner (sync time)

`lineHasSecret` runs on every added (`+`) diff line, for GitHub and GitLab. A line matching any rule raises `devops.secret_push` (alert DEV-001). `redactSecrets` uses the same rules to replace matches with `[REDACTED]` before a patch is stored or sent to an AI model. Rules have no ID in the code; they are numbered here by position.

| # | Detects | Kind |
|---|---|---|
| CS-1 | `aws_access_key_id` / `aws_secret_access_key` = value of 20+ characters | generic (value filtered) |
| CS-2 | `password`, `passwd`, `pwd`, `secret`, `api_key`, `apikey`, `api_secret`, `token`, `auth_token`, `access_token`, `private_key` = quoted value of 8+ characters | generic |
| CS-3 | `client_secret` / `client-secret` = value of 32+ characters | generic |
| CS-4 | AWS access key ID `AKIA…` / `ASIA…` | specific |
| CS-5 | GitHub tokens `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` | specific |
| CS-6 | GitHub fine-grained token `github_pat_` | specific |
| CS-7 | GitLab token `glpat-` | specific |
| CS-8 | PEM private key header (RSA, EC, DSA, OPENSSH, PGP) | specific |
| CS-9 | Slack token `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` | specific |
| CS-10 | Google API key `AIza…` | specific |
| CS-11 | SendGrid key `SG.…` | specific |
| CS-12 | Stripe live key `sk_live_` / `rk_live_` | specific |
| CS-13 | npm token `npm_` | specific |
| CS-14 | JSON Web Token `eyJ….eyJ….…` | specific |
| CS-15 | Database URL with password (`mysql`, `postgres(ql)`, `mongodb(+srv)`, `redis`, `amqp`) | specific |
| CS-16 | Azure storage connection string with `AccountKey` | specific |
| CS-17 | Slack incoming webhook URL | specific |

Generic rules apply the placeholder and entropy filter (configuration.md section 6). Specific rules always match. Lines with an ignore marker are skipped.

#### 4.1.1 Sensitive file names (sync time)

`.env`, `.env.local`, `.env.production`, `.env.staging`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `credentials.json`, `service-account.json`, `.aws/credentials`, `secrets.yaml`, `secrets.yml`, `terraform.tfvars`, `*.tfvars`. Matching is on the exact base name (or path suffix for `.aws/credentials`), case-insensitive. `*.ext` matches the extension. Files ending `.pub`, `.example`, `.sample`, `.template` or `.dist` never match.

### 4.2 Code scan (stored diffs)

`POST /api/v1/devops-connectors/{id}/code-scan` reads the connector's last 500 stored commits and scans each stored file diff. Findings are deduplicated by `category + title + file` (the repository is not part of the key, so the same path in two repositories is reported once). Every run inserts a new row in `code_scan_results`.

**Important limitation.** The stored patches are already redacted and cut to 2 000 characters per file at sync time. Most provider-specific secret patterns below therefore no longer match: the value is `[REDACTED]`. The "Generic Password" pattern still matches `password = "[REDACTED]"`, because `[REDACTED]` is 10 characters. Azure DevOps commits have no stored patch, so only the file-name checks apply.

Sensitive files (matched on the full path of every file in the diff):

| Title | Pattern | Severity |
|---|---|---|
| Environment file committed | path is exactly `.env`, `.env.local`, `.env.prod`, `.env.production`, `.env.staging` (repository root only) | critical |
| Certificate or private key file | ends `.pem`, `.key`, `.p12`, `.pfx`, `.cer`, `.crt` | critical |
| SSH private key | path is exactly `id_rsa`, `id_ecdsa`, `id_ed25519` (root only) | critical |
| AWS credentials file | ends `.aws/credentials` | critical |
| Secrets file | ends `secret(s).yml/yaml` or `credential(s).yml/yaml` | high |
| Terraform state file | ends `terraform.tfstate` | high |
| Kubernetes config file | ends `kubeconfig` | high |
| WordPress config (may contain DB credentials) | ends `wp-config.php` | medium |
| Database config file | ends `database.yml` / `database.yaml` | medium |

Secret patterns (on added lines; one finding per pattern per file; title is `<name> detected in commit`):

| Name | Severity |
|---|---|
| AWS Access Key | critical |
| AWS Secret Key | critical |
| Private Key Block | critical |
| GitHub Token | critical |
| Slack Token | critical |
| Stripe Key | critical |
| Google API Key | high |
| JWT Token | high |
| Generic Password | high |
| DB Connection String | high |
| Generic Token | medium |
| IP + Port Hardcoded | low |

Dangerous code patterns (on added lines, by file extension):

| Title | Extensions | Severity |
|---|---|---|
| eval() with user input | .js .ts .py .php .rb | high |
| exec() with user input | .js .ts .py .go .php | high |
| SQL string concatenation | .js .ts .py .php .java .go .cs | high |
| innerHTML assignment | .js .ts .jsx .tsx .html | medium |
| Hardcoded localhost URL | .js .ts .py .go .java .env | low |
| TODO: security comment | .js .ts .py .go .java .cs .php | info |
| Disabled SSL verification | .py .go .js .ts .yaml .yml | high |
| Hardcoded debug mode | .py .env .yaml .yml .json | medium |

Dependency checks (on added lines of the named file). These flag the **presence** of the package. The version is not compared.

| File | Packages flagged | Severity |
|---|---|---|
| `package.json` | lodash, axios, log4js, minimist, node-fetch, xmlhttprequest, marked, ejs | medium |
| `requirements.txt`, `Pipfile`, `Pipfile.lock` | django, flask, requests, pillow, cryptography, pyyaml, urllib3, jinja2 (when followed by a version operator) | medium |
| `go.mod` | github.com/dgrijalva/jwt-go, github.com/form3tech-oss/jwt-go, gopkg.in/yaml.v2 | high |

Implemented in: `codescan.go`.

### 4.3 SAST: file selection and source download

`POST /api/v1/devops-connectors/{id}/sast[?repo=&branch=]`:

1. **Repositories.** One selected repository, or every repository in the last 500 stored commits.
2. **File tree.** GitHub `git/trees/{branch}?recursive=1`; GitLab `repository/tree` (up to 2 000 entries); Azure DevOps `items?recursionLevel=full`.
3. **Filter.** Keep blobs that are source or configuration files: `.py .js .jsx .ts .tsx .mjs .cjs .vue .svelte .go .java .kt .kts .scala .groovy .swift .m .mm .php .c .cpp .cc .cxx .h .hpp .rb .cs .rs .lua .pl .pm .r .dart .tf .tfvars .yaml .yml .toml .sql .sh .bash .zsh .ps1 .bat .cmd .gradle .cfg .ini .properties .conf`, plus `Dockerfile*`, `Makefile`, `Jenkinsfile`, `Gemfile`, `Procfile`, `Vagrantfile`, `.env*`, `*.env`, and the manifests `package.json`, `package-lock.json`, `yarn.lock`, `requirements.txt`, `go.mod`, `Cargo.lock`, `composer.json`, `composer.lock`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `pom.xml`. Drop vendor paths and files over the size limit (300 000 bytes; 5 MiB for lockfiles).
4. **Cap.** Above 1 000 files, files are ranked and the first 1 000 kept. Order: CI files (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `.circleci/`); then Dockerfiles, `.env*`, `.sh`, `.ps1`, `.tf`; then main manifests; then other files; paths containing `test`, `mock` or `fixture` come last.
5. **Download.** GitHub: one tarball, with per-file download as the fallback. GitLab and Azure DevOps: one API call per file.
6. **Run the engines** in this order per repository: Semgrep → OSV dependency scan → built-in rules → CodeQL.
7. **Deduplicate** (4.7), count, and upsert one row per (connector, repository or `''`, branch).

### 4.4 Built-in SAST rules

208 regex rules (`sast_rules.go`). Each rule applies to files whose path matches its file pattern. It reports the **first** matching line per file (one finding per rule per file). Matching is per line, so patterns cannot span lines. The snippet is the matched line, trimmed to 120 characters. The list is also available from `GET /api/v1/sast-rules`.

The "Detects" column is the first sentence of the rule's own description. `any` rules apply to the extensions in their file pattern.

> These rules run on every SAST scan. Their results are then dropped by the deduplication step (section 4.7) and do not reach the pages. The table describes what the rules would report once that defect is fixed.

| ID | Language | Title | Detects | CWE | Severity |
|---|---|---|---|---|---|
| PY001 | python | SQL Injection | String formatting/concatenation used to build SQL query. | CWE-89 | critical |
| PY002 | python | OS Command Injection | User-controlled input passed to shell command. | CWE-78 | critical |
| PY003 | python | Unsafe Deserialization (pickle) | pickle.load/loads can execute arbitrary Python code when deserializing untrusted data. | CWE-502 | critical |
| PY004 | python | Use of eval() | eval() executes arbitrary Python code. | CWE-95 | high |
| PY005 | python | Server-Side Template Injection (SSTI) | User-controlled data passed directly to template engine. | CWE-94 | critical |
| PY006 | python | Weak Cryptographic Hash (MD5/SHA1) | MD5 and SHA1 are cryptographically broken. | CWE-327 | medium |
| PY007 | python | Path Traversal | User-controlled input used in file open(). | CWE-22 | high |
| PY008 | python | Unsafe YAML Deserialization | yaml.load() with FullLoader or no Loader can execute arbitrary Python code. | CWE-502 | high |
| PY009 | python | Debug Mode Enabled | Django/Flask DEBUG=True exposes stack traces, source code, and environment variables to users. | CWE-215 | medium |
| PY010 | python | SSL Certificate Verification Disabled | verify=False disables TLS certificate validation, allowing MITM attacks. | CWE-295 | high |
| JS001 | javascript | Cross-Site Scripting (XSS) - DOM Sink | Direct assignment to innerHTML/outerHTML or document.write() allows XSS if user-controlled data is used. | CWE-79 | high |
| JS002 | javascript | Code Injection via eval/Function | eval() and new Function() execute arbitrary JavaScript. | CWE-95 | high |
| JS003 | javascript | Prototype Pollution | Direct assignment to __proto__ or prototype can override Object properties, leading to RCE or auth bypass. | CWE-1321 | high |
| JS004 | javascript | Regular Expression DoS (ReDoS) | User-controlled input in RegExp can cause catastrophic backtracking, freezing the event loop. | CWE-1333 | medium |
| JS005 | javascript | JWT "none" Algorithm Vulnerability | Accepting "none" as a JWT algorithm allows attackers to forge tokens without a signature. | CWE-347 | critical |
| JS006 | javascript | Cookie Missing Security Flags | Cookies without httpOnly and secure flags are vulnerable to XSS theft and network interception. | CWE-614 | medium |
| JS007 | javascript | OS Command Injection (Node.js) | User input passed to child_process.exec() allows OS command injection. | CWE-78 | critical |
| JS008 | javascript | TLS Certificate Validation Disabled | Disabling TLS certificate validation allows man-in-the-middle attacks. | CWE-295 | high |
| JS009 | javascript | React dangerouslySetInnerHTML | dangerouslySetInnerHTML bypasses React's XSS protection. | CWE-79 | high |
| JS010 | javascript | Insecure Random for Security Tokens | Math.random() is not cryptographically secure and must not be used for security tokens. | CWE-338 | high |
| GO001 | go | SQL Injection | String concatenation or fmt.Sprintf used to build SQL query. | CWE-89 | critical |
| GO002 | go | OS Command Injection | String concatenation in exec.Command arguments can allow command injection. | CWE-78 | critical |
| GO003 | go | Path Traversal | User-controlled input in filepath.Join can escape intended directory with '../' sequences. | CWE-22 | high |
| GO004 | go | TLS Certificate Verification Disabled | InsecureSkipVerify:true disables all TLS certificate validation, allowing MITM attacks. | CWE-295 | high |
| GO005 | go | Weak Cryptographic Hash (MD5/SHA1) | MD5 and SHA1 are cryptographically broken for security purposes. | CWE-327 | medium |
| GO006 | go | HTTP Server with Default Mux | http.ListenAndServe with nil handler uses DefaultServeMux which may expose debug endpoints like /debug/pprof. | CWE-749 | medium |
| GO007 | go | Insecure Random (math/rand) for Security Tokens | math/rand is not cryptographically secure. | CWE-338 | high |
| GO008 | go | Outdated TLS Version (TLS 1.0/1.1) | TLS 1.0 and 1.1 are deprecated and have known vulnerabilities (BEAST, POODLE). | CWE-326 | high |
| JV001 | java | SQL Injection | String concatenation in SQL query construction. | CWE-89 | critical |
| JV002 | java | Java Deserialization | Java's ObjectInputStream.readObject() can execute arbitrary code if given a malicious serialized object. | CWE-502 | critical |
| JV003 | java | XML External Entity (XXE) | Default XML parsers in Java process external entities, enabling XXE attacks. | CWE-611 | high |
| JV004 | java | OS Command Injection | User input concatenated into Runtime.exec() or ProcessBuilder allows OS command injection. | CWE-78 | critical |
| JV005 | java | Weak Hash Algorithm (MD5/SHA-1) | MD5 and SHA-1 are broken for cryptographic use. | CWE-327 | medium |
| JV006 | java | Overly Permissive CORS | CORS wildcard (*) allows any origin to make cross-origin requests, enabling CSRF. | CWE-942 | medium |
| PHP001 | php | SQL Injection | Unsanitized $_GET/$_POST data in SQL query. | CWE-89 | critical |
| PHP002 | php | OS Command Injection | User-supplied data in shell execution function. | CWE-78 | critical |
| PHP003 | php | Remote Code Execution via eval() | User input in eval() = instant remote code execution. | CWE-95 | critical |
| PHP004 | php | Remote/Local File Inclusion (RFI/LFI) | User-controlled file path in include/require. | CWE-98 | critical |
| PHP005 | php | Reflected XSS | Unsanitized user input echoed directly to output. | CWE-79 | high |
| PHP006 | php | Weak Password Hashing (MD5/SHA1) | MD5/SHA1 for passwords is trivially cracked with GPU rainbow tables. | CWE-916 | critical |
| C001 | c | Unsafe String Function (Buffer Overflow) | strcpy/strcat/gets/sprintf do not check buffer bounds and can cause stack/heap overflow. | CWE-120 | high |
| C002 | c | Format String Vulnerability | User-controlled string as printf format argument allows reading/writing arbitrary memory. | CWE-134 | high |
| C003 | c | Integer Overflow in Memory Allocation | Multiplication in malloc/calloc size argument can overflow, allocating less memory than expected. | CWE-190 | medium |
| C004 | c | OS Command Injection via system() | User-controlled input in system() allows arbitrary command execution. | CWE-78 | critical |
| C005 | c | Double Free | Freeing the same memory twice causes heap corruption, potentially exploitable. | CWE-415 | high |
| ANY001 | any | Hardcoded Credential | Hardcoded secret or credential in source code. | CWE-798 | high |
| ANY002 | any | AWS Access Key ID Exposed | AWS Access Key ID found in source code. | CWE-798 | critical |
| ANY003 | any | Private Key in Source Code | A private key was committed to source code. | CWE-321 | critical |
| PY011 | python | Server-Side Request Forgery (SSRF) | User-controlled URL passed to requests library. | CWE-918 | high |
| PY012 | python | Open Redirect | User-controlled redirect destination. | CWE-601 | medium |
| PY013 | python | Django SECRET_KEY Exposed or Weak | Hardcoded or weak Django SECRET_KEY. | CWE-798 | critical |
| PY014 | python | Django ALLOWED_HOSTS Wildcard | ALLOWED_HOSTS = ['*'] allows HTTP Host header attacks. | CWE-183 | medium |
| PY015 | python | Insufficient Random Data Length | Token generated with fewer than 16 bytes (128 bits) of entropy is vulnerable to brute force. | CWE-331 | low |
| PY016 | python | Insecure Random (random module) for Security Token | Python's random module is not cryptographically secure. | CWE-338 | high |
| PY017 | python | AES-ECB Mode - Insecure Block Cipher Mode | ECB mode is deterministic and leaks patterns. | CWE-327 | high |
| PY018 | python | LDAP Injection | User-controlled input in LDAP bind or search. | CWE-90 | high |
| PY019 | python | JWT Signature Verification Disabled | JWT decoded without signature verification allows attackers to forge tokens. | CWE-347 | critical |
| PY020 | python | Unsafe Deserialization (marshal) | Python marshal is not secure against malformed data and can cause RCE. | CWE-502 | critical |
| JS011 | javascript | Server-Side Request Forgery (SSRF) | User-controlled URL in server-side HTTP request. | CWE-918 | high |
| JS012 | javascript | Sensitive Data in localStorage | localStorage is accessible to any JavaScript on the page. | CWE-312 | medium |
| JS013 | javascript | postMessage Without Origin Validation | Receiving postMessage without checking event.origin allows any window to send commands. | CWE-346 | medium |
| JS014 | javascript | Electron nodeIntegration Enabled | nodeIntegration:true in Electron allows any web content to execute Node.js code = RCE. | CWE-78 | critical |
| JS015 | javascript | NoSQL Injection (MongoDB) | User-controlled object passed directly to MongoDB .find(). | CWE-943 | high |
| JS016 | javascript | Path Traversal (Node.js) | User input in path.join/resolve can escape intended directory with '../'. | CWE-22 | high |
| JS017 | javascript | Dynamic require() with User Input | User-controlled module name in require() can load arbitrary files or execute code. | CWE-706 | critical |
| JS018 | javascript | Clickjacking Protection Disabled | X-Frame-Options or frameguard disabled. | CWE-1021 | medium |
| JS019 | javascript | Unsafe Deserialization (node-serialize) | node-serialize has a known RCE vulnerability (CVE-2017-5941). | CWE-502 | critical |
| JS020 | javascript | Prototype Pollution via Object.assign/merge | Merging user-controlled objects into existing objects can pollute Object.prototype. | CWE-1321 | high |
| GO009 | go | Server-Side Request Forgery (SSRF) | User-controlled URL in outbound HTTP request. | CWE-918 | high |
| GO010 | go | XXE - XML Parsing (Go) | Go's encoding/xml processes external entities by default in some configurations. | CWE-611 | medium |
| GO011 | go | SQL Injection via GORM Raw Query | String concatenation in GORM Raw/Exec query bypasses ORM protections. | CWE-89 | critical |
| GO012 | go | Open Redirect | User-controlled redirect URL. | CWE-601 | medium |
| GO013 | go | HTTP Response Header Injection | User-controlled value in HTTP response header. | CWE-113 | medium |
| GO014 | go | Certificate Parsing - Verify Error Handling | Certificate parsing errors must be checked. | CWE-295 | info |
| JV007 | java | Server-Side Request Forgery (SSRF) | User-controlled URL in server-side HTTP request. | CWE-918 | high |
| JV008 | java | JNDI Injection (Log4Shell Pattern) | JNDI lookup with user-controlled input. | CWE-917 | critical |
| JV009 | java | Spring Expression Language (SpEL) Injection | User-controlled input in SpEL expression can execute arbitrary Java code. | CWE-94 | critical |
| JV010 | java | LDAP Injection | User input in LDAP search filter. | CWE-90 | high |
| JV011 | java | XPath Injection | User input in XPath query can read arbitrary XML data or bypass authentication. | CWE-643 | high |
| JV012 | java | Spring @Value Binding to Sensitive Property | Sensitive configuration values injected via @Value may be exposed in stack traces or actuator endpoints. | CWE-312 | medium |
| PHP007 | php | Open Redirect | User-controlled redirect URL in Location header. | CWE-601 | medium |
| PHP008 | php | Server-Side Request Forgery (SSRF) | User-controlled URL in file_get_contents or cURL. | CWE-918 | high |
| PHP009 | php | PHP Object Injection via unserialize() | Deserializing user input with unserialize() can trigger __wakeup/__destruct magic methods = RCE. | CWE-502 | critical |
| PHP010 | php | Variable Injection via extract()/parse_str() | extract($_GET) lets attackers overwrite any variable including $db, $auth, $admin. | CWE-621 | critical |
| PHP011 | php | PHP Type Juggling (== vs ===) | PHP's loose comparison (==) has surprising coercions: '0e123' == '0e456' == 0 == false == ''. | CWE-697 | medium |
| PHP012 | php | RCE via preg_replace with /e Modifier | preg_replace with /e flag evaluates the replacement as PHP code = RCE. | CWE-95 | critical |
| C006 | c | Insecure Random (rand/srand) for Security | rand() seeded with time() is predictable. | CWE-338 | high |
| C007 | c | Stack-Based Buffer Overflow | Fixed-size stack buffer followed by an unbounded write function. | CWE-121 | critical |
| C008 | c | Use-After-Free Pattern | Pointer used after being freed. | CWE-416 | high |
| C009 | c | Unsafe Signal Handler | Signal handlers must only call async-signal-safe functions. | CWE-364 | medium |
| RB001 | ruby | SQL Injection (Ruby/ActiveRecord) | String interpolation in ActiveRecord query bypasses parameterization. | CWE-89 | critical |
| RB002 | ruby | Template Injection (ERB) | User input in ERB template executes arbitrary Ruby code. | CWE-94 | critical |
| RB003 | ruby | Dynamic Method Invocation via send() | send() with user-controlled method name can invoke any Ruby method including system(), eval(). | CWE-94 | critical |
| RB004 | ruby | Ruby YAML Deserialization RCE | YAML.load() with untrusted input executes arbitrary Ruby code (Psych gadget chain). | CWE-502 | critical |
| RB005 | ruby | OS Command Injection (Ruby) | User input interpolated into shell command string. | CWE-78 | critical |
| CS001 | csharp | SQL Injection (C#/ADO.NET) | String concatenation in SqlCommand. | CWE-89 | critical |
| CS002 | csharp | .NET Unsafe Deserialization | BinaryFormatter and related serializers are vulnerable to deserialization attacks and are banned in .NET 5+. | CWE-502 | critical |
| CS003 | csharp | SSRF (.NET) | User-controlled URL in server-side HTTP request. | CWE-918 | high |
| CS004 | csharp | OS Command Injection (C#) | User-controlled input in Process.Start or ProcessStartInfo. | CWE-78 | critical |
| CS005 | csharp | XXE - XML Parsing (.NET) | .NET XML parsers may process external entities by default in older versions. | CWE-611 | medium |
| RS001 | rust | Unsafe Block | unsafe{} blocks bypass Rust's memory safety guarantees. | CWE-119 | medium |
| RS002 | rust | unwrap()/expect() May Panic in Production | unwrap() and expect() panic on None/Err, crashing the thread or process in production. | CWE-248 | info |
| IAC001 | any | Hardcoded Secret in Terraform | Secrets in .tf files are committed to source control and exposed in state files. | CWE-798 | critical |
| IAC002 | any | Hardcoded Secret in YAML Config | Secrets in YAML configuration files committed to source control. | CWE-798 | high |
| IAC003 | any | Secret in Dockerfile ENV | ENV instructions with secrets are baked into the image and visible in docker history. | CWE-798 | high |
| IAC004 | any | Unpinned Docker Base Image | Using :latest or no tag means the image can change unexpectedly, potentially introducing vulnerabilities. | CWE-1104 | low |
| A01-PY001 | python | World-Writable File Permission | Setting chmod 777 gives all users read/write/execute access. | CWE-732 | high |
| A01-PY002 | python | File Write Without Permission Check | Writing to files without checking permissions may allow unauthorized access. | CWE-732 | info |
| A01-PY003 | python | DELETE Endpoint Without Auth Check | DELETE endpoints should verify authorization before allowing deletion. | CWE-284 | medium |
| A01-JS001 | javascript | Missing Auth Check Before Access | Checking req.user for null without proper middleware may allow bypass. | CWE-284 | high |
| A01-JS002 | javascript | Client-Side Role Check | Role checks in client-side code can be bypassed by attackers. | CWE-284 | medium |
| A01-JS003 | javascript | Token Stored in Browser Storage | Tokens in localStorage/sessionStorage are accessible to XSS attacks. | CWE-922 | medium |
| A01-GO001 | go | World-Writable File Permission | chmod 0777 grants all users full access to the file. | CWE-732 | high |
| A01-GO002 | go | Path Traversal via User Input | Building file paths from user input allows directory traversal attacks. | CWE-22 | critical |
| A01-JAVA001 | java | Permit All Access Configured | @PermitAll removes all access control for the annotated resource. | CWE-284 | high |
| A01-JAVA002 | java | Path Traversal via Request Parameter | Using request parameters to build file paths allows traversal attacks. | CWE-22 | critical |
| A01-PHP001 | php | Remote File Inclusion via User Input | Including files based on user input allows arbitrary code execution. | CWE-98 | critical |
| A01-PHP002 | php | Session Admin Flag Set Without Verification | Setting admin flags in session without server-side verification is dangerous. | CWE-284 | high |
| A02-PY001 | python | Weak Hash Algorithm (MD5/SHA1) | MD5 and SHA1 are cryptographically broken and should not be used for security. | CWE-327 | high |
| A02-PY002 | python | Deprecated Cipher Algorithm | DES, 3DES, Blowfish, RC4, RC2 are deprecated and cryptographically weak. | CWE-327 | critical |
| A02-PY003 | python | Hardcoded Encryption Key | Hardcoded encryption keys can be extracted from source code. | CWE-321 | medium |
| A02-JS001 | javascript | Weak Hash Algorithm | MD5 and SHA1 are cryptographically broken. | CWE-327 | high |
| A02-JS002 | javascript | Weak PRNG for Security Token | Math.random() is not cryptographically secure and predictable. | CWE-338 | critical |
| A02-JS003 | javascript | Base64 Is Not Encryption | Base64 encoding provides no security - it's trivially reversible. | CWE-311 | medium |
| A02-GO001 | go | MD5 Hash Used | MD5 is cryptographically broken and collision-prone. | CWE-327 | high |
| A02-GO002 | go | SHA1 Hash Used | SHA1 is deprecated for security purposes due to collision attacks. | CWE-327 | high |
| A02-GO003 | go | Deprecated Cipher | DES, RC4, and Blowfish are cryptographically weak. | CWE-327 | critical |
| A02-GO004 | go | RSA Key Too Short | RSA keys under 2048 bits are considered insecure. | CWE-326 | critical |
| A02-JAVA001 | java | Weak Hash Algorithm | MD5 and SHA-1 are cryptographically broken. | CWE-327 | high |
| A02-JAVA002 | java | Weak Cipher Algorithm | DES, RC4, Blowfish are deprecated and insecure. | CWE-327 | critical |
| A02-JAVA003 | java | Hardcoded Secret Key | Hardcoded encryption keys are exposed in source control. | CWE-321 | critical |
| A02-PHP001 | php | Weak Hash Function | md5() and sha1() are insecure for passwords and security hashing. | CWE-327 | high |
| A02-PHP002 | php | Deprecated mcrypt Extension | mcrypt is deprecated and removed in PHP 7.2+, uses weak algorithms. | CWE-327 | critical |
| A02-RB001 | ruby | Weak Hash Algorithm | MD5 and SHA1 are cryptographically broken. | CWE-327 | high |
| A02-RB002 | ruby | Weak Cipher | DES and RC4 are cryptographically broken. | CWE-327 | critical |
| A02-CS001 | csharp | Weak Hash Algorithm | MD5 and SHA1 are cryptographically broken. | CWE-327 | high |
| A02-CS002 | csharp | Weak Cipher Algorithm | DES, 3DES, RC2 are deprecated and insecure. | CWE-327 | critical |
| A03-PY001 | python | SQL Injection via String Formatting | Building SQL queries with string formatting allows injection attacks. | CWE-89 | critical |
| A03-PY002 | python | Command Injection via Shell | shell=True with user input allows command injection. | CWE-78 | critical |
| A03-PY003 | python | Code Injection via eval/exec | eval() and exec() execute arbitrary Python code. | CWE-95 | critical |
| A03-PY004 | python | Server-Side Template Injection Risk | render_template_string with user input enables SSTI attacks. | CWE-94 | high |
| A03-PY005 | python | Unsafe YAML Deserialization | yaml.load() without SafeLoader can execute arbitrary Python code. | CWE-502 | critical |
| A03-JS001 | javascript | Cross-Site Scripting (XSS) | Inserting user input into innerHTML enables XSS attacks. | CWE-79 | critical |
| A03-JS002 | javascript | Command Injection | Passing user input to exec() allows arbitrary command execution. | CWE-78 | critical |
| A03-JS003 | javascript | Code Injection via eval/Function | eval() and new Function() execute arbitrary JavaScript. | CWE-95 | critical |
| A03-JS004 | javascript | NoSQL Injection via $where | MongoDB $where operator executes JavaScript on the server. | CWE-943 | critical |
| A03-GO001 | go | SQL Injection via fmt.Sprintf | Building SQL with fmt.Sprintf and user data allows SQL injection. | CWE-89 | critical |
| A03-GO002 | go | Command Injection via exec.Command | Building command arguments from user input allows OS command injection. | CWE-78 | critical |
| A03-GO003 | go | Unsafe HTML/JS Template Injection | Casting to template.HTML/JS/URL bypasses Go's auto-escaping. | CWE-79 | high |
| A03-JAVA001 | java | SQL Injection via Statement | Concatenating user input into SQL statements allows injection. | CWE-89 | critical |
| A03-JAVA002 | java | OS Command Injection | Executing system commands with user input allows command injection. | CWE-78 | critical |
| A03-JAVA003 | java | Script Engine Code Injection | Evaluating scripts with user input enables arbitrary code execution. | CWE-94 | critical |
| A03-JAVA004 | java | Unsafe Java Deserialization | Java deserialization can execute arbitrary code via gadget chains. | CWE-502 | critical |
| A03-PHP001 | php | SQL Injection via Direct Query | Using user input directly in SQL queries allows SQL injection. | CWE-89 | critical |
| A03-PHP002 | php | Command Injection via Shell Functions | Passing user input to exec/system/shell_exec allows command injection. | CWE-78 | critical |
| A03-PHP003 | php | Unsafe PHP Deserialization | Deserializing user-controlled data can lead to object injection attacks. | CWE-502 | critical |
| A03-PHP004 | php | Reflected XSS | Echoing user input directly enables cross-site scripting. | CWE-79 | high |
| A03-RB001 | ruby | SQL Injection via String Interpolation | Using string interpolation in SQL queries allows injection. | CWE-89 | critical |
| A03-RB002 | ruby | Code Injection via eval | eval() and *_eval methods execute arbitrary Ruby code. | CWE-95 | critical |
| A03-RB003 | ruby | Command Injection | Passing params to system commands allows command injection. | CWE-78 | critical |
| A03-CS001 | csharp | SQL Injection via SqlCommand | Concatenating user input into SQL commands allows injection. | CWE-89 | critical |
| A03-CS002 | csharp | Command Injection via Process.Start | Using request parameters in Process.Start allows command injection. | CWE-78 | critical |
| A04-PY001 | python | Debug Mode Enabled in Production | Debug mode exposes stack traces, source code, and interactive consoles. | CWE-94 | high |
| A04-JS001 | javascript | Non-Production Mode Check | Code paths that bypass security in non-production modes can be accidentally enabled. | CWE-94 | medium |
| A04-GO001 | go | Unhandled Error Causes Panic/Fatal | Panicking on errors can crash the service and expose stack traces. | CWE-390 | low |
| A04-JAVA001 | java | Stack Trace Exposed | printStackTrace() may expose sensitive internal details to users. | CWE-209 | medium |
| A05-PY001 | python | Django ALLOWED_HOSTS Wildcard | ALLOWED_HOSTS = ['*'] allows host header injection attacks. | CWE-16 | high |
| A05-PY002 | python | CORS Wildcard Origin | Allowing all origins via CORS enables cross-origin attacks. | CWE-16 | high |
| A05-JS001 | javascript | CORS Wildcard in Express | cors({origin: '*'}) allows any website to make requests to your API. | CWE-16 | high |
| A05-GO001 | go | CORS Wildcard Origin | Wildcard CORS origin allows any site to access your API. | CWE-16 | high |
| A05-GO002 | go | Server Binding to All Interfaces | Binding to 0.0.0.0 exposes the service on all network interfaces. | CWE-16 | medium |
| A05-JAVA001 | java | CORS Wildcard | Wildcard CORS allows any origin to access your API. | CWE-16 | high |
| A05-PHP001 | php | Error Display Enabled | Displaying errors exposes internal paths and logic to attackers. | CWE-16 | high |
| A06-JS001 | javascript | Outdated jQuery Version | jQuery versions 1.x and 2.x have known XSS vulnerabilities. | CWE-1035 | high |
| A06-JS002 | javascript | Potentially Vulnerable Lodash Version | Lodash versions prior to 4.17.21 have prototype pollution vulnerabilities. | CWE-1035 | high |
| A06-PY001 | python | Outdated Django Version | Django 1.x and early 2.x versions are no longer supported and have known CVEs. | CWE-1035 | critical |
| A06-PY002 | python | Outdated Security-Sensitive Package | Old versions of Flask, requests, and cryptography have known vulnerabilities. | CWE-1035 | high |
| A07-PY001 | python | Insecure Session Cookie Configuration | Session cookies without Secure/HttpOnly flags are vulnerable to theft. | CWE-614 | high |
| A07-PY002 | python | JWT Signature Verification Disabled | Skipping JWT signature verification allows token forgery. | CWE-347 | critical |
| A07-JS001 | javascript | JWT Decoded Without Verification | jwt.decode() without verification accepts any token including forged ones. | CWE-347 | critical |
| A07-JS002 | javascript | Direct Password Comparison | Comparing passwords directly instead of using timing-safe comparison leaks information. | CWE-916 | critical |
| A07-GO001 | go | JWT Parsed Without Verification | Returning nil error from key function disables JWT verification. | CWE-347 | critical |
| A07-GO002 | go | Insecure Cookie Configuration | Cookies without HttpOnly and Secure flags are vulnerable to theft. | CWE-614 | high |
| A07-JAVA001 | java | Insecure Cookie Flag | Cookies with Secure=false or HttpOnly=false are vulnerable. | CWE-614 | high |
| A07-PHP001 | php | Session Fixation Risk | Not regenerating session ID on login allows session fixation attacks. | CWE-384 | high |
| A08-PY001 | python | Unsafe Pickle Deserialization | pickle.loads() executes arbitrary Python code during deserialization. | CWE-502 | critical |
| A08-PY002 | python | Unsafe Deserialization | marshal and shelve modules can execute arbitrary code. | CWE-502 | high |
| A08-JS001 | javascript | Unvalidated Deserialization | Deserializing user-controlled JSON without schema validation is dangerous. | CWE-502 | medium |
| A08-GO001 | go | Unsafe Gob Deserialization | Decoding gob from untrusted input can cause unexpected behavior. | CWE-502 | high |
| A09-PY001 | python | Silent Exception Handling | Silently swallowing exceptions prevents security event detection. | CWE-390 | medium |
| A09-JS001 | javascript | Empty Catch Block | Empty catch blocks hide errors and prevent security monitoring. | CWE-390 | medium |
| A09-GO001 | go | Empty Error Handler | Ignoring errors prevents detection of security-relevant failures. | CWE-390 | medium |
| A09-JAVA001 | java | Empty Catch Block | Empty catch blocks suppress exceptions and prevent security logging. | CWE-390 | medium |
| A10-PY001 | python | Server-Side Request Forgery (SSRF) | Making HTTP requests with user-controlled URLs allows SSRF attacks. | CWE-918 | critical |
| A10-JS001 | javascript | Server-Side Request Forgery (SSRF) | Making server-side HTTP requests with user-controlled URLs allows SSRF. | CWE-918 | critical |
| A10-GO001 | go | Server-Side Request Forgery (SSRF) | HTTP requests to user-controlled URLs allow SSRF attacks. | CWE-918 | critical |
| A10-JAVA001 | java | Server-Side Request Forgery (SSRF) | Opening URLs from request parameters allows SSRF attacks. | CWE-918 | critical |
| A10-PHP001 | php | SSRF via curl/file_get_contents | Using user input as URL in curl or file_get_contents allows SSRF. | CWE-918 | critical |
| SEC-001 | any | AWS Secret Access Key Exposed | Hardcoded AWS secret access key found in source code. | CWE-798 | critical |
| SEC-002 | any | Stripe Live Secret Key Exposed | Hardcoded Stripe live secret key found. | CWE-798 | critical |
| SEC-003 | any | GitHub Token Exposed | Hardcoded GitHub token found in source code. | CWE-798 | critical |
| SEC-004 | any | Database URL with Credentials Exposed | Database connection string with credentials found in source. | CWE-798 | critical |
| SEC-005 | any | Private Key Hardcoded | Private key material found hardcoded in source code. | CWE-798 | critical |
| SEC-006 | any | SendGrid API Key Exposed | Hardcoded SendGrid API key found. | CWE-798 | critical |
| SEC-007 | any | Twilio Auth Token Exposed | Hardcoded Twilio authentication token found. | CWE-798 | critical |
| SEC-008 | any | Slack Bot Token Exposed | Hardcoded Slack bot token found in source. | CWE-798 | high |
| SEC-009 | any | Mailgun API Key Exposed | Hardcoded Mailgun API key found. | CWE-798 | critical |
| SEC-010 | any | Firebase Service Account Credentials | Firebase service account credentials found in source code. | CWE-798 | critical |

Counts by language: Python 42, JavaScript/TypeScript 39, Go 31, Java/Kotlin 26, PHP 23, any (secrets and IaC) 17, Ruby 10, C/C++ 9, C# 9, Rust 2. By severity: critical 95, high 71, medium 36, low 3, info 3.

Notes on the rule set:

- Several rules overlap in subject, for example `PY001` and `A03-PY001` (SQL injection) or `PY008` and `A03-PY005` (YAML). Both report, with different rule IDs.
- File patterns differ between rule families. For example, `A01-JAVA*` rules apply to `.java` only, while `JV*` rules also cover `.kt` and `.kts`. `SEC-*` rules do not cover `.jsx` or `.tsx`.
- `A06-*` rules check manifests (`package.json`, `requirements*.txt`, `Pipfile`, `setup.py`) by regex. They are not version-accurate; the OSV scan (4.6) is.

### 4.5 Semgrep and CodeQL

**Semgrep** runs over the repository's scan directory with `--config /semgrep-rules` if that directory exists, else `--config p/default` (fetched from the Semgrep registry; the shipped image has no `/semgrep-rules`, see deployment.md section 6.1). Mapping:

| Semgrep field | Finding field |
|---|---|
| `check_id` | `rule_id`; the title is the last dotted segment in title case (for example `...exec-detected` → `Exec Detected`) |
| `extra.severity` `ERROR` / `WARNING` / `INFO` | `critical` / `high` / `medium` |
| `metadata.cwe`, `metadata.owasp` | first value |
| `metadata.fix` | fix text |
| source lines | snippet: 2 lines before to 1 line after the match, at most 500 characters, matched lines marked `>` |

**CodeQL** runs only when the `codeql` CLI is installed. It builds a database for the most common language in the repository (Go, JavaScript/TypeScript, Python, Java, C#, Ruby; one language per repository) with `--no-tracing`. It then runs the standard query pack `codeql/<lang>-queries` and parses the SARIF output. The title is the rule `name`. The severity comes from the rule's `properties.severity`. When that property is missing the code sets `medium`, so the SARIF `level` fallback (`error` → critical, `warning` → high) is never used *(unverified against real CodeQL output: in practice CodeQL findings may all be `medium`)*. C/C++ and PHP are not analysed by CodeQL here.

### 4.6 Dependency scanning (SCA, OSV)

After Semgrep, the scanner looks for lockfiles in the scan directory (up to 50 files, 8 MiB each). It extracts exact `name + version` pairs:

| File | Ecosystem | What is parsed |
|---|---|---|
| `package-lock.json` | npm | `packages` entries under `node_modules/` (lockfile v2/v3); else `dependencies` (v1) |
| `yarn.lock` | npm | yarn v1 header and `version` lines |
| `requirements.txt` | PyPI | `name==version` lines only (ranges are ignored) |
| `Pipfile.lock` | PyPI | `default` and `develop` entries pinned with `==` |
| `poetry.lock` | PyPI | `name` / `version` pairs |
| `go.mod` | Go | `require` lines (version without the leading `v`) |
| `Cargo.lock` | crates.io | `name` / `version` pairs |
| `composer.lock` | Packagist | `packages` (leading `v` removed) |

`package.json`, `pom.xml`, `build.gradle`, `Gemfile.lock` and `pnpm-lock.yaml` are not parsed by SCA.

Up to 2 000 unique packages are sent to `POST https://api.osv.dev/v1/querybatch` in batches of 500. Up to 150 matched advisories are then fetched (`GET /v1/vulns/{id}`, sorted by ID) for details. The whole lookup has a 60 second budget. A network failure produces no SCA findings and does not fail the scan.

One finding per (package, advisory):

| Field | Value |
|---|---|
| `rule_id` | `SCA-<OSV id>` (for example `SCA-GHSA-xxxx-xxxx-xxxx`) |
| Title | `Vulnerable dependency: <name> <version> (<id>)` |
| Severity | `database_specific.severity` of the advisory (`CRITICAL`, `HIGH`, `LOW`; anything else and advisories without details → `medium`). CVSS vectors are not evaluated. |
| CWE / OWASP | `CWE-1104` / `A06:2021 Vulnerable and Outdated Components` |
| Detail | Advisory summary and aliases (CVE IDs) |
| Fix | `Upgrade <name> to <first fixed version> or later.`, when OSV lists one |
| File / line | The lockfile path / 0 |
| Engine | `osv` |

> As with the built-in rules, OSV findings are currently removed by the deduplication step (4.7) before they are stored.

Implemented in: `sast_sca.go`.

### 4.7 SAST result deduplication

`deduplicateSASTFindings` (`sast_engine.go` line 1259):

1. Exact duplicates are removed by `engine + rule_id + file + line`.
2. Semgrep findings are kept. A CodeQL finding within ±2 lines of a Semgrep finding in the same file marks that Semgrep finding as `semgrep+codeql` and is dropped. Other CodeQL findings are kept.

**Defects (confirmed by running the function in isolation):**

- Findings with engine `builtin` or `osv` are not carried into the output. They are always discarded. A scan on a server without Semgrep therefore always reports zero findings, although the logs report built-in findings.
- The location map stores indexes into the step-1 list but uses them on the output list. When a CodeQL finding sits next to a Semgrep finding, and non-Semgrep findings came earlier in the list, the code either tags the wrong finding or panics with "index out of range". A panic fails the scan request. With `?async=1` the job is reported as failed.
- The location key does not include the repository. In a multi-repository scan, a CodeQL hit can be merged with a Semgrep hit at the same path and line in another repository.

### 4.8 IaC checks

There is no separate IaC engine. IaC coverage is:

| Check | Where |
|---|---|
| `IAC001` Hardcoded secret in Terraform (`.tf`, `.tfvars`) | built-in rules |
| `IAC002` Hardcoded secret in YAML config (`.yaml`, `.yml`) | built-in rules |
| `IAC003` Secret in Dockerfile `ENV` | built-in rules |
| `IAC004` Unpinned Docker base image | built-in rules |
| Terraform state, kubeconfig, `.tfvars`, secrets YAML committed | code scan sensitive files (4.2), sync-time sensitive-file events (4.1.1) |
| Whatever Terraform, Kubernetes, Dockerfile and YAML rules the active Semgrep configuration contains | Semgrep (`p/default`) |

`.tf`, `.yaml`, `.yml`, `.toml` and `Dockerfile` files are downloaded and given to Semgrep and CodeQL. Kubernetes, Helm, CloudFormation and ARM templates have no dedicated built-in rules.

### 4.9 Pipeline-change detection

| Mechanism | Output |
|---|---|
| Polled commit touches a CI/CD file | `devops.cicd_modified` (alert DEV-003). GitHub records a `risky` reason for risky additions (2.4). |
| Pipeline runs (GitLab pipelines, Azure DevOps builds; GitHub `workflow_run`, GitLab `pipeline` and Azure DevOps build webhooks) | `devops.pipeline_run` / `devops.workflow_run` events, severity 1 (2 when failed). Searchable. DEV-005 is the only rule over `devops.workflow_run`. |
| SAST file priority | CI files are scanned first when a repository exceeds 1 000 files |

---

## 5. Posture checks

`POST /api/v1/devops-connectors/{id}/posture` (**Posture** tab, **Run posture check**). The result is stored as the connector's last posture result. Checks are read-only.

| Provider | Check | Finding title | Severity | Resource |
|---|---|---|---|---|
| GitHub | Org `two_factor_requirement_enabled` is false | Organisation does not require two-factor authentication | high | org |
| GitHub | Repo `security_and_analysis.secret_scanning.status` = disabled | Secret scanning disabled | medium | `owner/repo` |
| GitHub | `secret_scanning_push_protection.status` = disabled | Push protection disabled | medium | `owner/repo` |
| GitHub | Branch protection API returns 404 for the default branch | Default branch is not protected | high | `owner/repo@branch` |
| GitHub | No required approving review, or count < 1 | Pull request approvals not required | medium | `owner/repo@branch` |
| GitHub | `allow_force_pushes.enabled` | Force pushes allowed on default branch | medium | `owner/repo@branch` |
| GitHub | `enforce_admins.enabled` is false | Branch protection not enforced for admins | low | `owner/repo@branch` |
| GitLab | Group `require_two_factor_authentication` is false | Group does not require two-factor authentication | high | group |
| GitLab | No protected-branch entry named as the default branch or `*` | Default branch is not protected | high | `group/project@branch` |
| GitLab | Push access level 30 (Developers) on that entry | Developers can push directly to the default branch | medium | `group/project@branch` |
| GitLab | `allow_force_push` on that entry | Force pushes allowed on default branch | medium | `group/project@branch` |
| Azure DevOps | No enabled, blocking "Minimum number of reviewers" policy (type `fa4e907d-…`) with ≥ 1 approver whose scope covers the repository's default branch (exact or prefix) | Default branch has no required-reviewer policy | high | `org/project/repo@branch` |

Rules for "cannot assess": if the API refuses a call (permissions, plan), the repository is skipped and no finding is raised. GitHub archived repositories and forks are skipped. GitLab empty projects, Azure DevOps disabled repositories, and repositories without a default branch are skipped. GitHub repository rulesets are not read, so a branch protected only by a ruleset is reported as "not protected" *(unverified)*. GitLab wildcard patterns other than `*` (for example `release/*`) are not matched.

Implemented in: `devops_posture.go`.

---

## 6. Alerts on DevOps events

Every `devops.*` event is evaluated against 21 signatures. Two engine paths do this:

1. The main detection pass, which evaluates all new events every cycle. It honours rule toggles and allow-lists (`engineGate`). It deduplicates on `sig:{rule}:host:{host}:d:{UTC day}`.
2. `runDevOpsCursor`, a DevOps-only pass with its own cursor and a 7-day first look-back. It deduplicates on `sig:{rule}:host:{host}:d:{day}:e:{entity}`. It does **not** consult rule toggles or allow-lists.

The two dedup keys differ, so a matching event can raise **two** alerts, one from each path *(suspected defect; observed from code only)*.

Alert title: `[<MITRE>] <Name>`. Host: the event host (organisation or repository).

| ID | Name | Fires on | Severity | MITRE |
|---|---|---|---|---|
| DEV-001 | Secret or Credential Pushed to Repository | `devops.secret_push` | 5 | T1552.001 |
| DEV-002 | Sensitive File Committed (.env, .pem, credentials) | `devops.sensitive_file` | 4 | T1552.001 |
| DEV-003 | CI/CD Pipeline Configuration Modified | `devops.cicd_modified` | 4 | T1195.002 |
| DEV-004 | Self-Hosted Runner Registered | action / event / type suffix `runners.create`, `runner_registered`, `enterprise.register_self_hosted_runner`, `org.register_self_hosted_runner`, `repo.register_self_hosted_runner`; or `type` = `self-hosted` with `runner`, `runner_created`, `runners.create` | 4 | T1195.002 |
| DEV-005 | Pipeline Secret or Variable Accessed from Unexpected Branch | `devops.workflow_run` whose raw JSON contains `fork` or `pull_request` and whose branch is not `main`, `master` or `develop` | 4 | T1195.002 |
| DEV-006 | Private Repository Made Public | `repo_publicized`, `repo.publicized`, `repository.publicized`, `made_public`, `publicized`, `visibility_change`, `changed_visibility_to_public`; or `repo.access` / `repository.access` with `visibility` = `public` | 5 | T1530 |
| DEV-007 | Repository Deleted | `repo.destroy`, `repo_destroy`, `repository.deleted`, `repository_deleted`, `repo_deleted`, `deleted` | 4 | T1485 |
| DEV-008 | Repository Transferred to External Account | `repo.transfer`, `repo_transfer`, `repository.transferred`, `repository_transferred`, `transfer_start`, `transferred` | 4 | T1537 |
| DEV-009 | New Organization Owner or Admin Added | `org.add_member`, `org_add_member`, `member_added`, `added_to_org`, `org.update_member`, `member.added`, `org.invite_member` **and** `role` (or `permission`) = `owner` / `admin` | 5 | T1098 |
| DEV-010 | Personal Access Token Created | `personal_access_token.created`, `pat.created`, `access_token_created`, `create_pat`, `personal_access_token.access_granted` | 4 | T1098 |
| DEV-011 | Deploy Key Added to Repository | `deploy_key.create`, `deploy_key_added`, `repo.add_deploy_key` | 3 | T1098.004 |
| DEV-012 | OAuth Application Installed with Broad Permissions | `oauth_application.create`, `integration_installation.create`, `app_installation`, `github_app_installed`, `oauth_access.create` | 4 | T1550.001 |
| DEV-013 | Branch Protection Removed or Weakened | `protected_branch.destroy`, `protected_branch_deleted`, `branch_protection_rule_deleted`, `remove_branch_protection`; or `protected_branch.update_admin_enforcement` / `.dismiss_stale_reviews` / `.update_require_code_owner_review` whose raw JSON contains `disabled`, `"enabled":false` or `"value":false` | 4 | T1562 |
| DEV-014 | Force Push to Protected Branch | Event with a `branch` field: `forced` or `deleted` on a protected branch name. Otherwise raw JSON containing `force_push` / `forced_push` / `protected_branch.destroy` together with `main` / `master` / `develop` / `release`. | 4 | T1562 |
| DEV-015 | Audit Log Streaming Disabled | `audit_log_streaming.disabled`, `audit_stream_delete`, `log_streaming_disabled`, `stream_key.destroy`, `audit_log_streaming.destroy` | 5 | T1562.008 |
| DEV-016 | Webhook Created on Organization | `hook.create`, `webhook_created`, `org_webhook_add`, `project_hook_add`, `org.add_webhook` | 3 | T1071.001 |
| DEV-017 | Repository Made Public Outside Business Hours | Any devops event outside business hours whose raw JSON contains `publicized`, `made_public` or `visibility_change` | 5 | T1530 |
| DEV-018 | Admin Added to Org Outside Business Hours | Outside business hours, raw JSON contains `org.add_member`, `member_added` or `org_admin`, and `owner` or `admin` | 5 | T1098 |
| DEV-019 | Mass Deletion Commit | `devops.mass_deletion` | 3 | T1485 |
| DEV-020 | Dependency Manifest Modified | `devops.dependency_change` | 2 | T1195.001 |
| DEV-021 | Commit Committer/Author Mismatch Without Signature | `devops.push` with `committer_mismatch` true and `verified` false (GitHub polling only; the GitHub web-flow committer `noreply@github.com` is ignored) | 3 | T1565 |

"Action / event / suffix" means the signature compares exact values against the raw `action` field, the raw `event` field, or the event type without the `devops.` prefix (`devopsParse`, `devops_typed.go`).

Coverage by provider (from the event shapes above; *unverified* against real payloads):

| Signature | GitHub | GitLab | Azure DevOps |
|---|---|---|---|
| DEV-001, 003 | poll | poll | poll (DEV-001 path match only) |
| DEV-002 | poll | poll | – |
| DEV-019, 020, 021 | poll | – | – |
| DEV-006 | audit `repo.access` with visibility, webhook `repository.publicized` / `public` | audit `.make_public`-style names are not produced; webhook has no visibility event | – |
| DEV-007, 008 | audit, webhook | webhook `project_destroy` / `project_transfer` | – |
| DEV-009 | audit (needs `role` or `permission` in the entry) | – (webhook sets `role` from `project_access`/`group_access`, but the event is `member_added`, which matches only if the role text is exactly `owner` or `admin`) | – |
| DEV-010, 011, 012, 013, 015, 016 | audit, webhooks | – | – |
| DEV-014 | webhook `push` | webhook `push` (deletion only) | webhook `git.push` (deletion only) |
| DEV-004, 005 | audit / webhook | – | – |

**Azure DevOps audit events** (`devops.audit`) do not match any DEV signature. The rated actions (permission changes, PAT creation, policy removal, repository deletion) are stored and searchable, but raise no DevOps alert.

**Suspected false positives:**

- DEV-007 matches any event whose raw `action` is `deleted`. GitHub webhooks such as `branch_protection_rule` (`deleted`), `deploy_key` (`deleted`) or `secret_scanning_alert` carry `action` in the raw JSON. A deleted branch-protection rule therefore raises both DEV-013 and "Repository Deleted".
- DEV-017 and DEV-018 search the whole raw JSON, so a commit message containing `publicized` outside business hours can match.
- DEV-005 searches the raw JSON for `fork` or `pull_request`. The workflow-run events built by the code contain neither field, so in practice DEV-005 fires only when a repository or branch name contains those words.

Implemented in: `devops_sigs.go`, `devops_typed.go`, `business_hours.go`, `detection_engine.go`.

---

## 7. Finding identity, merging and repository severity

### 7.1 On the Code pages (frontend)

The Code pages (section 8) build findings in the browser from three API calls per connector: `GET .../code-scan` (latest run), `GET .../sast` (latest SAST row of the connector, whatever repository it was for), and `GET .../posture`. Each finding gets:

| Field | Derivation |
|---|---|
| `repo` | Short repository name: the last path segment, before any `@branch`, lower-cased. `acme/api`, `group/sub/api` and `org/proj/api` all become `api`. |
| `where` | `file[:line]`, or the posture resource |
| `source` | `scan`, `sast` or `posture` |
| `type` | code-scan category (`secret`, `dependency`, `dangerous_code`, `sensitive_file`, `config`), or `sast`, or `posture` |
| `sev` | 5 critical, 4 high, 3 medium, 2 low, 1 info or unknown |

**Finding ID** (`CodeOverview.jsx`, `findingId`):

```
<connector id>-<source>-<hash32(repo | where | title | type)>
```

`hash32` is 32-bit FNV-1a, written in base 36. The ID is used in the URL `/devops/findings/:fid`. Properties:

- It is stable across reloads as long as the finding's repository, location, title and type stay the same. A change of line number gives a new ID.
- It is computed in the browser and is not stored. A link to a finding that a newer scan no longer reports shows "Finding not found".
- Two findings with the same connector, source, short repository name, location, title and type get the same ID. The finding page then shows the first one. 32-bit hash collisions are possible but unlikely at normal volumes.

Findings are not merged across sources on these pages. A secret reported by both the code scan and SAST appears twice.

### 7.2 Unified findings API (Insights → Code findings)

`GET /api/v1/findings[?min_severity=&source=&repo=]` builds a merged list on the server from the latest SAST row per (connector, repository), the latest code-scan row per connector, and the last posture result per connector.

| Aspect | Rule |
|---|---|
| Merge key | lower-case `repo | file | line | title`. The connector is not part of the key. |
| On merge | `sources` collects every scanner; the highest severity wins; the first non-empty remediation is kept |
| ID | First 12 hex characters of SHA-256 over `source, connector, repo, file, line, title` of the first finding seen |
| Severity normalisation | `critical`/`5`; `high`/`4`/`error`; `medium`/`3`/`warning`/`moderate`; `low`/`2`; anything else `info` |
| Order and cap | By severity, descending; at most 1 000 returned, with `total` and `by_severity` counts |

The rule ID and CWE are kept for SAST findings. Posture findings use the resource (`org/repo@branch`) as `repo`.

### 7.3 Repository scoring

There is no numeric repository score. A repository's state is the **highest severity** of its findings from all three sources:

| Worst finding | Shown as |
|---|---|
| critical | Critical (red) |
| high | High (amber) |
| medium | Medium |
| low / info | Low / Info |
| none | Clean |

The Repositories table sorts by worst severity, then by finding count, then by name. The only numeric score is the optional AI `risk_score` (0-100) in the AI summaries of the code scan and SAST. It is produced by the language model and is not used anywhere else.

---

## 8. What the user sees

The rail section **Code** has one entry, **Repositories** (`/devops`).

### 8.1 Code → Repositories (`/devops`)

The header shows a state (for example "2 repositories with critical findings"), the number of repositories, providers and sources, and the time of the last scan. Header numbers: **Repositories**, **Open findings**, **Secrets exposed** (findings of type `secret`), **Critical findings**, **Branch and access issues** (posture findings). Buttons: **Reload**, **Export** (CSV: severity, title, organisation, repository, where, type, source, scanned_at), **Connect source**.

Tabs:

| Tab | Content |
|---|---|
| **Repositories** | One row per repository: Severity, Repository, Top finding, Count, Branch, Scanned. Facets: Severity, Finding type, Provider, Organisation (with more than one connector). Filter syntax: free text, `severity:critical,high`, `type:secret`. Up to 300 rows. Organisation-level posture findings appear as a row `<org> (organisation)`. The repository list comes from the provider (`GET .../sast/repos`) and arrives after the findings, so clean repositories appear a moment later. |
| **Findings** | One row per finding: Severity, Finding, Repository, Where, Source, Scanned. Facets: Severity, Finding type, Source, Repository (top 15). Up to 500 rows. A row opens the finding page. |
| **Connectors and scans** | The per-connector workspaces (8.4) |

### 8.2 Repository page (`/devops/repos/:connector/:repo`)

`:repo` is the short repository name. The header shows `org/repo`, the provider, the branch, the last scan time, and the worst severity. Numbers: Open findings, Critical, High, Secrets, Branch and access issues. The table lists every finding for that repository from all three sources (Severity, Finding, Where, Type, Source, Scanned). Buttons: **Back**, **All repositories**. If no connector holds the repository, the page says "Repository not found in any connected source."

Because the key is the short name, two repositories with the same short name in one connector (for example `acme/api` and `acme-labs/api` seen through `/user/repos`) are merged into one page.

### 8.3 Finding page (`/devops/findings/:fid`)

- **Header:** title, severity, a link to the repository, location, source, scan time.
- **Details:** Type, Repository, Branch (SAST and posture), Location, Rule (SAST rule ID), Commit and author (code scan), Found by, and the full detail text.
- **How to fix:** the remediation text. Secret findings add: "Rotate the secret first: deleting it from the code does not remove it from git history."
- **Other findings in this repository:** up to 8, by severity.

The page has no status, assignee, comment or suppress action.

### 8.4 Per-connector workspace (Connectors and scans tab)

The left sidebar lists connectors (organisation, provider, status, items synced) and the **Add connector** buttons. The right panel shows the selected connector: provider, organisation, label, status, **Sync** and **Disconnect**, and these tabs:

| Tab | Content |
|---|---|
| **Code Changes** | Last 100 stored commits (search box, repository filter). A commit opens its detail with the file list and redacted patches. |
| **Code Scan** | Run the code scan, see counts and findings of the latest run, and request an AI summary (risk score, label, executive summary, top issues, immediate actions). |
| **SAST** | Repository selector (live list from the provider) and Branch field; **Run SAST Scan** (async job, polled every 2 seconds for up to 12 minutes); summary counts; severity filter; findings with snippet, CWE, OWASP, engine and fix; AI triage (risk label, systemic issues, likely false positives, immediate actions). Selecting a repository loads its last stored result. |
| **Events** | Up to 500 events whose host equals the organisation name (all time). Events whose host is a repository (GitHub audit entries with a repository) are not listed here. |
| **Alerts** | Up to 100 alerts whose host equals the organisation name. |
| **Posture** | **Run posture check** and the last result: repositories checked and each finding with its fix. |

Insights → **Code findings** shows the unified list from section 7.2 with severity and scanner filters.

Implemented in: `management/frontend/src/pages/code/CodeOverview.jsx`, `RepoPage.jsx`, `FindingPage.jsx`, `pages/DevOps.jsx`, `pages/Insights.jsx`, `components/Shell.jsx`.

---

## 9. Limits and caps

| Area | Limit |
|---|---|
| Polling | Every 5 min; 3 min per sync; default branch only; per-provider page caps (configuration.md section 7) |
| GitLab | First 50 projects; 20 commits per project per sync |
| Azure DevOps | 20 commits per repository per sync; no diff content |
| Stored patch | 2 000 characters per file, redacted |
| Code scan | Last 500 commits; repository not part of the dedup key |
| SAST | 1 000 files per repository; 300 KB per file (lockfiles 5 MiB); 10 min per job; one job per connector at a time |
| SCA | 50 lockfiles, 2 000 packages, 150 advisory look-ups, 60 s |
| Posture | 100 repositories |
| Pages | Overview SAST data is the connector's **latest SAST row only**: after scanning repository A, then B, the overview shows B's SAST findings only (A's are still in the database and in Insights → Code findings). 300 repositories and 500 findings per table. |
| Unified API | 1 000 findings |

---

## 10. Not verified against real platforms

The following were not exercised against live accounts while writing this documentation:

1. All token scopes and PAT permissions listed in deployment.md section 3.
2. GitHub audit-log fields (`action`, `actor`, `repo`, `created_at`, `@cursor`, `visibility`, `role`/`permission`) and whether `after=<cursor>` resumes correctly.
3. GitLab group audit events: the code reads `action_name`, which the API may not provide at the top level.
4. GitLab nested group paths in unencoded URL paths.
5. Azure DevOps audit fields (`actionId`, `actorDisplayName`, `ipAddress`) and the `7.1-preview.1` API version; project names with spaces in URLs; branch-policy scope matching.
6. Webhook payload fields for every provider, the GitHub `organization` event name, and Azure DevOps basic-auth delivery.
7. CodeQL SARIF severity mapping (likely always `medium`).
8. Semgrep `p/default` download behaviour with `--metrics=off` inside the shipped image.
9. GitHub rulesets versus classic branch protection in the posture check.
10. Behaviour under real rate limits on large organisations (the 3-minute sync timeout will cut long commit backfills).
