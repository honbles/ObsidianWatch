# Codebase security: capability reference

This document describes, end to end, what the Code feature does: what it collects from each Git platform, every scanning layer and its rules (secrets over full history, pattern rules, CodeQL, dependencies, IaC, licences, SBOM), automated scans and pull-request checks, runtime reachability of vulnerable dependencies, triage and fix suggestions, the platform threat-detection rules, and what each page shows. Everything here is derived from the source code at the time of writing.

Feature map:

| Capability | Section | Needs |
|---|---|---|
| Platform activity collection (audit logs, commits, pipelines, webhooks) | 2, 3 | A connector |
| Platform threat detection (DEV-001 … DEV-031, CODE-RT-001) | 6 | A connector; webhooks for real time |
| Code scan over stored diffs | 4.2 | A synced connector |
| SAST: secrets over history, pattern rules, CodeQL, dependencies, IaC, licences, SBOM | 4.3 – 4.8 | The scanner image (deployment.md section 6.1) |
| Automated scans: on push, on a schedule, pull-request checks with comments and merge blocking | 4.10 | Automation tab; webhooks; a token with write access for PR checks |
| Runtime reachability of dependency vulnerabilities | 4.11 | Linux agent with the host sensor on the servers |
| Triage that learns from decisions | 4.12 | – |
| Fix suggestions (dependency upgrades; AI for code) | 4.13 | AI provider and source-sharing opt-in for code fixes |
| Issues from findings | 4.14 | A token that can create issues |
| Code linked to a monitored service (findings checked against what that service runs; host view) | 4.15 | Application Monitoring service; Linux agent inventories for runtime matching |
| Posture checks, with checks the token could not run listed as not assessed | 5 | A connector; owner/admin rights for full coverage (deployment.md section 3.1) |

See also [deployment.md](deployment.md) and [configuration.md](configuration.md).

---

## 1. Data flow overview

```
 GitHub / GitLab / Azure DevOps
   │ poll every 5 min (DevOpsEngine)       │ webhooks (optional, real time)
   ▼                                       ▼
 commits + redacted diffs ─► devops_commits    devops.* events ─► events table ─► platform detection
 audit / pipeline / member events ─────────────────────────────►              (DEV-*, section 6) ─► alerts
                                           │
                                           ├─ push to default branch ─┐
                                           └─ pull/merge request ─────┤   code_scan_jobs (queue)
 Automation tab schedule (daily/weekly) ───────────────────────────────┤        │ worker
 SAST tab "Run SAST Scan" (manual) ─────────────────────────────────────┘        ▼
                       git clone ─► secrets (history) · pattern rules · Trivy/OSV · built-in · CodeQL
                                  ─► sast_results (findings, engines, SBOM)
                                  ─► PR: status + summary + inline comments (+ AI fixes)
 Linux agents (host sensor) ─► runtime_inventory events ─► runtime_packages ─► reachability labels,
                                                                              alert CODE-RT-001
 Analysts ─► triage decisions / rules ─► hide, learn, hints
 Code scan (stored diffs) ─► code_scan_results     Posture (settings APIs) ─► devops.posture.last.{id}
                                   │
       Code → Repositories pages, SAST tab, Insights → Code findings, GET /api/v1/findings
```

Three result paths exist:

- **Events and alerts.** Platform activity from polling and webhooks becomes `devops.*` events; the platform detection rules turn them into alerts (section 6). Runtime reachability adds alert CODE-RT-001.
- **Findings.** Results of the scanners (code scan, SAST/SCA, posture). They are shown on the Code pages and Insights → Code findings, labelled with runtime reachability and triage. They are not alerts.
- **Pull-request checks.** Findings a change introduces go back to the platform as a status, a summary and inline comments.

Implemented in: `devops_engine.go`, `devops_*.go`, `codescan.go`, `sast_*.go`, `code_automation.go`, `code_reporters.go`, `code_reachability.go`, `code_triage.go`, `code_fix.go`, `app_code.go`, `devops_posture.go`, `findings_unified.go`, `detection_engine.go`, `devops_sigs.go`, `devops_detect_more.go`.

---

## 2. What is collected by polling

Every polled item becomes a row in the events table with `os = "devops"`, `agent_id = "devops:{connector id}"`, and an event type starting with `devops.`. Commits are also stored in `devops_commits`.

### 2.1 GitHub

| Source | API | What is kept | Event type | Severity |
|---|---|---|---|---|
| Org audit log | `GET /orgs/{org}/audit-log?include=all` (cursor `after=`) | Every entry with an action, with the actor's IP (`actor_ip`) in `src_ip`. Git traffic (`git.clone`, `git.fetch`) and `repo.download_zip` are not stored one by one: one `devops.repo_clone_summary` event per actor and sync lists the distinct repositories copied (feeds DEV-028). | `devops.<action with . replaced by _>`, for example `devops.repo_destroy` | From the table in 2.1.1; unrated actions get 1 |
| Public user events (fallback when the audit log fails) | `GET /users/{org}/events` | All event types except Watch, Issues, IssueComment, CommitComment, Gollum | `devops.push`, `devops.repo_create`, `devops.delete_<reftype>`, `devops.repo_make_public`, `devops.member_<action>`, `devops.fork`, `devops.release_<action>`, `devops.pull_request_<action>`, other `devops.<type>` | 1 by default; repo create 4; delete 2 (4 on a protected branch); make public 5; member 4; fork 2; release 2 |
| Repository list | `/orgs/{org}/repos`, plus `/user/repos?affiliation=owner` for a personal account; only repositories whose owner is the connector's org are kept | Name, private flag, default branch | none (used to drive commit polling) | – |
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
| Group audit events (Premium) | `GET /groups/{g}/audit_events?created_after=` (paged, up to 20 × 100) | Rated entries. The action is read from `details` (`add`, `remove`, `change` with `from`/`to`, `custom_message`) or `event_name`; actor from `details.author_name`, IP from `details.ip_address` | `devops.<action with spaces replaced by _>` (for example `devops.added_user_access`), raw carries `event` (canonical name), `role`, `visibility`, `repo` | 4 or 2 |
| Project list | `/groups/{g}/projects?include_subgroups=true&archived=false`, else `/users/{u}/projects`, else the single project named by Org; all pages (up to 20 × 100) | ID, path, default branch | none | – |
| Pipelines | `/projects/{id}/pipelines?updated_after=` (50) | ID, status, source, ref, SHA, URL | `devops.pipeline_run` | 1; failed 2 |
| Project events (any tier) | `/projects/{id}/events?after=` (paged, up to 10 × 100) | `joined`, `left`, `expired`, `removed` → member change; `created`, `destroyed` of the project | `devops.member_change`, `devops.project_created`, `devops.project_destroyed` | 3 |
| Commits | `/projects/{id}/repository/commits?since=` (20) then `/commits/{sha}/diff` | As GitHub, without login, signature and committer | `devops.push` and the events in 2.4 | 1 |

Group and project paths are URL-encoded as one segment (`group/sub` → `group%2Fsub`), so nested groups and names with spaces work.

GitLab audit severity (substring match on the action and `event_name`):

| Severity | Contains |
|---|---|
| 4 | `added user`, `removed user`, `user_access`, `destroyed`, `removed project`, `transfer`, `made public`, `changed visibility`, `two-factor`, `deploy_key`, `personal access token`, `protected_branch`, `streaming`, `hook` |
| 2 | `added`, `removed`, `changed`, `updated`, `created`, `deleted` |
| dropped | anything else |

Canonical names given to GitLab audit entries so the DEV rules match them: member added → `org.add_member` (role from `details.as`), access level change → `org.update_member`, visibility changed to public → `repo.access` with `visibility: public`, project removed → `project_destroyed`, deploy key added → `deploy_key.create`, personal access token created → `personal_access_token.created`, protected branch removed → `protected_branch.destroy`, streaming destination removed → `audit_log_streaming.destroy`, hook added → `hook.create`, transfer → `repo.transfer`.

### 2.3 Azure DevOps

| Source | API | What is kept | Event type | Severity |
|---|---|---|---|---|
| Projects | `_apis/projects`, or only the connector's `project` when set | Name | none | – |
| Audit log (Azure DevOps Services only) | `auditservice.dev.azure.com/{org}/_apis/audit/auditlog?startTime=` (10 × 200) | Rated entries, with actor display name and IP address; raw also carries `event` (canonical name, below), `action`, and `role` / `visibility` when relevant | `devops.audit` | 4 or 2 |
| Builds | `{project}/_apis/build/builds?minTime=` (50) | ID, number, pipeline name, repository, branch, status, result, reason, requested-for | `devops.pipeline_run` | 1; failed 2 |
| Repositories | `{project}/_apis/git/repositories` | ID, name, default branch | none | – |
| Commits | `.../commits?searchCriteria.fromDate=&$top=20` then `.../commits/{id}/changes` | Author, message, file paths and change types (no content) | `devops.push`, plus `devops.secret_push` (path match only) and `devops.cicd_modified` | 1 |

Azure DevOps audit severity (substring match on `actionId`, case-insensitive):

| Severity | Contains |
|---|---|
| 4 | `modifypermission`, `removepermission`, `projectcollectionadmin`, `addmember`, `removemember`, `grouprenamed`, `serviceconnection`, `token.pat`, `token.ssh`, `token.delete`, `policy.policyconfigremoved`, `policy.policyconfigmodified`, `bypassed`, `repositorydeleted`, `project.delete`, `organization.`, `extension.`, `agentpool`, `securefile`, `library.variablegroup` |
| 2 | `create`, `modif`, `delete`, `remove`, `add`, `update`, `change` |
| dropped | anything else |

All Azure DevOps calls use the connector's `base_url` when set (the full organisation or collection URL, for example `https://tfs.example.com/tfs/DefaultCollection` for Azure DevOps Server), otherwise `https://dev.azure.com/{org}`. Azure DevOps Server has no audit API; for such a connector the audit step is skipped and a coverage note says so.

Canonical names for Azure DevOps audit actions: `Git.RepositoryDeleted` / `Git.RepositoryDestroyed` → `repo.destroy`; `Token.PatCreate*` → `personal_access_token.created`; `Token.SshCreate*` → `public_key.create`; `Policy.PolicyConfigRemoved` → `protected_branch.destroy`; `AuditLog.StreamDeleted` / `AuditLog.StreamDisabled*` → `audit_log_streaming.destroy`; `Extension.Installed` → `integration_installation.create`; `Group.UpdateGroupMembership.Add` → `org.add_member` (role `admin` when the group is an administrators group); `Project.UpdateVisibility*` → `repo.access` (with `visibility: public` when made public); agent pool creation → `runners.create`; service connection create/modify → `service_connection.change`.

All Azure DevOps audit entries share the event type `devops.audit`. The action is in the raw `actionId` field. No DEV signature matches `devops.audit` by action (see section 6), so these events are searchable but raise no DevOps alert.

### 2.4 Events derived from each polled commit

| Event type | Condition | Severity | GitHub | GitLab | Azure DevOps |
|---|---|---|---|---|---|
| `devops.push` | Always, one per commit | 1 | yes | yes | yes |
| `devops.secret_push` | An added diff line matches the commit secret scanner (section 4.1). Azure DevOps: a file **path** matches a provider-specific pattern. | 5 (Azure DevOps 4) | yes | yes | path only |
| `devops.cicd_modified` | A changed file is a CI/CD file: path starts with `.github/workflows/`, or equals `.gitlab-ci.yml`, `azure-pipelines.yml`, `Jenkinsfile`, `.circleci/config.yml`, `.travis.yml`, `bitbucket-pipelines.yml`, `cloudbuild.yaml`. GitLab and Azure DevOps use a substring match on the path. Raw `risky` lists what the change adds (below). | 2; with risky additions 3, 4 or 5 (below). Azure DevOps (paths only) 3. | yes | yes | yes |
| `devops.sensitive_file` | A non-deleted file matches a sensitive name (section 4.1.1) | 3 | yes | yes | no |
| `devops.mass_deletion` | ≥ 1 000 deleted lines and deletions > 5 × additions | 3 | yes | no | no |
| `devops.dependency_change` | A non-deleted dependency manifest (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.mod`, `go.sum`, `requirements.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`, `pom.xml`, `build.gradle`, `Gemfile`, `Gemfile.lock`, `Cargo.toml`, `Cargo.lock`, `composer.json`, `composer.lock`) or package-manager configuration (`.npmrc`, `.yarnrc`, `.yarnrc.yml`, `pip.conf`, `nuget.config`) changed. Raw `risks` lists risky additions (below). | 1; with risks 3 | yes | no | no |

**Risky pipeline additions** (GitHub and GitLab, on the added lines of a CI/CD file; every match is recorded in `risky`, separated by `; `):

| Reason recorded | What is looked for |
|---|---|
| `pull_request_target trigger` | `pull_request_target` |
| `checks out pull request head code` | `ref: ${{ github.event.pull_request.head.sha }}` / `.head.ref` / `github.head_ref` |
| `untrusted event data interpolated into a step` | `${{ github.event.<issue/pull_request/comment/review/discussion/head_commit/commits/pages/workflow_run>….<title/body/message/name/label/ref/email/head_branch> }}` or `${{ github.head_ref }}` |
| `secrets: inherit` | `secrets: inherit` |
| `self-hosted runner` | `self-hosted` |
| `write permissions for the workflow token` | `permissions: write-all`, or `contents`, `actions`, `packages`, `id-token`, `pull-requests` set to `write` |
| `download piped to a shell` | `curl`/`wget … \| sh/bash/zsh`, `bash <(curl …)` |
| `prints, dumps or encodes secrets` | `echo`/`printf`/`cat` with `${{ secrets.… }}`, `printenv`, `env \|`, `base64` with a secret, `toJSON(secrets)` |
| `sends the CI token to a URL` | `curl`/`wget`/`Invoke-WebRequest` with `$CI_JOB_TOKEN`, `System.AccessToken`, `secrets.GITHUB_TOKEN` or `github.token` |
| `third-party action not pinned to a commit SHA` | `uses: owner/repo@ref` where the owner is not `actions` or `github` and the ref is not a 40-character SHA |

Severity of the event: 5 when `pull_request_target` comes with a PR-head checkout or untrusted interpolation (the "pwn request" pattern); 4 for untrusted interpolation, printed secrets or a CI token sent out; 3 for any other risky addition; 2 otherwise.

**Risky dependency changes** (added lines): an `install`/`preinstall`/`postinstall` script in `package.json`; a dependency fetched from `git+https`, `git+ssh`, `github:` or an `http(s)` tarball; `--extra-index-url`, `--index-url`, `--trusted-host`, a `registry=` or `"registry":` line, a Poetry source, a Gemfile `source`; a `go.mod` `replace` to a local path or another module.

**Event IDs and timestamps.** Commit events have stable IDs such as `devops:{sha}:push`, `devops:gl:{sha}:secret` or `devops:az:{sha}:cicd`. Their time is the commit time; zero or future times fall back to the receive time. Because events are inserted with `ON CONFLICT (id, time) DO NOTHING`, the 2-minute overlap and manual re-syncs do not create duplicates. Exception: GitLab `secret_push`, `cicd_modified` and `sensitive_file` events use the raw commit time without the future-date guard.

**Stored commits.** The commit key is `{connector}:{first 4 bytes of sha256(repo) as hex}:{sha}`. Identical SHAs in forks or in two connectors therefore stay separate. The branch stored is the repository's default branch, because only the default branch is polled.

---

## 3. What is collected by webhooks

Webhook events have `time` = receive time.

A payload is read up to 1 MiB before its signature or token is checked. A larger one is refused with 413 and logged as `devops webhook: payload over the size limit` (not as an invalid signature); polled data (commits, audit events) still arrives with the next poll, but a scan that delivery would have started (3.4) does not run.

### 3.1 GitHub (`X-GitHub-Event`)

| Event | Event type produced | Severity |
|---|---|---|
| `push` | `devops.push` with `ref`, `branch`, `pusher`, `commits` (count), `forced`, `deleted`, `created`. No diff is fetched; polling handles content. | 1; force push or deletion 2; on a protected branch 4 |
| `repository` | `devops.repo_<action>` (for example `repo_publicized`, `repo_deleted`, `repo_transferred`) | 2; `publicized` 5; `deleted`, `transferred` 4 |
| `member` | `devops.member_<action>` | 3; `added` 4 |
| `workflow_run` | `devops.workflow_run` with `action`, `conclusion`, `branch`, `trigger` (the run's event), `head_repo`, `from_fork`, `workflow`, `path` | 1; 4 when the code came from a fork and the trigger runs with the base repository's secrets (`pull_request_target`, `workflow_run`, `issue_comment`, `pull_request_review_comment`) |
| `organization` | `devops.org_<action>`; raw `event` is the audit-log name (`member_added` → `org.add_member`, `member_removed` → `org.remove_member`, `member_invited` → `org.invite_member`), with `member` and `role` | Audit severity of that name, else 2; `deleted` 5 |
| `team`, `team_add`, `membership`, `deploy_key`, `installation`, `installation_repositories`, `github_app_authorization` | `devops.<event>_<action>` | 3; `created` or `added` 4 |
| `branch_protection_rule`, `branch_protection_configuration`, `repository_ruleset`, `security_and_analysis`, `repository_import` | `devops.<event>_<action>` | 3; `deleted` or `disabled` 4 |
| `secret_scanning_alert`, `secret_scanning_alert_location`, `code_scanning_alert`, `dependabot_alert`, `repository_vulnerability_alert`, `repository_advisory`, `security_advisory` | `devops.<event>_<action>`; a secret-scanning alert whose `push_protection_bypassed` is true records it with `secret_type` and `bypassed_by` (DEV-024) | 3; `created` or `reopened` 4 |
| `security_and_analysis` turning a feature off | `devops.security_and_analysis` with `disabled` (the features that went from enabled to disabled) (DEV-025) | 4 |
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

### 3.4 Webhooks that start scans

Besides becoming events, some webhooks queue scan jobs when the connector's automation policy allows it (section 4.10):

| Provider | Starts a PR check | Starts a branch scan |
|---|---|---|
| GitHub | `pull_request` with action `opened`, `synchronize`, `reopened`, `ready_for_review` (not drafts) | `push` to the repository's default branch (not a deletion) |
| GitLab | `merge_request` with action `open`, `reopen`, or `update` with new commits (`oldrev` present); not drafts | `push` to the project's default branch |
| Azure DevOps | `git.pullrequest.created`, `git.pullrequest.updated` (status `active`, not drafts) | `git.push` updating the repository's default branch |

### 3.5 Event IDs

With a delivery ID, webhook events get the ID `gh-wh:{delivery}:{n}`, `gl-wh:{uuid}:{n}` or `ado-wh:{id}:{n}`. Without one, the ID includes the receive time in nanoseconds, so a retried delivery creates a second event.

---

## 4. Scanning layers

| Layer | Input | Trigger | Stored in | Engine label |
|---|---|---|---|---|
| 4.1 Commit secret scanner | Added lines of polled diffs | Every sync | `devops.secret_push` events | – |
| 4.2 Code scan | Stored, redacted commit diffs (last 500 commits) | **Code Scan** tab | `code_scan_results` | – |
| 4.3a History secrets | Every commit of the cloned branch | **SAST** tab | `sast_results` | `gitleaks`, or `history` (built-in patterns) |
| 4.4 Built-in SAST rules | The checkout (4.3) | **SAST** tab | `sast_results` | `builtin` |
| 4.5 Pattern rules / CodeQL | The checkout | **SAST** tab | `sast_results` | `semgrep` (opengrep or semgrep engine), `codeql`, `semgrep+codeql` |
| 4.6 Dependencies, IaC, licences, SBOM | The checkout | **SAST** tab | `sast_results` (`findings`, `sbom`) | `trivy`, or `osv` when Trivy is missing |
| 4.9 Pipeline-change detection | Polled commits | Every sync | `devops.cicd_modified` events | – |
| 5 Posture | Provider settings APIs | **Posture** tab | settings `devops.posture.last.{id}` | – |

Every SAST result stores `engines`: what ran, what was missing, and why something failed (for example `{"source":"git","gitleaks":"ran","semgrep":"ran","trivy":"ran","codeql":"ran","codeql-languages":"go,javascript","builtin":"ran"}`). The SAST tab shows it as chips; a crossed-out chip is an engine that did not run.

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

`POST /api/v1/devops-connectors/{id}/code-scan` reads the connector's last 500 stored commits and scans each stored file diff. Findings are deduplicated by `repository + category + title + file`. Every run inserts a new row in `code_scan_results`.

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

### 4.3 SAST: source download

`POST /api/v1/devops-connectors/{id}/sast[?repo=&branch=]`:

1. **Repositories.** One selected repository, or every repository in the last 500 stored commits. A selected repository must belong to the connector's organization (GitHub owner, GitLab group path, Azure DevOps organization; a GitLab group given by numeric ID is not checked), or the request is refused with 403: the token often reaches more than that organization, and the findings would be readable by every console user. The same check applies to `GET .../sast/branches`.
2. **Clone.** `git clone --single-branch --no-tags` of the branch (`HEAD` = default branch), with the **whole branch history** unless `OW_SAST_SECRET_HISTORY=false` (then `--depth 1`). If the full clone fails it is retried shallow. The token is sent as an `Authorization: Basic` header through `GIT_CONFIG_*` environment variables (GitHub user `x-access-token`, GitLab `oauth2`, Azure DevOps any user), never in the URL or the command line, and scoped to the provider's origin (`http.<origin>/.extraHeader`), so git sends it to no other host. The clone is hardened: hooks disabled, symlinks checked out as plain files (no scanner can follow a link out of the checkout), HTTPS only, no submodules, no LFS download, a redirect followed only on the first request (and then without the token when it leads to another host), no user or system git config. Limit: 5 minutes and `OW_SAST_MAX_REPO_MB` (default 2 048 MB) on disk.
3. **Fallback.** When the clone fails (git missing, network, permissions), the previous API download is used: the provider's file tree, source and configuration files only, capped at 1 000 files ranked by risk (CI files first, tests last), 300 000 bytes per file (5 MiB for lockfiles); GitHub as one tarball, GitLab and Azure DevOps one call per file. History secrets do not run then.
4. **Run the engines** per repository: history secrets → pattern rules → Trivy (or OSV) → built-in rules → CodeQL. A missing engine is skipped and recorded.
5. **Deduplicate** (4.7), count, and upsert one row per (connector, repository or `''`, branch). A scan of all repositories also stores each repository's own row (its branch, commit, findings and SBOM), so the repository page shows it and the coverage (8.1) counts it, with the engine report and, for a single-repository scan, the SBOM.

If no repository could be downloaded, the response carries a `warning` with the last clone error, shown in the SAST tab.

### 4.3a History secrets

With **gitleaks** installed: `gitleaks git` over the clone (its full rule set, 5 MB per blob). Without it: the built-in secret patterns of section 4.2 (critical and high ones only) over `git log -p` added lines, up to 5 000 commits.

One finding per (rule, file, secret), however many commits contain it:

| Field | Value |
|---|---|
| `rule_id` | `SECRET-<rule>` |
| Severity | **critical** when the secret is still in the file on the scanned branch; **high** when it was removed but remains in history |
| Detail | Rule, masked secret (first 4 and last 2 characters), the commit that introduced it, author and date, and whether it is still present |
| Fix | Revoke and rotate at the issuer first; deleting the line or rewriting history does not invalidate a leaked credential |

The secret value is never stored; it is only held in memory to compare with the current file.

### 4.4 Built-in SAST rules

212 regex rules (`sast_rules.go`). Each rule applies to files whose path matches its file pattern. It reports every matching line in a file, up to 10 per rule per file. A rule can carry an exclusion pattern: a matching line that also matches it is not reported (ANY001 skips interpolated values and SQL text; IAC001 skips `${...}` values). Matching is per line, so patterns cannot span lines. The snippet is the matched line, trimmed to 120 characters; for credential findings (CWE-798, 259, 321, 312, 522 and secret rules) every literal value in it is masked to its first two characters before the result is stored, shown, sent to AI or posted. On a clone, only source files (the same file types and size cap as the API download) are read; `.git` and dependency directories are not walked. The list is also available from `GET /api/v1/sast-rules`.

The "Detects" column is the first sentence of the rule's own description. `any` rules apply to the extensions in their file pattern.

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
| JS021 | javascript | SQL Injection | A SQL statement is built with a template literal or string concatenation and passed to a query function (mysql, pg, sequelize, knex.raw, Prisma $queryRawUnsafe, TypeORM). | CWE-89 | critical |
| JS022 | javascript | Cross-Site Scripting (XSS) - Angular Sanitizer Bypass | DomSanitizer.bypassSecurityTrust* turns off Angular's built-in escaping for the value; user-controlled content becomes script. | CWE-79 | high |
| JS023 | javascript | XML External Entity (XXE) Processing Enabled | The XML parser is told to substitute entities (libxmljs noent: true and similar), so a document can read local files or reach internal URLs. | CWE-611 | high |
| JS024 | javascript | Open Redirect | The redirect target comes straight from the request, so a link to this site can send users to any other site (phishing). | CWE-601 | medium |
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
| A01-JS003 | javascript | Token Stored in Browser Storage | A token written to sessionStorage is readable by any script on the page, so one XSS steals it (localStorage is rule JS012). | CWE-922 | medium |
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
| A02-JS003 | javascript | Base64 Is Not Encryption | Base64 encoding provides no security - it's trivially reversible. | CWE-311 | low |
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
| A08-JS001 | javascript | Unsafe Deserialization | A serializer that restores functions or classes (node-serialize, serialize-to-js, funcster) runs code from a crafted payload; JSON.parse does not and is not reported. | CWE-502 | medium |
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

### 4.5 Pattern rules and CodeQL

**Pattern rules** run with the **opengrep** engine (LGPL-2.1, with `--taint-intrafile` for taint across functions in a file) or, when only it is installed, the **Semgrep CE** engine (LGPL-2.1, `--metrics=off`). The rules are the **opengrep-rules** set bundled in the image at `/opt/obsidianwatch/rules/opengrep` (override with `OW_SEMGREP_RULES`; a directory mounted at `/semgrep-rules` is also used). Nothing is downloaded at scan time: the Semgrep registry packs (`p/default` and the `semgrep-rules` repository) are under the Semgrep Rules License, which limits them to internal, non-competing use, so the product never fetches them. Without an engine binary or a rules directory the layer is reported as missing. Mapping:

| Semgrep field | Finding field |
|---|---|
| `check_id` | `rule_id`; the title is the last dotted segment in title case (for example `...exec-detected` → `Exec Detected`) |
| `extra.severity` `ERROR` / `WARNING` / `INFO` | `critical` / `high` / `medium` |
| `metadata.cwe`, `metadata.owasp` | first value |
| `metadata.fix` | fix text |
| source lines | snippet: 2 lines before to 1 line after the match, at most 500 characters, matched lines marked `>` |

**CodeQL** runs only when the `codeql` CLI is installed. It analyses **every supported language** with at least 3 files (the 4 largest): JavaScript/TypeScript, Python, Java/Kotlin, C#, Ruby, C/C++ and Rust with `--build-mode=none` (no build, no repository code runs), and Go with an explicit `go build ./...` per Go module (every directory with a `go.mod`, up to 20, outside vendored, test-data and hidden directories; `go build -C <dir> ./...` for one in a subdirectory), with cgo off and the installed toolchain only; no Makefile or build script from the repository is run. Each language runs the `security-extended` suite of its pack (`codeql/<lang>-queries:codeql-suites/<lang>-security-extended.qls`). The languages analysed are listed in the engine report. The title is the rule `name`. Severity: the rule's `security-severity` score when present (≥ 9.0 critical, ≥ 7.0 high, ≥ 4.0 medium, otherwise low, the GitHub code-scanning bands); otherwise the rule's `problem.severity` / `severity` / default level, then the result's SARIF `level` (`error` → high, `warning` → medium, `note` / `recommendation` → low); medium when none is given. PHP and Swift are not analysed by CodeQL here (pattern rules cover PHP).

### 4.6 Dependencies, IaC, licences and SBOM

**Trivy** (`trivy fs`, scanners `vuln,misconfig,license`, `--list-all-pkgs`) runs over the checkout:

| Finding | From | `rule_id` | Severity |
|---|---|---|---|
| Vulnerable dependency, direct or transitive | Every lockfile and manifest Trivy reads: npm/yarn/pnpm, pip/Pipfile/poetry/uv, Go modules, Maven `pom.xml`, Gradle lockfiles, Gemfile.lock, NuGet, Cargo, Composer, Conan, Swift, Dart, Elixir, and more | `SCA-<CVE/GHSA>` | Trivy's rating |
| IaC / Dockerfile misconfiguration | Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, Azure ARM, Docker Compose (Trivy's built-in checks; failed checks only) | `IAC-<AVD id>` | Trivy's rating, with start and end line |
| Licence | Forbidden, restricted and reciprocal licences of dependencies (notice and permissive licences are not findings) | `LICENSE-<CATEGORY>` | Trivy's rating |

The vulnerability databases ship in the image (`/var/cache/trivy`). With network access Trivy refreshes them when they are stale; `OW_SCANNER_DB_UPDATE=false` keeps them frozen (fully offline). Checks use the set embedded in the binary (`--skip-check-update`), and `--offline-scan` stops Trivy from calling package registries.

**SBOM.** The packages Trivy found become a CycloneDX 1.5 JSON document (components with purl, licences, `transitive` flag and source file; vulnerabilities linked to their component, each with its rating, detail, `recommendation` (the fix) and an `advisories` URL). A vulnerability is listed once per component, even when several manifests declare the same version (for example the same Go module in five `go.mod` files); SBOMs stored before this rule are de-duplicated when shown. It is stored with the repository's result. **View SBOM** in the SAST tab opens the SBOM page (`/devops/sbom/{connector}?repo=&branch=`): header counts (components, transitive, vulnerable, running, deployed), facets (vulnerabilities by worst severity, runtime, direct/transitive, ecosystem, licence, manifest), and a component table sorted by worst vulnerability then runtime. The **Vulnerabilities** column shows the two worst IDs as tags (coloured by severity) and "+N"; a tag opens that vulnerability, a row or "+N" opens the component. The component drawer shows ecosystem, direct or transitive, every manifest that declares the version, licences, where it runs (hosts, services), counts by severity, the fix, and each vulnerability with its severity, description, triage decision, links to **NVD** (CVE IDs), **GitHub advisory** (GHSA) or **OSV** (GO-, PYSEC-, RUSTSEC-), the scanner's **Advisory**, and the **Issue** created from it; a filter appears for more than six vulnerabilities. Manifests, fix, triage and issue links come from the same scan's findings. The page offers **Export CSV** of the filtered components and **Download CycloneDX**. API: `GET /api/v1/devops-connectors/{id}/sast/sbom?repo=<full name>[&branch=]` returns the CycloneDX file; with `&view=1` it returns the flattened components with vulnerabilities and runtime status. Without Trivy the SBOM is built from the built-in manifest parser below. Scans of all repositories at once store no SBOM.

**Without Trivy**, or when its vulnerability database is unavailable, the built-in parser and OSV are used as before: lockfiles in the checkout (up to 50 files, 8 MiB each), exact `name + version` pairs:

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

Up to 2 000 unique packages go to `POST https://api.osv.dev/v1/querybatch` (batches of 500), and up to 150 advisories are fetched for details, within 60 seconds. Findings: `SCA-<OSV id>`, severity from `database_specific.severity` (else medium), fix from the first fixed version, engine `osv`. A network failure produces no OSV findings and does not fail the scan.

Implemented in: `sast_engines.go` (`runTrivy`, `parseTrivy`, `buildCycloneDX`, `sbomFromManifests`), `sast_sca.go`.

### 4.7 SAST result deduplication

`deduplicateSASTFindings` (`sast_engine.go`):

1. Exact duplicates are removed by `engine + repository + rule_id + file + line`.
2. Two built-in rules on the same line with the same CWE (for example JS002 and A03-JS003 for `eval`) are one finding: the more severe is kept.
3. Every non-CodeQL finding (Semgrep, built-in rules, OSV) is kept. A CodeQL finding within ±2 lines of a Semgrep finding in the same file **of the same repository** marks that Semgrep finding as `semgrep+codeql` and is dropped. Other CodeQL findings are kept.
4. A built-in finding within ±2 lines of a Semgrep or CodeQL finding with the same CWE in the same file is dropped: the engine's finding has the better message.

Before these steps, credential snippets are masked (4.4), and findings in test code are marked: a file under a test, fixture, example or sample directory (`test`, `tests`, `__tests__`, `spec`, `e2e`, `cypress`, `testdata`, `fixtures`, `mocks`, `examples`, `samples`, `demo` and similar) or named by a test convention (`*_test.go`, `test_*.py`, `*.test.ts`, `*.spec.js`, `*Test.java`, `*Tests.cs` and similar) gets `test_code: true` and one severity level less (critical → high → medium → low). Secrets and dependency findings keep their severity. A pull request blocks on the lowered severity.

### 4.8 IaC checks

| Check | Where |
|---|---|
| Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, ARM, Compose misconfigurations | Trivy (4.6) |
| `IAC001` Hardcoded secret in Terraform (`.tf`, `.tfvars`) | built-in rules |
| `IAC002` Hardcoded secret in YAML config (`.yaml`, `.yml`) | built-in rules |
| `IAC003` Secret in Dockerfile `ENV` | built-in rules |
| `IAC004` Unpinned Docker base image | built-in rules |
| Terraform, Kubernetes, Dockerfile and YAML pattern rules | opengrep-rules (4.5) |
| Terraform state, kubeconfig, `.tfvars`, secrets YAML committed | code scan sensitive files (4.2), sync-time sensitive-file events (4.1.1) |

Container images are not pulled or scanned; Dockerfiles are checked as configuration.

### 4.9 Pipeline-change detection

| Mechanism | Output |
|---|---|
| Polled commit touches a CI/CD file | `devops.cicd_modified` with the risky additions found (section 2.4). Alerts: DEV-023 when anything risky was added, DEV-003 (informational) otherwise. |
| Pipeline runs (GitLab pipelines, Azure DevOps builds; GitHub `workflow_run`, GitLab `pipeline` and Azure DevOps build webhooks) | `devops.pipeline_run` / `devops.workflow_run` events, severity 1 (2 when failed). GitHub `workflow_run` records the trigger and whether the code came from a fork (DEV-005). |
| SAST pattern rules and Trivy | Workflow and pipeline files are part of the checkout; Trivy's misconfiguration checks and the opengrep rules for YAML / GitHub Actions apply. |
| PR checks | A pull request that changes a workflow is scanned like any other change. |

### 4.10 Automation: on push, on a schedule, and pull/merge request checks

Set per connector on the **Automation** tab (`GET/PUT /api/v1/devops-connectors/{id}/scan-policy`, admin to change; stored in setting `code.policy.{id}`). Everything is off by default.

| Setting | Effect |
|---|---|
| Scan every pull request | A `pull_request` (opened, synchronize, reopened, ready for review; drafts skipped), GitLab `merge_request` (open, reopen, update with new commits) or Azure DevOps `git.pullrequest.created/updated` webhook queues a PR check |
| Post comments | On a **public** repository (or when the visibility cannot be read): one summary with the outcome and counts by severity only, no titles, files or lines, posted when the outcome or the count changes, and no AI fixes; the details are in the console. Otherwise: summary comment plus inline comments on changed lines; each finding is commented once per PR (keyed on rule, file and the text of the line, so it survives lines moving) |
| Fail the check on | `critical` (default), `high`, `medium`, `low` or never |
| Run CodeQL on pull requests | Off by default (it adds minutes per update) |
| AI fix suggestions in comments | Off by default. Up to 5 per update (section 4.13). Needs an AI provider and the source-sharing opt-in. |
| Inline comments per update | 1-100, default 20; the rest are listed in the summary |
| Scan on push | A push to the repository's **default branch** queues a full branch scan |
| Scheduled scan | Every 5 days by default (all repositories and all branches), or daily, or weekly on Monday, at a UTC hour; all repositories seen for the connector, or a listed set; all branches (up to 2,000 per repository, one job each, stored per branch) or the default branch only. A rescan is how a fixed finding is noticed: each branch's new result replaces its old one. If listing branches fails, the default branch is scanned |

**Jobs** are rows in `code_scan_jobs` (migration `076`): queued, running, done or failed, with the trigger, target, finding count, whether it blocked, what was posted, and the findings. The same target and commit is never queued twice while one is pending. One worker runs them in order (`OW_CODE_SCAN_WORKERS`, up to 4); a restart fails jobs that were running. **Scan all repositories now** queues a manual branch scan of every known repository. A branch scan stores its result as the repository's SAST result (the Code pages show it).

**A PR check:**

1. Sets the commit status to pending.
2. Fetches the base branch and the PR head (`refs/pull/N/head` on GitHub, `refs/merge-requests/N/head` on GitLab, the source branch on Azure DevOps; fork PRs work on GitHub and GitLab) into an empty hardened repository, checks out the head and finds the merge base (deepening the shallow fetch once if needed).
3. Runs every engine on the head; secrets are searched only in the PR's own commits (`merge-base..HEAD`).
4. Keeps what the PR introduces: findings on lines it changed (a multi-line finding counts if it overlaps a change), secrets from its commits, and dependency, licence or IaC findings without a line in files it changed that the merge base does not already have (the base is scanned only when needed). Findings dismissed by triage (section 4.12) are dropped and counted in the job notes. Dependency findings carry their runtime reachability (section 4.11), shown in the comment as a count of services and hosts only: a pull request can be public, so the names stay on the finding page in the console.
5. Sets the status: failure when a kept finding is at or above the blocking level, otherwise success.
6. Posts the summary and inline comments (GitHub: one review; GitLab: MR note and line discussions; Azure DevOps: PR threads). If GitHub refuses a review because a line is outside its diff, the findings are posted as a list in one comment instead. A summary is posted only when new findings appear or the outcome changes.

**Blocking a merge** is done by the provider: make the status required.

| Provider | Status name | Where to require it |
|---|---|---|
| GitHub | `ObsidianWatch / code scan` | Branch protection or ruleset → require status checks |
| GitLab | `ObsidianWatch code scan` (external commit status, part of the pipeline) | Settings → Merge requests → Pipelines must succeed |
| Azure DevOps | genre `obsidianwatch`, name `code-scan` | Branch policies → Status checks → required |

Set `OW_PUBLIC_URL` to the management UI's address to make the status link back to it.

Implemented in: `code_automation.go`, `code_reporters.go`, `store/code_jobs.go`.

### 4.11 Runtime reachability of dependency vulnerabilities

A dependency finding says a vulnerable version is in a lockfile. Runtime reachability says whether that version is actually running.

**Where the data comes from.** The Linux agent's host runtime sensor (application profile, `app_monitoring.ebpf.enabled: true`) knows the service processes on the host: those discovered by their listening ports and those sending OpenTelemetry. Every 15 minutes it reads each one through `/proc/<pid>` (containers included, through `/proc/<pid>/root`) and reports a `runtime_inventory` event with the packages it found. An unchanged inventory is re-sent every 6 hours; large ones are split into events of 500 packages.

| Language | Loaded (code is in the process) | Deployed (installed where the process loads code from) |
|---|---|---|
| Go | every module in the binary's build info | – |
| Java / Kotlin | each memory-mapped jar (Maven coordinates from `META-INF/maven/**/pom.properties`; shaded jars give several) | jars nested in a Spring Boot or WAR archive (`BOOT-INF/lib`, `WEB-INF/lib`) |
| Python | a distribution whose native extension (`.so`) is mapped | every distribution (`*.dist-info`) in the interpreter's or virtualenv's site-packages |
| Node.js | a package whose native addon (`.node`) is mapped | `node_modules/.package-lock.json` (or each top-level `package.json`) in the process's working directory |
| .NET | an assembly from `~/.nuget/packages/<id>/<version>/`, or a `deps.json` package whose runtime assembly is mapped | every package in the app's `*.deps.json` |

Nothing is executed and nothing is written; at most 5 000 packages per process. Windows and macOS agents do not report inventories yet. Pure Python and JavaScript modules are not memory-mapped, so for those languages "deployed" is usually the strongest evidence.

**Indexing.** The management server folds the events into `runtime_packages` (migration `077`) every 2 minutes, keyed by package, version and process context (agent, service, container, executable); rows not seen for 14 days are deleted.

**Labels.** Every dependency finding (`SCA-*`, from Trivy or OSV) carries its ecosystem, package and version, and gets a `reachability` label when it is read (SAST tab, Code overview, Insights → Code findings, PR comments):

| Level | Meaning |
|---|---|
| `loaded` | this exact version is loaded by a process seen in the last 24 hours (hosts and services listed) |
| `deployed` | installed for such a process, not proven loaded |
| `not_running` | hosts report inventories and none has this version |
| `unknown` | no host has reported an inventory in the last 24 hours |

Names are matched case-insensitively (PyPI also treats `-`, `_` and `.` alike) and Go versions with or without the leading `v`. On the Code pages the match is fleet-wide: a version running on any monitored host counts, and the label lists where. On a service's **Code** tab (section 4.15) the same data is narrowed to that service's own processes.

**Attribution to a service.** Each inventory row records the agent, process id (`pid`, migration `080`), container and discovered service name. A row belongs to a monitored service when, on the same agent, its pid is a live instance's pid; else its container id matches an instance's container (full or shortened id); else its discovered name is the service's name. The executable alone is never used, because every Java service on a host shares `/usr/bin/java`. Rows indexed before migration `080` have pid 0 and fall back to container and name.

Findings of equal severity sort running ones first; the Code overview has a **Runtime** facet.

**Alert CODE-RT-001 "Vulnerable dependency running".** When a critical or high dependency finding from the latest SAST result of any repository (last 30 days) is **loaded** on a host, an alert is raised on that host (severity 5 for critical, 4 for high; MITRE T1190), one per vulnerability, package, version and host per day. The check runs when new inventories arrive and every 10 minutes. When the loading process belongs to a monitored service, the alert names it ("service orders (prod) on web-01"), its severity is weighted like application alerts (one level up for an internet-facing service, one for high or critical criticality, capped at 5), and it is linked to every service on that host that loads the package, so it shows on those services' **Alerts** tab and on the host page.

**Lookup.** `GET /api/v1/runtime-packages?name=<package>[&ecosystem=&version=&hours=]` answers "is this package running anywhere?" with every host, service and process it was seen in, and the number of hosts reporting inventories.

Implemented in: `agents/linux/internal/runtimeinv`, `agents/linux/internal/ebpf/inventory_linux.go`, `management/backend/internal/api/code_reachability.go`, `store/runtime_packages.go`.

### 4.12 Triage and learning

**Decisions.** On a SAST finding (SAST tab, expand the finding) an analyst or admin records **False positive**, **Accept risk** (both need a reason) or **Confirm**, or clears the decision. `POST /api/v1/devops-connectors/{id}/findings/triage` stores it in `code_finding_triage` (migration `078`) per connector, repository and **fingerprint**: SHA-1 of the rule, the file, and the package and version (dependencies) or the flagged code without line numbers (code), else the title. The fingerprint survives rescans and lines moving; a different dependency version or changed code is a new finding.

**Triage rules.** An admin can dismiss a rule for one repository or every repository of the connector, optionally under a path prefix and with an expiry (`POST .../triage-rules {repo, rule_id, path_prefix, status, reason, days}`; listed and deleted on the **Automation** tab). A reason is required.

**Effect of a dismissal** (false positive or accepted risk, by decision or rule): the finding is hidden in the SAST tab unless **Show dismissed** is ticked, it is labelled in the Code overview (**Triage** facet), it never blocks or gets a comment in a PR check, it raises no CODE-RT-001 alert, and it is not sent to the AI triage summary. "Confirmed" changes nothing but the label and feeds learning.

**Learning.** When findings are read, earlier decisions on the same rule produce hints on new, undecided findings (shown as a dashed badge and a line in the expanded finding):

| Hint | When |
|---|---|
| Likely false positive (this repository) | At least 3 earlier findings of the rule in the repository were dismissed, and at least 4 times as many dismissed as confirmed. If 2 or more of them share a directory with this finding, the hint names it and the suggested rule is narrowed to that path prefix. |
| Likely false positive (across repositories) | The rule was dismissed in 3 or more repositories of the connector and never confirmed anywhere. |
| Likely real | 2 or more earlier findings of the rule in the repository were confirmed and none dismissed. |

A "likely false positive" hint offers a one-click triage rule (with the reason typed in the finding). Hints never hide anything by themselves.

Implemented in: `code_triage.go`; UI `pages/code/FindingActions.jsx`, `AutomationPanel.jsx`.

### 4.13 Fix suggestions

**Suggest fix** on a SAST finding (`POST /api/v1/devops-connectors/{id}/sast/fix {repo, branch, finding}`):

| Finding | Suggestion |
|---|---|
| Dependency (`SCA-*`) | No AI. The fixed version from the advisory, and the command for the package manager (`npm install pkg@v`, `yarn up`, `pnpm update`, `poetry add`, `pipenv install`, `uv add`, `go get …@v… && go mod tidy`, `dotnet add package --version`, `bundle update --conservative`, `cargo update -p --precise`, `composer require`, or the Maven coordinates to change). Without a fixed version it says so and gives the runtime status. |
| Code finding with a line | AI. The server reads the file from the provider at the scanned branch, sends the finding and up to 30 lines around it (fenced as untrusted input, with the prompt-injection guard), and asks for an explanation, a confidence, whether it looks like a false positive, and a replacement for a line range. The server accepts the range only if it lies inside what the model was shown and is at most 40 lines, and builds the unified diff itself. Nothing is applied to the repository. |
| No line (history secret, configuration) | No AI; the finding's own fix text applies. |

AI suggestions need an AI provider (Settings → AI, Groq or Anthropic) **and** the operator opt-in to send source (`ai.send_source_snippets = true`); otherwise the request answers 412 with the reason. They are cached for 30 days per finding, file content around it and model (`code_fix_cache`) and share the source-AI rate limit (6 requests per 10 minutes).

**In PR comments** (policy "AI fix suggestions in comments"): for up to 5 inline findings per update the suggestion is built from the PR checkout. A one-line replacement of the commented line becomes a one-click suggestion block on GitHub (```` ```suggestion ````) and GitLab (```` ```suggestion:-0+0 ````); anything else is shown as a diff; dependency findings get the upgrade command; an AI "may be a false positive" verdict is shown too.

**AI triage summary** (SAST tab, **AI Triage**): unchanged in shape (risk score, critical issues, likely false positives, actions), now over the repository on screen and without dismissed findings.

Implemented in: `code_fix.go`, `code_reporters.go` (`fixBlock`), `sast_engine.go` (`handleSASTAI`).

### 4.14 Creating issues from findings

**Create issues** (button next to **Run SAST Scan** and **AI Triage** in the SAST tab, shown once a repository's result is loaded) turns that repository's latest result for the branch into issues on its platform: GitHub issues, GitLab issues (created confidential), or Azure DevOps "Bug" work items. `POST /api/v1/devops-connectors/{id}/sast/issues {repo, branch, min_severity, dry_run}`; analysts and admins.

| Aspect | Behaviour |
|---|---|
| Grouping | One issue per problem per repository: per rule for code findings and secrets (every location listed as a checklist with links to the file and line), per package version for dependencies (every vulnerability listed). Not one issue per finding. |
| Filter | At or above a chosen severity (default high). Findings dismissed by triage are left out. |
| Preview | The dialog first shows what would be created (a dry run): each problem, its count, and whether an issue already exists. Nothing is written until **Create**. |
| Repeat clicks | ObsidianWatch records which findings each issue covers (`code_finding_issues`, migration `079`). A new problem gets a new issue; new locations of a known problem are added as a comment on its issue; nothing already sent is sent again. |
| Open / closed | Not tracked. Closing an issue does not dismiss the finding, and fixing the code does not close the issue. The SAST results stay the source of truth. Each finding with an issue shows an **issue** link. |
| Public repositories | Skipped: an issue would disclose the vulnerability before it is fixed. If the visibility cannot be read, the repository is treated as public. |
| Content | Severity, repository, branch, description, CWE/OWASP, runtime status when the package is running, fix, locations; secrets never include the value. Labels/tags `security`, `obsidianwatch`, `severity:<level>`. |
| Limit | 50 new issues per click; click again for the rest. |
| Token | Needs permission to create issues: GitHub Issues (read and write), GitLab `api`, Azure DevOps Work Items (read and write). |

Implemented in: `code_issues.go`; UI `pages/code/CreateIssuesDialog.jsx`.

### 4.15 Linking code to a monitored service

An admin links a repository branch to an Application Monitoring service; there is no automatic linking. Services are per environment (name + environment), so a production service can follow `main` and a staging one `develop`. A service can have several links (for example a monorepo and a shared library).

**Link.** Service page → **Code** tab → **Link repository**: pick the connector, the repository (from the provider) and the branch (from the provider, default marked, with the last scan time). `POST /api/v1/app/services/{id}/code-links` `{connector_id, repo, branch, is_default}` (admin). Linking again changes the branch. If the branch has no stored scan, a branch scan is queued (trigger `service-link`) and the tab refreshes while it runs. **Unlink**: `DELETE /api/v1/app/services/{id}/code-links/{link}` (admin). Links are stored in `service_code_links` (migration `080`) and are removed with their connector.

**Which scan: the deployed commit first.** When the service's live instances report the commit they run (application capability.md section 1.2), the tab groups them by commit ("Running 3f2a… · 3 instances on web-01, web-02 · from container image label"). For the commit with the most instances it shows the findings of the scan of **that commit**: a stored result whose `commit_sha` is that commit (every scan now records the commit it checked out, migration `081`), or a scan of exactly that commit. A commit with no scan is queued as a job of kind `commit` (trigger `deployed`): the commit is fetched by id (`git init`, `git fetch <remote> <sha>`, detached checkout, same hardening as every clone) and the result is stored as branch `@<sha>`; the 20 newest commit scans of a repository are kept. Commit scans never appear in branch lists, the repository's own result, the Code overview or Insights. A watcher checks linked services every 5 minutes (and when a link is created) and queues up to 10 commit scans per round; a failed commit scan is retried after 6 hours. The state of each commit is shown: scanned (with counts), scan queued, scanning, scan failed (with the error), short commit id (7-character ids cannot be fetched), or different repository (the instance reports a repository URL that is not the linked one; no scan is queued). While no commit is reported or its scan is pending, the findings are those of the linked branch, and the tab says so.

**Branch fallback.** The latest stored result for that repository whose branch is the linked branch, or, when the linked branch is the default branch, a result stored as `HEAD` or with no branch (scheduled and manual default-branch scans).

**Code tab** (`GET /api/v1/app/services/{id}/code`):

| Part | What it shows |
|---|---|
| Linked code | each link: repository, branch, connector, last scan (or "scanning…"), counts by severity, dismissed count |
| Findings | every not-dismissed finding of the linked scans. Dependency findings get **Running here**: `loaded` (this service's process has the version in memory), `deployed` (in its files, not seen loaded), `not_in_service` (its processes do not run this version), `unknown` (no inventory for this service). Code and secret findings show "code". Filter: running here or not known (default), dependencies, code and secrets, all |
| Priority | the scanner severity, raised one level for an internet-facing and one for a high/critical service when the package is loaded here, lowered one level when it is not in this service (capped 5) |
| From the host scan | per host: the OS package the platform service runs from (for example `nginx-core 1.18.0`, `postgresql-16 16.2`), host-scan port findings on the service's listening ports, and cached NVD CVEs for that package |
| Also loaded by this service | vulnerable package versions this service loads that were found in repositories **not** linked to it (evidence for which repository it is really built from) |

The page also says why runtime matching is missing when it is: no live instance, no inventory from its hosts, or inventory with nothing attributed to this service.

Implemented in: `app_code.go`, `store/service_code_links.go`, frontend `pages/app/tabs/AppTabCode.jsx`.

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

Rules for "cannot assess": if the API refuses a call (permissions, plan), no finding is raised for that check, and the check is listed under **not assessed** instead. The result has a `not_assessed` list, one entry per check and reason: `check`, `count` (repositories or projects), `reason` (for example "access denied (403)" or "setting not visible to this token (repository admins only)"), `fix` (the token rights that would let it run) and up to 5 example resources. The **Posture** tab shows these in an amber box above the findings ("A finding count of 0 does not mean these are configured"), and the summary line counts them. What lands there:

| Provider | Not assessed when |
|---|---|
| GitHub | `GET /orgs/{org}` fails (other than 404, a personal account) or does not return `two_factor_requirement_enabled` (only org owners see it); a repository's `security_and_analysis` is absent (only repository admins see it); the branch-protection call fails with anything but 404 (403 without admin rights, or private repositories on GitHub Free); no repository is visible at all |
| GitLab | the group call fails or hides `require_two_factor_authentication`; `protected_branches` fails for a project (Developers cannot read it); no project with a default branch is visible |
| Azure DevOps | a project's repository list or policy configuration call fails |

So a token without owner or admin rights gives an honest "N checks not assessed" instead of a clean result. GitHub archived repositories and forks are skipped. GitLab empty projects, Azure DevOps disabled repositories, and repositories without a default branch are skipped. GitHub repository rulesets are not read, so a branch protected only by a ruleset is reported as "not protected". GitLab wildcard patterns other than `*` (for example `release/*`) are not matched.

Implemented in: `devops_posture.go`.

---

## 6. Platform threat detection

Platform threat detection watches what happens **on** the Git platforms (who changed access, pipelines, protections, secrets, which code left) rather than what is in the code. Inputs are the `devops.*` events from polling (section 2) and webhooks (section 3). Output is alerts in the normal alert queue, with the same workflow, notifications and response as endpoint and cloud alerts.

**Engine.** Every `devops.*` event is evaluated by one path, `runDevOpsCursor`: a DevOps-only cursor over `ingested_at` with a 7-day first look-back. It runs at start-up, on every detection interval, and whenever an ingest notification arrives (the management server notifies after it stores connector or webhook events, so webhook alerts appear within seconds). The main detection pass skips DevOps events. Rule toggles, severity overrides, retired rules and allow-lists (`engineGate`) apply.

**Dedup.** Key `sig:{rule}:host:{host}:d:{UTC day}:e:{entity}`, the entity being a hash of connector, repository, actor, file or path, branch or ref, member and rule (`devopsDedupKey`); DEV-029/030 also include the IP. Within the alert-grouping window (same title and host, open alert) further hits are added to the open alert as related events.

Alert title: `[<MITRE>] <Name>`. Host: the event host (organisation, or repository for GitHub audit entries with one).

### 6.1 Rules

"Action / event / suffix" means the rule compares exact values against the raw `action` field, the raw `event` field, or the event type without the `devops.` prefix (`devopsParse`, `devops_typed.go`). Azure DevOps and GitLab audit entries carry a canonical `event` name (sections 2.2, 2.3), so the same rules apply to them.

| ID | Name | Fires on | Sev | MITRE |
|---|---|---|---|---|
| DEV-001 | Secret or Credential Pushed to Repository | `devops.secret_push` (commit secret scanner, section 4.1) | 5 | T1552.001 |
| DEV-002 | Sensitive File Committed | `devops.sensitive_file` | 4 | T1552.001 |
| DEV-003 | CI/CD Pipeline Configuration Modified | `devops.cicd_modified` with **no** risky addition (informational) | 2 | T1195.002 |
| DEV-004 | Self-Hosted Runner Registered | `runners.create`, `runner_registered`, `enterprise/org/repo.register_self_hosted_runner`, or `type` = `self-hosted` with a runner action; Azure DevOps agent pool creation | 4 | T1195.002 |
| DEV-005 | Fork Code Ran in a Privileged Pipeline | `devops.workflow_run` with `from_fork` and a trigger that runs with the base repository's secrets (`pull_request_target`, `workflow_run`, `issue_comment`, `pull_request_review_comment`); the `in_progress` delivery is ignored | 4 | T1195.002 |
| DEV-006 | Private Repository Made Public | `repo_publicized`, `repo.publicized`, `repository.publicized`, `made_public`, `publicized`, `visibility_change`, `changed_visibility_to_public`, or `repo.access` / `repository.access` with `visibility` = `public` | 5 | T1530 |
| DEV-007 | Repository Deleted | `repo.destroy`, `repo_destroy`, `repository.deleted`, `repository_deleted`, `repo_deleted`, `project_destroy`, `project.destroy`, `project_deleted`, `project_destroyed`, `git.repositorydeleted`, `git.repositorydestroyed` | 4 | T1485 |
| DEV-008 | Repository Transferred to External Account | `repo.transfer`, `repo_transfer`, `repository.transferred`, `repository_transferred`, `transfer_start`, `transferred` | 4 | T1537 |
| DEV-009 | New Organization Owner or Admin Added | `org.add_member`, `org_add_member`, `member_added`, `added_to_org`, `org.update_member`, `member.added`, `org.invite_member` **and** `role` / `permission` = `owner` or `admin` | 5 | T1098 |
| DEV-010 | Personal Access Token Created | `personal_access_token.created`, `pat.created`, `access_token_created`, `create_pat`, `personal_access_token.access_granted` | 4 | T1098 |
| DEV-011 | Deploy Key Added to Repository | `deploy_key.create`, `deploy_key_added`, `repo.add_deploy_key` | 3 | T1098.004 |
| DEV-012 | OAuth Application Installed with Broad Permissions | `oauth_application.create`, `integration_installation.create`, `app_installation`, `github_app_installed`, `oauth_access.create` | 4 | T1550.001 |
| DEV-013 | Branch Protection Removed or Weakened | `protected_branch.destroy`, `protected_branch_deleted`, `branch_protection_rule_deleted`, `remove_branch_protection`; or admin enforcement / stale reviews / code-owner review turned off | 4 | T1562 |
| DEV-014 | Force Push to Protected Branch | An event with a `branch` field: `forced` or `deleted` on a protected branch name. Audit entries: a force-push action with a protected `branch` field. | 4 | T1562 |
| DEV-015 | Audit Log Streaming Disabled | `audit_log_streaming.disabled`, `audit_stream_delete`, `log_streaming_disabled`, `stream_key.destroy`, `audit_log_streaming.destroy` | 5 | T1562.008 |
| DEV-016 | Webhook Created on Organization | `hook.create`, `webhook_created`, `org_webhook_add`, `project_hook_add`, `org.add_webhook` | 3 | T1071.001 |
| DEV-017 | Repository Made Public Outside Business Hours | DEV-006's match, outside business hours | 5 | T1530 |
| DEV-018 | Admin Added to Org Outside Business Hours | DEV-009's match, outside business hours | 5 | T1098 |
| DEV-019 | Mass Deletion Commit | `devops.mass_deletion` | 3 | T1485 |
| DEV-020 | Risky Dependency Change | `devops.dependency_change` with risks (install script, git/URL dependency, extra index or registry, go.mod replace). Version bumps alone do not alert. | 3 | T1195.001 |
| DEV-021 | Commit Committer/Author Mismatch Without Signature | `devops.push` with `committer_mismatch` and not `verified` (GitHub polling; the web-flow committer is ignored) | 3 | T1565 |
| DEV-022 | Azure DevOps High-Risk Audit Change | An Azure DevOps audit entry rated 4 that no more specific rule covers (permissions, service connections, policies, extensions) | 3 | T1098 |
| DEV-023 | Dangerous CI/CD Pipeline Change | `devops.cicd_modified` with risky additions (section 2.4). The alert severity follows the event: 5 for the pwn-request pattern. | 4 | T1195.002 |
| DEV-024 | Secret Scanning Push Protection Bypassed | `secret_scanning_push_protection.bypass` (audit) or a secret-scanning alert with `push_protection_bypassed` (webhook) | 4 | T1552.001 |
| DEV-025 | Repository Security Feature Disabled | `repository_secret_scanning.disable`, `repository_secret_scanning_push_protection.disable`, `dependabot_alerts.disable`, `repository_vulnerability_alerts.disable`, `dependabot_security_updates.disable`, org push-protection disable, code scanning disable; webhook `security_and_analysis` turning a feature off | 4 | T1562.001 |
| DEV-026 | CI/CD Secret or Variable Changed | Actions secret create/update/remove (org, repo, environment), Codespaces/Dependabot org secrets; GitLab CI variable changes; Azure DevOps variable groups and secure files | 3 | T1098 |
| DEV-027 | Branch Protection Bypassed | `protected_branch.policy_override`, `protected_branch.rejected_ref_update_override`, `repository_ruleset.bypass`; Azure DevOps `Git.RefUpdatePoliciesBypassed` | 4 | T1562 |
| DEV-028 | Mass Repository Clone or Download | `devops.repo_clone_summary` with 15 or more distinct repositories for one human actor in one sync batch (about 5 minutes). Actors ending `[bot]` / `-bot`, `github-actions`, `dependabot` are excluded. GitHub audit log only. | 4 | T1213.003 |
| DEV-029 | Platform Activity from a Known-Malicious IP | Any DevOps event whose `src_ip` (GitHub `actor_ip`, GitLab `details.ip_address`, Azure DevOps `ipAddress`) is an IP indicator from threat intelligence (OTX indicators below the OTX confidence threshold are ignored, as for endpoint rules) | 5 | T1078 |
| DEV-030 | Sensitive Platform Change from a New IP | An event of severity 4 or more from an actor and IP, when the actor used other IPs on the platform in the last 30 days but never this one | 3 | T1078 |
| DEV-031 | Organization or Repository Webhook Removed | `hook.destroy`, `hook.active_changed`, `webhook_deleted`, `project_hook_destroy`, `group_hook_destroy`, GitLab "removed hook". If it was the ObsidianWatch webhook, real-time detection stops (polling continues). | 3 | T1562.008 |
| CODE-RT-001 | Vulnerable dependency running | A critical or high dependency finding from the latest SAST result of a repository is loaded by a running process (section 4.11); not for dismissed findings. Host = the server running it. | 5 / 4 | T1190 |

DEV-029 and DEV-030 need data outside the event (threat intelligence, the actor's history), so they are evaluated by the DevOps pass itself; they appear in the rule list and follow the same toggles and overrides.

### 6.2 Coverage by provider

| Rules | GitHub | GitLab | Azure DevOps |
|---|---|---|---|
| DEV-001, 002, 019, 020, 021 | polled commits (019/020/021 GitHub only) | polled commits (001, 002) | polled commits (001 by path only) |
| DEV-003, 023 | polled commits, content analysed | polled commits, content analysed | polled commits, paths only (DEV-003) |
| DEV-004 | audit, webhook | – | audit (agent pool) |
| DEV-005 | webhook `workflow_run` | – | – |
| DEV-006, 017 | audit, webhooks | audit | audit (project visibility) |
| DEV-007, 008 | audit, webhooks | audit, webhooks, project events | audit |
| DEV-009, 018 | audit, `organization` webhook | audit | audit (admin group) |
| DEV-010, 011, 012, 013, 015, 016, 031 | audit, webhooks | audit (where GitLab records the action) | audit: 010, 012, 013, 015 |
| DEV-014 | webhook `push` | webhook `push` (deletions) | webhook `git.push` (deletions) |
| DEV-022 | – | – | audit |
| DEV-024, 025 | audit, webhooks | – | – |
| DEV-026 | audit | audit | audit |
| DEV-027 | audit | – | audit |
| DEV-028 | audit (Enterprise, git events in the audit log) | – | – |
| DEV-029, 030 | audit (actor IP) | audit (IP) | audit (IP) |
| CODE-RT-001 | any provider's SAST results × Linux agent inventories | same | same |

Audit-based rules need the provider's audit source: GitHub Enterprise Cloud audit log (an org owner's token), GitLab Premium group audit events, Azure DevOps organisation auditing. Without it, GitHub falls back to public user events and many rules have no input; the connector shows a coverage note.

### 6.3 Tuning

| Need | How |
|---|---|
| Turn a rule off or change its severity | Detect → Rules (general rule settings) |
| Silence a known actor, repository or IP | Detect → Suppressions / allow-lists (`engineGate`) |
| Business hours for DEV-017/018 | Settings `detection.business_hours` (for example `07-19`) and `detection.business_tz` (IANA zone); default 06-22 UTC |
| OTX confidence for DEV-029 | Setting `ioc_otx_min_confidence` (default 70) |
| Stop CODE-RT-001 for an accepted risk | Triage the dependency finding as accepted risk (section 4.12) |

Implemented in: `devops_sigs.go`, `devops_detect_more.go`, `devops_typed.go`, `business_hours.go`, `detection_engine.go` (`runDevOpsCursor`), `code_reachability.go` (CODE-RT-001).

---

## 7. Finding identity, merging and repository severity

### 7.1 On the Code pages (frontend)

The Code pages (section 8) build findings in the browser from three API calls per connector: `GET .../code-scan` (latest run), `GET .../sast` (its `scans` list: the latest SAST row of every repository of the connector), and `GET .../posture`. Each finding gets:

| Field | Derivation |
|---|---|
| `repo` | Short repository name: the last path segment, before any `@branch`, lower-cased. `acme/api`, `group/sub/api` and `org/proj/api` all become `api`. |
| `where` | `file[:line]`, or the posture resource |
| `source` | `scan`, `sast` or `posture` |
| `type` | code-scan category (`secret`, `dependency`, `dangerous_code`, `sensitive_file`, `config`), or `sast`, or `posture` |
| `sev` | 5 critical, 4 high, 3 medium, 2 low, 1 info or unknown |
| `reach` | SAST dependency findings: runtime reachability level (section 4.11) |
| `triage` | SAST findings: `confirmed`, `false_positive`, `accepted_risk`, a learned hint, or `open` (section 4.12) |

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

The rule ID and CWE are kept for SAST findings, and dependency findings carry `package`, `version` and `reachability`. Posture findings use the resource (`org/repo@branch`) as `repo`.

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

The header shows a state (for example "2 repositories with critical findings"), the number of repositories, providers and sources, and the time of the last scan. Header numbers: **Repositories scanned** (repositories with a stored SAST result / repositories the sources report now), **Branches scanned** (branches with a stored SAST result / all branches of those repositories), **Open findings**, **Secrets exposed** (findings of type `secret`), **Critical findings**, **Branch and access issues** (posture findings). Buttons: **Reload**, **Export** (CSV: severity, title, organisation, repository, where, type, source, scanned_at), **Connect source**.

Coverage comes from `GET /api/v1/devops-connectors/{id}/sast/coverage` per connector, after the repository list: `repos_total`, `repos_scanned`, `branches_total`, `branches_scanned`, `branches_partial`, `repos_partial`, and per repository its default branch, whether it was scanned, the last scan, and branches scanned / total. A branch counts as scanned when a stored result exists for it (`HEAD` = the default branch); results of single commits (`@sha`) and of "scan all" (`''`) are not branches, and branches or repositories that no longer exist are not counted. Branch lists are one provider call per repository: they are fetched four at a time, cached 30 minutes, for the 300 most recently scanned repositories. "partial" is shown next to a number when some branch lists could not be read (or a source has more than 300 repositories), or when a source's repository list could not be read (then its scanned repositories are counted and each one's total is at least its scanned branches).

Tabs:

| Tab | Content |
|---|---|
| **Repositories** | One row per repository: Severity, Repository, Top finding, Count, Branch, **Branches scanned** (scanned / total), Scanned ("Not scanned" when the repository has no stored SAST result). Facets: Severity, Finding type, Provider, Organisation (with more than one connector), **Scan status** (Scanned, Not scanned). Scanned repositories without findings are listed too. Filter syntax: free text, `severity:critical,high`, `type:secret`. Up to 300 rows. Organisation-level posture findings appear as a row `<org> (organisation)`. The repository list comes from the provider (`GET .../sast/repos`) and arrives after the findings, so clean repositories appear a moment later. |
| **Findings** | One row per finding: Severity, Finding (with runtime and triage badges), Repository, Where, Source, Scanned. Facets: Severity, Finding type, Source, **Triage**, **Code** (production, or test and example code; SAST findings), **Runtime (dependencies)**, Repository (top 15). Findings in test code carry a "test code" tag. Rows of equal severity sort running dependencies first. Up to 500 rows. A row opens the finding page. |
| **Connectors and scans** | The per-connector workspaces (8.4) |

### 8.2 Repository page (`/devops/repos/:connector/:repo`)

`:repo` is the short repository name. The header shows `org/repo`, the provider, the branch, the last scan time, and the worst severity. Numbers: Open findings, Critical, High, Secrets, Branch and access issues. The table lists every finding for that repository from all three sources (Severity, Finding, Where, Type, Source, Scanned). Buttons: **Back**, **All repositories**. If no connector holds the repository, the page says "Repository not found in any connected source."

Because the key is the short name, two repositories with the same short name in one connector (for example after renaming the organisation) are merged into one page.

### 8.3 Finding page (`/devops/findings/:fid`)

- **Header:** title, severity, a link to the repository, location, source, scan time.
- **Details:** Type, Repository, Branch (SAST and posture), Location, Rule (SAST rule ID), Commit and author (code scan), Found by, and the full detail text.
- **How to fix:** the remediation text. Secret findings add: "Rotate the secret first: deleting it from the code does not remove it from git history."
- **Other findings in this repository:** up to 8, by severity.

Triage and fix suggestions are done in the connector's SAST tab (8.4); the finding page shows no actions.

### 8.4 Per-connector workspace (Connectors and scans tab)

The left sidebar lists connectors (organisation, provider, status, items synced) and the **Add connector** buttons. The right panel shows the selected connector: provider, organisation, label, status, **Sync** and **Disconnect**, and these tabs:

| Tab | Content |
|---|---|
| **Code Changes** | Last 100 stored commits (search box, repository filter). A commit opens its detail with the file list and redacted patches. |
| **Code Scan** | Run the code scan, see counts and findings of the latest run, and request an AI summary (risk score, label, executive summary, top issues, immediate actions). |
| **SAST** | Repository selector (live list from the provider, GitHub paged up to 2 000 repositories) and Branch dropdown (`GET .../sast/branches?repo=`: the repository's branches from the provider, default first, then scanned branches, marked "scanned"); choosing a repository or branch shows the latest stored result of exactly that branch (from a manual, scheduled, on-push or "scan all" run); **Run SAST Scan** (async job, polled every 2 seconds for up to 42 minutes); engine chips (what ran, what was missing or failed, source git clone or API, CodeQL languages); **Download SBOM (CycloneDX)**; summary counts; severity filter; **Show dismissed**; findings with snippet, CWE, OWASP, engine, runtime badge, triage badge or hint, and fix; per finding **Suggest fix** / **Show fix**, **False positive**, **Accept risk**, **Confirm**, **Clear decision**, and a one-click triage rule from a hint; **AI Triage** summary of the repository on screen. Selecting a repository loads its last stored result. |
| **Automation** | Policy (PR checks, comments, CodeQL on PRs, AI fixes in comments, blocking level, comments per update, scan on push, schedule and hour, repositories for scheduled scans), **Scan all repositories now**, the status name to require for merge blocking with the provider-specific steps, the **Triage rules** list (delete), and the **Automated scans** list (trigger, repository, target, result, findings; a row shows what was posted, notes and the findings). Refreshes every 10 seconds. |
| **Events** | Up to 500 events whose host equals the organisation name (all time). Events whose host is a repository (GitHub audit entries with a repository) are not listed here. |
| **Alerts** | Up to 100 alerts whose host equals the organisation name. |
| **Posture** | **Run posture check** and the last result: repositories checked, each finding with its fix, and the checks the token could not run (not assessed) with the rights that would fix it. |

Insights → **Code findings** shows the unified list from section 7.2 with severity and scanner filters.

Implemented in: `management/frontend/src/pages/code/CodeOverview.jsx`, `RepoPage.jsx`, `FindingPage.jsx`, `pages/DevOps.jsx`, `pages/Insights.jsx`, `components/Shell.jsx`.

---

## 9. Limits and caps

| Area | Limit |
|---|---|
| Polling | Every 5 min; 3 min per sync; default branch only; per-provider page caps (configuration.md section 7) |
| GitLab | Up to 2 000 projects (20 pages); 20 commits per project per sync |
| Azure DevOps | 20 commits per repository per sync; no diff content |
| Stored patch | 2 000 characters per file, redacted |
| Code scan | Last 500 commits |
| SAST | Whole repository from git (2 048 MB on disk, 5 min clone); API fallback 1 000 files, 300 KB per file (lockfiles 5 MiB); history secrets 5 min; pattern rules 10 min; Trivy 9 min; one pattern-rule or CodeQL run at a time across all scans; CodeQL 12 min for up to 4 languages; 40 min per job; one job per connector and repository/branch at a time |
| SCA (OSV fallback) | 50 lockfiles, 2 000 packages, 150 advisory look-ups, 60 s |
| Automation | 1 worker (up to 4 with `OW_CODE_SCAN_WORKERS`); 40 min per job; schedule checked every 10 min; scheduled scans up to 200 known repositories per connector |
| Concurrent repository scans | `OW_SAST_MAX_CONCURRENT` (default 2): manual, "scan all", push, schedule and pull-request scans share the slots |
| PR checks | Shallow fetch of 300 commits (deepened once to 3 000); inline comments 1-100 per update (default 20); AI fixes 5 per update; 2 000 commented-finding keys remembered per PR |
| Runtime inventory | Every 15 min per service process (re-sent every 6 h when unchanged); 5 000 packages per process; "running" = seen in 24 h; index rows kept 14 days |
| AI | Source-AI rate limit 6 requests per 10 minutes (shared by AI triage and fix suggestions); 30 lines of context each side; fixes cached 30 days |
| Posture | 100 repositories |
| Pages | Overview SAST data is the latest row of each repository (up to 1 000 repositories per connector). 300 repositories and 500 findings per table. |
| Unified API | 1 000 findings |
