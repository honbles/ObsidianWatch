package api

import (
	"strings"
	"obsidianwatch/management/internal/store"
)

// devopsSignatures — detection rules for GitHub/GitLab/Azure DevOps events.
// All match on EventType starting with "devops." and parse the Raw JSON field.
var devopsSignatures = []ThreatSig{

	// ── Secret / Credential Exposure ──────────────────────────────────────────
	{
		ID: "DEV-001", Name: "Secret or Credential Pushed to Repository",
		Description: "A commit was pushed containing a detected secret — API key, password, private key, or token. Immediate rotation required. The credential should be considered compromised.",
		Severity: 5, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "devops.secret_push"
		},
	},
	{
		ID: "DEV-002", Name: "Sensitive File Committed (.env, .pem, credentials)",
		Description: "A commit included a file type commonly containing secrets — .env, .pem, .key, credentials.json, terraform.tfvars, etc.",
		Severity: 4, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "devops.sensitive_file"
		},
	},

	// ── Pipeline / CI-CD ──────────────────────────────────────────────────────
	{
		ID: "DEV-003", Name: "CI/CD Pipeline Configuration Modified",
		Description: "A workflow or pipeline file was modified (.github/workflows/, .gitlab-ci.yml, azure-pipelines.yml, Jenkinsfile). Pipeline changes can redirect secrets, modify deployments, or execute arbitrary code in the build environment.",
		Severity: 4, MITRE: "T1195.002", Category: "Supply Chain",
		Match: func(ev store.Event) bool {
			return ev.EventType == "devops.cicd_modified"
		},
	},
	{
		ID: "DEV-004", Name: "Self-Hosted Runner Registered",
		Description: "A new self-hosted GitHub Actions or GitLab runner was registered. Attackers register runners to execute pipeline jobs in their own environment, exfiltrating secrets and build artifacts.",
		Severity: 4, MITRE: "T1195.002", Category: "Supply Chain",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)), "runners.create", "runner_registered",
					"\"type\":\"self-hosted\"", "self_hosted")
		},
	},
	{
		ID: "DEV-005", Name: "Pipeline Secret or Variable Accessed from Unexpected Branch",
		Description: "A pipeline job ran and accessed secrets from a branch other than main/master/develop. This is the classic fork PR attack — untrusted code accessing privileged secrets.",
		Severity: 4, MITRE: "T1195.002", Category: "Supply Chain",
		Match: func(ev store.Event) bool {
			if ev.EventType != "devops.workflow_run" {
				return false
			}
			raw := strings.ToLower(rawStr(ev))
			// Flag if ran from a fork or unexpected branch
			return containsAny(raw, "fork", "pull_request") &&
				!containsAny(raw, "\"branch\":\"main\"", "\"branch\":\"master\"",
					"\"branch\":\"develop\"")
		},
	},

	// ── Repository Exposure ───────────────────────────────────────────────────
	{
		ID: "DEV-006", Name: "Private Repository Made Public",
		Description: "A repository was changed from private to public — all code, commit history, and any hardcoded secrets are now publicly accessible.",
		Severity: 5, MITRE: "T1530", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"repo_publicized", "repo.publicized", "made_public",
					"\"action\":\"publicized\"", "visibility_change",
					"changed_visibility_to_public")
		},
	},
	{
		ID: "DEV-007", Name: "Repository Deleted",
		Description: "A repository was deleted — code and history permanently removed.",
		Severity: 4, MITRE: "T1485", Category: "Impact",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"repo_destroy", "repo.destroy", "\"action\":\"deleted\"",
					"repository_deleted", "repo_deleted")
		},
	},
	{
		ID: "DEV-008", Name: "Repository Transferred to External Account",
		Description: "A repository was transferred to a different organization or user — possible data exfiltration.",
		Severity: 4, MITRE: "T1537", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"repo.transfer", "repo_transfer", "\"action\":\"transferred\"",
					"transfer_start", "repository_transferred")
		},
	},

	// ── Access Control / Persistence ──────────────────────────────────────────
	{
		ID: "DEV-009", Name: "New Organization Owner or Admin Added",
		Description: "A user was granted Owner or Admin role in the organization. This is the highest privilege level and provides full access to all repositories, secrets, and billing.",
		Severity: 5, MITRE: "T1098", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"org.add_member", "org_add_member", "member_added",
					"\"role\":\"owner\"", "\"role\":\"admin\"",
					"added_to_org", "org.update_member") &&
				containsAny(strings.ToLower(rawStr(ev)), "owner", "admin")
		},
	},
	{
		ID: "DEV-010", Name: "Personal Access Token Created",
		Description: "A Personal Access Token was created — PATs provide programmatic access and can persist after password changes or MFA enforcement. Long-lived PATs are a common backdoor.",
		Severity: 4, MITRE: "T1098", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"personal_access_token.created", "pat.created",
					"access_token_created", "create_pat",
					"\"action\":\"created\"") &&
				containsAny(strings.ToLower(rawStr(ev)), "token", "pat", "access_key")
		},
	},
	{
		ID: "DEV-011", Name: "Deploy Key Added to Repository",
		Description: "An SSH deploy key was added to a repository — provides persistent read (or write) access to the repo without using a user account.",
		Severity: 3, MITRE: "T1098.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"deploy_key.create", "deploy_key_added",
					"\"action\":\"create\"") &&
				containsAny(strings.ToLower(rawStr(ev)), "deploy_key", "deploykey")
		},
	},
	{
		ID: "DEV-012", Name: "OAuth Application Installed with Broad Permissions",
		Description: "A new OAuth application or GitHub App was installed on the organization. Malicious OAuth apps are used for persistent access and data exfiltration.",
		Severity: 4, MITRE: "T1550.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"oauth_application.create", "integration_installation.create",
					"app_installation", "github_app_installed",
					"oauth_access.create")
		},
	},

	// ── Branch Protection / Defense Evasion ──────────────────────────────────
	{
		ID: "DEV-013", Name: "Branch Protection Removed or Weakened",
		Description: "Branch protection rules were removed or relaxed on a protected branch (main/master). This allows force pushes, bypasses required reviews, and opens the door to supply chain attacks.",
		Severity: 4, MITRE: "T1562", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"protected_branch.destroy", "protected_branch_deleted",
					"branch_protection_rule_deleted", "remove_branch_protection",
					"update_admin_enforcement", "require_code_owner_reviews") &&
				!containsAny(strings.ToLower(rawStr(ev)), "create", "add", "enable")
		},
	},
	{
		ID: "DEV-014", Name: "Force Push to Protected Branch",
		Description: "A force push was made directly to main/master or another protected branch — rewrites history and can remove evidence of malicious commits.",
		Severity: 4, MITRE: "T1562", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)), "force_push", "forced_push",
					"\"forced\":true") &&
				containsAny(strings.ToLower(rawStr(ev)), "main", "master", "develop", "release")
		},
	},
	{
		ID: "DEV-015", Name: "Audit Log Streaming Disabled",
		Description: "GitHub or GitLab audit log streaming was disabled — security events will no longer be forwarded to SIEM.",
		Severity: 5, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"audit_log_streaming.disabled", "audit_stream_delete",
					"log_streaming_disabled", "stream_key.destroy")
		},
	},
	{
		ID: "DEV-016", Name: "Webhook Created on Organization",
		Description: "A new webhook was created on the org — could be used to exfiltrate events, code, or to receive C2 callbacks.",
		Severity: 3, MITRE: "T1071.001", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) &&
				containsAny(strings.ToLower(rawStr(ev)),
					"hook.create", "webhook_created", "org_webhook_add",
					"project_hook_add")
		},
	},

	// ── After Hours Activity ──────────────────────────────────────────────────
	{
		ID: "DEV-017", Name: "Repository Made Public Outside Business Hours",
		Description: "A repository was made public outside normal business hours — suspicious timing.",
		Severity: 5, MITRE: "T1530", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			if !isDevOpsEvent(ev) {
				return false
			}
			hour := ev.Time.UTC().Hour()
			isOutside := hour < 6 || hour >= 22
			return isOutside && containsAny(strings.ToLower(rawStr(ev)),
				"publicized", "made_public", "visibility_change")
		},
	},
	{
		ID: "DEV-018", Name: "Admin Added to Org Outside Business Hours",
		Description: "A user was granted org admin access outside normal business hours.",
		Severity: 5, MITRE: "T1098", Category: "Persistence",
		Match: func(ev store.Event) bool {
			if !isDevOpsEvent(ev) {
				return false
			}
			hour := ev.Time.UTC().Hour()
			isOutside := hour < 6 || hour >= 22
			return isOutside && containsAny(strings.ToLower(rawStr(ev)),
				"org.add_member", "member_added", "org_admin") &&
				containsAny(strings.ToLower(rawStr(ev)), "owner", "admin")
		},
	},
}
