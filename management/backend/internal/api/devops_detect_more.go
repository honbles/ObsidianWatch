package api

// devops_detect_more.go - Code platform threat detection, second pass.
//
// New signals:
//   - Pipeline content analysis: what a CI/CD change adds (untrusted input in
//     shell steps, PR code checked out under pull_request_target, broad token
//     permissions, unpinned third-party actions, secrets printed, download
//     piped to a shell, CI token sent out). DEV-023.
//   - Dependency change analysis: install scripts, dependencies fetched from
//     git/URLs, extra package indexes or registries, go.mod replace to a fork.
//     DEV-020 now fires only on these.
//   - Push protection bypass (DEV-024), security feature disabled (DEV-025),
//     CI/CD secret changed (DEV-026), branch protection bypassed (DEV-027),
//     mass repository clone/download (DEV-028), webhook removed (DEV-031).
//   - Context checks in the DevOps detection pass: platform activity from an
//     IP on a threat-intel list (DEV-029), and a sensitive change from an IP
//     the actor has not used in 30 days (DEV-030).

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Pipeline content ──────────────────────────────────────────────────────────

var (
	ghUntrustedExprRe  = regexp.MustCompile(`\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages|workflow_run)\.[\w.\[\]*]*(title|body|message|name|label|ref|email|head_branch|default_branch)|head_ref)\s*\}\}`)
	ghPRHeadCheckoutRe = regexp.MustCompile(`ref:\s*\$\{\{\s*github\.(event\.pull_request\.head\.(sha|ref)|head_ref)`)
	ghUsesRe           = regexp.MustCompile(`uses:\s*["']?([\w.-]+)/([\w./-]+)@([\w.\-/]+)`)
	shaRe              = regexp.MustCompile(`^[0-9a-f]{40}$`)
	secretPrintRe      = regexp.MustCompile(`(?i)(echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\.|(\bprintenv\b|\benv\b\s*(\||>|$))|base64[^\n]*\$\{\{\s*secrets\.|toJSON\(\s*secrets\s*\)`)
	ciTokenOutRe       = regexp.MustCompile(`(?i)(curl|wget|invoke-webrequest|iwr)\b[^\n]*(\$CI_JOB_TOKEN|\$\{?CI_JOB_TOKEN|System\.AccessToken|\$\(System\.AccessToken\)|secrets\.GITHUB_TOKEN|github\.token)`)
	pipeShellRe        = regexp.MustCompile(`(?i)(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b|bash\s+<\(\s*(curl|wget)`)
)

// pipelineRisks lists what the added lines of a pipeline-file patch do that
// commonly leads to secret theft or code execution in CI.
func pipelineRisks(patch string) []string {
	added := []string{}
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			added = append(added, line[1:])
		}
	}
	body := strings.Join(added, "\n")
	low := strings.ToLower(body)
	var out []string
	add := func(r string) {
		for _, x := range out {
			if x == r {
				return
			}
		}
		out = append(out, r)
	}
	prTarget := strings.Contains(low, "pull_request_target")
	if prTarget {
		add("pull_request_target trigger")
	}
	if ghPRHeadCheckoutRe.MatchString(body) {
		add("checks out pull request head code")
	}
	if ghUntrustedExprRe.MatchString(body) {
		add("untrusted event data interpolated into a step")
	}
	if strings.Contains(low, "secrets: inherit") {
		add("secrets: inherit")
	}
	if strings.Contains(low, "self-hosted") {
		add("self-hosted runner")
	}
	if strings.Contains(low, "permissions: write-all") || regexp.MustCompile(`(?m)^\s*(contents|actions|packages|id-token|pull-requests):\s*write`).MatchString(low) {
		add("write permissions for the workflow token")
	}
	if pipeShellRe.MatchString(body) {
		add("download piped to a shell")
	}
	if secretPrintRe.MatchString(body) {
		add("prints, dumps or encodes secrets")
	}
	if ciTokenOutRe.MatchString(body) {
		add("sends the CI token to a URL")
	}
	for _, m := range ghUsesRe.FindAllStringSubmatch(body, -1) {
		owner, ref := strings.ToLower(m[1]), m[3]
		if owner == "actions" || owner == "github" || shaRe.MatchString(ref) {
			continue
		}
		add("third-party action not pinned to a commit SHA")
		break
	}
	return out
}

// pipelineRiskSeverity: an injection or PR-code checkout combined with
// pull_request_target is the pwn-request pattern.
func pipelineRiskSeverity(risks []string) int {
	has := func(s string) bool {
		for _, r := range risks {
			if r == s {
				return true
			}
		}
		return false
	}
	switch {
	case has("pull_request_target trigger") && (has("checks out pull request head code") || has("untrusted event data interpolated into a step")):
		return 5
	case has("sends the CI token to a URL"), has("prints, dumps or encodes secrets"), has("untrusted event data interpolated into a step"):
		return 4
	case len(risks) > 0:
		return 3
	}
	return 0
}

// ── Dependency changes ────────────────────────────────────────────────────────

var (
	installScriptRe = regexp.MustCompile(`"(pre|post)?install"\s*:`)
	gitDepRe        = regexp.MustCompile(`(?i)(git\+(https?|ssh)://|github:[\w-]+/|"https?://[^"]+\.(tgz|tar\.gz|zip)"|@\s*git\+|\bgit\s*=\s*["']https?://)`)
	extraIndexRe    = regexp.MustCompile(`(?i)(--extra-index-url|--index-url|--trusted-host|^\s*registry\s*=|"registry"\s*:|\[\[tool\.poetry\.source\]\]|source\s+["']https?://)`)
	goReplaceRe     = regexp.MustCompile(`(?m)^\s*replace\s+\S+.*=>\s*(\.|/|\S+\s+v)`)
)

// dependencyRisks lists risky things a manifest/lockfile patch adds.
func dependencyRisks(file, patch string) []string {
	var added []string
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			added = append(added, line[1:])
		}
	}
	body := strings.Join(added, "\n")
	base := strings.ToLower(file[strings.LastIndex(file, "/")+1:])
	var out []string
	if base == "package.json" && installScriptRe.MatchString(body) {
		out = append(out, "adds an install script")
	}
	if gitDepRe.MatchString(body) {
		out = append(out, "dependency fetched from a git repository or URL")
	}
	if extraIndexRe.MatchString(body) || base == ".npmrc" || base == ".yarnrc.yml" || base == "pip.conf" {
		if extraIndexRe.MatchString(body) {
			out = append(out, "adds a package index or registry")
		}
	}
	if base == "go.mod" && goReplaceRe.MatchString(body) {
		out = append(out, "go.mod replace directive")
	}
	return out
}

// ── Mass clone / download summary ─────────────────────────────────────────────

// cloneActions are GitHub audit-log actions that copy a repository out.
var cloneActions = map[string]bool{"git.clone": true, "git.fetch": true, "repo.download_zip": true}

// massCloneThreshold is how many distinct repositories one actor copies in
// one audit batch (one sync, about 5 minutes) before DEV-028 fires.
const massCloneThreshold = 15

// cloneSummaries turns per-clone audit entries into one event per actor with
// the distinct repositories copied (individual clones are not stored).
func cloneSummaries(entries []map[string]interface{}, conn *store.DevOpsConnector) []CloudEvent {
	type agg struct {
		repos map[string]bool
		ip    string
		last  time.Time
	}
	by := map[string]*agg{}
	for _, e := range entries {
		action, _ := e["action"].(string)
		if !cloneActions[strings.ToLower(action)] {
			continue
		}
		actor, _ := e["actor"].(string)
		repo, _ := e["repo"].(string)
		if actor == "" || repo == "" {
			continue
		}
		a := by[actor]
		if a == nil {
			a = &agg{repos: map[string]bool{}}
			by[actor] = a
		}
		a.repos[repo] = true
		if ip, _ := e["actor_ip"].(string); ip != "" {
			a.ip = ip
		}
		if ts, _ := e["created_at"].(float64); ts > 0 {
			if t := time.UnixMilli(int64(ts)); t.After(a.last) {
				a.last = t
			}
		}
	}
	var out []CloudEvent
	for actor, a := range by {
		repos := make([]string, 0, len(a.repos))
		for r := range a.repos {
			repos = append(repos, r)
		}
		if len(repos) > 200 {
			repos = repos[:200]
		}
		when := a.last
		if when.IsZero() {
			when = time.Now()
		}
		raw, _ := json.Marshal(map[string]interface{}{"event": "repo_clone_summary", "actor": actor,
			"distinct_repos": len(a.repos), "repos": repos, "bot": isBotActor(actor)})
		out = append(out, CloudEvent{
			ID: fmt.Sprintf("gh-clones:%d:%s:%d", conn.ID, actor, when.Unix()/300), Time: when,
			AgentID: fmt.Sprintf("devops:%d", conn.ID), Host: conn.Org, OS: "devops",
			EventType: "devops.repo_clone_summary", Severity: 1, Source: "github_audit",
			Username: actor, SrcIP: a.ip, Raw: raw,
		})
	}
	return out
}

func isBotActor(a string) bool {
	a = strings.ToLower(a)
	return strings.HasSuffix(a, "[bot]") || strings.HasSuffix(a, "-bot") || a == "github-actions" || a == "dependabot"
}

// ── Additional signatures ─────────────────────────────────────────────────────

func rawField(ev store.Event, key string) interface{} {
	var m map[string]interface{}
	if json.Unmarshal(ev.Raw, &m) != nil {
		return nil
	}
	return m[key]
}

var devopsSignaturesMore = []ThreatSig{
	{
		ID: "DEV-023", Name: "Dangerous CI/CD Pipeline Change",
		Description: "A pipeline change added a construct that leads to secret theft or code execution in CI: untrusted event data in a shell step, pull request code checked out under pull_request_target, secrets printed or encoded, the CI token sent to a URL, a download piped to a shell, write permissions for the token, or a third-party action not pinned to a commit.",
		Severity:    4, MITRE: "T1195.002", Category: "Supply Chain",
		Match: func(ev store.Event) bool {
			if ev.EventType != "devops.cicd_modified" {
				return false
			}
			r, _ := rawField(ev, "risky").(string)
			return r != ""
		},
	},
	{
		ID: "DEV-024", Name: "Secret Scanning Push Protection Bypassed",
		Description: "Someone pushed a detected secret by bypassing push protection. The secret is now in the repository history and must be rotated.",
		Severity:    4, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			if !isDevOpsEvent(ev) {
				return false
			}
			t := devopsParse(ev)
			if t.is(ev, "secret_scanning_push_protection.bypass", "secret_scanning_push_protection_bypass", "push_protection_bypass") {
				return true
			}
			b, _ := rawField(ev, "push_protection_bypassed").(bool)
			return b
		},
	},
	{
		ID: "DEV-025", Name: "Repository Security Feature Disabled",
		Description: "Secret scanning, push protection, Dependabot alerts, vulnerability alerts or code scanning was turned off for a repository or the organisation.",
		Severity:    4, MITRE: "T1562.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			if !isDevOpsEvent(ev) {
				return false
			}
			t := devopsParse(ev)
			if t.is(ev, "repository_secret_scanning.disable", "repository_secret_scanning_push_protection.disable",
				"dependabot_alerts.disable", "repository_vulnerability_alerts.disable", "dependabot_security_updates.disable",
				"org.secret_scanning_push_protection_disable", "secret_scanning.disable", "code_scanning.disable",
				"org.disable_secret_scanning", "repository_code_security.disable") {
				return true
			}
			d, _ := rawField(ev, "disabled").([]interface{})
			return ev.EventType == "devops.security_and_analysis" && len(d) > 0
		},
	},
	{
		ID: "DEV-026", Name: "CI/CD Secret or Variable Changed",
		Description: "A CI/CD secret, variable or variable group was created, changed or removed. Attackers swap deployment credentials or plant tokens to reach production.",
		Severity:    3, MITRE: "T1098", Category: "Persistence",
		Match: func(ev store.Event) bool {
			if !isDevOpsEvent(ev) {
				return false
			}
			t := devopsParse(ev)
			a := t.Action + " " + t.Event
			return t.is(ev, "org.update_actions_secret", "org.remove_actions_secret", "org.create_actions_secret",
				"repo.create_actions_secret", "repo.update_actions_secret", "repo.remove_actions_secret",
				"environment.create_actions_secret", "environment.update_actions_secret", "environment.remove_actions_secret",
				"codespaces.create_an_org_secret", "dependabot.create_org_secret") ||
				(containsAny(a, "ci_variable", "ci variable", "library.variablegroup", "securefile") && !containsAny(a, "read", "view"))
		},
	},
	{
		ID: "DEV-027", Name: "Branch Protection Bypassed",
		Description: "A change was pushed or merged by overriding branch protection or a ruleset (an administrator bypass). Required reviews and checks did not apply to it.",
		Severity:    4, MITRE: "T1562", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			if !isDevOpsEvent(ev) {
				return false
			}
			t := devopsParse(ev)
			return t.is(ev, "protected_branch.policy_override", "protected_branch.rejected_ref_update_override",
				"repository_ruleset.bypass", "ruleset.bypass", "git.refupdatepoliciesbypassed") ||
				strings.Contains(t.Action, "policiesbypassed")
		},
	},
	{
		ID: "DEV-028", Name: "Mass Repository Clone or Download",
		Description: fmt.Sprintf("One account cloned or downloaded %d or more distinct repositories within about five minutes. This is how source code is exfiltrated with a stolen token or by a departing insider.", massCloneThreshold),
		Severity:    4, MITRE: "T1213.003", Category: "Collection",
		Match: func(ev store.Event) bool {
			if ev.EventType != "devops.repo_clone_summary" {
				return false
			}
			var m struct {
				N   int  `json:"distinct_repos"`
				Bot bool `json:"bot"`
			}
			return json.Unmarshal(ev.Raw, &m) == nil && !m.Bot && m.N >= massCloneThreshold
		},
	},
	{
		ID: "DEV-031", Name: "Organization or Repository Webhook Removed",
		Description: "A webhook was deleted or disabled. If it was the ObsidianWatch webhook, real-time detection for this platform has stopped (polling continues).",
		Severity:    3, MITRE: "T1562.008", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return isDevOpsEvent(ev) && devopsParse(ev).is(ev, "hook.destroy", "hook.active_changed", "webhook_deleted",
				"project_hook_destroy", "group_hook_destroy", "removed hook", "removed_hook")
		},
	},
}

func init() {
	devopsSignatures = append(devopsSignatures, devopsSignaturesMore...)
}

// ── Context checks in the DevOps detection pass ───────────────────────────────

// devopsContextAlerts raises DEV-029 and DEV-030, which need data outside the
// event (threat intelligence, the actor's history).
func (e *DetectionEngine) devopsContextAlerts(ctx context.Context, ev store.Event, cfg *engineConfig, states map[string]store.DetectionSignatureState) int {
	if ev.SrcIP == nil || *ev.SrcIP == "" {
		return 0
	}
	ip := strings.ToLower(*ev.SrcIP)
	created := 0
	enabled := func(id string) bool {
		if retiredSigIDs[id] {
			return false
		}
		st, ok := states[id]
		return !ok || st.Enabled
	}
	raise := func(id, title, desc string, sev int) {
		if st, ok := states[id]; ok && st.Severity != nil {
			sev = *st.Severity
		}
		adjust, skip := engineGate(ctx, e.db, id, ev)
		if skip {
			return
		}
		alert := store.Alert{Title: title, Description: desc, Severity: adjust(sev), Host: ev.Host, AgentID: ev.AgentID,
			EventType: ev.EventType, EventID: devopsDedupKey(id, ev) + ":" + ip, SourceEventID: ev.ID}
		if _, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
			created++
		}
	}
	user := strOrDash(ev.UserName)
	if enabled("DEV-029") && cfg != nil {
		if ioc, ok := cfg.ipIOCs[ip]; ok && iocUsable(ioc, cfg) {
			raise("DEV-029", "[T1078] Platform Activity from a Known-Malicious IP",
				fmt.Sprintf("%s performed %s from %s, which is on the %s threat list (%s, confidence %d).\n\nTreat the account's token or session as compromised: revoke it and review its recent activity.",
					user, ev.EventType, ip, ioc.Source, strings.TrimSpace(ioc.ThreatType+" "+ioc.Malware), ioc.Confidence), 5)
		}
	}
	if enabled("DEV-030") && ev.Severity >= 4 && user != "-" {
		var seenOther, seenThis bool
		_ = e.db.QueryRowContext(ctx, `
			SELECT EXISTS(SELECT 1 FROM events WHERE os='devops' AND user_name=$1 AND src_ip IS NOT NULL AND src_ip<>$2
			              AND time > $3::timestamptz - INTERVAL '30 days' AND time < $3::timestamptz - INTERVAL '10 minutes'),
			       EXISTS(SELECT 1 FROM events WHERE os='devops' AND user_name=$1 AND src_ip=$2
			              AND time > $3::timestamptz - INTERVAL '30 days' AND time < $3::timestamptz - INTERVAL '10 minutes')`,
			user, ip, ev.Time).Scan(&seenOther, &seenThis)
		if seenOther && !seenThis {
			raise("DEV-030", "[T1078] Sensitive Platform Change from a New IP",
				fmt.Sprintf("%s made a high-severity change (%s) from %s, an address this account has not used on the platform in the last 30 days.\n\nConfirm with the user; a stolen token or session is used from new infrastructure.",
					user, ev.EventType, ip), 3)
		}
	}
	return created
}

// iocUsable applies the same OTX confidence gate as the endpoint rules.
func iocUsable(ioc store.IOCIndicator, cfg *engineConfig) bool {
	if strings.EqualFold(ioc.Source, "otx") && ioc.Confidence < cfg.otxMinConfidence {
		return false
	}
	return true
}

// Catalogue entries so DEV-029/030 appear in the rule list and can be
// toggled; they never match on their own (the context pass raises them).
var devopsContextSigs = []ThreatSig{
	{ID: "DEV-029", Name: "Platform Activity from a Known-Malicious IP",
		Description: "A Git platform action (audit log entry with an IP) came from an address on a threat-intelligence list.",
		Severity:    5, MITRE: "T1078", Category: "Initial Access", Match: func(store.Event) bool { return false }},
	{ID: "DEV-030", Name: "Sensitive Platform Change from a New IP",
		Description: "A high-severity platform change came from an IP the account has not used in the last 30 days, while it has used others.",
		Severity:    3, MITRE: "T1078", Category: "Initial Access", Match: func(store.Event) bool { return false }},
}

func init() {
	devopsSignatures = append(devopsSignatures, devopsContextSigs...)
}
