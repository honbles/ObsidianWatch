package api

// devops_github.go — GitHub polling and webhook ingestion
//
// Polling (every 5 min):
//   - GET /orgs/{org}/audit-log  — org-level events (member changes, repo visibility, PATs)
//   - GET /repos/{owner}/{repo}/commits — recent commits with diff
//
// Webhooks (real-time):
//   - push           — commit code changes
//   - repository     — repo created/deleted/made public
//   - member         — org member added/removed
//   - org            — org events (member invited, webhook created)
//   - workflow_run   — CI pipeline run
//   - team           — team membership changes

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// sensitiveFiles are file patterns that should always be flagged
var sensitiveFilePatterns = []string{
	".env", ".env.local", ".env.production", ".env.staging",
	"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
	"*.pem", "*.key", "*.p12", "*.pfx",
	"credentials.json", "service-account.json",
	".aws/credentials", "secrets.yaml", "secrets.yml",
	"terraform.tfvars", "*.tfvars",
}

// cicdFiles — changes to these trigger pipeline-modification alerts
var cicdFiles = []string{
	".github/workflows/", ".gitlab-ci.yml", "azure-pipelines.yml",
	"Jenkinsfile", ".circleci/config.yml", ".travis.yml",
	"bitbucket-pipelines.yml", "cloudbuild.yaml",
}

// ── GitHub API client ─────────────────────────────────────────────────────────

type githubClient struct {
	token string
	org   string
}

// rateLimitWait inspects a GitHub response and returns how long to wait
// before retrying when it was rate limited (primary or secondary), else 0.
func rateLimitWait(resp *http.Response) time.Duration {
	if resp.StatusCode != 429 && resp.StatusCode != 403 {
		return 0
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
			return time.Duration(secs)*time.Second + time.Second
		}
	}
	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			if d := time.Until(time.Unix(reset, 0)) + time.Second; d > 0 {
				return d
			}
			return time.Second
		}
	}
	if resp.StatusCode == 429 {
		return 30 * time.Second
	}
	return 0
}

const maxRateLimitWait = 90 * time.Second

// get performs a GET, transparently honouring rate limits (DO-07): it waits
// for Retry-After / X-RateLimit-Reset (bounded) and retries up to 2 times.
func (c *githubClient) get(ctx context.Context, url string) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		wait := rateLimitWait(resp)
		if wait == 0 || attempt >= 2 {
			return resp, nil
		}
		if wait > maxRateLimitWait {
			return resp, nil // let caller surface the rate-limit error
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

func (c *githubClient) getJSON(ctx context.Context, url string, out interface{}) error {
	_, err := c.getJSONNext(ctx, url, out)
	return err
}

// nextLink extracts rel="next" from a GitHub Link header.
func nextLink(h string) string {
	for _, part := range strings.Split(h, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		if i := strings.Index(part, "<"); i >= 0 {
			if j := strings.Index(part, ">"); j > i {
				return part[i+1 : j]
			}
		}
	}
	return ""
}

// getJSONNext is getJSON that also returns the next-page URL (DO-04).
func (c *githubClient) getJSONNext(ctx context.Context, url string, out interface{}) (string, error) {
	resp, err := c.get(ctx, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return "", fmt.Errorf("not found: %s", url)
	}
	if rateLimitWait(resp) > 0 {
		return "", fmt.Errorf("GitHub rate limit exceeded (%d); will retry next sync", resp.StatusCode)
	}
	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		return "", fmt.Errorf("auth error %d: check token permissions", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("GitHub API %d: %s", resp.StatusCode, string(body))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return "", err
	}
	return nextLink(resp.Header.Get("Link")), nil
}

// ── Test connection ────────────────────────────────────────────────────────────

func testGitHubConnection(ctx context.Context, token, org string) (string, error) {
	client := &githubClient{token: token, org: org}
	var result struct {
		Login string `json:"login"`
		Name  string `json:"name"`
		Type  string `json:"type"`
	}
	// Try as org first
	orgURL := fmt.Sprintf("https://api.github.com/orgs/%s", org)
	if err := client.getJSON(ctx, orgURL, &result); err == nil {
		label := result.Name
		if label == "" {
			label = result.Login
		}
		return label, nil
	}
	// Try as user account
	userURL := fmt.Sprintf("https://api.github.com/users/%s", org)
	if err := client.getJSON(ctx, userURL, &result); err == nil {
		label := result.Name
		if label == "" {
			label = result.Login
		}
		return label, nil
	}
	// Verify token is valid at all
	var me struct {
		Login string `json:"login"`
	}
	if err := client.getJSON(ctx, "https://api.github.com/user", &me); err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}
	return "", fmt.Errorf("org/user %q not found or not accessible with this token (authenticated as %s)", org, me.Login)
}

// ── Sync GitHub ───────────────────────────────────────────────────────────────

func syncGitHub(ctx context.Context, conn *store.DevOpsConnector, db *store.DB, eventDB *store.DB) (int, string, error) {
	token := conn.Credentials["token"]
	if token == "" {
		return 0, "", fmt.Errorf("missing GitHub token")
	}

	client := &githubClient{token: token, org: conn.Org}
	total := 0
	cursor := conn.SyncCursor

	// ── 1. Pull org audit log (orgs only) or user events (personal accounts) ───
	auditURL := fmt.Sprintf("https://api.github.com/orgs/%s/audit-log?per_page=100&include=all", conn.Org)
	if cursor != "" {
		auditURL += "&after=" + cursor
	}
	var auditEvents []map[string]interface{}
	next, auditErr := client.getJSONNext(ctx, auditURL, &auditEvents)
	if auditErr == nil {
		// Org account — has full audit log. DO-04: follow pagination (bounded).
		for pg := 0; ; pg++ {
			events, newCursor := githubAuditToEvents(auditEvents, conn)
			if len(events) > 0 {
				n, _ := ingestCloudEvents(ctx, eventDB, events)
				total += n
				if newCursor != "" {
					cursor = newCursor
				}
			}
			if next == "" || pg >= 9 {
				break
			}
			auditEvents = nil
			var e error
			next, e = client.getJSONNext(ctx, next, &auditEvents)
			if e != nil {
				break
			}
		}
	} else {
		// Personal account — use public events API as fallback
		setCoverageNote(conn.ID, "Limited coverage: org audit log unavailable ("+auditErr.Error()+"). Using public user events only — requires GitHub Enterprise Cloud and an org-admin token for full audit-log detection.")
		userEventsURL := fmt.Sprintf("https://api.github.com/users/%s/events?per_page=100", conn.Org)
		var userEvents []map[string]interface{}
		if client.getJSON(ctx, userEventsURL, &userEvents) == nil {
			events, _ := githubAuditToEvents(userEvents, conn)
			if len(events) > 0 {
				n, _ := ingestCloudEvents(ctx, eventDB, events)
				total += n
			}
		}
	}

	// ── 2. Pull recent commits from all repos ─────────────────────────────────
	// Try org repos first; fall back to user repos for personal accounts
	var repos []struct {
		FullName      string `json:"full_name"`
		Private       bool   `json:"private"`
		PushedAt      string `json:"pushed_at"`
		DefaultBranch string `json:"default_branch"`
	}
	// Fetch from BOTH endpoints and merge — ensures org repos + personal public + private all included
	seen := map[string]bool{}
	for _, url := range []string{
		fmt.Sprintf("https://api.github.com/orgs/%s/repos?per_page=100&sort=pushed&type=all", conn.Org),
		"https://api.github.com/user/repos?per_page=100&sort=pushed&type=all",
	} {
		var batch []struct {
			FullName      string `json:"full_name"`
			Private       bool   `json:"private"`
			PushedAt      string `json:"pushed_at"`
			DefaultBranch string `json:"default_branch"`
		}
		var pageErr error
		for pg := 0; pg < 10 && url != ""; pg++ { // DO-04: follow Link: rel="next"
			var pageBatch []struct {
				FullName      string `json:"full_name"`
				Private       bool   `json:"private"`
				PushedAt      string `json:"pushed_at"`
				DefaultBranch string `json:"default_branch"`
			}
			next, e := client.getJSONNext(ctx, url, &pageBatch)
			if e != nil {
				pageErr = e
				break
			}
			batch = append(batch, pageBatch...)
			url = next
		}
		if pageErr == nil || len(batch) > 0 {
			for _, r := range batch {
				if !seen[r.FullName] {
					seen[r.FullName] = true
					repos = append(repos, struct {
						FullName      string `json:"full_name"`
						Private       bool   `json:"private"`
						PushedAt      string `json:"pushed_at"`
						DefaultBranch string `json:"default_branch"`
					}{r.FullName, r.Private, r.PushedAt, r.DefaultBranch})
				}
			}
		}
	}
	if len(repos) > 0 {
		// First sync: go back 30 days to populate history
		// Subsequent syncs: start from last sync minus 2 min overlap
		since := time.Now().UTC().Add(-30 * 24 * time.Hour)
		if conn.LastSync != nil {
			since = conn.LastSync.Add(-2 * time.Minute)
		}

		for _, repo := range repos {
			commitsURL := fmt.Sprintf(
				"https://api.github.com/repos/%s/commits?per_page=100&since=%s",
				repo.FullName, since.Format(time.RFC3339),
			)
			var commits []struct {
				SHA    string `json:"sha"`
				Commit struct {
					Message string `json:"message"`
					Author  struct {
						Name  string `json:"name"`
						Email string `json:"email"`
						Date  string `json:"date"`
					} `json:"author"`
					Committer struct {
						Email string `json:"email"`
					} `json:"committer"`
					Verification struct {
						Verified bool   `json:"verified"`
						Reason   string `json:"reason"`
					} `json:"verification"`
				} `json:"commit"`
				Author *struct {
					Login string `json:"login"`
				} `json:"author"`
				HTMLURL string `json:"html_url"`
			}

			// DO-06: 100 per page and follow Link up to 5 pages (was 20, one page).
			for pg, pageURL := 0, commitsURL; pg < 5 && pageURL != ""; pg++ {
				var page []struct {
					SHA    string `json:"sha"`
					Commit struct {
						Message string `json:"message"`
						Author  struct {
							Name  string `json:"name"`
							Email string `json:"email"`
							Date  string `json:"date"`
						} `json:"author"`
						Committer struct {
							Email string `json:"email"`
						} `json:"committer"`
						Verification struct {
							Verified bool   `json:"verified"`
							Reason   string `json:"reason"`
						} `json:"verification"`
					} `json:"commit"`
					Author *struct {
						Login string `json:"login"`
					} `json:"author"`
					HTMLURL string `json:"html_url"`
				}
				next, perr := client.getJSONNext(ctx, pageURL, &page)
				if perr != nil {
					break
				}
				commits = append(commits, page...)
				pageURL = next
			}
			if len(commits) == 0 {
				continue
			}

			for _, c := range commits {
				// Get commit details (diff)
				detailURL := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repo.FullName, c.SHA)
				var detail struct {
					Files []struct {
						Filename  string `json:"filename"`
						Status    string `json:"status"`
						Additions int    `json:"additions"`
						Deletions int    `json:"deletions"`
						Patch     string `json:"patch"`
					} `json:"files"`
					Stats struct {
						Additions int `json:"additions"`
						Deletions int `json:"deletions"`
						Total     int `json:"total"`
					} `json:"stats"`
				}
				client.getJSON(ctx, detailURL, &detail)

				authorLogin := ""
				if c.Author != nil {
					authorLogin = c.Author.Login
				}
				pushedAt, _ := time.Parse(time.RFC3339, c.Commit.Author.Date)

				// Build diff summary
				diffs := make([]store.CommitFileDiff, 0, len(detail.Files))
				secretsFound := []string{}
				cicdModified := false
				cicdRisky := ""
				sensitiveModified := false

				for _, f := range detail.Files {
					diffs = append(diffs, store.CommitFileDiff{
						File:      f.Filename,
						Additions: f.Additions,
						Deletions: f.Deletions,
						Status:    f.Status,
						Patch:     truncatePatch(redactSecrets(f.Patch), 2000),
					})

					// Secret scanning on added lines
					if f.Patch != "" {
						for _, line := range strings.Split(f.Patch, "\n") {
							if !strings.HasPrefix(line, "+") {
								continue
							}
							if lineHasSecret(line) {
								secretsFound = append(secretsFound, f.Filename)
							}
						}
					}

					// CI/CD file check
					for _, cicd := range cicdFiles {
						if strings.HasPrefix(f.Filename, cicd) || f.Filename == cicd {
							cicdModified = true
							if r := riskyPipelineContent(f.Patch); r != "" {
								cicdRisky = r
							}
						}
					}

					// Sensitive file check
					for _, sf := range sensitiveFilePatterns {
						if !isRemovedStatus(f.Status) && matchesGlob(f.Filename, sf) {
							sensitiveModified = true
						}
					}
				}

				diffJSON, _ := json.Marshal(diffs)
				commit := store.DevOpsCommit{
					ID:          c.SHA,
					ConnectorID: conn.ID,
					Repo:        repo.FullName,
					Branch: func() string {
						if repo.DefaultBranch != "" {
							return repo.DefaultBranch
						}
						return "HEAD"
					}(),
					AuthorName:     c.Commit.Author.Name,
					AuthorEmail:    c.Commit.Author.Email,
					AuthorUsername: authorLogin,
					Message:        c.Commit.Message,
					URL:            c.HTMLURL,
					FilesChanged:   len(detail.Files),
					Additions:      detail.Stats.Additions,
					Deletions:      detail.Stats.Deletions,
					DiffSummary:    diffJSON,
					PushedAt:       pushedAt,
				}
				db.UpsertDevOpsCommit(ctx, commit)
				total++

				// Always emit a devops.push event for every commit
				pushRaw, _ := json.Marshal(map[string]interface{}{
					"event":         "push",
					"sha":           c.SHA,
					"repo":          repo.FullName,
					"author":        authorLogin,
					"author_name":   c.Commit.Author.Name,
					"author_email":  c.Commit.Author.Email,
					"message":       c.Commit.Message,
					"url":           c.HTMLURL,
					"files_changed": len(detail.Files),
					"additions":     detail.Stats.Additions,
					"deletions":     detail.Stats.Deletions,
					"pushed_at":     pushedAt,
					// DS-07 integrity signals
					"verified":           c.Commit.Verification.Verified,
					"verification_reason": c.Commit.Verification.Reason,
					"committer_mismatch": committerMismatch(c.Commit.Author.Email, c.Commit.Committer.Email),
				})
				baseEvents := []CloudEvent{{
					ID:        "devops:" + c.SHA + ":push",
					Time:      commitEventTime(pushedAt),
					AgentID:   fmt.Sprintf("devops:%d", conn.ID),
					Host:      conn.Org,
					OS:        "devops",
					EventType: "devops.push",
					Severity:  1,
					Source:    "github",
					Username:  authorLogin,
					Raw:       pushRaw,
				}}
				ingestCloudEvents(ctx, eventDB, baseEvents)
				total++

				// Generate security events for dangerous commits
				events := []CloudEvent{}

				if len(secretsFound) > 0 {
					raw, _ := json.Marshal(map[string]interface{}{
						"event":   "secret_pushed",
						"sha":     c.SHA,
						"repo":    repo.FullName,
						"author":  authorLogin,
						"files":   secretsFound,
						"message": c.Commit.Message,
						"url":     c.HTMLURL,
					})
					events = append(events, CloudEvent{
						ID:        "devops:" + c.SHA + ":secret",
						Time:      commitEventTime(pushedAt),
						AgentID:   fmt.Sprintf("devops:%d", conn.ID),
						Host:      conn.Org,
						OS:        "devops",
						EventType: "devops.secret_push",
						Severity:  5,
						Source:    "github",
						Username:  authorLogin,
						Raw:       raw,
					})
				}

				if cicdModified {
					raw, _ := json.Marshal(map[string]interface{}{
						"event":   "cicd_modified",
						"risky":   cicdRisky,
						"sha":     c.SHA,
						"repo":    repo.FullName,
						"author":  authorLogin,
						"message": c.Commit.Message,
						"url":     c.HTMLURL,
					})
					events = append(events, CloudEvent{
						ID:        "devops:" + c.SHA + ":cicd",
						Time:      commitEventTime(pushedAt),
						AgentID:   fmt.Sprintf("devops:%d", conn.ID),
						Host:      conn.Org,
						OS:        "devops",
						EventType: "devops.cicd_modified",
						Severity: func() int {
							if cicdRisky != "" {
								return 4
							}
							return 3
						}(),
						Source: "github",
						Username:  authorLogin,
						Raw:       raw,
					})
				}

				if sensitiveModified {
					raw, _ := json.Marshal(map[string]interface{}{
						"event":   "sensitive_file",
						"sha":     c.SHA,
						"repo":    repo.FullName,
						"author":  authorLogin,
						"message": c.Commit.Message,
						"url":     c.HTMLURL,
					})
					events = append(events, CloudEvent{
						ID:        "devops:" + c.SHA + ":sensitive",
						Time:      commitEventTime(pushedAt),
						AgentID:   fmt.Sprintf("devops:%d", conn.ID),
						Host:      conn.Org,
						OS:        "devops",
						EventType: "devops.sensitive_file",
						Severity:  3,
						Source:    "github",
						Username:  authorLogin,
						Raw:       raw,
					})
				}

				// DS-07: mass deletion and dependency-manifest changes.
				if detail.Stats.Deletions >= 1000 && detail.Stats.Deletions > 5*detail.Stats.Additions {
					raw, _ := json.Marshal(map[string]interface{}{
						"event": "mass_deletion", "sha": c.SHA, "repo": repo.FullName, "author": authorLogin,
						"additions": detail.Stats.Additions, "deletions": detail.Stats.Deletions,
						"message": c.Commit.Message, "url": c.HTMLURL,
					})
					events = append(events, CloudEvent{
						ID: "devops:" + c.SHA + ":massdel", Time: commitEventTime(pushedAt),
						AgentID: fmt.Sprintf("devops:%d", conn.ID), Host: conn.Org, OS: "devops",
						EventType: "devops.mass_deletion", Severity: 3, Source: "github",
						Username: authorLogin, Raw: raw,
					})
				}
				var manifests []string
				for _, f := range detail.Files {
					if isDependencyManifest(f.Filename) && !isRemovedStatus(f.Status) {
						manifests = append(manifests, f.Filename)
					}
				}
				if len(manifests) > 0 {
					raw, _ := json.Marshal(map[string]interface{}{
						"event": "dependency_change", "sha": c.SHA, "repo": repo.FullName, "author": authorLogin,
						"files": manifests, "message": c.Commit.Message, "url": c.HTMLURL,
					})
					events = append(events, CloudEvent{
						ID: "devops:" + c.SHA + ":deps", Time: commitEventTime(pushedAt),
						AgentID: fmt.Sprintf("devops:%d", conn.ID), Host: conn.Org, OS: "devops",
						EventType: "devops.dependency_change", Severity: 2, Source: "github",
						Username: authorLogin, Raw: raw,
					})
				}

				if len(events) > 0 {
					n, _ := ingestCloudEvents(ctx, eventDB, events)
					total += n
				}
			}
		}
	}

	return total, cursor, nil
}

// ── Audit log → events ────────────────────────────────────────────────────────

func githubAuditToEvents(entries []map[string]interface{}, conn *store.DevOpsConnector) ([]CloudEvent, string) {
	events := []CloudEvent{}
	lastCursor := ""

	for _, entry := range entries {
		action, _ := entry["action"].(string)
		actor, _ := entry["actor"].(string)
		repoName, _ := entry["repo"].(string)
		ts, _ := entry["created_at"].(float64)
		eventTime := time.Now()
		if ts > 0 {
			eventTime = time.Unix(int64(ts)/1000, 0)
		}
		if cursor, ok := entry["@cursor"].(string); ok && cursor != "" {
			lastCursor = cursor
		}

		sev := githubAuditSeverity(action)
		if sev == 0 {
			continue // skip low-interest events
		}

		raw, _ := json.Marshal(entry)
		host := conn.Org
		if repoName != "" {
			host = repoName
		}

		events = append(events, CloudEvent{
			ID:        fmt.Sprintf("gh-audit:%s:%s:%.0f", conn.Org, action, ts),
			Time:      eventTime,
			AgentID:   fmt.Sprintf("devops:%d", conn.ID),
			Host:      host,
			OS:        "devops",
			EventType: "devops." + strings.ReplaceAll(action, ".", "_"),
			Severity:  sev,
			Source:    "github_audit",
			Username:  actor,
			Raw:       raw,
		})
	}
	return events, lastCursor
}

// githubAuditSeverity rates a GitHub audit-log action.
//
// DS-03: matching used to be substring-based ("public" anywhere => Critical,
// so public_key.create — an SSH key being added — rated 5) and only ~30
// actions were rated, so the rest were dropped before ingest. Actions are now
// matched exactly or by dotted prefix ("hook" matches "hook.create" but not
// "hookup"), and the list covers audit-streaming, rulesets, 2FA and
// secret-scanning controls.
func githubAuditSeverity(action string) int {
	action = strings.ToLower(strings.TrimSpace(action))
	critical := []string{
		"repo.destroy",
		"audit_log_streaming.destroy", "audit_log_streaming.update", "audit_log_streaming.disable",
		"org.disable_two_factor_requirement", "business.disable_two_factor_requirement",
		"org.disable_saml", "org.disable_oauth_app_restrictions",
		"repository_visibility_change.enable",
	}
	high := []string{
		"org.add_member", "org.remove_member", "org.update_member",
		"org.add_billing_manager", "org.invite_member", "org.update_actions_secret", "org.remove_actions_secret",
		"repo.create", "repo.access", "repo.transfer",
		"protected_branch.destroy", "protected_branch.update_admin_enforcement",
		"protected_branch.update_require_code_owner_reviews", "protected_branch.policy_override",
		"repository_ruleset.destroy", "repository_ruleset.update",
		"hook.create", "hook.destroy", "hook.config_changed",
		"oauth_application.create", "integration_installation.create",
		"repository_secret_scanning.disable", "repository_secret_scanning_push_protection.disable",
		"repository_vulnerability_alerts.disable", "dependabot_alerts.disable",
		"deploy_key.create", "public_key.create", "personal_access_token.create",
		"audit_log_streaming.create",
	}
	medium := []string{
		"repo.rename", "repo.archived", "repo.unarchived",
		"team.add_member", "team.remove_member", "team.add_repository",
		"org.update_default_repository_permission",
		"protected_branch.create", "protected_branch.update",
		"repository_ruleset.create",
		"personal_access_token.created", "personal_access_token_request",
		"runners.create", "org.runner_group_created", "workflows.approve_workflow_job",
	}
	match := func(list []string) bool {
		for _, h := range list {
			if action == h || strings.HasPrefix(action, h+".") {
				return true
			}
		}
		return false
	}
	switch {
	case match(critical) || strings.HasSuffix(action, ".make_public") || strings.HasSuffix(action, ".set_public"):
		return 5
	case match(high):
		return 4
	case match(medium):
		return 3
	}
	return 0
}

// ── Webhook handler ───────────────────────────────────────────────────────────

// DO-01 brute-force/spam guard: webhook bodies can trigger DB writes, so
// rate-limit by connector ID.
var webhookLimiter = NewRateLimiter(1*time.Minute, 60)

func handleGitHubWebhook(db *store.DB, eventDB *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if !webhookLimiter.Allow(idStr) {
			http.Error(w, "rate limited", 429)
			return
		}
		// DO-01: 10MB -> 1MB. GitHub webhook payloads are small; a large
		// cap just gives an attacker more room before the signature check
		// below ever runs.
		body, err := io.ReadAll(io.LimitReader(r.Body, 1*1024*1024))
		if err != nil {
			http.Error(w, "read error", 400)
			return
		}

		// Look up connector to get org + webhook secret
		var conn *store.DevOpsConnector
		if idStr != "" {
			if id, err := strconv.ParseInt(idStr, 10, 64); err == nil {
				conn, _ = db.GetDevOpsConnectorRaw(r.Context(), id)
			}
		}
		if conn == nil {
			http.Error(w, "unknown connector", 404)
			return
		}

		// DO-01: this used to be `if conn != nil && secret != "" && sig != ""`
		// — so an unconfigured secret, or simply omitting the signature
		// header, skipped validation entirely and let anyone POST arbitrary
		// webhook events. All three cases must now fail closed.
		if conn.WebhookSecret == "" {
			logger.Warn("devops webhook: no secret configured", "connector", idStr)
			http.Error(w, "webhook secret not configured", 401)
			return
		}
		sig := r.Header.Get("X-Hub-Signature-256")
		if sig == "" {
			http.Error(w, "missing signature", 401)
			return
		}
		mac := hmac.New(sha256.New, []byte(conn.WebhookSecret))
		mac.Write(body)
		expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(sig), []byte(expected)) {
			logger.Warn("devops webhook: invalid HMAC signature", "connector", idStr)
			http.Error(w, "invalid signature", 401)
			return
		}

		event := r.Header.Get("X-GitHub-Event")
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}

		// DO-03: replay protection. GitHub sends a unique X-GitHub-Delivery
		// per delivery (and the same one on a manual redeliver); a repeat
		// inside the retention window is acknowledged but not re-processed.
		delivery := r.Header.Get("X-GitHub-Delivery")
		if delivery != "" && webhookDeliverySeen(idStr+":"+delivery) {
			logger.Info("devops webhook: duplicate delivery ignored", "connector", idStr, "delivery", delivery)
			w.WriteHeader(204)
			return
		}

		logger.Info("devops webhook received", "event", event, "connector", idStr)
		events := processGitHubWebhookEvent(event, payload, conn)
		if delivery != "" {
			for i := range events {
				events[i].ID = fmt.Sprintf("gh-wh:%s:%d", delivery, i)
			}
		}
		if len(events) > 0 {
			ingestCloudEvents(r.Context(), eventDB, events)
		}

		w.WriteHeader(204)
	}
}

func processGitHubWebhookEvent(event string, payload map[string]interface{}, conn *store.DevOpsConnector) []CloudEvent {
	events := []CloudEvent{}
	org := ""
	connID := int64(0)
	if conn != nil {
		org = conn.Org
		connID = conn.ID
	}

	sender, _ := payload["sender"].(map[string]interface{})
	actor := ""
	if sender != nil {
		actor, _ = sender["login"].(string)
	}

	repoObj, _ := payload["repository"].(map[string]interface{})
	repoName := ""
	if repoObj != nil {
		repoName, _ = repoObj["full_name"].(string)
	}

	now := time.Now()
	agentID := fmt.Sprintf("devops:%d", connID)

	makeEvent := func(eventType string, sev int, raw interface{}) CloudEvent {
		rawJSON, _ := json.Marshal(raw)
		return CloudEvent{
			ID:        fmt.Sprintf("gh-wh:%s:%s:%d", eventType, actor, now.UnixNano()),
			Time:      now,
			AgentID:   agentID,
			Host:      org,
			OS:        "devops",
			EventType: eventType,
			Severity:  sev,
			Source:    "github_webhook",
			Username:  actor,
			Raw:       rawJSON,
		}
	}

	switch event {
	case "push":
		// Handled by commit polling — webhook gives us real-time notification
		// We emit a push event and let polling fetch the diff
		ref, _ := payload["ref"].(string)
		commits, _ := payload["commits"].([]interface{})
		forced, _ := payload["forced"].(bool)
		deleted, _ := payload["deleted"].(bool)
		created, _ := payload["created"].(bool)
		branch := strings.TrimPrefix(ref, "refs/heads/")
		raw := map[string]interface{}{
			"event": "push", "ref": ref, "branch": branch, "pusher": actor,
			"repo": repoName, "commits": len(commits),
			"forced": forced, "deleted": deleted, "created": created,
		}
		// DS-02: force pushes and branch deletions rewrite/destroy history.
		sev := 1
		if (forced || deleted) && isProtectedBranch(branch) {
			sev = 4
		} else if forced || deleted {
			sev = 2
		}
		events = append(events, makeEvent("devops.push", sev, raw))

	case "repository":
		action, _ := payload["action"].(string)
		sev := 2
		if action == "publicized" {
			sev = 5
		} else if action == "deleted" || action == "transferred" {
			sev = 4
		}
		raw := map[string]interface{}{"event": "repository." + action, "repo": repoName, "actor": actor}
		events = append(events, makeEvent("devops.repo_"+action, sev, raw))

	case "member":
		action, _ := payload["action"].(string)
		member, _ := payload["member"].(map[string]interface{})
		memberLogin := ""
		if member != nil {
			memberLogin, _ = member["login"].(string)
		}
		sev := 3
		if action == "added" {
			sev = 4
		}
		raw := map[string]interface{}{
			"event": "member." + action, "actor": actor,
			"member": memberLogin, "repo": repoName,
		}
		events = append(events, makeEvent("devops.member_"+action, sev, raw))

	case "workflow_run":
		wf, _ := payload["workflow_run"].(map[string]interface{})
		conclusion := ""
		headBranch := ""
		if wf != nil {
			conclusion, _ = wf["conclusion"].(string)
			headBranch, _ = wf["head_branch"].(string)
		}
		raw := map[string]interface{}{
			"event": "workflow_run", "repo": repoName,
			"actor": actor, "conclusion": conclusion, "branch": headBranch,
		}
		events = append(events, makeEvent("devops.workflow_run", 1, raw))

	case "org":
		action, _ := payload["action"].(string)
		sev := githubAuditSeverity("org." + action)
		if sev == 0 {
			sev = 2
		}
		raw := map[string]interface{}{"event": "org." + action, "actor": actor}
		events = append(events, makeEvent("devops.org_"+action, sev, raw))
	}

	return events
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func truncatePatch(patch string, max int) string {
	if len(patch) <= max {
		return patch
	}
	return patch[:max] + "\n... (truncated)"
}

// matchesGlob matches a repo path against a sensitive-file pattern.
//
// DS-04: this used to be substring/suffix matching, so "id_rsa" matched
// "id_rsa.pub", ".env" matched ".envrc", and "*.pem" matched public
// certificates. Patterns now match the exact basename (or an exact path
// suffix for patterns containing "/"), "*.ext" matches the extension only,
// and public-half / template files are never treated as secrets.
func matchesGlob(filename, pattern string) bool {
	f := strings.ToLower(strings.TrimPrefix(filename, "/"))
	base := f
	if i := strings.LastIndex(f, "/"); i >= 0 {
		base = f[i+1:]
	}
	for _, safe := range []string{".pub", ".example", ".sample", ".template", ".dist"} {
		if strings.HasSuffix(base, safe) {
			return false
		}
	}
	p := strings.ToLower(pattern)
	if strings.HasPrefix(p, "*.") {
		return strings.HasSuffix(base, p[1:])
	}
	if strings.Contains(p, "/") {
		return f == p || strings.HasSuffix(f, "/"+p)
	}
	return base == p
}

// isRemovedStatus reports whether a file status means the file was deleted;
// deleting a secret file is remediation, not exposure.
func isRemovedStatus(status string) bool {
	return status == "removed" || status == "deleted" || status == "delete"
}

// riskyPipelineContent inspects ADDED lines of a pipeline-file patch for
// constructs that commonly enable secret exfiltration or code execution
// (DS-04). Returns a short reason, or "" if nothing risky was added.
func riskyPipelineContent(patch string) string {
	for _, line := range strings.Split(patch, "\n") {
		if !strings.HasPrefix(line, "+") {
			continue
		}
		l := strings.ToLower(line)
		switch {
		case strings.Contains(l, "pull_request_target"):
			return "pull_request_target trigger"
		case strings.Contains(l, "secrets: inherit"):
			return "secrets: inherit"
		case strings.Contains(l, "self-hosted"):
			return "self-hosted runner"
		case (strings.Contains(l, "curl") || strings.Contains(l, "wget")) &&
			(strings.Contains(l, "| bash") || strings.Contains(l, "|bash") || strings.Contains(l, "| sh")):
			return "download piped to shell"
		}
	}
	return ""
}

// webhookDeliverySeen records a delivery ID and reports whether it was
// already seen within the last 24h. In-memory and bounded (restart clears it;
// the deterministic event ID then makes a re-processed delivery overwrite
// rather than duplicate when times match).
var webhookDeliveries = struct {
	sync.Mutex
	m map[string]time.Time
}{m: map[string]time.Time{}}

func webhookDeliverySeen(key string) bool {
	now := time.Now()
	webhookDeliveries.Lock()
	defer webhookDeliveries.Unlock()
	if t, ok := webhookDeliveries.m[key]; ok && now.Sub(t) < 24*time.Hour {
		return true
	}
	if len(webhookDeliveries.m) > 20000 {
		for k, t := range webhookDeliveries.m {
			if now.Sub(t) >= 24*time.Hour {
				delete(webhookDeliveries.m, k)
			}
		}
		if len(webhookDeliveries.m) > 20000 {
			webhookDeliveries.m = map[string]time.Time{}
		}
	}
	webhookDeliveries.m[key] = now
	return false
}

// isProtectedBranch reports whether a branch name is conventionally protected.
func isProtectedBranch(b string) bool {
	b = strings.ToLower(b)
	switch b {
	case "main", "master", "develop", "development", "trunk", "production", "prod":
		return true
	}
	return strings.HasPrefix(b, "release/") || strings.HasPrefix(b, "release-")
}

// committerMismatch reports whether the committer differs from the author
// (rebased / cherry-picked / forged history). GitHub's web-flow committer
// (web UI merges and edits) is expected and ignored.
func committerMismatch(authorEmail, committerEmail string) bool {
	a, c := strings.ToLower(authorEmail), strings.ToLower(committerEmail)
	if c == "" || a == c || c == "noreply@github.com" {
		return false
	}
	return true
}

var dependencyManifests = map[string]bool{
	"package.json": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"go.mod": true, "go.sum": true, "requirements.txt": true, "pipfile": true, "pipfile.lock": true,
	"poetry.lock": true, "pyproject.toml": true, "pom.xml": true, "build.gradle": true, "gemfile": true,
	"gemfile.lock": true, "cargo.toml": true, "cargo.lock": true, "composer.json": true, "composer.lock": true,
}

func isDependencyManifest(path string) bool {
	base := strings.ToLower(path)
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return dependencyManifests[base]
}
