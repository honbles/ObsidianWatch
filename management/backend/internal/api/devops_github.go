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
	"log/slog"
	"strconv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Secret patterns for scanning commit diffs ─────────────────────────────────
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+]{20,})`),
	regexp.MustCompile(`(?i)(password|passwd|secret|api_key|apikey|api_secret|token|auth_token|access_token|private_key)\s*[=:]\s*["']([^"'\s]{8,})`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                        // AWS Access Key
	regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),                // GitHub PAT
	regexp.MustCompile(`(?i)glpat-[a-zA-Z0-9\-_]{20}`),           // GitLab PAT
	regexp.MustCompile(`(?i)-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), // Private key
	regexp.MustCompile(`(?i)(client_secret|client-secret)\s*[=:]\s*["']?([a-zA-Z0-9\-_.~]{32,})`),
	regexp.MustCompile(`(?i)xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}`), // Slack token
	regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),             // GCP API key
	regexp.MustCompile(`(?i)SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9_-]{43}`), // SendGrid
}

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

func (c *githubClient) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return http.DefaultClient.Do(req)
}

func (c *githubClient) getJSON(ctx context.Context, url string, out interface{}) error {
	resp, err := c.get(ctx, url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return fmt.Errorf("not found: %s", url)
	}
	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		return fmt.Errorf("auth error %d: check token permissions", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API %d: %s", resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(out)
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
		if label == "" { label = result.Login }
		return label, nil
	}
	// Try as user account
	userURL := fmt.Sprintf("https://api.github.com/users/%s", org)
	if err := client.getJSON(ctx, userURL, &result); err == nil {
		label := result.Name
		if label == "" { label = result.Login }
		return label, nil
	}
	// Verify token is valid at all
	var me struct{ Login string `json:"login"` }
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
	if err := client.getJSON(ctx, auditURL, &auditEvents); err == nil {
		// Org account — has full audit log
		events, newCursor := githubAuditToEvents(auditEvents, conn)
		if len(events) > 0 {
			n, _ := ingestCloudEvents(ctx, eventDB, events)
			total += n
			if newCursor != "" {
				cursor = newCursor
			}
		}
	} else {
		// Personal account — use public events API as fallback
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
		if err := client.getJSON(ctx, url, &batch); err == nil {
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
				"https://api.github.com/repos/%s/commits?per_page=20&since=%s",
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
				} `json:"commit"`
				Author *struct {
					Login string `json:"login"`
				} `json:"author"`
				HTMLURL string `json:"html_url"`
			}

			if err := client.getJSON(ctx, commitsURL, &commits); err != nil {
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
				sensitiveModified := false

				for _, f := range detail.Files {
					diffs = append(diffs, store.CommitFileDiff{
						File:      f.Filename,
						Additions: f.Additions,
						Deletions: f.Deletions,
						Status:    f.Status,
						Patch:     truncatePatch(f.Patch, 2000),
					})

					// Secret scanning on added lines
					if f.Patch != "" {
						for _, line := range strings.Split(f.Patch, "\n") {
							if !strings.HasPrefix(line, "+") {
								continue
							}
							for _, pat := range secretPatterns {
								if pat.MatchString(line) {
									secretsFound = append(secretsFound, f.Filename)
									break
								}
							}
						}
					}

					// CI/CD file check
					for _, cicd := range cicdFiles {
						if strings.HasPrefix(f.Filename, cicd) || f.Filename == cicd {
							cicdModified = true
						}
					}

					// Sensitive file check
					for _, sf := range sensitiveFilePatterns {
						if matchesGlob(f.Filename, sf) {
							sensitiveModified = true
						}
					}
				}

				diffJSON, _ := json.Marshal(diffs)
				commit := store.DevOpsCommit{
					ID:             c.SHA,
					ConnectorID:    conn.ID,
					Repo:           repo.FullName,
					Branch:         func() string { if repo.DefaultBranch != "" { return repo.DefaultBranch }; return "HEAD" }(),
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
					"event":          "push",
					"sha":            c.SHA,
					"repo":           repo.FullName,
					"author":         authorLogin,
					"author_name":    c.Commit.Author.Name,
					"author_email":   c.Commit.Author.Email,
					"message":        c.Commit.Message,
					"url":            c.HTMLURL,
					"files_changed":  len(detail.Files),
					"additions":      detail.Stats.Additions,
					"deletions":      detail.Stats.Deletions,
					"pushed_at":      pushedAt,
				})
				baseEvents := []CloudEvent{{
					ID:        "devops:" + c.SHA + ":push",
					Time:      time.Now().UTC(),
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
						"event":    "secret_pushed",
						"sha":      c.SHA,
						"repo":     repo.FullName,
						"author":   authorLogin,
						"files":    secretsFound,
						"message":  c.Commit.Message,
						"url":      c.HTMLURL,
					})
					events = append(events, CloudEvent{
						ID:        "devops:" + c.SHA + ":secret",
						Time:      time.Now().UTC(), // use now so detection engine catches it
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
						"sha":     c.SHA,
						"repo":    repo.FullName,
						"author":  authorLogin,
						"message": c.Commit.Message,
						"url":     c.HTMLURL,
					})
					events = append(events, CloudEvent{
						ID:        "devops:" + c.SHA + ":cicd",
						Time:      time.Now().UTC(),
						AgentID:   fmt.Sprintf("devops:%d", conn.ID),
						Host:      conn.Org,
						OS:        "devops",
						EventType: "devops.cicd_modified",
						Severity:  4,
						Source:    "github",
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
						Time:      time.Now().UTC(),
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

func githubAuditSeverity(action string) int {
	high := []string{
		"org.add_member", "org.remove_member", "org.update_member",
		"repo.create", "repo.destroy", "repo.access",
		"protected_branch.destroy", "protected_branch.update_admin_enforcement",
		"protected_branch.update_require_code_owner_reviews",
		"org.add_billing_manager", "org.invite_member",
		"hook.create", "hook.destroy",
		"oauth_application.create", "integration_installation.create",
	}
	medium := []string{
		"repo.rename", "repo.transfer",
		"team.add_member", "team.remove_member",
		"org.update_default_repository_permission",
		"protected_branch.create",
		"personal_access_token.created",
		"deploy_key.create",
		"runners.create",
	}
	action = strings.ToLower(action)
	for _, h := range high {
		if strings.Contains(action, h) {
			return 4
		}
	}
	for _, m := range medium {
		if strings.Contains(action, m) {
			return 3
		}
	}
	// Repo made public is critical
	if strings.Contains(action, "public") {
		return 5
	}
	return 0
}

// ── Webhook handler ───────────────────────────────────────────────────────────

func handleGitHubWebhook(db *store.DB, eventDB *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
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

		// Validate HMAC signature if secret is configured
		sig := r.Header.Get("X-Hub-Signature-256")
		if conn != nil && conn.WebhookSecret != "" && sig != "" {
			mac := hmac.New(sha256.New, []byte(conn.WebhookSecret))
			mac.Write(body)
			expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			if !hmac.Equal([]byte(sig), []byte(expected)) {
				logger.Warn("devops webhook: invalid HMAC signature", "connector", idStr)
				http.Error(w, "invalid signature", 401)
				return
			}
		}

		event := r.Header.Get("X-GitHub-Event")
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}

		logger.Info("devops webhook received", "event", event, "connector", idStr)
		events := processGitHubWebhookEvent(event, payload, conn)
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
		raw := map[string]interface{}{
			"event": "push", "ref": ref, "pusher": actor,
			"repo": repoName, "commits": len(commits),
		}
		events = append(events, makeEvent("devops.push", 1, raw))

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

func matchesGlob(filename, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		ext := pattern[1:]
		return strings.HasSuffix(filename, ext)
	}
	return strings.Contains(filename, pattern) || filename == pattern
}
