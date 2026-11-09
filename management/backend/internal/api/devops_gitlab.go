package api

// devops_gitlab.go — GitLab polling and webhook ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type gitlabClient struct {
	token   string
	baseURL string // https://gitlab.com or self-hosted
	group   string
}

func (c *gitlabClient) getJSON(ctx context.Context, path string, out interface{}) error {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fmt.Errorf("auth error %d: check token permissions", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitLab API %d: %s", resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func testGitLabConnection(ctx context.Context, token, baseURL, group string) (string, error) {
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	client := &gitlabClient{token: token, baseURL: baseURL, group: group}
	var result struct {
		FullName string `json:"full_name"`
		Name     string `json:"name"`
		ID       int    `json:"id"`
	}
	path := fmt.Sprintf("/api/v4/groups/%s", group)
	if err := client.getJSON(ctx, path, &result); err != nil {
		// Try as project
		path = fmt.Sprintf("/api/v4/projects/%s", strings.ReplaceAll(group, "/", "%2F"))
		if err2 := client.getJSON(ctx, path, &result); err2 != nil {
			return "", fmt.Errorf("group/project not found: %w", err)
		}
	}
	if result.FullName != "" {
		return result.FullName, nil
	}
	return result.Name, nil
}

func syncGitLab(ctx context.Context, conn *store.DevOpsConnector, db *store.DB, eventDB *store.DB) (int, string, error) {
	token := conn.Credentials["token"]
	baseURL := conn.Credentials["base_url"]
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	if token == "" {
		return 0, "", fmt.Errorf("missing GitLab token")
	}

	client := &gitlabClient{token: token, baseURL: baseURL, group: conn.Org}
	total := 0
	cursor := conn.SyncCursor

	// First sync (no commits yet): go back 30 days
	// Subsequent syncs: start from last sync minus 2 min overlap
	var commitCount int
	db.QueryRowContext(ctx, `SELECT count(*) FROM devops_commits WHERE connector_id=$1`, conn.ID).Scan(&commitCount)
	since := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if conn.LastSync != nil && commitCount > 0 {
		since = conn.LastSync.Add(-2 * time.Minute)
	}
	sinceStr := since.Format(time.RFC3339)

	// ── 1. Group audit events ─────────────────────────────────────────────────
	auditPath := fmt.Sprintf("/api/v4/groups/%s/audit_events?per_page=100&created_after=%s",
		conn.Org, sinceStr)
	var auditEvents []map[string]interface{}
	if err := client.getJSON(ctx, auditPath, &auditEvents); err == nil {
		events := gitlabAuditToEvents(auditEvents, conn)
		n, _ := ingestCloudEvents(ctx, eventDB, events)
		total += n
	}

	// ── 2. Recent commits from group/user projects ──────────────────────────
	var projects []struct {
		ID                int    `json:"id"`
		PathWithNamespace string `json:"path_with_namespace"`
		DefaultBranch     string `json:"default_branch"`
	}
	// Try group endpoint first, fall back to user/personal namespace
	groupPath := fmt.Sprintf("/api/v4/groups/%s/projects?per_page=50&order_by=last_activity_at&include_subgroups=true", conn.Org)
	userPath  := fmt.Sprintf("/api/v4/users/%s/projects?per_page=50&order_by=last_activity_at", conn.Org)
	if err := client.getJSON(ctx, groupPath, &projects); err != nil || len(projects) == 0 {
		client.getJSON(ctx, userPath, &projects)
	}
	if true {
		for _, proj := range projects {
			// DO-11: pipeline runs and tier-independent project events.
			var pipes []glPipeline
			if client.getJSON(ctx, fmt.Sprintf("/api/v4/projects/%d/pipelines?per_page=50&updated_after=%s", proj.ID, sinceStr), &pipes) == nil {
				n, _ := ingestCloudEvents(ctx, eventDB, gitlabPipelinesToEvents(pipes, proj.PathWithNamespace, conn))
				total += n
			}
			var pevents []map[string]interface{}
			if client.getJSON(ctx, fmt.Sprintf("/api/v4/projects/%d/events?per_page=100&after=%s", proj.ID, since.AddDate(0, 0, -1).Format("2006-01-02")), &pevents) == nil {
				n, _ := ingestCloudEvents(ctx, eventDB, gitlabProjectEventsToEvents(pevents, proj.PathWithNamespace, conn))
				total += n
			}
			commitsPath := fmt.Sprintf("/api/v4/projects/%d/repository/commits?per_page=20&since=%s", proj.ID, sinceStr)
			var commits []struct {
				ID             string `json:"id"`
				Title          string `json:"title"`
				Message        string `json:"message"`
				AuthorName     string `json:"author_name"`
				AuthorEmail    string `json:"author_email"`
				CommittedDate  string `json:"committed_date"`
				WebURL         string `json:"web_url"`
			}
			if err := client.getJSON(ctx, commitsPath, &commits); err != nil {
				continue
			}

			for _, c := range commits {
				// Get diff
				diffPath := fmt.Sprintf("/api/v4/projects/%d/repository/commits/%s/diff", proj.ID, c.ID)
				var diffs []struct {
					OldPath     string `json:"old_path"`
					NewPath     string `json:"new_path"`
					Diff        string `json:"diff"`
					NewFile     bool   `json:"new_file"`
					DeletedFile bool   `json:"deleted_file"`
					RenamedFile bool   `json:"renamed_file"`
				}
				client.getJSON(ctx, diffPath, &diffs)

				pushedAt, _ := time.Parse(time.RFC3339, c.CommittedDate)

				fileDiffs := make([]store.CommitFileDiff, 0, len(diffs))
				secretsFound := []string{}
				cicdModified := false
				sensitiveModified := false
				totalAdd, totalDel := 0, 0

				for _, d := range diffs {
					adds, dels := countDiffLines(d.Diff)
					totalAdd += adds
					totalDel += dels

					status := "modified"
					if d.NewFile {
						status = "added"
					} else if d.DeletedFile {
						status = "removed"
					}

					fileDiffs = append(fileDiffs, store.CommitFileDiff{
						File:      d.NewPath,
						Additions: adds,
						Deletions: dels,
						Status:    status,
						Patch:     truncatePatch(redactSecrets(d.Diff), 2000),
					})

					for _, line := range strings.Split(d.Diff, "\n") {
						if !strings.HasPrefix(line, "+") {
							continue
						}
						if lineHasSecret(line) {
							secretsFound = append(secretsFound, d.NewPath)
						}
					}

					for _, cicd := range cicdFiles {
						if strings.Contains(d.NewPath, cicd) || d.NewPath == cicd {
							cicdModified = true
						}
					}
					for _, sf := range sensitiveFilePatterns {
						if !d.DeletedFile && matchesGlob(d.NewPath, sf) {
							sensitiveModified = true
						}
					}
				}

				diffJSON, _ := json.Marshal(fileDiffs)
				commit := store.DevOpsCommit{
					ID:          "gl:" + c.ID,
					ConnectorID: conn.ID,
					Repo:        proj.PathWithNamespace,
					Branch:      func() string { if proj.DefaultBranch != "" { return proj.DefaultBranch }; return "HEAD" }(),
					AuthorName:  c.AuthorName,
					AuthorEmail: c.AuthorEmail,
					Message:     c.Message,
					URL:         c.WebURL,
					FilesChanged: len(diffs),
					Additions:   totalAdd,
					Deletions:   totalDel,
					DiffSummary: diffJSON,
					PushedAt:    pushedAt,
				}
				db.UpsertDevOpsCommit(ctx, commit)
				total++

				// Always emit a devops.push event for every commit
				pushRaw, _ := json.Marshal(map[string]interface{}{
					"event":         "push",
					"sha":           c.ID,
					"repo":          proj.PathWithNamespace,
					"author_name":   c.AuthorName,
					"author_email":  c.AuthorEmail,
					"message":       c.Message,
					"url":           c.WebURL,
					"files_changed": len(diffs),
					"additions":     totalAdd,
					"deletions":     totalDel,
					"pushed_at":     pushedAt,
				})
				ingestCloudEvents(ctx, eventDB, []CloudEvent{{
					ID:        "devops:gl:" + c.ID + ":push",
					Time:      commitEventTime(pushedAt),
					AgentID:   fmt.Sprintf("devops:%d", conn.ID),
					Host:      conn.Org,
					OS:        "devops",
					EventType: "devops.push",
					Severity:  1,
					Source:    "gitlab",
					Username:  c.AuthorEmail,
					Raw:       pushRaw,
				}})
				total++

				evts := []CloudEvent{}
				if len(secretsFound) > 0 {
					raw, _ := json.Marshal(map[string]interface{}{
						"event": "secret_pushed", "sha": c.ID,
						"repo": proj.PathWithNamespace, "author": c.AuthorEmail,
						"files": secretsFound, "message": c.Title, "url": c.WebURL,
					})
					evts = append(evts, CloudEvent{
						ID:        "devops:gl:" + c.ID + ":secret",
						Time:      pushedAt,
						AgentID:   fmt.Sprintf("devops:%d", conn.ID),
						Host:      conn.Org, OS: "devops",
						EventType: "devops.secret_push",
						Severity:  5, Source: "gitlab", Username: c.AuthorEmail, Raw: raw,
					})
				}
				if cicdModified {
					raw, _ := json.Marshal(map[string]interface{}{
						"event": "cicd_modified", "sha": c.ID,
						"repo": proj.PathWithNamespace, "author": c.AuthorEmail,
						"message": c.Title, "url": c.WebURL,
					})
					evts = append(evts, CloudEvent{
						ID:        "devops:gl:" + c.ID + ":cicd",
						Time:      pushedAt,
						AgentID:   fmt.Sprintf("devops:%d", conn.ID),
						Host:      conn.Org, OS: "devops",
						EventType: "devops.cicd_modified",
						Severity:  4, Source: "gitlab", Username: c.AuthorEmail, Raw: raw,
					})
				}
				if sensitiveModified {
					raw, _ := json.Marshal(map[string]interface{}{
						"event": "sensitive_file", "sha": c.ID,
						"repo": proj.PathWithNamespace, "author": c.AuthorEmail,
						"message": c.Title,
					})
					evts = append(evts, CloudEvent{
						ID:        "devops:gl:" + c.ID + ":sensitive",
						Time:      pushedAt,
						AgentID:   fmt.Sprintf("devops:%d", conn.ID),
						Host:      conn.Org, OS: "devops",
						EventType: "devops.sensitive_file",
						Severity:  3, Source: "gitlab", Username: c.AuthorEmail, Raw: raw,
					})
				}
				if len(evts) > 0 {
					n, _ := ingestCloudEvents(ctx, eventDB, evts)
					total += n
				}
			}
		}
	}

	return total, cursor, nil
}

func gitlabAuditToEvents(entries []map[string]interface{}, conn *store.DevOpsConnector) []CloudEvent {
	events := []CloudEvent{}
	for _, e := range entries {
		action, _ := e["action_name"].(string)
		author, _ := e["author_name"].(string)
		ts, _ := e["created_at"].(string)
		eventTime, _ := time.Parse(time.RFC3339, ts)
		if eventTime.IsZero() {
			eventTime = time.Now()
		}
		sev := gitlabAuditSeverity(action)
		if sev == 0 {
			continue
		}
		raw, _ := json.Marshal(e)
		events = append(events, CloudEvent{
			ID:        fmt.Sprintf("gl-audit:%d:%s:%s", conn.ID, action, ts),
			Time:      eventTime,
			AgentID:   fmt.Sprintf("devops:%d", conn.ID),
			Host:      conn.Org, OS: "devops",
			EventType: "devops." + strings.ReplaceAll(action, " ", "_"),
			Severity:  sev, Source: "gitlab_audit",
			Username:  author, Raw: raw,
		})
	}
	return events
}

func gitlabAuditSeverity(action string) int {
	a := strings.ToLower(action)
	if containsAny(a, "added user", "removed user", "destroyed", "transferred", "made public",
		"changed visibility", "enabled two-factor", "disabled two-factor",
		"added deploy key", "created personal access token") {
		return 4
	}
	if containsAny(a, "added", "removed", "changed", "updated", "created") {
		return 2
	}
	return 0
}

func countDiffLines(diff string) (adds, dels int) {
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			adds++
		} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			dels++
		}
	}
	return
}
