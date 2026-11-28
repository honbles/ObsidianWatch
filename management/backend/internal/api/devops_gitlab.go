package api

// devops_gitlab.go - GitLab polling and webhook ingestion

import (
	"context"
	neturl "net/url"
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
	_, err := c.getJSONPage(ctx, path, out)
	return err
}

// getJSONPage fetches one page and returns GitLab's X-Next-Page ("" on the
// last page).
func (c *gitlabClient) getJSONPage(ctx context.Context, path string, out interface{}) (string, error) {
	url := strings.TrimRight(c.baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)
	resp, err := devopsHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return "", fmt.Errorf("auth error %d: check token permissions", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("GitLab API %d: %s", resp.StatusCode, string(body))
	}
	return resp.Header.Get("X-Next-Page"), json.NewDecoder(resp.Body).Decode(out)
}

// gitlabGetAll follows X-Next-Page up to maxPages. Every list call used to read
// only the first page, so groups with more than 50 projects, or more than 100
// audit events since the last sync, silently lost the rest.
func gitlabGetAll[T any](ctx context.Context, c *gitlabClient, path string, maxPages int) ([]T, error) {
	var all []T
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	page := "1"
	for i := 0; i < maxPages && page != ""; i++ {
		var batch []T
		next, err := c.getJSONPage(ctx, path+sep+"page="+page, &batch)
		if err != nil {
			if i == 0 {
				return nil, err
			}
			return all, nil
		}
		all = append(all, batch...)
		page = next
	}
	return all, nil
}

// gitlabID encodes a group or project path for use as an :id path segment
// (group/sub -> group%2Fsub). Numeric IDs pass through.
func gitlabID(pathOrID string) string {
	return neturl.PathEscape(strings.Trim(pathOrID, "/"))
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
	path := fmt.Sprintf("/api/v4/groups/%s", gitlabID(group))
	if err := client.getJSON(ctx, path, &result); err != nil {
		// Try as project
		path = fmt.Sprintf("/api/v4/projects/%s", gitlabID(group))
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
		gitlabID(conn.Org), neturl.QueryEscape(sinceStr))
	if auditEvents, err := gitlabGetAll[map[string]interface{}](ctx, client, auditPath, 20); err == nil {
		events := gitlabAuditToEvents(auditEvents, conn)
		n, _ := ingestCloudEvents(ctx, eventDB, events)
		total += n
	}

	// ── 2. Recent commits from group/user projects ──────────────────────────
	projects, _ := gitlabProjects(ctx, client, conn.Org)
	if true {
		for _, proj := range projects {
			// DO-11: pipeline runs and tier-independent project events.
			var pipes []glPipeline
			if client.getJSON(ctx, fmt.Sprintf("/api/v4/projects/%d/pipelines?per_page=50&updated_after=%s", proj.ID, neturl.QueryEscape(sinceStr)), &pipes) == nil {
				n, _ := ingestCloudEvents(ctx, eventDB, gitlabPipelinesToEvents(pipes, proj.PathWithNamespace, conn))
				total += n
			}
			if pevents, err := gitlabGetAll[map[string]interface{}](ctx, client, fmt.Sprintf("/api/v4/projects/%d/events?per_page=100&after=%s", proj.ID, since.AddDate(0, 0, -1).Format("2006-01-02")), 10); err == nil {
				n, _ := ingestCloudEvents(ctx, eventDB, gitlabProjectEventsToEvents(pevents, proj.PathWithNamespace, conn))
				total += n
			}
			commitsPath := fmt.Sprintf("/api/v4/projects/%d/repository/commits?per_page=20&since=%s", proj.ID, neturl.QueryEscape(sinceStr))
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
				cicdModified, cicdRisky := false, ""
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
							for _, r := range pipelineRisks(d.Diff) {
								if !strings.Contains(cicdRisky, r) {
									if cicdRisky != "" {
										cicdRisky += "; "
									}
									cicdRisky += r
								}
							}
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
						"event": "cicd_modified", "sha": c.ID, "risky": cicdRisky,
						"repo": proj.PathWithNamespace, "author": c.AuthorEmail,
						"message": c.Title, "url": c.WebURL,
					})
					cicdSev := 2
					if sev := pipelineRiskSeverity(strings.Split(cicdRisky, "; ")); cicdRisky != "" && sev > 0 {
						cicdSev = sev
					}
					evts = append(evts, CloudEvent{
						ID:        "devops:gl:" + c.ID + ":cicd",
						Time:      pushedAt,
						AgentID:   fmt.Sprintf("devops:%d", conn.ID),
						Host:      conn.Org, OS: "devops",
						EventType: "devops.cicd_modified",
						Severity:  cicdSev, Source: "gitlab", Username: c.AuthorEmail, Raw: raw,
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

// gitlabAuditToEvents converts /groups/:id/audit_events entries. Those carry
// event_name (newer GitLab) and a details object (add/remove/change, from/to,
// author_name, custom_message); there is no action_name or author_name at the
// top level, which is what the converter used to read, so every audit entry
// was dropped as "not interesting".
func gitlabAuditToEvents(entries []map[string]interface{}, conn *store.DevOpsConnector) []CloudEvent {
	events := []CloudEvent{}
	for _, e := range entries {
		action, canon, role, vis := gitlabAuditAction(e)
		if action == "" {
			continue
		}
		details, _ := e["details"].(map[string]interface{})
		author, _ := details["author_name"].(string)
		if author == "" {
			author, _ = e["author_name"].(string)
		}
		ts, _ := e["created_at"].(string)
		eventTime, _ := time.Parse(time.RFC3339, ts)
		if eventTime.IsZero() {
			eventTime = time.Now()
		}
		sev := gitlabAuditSeverity(action)
		if sev == 0 {
			continue
		}
		enriched := map[string]interface{}{}
		for k, v := range e {
			enriched[k] = v
		}
		enriched["event"], enriched["action"] = canon, action
		if role != "" {
			enriched["role"] = role
		}
		if vis != "" {
			enriched["visibility"] = vis
		}
		if p, _ := details["entity_path"].(string); p != "" {
			enriched["repo"] = p
		}
		raw, _ := json.Marshal(enriched)
		id := fmt.Sprint(e["id"])
		if id == "" || id == "<nil>" {
			id = action + ":" + ts
		}
		ip, _ := details["ip_address"].(string)
		events = append(events, CloudEvent{
			ID:        fmt.Sprintf("gl-audit:%d:%s", conn.ID, id),
			Time:      eventTime,
			AgentID:   fmt.Sprintf("devops:%d", conn.ID),
			Host:      conn.Org, OS: "devops",
			EventType: "devops." + strings.ReplaceAll(strings.ToLower(action), " ", "_"),
			Severity:  sev, Source: "gitlab_audit",
			Username:  author, SrcIP: ip, Raw: raw,
		})
	}
	return events
}

// gitlabAuditAction returns a readable action ("added user_access"), the
// canonical event name the DEV-* rules know, and role/visibility when present.
func gitlabAuditAction(e map[string]interface{}) (action, canon, role, visibility string) {
	details, _ := e["details"].(map[string]interface{})
	str := func(k string) string { v, _ := details[k].(string); return v }
	name, _ := e["event_name"].(string)
	if legacy, _ := e["action_name"].(string); legacy != "" && name == "" {
		name = legacy
	}
	switch {
	case str("add") != "":
		action = "added " + str("add")
		role = strings.ToLower(str("as"))
	case str("remove") != "":
		action = "removed " + str("remove")
	case str("change") != "":
		action = "changed " + str("change")
		if strings.EqualFold(str("change"), "visibility") && strings.EqualFold(str("to"), "public") {
			visibility = "public"
		}
		if strings.Contains(strings.ToLower(str("change")), "access") {
			role = strings.ToLower(str("to"))
		}
	case str("custom_message") != "":
		action = str("custom_message")
	case name != "":
		action = strings.ReplaceAll(name, "_", " ")
	}
	a := strings.ToLower(action + " " + name)
	switch {
	case containsAny(a, "removed project", "project destroyed", "project_destroyed", "project_deletion"):
		canon = "project_destroyed"
	case visibility == "public":
		canon = "repo.access"
	case containsAny(a, "added user_access", "member_created", "added user"):
		canon = "org.add_member"
	case containsAny(a, "access_level", "changed access", "member_updated"):
		canon = "org.update_member"
	case containsAny(a, "deploy_key", "deploy key"):
		if strings.Contains(a, "added") || strings.Contains(a, "created") {
			canon = "deploy_key.create"
		}
	case containsAny(a, "personal access token", "personal_access_token", "access_token_created"):
		if containsAny(a, "creat", "added") {
			canon = "personal_access_token.created"
		}
	case containsAny(a, "protected_branch", "protected branch"):
		if containsAny(a, "removed", "destroy", "unprotect") {
			canon = "protected_branch.destroy"
		}
	case containsAny(a, "audit_event_streaming", "streaming destination", "event streaming"):
		if containsAny(a, "removed", "destroy", "delete") {
			canon = "audit_log_streaming.destroy"
		}
	case containsAny(a, "project_hook", "group_hook", "hook"):
		if containsAny(a, "added", "creat") {
			canon = "hook.create"
		}
	case containsAny(a, "transfer"):
		canon = "repo.transfer"
	}
	if canon == "" {
		canon = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(action)), " ", "_")
	}
	return action, canon, role, visibility
}

func gitlabAuditSeverity(action string) int {
	a := strings.ToLower(action)
	if containsAny(a, "added user", "removed user", "user_access", "destroyed", "removed project", "transfer",
		"made public", "changed visibility", "two-factor", "two_factor",
		"deploy_key", "deploy key", "personal access token", "personal_access_token",
		"protected_branch", "protected branch", "streaming", "hook") {
		return 4
	}
	if containsAny(a, "added", "removed", "changed", "updated", "created", "deleted") {
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

type gitlabProject struct {
	ID                int    `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	DefaultBranch     string `json:"default_branch"`
	EmptyRepo         bool   `json:"empty_repo"`
	Archived          bool   `json:"archived"`
}

// gitlabProjects lists the connector's projects: the group's (with subgroups),
// else the user namespace's, else the single project when Org names one.
func gitlabProjects(ctx context.Context, c *gitlabClient, org string) ([]gitlabProject, error) {
	groupPath := fmt.Sprintf("/api/v4/groups/%s/projects?per_page=100&order_by=last_activity_at&include_subgroups=true&archived=false", gitlabID(org))
	ps, gerr := gitlabGetAll[gitlabProject](ctx, c, groupPath, 20)
	if gerr == nil && len(ps) > 0 {
		return ps, nil
	}
	userPath := fmt.Sprintf("/api/v4/users/%s/projects?per_page=100&order_by=last_activity_at&archived=false", gitlabID(org))
	if ps, err := gitlabGetAll[gitlabProject](ctx, c, userPath, 20); err == nil && len(ps) > 0 {
		return ps, nil
	}
	var one gitlabProject
	if err := c.getJSON(ctx, "/api/v4/projects/"+gitlabID(org), &one); err == nil && one.PathWithNamespace != "" {
		return []gitlabProject{one}, nil
	}
	// Say what the group listing found: that is the case for a group connector.
	if gerr != nil {
		return nil, fmt.Errorf("listing the projects of group %q: %v", org, gerr)
	}
	return nil, fmt.Errorf("group %q lists no projects this token can see: the token's user must be a member (Reporter or above) of the projects, or of the group, and the token needs the read_api scope", org)
}
