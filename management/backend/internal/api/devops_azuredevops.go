package api

// devops_azuredevops.go — Azure DevOps polling and webhook ingestion
//
// Azure DevOps REST API v7.0
// Auth: Personal Access Token (PAT) via Basic auth (base64 encoded ":PAT")
// Base URL: https://dev.azure.com/{organization}

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Azure DevOps HTTP client ──────────────────────────────────────────────────

type azureClient struct {
	token   string
	baseURL string // https://dev.azure.com/{org}
	org     string
}

func newAzureClient(token, org string) *azureClient {
	return &azureClient{
		token:   token,
		baseURL: fmt.Sprintf("https://dev.azure.com/%s", org),
		org:     org,
	}
}

func (c *azureClient) do(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	// Azure DevOps uses Basic auth with empty username and PAT as password
	auth := base64.StdEncoding.EncodeToString([]byte(":" + c.token))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(req)
}

func (c *azureClient) getJSON(ctx context.Context, url string, out interface{}) error {
	resp, err := c.do(ctx, url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return fmt.Errorf("Azure DevOps: unauthorized — check PAT token and scopes")
	}
	if resp.StatusCode == 404 {
		return fmt.Errorf("Azure DevOps: not found — %s", url)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Azure DevOps API %d: %s", resp.StatusCode, string(body)[:min(200, len(body))])
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Main sync function ────────────────────────────────────────────────────────

func syncAzureDevOps(ctx context.Context, conn *store.DevOpsConnector, db *store.DB, eventDB *store.DB) (int, string, error) {
	token := conn.Credentials["token"]
	org := conn.Org
	if token == "" {
		return 0, "", fmt.Errorf("missing Azure DevOps PAT token")
	}

	client := newAzureClient(token, org)
	total := 0

	// First sync: go back 30 days; subsequent: from last sync
	var commitCount int
	db.QueryRowContext(ctx, `SELECT count(*) FROM devops_commits WHERE connector_id=$1`, conn.ID).Scan(&commitCount)
	since := time.Now().UTC().Add(-30 * 24 * time.Hour)
	if conn.LastSync != nil && commitCount > 0 {
		since = conn.LastSync.Add(-2 * time.Minute)
	}
	sinceStr := since.UTC().Format(time.RFC3339)

	// ── 1. List projects ──────────────────────────────────────────────────────
	var projectsResp struct {
		Value []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"value"`
	}
	projectsURL := fmt.Sprintf("%s/_apis/projects?api-version=7.0", client.baseURL)
	if err := client.getJSON(ctx, projectsURL, &projectsResp); err != nil {
		return 0, "", fmt.Errorf("failed to list projects: %w", err)
	}

	for _, proj := range projectsResp.Value {
		// ── 2. List repos in project ──────────────────────────────────────────
		var reposResp struct {
			Value []struct {
				ID            string `json:"id"`
				Name          string `json:"name"`
				DefaultBranch string `json:"defaultBranch"` // refs/heads/main
				RemoteURL     string `json:"remoteUrl"`
			} `json:"value"`
		}
		reposURL := fmt.Sprintf("%s/%s/_apis/git/repositories?api-version=7.0", client.baseURL, proj.Name)
		if err := client.getJSON(ctx, reposURL, &reposResp); err != nil {
			continue
		}

		for _, repo := range reposResp.Value {
			// Normalise branch: refs/heads/main → main
			branch := strings.TrimPrefix(repo.DefaultBranch, "refs/heads/")
			if branch == "" {
				branch = "main"
			}
			repoFullName := fmt.Sprintf("%s/%s/%s", org, proj.Name, repo.Name)

			// ── 3. Get commits ────────────────────────────────────────────────
			var commitsResp struct {
				Value []struct {
					CommitID string `json:"commitId"`
					Comment  string `json:"comment"`
					Author   struct {
						Name  string `json:"name"`
						Email string `json:"email"`
						Date  string `json:"date"`
					} `json:"author"`
					URL string `json:"url"`
				} `json:"value"`
			}
			commitsURL := fmt.Sprintf(
				"%s/%s/_apis/git/repositories/%s/commits?searchCriteria.fromDate=%s&searchCriteria.$top=20&api-version=7.0",
				client.baseURL, proj.Name, repo.ID, sinceStr,
			)
			if err := client.getJSON(ctx, commitsURL, &commitsResp); err != nil {
				continue
			}

			for _, c := range commitsResp.Value {
				pushedAt, _ := time.Parse(time.RFC3339, c.Author.Date)

				// ── 4. Get changes (diff) ─────────────────────────────────────
				var changesResp struct {
					Changes []struct {
						Item struct {
							Path string `json:"path"`
						} `json:"item"`
						ChangeType string `json:"changeType"` // add, edit, delete
					} `json:"changes"`
				}
				changesURL := fmt.Sprintf(
					"%s/%s/_apis/git/repositories/%s/commits/%s/changes?api-version=7.0",
					client.baseURL, proj.Name, repo.ID, c.CommitID,
				)
				client.getJSON(ctx, changesURL, &changesResp)

				fileDiffs := make([]store.CommitFileDiff, 0, len(changesResp.Changes))
				secretsFound := []string{}
				cicdModified := false
				sensitiveModified := false

				for _, ch := range changesResp.Changes {
					status := "modified"
					switch ch.ChangeType {
					case "add":
						status = "added"
					case "delete":
						status = "removed"
					}
					fileDiffs = append(fileDiffs, store.CommitFileDiff{
						File:   ch.Item.Path,
						Status: status,
					})
					// Secret pattern check on path
					for _, pat := range secretPatterns {
						if pat.MatchString(ch.Item.Path) {
							secretsFound = append(secretsFound, ch.Item.Path)
							break
						}
					}
					for _, cicd := range cicdFiles {
						if strings.Contains(ch.Item.Path, cicd) {
							cicdModified = true
						}
					}
					for _, sf := range sensitiveFilePatterns {
						if matchesGlob(ch.Item.Path, sf) {
							sensitiveModified = true
						}
					}
				}

				diffJSON, _ := json.Marshal(fileDiffs)
				commit := store.DevOpsCommit{
					ID:           "az:" + c.CommitID,
					ConnectorID:  conn.ID,
					Repo:         repoFullName,
					Branch:       branch,
					AuthorName:   c.Author.Name,
					AuthorEmail:  c.Author.Email,
					Message:      c.Comment,
					URL:          c.URL,
					FilesChanged: len(changesResp.Changes),
					DiffSummary:  diffJSON,
					PushedAt:     pushedAt,
				}
				db.UpsertDevOpsCommit(ctx, commit)
				total++

				// Emit devops events
				pushRaw, _ := json.Marshal(map[string]interface{}{
					"event":         "push",
					"sha":           c.CommitID,
					"repo":          repoFullName,
					"author_name":   c.Author.Name,
					"author_email":  c.Author.Email,
					"message":       c.Comment,
					"files_changed": len(changesResp.Changes),
					"pushed_at":     pushedAt,
				})
				ingestCloudEvents(ctx, eventDB, []CloudEvent{{
					ID:        "devops:az:" + c.CommitID + ":push",
					Time:      time.Now().UTC(),
					AgentID:   fmt.Sprintf("devops:%d", conn.ID),
					Host:      conn.Org,
					OS:        "devops",
					EventType: "devops.push",
					Severity:  1,
					Source:    "azuredevops",
					Raw:       pushRaw,
				}})

				// Secret push event
				if len(secretsFound) > 0 {
					secretRaw, _ := json.Marshal(map[string]interface{}{
						"sha": c.CommitID, "repo": repoFullName, "files": secretsFound,
					})
					ingestCloudEvents(ctx, eventDB, []CloudEvent{{
						ID:        "devops:az:" + c.CommitID + ":secret",
						Time:      time.Now().UTC(),
						AgentID:   fmt.Sprintf("devops:%d", conn.ID),
						Host:      conn.Org,
						OS:        "devops",
						EventType: "devops.secret_push",
						Severity:  4,
						Source:    "azuredevops",
						Raw:       secretRaw,
					}})
				}
				// CICD modified event
				if cicdModified {
					cicdRaw, _ := json.Marshal(map[string]interface{}{
						"sha": c.CommitID, "repo": repoFullName,
					})
					ingestCloudEvents(ctx, eventDB, []CloudEvent{{
						ID:        "devops:az:" + c.CommitID + ":cicd",
						Time:      time.Now().UTC(),
						AgentID:   fmt.Sprintf("devops:%d", conn.ID),
						Host:      conn.Org,
						OS:        "devops",
						EventType: "devops.cicd_modified",
						Severity:  3,
						Source:    "azuredevops",
						Raw:       cicdRaw,
					}})
				}
				_ = sensitiveModified
			}
		}
	}

	return total, "", nil
}

// ── SAST helpers for Azure DevOps ────────────────────────────────────────────

func fetchAzureTree(ctx context.Context, token, org, project, repoID, branch string) ([]ghTreeEntry, error) {
	client := newAzureClient(token, org)
	var itemsResp struct {
		Value []struct {
			Path         string `json:"path"`
			IsFolder     bool   `json:"isFolder"`
			ContentLength int64 `json:"contentLength"`
		} `json:"value"`
	}
	url := fmt.Sprintf(
		"https://dev.azure.com/%s/%s/_apis/git/repositories/%s/items?recursionLevel=full&versionDescriptor.version=%s&versionDescriptor.versionType=branch&api-version=7.0",
		org, project, repoID, branch,
	)
	if err := client.getJSON(ctx, url, &itemsResp); err != nil {
		return nil, err
	}
	var out []ghTreeEntry
	for _, item := range itemsResp.Value {
		if item.IsFolder {
			continue
		}
		out = append(out, ghTreeEntry{
			Path: strings.TrimPrefix(item.Path, "/"),
			Type: "blob",
			Size: int(item.ContentLength),
		})
	}
	return out, nil
}

func fetchAzureFileContent(ctx context.Context, token, org, project, repoID, path, branch string) (string, error) {
	client := newAzureClient(token, org)
	url := fmt.Sprintf(
		"https://dev.azure.com/%s/%s/_apis/git/repositories/%s/items?path=%s&versionDescriptor.version=%s&versionDescriptor.versionType=branch&$format=text&api-version=7.0",
		org, project, repoID, path, branch,
	)
	resp, err := client.do(ctx, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Azure API %d for %s", resp.StatusCode, path)
	}
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

// testAzureDevOpsConnection verifies the token and org are valid
func testAzureDevOpsConnection(ctx context.Context, token, org, baseURL string) (string, error) {
	if baseURL == "" {
		baseURL = fmt.Sprintf("https://dev.azure.com/%s", org)
	}
	client := &azureClient{token: token, baseURL: baseURL, org: org}
	var result struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	url := fmt.Sprintf("%s/_apis/projects?api-version=7.0&$top=1", baseURL)
	if err := client.getJSON(ctx, url, &result); err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	return fmt.Sprintf("%s (%d projects visible)", org, len(result.Value)), nil
}
