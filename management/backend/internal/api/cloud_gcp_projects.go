package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// G-21: GCP multi-project / org-level scope.
//
// The connector's project_id may be a single project, a comma-separated list,
// or "*". With "*" (or an empty list) plus an org_id or folder_id credential,
// projects are discovered through Cloud Resource Manager. The service account
// needs resourcemanager.projects.list / folders.list on that scope.

const (
	gcpMaxProjects = 100
	gcpMaxFolders  = 200
)

var gcpCRMBase = "https://cloudresourcemanager.googleapis.com/v3"

func splitGCPProjectList(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\n' }) {
		if p != "" && p != "*" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// normalizeGCPParent turns "123", "organizations/123" or "folders/9" into a
// CRM parent string. kind is "organizations" or "folders".
func normalizeGCPParent(kind, v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "/") {
		return v
	}
	return kind + "/" + v
}

func parseGCPProjectsPage(body []byte) (ids []string, next string) {
	var r struct {
		Projects []struct {
			ProjectID string `json:"projectId"`
			State     string `json:"state"`
		} `json:"projects"`
		NextPageToken string `json:"nextPageToken"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil, ""
	}
	for _, p := range r.Projects {
		if p.ProjectID != "" && (p.State == "" || p.State == "ACTIVE") {
			ids = append(ids, p.ProjectID)
		}
	}
	return ids, r.NextPageToken
}

func parseGCPFoldersPage(body []byte) (names []string, next string) {
	var r struct {
		Folders []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"folders"`
		NextPageToken string `json:"nextPageToken"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil, ""
	}
	for _, f := range r.Folders {
		if f.Name != "" && (f.State == "" || f.State == "ACTIVE") {
			names = append(names, f.Name)
		}
	}
	return names, r.NextPageToken
}

func gcpCRMGet(ctx context.Context, token, path string, q url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", gcpCRMBase+path+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, nil
}

// discoverGCPProjects walks parent (organization or folder) breadth-first and
// returns active project IDs, capped at gcpMaxProjects.
func discoverGCPProjects(ctx context.Context, token, parent string) ([]string, error) {
	queue := []string{parent}
	visited := 0
	var ids []string
	seen := map[string]bool{}
	for len(queue) > 0 && len(ids) < gcpMaxProjects {
		cur := queue[0]
		queue = queue[1:]
		visited++
		if visited > gcpMaxFolders {
			break
		}
		for page := ""; ; {
			q := url.Values{"parent": {cur}, "pageSize": {"500"}}
			if page != "" {
				q.Set("pageToken", page)
			}
			body, err := gcpCRMGet(ctx, token, "/projects", q)
			if err != nil {
				return ids, fmt.Errorf("list projects under %s: %w", cur, err)
			}
			got, next := parseGCPProjectsPage(body)
			for _, id := range got {
				if !seen[id] && len(ids) < gcpMaxProjects {
					seen[id] = true
					ids = append(ids, id)
				}
			}
			if next == "" {
				break
			}
			page = next
		}
		for page := ""; ; {
			q := url.Values{"parent": {cur}, "pageSize": {"500"}}
			if page != "" {
				q.Set("pageToken", page)
			}
			body, err := gcpCRMGet(ctx, token, "/folders", q)
			if err != nil {
				return ids, fmt.Errorf("list folders under %s: %w", cur, err)
			}
			names, next := parseGCPFoldersPage(body)
			queue = append(queue, names...)
			if next == "" {
				break
			}
			page = next
		}
	}
	return ids, nil
}

// resolveGCPProjects returns the projects a connector should sync.
func resolveGCPProjects(ctx context.Context, sa gcpServiceAccount, setting, orgID, folderID string) ([]string, error) {
	explicit := splitGCPProjectList(setting)
	parent := normalizeGCPParent("folders", folderID)
	if parent == "" {
		parent = normalizeGCPParent("organizations", orgID)
	}
	wantDiscovery := strings.TrimSpace(setting) == "*" || (len(explicit) == 0 && parent != "")
	if !wantDiscovery {
		if len(explicit) == 0 {
			if sa.ProjectID == "" {
				return nil, fmt.Errorf("project_id required")
			}
			return []string{sa.ProjectID}, nil
		}
		return explicit, nil
	}
	if parent == "" {
		return nil, fmt.Errorf("project_id \"*\" needs an org_id or folder_id to discover projects")
	}
	tok, err := getGCPTokenWithScope(ctx, sa, "https://www.googleapis.com/auth/cloud-platform.read-only")
	if err != nil {
		return nil, fmt.Errorf("GCP auth (discovery): %w", err)
	}
	ids, err := discoverGCPProjects(ctx, tok, parent)
	if len(ids) == 0 {
		if err == nil {
			err = fmt.Errorf("no active projects under %s", parent)
		}
		return nil, err
	}
	return ids, nil
}

// firstGCPProject returns the first explicitly listed project, used by the
// per-project scanners (CSPM, assets, blast radius, extended logs). "*" and
// empty return "" so callers fall back to the service account's own project.
func firstGCPProject(setting string) string {
	if l := splitGCPProjectList(setting); len(l) > 0 {
		return l[0]
	}
	return ""
}
