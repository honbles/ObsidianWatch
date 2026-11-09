package api

// DR-02 (first slice): GitHub source-control posture — branch protection,
// secret scanning / push protection and org 2FA. Read-only checks; results
// are returned to the caller (no persistence yet).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type PostureFinding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Resource string `json:"resource"`
	Fix      string `json:"fix"`
}

type ghRepoInfo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	Fork          bool   `json:"fork"`
	DefaultBranch string `json:"default_branch"`
	Security      struct {
		SecretScanning struct {
			Status string `json:"status"`
		} `json:"secret_scanning"`
		PushProtection struct {
			Status string `json:"status"`
		} `json:"secret_scanning_push_protection"`
	} `json:"security_and_analysis"`
}

type ghProtection struct {
	RequiredReviews *struct {
		Count int `json:"required_approving_review_count"`
	} `json:"required_pull_request_reviews"`
	EnforceAdmins struct {
		Enabled bool `json:"enabled"`
	} `json:"enforce_admins"`
	AllowForcePush struct {
		Enabled bool `json:"enabled"`
	} `json:"allow_force_pushes"`
	RequiredStatus *struct{} `json:"required_status_checks"`
}

// postureFromProtection evaluates a branch-protection response. unprotected
// means the API said 404 (no rule).
func postureFromProtection(repo, branch string, p *ghProtection, unprotected bool) []PostureFinding {
	res := repo + "@" + branch
	if unprotected || p == nil {
		return []PostureFinding{{"high", "Default branch is not protected",
			"Anyone with write access can push directly to " + branch + ", bypassing review.", res,
			"Add a branch protection rule or ruleset requiring pull requests and approvals."}}
	}
	var out []PostureFinding
	if p.RequiredReviews == nil || p.RequiredReviews.Count < 1 {
		out = append(out, PostureFinding{"medium", "Pull request approvals not required",
			"Changes can be merged without an approving review.", res, "Require at least one approving review."})
	}
	if p.AllowForcePush.Enabled {
		out = append(out, PostureFinding{"medium", "Force pushes allowed on default branch",
			"History can be rewritten, hiding malicious commits.", res, "Disallow force pushes."})
	}
	if !p.EnforceAdmins.Enabled {
		out = append(out, PostureFinding{"low", "Branch protection not enforced for admins",
			"Repository admins can bypass the rules (including a compromised admin token).", res, "Enable 'Do not allow bypassing the above settings'."})
	}
	return out
}

func postureFromRepo(r ghRepoInfo) []PostureFinding {
	var out []PostureFinding
	if st := r.Security.SecretScanning.Status; st == "disabled" {
		out = append(out, PostureFinding{"medium", "Secret scanning disabled",
			"Committed credentials will not be detected by GitHub.", r.FullName, "Enable secret scanning."})
	}
	if st := r.Security.PushProtection.Status; st == "disabled" {
		out = append(out, PostureFinding{"medium", "Push protection disabled",
			"Secrets can be pushed without being blocked.", r.FullName, "Enable secret scanning push protection."})
	}
	return out
}

const posturMaxRepos = 100

func githubPosture(ctx context.Context, c *githubClient) ([]PostureFinding, int, error) {
	var findings []PostureFinding
	var org struct {
		TwoFactor *bool `json:"two_factor_requirement_enabled"`
	}
	if err := c.getJSON(ctx, "https://api.github.com/orgs/"+c.org, &org); err == nil && org.TwoFactor != nil && !*org.TwoFactor {
		findings = append(findings, PostureFinding{"high", "Organisation does not require two-factor authentication",
			"Members can access the organisation with password-only accounts.", c.org, "Enable 'Require two-factor authentication' in organisation security settings."})
	}
	var repos []ghRepoInfo
	url := fmt.Sprintf("https://api.github.com/orgs/%s/repos?per_page=100&type=all", c.org)
	for pg := 0; url != "" && pg < 2; pg++ {
		var page []ghRepoInfo
		next, err := c.getJSONNext(ctx, url, &page)
		if err != nil {
			if pg == 0 {
				// personal account fallback
				var up []ghRepoInfo
				if _, e2 := c.getJSONNext(ctx, fmt.Sprintf("https://api.github.com/users/%s/repos?per_page=100", c.org), &up); e2 != nil {
					return nil, 0, err
				}
				repos = up
			}
			break
		}
		repos = append(repos, page...)
		url = next
	}
	checked := 0
	for _, r := range repos {
		if r.Archived || r.Fork {
			continue
		}
		if checked >= posturMaxRepos {
			break
		}
		checked++
		findings = append(findings, postureFromRepo(r)...)
		var prot ghProtection
		err := c.getJSON(ctx, fmt.Sprintf("https://api.github.com/repos/%s/branches/%s/protection", r.FullName, r.DefaultBranch), &prot)
		switch {
		case err == nil:
			findings = append(findings, postureFromProtection(r.FullName, r.DefaultBranch, &prot, false)...)
		case strings.HasPrefix(err.Error(), "not found"):
			findings = append(findings, postureFromProtection(r.FullName, r.DefaultBranch, nil, true)...)
		default:
			// auth/plan limitation: cannot assess; do not report a false finding
		}
	}
	return findings, checked, nil
}

func handleDevOpsPosture(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid id")
			return
		}
		conn, err := db.GetDevOpsConnectorRaw(r.Context(), id)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "connector not found")
			return
		}
		token := conn.Credentials["token"]
		if token == "" {
			writeJSONError(w, http.StatusBadRequest, "connector has no token")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		var findings []PostureFinding
		var checked int
		switch conn.Provider {
		case "github":
			findings, checked, err = githubPosture(ctx, &githubClient{token: token, org: conn.Org})
		case "gitlab":
			base := conn.Credentials["base_url"]
			if base == "" {
				base = "https://gitlab.com"
			}
			findings, checked, err = gitlabPosture(ctx, &gitlabClient{token: token, baseURL: base, group: conn.Org})
		case "azuredevops":
			findings, checked, err = azureDevOpsPosture(ctx, newAzureClient(token, conn.Org), conn.Org)
		default:
			writeJSONError(w, http.StatusNotImplemented, "posture checks are implemented for GitHub, GitLab and Azure DevOps")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusBadGateway, conn.Provider+" posture scan failed: "+err.Error())
			return
		}
		out := map[string]interface{}{"findings": findings, "repos_checked": checked, "scanned_at": time.Now().UTC()}
		if b, merr := json.Marshal(out); merr == nil && len(b) < 4<<20 {
			_ = db.SetSetting(r.Context(), postureResultKey(id), string(b)) // DR-02: keep last result
		}
		writeJSON(w, http.StatusOK, out)
	}
}

const postureResultPrefix = "devops.posture.last."

func postureResultKey(id int64) string { return postureResultPrefix + strconv.FormatInt(id, 10) }

// handleGetDevOpsPosture returns the last stored posture result for a connector.
func handleGetDevOpsPosture(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid id")
			return
		}
		v, _ := db.GetSetting(r.Context(), postureResultKey(id))
		if v == "" {
			writeJSONError(w, http.StatusNotFound, "no posture scan has been run yet")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(v))
	}
}

// ── GitLab ───────────────────────────────────────────────────────────────────

type glProtectedBranch struct {
	Name             string `json:"name"`
	AllowForcePush   bool   `json:"allow_force_push"`
	PushAccessLevels []struct {
		AccessLevel int `json:"access_level"`
	} `json:"push_access_levels"`
}

// glPostureFromBranches evaluates a project's protected-branch list against its
// default branch.
func glPostureFromBranches(project, def string, pbs []glProtectedBranch) []PostureFinding {
	res := project + "@" + def
	for _, b := range pbs {
		if b.Name != def && b.Name != "*" {
			continue
		}
		var out []PostureFinding
		for _, l := range b.PushAccessLevels {
			if l.AccessLevel == 30 { // Developers + Maintainers may push directly
				out = append(out, PostureFinding{"medium", "Developers can push directly to the default branch",
					"Protected-branch push access is set to Developers, bypassing merge requests.", res,
					"Set 'Allowed to push' to Maintainers or No one and require merge requests."})
				break
			}
		}
		if b.AllowForcePush {
			out = append(out, PostureFinding{"medium", "Force pushes allowed on default branch",
				"History can be rewritten, hiding malicious commits.", res, "Disable 'Allowed to force push'."})
		}
		return out
	}
	return []PostureFinding{{"high", "Default branch is not protected",
		"Anyone with write access can push directly to " + def + ", bypassing review.", res,
		"Protect the default branch and require merge requests."}}
}

func gitlabPosture(ctx context.Context, c *gitlabClient) ([]PostureFinding, int, error) {
	var findings []PostureFinding
	var grp struct {
		RequireTwoFactor *bool `json:"require_two_factor_authentication"`
	}
	if err := c.getJSON(ctx, "/api/v4/groups/"+c.group, &grp); err == nil && grp.RequireTwoFactor != nil && !*grp.RequireTwoFactor {
		findings = append(findings, PostureFinding{"high", "Group does not require two-factor authentication",
			"Members can access the group with password-only accounts.", c.group,
			"Enable 'Require all users to set up two-factor authentication' in group settings."})
	}
	var projects []struct {
		ID                int    `json:"id"`
		PathWithNamespace string `json:"path_with_namespace"`
		DefaultBranch     string `json:"default_branch"`
		EmptyRepo         bool   `json:"empty_repo"`
	}
	path := fmt.Sprintf("/api/v4/groups/%s/projects?per_page=100&archived=false&include_subgroups=true", c.group)
	if err := c.getJSON(ctx, path, &projects); err != nil {
		return nil, 0, err
	}
	checked := 0
	for _, p := range projects {
		if p.EmptyRepo || p.DefaultBranch == "" {
			continue
		}
		if checked >= posturMaxRepos {
			break
		}
		checked++
		var pbs []glProtectedBranch
		if err := c.getJSON(ctx, fmt.Sprintf("/api/v4/projects/%d/protected_branches", p.ID), &pbs); err != nil {
			continue // cannot assess (permissions); no false finding
		}
		findings = append(findings, glPostureFromBranches(p.PathWithNamespace, p.DefaultBranch, pbs)...)
	}
	return findings, checked, nil
}

// ── Azure DevOps ─────────────────────────────────────────────────────────────

const adoMinReviewersPolicy = "fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"

type adoPolicy struct {
	IsEnabled  bool `json:"isEnabled"`
	IsBlocking bool `json:"isBlocking"`
	Type       struct {
		ID string `json:"id"`
	} `json:"type"`
	Settings struct {
		MinimumApproverCount int `json:"minimumApproverCount"`
		Scope                []struct {
			RepositoryID *string `json:"repositoryId"`
			RefName      string  `json:"refName"`
			MatchKind    string  `json:"matchKind"`
		} `json:"scope"`
	} `json:"settings"`
}

// adoDefaultBranchReviewed reports whether an enabled, blocking minimum-reviewer
// policy covers the repository's default branch.
func adoDefaultBranchReviewed(repoID, defaultBranch string, policies []adoPolicy) bool {
	for _, p := range policies {
		if !p.IsEnabled || !p.IsBlocking || p.Type.ID != adoMinReviewersPolicy || p.Settings.MinimumApproverCount < 1 {
			continue
		}
		for _, sc := range p.Settings.Scope {
			if sc.RepositoryID != nil && !strings.EqualFold(*sc.RepositoryID, repoID) {
				continue
			}
			switch strings.ToLower(sc.MatchKind) {
			case "prefix":
				if strings.HasPrefix(defaultBranch, sc.RefName) {
					return true
				}
			default:
				if sc.RefName == defaultBranch {
					return true
				}
			}
		}
	}
	return false
}

func azureDevOpsPosture(ctx context.Context, c *azureClient, org string) ([]PostureFinding, int, error) {
	var projects struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	if err := c.getJSON(ctx, fmt.Sprintf("https://dev.azure.com/%s/_apis/projects?api-version=7.0", org), &projects); err != nil {
		return nil, 0, err
	}
	var findings []PostureFinding
	checked := 0
	for _, pr := range projects.Value {
		var repos struct {
			Value []struct {
				ID            string `json:"id"`
				Name          string `json:"name"`
				DefaultBranch string `json:"defaultBranch"`
				IsDisabled    bool   `json:"isDisabled"`
			} `json:"value"`
		}
		if err := c.getJSON(ctx, fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/git/repositories?api-version=7.0", org, pr.Name), &repos); err != nil {
			continue
		}
		var pols struct {
			Value []adoPolicy `json:"value"`
		}
		if err := c.getJSON(ctx, fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/policy/configurations?api-version=7.0", org, pr.Name), &pols); err != nil {
			continue // cannot assess this project
		}
		for _, r := range repos.Value {
			if r.IsDisabled || r.DefaultBranch == "" || checked >= posturMaxRepos {
				continue
			}
			checked++
			if !adoDefaultBranchReviewed(r.ID, r.DefaultBranch, pols.Value) {
				findings = append(findings, PostureFinding{"high", "Default branch has no required-reviewer policy",
					"No enabled, blocking minimum-reviewer branch policy covers " + r.DefaultBranch + ", so changes can merge without review.",
					fmt.Sprintf("%s/%s/%s@%s", org, pr.Name, r.Name, strings.TrimPrefix(r.DefaultBranch, "refs/heads/")),
					"Add a Minimum number of reviewers branch policy (blocking) on the default branch."})
			}
		}
	}
	return findings, checked, nil
}
