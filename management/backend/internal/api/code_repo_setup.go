package api

// code_repo_setup.go - configures a repository for code automation, so nobody
// has to click through the provider's settings:
//
//   - the webhook (push, pull/merge request and comment events) pointing at
//     this server, with the connector's secret;
//   - branch protection on the protected branch: changes only through a
//     pull/merge request, the "ObsidianWatch / code scan" check required, no
//     force push or deletion, administrators included.
//
// Existing settings are merged, not replaced: other required checks, review
// rules and push restrictions stay. Each step reports done, unchanged,
// skipped or failed with the provider's message, so a missing token
// permission is visible.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type setupStep struct {
	Step   string `json:"step"`
	Status string `json:"status"` // done | unchanged | skipped | failed
	Detail string `json:"detail,omitempty"`
}

type setupResult struct {
	Repo      string      `json:"repo"`
	Branch    string      `json:"branch"`
	OK        bool        `json:"ok"`
	Steps     []setupStep `json:"steps"`
	UpdatedAt time.Time   `json:"updated_at"`
}

func (r *setupResult) add(step, status, detail string) {
	r.Steps = append(r.Steps, setupStep{Step: step, Status: status, Detail: truncate(detail, 400)})
}

// webhookURL is where the provider sends events for this connector.
func webhookURL(conn *store.DevOpsConnector) string {
	base := targetURL()
	if base == "" {
		return ""
	}
	switch conn.Provider {
	case "gitlab":
		return fmt.Sprintf("%s/api/v1/devops/webhook-gitlab/%d", base, conn.ID)
	case "azuredevops":
		return fmt.Sprintf("%s/api/v1/devops/webhook-azuredevops/%d", base, conn.ID)
	}
	return fmt.Sprintf("%s/api/v1/devops/webhook/%d", base, conn.ID)
}

func randomSecret() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// permissionHint explains a provider refusal in terms of token rights.
func permissionHint(provider string, err error) string {
	msg := err.Error()
	if !strings.Contains(msg, " 403") && !strings.Contains(msg, " 401") && !strings.Contains(msg, " 404") {
		return msg
	}
	switch provider {
	case "github":
		return msg + " (the token needs the Administration and Webhooks permissions on this repository, write; branch protection on a private repository also needs GitHub Pro, Team or Enterprise)"
	case "gitlab":
		return msg + " (the token needs the api scope and the Maintainer role on this project)"
	case "azuredevops":
		return msg + " (the PAT needs Code (read, write & manage), Service Hooks (read & write) and project administrator rights for branch policies)"
	}
	return msg
}

// setupRepository runs every step for one protected branch and stores the result.
func setupRepository(ctx context.Context, db *store.DB, conn *store.DevOpsConnector, repo, branch string) setupResult {
	res := setupResult{Repo: repo, Branch: branch, UpdatedAt: time.Now().UTC()}
	secret, err := db.EnsureDevOpsWebhookSecret(ctx, conn.ID, randomSecret())
	if err != nil {
		res.add("webhook secret", "failed", err.Error())
	}
	conn.WebhookSecret = secret
	switch conn.Provider {
	case "github":
		githubSetup(ctx, conn, repo, branch, &res)
	case "gitlab":
		gitlabSetup(ctx, conn, repo, branch, &res)
	case "azuredevops":
		adoSetup(ctx, conn, repo, branch, &res)
	default:
		res.add("provider", "failed", "unsupported provider "+conn.Provider)
	}
	res.OK = true
	for _, s := range res.Steps {
		if s.Status == "failed" || (s.Status == "skipped" && strings.HasPrefix(s.Step, "webhook")) {
			res.OK = false
		}
	}
	steps, _ := json.Marshal(res.Steps)
	_, _ = db.ExecContext(ctx, `INSERT INTO code_repo_setup (connector_id, repo, branch, ok, steps, updated_at)
		VALUES ($1,$2,$3,$4,$5,NOW()) ON CONFLICT (connector_id, repo, branch)
		DO UPDATE SET ok=EXCLUDED.ok, steps=EXCLUDED.steps, updated_at=NOW()`, conn.ID, repo, branch, res.OK, steps)
	return res
}

const noPublicURL = "OW_PUBLIC_URL is not set: set it to the address the provider can reach this server at (for example https://siem.example.com), then set up again"

// ── GitHub ────────────────────────────────────────────────────────────────────

var githubAPI = "https://api.github.com"

func ghHeaders(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
}

func githubSetup(ctx context.Context, conn *store.DevOpsConnector, repo, branch string, res *setupResult) {
	h := ghHeaders(conn.Credentials["token"])
	// Webhook.
	if url := webhookURL(conn); url == "" {
		res.add("webhook", "skipped", noPublicURL)
	} else {
		var hooks []struct {
			ID     int64    `json:"id"`
			Events []string `json:"events"`
			Config struct {
				URL string `json:"url"`
			} `json:"config"`
		}
		events := []string{"push", "pull_request", "issue_comment", "pull_request_review_comment"}
		body := map[string]interface{}{"name": "web", "active": true, "events": events,
			"config": map[string]string{"url": url, "content_type": "json", "secret": conn.WebhookSecret, "insecure_ssl": "0"}}
		if err := devopsJSON(ctx, "GET", fmt.Sprintf("%s/repos/%s/hooks?per_page=100", githubAPI, repo), h, nil, &hooks); err != nil {
			res.add("webhook", "failed", permissionHint("github", err))
		} else {
			var id int64
			for _, x := range hooks {
				if x.Config.URL == url {
					id = x.ID
				}
			}
			if id > 0 {
				// Update: the secret and events may have changed.
				if err := devopsJSON(ctx, "PATCH", fmt.Sprintf("%s/repos/%s/hooks/%d", githubAPI, repo, id), h, body, nil); err != nil {
					res.add("webhook", "failed", permissionHint("github", err))
				} else {
					res.add("webhook", "unchanged", "already pointed here; events and secret refreshed")
				}
			} else if err := devopsJSON(ctx, "POST", fmt.Sprintf("%s/repos/%s/hooks", githubAPI, repo), h, body, nil); err != nil {
				res.add("webhook", "failed", permissionHint("github", err))
			} else {
				res.add("webhook", "done", "created for push, pull_request and comment events")
			}
		}
	}
	// Branch protection, merged with what exists.
	purl := fmt.Sprintf("%s/repos/%s/branches/%s/protection", githubAPI, repo, neturl.PathEscape(branch))
	var cur map[string]interface{}
	if err := devopsJSON(ctx, "GET", purl, h, nil, &cur); err != nil && !strings.Contains(err.Error(), " 404") {
		res.add("branch protection", "failed", permissionHint("github", err))
		return
	}
	body := githubProtectionBody(cur)
	if err := devopsJSON(ctx, "PUT", purl, h, body, nil); err != nil {
		res.add("branch protection", "failed", permissionHint("github", err))
		return
	}
	res.add("branch protection", "done", "pull requests required, \""+statusName+"\" required, no force push or deletion, administrators included")
}

// githubProtectionBody builds the PUT body from the current protection (nil
// when there is none), keeping other checks, review rules and restrictions.
func githubProtectionBody(cur map[string]interface{}) map[string]interface{} {
	obj := func(m map[string]interface{}, k string) map[string]interface{} {
		v, _ := m[k].(map[string]interface{})
		return v
	}
	checks := []map[string]interface{}{}
	have := false
	if rsc := obj(cur, "required_status_checks"); rsc != nil {
		if cs, ok := rsc["checks"].([]interface{}); ok && len(cs) > 0 {
			for _, c := range cs {
				cm, _ := c.(map[string]interface{})
				ctxName, _ := cm["context"].(string)
				if ctxName == "" {
					continue
				}
				entry := map[string]interface{}{"context": ctxName}
				if id, ok := cm["app_id"].(float64); ok && id > 0 {
					entry["app_id"] = int64(id)
				}
				checks = append(checks, entry)
				have = have || ctxName == statusName
			}
		} else if cs, ok := rsc["contexts"].([]interface{}); ok {
			for _, c := range cs {
				if s, _ := c.(string); s != "" {
					checks = append(checks, map[string]interface{}{"context": s})
					have = have || s == statusName
				}
			}
		}
	}
	if !have {
		checks = append(checks, map[string]interface{}{"context": statusName})
	}
	strict := false
	if rsc := obj(cur, "required_status_checks"); rsc != nil {
		strict, _ = rsc["strict"].(bool)
	}
	reviews := map[string]interface{}{"required_approving_review_count": 0}
	if pr := obj(cur, "required_pull_request_reviews"); pr != nil {
		for _, k := range []string{"dismiss_stale_reviews", "require_code_owner_reviews", "require_last_push_approval"} {
			if v, ok := pr[k].(bool); ok {
				reviews[k] = v
			}
		}
		if n, ok := pr["required_approving_review_count"].(float64); ok {
			reviews["required_approving_review_count"] = int(n)
		}
	}
	var restrictions interface{}
	if rs := obj(cur, "restrictions"); rs != nil {
		names := func(k, field string) []string {
			out := []string{}
			list, _ := rs[k].([]interface{})
			for _, x := range list {
				xm, _ := x.(map[string]interface{})
				if s, _ := xm[field].(string); s != "" {
					out = append(out, s)
				}
			}
			return out
		}
		restrictions = map[string]interface{}{"users": names("users", "login"), "teams": names("teams", "slug"), "apps": names("apps", "slug")}
	}
	body := map[string]interface{}{
		"required_status_checks":        map[string]interface{}{"strict": strict, "checks": checks},
		"enforce_admins":                true,
		"required_pull_request_reviews": reviews,
		"restrictions":                  restrictions,
		"allow_force_pushes":            false,
		"allow_deletions":               false,
	}
	for _, k := range []string{"required_linear_history", "required_conversation_resolution"} {
		if v := obj(cur, k); v != nil {
			if en, ok := v["enabled"].(bool); ok {
				body[k] = en
			}
		}
	}
	return body
}

// ── GitLab ────────────────────────────────────────────────────────────────────

func gitlabAPIBase(conn *store.DevOpsConnector) string {
	base := strings.TrimRight(conn.Credentials["base_url"], "/")
	if base == "" {
		base = "https://gitlab.com"
	}
	return base + "/api/v4"
}

func gitlabSetup(ctx context.Context, conn *store.DevOpsConnector, repo, branch string, res *setupResult) {
	h := map[string]string{"PRIVATE-TOKEN": conn.Credentials["token"]}
	proj := gitlabAPIBase(conn) + "/projects/" + neturl.PathEscape(repo)
	if url := webhookURL(conn); url == "" {
		res.add("webhook", "skipped", noPublicURL)
	} else {
		var hooks []struct {
			ID  int64  `json:"id"`
			URL string `json:"url"`
		}
		body := map[string]interface{}{"url": url, "token": conn.WebhookSecret, "push_events": true, "merge_requests_events": true,
			"note_events": true, "enable_ssl_verification": true}
		if err := devopsJSON(ctx, "GET", proj+"/hooks?per_page=100", h, nil, &hooks); err != nil {
			res.add("webhook", "failed", permissionHint("gitlab", err))
		} else {
			var id int64
			for _, x := range hooks {
				if x.URL == url {
					id = x.ID
				}
			}
			if id > 0 {
				if err := devopsJSON(ctx, "PUT", fmt.Sprintf("%s/hooks/%d", proj, id), h, body, nil); err != nil {
					res.add("webhook", "failed", permissionHint("gitlab", err))
				} else {
					res.add("webhook", "unchanged", "already pointed here; events and token refreshed")
				}
			} else if err := devopsJSON(ctx, "POST", proj+"/hooks", h, body, nil); err != nil {
				res.add("webhook", "failed", permissionHint("gitlab", err))
			} else {
				res.add("webhook", "done", "created for push, merge request and comment events")
			}
		}
	}
	// Protected branch: nobody pushes, developers and maintainers merge, no force push.
	pb := proj + "/protected_branches/" + neturl.PathEscape(branch)
	var cur struct {
		PushAccessLevels []struct {
			ID          int64 `json:"id"`
			AccessLevel int   `json:"access_level"`
		} `json:"push_access_levels"`
		AllowForcePush bool `json:"allow_force_push"`
	}
	err := devopsJSON(ctx, "GET", pb, h, nil, &cur)
	switch {
	case err != nil && strings.Contains(err.Error(), " 404"):
		q := neturl.Values{"name": {branch}, "push_access_level": {"0"}, "merge_access_level": {"30"}, "allow_force_push": {"false"}}
		if err := devopsJSON(ctx, "POST", proj+"/protected_branches?"+q.Encode(), h, nil, nil); err != nil {
			res.add("protected branch", "failed", permissionHint("gitlab", err))
		} else {
			res.add("protected branch", "done", "protected: no direct pushes (merge requests only), developers can merge, no force push")
		}
	case err != nil:
		res.add("protected branch", "failed", permissionHint("gitlab", err))
	default:
		var changes []map[string]interface{}
		for _, l := range cur.PushAccessLevels {
			if l.AccessLevel != 0 {
				changes = append(changes, map[string]interface{}{"id": l.ID, "_destroy": true})
			}
		}
		if len(changes) == 0 && !cur.AllowForcePush && len(cur.PushAccessLevels) > 0 {
			res.add("protected branch", "unchanged", "already protected with no direct pushes")
			break
		}
		if len(changes) > 0 || len(cur.PushAccessLevels) == 0 {
			changes = append(changes, map[string]interface{}{"access_level": 0})
		}
		if err := devopsJSON(ctx, "PATCH", pb, h, map[string]interface{}{"allow_force_push": false, "allowed_to_push": changes}, nil); err != nil {
			res.add("protected branch", "failed", permissionHint("gitlab", err))
		} else {
			res.add("protected branch", "done", "direct pushes and force pushes removed; merge rules kept")
		}
	}
	if err := devopsJSON(ctx, "PUT", proj, h, map[string]interface{}{"only_allow_merge_if_pipeline_succeeds": true}, nil); err != nil {
		res.add("pipelines must succeed", "failed", permissionHint("gitlab", err))
	} else {
		res.add("pipelines must succeed", "done", "the ObsidianWatch status is part of the pipeline, so a failing check blocks the merge")
	}
}

// ── Azure DevOps ──────────────────────────────────────────────────────────────

const adoStatusPolicyType = "cbdc66da-9728-4af8-aada-9a5a32e4a226"

func adoHeaders(token string) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+token))}
}

func adoSetup(ctx context.Context, conn *store.DevOpsConnector, repo, branch string, res *setupResult) {
	parts := strings.SplitN(repo, "/", 3)
	if len(parts) != 3 {
		res.add("repository", "failed", "expected organisation/project/repository")
		return
	}
	c := adoClientFor(conn)
	h := adoHeaders(conn.Credentials["token"])
	project, name := parts[1], parts[2]
	var p struct {
		ID string `json:"id"`
	}
	var r struct {
		ID string `json:"id"`
	}
	if err := devopsJSON(ctx, "GET", fmt.Sprintf("%s/_apis/projects/%s?api-version=7.1", c.baseURL, neturl.PathEscape(project)), h, nil, &p); err != nil {
		res.add("repository", "failed", permissionHint("azuredevops", err))
		return
	}
	if err := devopsJSON(ctx, "GET", fmt.Sprintf("%s/%s/_apis/git/repositories/%s?api-version=7.1", c.baseURL, neturl.PathEscape(project), neturl.PathEscape(name)), h, nil, &r); err != nil {
		res.add("repository", "failed", permissionHint("azuredevops", err))
		return
	}
	// Service hooks.
	if url := webhookURL(conn); url == "" {
		res.add("webhook", "skipped", noPublicURL)
	} else {
		var subs struct {
			Value []struct {
				EventType       string            `json:"eventType"`
				PublisherInputs map[string]string `json:"publisherInputs"`
				ConsumerInputs  map[string]string `json:"consumerInputs"`
			} `json:"value"`
		}
		if err := devopsJSON(ctx, "GET", c.baseURL+"/_apis/hooks/subscriptions?api-version=7.1", h, nil, &subs); err != nil {
			res.add("webhook", "failed", permissionHint("azuredevops", err))
		} else {
			created, kept := 0, 0
			var firstErr error
			for _, ev := range []string{"git.push", "git.pullrequest.created", "git.pullrequest.updated", "ms.vss-code.git-pullrequest-comment-event"} {
				exists := false
				for _, s := range subs.Value {
					if s.EventType == ev && s.ConsumerInputs["url"] == url && strings.EqualFold(s.PublisherInputs["repository"], r.ID) {
						exists = true
					}
				}
				if exists {
					kept++
					continue
				}
				body := map[string]interface{}{"publisherId": "tfs", "eventType": ev, "resourceVersion": "1.0",
					"consumerId": "webHooks", "consumerActionId": "httpRequest",
					"publisherInputs": map[string]string{"projectId": p.ID, "repository": r.ID},
					"consumerInputs":  map[string]string{"url": url, "basicAuthUsername": "obsidianwatch", "basicAuthPassword": conn.WebhookSecret}}
				if err := devopsJSON(ctx, "POST", c.baseURL+"/_apis/hooks/subscriptions?api-version=7.1", h, body, nil); err != nil && firstErr == nil {
					firstErr = err
				} else if err == nil {
					created++
				}
			}
			switch {
			case firstErr != nil:
				res.add("webhook", "failed", permissionHint("azuredevops", firstErr))
			case created == 0:
				res.add("webhook", "unchanged", "service hooks already point here")
			default:
				res.add("webhook", "done", fmt.Sprintf("%d service hook(s) created (push, pull request, comments)", created))
			}
		}
	}
	// Required status policy: a branch with a required policy accepts changes only through pull requests.
	ref := "refs/heads/" + strings.TrimPrefix(branch, "refs/heads/")
	var pols struct {
		Value []struct {
			Type struct {
				ID string `json:"id"`
			} `json:"type"`
			Settings map[string]interface{} `json:"settings"`
		} `json:"value"`
	}
	base := fmt.Sprintf("%s/%s/_apis/policy/configurations", c.baseURL, neturl.PathEscape(project))
	q := neturl.Values{"repositoryId": {r.ID}, "refName": {ref}, "api-version": {"7.1"}}
	if err := devopsJSON(ctx, "GET", base+"?"+q.Encode(), h, nil, &pols); err != nil {
		res.add("branch policy", "failed", permissionHint("azuredevops", err))
		return
	}
	for _, pl := range pols.Value {
		if pl.Type.ID == adoStatusPolicyType && pl.Settings["statusGenre"] == "obsidianwatch" && pl.Settings["statusName"] == "code-scan" {
			res.add("branch policy", "unchanged", "the ObsidianWatch status is already required")
			return
		}
	}
	body := map[string]interface{}{"isEnabled": true, "isBlocking": true, "type": map[string]string{"id": adoStatusPolicyType},
		"settings": map[string]interface{}{"statusName": "code-scan", "statusGenre": "obsidianwatch", "invalidateOnSourceUpdate": true,
			"scope": []map[string]string{{"repositoryId": r.ID, "refName": ref, "matchKind": "exact"}}}}
	if err := devopsJSON(ctx, "POST", base+"?api-version=7.1", h, body, nil); err != nil {
		res.add("branch policy", "failed", permissionHint("azuredevops", err))
		return
	}
	res.add("branch policy", "done", "the ObsidianWatch status is required; the branch now accepts changes only through pull requests")
}

// ── API ───────────────────────────────────────────────────────────────────────

// handleRepoSetupList: GET /api/v1/devops-connectors/{id}/protected/setup.
func handleRepoSetupList(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		rows, err := db.QueryContext(r.Context(), `SELECT repo, branch, ok, steps, updated_at FROM code_repo_setup WHERE connector_id=$1`, id)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()
		out := []setupResult{}
		for rows.Next() {
			var s setupResult
			var steps []byte
			if rows.Scan(&s.Repo, &s.Branch, &s.OK, &steps, &s.UpdatedAt) == nil {
				_ = json.Unmarshal(steps, &s.Steps)
				out = append(out, s)
			}
		}
		writeJSON(w, 200, map[string]interface{}{"setup": out, "public_url": targetURL()})
	}
}

// handleRepoSetup: POST /api/v1/devops-connectors/{id}/protected/setup {repo, branch} (admin).
// Queues the setup as an automation job.
func handleRepoSetup(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		var body struct {
			Repo   string `json:"repo"`
			Branch string `json:"branch"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
		policy := loadCodeScanPolicy(r.Context(), db, id)
		if _, ok := policy.profileFor(body.Repo, body.Branch); !ok {
			writeJSON(w, 400, map[string]string{"error": "add the branch under Protected branches first"})
			return
		}
		enqueueCodeJob(r.Context(), db, store.CodeScanJob{ConnectorID: id, Kind: "setup", Trigger: "manual",
			Repo: body.Repo, Ref: body.Branch, HeadSHA: "setup:" + time.Now().UTC().Format(time.RFC3339)}, nil)
		writeJSON(w, 202, map[string]bool{"queued": true})
	}
}
