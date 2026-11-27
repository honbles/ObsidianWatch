package api

// code_reporters.go - sending PR check results back to the provider, and
// turning provider webhooks into scan jobs.
//
//   GitHub:  commit status (context "ObsidianWatch / code scan"), a PR review
//            with inline comments on the changed lines, an issue comment for
//            the summary.
//   GitLab:  commit status (name "ObsidianWatch code scan"; external statuses
//            are part of the pipeline, so "Pipelines must succeed" blocks the
//            merge), MR discussions on the changed lines, an MR note.
//   Azure DevOps: PR status (genre "obsidianwatch", name "code-scan"; a
//            "Status check" branch policy blocks the merge), PR threads.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"obsidianwatch/management/internal/store"
)

// devopsJSON sends one JSON request through the guarded provider client.
func devopsJSON(ctx context.Context, method, url string, headers map[string]string, body, out interface{}) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers { // may override the content type
		req.Header.Set(k, v)
	}
	resp, err := devopsHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("%s %d: %s", method, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// prInline is one comment on a changed line.
type prInline struct {
	Path string
	Line int
	Body string
}

type prReporter interface {
	// SetStatus: pending | success | failure | error
	SetStatus(ctx context.Context, state, description string) error
	Comment(ctx context.Context, body string) error
	Inline(ctx context.Context, comments []prInline, summary string) error
}

const statusName = "ObsidianWatch / code scan"

func newPRReporter(conn *store.DevOpsConnector, job *store.CodeScanJob) prReporter {
	if job.HeadSHA == "" || conn.Credentials["token"] == "" {
		return nil
	}
	switch conn.Provider {
	case "github":
		return &githubPR{token: conn.Credentials["token"], repo: job.Repo, pr: job.Ref, sha: job.HeadSHA}
	case "gitlab":
		base := strings.TrimRight(conn.Credentials["base_url"], "/")
		if base == "" {
			base = "https://gitlab.com"
		}
		return &gitlabPR{token: conn.Credentials["token"], base: base, project: neturl.PathEscape(job.Repo), mr: job.Ref, sha: job.HeadSHA}
	case "azuredevops":
		parts := strings.SplitN(job.Repo, "/", 3)
		if len(parts) != 3 {
			return nil
		}
		return &adoPR{client: adoClientFor(conn), project: parts[1], repo: parts[2], pr: job.Ref}
	}
	return nil
}

func targetURL() string { return strings.TrimRight(os.Getenv("OW_PUBLIC_URL"), "/") }

// ── GitHub ────────────────────────────────────────────────────────────────────

type githubPR struct{ token, repo, pr, sha string }

func (g *githubPR) h() map[string]string {
	return map[string]string{"Authorization": "Bearer " + g.token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
}

func (g *githubPR) SetStatus(ctx context.Context, state, desc string) error {
	body := map[string]string{"state": state, "context": statusName, "description": truncate(desc, 140)}
	if u := targetURL(); u != "" {
		body["target_url"] = u + "/devops"
	}
	return devopsJSON(ctx, "POST", fmt.Sprintf("https://api.github.com/repos/%s/statuses/%s", g.repo, g.sha), g.h(), body, nil)
}

func (g *githubPR) Comment(ctx context.Context, body string) error {
	return devopsJSON(ctx, "POST", fmt.Sprintf("https://api.github.com/repos/%s/issues/%s/comments", g.repo, g.pr), g.h(),
		map[string]string{"body": body}, nil)
}

func (g *githubPR) Inline(ctx context.Context, cs []prInline, summary string) error {
	comments := make([]map[string]interface{}, 0, len(cs))
	for _, c := range cs {
		comments = append(comments, map[string]interface{}{"path": c.Path, "line": c.Line, "side": "RIGHT", "body": c.Body})
	}
	return devopsJSON(ctx, "POST", fmt.Sprintf("https://api.github.com/repos/%s/pulls/%s/reviews", g.repo, g.pr), g.h(),
		map[string]interface{}{"commit_id": g.sha, "event": "COMMENT", "body": summary, "comments": comments}, nil)
}

// ── GitLab ────────────────────────────────────────────────────────────────────

type gitlabPR struct{ token, base, project, mr, sha string }

func (g *gitlabPR) h() map[string]string { return map[string]string{"PRIVATE-TOKEN": g.token} }

func (g *gitlabPR) SetStatus(ctx context.Context, state, desc string) error {
	st := map[string]string{"pending": "running", "success": "success", "failure": "failed", "error": "failed"}[state]
	q := neturl.Values{"state": {st}, "name": {"ObsidianWatch code scan"}, "description": {truncate(desc, 255)}}
	if u := targetURL(); u != "" {
		q.Set("target_url", u+"/devops")
	}
	return devopsJSON(ctx, "POST", fmt.Sprintf("%s/api/v4/projects/%s/statuses/%s?%s", g.base, g.project, g.sha, q.Encode()), g.h(), nil, nil)
}

func (g *gitlabPR) Comment(ctx context.Context, body string) error {
	return devopsJSON(ctx, "POST", fmt.Sprintf("%s/api/v4/projects/%s/merge_requests/%s/notes", g.base, g.project, g.mr), g.h(),
		map[string]string{"body": body}, nil)
}

func (g *gitlabPR) Inline(ctx context.Context, cs []prInline, summary string) error {
	var mr struct {
		DiffRefs struct {
			BaseSHA  string `json:"base_sha"`
			HeadSHA  string `json:"head_sha"`
			StartSHA string `json:"start_sha"`
		} `json:"diff_refs"`
	}
	if err := devopsJSON(ctx, "GET", fmt.Sprintf("%s/api/v4/projects/%s/merge_requests/%s", g.base, g.project, g.mr), g.h(), nil, &mr); err != nil {
		return err
	}
	if err := g.Comment(ctx, summary); err != nil {
		return err
	}
	var firstErr error
	for _, c := range cs {
		err := devopsJSON(ctx, "POST", fmt.Sprintf("%s/api/v4/projects/%s/merge_requests/%s/discussions", g.base, g.project, g.mr), g.h(),
			map[string]interface{}{"body": c.Body, "position": map[string]interface{}{
				"position_type": "text", "base_sha": mr.DiffRefs.BaseSHA, "head_sha": mr.DiffRefs.HeadSHA, "start_sha": mr.DiffRefs.StartSHA,
				"new_path": c.Path, "old_path": c.Path, "new_line": c.Line,
			}}, nil)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ── Azure DevOps ──────────────────────────────────────────────────────────────

type adoPR struct {
	client            *azureClient
	project, repo, pr string
}

func (a *adoPR) h() map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+a.client.token))}
}

func (a *adoPR) url(suffix string) string {
	return fmt.Sprintf("%s/%s/_apis/git/repositories/%s/pullRequests/%s/%s", a.client.baseURL,
		neturl.PathEscape(a.project), neturl.PathEscape(a.repo), a.pr, suffix)
}

func (a *adoPR) SetStatus(ctx context.Context, state, desc string) error {
	st := map[string]string{"pending": "pending", "success": "succeeded", "failure": "failed", "error": "error"}[state]
	body := map[string]interface{}{"state": st, "description": truncate(desc, 250),
		"context": map[string]string{"name": "code-scan", "genre": "obsidianwatch"}}
	if u := targetURL(); u != "" {
		body["targetUrl"] = u + "/devops"
	}
	return devopsJSON(ctx, "POST", a.url("statuses?api-version=7.1-preview.1"), a.h(), body, nil)
}

func (a *adoPR) thread(ctx context.Context, body string, path string, line int) error {
	t := map[string]interface{}{
		"comments": []map[string]interface{}{{"parentCommentId": 0, "content": body, "commentType": 1}},
		"status":   "active",
	}
	if path != "" {
		t["threadContext"] = map[string]interface{}{"filePath": "/" + strings.TrimPrefix(path, "/"),
			"rightFileStart": map[string]int{"line": line, "offset": 1}, "rightFileEnd": map[string]int{"line": line, "offset": 1}}
	}
	return devopsJSON(ctx, "POST", a.url("threads?api-version=7.1"), a.h(), t, nil)
}

func (a *adoPR) Comment(ctx context.Context, body string) error { return a.thread(ctx, body, "", 0) }

func (a *adoPR) Inline(ctx context.Context, cs []prInline, summary string) error {
	if err := a.Comment(ctx, summary); err != nil {
		return err
	}
	var firstErr error
	for _, c := range cs {
		if err := a.thread(ctx, c.Body, c.Path, c.Line); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ── What to post ──────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func sevLabel(s string) string { return strings.ToUpper(s) }

func findingComment(f SASTFinding, provider string, fix *fixSuggestion) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**%s · %s**\n\n", sevLabel(f.Severity), f.Title)
	if f.Detail != "" {
		b.WriteString(truncate(f.Detail, 1200) + "\n\n")
	}
	if f.Fix != "" {
		b.WriteString("**Fix:** " + truncate(f.Fix, 600) + "\n\n")
	}
	if r := f.Reachability; r != nil && (r.Level == "loaded" || r.Level == "deployed") {
		// Counts only: a pull request (and its comments) can be public, and service and host names describe
		// internal infrastructure. The names are on the finding page in the console.
		var where []string
		if n := len(r.Services); n > 0 {
			where = append(where, plural(n, "service"))
		}
		if n := len(r.Hosts); n > 0 {
			where = append(where, plural(n, "host"))
		}
		suffix := ""
		if len(where) > 0 {
			suffix = " (" + strings.Join(where, ", ") + ")"
		}
		fmt.Fprintf(&b, "**Runtime:** this version is %s now%s.\n\n", map[string]string{"loaded": "loaded by a running process", "deployed": "installed for a running process"}[r.Level], suffix)
	}
	b.WriteString(fixBlock(f, provider, fix))
	meta := []string{"rule `" + f.RuleID + "`", f.Engine}
	if f.CWE != "" {
		meta = append(meta, f.CWE)
	}
	b.WriteString("<sub>ObsidianWatch · " + strings.Join(meta, " · ") + "</sub>")
	return b.String()
}

func prSummary(policy codeScanPolicy, findings []SASTFinding, blocked bool, unposted []SASTFinding) string {
	c := countBySeverity(findings)
	var b strings.Builder
	b.WriteString(botMarker + "\n### ObsidianWatch code scan\n\n")
	switch {
	case len(findings) == 0:
		b.WriteString("No new issues in the lines and files this change touches. ✅\n")
	case blocked:
		fmt.Fprintf(&b, "**Failing:** this change adds issues at or above **%s**.\n\n", policy.BlockOn)
	default:
		b.WriteString("New issues found; none at the blocking level.\n\n")
	}
	if len(findings) > 0 {
		fmt.Fprintf(&b, "| Critical | High | Medium | Low |\n|---|---|---|---|\n| %d | %d | %d | %d |\n\n",
			c["critical"], c["high"], c["medium"], c["low"])
	}
	if len(unposted) > 0 {
		b.WriteString("Not shown inline (file-level, or above the comment limit):\n\n")
		for i, f := range unposted {
			if i == 30 {
				fmt.Fprintf(&b, "- … and %d more\n", len(unposted)-30)
				break
			}
			where := f.File
			if f.Line > 0 {
				where = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			fmt.Fprintf(&b, "- **%s** %s — `%s`\n", sevLabel(f.Severity), truncate(f.Title, 120), where)
		}
	}
	if len(findings) > 0 && policy.agentHint {
		fmt.Fprintf(&b, "\nReply `@%s apply` to have ObsidianWatch commit fixes to this branch, or mention `@%s` with a question.\n", botName, botName)
	}
	return b.String()
}

// reportPR posts the status and, when enabled, comments. Inline comments are
// posted once per finding (tracked in code_pr_checks); the summary is posted
// when the outcome changes or new findings appear.
func reportPR(ctx context.Context, db *store.DB, rep prReporter, conn *store.DevOpsConnector, job *store.CodeScanJob,
	policy codeScanPolicy, findings []SASTFinding, blocked bool, public bool, dir string, fixer func(SASTFinding) *fixSuggestion) []string {
	var done []string
	state, desc := "success", "No new issues"
	if len(findings) > 0 {
		desc = fmt.Sprintf("%d new issue(s)", len(findings))
	}
	if blocked {
		state = "failure"
		desc += fmt.Sprintf("; blocking at %s or above", policy.BlockOn)
	}
	if err := rep.SetStatus(ctx, state, desc); err != nil {
		done = append(done, "status failed: "+err.Error())
	} else {
		done = append(done, "status "+state)
	}
	if !policy.PRComments {
		return done
	}
	st := db.GetPRCheckState(ctx, conn.ID, job.Repo, job.Ref)
	if public {
		// A public repository's pull request is readable by anyone: say how many issues and how severe, never
		// what or where (that would tell the world how to exploit them before they are fixed). The details are
		// in the console. Posted when the outcome or the count changes.
		sig := fmt.Sprintf("%s:%d", state, len(findings))
		if st.LastState != sig {
			if err := rep.Comment(ctx, publicPRSummary(policy, findings, blocked)); err != nil {
				done = append(done, "comments failed: "+err.Error())
			} else {
				done = append(done, "summary only (public repository)")
			}
		}
		st.LastSHA, st.LastState = job.HeadSHA, sig
		_ = db.SavePRCheckState(ctx, conn.ID, job.Repo, job.Ref, st)
		return done
	}
	sort.SliceStable(findings, func(i, j int) bool { return sevRank(findings[i].Severity) > sevRank(findings[j].Severity) })
	var inline []prInline
	var unposted []SASTFinding
	newOnes, fixes := 0, 0
	for _, f := range findings {
		key := findingKey(f, dir)
		if st.Commented[key] {
			continue
		}
		newOnes++
		if f.Line > 0 && len(inline) < policy.MaxComments {
			var fix *fixSuggestion
			if fixer != nil && fixes < maxPRFixes {
				if fix = fixer(f); fix != nil {
					fixes++
				}
			}
			inline = append(inline, prInline{Path: f.File, Line: f.Line, Body: findingComment(f, conn.Provider, fix)})
			st.Commented[key] = true
			continue
		}
		unposted = append(unposted, f)
		st.Commented[key] = true
	}
	if newOnes > 0 || st.LastState != state {
		_, policy.agentHint = policy.profileFor(job.Repo, job.BaseBranch)
		summary := prSummary(policy, findings, blocked, unposted)
		var err error
		if len(inline) > 0 {
			err = rep.Inline(ctx, inline, summary)
			if err != nil {
				// A comment on a line the provider does not consider part of the
				// diff fails the whole review on GitHub: post the list instead.
				all := append(append([]SASTFinding{}, unposted...), findingsFromInline(findings, inline)...)
				err = rep.Comment(ctx, prSummary(policy, findings, blocked, all))
			}
		} else {
			err = rep.Comment(ctx, summary)
		}
		if err != nil {
			done = append(done, "comments failed: "+err.Error())
		} else {
			done = append(done, fmt.Sprintf("summary + %d inline comment(s)", len(inline)))
		}
	}
	st.LastSHA, st.LastState = job.HeadSHA, state
	_ = db.SavePRCheckState(ctx, conn.ID, job.Repo, job.Ref, st)
	return done
}

func findingsFromInline(all []SASTFinding, inline []prInline) []SASTFinding {
	want := map[string]bool{}
	for _, c := range inline {
		want[fmt.Sprintf("%s:%d", c.Path, c.Line)] = true
	}
	var out []SASTFinding
	for _, f := range all {
		if want[fmt.Sprintf("%s:%d", f.File, f.Line)] {
			out = append(out, f)
		}
	}
	return out
}

// ── Webhook triggers ──────────────────────────────────────────────────────────

func boolAt(m map[string]interface{}, path ...string) bool {
	var cur interface{} = m
	for _, p := range path {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return false
		}
		cur = mm[p]
	}
	b, _ := cur.(bool)
	return b
}

func str(m map[string]interface{}, path ...string) string {
	var cur interface{} = m
	for _, p := range path {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	switch v := cur.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	}
	return ""
}

// githubCodeTriggers queues scans for GitHub pull_request and push webhooks.
func githubCodeTriggers(ctx context.Context, db *store.DB, conn *store.DevOpsConnector, event string, p map[string]interface{}, logger *slog.Logger) {
	policy := loadCodeScanPolicy(ctx, db, conn.ID)
	switch event {
	case "pull_request":
		action := str(p, "action")
		if !policy.prScanned(str(p, "repository", "full_name"), str(p, "pull_request", "base", "ref")) || (action != "opened" && action != "synchronize" && action != "reopened" && action != "ready_for_review") {
			return
		}
		if boolAt(p, "pull_request", "draft") {
			return
		}
		enqueueCodeJob(ctx, db, store.CodeScanJob{ConnectorID: conn.ID, Kind: "pr", Trigger: "pr",
			Repo: str(p, "repository", "full_name"), Ref: str(p, "number"),
			BaseBranch: str(p, "pull_request", "base", "ref"), HeadRef: str(p, "pull_request", "head", "ref"),
			HeadSHA: str(p, "pull_request", "head", "sha")}, logger)
	case "issue_comment", "pull_request_review_comment":
		if str(p, "action") != "created" {
			return
		}
		body := str(p, "comment", "body")
		assoc := str(p, "comment", "author_association")
		if !mentionsBot(body) || str(p, "comment", "user", "type") == "Bot" ||
			(assoc != "OWNER" && assoc != "MEMBER" && assoc != "COLLABORATOR") {
			return
		}
		pr := str(p, "pull_request", "number")
		if event == "issue_comment" {
			issue, _ := p["issue"].(map[string]interface{})
			if _, isPR := issue["pull_request"]; !isPR {
				return
			}
			pr = str(p, "issue", "number")
		}
		queueAgentJob(ctx, db, conn, str(p, "repository", "full_name"), pr,
			agentPayload{CommentID: str(p, "comment", "id"), Body: body, Author: str(p, "comment", "user", "login")}, logger)
	case "push":
		if !policy.ScanOnPush {
			return
		}
		if deleted, _ := p["deleted"].(bool); deleted {
			return
		}
		repo, ref := str(p, "repository", "full_name"), str(p, "ref")
		if b, ok := policy.pushScanBranch(repo, ref, str(p, "repository", "default_branch")); ok {
			enqueueCodeJob(ctx, db, store.CodeScanJob{ConnectorID: conn.ID, Kind: "branch", Trigger: "push",
				Repo: repo, Ref: b, HeadSHA: str(p, "after")}, logger)
		}
	}
}

// gitlabCodeTriggers handles merge_request and push webhooks.
func gitlabCodeTriggers(ctx context.Context, db *store.DB, conn *store.DevOpsConnector, p map[string]interface{}, logger *slog.Logger) {
	policy := loadCodeScanPolicy(ctx, db, conn.ID)
	kind := str(p, "object_kind")
	switch kind {
	case "merge_request":
		action := str(p, "object_attributes", "action")
		newCommits := action == "update" && str(p, "object_attributes", "oldrev") != ""
		if !policy.prScanned(str(p, "project", "path_with_namespace"), str(p, "object_attributes", "target_branch")) || !(action == "open" || action == "reopen" || newCommits) {
			return
		}
		if boolAt(p, "object_attributes", "draft") {
			return
		}
		enqueueCodeJob(ctx, db, store.CodeScanJob{ConnectorID: conn.ID, Kind: "pr", Trigger: "pr",
			Repo: str(p, "project", "path_with_namespace"), Ref: str(p, "object_attributes", "iid"),
			BaseBranch: str(p, "object_attributes", "target_branch"), HeadRef: str(p, "object_attributes", "source_branch"),
			HeadSHA: str(p, "object_attributes", "last_commit", "id")}, logger)
	case "note":
		body := str(p, "object_attributes", "note")
		if str(p, "object_attributes", "noteable_type") != "MergeRequest" || !mentionsBot(body) {
			return
		}
		queueAgentJob(ctx, db, conn, str(p, "project", "path_with_namespace"), str(p, "merge_request", "iid"),
			agentPayload{CommentID: str(p, "object_attributes", "id"), Body: body, Author: str(p, "user", "username"), AuthorID: str(p, "user", "id")}, logger)
	case "push":
		if !policy.ScanOnPush || str(p, "after") == gitlabZeroSHA {
			return
		}
		repo, ref := str(p, "project", "path_with_namespace"), str(p, "ref")
		if b, ok := policy.pushScanBranch(repo, ref, str(p, "project", "default_branch")); ok {
			enqueueCodeJob(ctx, db, store.CodeScanJob{ConnectorID: conn.ID, Kind: "branch", Trigger: "push",
				Repo: repo, Ref: b, HeadSHA: str(p, "after")}, logger)
		}
	}
}

// adoCodeTriggers handles git.pullrequest.created/updated and git.push.
func adoCodeTriggers(ctx context.Context, db *store.DB, conn *store.DevOpsConnector, p map[string]interface{}, logger *slog.Logger) {
	policy := loadCodeScanPolicy(ctx, db, conn.ID)
	res, _ := p["resource"].(map[string]interface{})
	if str(p, "eventType") == "ms.vss-code.git-pullrequest-comment-event" {
		body := str(res, "comment", "content")
		proj, name := str(res, "pullRequest", "repository", "project", "name"), str(res, "pullRequest", "repository", "name")
		if mentionsBot(body) && proj != "" && name != "" {
			queueAgentJob(ctx, db, conn, conn.Org+"/"+proj+"/"+name, str(res, "pullRequest", "pullRequestId"),
				agentPayload{CommentID: str(res, "comment", "id") + "-" + str(res, "comment", "lastUpdatedDate"), Body: body,
					Author: str(res, "comment", "author", "displayName")}, logger)
		}
		return
	}
	project := str(res, "repository", "project", "name")
	repoName := str(res, "repository", "name")
	if project == "" || repoName == "" {
		return
	}
	repo := conn.Org + "/" + project + "/" + repoName
	switch str(p, "eventType") {
	case "git.pullrequest.created", "git.pullrequest.updated":
		if !policy.prScanned(repo, strings.TrimPrefix(str(res, "targetRefName"), "refs/heads/")) || str(res, "status") != "active" {
			return
		}
		if draft, _ := res["isDraft"].(bool); draft {
			return
		}
		enqueueCodeJob(ctx, db, store.CodeScanJob{ConnectorID: conn.ID, Kind: "pr", Trigger: "pr",
			Repo: repo, Ref: str(res, "pullRequestId"),
			BaseBranch: strings.TrimPrefix(str(res, "targetRefName"), "refs/heads/"), HeadRef: str(res, "sourceRefName"),
			HeadSHA: str(res, "lastMergeSourceCommit", "commitId")}, logger)
	case "git.push":
		if !policy.ScanOnPush {
			return
		}
		def := strings.TrimPrefix(str(res, "repository", "defaultBranch"), "refs/heads/")
		updates, _ := res["refUpdates"].([]interface{})
		for _, u := range updates {
			ru, _ := u.(map[string]interface{})
			if str(ru, "newObjectId") == adoZeroSHA {
				continue
			}
			if b, ok := policy.pushScanBranch(repo, str(ru, "name"), def); ok {
				enqueueCodeJob(ctx, db, store.CodeScanJob{ConnectorID: conn.ID, Kind: "branch", Trigger: "push",
					Repo: repo, Ref: b, HeadSHA: str(ru, "newObjectId")}, logger)
			}
		}
	}
}

// maxPRFixes bounds AI calls per PR update.
const maxPRFixes = 5

// fixBlock renders a fix suggestion in a PR comment. A one-line replacement
// of the commented line becomes a one-click suggestion on GitHub and GitLab;
// anything else is shown as a diff to apply by hand.
func fixBlock(f SASTFinding, provider string, fix *fixSuggestion) string {
	if fix == nil {
		return ""
	}
	var b strings.Builder
	if fix.LikelyFalsePos {
		b.WriteString("**AI review:** this may be a false positive. " + truncate(fix.FalsePosReason, 500) + "\n\n")
	}
	switch {
	case fix.Kind == "dependency" && fix.Command != "":
		b.WriteString("**Suggested fix:** `" + fix.Command + "`\n\n")
	case fix.Diff != "" && fix.StartLine == f.Line && fix.EndLine == f.Line && (provider == "github" || provider == "gitlab"):
		fence := "```suggestion"
		if provider == "gitlab" {
			fence = "```suggestion:-0+0"
		}
		b.WriteString("**Suggested fix** (AI, confidence " + strconv.Itoa(fix.Confidence) + "%; review before applying):\n\n" + fence + "\n" + strings.TrimSuffix(fix.Replacement, "\n") + "\n```\n\n")
	case fix.Diff != "":
		b.WriteString("**Suggested fix** (AI, confidence " + strconv.Itoa(fix.Confidence) + "%; review before applying):\n\n```diff\n" + truncate(fix.Diff, 3000) + "```\n\n")
		if fix.Explanation != "" {
			b.WriteString(truncate(fix.Explanation, 600) + "\n\n")
		}
	}
	return b.String()
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// publicPRSummary is the pull-request comment for a public repository: counts and the outcome only.
func publicPRSummary(policy codeScanPolicy, findings []SASTFinding, blocked bool) string {
	c := countBySeverity(findings)
	var b strings.Builder
	b.WriteString(botMarker + "\n### ObsidianWatch code scan\n\n")
	switch {
	case len(findings) == 0:
		b.WriteString("No new issues in the lines and files this change touches. ✅\n")
	case blocked:
		fmt.Fprintf(&b, "**Failing:** this change adds issues at or above **%s**.\n\n", policy.BlockOn)
	default:
		b.WriteString("New issues found; none at the blocking level.\n\n")
	}
	if len(findings) > 0 {
		fmt.Fprintf(&b, "| Critical | High | Medium | Low |\n|---|---|---|---|\n| %d | %d | %d | %d |\n\n",
			c["critical"], c["high"], c["medium"], c["low"])
		b.WriteString("This repository is public, so the details are not posted here. ")
		if u := targetURL(); u != "" {
			b.WriteString("Maintainers can see them in [ObsidianWatch](" + u + "/devops).\n")
		} else {
			b.WriteString("Maintainers can see them in ObsidianWatch.\n")
		}
	}
	return b.String()
}
