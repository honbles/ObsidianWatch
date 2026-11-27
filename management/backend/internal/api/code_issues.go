package api

// code_issues.go - "Create issues" for SAST findings.
//
// One click turns a repository's findings into issues on its platform
// (GitHub Issues, GitLab Issues, Azure DevOps "Bug" work items):
//
//   - Grouped: one issue per problem per repository - per rule for code and
//     secrets (listing every location), per package version for dependencies
//     (listing its vulnerabilities) - not one issue per finding.
//   - Filtered: at or above a minimum severity (default high); findings
//     dismissed by triage are left out.
//   - Remembered, not synchronised: ObsidianWatch records which findings each
//     issue covers. Clicking again creates issues only for new problems and
//     adds new locations of known problems as a comment on the existing
//     issue. Whether an issue is open or closed is not tracked.
//   - Public repositories are skipped: an issue there would publish the
//     vulnerability before it is fixed. Secret values are never included.
//   - Preview first (dry_run), then create; at most 50 new issues per click.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"obsidianwatch/management/internal/store"
)

const maxIssuesPerClick = 50

type issueGroup struct {
	Key      string        `json:"key"`
	Title    string        `json:"title"`
	Severity string        `json:"severity"`
	Findings []SASTFinding `json:"-"`
	Count    int           `json:"findings"`
	Existing string        `json:"existing_issue,omitempty"` // URL when an issue already exists
	New      int           `json:"new_findings"`             // findings not yet in that issue
}

// issueGroupKey: dependencies by package version, everything else by rule.
func issueGroupKey(f SASTFinding) (key, title string) {
	if f.Package != "" {
		return "pkg:" + f.Ecosystem + ":" + strings.ToLower(f.Package) + "@" + f.Version,
			fmt.Sprintf("Vulnerable dependency: %s %s", f.Package, f.Version)
	}
	t := f.Title
	if strings.HasPrefix(f.RuleID, "SECRET-") {
		t = strings.TrimPrefix(t, "Secret in repository history: ")
		t = "Secret in repository: " + t
	}
	return "rule:" + f.RuleID, t
}

func groupFindings(fs []SASTFinding, minSev string) []*issueGroup {
	by := map[string]*issueGroup{}
	var order []string
	for _, f := range fs {
		if findingDismissed(f) || sevRank(strings.ToLower(f.Severity)) < sevRank(minSev) {
			continue
		}
		k, t := issueGroupKey(f)
		g := by[k]
		if g == nil {
			g = &issueGroup{Key: k, Title: truncate(t, 200), Severity: strings.ToLower(f.Severity)}
			by[k] = g
			order = append(order, k)
		}
		if sevRank(strings.ToLower(f.Severity)) > sevRank(g.Severity) {
			g.Severity = strings.ToLower(f.Severity)
		}
		g.Findings = append(g.Findings, f)
	}
	out := make([]*issueGroup, 0, len(order))
	for _, k := range order {
		g := by[k]
		g.Count = len(g.Findings)
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool { return sevRank(out[i].Severity) > sevRank(out[j].Severity) })
	return out
}

// fileLink is a link to the file and line on the platform.
func fileLink(conn *store.DevOpsConnector, repo, branch, file string, line int) string {
	if file == "" {
		return ""
	}
	if branch == "" || branch == "HEAD" {
		branch = "HEAD"
	}
	switch conn.Provider {
	case "github":
		u := fmt.Sprintf("https://github.com/%s/blob/%s/%s", repo, neturl.PathEscape(branch), file)
		if line > 0 {
			u += fmt.Sprintf("#L%d", line)
		}
		return u
	case "gitlab":
		base := strings.TrimRight(conn.Credentials["base_url"], "/")
		if base == "" {
			base = "https://gitlab.com"
		}
		u := fmt.Sprintf("%s/%s/-/blob/%s/%s", base, repo, neturl.PathEscape(branch), file)
		if line > 0 {
			u += fmt.Sprintf("#L%d", line)
		}
		return u
	case "azuredevops":
		parts := strings.SplitN(repo, "/", 3)
		if len(parts) != 3 {
			return ""
		}
		u := fmt.Sprintf("%s/%s/_git/%s?path=/%s", adoClientFor(conn).baseURL, neturl.PathEscape(parts[1]), neturl.PathEscape(parts[2]), neturl.QueryEscape(file))
		if branch != "HEAD" {
			u += "&version=GB" + neturl.QueryEscape(branch)
		}
		if line > 0 {
			u += fmt.Sprintf("&line=%d&lineEnd=%d&lineStartColumn=1&lineEndColumn=200", line, line)
		}
		return u
	}
	return ""
}

func locationLines(conn *store.DevOpsConnector, repo, branch string, fs []SASTFinding) string {
	var b strings.Builder
	for i, f := range fs {
		if i == 100 {
			fmt.Fprintf(&b, "- … and %d more (see ObsidianWatch)\n", len(fs)-100)
			break
		}
		where := f.File
		if f.Line > 0 {
			where = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		if link := fileLink(conn, repo, branch, f.File, f.Line); link != "" {
			fmt.Fprintf(&b, "- [ ] [`%s`](%s)", where, link)
		} else {
			fmt.Fprintf(&b, "- [ ] `%s`", where)
		}
		if f.Package != "" {
			fmt.Fprintf(&b, " — **%s** %s (%s)", strings.TrimPrefix(f.RuleID, "SCA-"), strings.ToUpper(f.Severity), truncate(f.Title, 120))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// issueBody renders a group as Markdown. Secrets: no snippet, masked detail only.
func issueBody(conn *store.DevOpsConnector, repo, branch string, g *issueGroup) string {
	f := g.Findings[0]
	var b strings.Builder
	fmt.Fprintf(&b, "**Severity:** %s · **Repository:** `%s` · **Branch:** `%s`\n\n", strings.ToUpper(g.Severity), repo, branchLabel(branch))
	if f.Package == "" && f.Detail != "" {
		b.WriteString(truncate(f.Detail, 1500) + "\n\n")
	}
	if f.CWE != "" || f.OWASP != "" {
		fmt.Fprintf(&b, "%s %s\n\n", f.CWE, f.OWASP)
	}
	if r := f.Reachability; r != nil && r.Level == "loaded" {
		fmt.Fprintf(&b, "> **Running now:** this version is loaded by %s.\n\n", strings.Join(append(append([]string{}, r.Services...), r.Hosts...), ", "))
	}
	if f.Fix != "" {
		b.WriteString("### How to fix\n\n" + truncate(f.Fix, 1500) + "\n\n")
	}
	if strings.HasPrefix(f.RuleID, "SECRET-") {
		b.WriteString("Rotate the credential at its issuer first; deleting it from the code does not invalidate it.\n\n")
	}
	if f.Package != "" {
		b.WriteString("### Vulnerabilities\n\n")
	} else {
		fmt.Fprintf(&b, "### Locations (%d)\n\n", len(g.Findings))
	}
	b.WriteString(locationLines(conn, repo, branch, g.Findings))
	fmt.Fprintf(&b, "\n<sub>Created by ObsidianWatch from a code scan (rule `%s`, %s). ObsidianWatch shows whether each location is still present; this issue is not updated when it is fixed.</sub>\n", f.RuleID, f.Engine)
	return b.String()
}

func branchLabel(b string) string {
	if b == "" || b == "HEAD" {
		return "default"
	}
	return b
}

// ── Provider calls ────────────────────────────────────────────────────────────

// repoIsPublic reports the repository's visibility; unknown counts as public
// (the safe answer, since an issue there would disclose the finding).
func repoIsPublic(ctx context.Context, conn *store.DevOpsConnector, repo string) (bool, error) {
	token := conn.Credentials["token"]
	switch conn.Provider {
	case "github":
		var r struct {
			Private    bool   `json:"private"`
			Visibility string `json:"visibility"`
		}
		err := devopsJSON(ctx, "GET", "https://api.github.com/repos/"+repo, map[string]string{"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"}, nil, &r)
		return err != nil || (!r.Private && r.Visibility != "internal"), err
	case "gitlab":
		var r struct {
			Visibility string `json:"visibility"`
		}
		err := devopsJSON(ctx, "GET", gitlabBase(conn)+"/api/v4/projects/"+gitlabID(repo), map[string]string{"PRIVATE-TOKEN": token}, nil, &r)
		return err != nil || r.Visibility == "public" || r.Visibility == "", err
	case "azuredevops":
		parts := strings.SplitN(repo, "/", 3)
		if len(parts) != 3 {
			return true, fmt.Errorf("bad repository %q", repo)
		}
		var r struct {
			Visibility string `json:"visibility"`
		}
		err := devopsJSON(ctx, "GET", fmt.Sprintf("%s/_apis/projects/%s?api-version=7.0", adoClientFor(conn).baseURL, neturl.PathEscape(parts[1])),
			map[string]string{"Authorization": adoBasic(token)}, nil, &r)
		return err != nil || strings.EqualFold(r.Visibility, "public"), err
	}
	return true, fmt.Errorf("unknown provider")
}

func gitlabBase(conn *store.DevOpsConnector) string {
	if b := strings.TrimRight(conn.Credentials["base_url"], "/"); b != "" {
		return b
	}
	return "https://gitlab.com"
}

func adoBasic(token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+token))
}

// createIssue opens an issue and returns its reference and URL.
func createIssue(ctx context.Context, conn *store.DevOpsConnector, repo, title, body, severity string) (ref, url string, err error) {
	token := conn.Credentials["token"]
	labels := []string{"security", "obsidianwatch", "severity:" + severity}
	switch conn.Provider {
	case "github":
		var r struct {
			Number  int    `json:"number"`
			HTMLURL string `json:"html_url"`
		}
		err = devopsJSON(ctx, "POST", "https://api.github.com/repos/"+repo+"/issues",
			map[string]string{"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"},
			map[string]interface{}{"title": title, "body": body, "labels": labels}, &r)
		return strconv.Itoa(r.Number), r.HTMLURL, err
	case "gitlab":
		var r struct {
			IID    int    `json:"iid"`
			WebURL string `json:"web_url"`
		}
		err = devopsJSON(ctx, "POST", gitlabBase(conn)+"/api/v4/projects/"+gitlabID(repo)+"/issues",
			map[string]string{"PRIVATE-TOKEN": token},
			map[string]interface{}{"title": title, "description": body, "labels": strings.Join(labels, ","), "confidential": true}, &r)
		return strconv.Itoa(r.IID), r.WebURL, err
	case "azuredevops":
		parts := strings.SplitN(repo, "/", 3)
		if len(parts) != 3 {
			return "", "", fmt.Errorf("bad repository %q", repo)
		}
		var r struct {
			ID    int `json:"id"`
			Links struct {
				HTML struct {
					Href string `json:"href"`
				} `json:"html"`
			} `json:"_links"`
		}
		patch := []map[string]interface{}{
			{"op": "add", "path": "/fields/System.Title", "value": title},
			{"op": "add", "path": "/fields/Microsoft.VSTS.TCM.ReproSteps", "value": markdownToADOHTML(body)},
			{"op": "add", "path": "/fields/System.Tags", "value": strings.Join(labels, "; ")},
		}
		err = devopsJSON(ctx, "POST", fmt.Sprintf("%s/%s/_apis/wit/workitems/$Bug?api-version=7.1", adoClientFor(conn).baseURL, neturl.PathEscape(parts[1])),
			map[string]string{"Authorization": adoBasic(token), "Content-Type": "application/json-patch+json"}, patch, &r)
		return strconv.Itoa(r.ID), r.Links.HTML.Href, err
	}
	return "", "", fmt.Errorf("unknown provider")
}

// commentIssue adds new locations to an existing issue.
func commentIssue(ctx context.Context, conn *store.DevOpsConnector, repo, ref, body string) error {
	token := conn.Credentials["token"]
	switch conn.Provider {
	case "github":
		return devopsJSON(ctx, "POST", "https://api.github.com/repos/"+repo+"/issues/"+ref+"/comments",
			map[string]string{"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"}, map[string]string{"body": body}, nil)
	case "gitlab":
		return devopsJSON(ctx, "POST", gitlabBase(conn)+"/api/v4/projects/"+gitlabID(repo)+"/issues/"+ref+"/notes",
			map[string]string{"PRIVATE-TOKEN": token}, map[string]string{"body": body}, nil)
	case "azuredevops":
		parts := strings.SplitN(repo, "/", 3)
		if len(parts) != 3 {
			return fmt.Errorf("bad repository %q", repo)
		}
		return devopsJSON(ctx, "POST", fmt.Sprintf("%s/%s/_apis/wit/workItems/%s/comments?api-version=7.1-preview.4", adoClientFor(conn).baseURL, neturl.PathEscape(parts[1]), ref),
			map[string]string{"Authorization": adoBasic(token)}, map[string]string{"text": markdownToADOHTML(body)}, nil)
	}
	return fmt.Errorf("unknown provider")
}

// markdownToADOHTML: Azure DevOps fields are HTML; keep it readable.
func markdownToADOHTML(md string) string {
	var b strings.Builder
	for _, line := range strings.Split(md, "\n") {
		b.WriteString(html.EscapeString(line) + "<br/>")
	}
	return b.String()
}

// ── Handler ───────────────────────────────────────────────────────────────────

type issueRecord struct {
	ref, url string
	fps      map[string]bool
}

func loadIssueRecords(ctx context.Context, db *store.DB, connID int64, repo string) map[string]*issueRecord {
	out := map[string]*issueRecord{}
	rows, err := db.QueryContext(ctx, `SELECT group_key, issue_ref, issue_url, fingerprints FROM code_finding_issues WHERE connector_id=$1 AND repo=$2`, connID, repo)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k, ref, url string
		var raw []byte
		if rows.Scan(&k, &ref, &url, &raw) != nil {
			continue
		}
		var list []string
		_ = json.Unmarshal(raw, &list)
		rec := &issueRecord{ref: ref, url: url, fps: map[string]bool{}}
		for _, f := range list {
			rec.fps[f] = true
		}
		out[k] = rec
	}
	return out
}

// issueLinksByFingerprint: fingerprint -> issue URL, to show on findings.
func issueLinksByFingerprint(ctx context.Context, db *store.DB, connID int64) map[string]string {
	out := map[string]string{}
	rows, err := db.QueryContext(ctx, `SELECT repo, issue_url, fingerprints FROM code_finding_issues WHERE connector_id=$1`, connID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var repo, url string
		var raw []byte
		if rows.Scan(&repo, &url, &raw) != nil {
			continue
		}
		var list []string
		_ = json.Unmarshal(raw, &list)
		for _, f := range list {
			out[repo+"\x00"+f] = url
		}
	}
	return out
}

// handleCreateIssues: POST /api/v1/devops-connectors/{id}/sast/issues
// {repo, branch, min_severity, dry_run}.
func handleCreateIssues(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		var body struct {
			Repo        string `json:"repo"`
			Branch      string `json:"branch"`
			MinSeverity string `json:"min_severity"`
			DryRun      bool   `json:"dry_run"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body) != nil || body.Repo == "" {
			writeJSON(w, 400, map[string]string{"error": "repo is required (issues are created per repository)"})
			return
		}
		if sevRank(body.MinSeverity) == 0 {
			body.MinSeverity = "high"
		}
		conn, err := db.GetDevOpsConnectorRaw(r.Context(), connID)
		if err != nil || conn == nil {
			writeJSON(w, 404, map[string]string{"error": "connector not found"})
			return
		}
		// One run per repository at a time: two clicks (or two users) would both see "no issue yet" for a group
		// and create it twice on the code platform.
		unlock := lockIssueRepo(connID, body.Repo)
		defer unlock()
		// The latest stored result of that repository and branch.
		var raw []byte
		var branch string
		q := `SELECT findings, COALESCE(branch,'') FROM sast_results WHERE connector_id=$1 AND repo=$2`
		args := []interface{}{connID, body.Repo}
		if body.Branch != "" {
			q += ` AND (branch=$3 OR ($3='HEAD' AND branch=''))`
			args = append(args, body.Branch)
		} else {
			q += ` AND branch NOT LIKE '@%'`
		}
		if err := db.QueryRowContext(r.Context(), q+` ORDER BY scanned_at DESC LIMIT 1`, args...).Scan(&raw, &branch); err != nil {
			writeJSON(w, 404, map[string]string{"error": "no scan result for this repository and branch; run a SAST scan first"})
			return
		}
		var findings []SASTFinding
		_ = json.Unmarshal(raw, &findings)
		findings = enrichFindings(r.Context(), db, connID, findings)
		groups := groupFindings(findings, body.MinSeverity)
		records := loadIssueRecords(r.Context(), db, connID, body.Repo)
		newIssues, comments := 0, 0
		for _, g := range groups {
			rec := records[g.Key]
			for _, f := range g.Findings {
				if rec == nil || !rec.fps[f.Fingerprint] {
					g.New++
				}
			}
			if rec != nil {
				g.Existing = rec.url
				if g.New > 0 {
					comments++
				}
			} else {
				newIssues++
			}
		}
		public, visErr := repoIsPublic(r.Context(), conn, body.Repo)
		plan := map[string]interface{}{"repo": body.Repo, "branch": branchLabel(branch), "min_severity": body.MinSeverity,
			"groups": groups, "new_issues": newIssues, "comments": comments, "public_repo": public,
			"limit": maxIssuesPerClick}
		if public {
			reason := "the repository is public: an issue would disclose the vulnerability before it is fixed"
			if visErr != nil {
				reason = "the repository's visibility could not be read (" + visErr.Error() + "), so it is treated as public"
			}
			plan["blocked"] = reason
		}
		if body.DryRun || public {
			writeJSON(w, 200, plan)
			return
		}

		user := claimsUsername(r)
		var created, updated []map[string]string
		var failed []string
		for _, g := range groups {
			if g.New == 0 {
				continue
			}
			rec := records[g.Key]
			var fps []string
			for _, f := range g.Findings {
				fps = append(fps, f.Fingerprint)
			}
			if rec == nil {
				if len(created) >= maxIssuesPerClick {
					continue
				}
				ref, url, err := createIssue(r.Context(), conn, body.Repo, "[Security] "+g.Title, issueBody(conn, body.Repo, branch, g), g.Severity)
				if err != nil {
					failed = append(failed, g.Title+": "+err.Error())
					if len(failed) >= 3 && len(created) == 0 {
						break // permissions problem; stop early
					}
					continue
				}
				b, _ := json.Marshal(fps)
				_, _ = db.ExecContext(r.Context(), `INSERT INTO code_finding_issues (connector_id, repo, group_key, issue_ref, issue_url, fingerprints, created_by)
					VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (connector_id, repo, group_key) DO NOTHING`, connID, body.Repo, g.Key, ref, url, b, user)
				created = append(created, map[string]string{"title": g.Title, "url": url})
				continue
			}
			var fresh []SASTFinding
			for _, f := range g.Findings {
				if !rec.fps[f.Fingerprint] {
					fresh = append(fresh, f)
				}
			}
			text := fmt.Sprintf("ObsidianWatch found %d new location(s) of this problem (branch `%s`):\n\n%s", len(fresh), branchLabel(branch), locationLines(conn, body.Repo, branch, fresh))
			if err := commentIssue(r.Context(), conn, body.Repo, rec.ref, text); err != nil {
				failed = append(failed, g.Title+": "+err.Error())
				continue
			}
			for _, f := range fresh {
				rec.fps[f.Fingerprint] = true
			}
			all := make([]string, 0, len(rec.fps))
			for f := range rec.fps {
				all = append(all, f)
			}
			b, _ := json.Marshal(all)
			_, _ = db.ExecContext(r.Context(), `UPDATE code_finding_issues SET fingerprints=$4, updated_at=NOW() WHERE connector_id=$1 AND repo=$2 AND group_key=$3`, connID, body.Repo, g.Key, b)
			updated = append(updated, map[string]string{"title": g.Title, "url": rec.url})
		}
		plan["created"], plan["updated"], plan["failed"] = created, updated, failed
		if newIssues > maxIssuesPerClick {
			plan["note"] = fmt.Sprintf("%d issues were created; click again for the remaining %d", len(created), newIssues-len(created))
		}
		writeJSON(w, 200, plan)
	}
}

var issueRepoLocks sync.Map // "connector/repo" -> *sync.Mutex

func lockIssueRepo(connID int64, repo string) func() {
	m, _ := issueRepoLocks.LoadOrStore(fmt.Sprintf("%d/%s", connID, repo), &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
