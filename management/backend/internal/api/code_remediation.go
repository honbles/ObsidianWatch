package api

// code_remediation.go - fix pull requests and @obsidianwatch replies.
//
// Fix pull requests ("fix" jobs): a result from two or more engines is
// correlated first (if it is not already). When a scheduled or manual scan of a
// protected branch with "Open fix pull requests" on has findings that no open
// fix PR covers, the agent groups them by kind (dependency upgrades, one PR
// per weakness family), writes the changes on a new branch and opens a pull
// request into the protected branch. It never merges. At most 10 of its PRs
// are open per branch; findings in a fix PR closed without merging are not
// retried for 30 days. Public repositories get no fix PRs (they would
// disclose the vulnerabilities).
//
// Mentions ("agent" jobs): a comment with @obsidianwatch on a pull request
// into a protected branch, or on one of the agent's fix PRs, from someone
// with write access:
//   - on a fix PR: the agent answers and, when the comment reports a problem
//     with its change, pushes a revised fix to that PR's branch;
//   - "@obsidianwatch apply" on a developer's PR: the agent fixes the PR
//     check's findings and commits to the PR branch (not for forks);
//   - otherwise: the agent answers the question.

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
)

const (
	maxOpenFixPRs      = 10
	maxFindingsPerFix  = 15
	agentFileBudget    = 150 << 10
	maxAgentJobsPerDay = 30
)

type fixGroup struct {
	Key      string
	Title    string
	Findings []SASTFinding
}

var familyTitle = map[string]string{
	"injection": "Fix injection flaws", "xss": "Fix cross-site scripting", "path-traversal": "Fix path traversal",
	"ssrf": "Fix server-side request forgery", "deserialization": "Fix unsafe deserialization", "crypto": "Fix weak cryptography",
	"access-control": "Fix access control", "authentication": "Fix authentication flaws", "open-redirect": "Fix open redirects",
	"xxe": "Fix XML external entities", "csrf": "Fix missing CSRF protection",
}

// groupForFix groups fixable findings by kind; secrets and licences are left
// out (a secret needs rotating, not a code change).
func groupForFix(fs []SASTFinding) (groups []fixGroup, skipped map[string]int) {
	skipped = map[string]int{}
	by := map[string]*fixGroup{}
	var order []string
	for _, f := range fs {
		var key, title string
		eng := findingEngineID(f)
		switch {
		case strings.HasPrefix(f.RuleID, "SECRET-") || eng == engSecrets:
			skipped["secret (rotate it; a code change does not remove it from history)"]++
			continue
		case strings.HasPrefix(f.RuleID, "LICENSE-"):
			skipped["licence"]++
			continue
		case eng == engDependencies && f.Package != "":
			key, title = "dependencies", "Upgrade vulnerable dependencies"
		case strings.HasPrefix(f.RuleID, "IAC") || (eng == engDependencies && f.Package == ""):
			key, title = "iac", "Fix infrastructure-as-code misconfigurations"
		case strings.HasPrefix(f.RuleID, "BL-"):
			cat := strings.ToLower(strings.TrimPrefix(f.RuleID, "BL-"))
			key, title = "bl-"+cat, "Fix business-logic flaws: "+strings.ReplaceAll(cat, "-", " ")
		default:
			fam := cweFamily(f.CWE)
			if fam == "" {
				fam = "rule-" + strings.ToLower(f.RuleID)
			}
			key = fam
			if t, ok := familyTitle[fam]; ok {
				title = t
			} else {
				title = "Fix " + strings.TrimSpace(truncateRunes(f.Title, 60))
			}
		}
		g, ok := by[key]
		if !ok {
			g = &fixGroup{Key: key, Title: title}
			by[key] = g
			order = append(order, key)
		}
		g.Findings = append(g.Findings, f)
	}
	for _, k := range order {
		g := by[k]
		sort.SliceStable(g.Findings, func(i, j int) bool {
			return sevRank(strings.ToLower(g.Findings[i].Severity)) > sevRank(strings.ToLower(g.Findings[j].Severity))
		})
		groups = append(groups, *g)
	}
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := sevRank(strings.ToLower(groups[i].Findings[0].Severity)), sevRank(strings.ToLower(groups[j].Findings[0].Severity))
		if a != b {
			return a > b
		}
		return len(groups[i].Findings) > len(groups[j].Findings)
	})
	return groups, skipped
}

var manifestNames = []string{"package.json", "requirements.txt", "pyproject.toml", "Pipfile", "go.mod", "pom.xml", "build.gradle",
	"build.gradle.kts", "Gemfile", "composer.json", "Cargo.toml"}

// fixFiles lists the files the agent sees for a group: each finding's file,
// and for dependency findings the manifests next to it.
func fixFiles(dir string, g fixGroup) []string {
	seen := map[string]bool{}
	var out []string
	add := func(rel string) {
		if rel != "" && !seen[rel] {
			if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel))); err == nil {
				seen[rel] = true
				out = append(out, rel)
			}
		}
	}
	for _, f := range g.Findings {
		if g.Key == "dependencies" {
			d := path.Dir(f.File)
			if d == "." {
				d = ""
			}
			for _, m := range manifestNames {
				add(path.Join(d, m))
			}
			if matches, _ := filepath.Glob(filepath.Join(dir, filepath.FromSlash(d), "*.csproj")); len(matches) > 0 {
				for _, m := range matches {
					rel, _ := filepath.Rel(dir, m)
					add(filepath.ToSlash(rel))
				}
			}
			if !lockfileNames[path.Base(f.File)] {
				add(f.File)
			}
			continue
		}
		add(f.File)
	}
	return out
}

type fixFindingRef struct {
	ID       string `json:"id"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	EndLine  int    `json:"end_line,omitempty"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
	Package  string `json:"package,omitempty"`
	Version  string `json:"version,omitempty"`
	CWE      string `json:"cwe,omitempty"`
	Engine   string `json:"engine,omitempty"`
}

func fixRefs(fs []SASTFinding) []fixFindingRef {
	out := make([]fixFindingRef, 0, len(fs))
	for _, f := range fs {
		fp := f.Fingerprint
		if fp == "" {
			fp = findingFingerprint(f)
		}
		id := fp
		if len(id) > 10 {
			id = id[:10]
		}
		out = append(out, fixFindingRef{ID: id, RuleID: f.RuleID, Severity: f.Severity, File: f.File, Line: f.Line, EndLine: f.EndLine,
			Title: truncateRunes(f.Title, 160), Detail: truncateRunes(f.Detail, 500), Fix: truncateRunes(f.Fix, 300),
			Package: f.Package, Version: f.Version, CWE: f.CWE, Engine: f.Engine})
	}
	return out
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func fixBranchName(key string, fps []string) string {
	h := sha1.Sum([]byte(strings.Join(fps, ",")))
	slug := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(key), "-"), "-")
	if len(slug) > 40 {
		slug = slug[:40]
	}
	return fmt.Sprintf("obsidianwatch/fix-%s-%s-%s", slug, time.Now().UTC().Format("20060102"), hex.EncodeToString(h[:3]))
}

func fixPRBody(g fixGroup, branch, model string, ans agentAnswer, refused []string, changed []string) string {
	var b strings.Builder
	b.WriteString(botMarker + "\n")
	fmt.Fprintf(&b, "## %s\n\n", g.Title)
	fmt.Fprintf(&b, "Opened by ObsidianWatch's remediation agent (`%s`) for findings on `%s`. **It is never merged automatically:** review it, run your tests and merge it yourself.\n\n", model, branch)
	b.WriteString("| Severity | Finding | Location |\n|---|---|---|\n")
	for _, f := range g.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		if f.Package != "" {
			loc = fmt.Sprintf("%s %s (%s)", f.Package, f.Version, f.File)
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` |\n", strings.ToUpper(f.Severity), strings.ReplaceAll(f.Title, "|", "/"), strings.ReplaceAll(loc, "|", "/"))
	}
	if s := strings.TrimSpace(ans.Summary); s != "" {
		b.WriteString("\n### What changed\n" + s + "\n")
	}
	fmt.Fprintf(&b, "\nFiles: %s\n", "`"+strings.Join(changed, "`, `")+"`")
	if t := strings.TrimSpace(ans.Testing); t != "" {
		b.WriteString("\n### How to test\n" + t + "\n")
	}
	if len(ans.Skipped) > 0 || len(refused) > 0 {
		b.WriteString("\n### Not fixed here\n")
		for _, s := range ans.Skipped {
			fmt.Fprintf(&b, "- `%s`: %s\n", s.ID, s.Reason)
		}
		for _, r := range refused {
			fmt.Fprintf(&b, "- edit refused: %s\n", r)
		}
	}
	fmt.Fprintf(&b, "\nMention `@%s` in a comment to ask about this change or report a problem; it answers here and can push a revised fix to this branch.\n", botName)
	return b.String()
}

// refreshFixPRs updates the state of a branch's open fix PRs.
func refreshFixPRs(ctx context.Context, db *store.DB, conn *store.DevOpsConnector, repo, branch string) {
	rows, err := db.QueryContext(ctx, `SELECT id, number FROM code_fix_prs WHERE connector_id=$1 AND repo=$2 AND base_branch=$3 AND status='open' AND number <> ''`,
		conn.ID, repo, branch)
	if err != nil {
		return
	}
	type pr struct {
		id  int64
		num string
	}
	var list []pr
	for rows.Next() {
		var p pr
		if rows.Scan(&p.id, &p.num) == nil {
			list = append(list, p)
		}
	}
	rows.Close()
	for _, p := range list {
		if info, err := getPR(ctx, conn, repo, p.num); err == nil && info.State != "open" {
			_, _ = db.ExecContext(ctx, `UPDATE code_fix_prs SET status=$2, updated_at=NOW() WHERE id=$1`, p.id, info.State)
		}
	}
}

// coveredFingerprints are findings an open fix PR covers, or that a fix PR
// closed without merging covered in the last 30 days.
func coveredFingerprints(ctx context.Context, db *store.DB, connID int64, repo, branch string) (map[string]bool, int) {
	out := map[string]bool{}
	open := 0
	rows, err := db.QueryContext(ctx, `SELECT status, fingerprints FROM code_fix_prs WHERE connector_id=$1 AND repo=$2 AND base_branch=$3
		AND (status='open' OR (status='closed' AND updated_at > NOW() - INTERVAL '30 days'))`, connID, repo, branch)
	if err != nil {
		return out, 0
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var fj []byte
		if rows.Scan(&st, &fj) != nil {
			continue
		}
		if st == "open" {
			open++
		}
		var fps []string
		_ = json.Unmarshal(fj, &fps)
		for _, f := range fps {
			out[f] = true
		}
	}
	return out, open
}

// queueFixJob queues remediation of a protected branch.
func queueFixJob(ctx context.Context, db *store.DB, connID int64, repo, branch, trigger string, logger *slog.Logger) {
	enqueueCodeJob(ctx, db, store.CodeScanJob{ConnectorID: connID, Kind: "fix", Trigger: trigger, Repo: repo, Ref: branch,
		HeadSHA: "fix:" + time.Now().UTC().Format(time.RFC3339)}, logger)
}

func runFixJob(ctx context.Context, cfg *config.Config, db *store.DB, conn *store.DevOpsConnector, job *store.CodeScanJob, logger *slog.Logger) (codeJobResult, error) {
	res := codeJobResult{Engines: engineReport{}}
	policy := loadCodeScanPolicy(ctx, db, conn.ID)
	prof, ok := policy.profileFor(job.Repo, job.Ref)
	if !ok {
		return res, fmt.Errorf("%s %s is not a protected branch", job.Repo, job.Ref)
	}
	if public, _ := repoIsPublic(ctx, conn, job.Repo); public && prof.PublicAck == nil {
		res.Notes = append(res.Notes, `public repository (or visibility unknown): waiting for an admin to confirm with "proceed" in Automation; fix pull requests would disclose the vulnerabilities`)
		return res, nil
	}
	if err := businessLogicReady(ctx, cfg, db); err != nil {
		return res, err
	}
	// Fix PRs are always built from correlated findings when two or more
	// engines ran, whatever the profile's Correlate option says: raw
	// multi-engine findings would give duplicate PRs on the same code and
	// no false-positive verdicts.
	{
		var corr []byte
		var ej []byte
		if db.QueryRowContext(ctx, `SELECT correlation, COALESCE(engines,'{}'::jsonb) FROM sast_results WHERE connector_id=$1 AND repo=$2 AND branch=$3`,
			conn.ID, job.Repo, job.Ref).Scan(&corr, &ej) == nil && len(corr) == 0 {
			var eng engineReport
			_ = json.Unmarshal(ej, &eng)
			if correlationAllowed(eng) {
				if _, err := correlateStored(ctx, cfg, db, conn.ID, job.Repo, job.Ref, true); err != nil {
					res.Notes = append(res.Notes, "correlation before fixing: "+err.Error())
				}
			}
		}
	}
	refreshFixPRs(ctx, db, conn, job.Repo, job.Ref)
	covered, open := coveredFingerprints(ctx, db, conn.ID, job.Repo, job.Ref)
	slots := maxOpenFixPRs - open
	if slots <= 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d fix pull requests are already open for this branch; none opened", open))
		return res, nil
	}
	var fj []byte
	if err := db.QueryRowContext(ctx, `SELECT findings FROM sast_results WHERE connector_id=$1 AND repo=$2 AND branch=$3`,
		conn.ID, job.Repo, job.Ref).Scan(&fj); err != nil {
		return res, fmt.Errorf("no stored SAST result for %s %s", job.Repo, job.Ref)
	}
	var all []SASTFinding
	_ = json.Unmarshal(fj, &all)
	all, hidden := withoutDismissed(enrichFindings(ctx, db, conn.ID, all))
	var todo []SASTFinding
	for _, f := range all {
		switch {
		case f.TestCode, covered[f.Fingerprint], !policy.fixes(f.Severity):
		case f.Correlation != nil && f.Correlation.Verdict == "false_positive":
		default:
			todo = append(todo, f)
		}
	}
	if hidden > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d dismissed finding(s) left out", hidden))
	}
	groups, skipped := groupForFix(todo)
	for why, n := range skipped {
		res.Notes = append(res.Notes, fmt.Sprintf("%d %s finding(s) not fixed by a pull request", n, why))
	}
	if len(groups) == 0 {
		res.Notes = append(res.Notes, "no new findings to fix")
		return res, nil
	}
	if len(groups) > slots {
		res.Notes = append(res.Notes, fmt.Sprintf("%d more group(s) wait for open fix pull requests to close", len(groups)-slots))
		groups = groups[:slots]
	}

	tmp, err := os.MkdirTemp("", fmt.Sprintf("codefix-%d-", job.ID))
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	dir := filepath.Join(tmp, "repo")
	if err := cloneRepo(ctx, conn, job.Repo, job.Ref, dir, 1); err != nil {
		return res, err
	}
	base := gitHeadSHA(ctx, dir)
	for _, g := range groups {
		if len(g.Findings) > maxFindingsPerFix {
			g.Findings = g.Findings[:maxFindingsPerFix]
		}
		if _, err := gitIn(ctx, dir, "", "checkout", "-q", "-f", "--detach", base); err != nil {
			return res, err
		}
		_, _ = gitIn(ctx, dir, "", "clean", "-fdq")
		rels := fixFiles(dir, g)
		files, left := agentFiles(dir, rels, agentFileBudget)
		if len(files) == 0 {
			res.Notes = append(res.Notes, g.Title+": the files could not be read")
			continue
		}
		refs, _ := json.Marshal(fixRefs(g.Findings))
		task := fmt.Sprintf("Fix these findings on branch %q of %s. Group: %s.\n\nFindings:\n%s", job.Ref, job.Repo, g.Title, fenceUntrusted("findings", string(refs)))
		if len(left) > 0 {
			task += fmt.Sprintf("\n\n%d more file(s) are not shown; list their findings in skipped.", len(left))
		}
		ans, model, err := askAgent(ctx, cfg, db, task, files, 16000)
		if err != nil {
			res.Notes = append(res.Notes, g.Title+": "+err.Error())
			continue
		}
		allowed, findingFiles := map[string]bool{}, map[string]bool{}
		for f := range files {
			allowed[f] = true
		}
		var fps []string
		for _, f := range g.Findings {
			findingFiles[f.File] = true
			fps = append(fps, f.Fingerprint)
		}
		changed, refused := applyEdits(dir, ans.Edits, allowed, findingFiles)
		if len(changed) == 0 {
			res.Notes = append(res.Notes, g.Title+": no change made"+refusedNote(refused, ans))
			continue
		}
		head := fixBranchName(g.Key, fps)
		if _, err := gitIn(ctx, dir, "", "checkout", "-q", "-b", head); err != nil {
			return res, err
		}
		if _, err := commitAndPush(ctx, conn, job.Repo, dir, head, "ObsidianWatch: "+g.Title); err != nil {
			res.Notes = append(res.Notes, g.Title+": "+err.Error())
			continue
		}
		pr, err := createPR(ctx, conn, job.Repo, head, job.Ref, "ObsidianWatch: "+g.Title, fixPRBody(g, job.Ref, model, ans, refused, changed))
		if err != nil {
			res.Notes = append(res.Notes, g.Title+": branch "+head+" pushed, pull request failed: "+err.Error())
			continue
		}
		fpj, _ := json.Marshal(fps)
		fj, _ := json.Marshal(fixRefs(g.Findings))
		_, _ = db.ExecContext(ctx, `INSERT INTO code_fix_prs (connector_id, repo, base_branch, head_branch, number, url, group_key, title, fingerprints, findings, model)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, conn.ID, job.Repo, job.Ref, head, pr.Number, pr.URL, g.Key, g.Title, fpj, fj, model)
		res.Reported = append(res.Reported, fmt.Sprintf("fix PR #%s (%s, %d finding(s)): %s", pr.Number, g.Title, len(g.Findings), pr.URL))
		res.Findings = append(res.Findings, g.Findings...)
	}
	res.Counts = countBySeverity(res.Findings)
	return res, nil
}

func refusedNote(refused []string, ans agentAnswer) string {
	var parts []string
	for _, s := range ans.Skipped {
		parts = append(parts, s.Reason)
	}
	parts = append(parts, refused...)
	if len(parts) == 0 {
		return ""
	}
	return " (" + truncate(strings.Join(parts, "; "), 400) + ")"
}

// ── Mentions ──────────────────────────────────────────────────────────────────

type agentPayload struct {
	CommentID string `json:"comment_id"`
	Body      string `json:"body"`
	Author    string `json:"author"`
	AuthorID  string `json:"author_id,omitempty"`
}

var mentionRe = regexp.MustCompile(`(?i)(^|[^\w@])@` + botName + `\b`)
var applyRe = regexp.MustCompile(`(?i)@` + botName + `\s+apply\b`)

// mentionsBot reports whether a comment asks the agent, ignoring its own comments.
func mentionsBot(body string) bool {
	return !strings.Contains(body, botMarker) && mentionRe.MatchString(body)
}

// queueAgentJob queues a reply to a comment on a pull request.
func queueAgentJob(ctx context.Context, db *store.DB, conn *store.DevOpsConnector, repo, pr string, p agentPayload, logger *slog.Logger) {
	if repo == "" || pr == "" || p.CommentID == "" {
		return
	}
	p.Body = truncateRunes(p.Body, 4000)
	b, _ := json.Marshal(p)
	enqueueCodeJob(ctx, db, store.CodeScanJob{ConnectorID: conn.ID, Kind: "agent", Trigger: "mention", Repo: repo, Ref: pr,
		HeadSHA: "comment:" + p.CommentID, Payload: b}, logger)
}

// gitlabCanWrite checks that a GitLab user is at least a developer on the project.
func gitlabCanWrite(ctx context.Context, conn *store.DevOpsConnector, repo, userID string) bool {
	var m struct {
		AccessLevel int `json:"access_level"`
	}
	err := devopsJSON(ctx, "GET", gitlabAPIBase(conn)+"/projects/"+pathEscapeAll(repo)+"/members/all/"+userID,
		map[string]string{"PRIVATE-TOKEN": conn.Credentials["token"]}, nil, &m)
	return err == nil && m.AccessLevel >= 30
}

func runAgentJob(ctx context.Context, cfg *config.Config, db *store.DB, conn *store.DevOpsConnector, job *store.CodeScanJob, logger *slog.Logger) (codeJobResult, error) {
	res := codeJobResult{Engines: engineReport{}}
	var p agentPayload
	if err := json.Unmarshal(job.Payload, &p); err != nil || p.Body == "" {
		return res, fmt.Errorf("no comment in the job")
	}
	if conn.Provider == "gitlab" && !gitlabCanWrite(ctx, conn, job.Repo, p.AuthorID) {
		res.Notes = append(res.Notes, "ignored: the commenter is not a developer or maintainer of the project")
		return res, nil
	}
	var recent int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM code_scan_jobs WHERE connector_id=$1 AND kind='agent' AND repo=$2 AND ref=$3
		AND created_at > NOW() - INTERVAL '24 hours'`, conn.ID, job.Repo, job.Ref).Scan(&recent)
	if recent > maxAgentJobsPerDay {
		res.Notes = append(res.Notes, "ignored: more than 30 requests on this pull request today")
		return res, nil
	}
	info, err := getPR(ctx, conn, job.Repo, job.Ref)
	if err != nil {
		return res, err
	}
	if info.State != "open" {
		res.Notes = append(res.Notes, "ignored: the pull request is "+info.State)
		return res, nil
	}
	policy := loadCodeScanPolicy(ctx, db, conn.ID)
	if public, _ := repoIsPublic(ctx, conn, job.Repo); public {
		prof, _ := policy.profileFor(job.Repo, info.BaseRef)
		if prof.PublicAck == nil {
			_ = commentPR(ctx, conn, job.Repo, job.Ref, "This repository is public, so I don't discuss or fix its security findings here until an ObsidianWatch admin confirms it for this branch.")
			res.Notes = append(res.Notes, "public repository without confirmation: not answered")
			return res, nil
		}
	}
	reply := func(text string) {
		if err := commentPR(ctx, conn, job.Repo, job.Ref, text); err != nil {
			res.Notes = append(res.Notes, "reply: "+err.Error())
		} else {
			res.Reported = append(res.Reported, "replied to "+p.Author)
		}
	}
	if err := businessLogicReady(ctx, cfg, db); err != nil {
		reply("I can't work on this: " + err.Error() + ".")
		return res, nil
	}

	// Which findings, and may the agent push?
	var refs []fixFindingRef
	ours := false
	var fixID int64
	var fj []byte
	if db.QueryRowContext(ctx, `SELECT id, findings FROM code_fix_prs WHERE connector_id=$1 AND repo=$2 AND number=$3`,
		conn.ID, job.Repo, job.Ref).Scan(&fixID, &fj) == nil {
		ours = true
		_ = json.Unmarshal(fj, &refs)
	} else {
		if _, ok := policy.profileFor(job.Repo, info.BaseRef); !ok {
			res.Notes = append(res.Notes, "ignored: the pull request does not target a protected branch")
			return res, nil
		}
		var rj []byte
		if db.QueryRowContext(ctx, `SELECT result FROM code_scan_jobs WHERE connector_id=$1 AND kind='pr' AND repo=$2 AND ref=$3 AND status='done'
			ORDER BY id DESC LIMIT 1`, conn.ID, job.Repo, job.Ref).Scan(&rj) == nil {
			var r codeJobResult
			_ = json.Unmarshal(rj, &r)
			refs = fixRefs(r.Findings)
		}
	}
	apply := applyRe.MatchString(p.Body)
	canPush := ours || apply
	if canPush && info.Fork {
		reply("This pull request comes from a fork, so I can't push to it. I can still answer questions here.")
		canPush = false
	}
	if apply && !ours && len(refs) == 0 {
		reply("The last check of this pull request found nothing for me to fix.")
		return res, nil
	}

	// Files: the findings' files on the PR head.
	tmp, err := os.MkdirTemp("", fmt.Sprintf("codeagent-%d-", job.ID))
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	dir := filepath.Join(tmp, "repo")
	files := map[string]string{}
	if !info.Fork {
		if err := cloneRepo(ctx, conn, job.Repo, info.HeadRef, dir, 1); err != nil {
			return res, err
		}
		g := fixGroup{}
		for _, r := range refs {
			if r.Package != "" {
				g.Key = "dependencies" // manifests next to the lockfiles too
			}
			g.Findings = append(g.Findings, SASTFinding{File: r.File, Package: r.Package})
		}
		files, _ = agentFiles(dir, fixFiles(dir, g), agentFileBudget)
	}
	refJSON, _ := json.Marshal(refs)
	var task string
	switch {
	case ours:
		task = fmt.Sprintf("You opened this pull request to fix the findings below. %s commented on it.\nAnswer in \"reply\" (markdown, short). If the comment reports a problem with your change or asks for a change, fix it with edits; otherwise return no edits.", p.Author)
	case apply && canPush:
		task = fmt.Sprintf("%s asked you to fix the security findings of their pull request. Fix them with edits and summarise in \"reply\".", p.Author)
	default:
		task = fmt.Sprintf("%s asked you about the security findings of their pull request. Answer in \"reply\" (markdown, short). Do not return edits.", p.Author)
	}
	task += "\n\nComment:\n" + fenceUntrusted("comment", p.Body) + "\n\nFindings:\n" + fenceUntrusted("findings", string(refJSON))
	ans, _, err := askAgent(ctx, cfg, db, task, files, 12000)
	if err != nil {
		reply("I couldn't answer: " + err.Error())
		return res, nil
	}
	text := strings.TrimSpace(ans.Reply)
	if text == "" {
		text = strings.TrimSpace(ans.Summary)
	}
	if canPush && len(ans.Edits) > 0 {
		allowed, findingFiles := map[string]bool{}, map[string]bool{}
		for f := range files {
			allowed[f] = true
		}
		for _, r := range refs {
			findingFiles[r.File] = true
		}
		changed, refused := applyEdits(dir, ans.Edits, allowed, findingFiles)
		if len(changed) > 0 {
			sha, err := commitAndPush(ctx, conn, job.Repo, dir, info.HeadRef, "ObsidianWatch: changes requested by "+p.Author)
			if err != nil {
				text += "\n\nI could not push the change: " + err.Error()
			} else {
				text += fmt.Sprintf("\n\nPushed %s to `%s`: %s.", shortSHA(sha), info.HeadRef, "`"+strings.Join(changed, "`, `")+"`")
				if t := strings.TrimSpace(ans.Testing); t != "" {
					text += "\n\n**How to test:** " + t
				}
			}
		}
		if len(refused) > 0 {
			text += "\n\nEdits I did not apply: " + strings.Join(refused, "; ")
		}
	}
	if text == "" {
		text = "I have nothing to add."
	}
	reply(text)
	if ours {
		_, _ = db.ExecContext(ctx, `UPDATE code_fix_prs SET agent_replies=agent_replies+1, updated_at=NOW() WHERE id=$1`, fixID)
	}
	return res, nil
}

func shortSHA(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// ── API ───────────────────────────────────────────────────────────────────────

type fixPRRow struct {
	ID           int64     `json:"id"`
	Repo         string    `json:"repo"`
	BaseBranch   string    `json:"base_branch"`
	HeadBranch   string    `json:"head_branch"`
	Number       string    `json:"number"`
	URL          string    `json:"url"`
	Title        string    `json:"title"`
	Findings     int       `json:"findings"`
	Model        string    `json:"model"`
	Status       string    `json:"status"`
	AgentReplies int       `json:"agent_replies"`
	CreatedAt    time.Time `json:"created_at"`
}

// handleListFixPRs: GET /api/v1/devops-connectors/{id}/fix-prs.
func handleListFixPRs(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		rows, err := db.QueryContext(r.Context(), `SELECT id, repo, base_branch, head_branch, number, url, title,
			jsonb_array_length(fingerprints), model, status, agent_replies, created_at
			FROM code_fix_prs WHERE connector_id=$1 ORDER BY id DESC LIMIT 200`, id)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()
		out := []fixPRRow{}
		for rows.Next() {
			var x fixPRRow
			if rows.Scan(&x.ID, &x.Repo, &x.BaseBranch, &x.HeadBranch, &x.Number, &x.URL, &x.Title, &x.Findings, &x.Model, &x.Status, &x.AgentReplies, &x.CreatedAt) == nil {
				out = append(out, x)
			}
		}
		writeJSON(w, 200, map[string]interface{}{"fix_prs": out})
	}
}

// handleQueueRemediation: POST /api/v1/devops-connectors/{id}/protected/remediate {repo, branch} (admin).
func handleQueueRemediation(db *store.DB, logger *slog.Logger) http.HandlerFunc {
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
		prof, ok := loadCodeScanPolicy(r.Context(), db, id).profileFor(body.Repo, body.Branch)
		if !ok {
			writeJSON(w, 400, map[string]string{"error": "add the branch under Protected branches first"})
			return
		}
		if conn, err := db.GetDevOpsConnectorRaw(r.Context(), id); err == nil && conn != nil && prof.PublicAck == nil {
			if public, _ := repoIsPublic(r.Context(), conn, body.Repo); public {
				writeJSON(w, 409, map[string]interface{}{"public": true, "error": `the repository is public: confirm with "proceed" first`})
				return
			}
		}
		queueFixJob(r.Context(), db, id, body.Repo, body.Branch, "manual", logger)
		writeJSON(w, 202, map[string]bool{"queued": true})
	}
}

// handleRepoVisibility: GET /api/v1/devops-connectors/{id}/protected/visibility?repo=&branch=.
func handleRepoVisibility(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		conn, err := db.GetDevOpsConnectorRaw(r.Context(), id)
		if err != nil || conn == nil {
			writeJSON(w, 404, map[string]string{"error": "connector not found"})
			return
		}
		repo, branch := r.URL.Query().Get("repo"), r.URL.Query().Get("branch")
		public, verr := repoIsPublic(r.Context(), conn, repo)
		prof, _ := loadCodeScanPolicy(r.Context(), db, id).profileFor(repo, branch)
		out := map[string]interface{}{"public": public, "confirmed": prof.PublicAck != nil}
		if prof.PublicAck != nil {
			out["confirmed_by"], out["confirmed_at"] = prof.PublicAck.By, prof.PublicAck.At
		}
		if verr != nil {
			out["error"] = verr.Error()
		}
		writeJSON(w, 200, out)
	}
}

// handlePublicAck: POST /api/v1/devops-connectors/{id}/protected/public-ack
// {repo, branch, confirm: "proceed"} (admin), or {.., revoke: true}.
func handlePublicAck(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		var body struct {
			Repo    string `json:"repo"`
			Branch  string `json:"branch"`
			Confirm string `json:"confirm"`
			Revoke  bool   `json:"revoke"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
		if !body.Revoke && !strings.EqualFold(strings.TrimSpace(body.Confirm), "proceed") {
			writeJSON(w, 400, map[string]string{"error": `type "proceed" to confirm`})
			return
		}
		ctx := r.Context()
		p := loadCodeScanPolicy(ctx, db, id)
		found := false
		for i := range p.Protected {
			b := &p.Protected[i]
			if strings.EqualFold(b.Repo, body.Repo) && b.Branch == body.Branch {
				found = true
				if body.Revoke {
					b.PublicAck = nil
				} else {
					b.PublicAck = &publicAck{By: claimsUsername(r), At: time.Now().UTC()}
				}
			}
		}
		if !found {
			writeJSON(w, 400, map[string]string{"error": "save the branch under Protected branches first"})
			return
		}
		b, _ := json.Marshal(p)
		if err := db.SetSetting(ctx, codePolicyKey(id), string(b)); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, p)
	}
}
