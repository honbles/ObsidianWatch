package api

// code_automation.go - Code step 3: scans that run without anyone pressing a
// button.
//
//   - On push to a repository's default branch (webhook), when enabled.
//   - On a schedule (every 5 days by default, all repositories and branches; or daily or weekly), at a chosen UTC hour.
//   - On every pull/merge request update (webhook): the PR head is scanned,
//     only findings on lines the PR changes (or in dependency/IaC files it
//     changes and that are new compared with the base) are kept, and the
//     result goes back to the provider as a commit status (which branch
//     protection can require, so a failing check blocks the merge), a summary
//     comment and inline review comments.
//
// Jobs are rows in code_scan_jobs so they survive restarts and are visible in
// the UI; one worker runs them in order (OW_CODE_SCAN_WORKERS for more).

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
	"obsidianwatch/management/internal/telemetry"
)

// ── Policy ────────────────────────────────────────────────────────────────────

// codeScanPolicy is a connector's automation settings (setting
// code.policy.<connector id>).
type codeScanPolicy struct {
	PRChecks     bool   `json:"pr_checks"`     // scan pull/merge requests
	PRComments   bool   `json:"pr_comments"`   // post summary + inline comments
	BlockOn      string `json:"block_on"`      // none | critical | high | medium | low
	ScanOnPush   bool   `json:"scan_on_push"`  // scan a protected branch on push
	Schedule     string `json:"schedule"`      // off | daily | weekly | every5d (protected branches)
	ScheduleHour int    `json:"schedule_hour"` // UTC hour 0-23
	PRCodeQL     bool   `json:"pr_codeql"`     // CodeQL on PRs (slow), when the branch's engines include it
	PRAIFixes    bool   `json:"pr_ai_fixes"`   // AI fix suggestions in PR comments (step 5)
	MaxComments  int    `json:"max_comments"`  // inline comments per update
	// Protected is the protected branches of this connector's repositories,
	// each with its scan profile. Scheduled scans, push scans and the
	// business-logic engine work only on these.
	Protected []branchProfile `json:"protected"`
	// FixMinSeverity: the lowest severity fix pull requests cover (default high).
	FixMinSeverity string `json:"fix_min_severity"`
	// ManualSetup: do not configure the repository (webhook, branch
	// protection) when a protected branch is added; use "Set up" instead.
	ManualSetup bool `json:"manual_setup"`

	agentHint bool // set while reporting a PR into a protected branch (not stored)
}

// fixes reports whether fix pull requests cover a finding of this severity.
func (p codeScanPolicy) fixes(sev string) bool {
	return sevRank(strings.ToLower(sev)) >= sevRank(p.FixMinSeverity)
}

// prScanned reports whether a PR into base is checked: PRs into a protected
// branch always are; others when "Scan every pull request" is on.
func (p codeScanPolicy) prScanned(repo, base string) bool {
	if p.PRChecks {
		return true
	}
	_, ok := p.profileFor(repo, base)
	return ok
}

// branchProfile is one protected branch and how it is scanned.
type branchProfile struct {
	Repo    string   `json:"repo"`
	Branch  string   `json:"branch"`
	Engines []string `json:"engines"` // empty = the default (non-AI) engines
	// Correlate: after each automated scan of the branch, correlate the
	// engines' findings with the code model (needs two or more engines).
	Correlate bool `json:"correlate"`
	// Remediate: after a scheduled or manual scan, open fix pull requests for
	// new findings (code_remediation.go). The agent never merges.
	Remediate bool `json:"remediate"`
	// PublicAck: an admin typed "proceed" to allow fix pull requests and agent
	// replies on this public repository. Set only by POST .../protected/public-ack.
	PublicAck *publicAck `json:"public_ack,omitempty"`
}

type publicAck struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
}

const maxProtectedBranches = 500

func defaultCodeScanPolicy() codeScanPolicy {
	// Rescanning is how a fixed issue is noticed, so protected branches are
	// rescanned every 5 days unless turned off.
	return codeScanPolicy{PRComments: true, BlockOn: "critical", Schedule: "every5d", ScheduleHour: 2, MaxComments: 20}
}

// profileFor returns the scan profile of a protected branch.
func (p codeScanPolicy) profileFor(repo, branch string) (branchProfile, bool) {
	branch = strings.TrimPrefix(branch, "refs/heads/")
	for _, b := range p.Protected {
		if strings.EqualFold(b.Repo, repo) && b.Branch == branch {
			return b, true
		}
	}
	return branchProfile{}, false
}

// pushScanBranch decides whether a push to ref is scanned: pushes to a
// protected branch are; with no protected branches configured, pushes to the
// default branch are (the behaviour before protected branches existed).
func (p codeScanPolicy) pushScanBranch(repo, ref, defaultBranch string) (string, bool) {
	if !strings.HasPrefix(ref, "refs/heads/") {
		return "", false
	}
	b := strings.TrimPrefix(ref, "refs/heads/")
	if _, ok := p.profileFor(repo, b); ok {
		return b, true
	}
	def := strings.TrimPrefix(defaultBranch, "refs/heads/")
	if len(p.Protected) == 0 && def != "" && b == def {
		return b, true
	}
	return "", false
}

// engineSetFor is the engine set of a protected branch (nil: not protected,
// or protected with the default engines).
func (p codeScanPolicy) engineSetFor(repo, branch string) (engineSet, bool) {
	b, ok := p.profileFor(repo, branch)
	if !ok {
		return nil, false
	}
	return newEngineSet(b.Engines), true
}

func codePolicyKey(id int64) string { return "code.policy." + strconv.FormatInt(id, 10) }

func loadCodeScanPolicy(ctx context.Context, db *store.DB, connID int64) codeScanPolicy {
	p := defaultCodeScanPolicy()
	if v, err := db.GetSetting(ctx, codePolicyKey(connID)); err == nil && v != "" {
		_ = json.Unmarshal([]byte(v), &p)
		// A policy saved before the 5-day default existed has no
		// schedule_branches; its "off" was the old default, not a choice.
		if !strings.Contains(v, `"schedule_branches"`) && !strings.Contains(v, `"protected"`) && p.Schedule == "off" {
			p.Schedule = "every5d"
		}
	}
	return p.normalised()
}

func (p codeScanPolicy) normalised() codeScanPolicy {
	switch p.BlockOn {
	case "none", "critical", "high", "medium", "low":
	default:
		p.BlockOn = "critical"
	}
	switch p.Schedule {
	case "off", "daily", "weekly", "every5d":
	default:
		p.Schedule = "off"
	}
	seen := map[string]bool{}
	var prot []branchProfile
	for _, b := range p.Protected {
		b.Repo, b.Branch = strings.TrimSpace(b.Repo), strings.TrimPrefix(strings.TrimSpace(b.Branch), "refs/heads/")
		if b.Repo == "" || b.Branch == "" || b.Branch == "HEAD" || len(b.Repo) > 300 || len(b.Branch) > 250 {
			continue
		}
		k := strings.ToLower(b.Repo) + "\x00" + b.Branch
		if seen[k] || len(prot) >= maxProtectedBranches {
			continue
		}
		seen[k] = true
		b.Engines, _ = parseEngineIDs(b.Engines) // invalid IDs are answered with 400 before this
		if len(b.Engines) == 1 {
			b.Correlate = false // one engine: nothing to correlate
		}
		prot = append(prot, b)
	}
	p.Protected = prot
	switch p.FixMinSeverity {
	case "critical", "high", "medium", "low":
	default:
		p.FixMinSeverity = "high"
	}
	if p.ScheduleHour < 0 || p.ScheduleHour > 23 {
		p.ScheduleHour = 2
	}
	if p.MaxComments <= 0 || p.MaxComments > 100 {
		p.MaxComments = 20
	}
	return p
}

// blocks reports whether a finding of this severity fails the check.
func (p codeScanPolicy) blocks(sev string) bool {
	return p.BlockOn != "none" && sevRank(strings.ToLower(sev)) >= sevRank(p.BlockOn)
}

// ── Queue ─────────────────────────────────────────────────────────────────────

var codeJobWake = make(chan struct{}, 1)

// enqueueCodeJob queues a scan and wakes the worker.
func enqueueCodeJob(ctx context.Context, db *store.DB, j store.CodeScanJob, logger *slog.Logger) {
	id, err := db.EnqueueCodeScanJob(ctx, j)
	if err != nil {
		if logger != nil {
			logger.Warn("code automation: enqueue failed", "repo", j.Repo, "err", err)
		}
		return
	}
	if id > 0 && logger != nil {
		logger.Info("code automation: queued", "job", id, "kind", j.Kind, "trigger", j.Trigger, "repo", j.Repo, "ref", j.Ref)
	}
	select {
	case codeJobWake <- struct{}{}:
	default:
	}
}

// CodeAutomation runs queued jobs and the schedule.
type CodeAutomation struct {
	cfg    *config.Config
	db     *store.DB
	logger *slog.Logger
}

func NewCodeAutomation(cfg *config.Config, db *store.DB, logger *slog.Logger) *CodeAutomation {
	return &CodeAutomation{cfg: cfg, db: db, logger: logger}
}

func (a *CodeAutomation) Run(ctx context.Context) {
	a.db.FailStaleCodeScanJobs(ctx, time.Minute)
	workers := 1
	if n, err := strconv.Atoi(os.Getenv("OW_CODE_SCAN_WORKERS")); err == nil && n > 0 && n <= 4 {
		workers = n
	}
	for i := 0; i < workers; i++ {
		go a.worker(ctx)
	}
	sched := time.NewTicker(10 * time.Minute)
	defer sched.Stop()
	a.runSchedule(ctx, time.Now().UTC())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-sched.C:
			a.runSchedule(ctx, now.UTC())
		}
	}
}

func (a *CodeAutomation) worker(ctx context.Context) {
	poll := time.NewTicker(30 * time.Second)
	defer poll.Stop()
	for ctx.Err() == nil {
		job, err := a.db.ClaimCodeScanJob(ctx)
		if err != nil {
			a.logger.Warn("code automation: claim failed", "err", err)
		}
		if job != nil {
			a.runJob(ctx, job)
			continue // look for the next one straight away
		}
		select {
		case <-ctx.Done():
			return
		case <-codeJobWake:
		case <-poll.C:
		}
	}
}

// codeJobResult is stored with each job.
type codeJobResult struct {
	Engines  engineReport   `json:"engines"`
	Findings []SASTFinding  `json:"findings"`
	Counts   map[string]int `json:"counts"`
	Reported []string       `json:"reported,omitempty"` // what was posted to the provider
	Notes    []string       `json:"notes,omitempty"`
}

func (a *CodeAutomation) runJob(ctx context.Context, job *store.CodeScanJob) {
	release, err := acquireScanSlot(ctx) // before the job's own time limit starts
	defer release()
	if err != nil {
		return
	}
	jctx, cancel := context.WithTimeout(ctx, 40*time.Minute)
	defer cancel()
	jctx, span := telemetry.StartJob(jctx, "code-scan."+job.Kind)
	defer span.End()
	conn, err := a.db.GetDevOpsConnectorRaw(jctx, job.ConnectorID)
	if err != nil || conn == nil {
		_ = a.db.FinishCodeScanJob(ctx, job.ID, "failed", false, 0, "connector not found", nil)
		return
	}
	var res codeJobResult
	var blocked bool
	switch job.Kind {
	case "pr":
		res, blocked, err = runPRScan(jctx, a.cfg, a.db, conn, job, a.logger)
	case "fix":
		res, err = runFixJob(jctx, a.cfg, a.db, conn, job, a.logger)
	case "agent":
		res, err = runAgentJob(jctx, a.cfg, a.db, conn, job, a.logger)
	case "setup":
		s := setupRepository(jctx, a.db, conn, job.Repo, job.Ref)
		res = codeJobResult{Engines: engineReport{}}
		for _, st := range s.Steps {
			res.Reported = append(res.Reported, st.Step+": "+st.Status+" "+st.Detail)
		}
		if !s.OK {
			err = fmt.Errorf("setup incomplete; see the steps")
		}
	default:
		res, err = runBranchScan(jctx, a.cfg, a.db, conn, job, a.logger)
	}
	status, msg := "done", ""
	if err != nil {
		status, msg = "failed", err.Error()
		span.SetError(msg)
	}
	b, _ := json.Marshal(res)
	_ = a.db.FinishCodeScanJob(ctx, job.ID, status, blocked, len(res.Findings), msg, b)
	a.logger.Info("code automation: job finished", "job", job.ID, "kind", job.Kind, "repo", job.Repo,
		"status", status, "findings", len(res.Findings), "blocked", blocked, "err", msg)
}

func countBySeverity(f []SASTFinding) map[string]int {
	c := map[string]int{}
	for _, x := range f {
		c[x.Severity]++
	}
	return c
}

// ── Branch scans (push, schedule, manual) ─────────────────────────────────────

func runBranchScan(ctx context.Context, cfg *config.Config, db *store.DB, conn *store.DevOpsConnector, job *store.CodeScanJob, logger *slog.Logger) (codeJobResult, error) {
	res := codeJobResult{Engines: engineReport{}}
	// A protected branch is scanned with its profile's engines.
	var set engineSet
	var bl *blContext
	correlate, remediate := false, false
	if job.Kind != "commit" {
		policy := loadCodeScanPolicy(ctx, db, conn.ID)
		if s, ok := policy.engineSetFor(job.Repo, job.Ref); ok {
			set, bl = s, &blContext{cfg: cfg, db: db}
			prof, _ := policy.profileFor(job.Repo, job.Ref)
			correlate, remediate = prof.Correlate, prof.Remediate
		}
	}
	tmp, err := os.MkdirTemp("", fmt.Sprintf("codejob-%d-", job.ID))
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	dir := filepath.Join(tmp, "repo")
	branch := job.Ref
	if branch == "" {
		branch = "HEAD"
	}
	depth, history := 0, sastHistoryEnabled()
	if !history {
		depth = 1
	}
	if job.Kind == "commit" { // one exact (deployed) commit, stored as branch "@<sha>"
		if err := cloneCommit(ctx, conn, job.Repo, job.HeadSHA, dir, depth); err != nil {
			return res, err
		}
		branch = "@" + job.HeadSHA
	} else if err := cloneRepo(ctx, conn, job.Repo, branch, dir, depth); err != nil {
		return res, err
	}
	sha := gitHeadSHA(ctx, dir)
	res.Engines.set("source", "git")
	findings, sbom := scanCheckout(ctx, conn, job.Repo, dir, scanOpts{History: history, Semgrep: semgrepAvailable(), CodeQL: codeqlAvailable(),
		Engines: set, BL: bl}, res.Engines, logger)
	findings, sbom = mergeStoredEngines(ctx, db, conn.ID, job.Repo, branch, set, res.Engines, findings, sbom)
	findings = deduplicateSASTFindings(findings)
	res.Findings, res.Counts = findings, countBySeverity(findings)
	// The stored result is what the Code pages show for this repository.
	if err := saveSASTResult(ctx, db, conn.ID, job.Repo, branch, sha, res.Engines, findings, sbom, 1, countSourceFiles(dir)); err != nil {
		res.Notes = append(res.Notes, "could not store the result: "+err.Error())
	} else if correlate {
		// The protected branch's profile asks for correlation: the
		// correlated findings become the branch's findings.
		if meta, err := correlateStored(ctx, cfg, db, conn.ID, job.Repo, branch, true); err != nil {
			res.Notes = append(res.Notes, "correlation: "+err.Error())
		} else {
			res.Notes = append(res.Notes, fmt.Sprintf("correlated %d engine findings into %d (%d merged, %d marked false positive)", meta.Raw, meta.Findings, meta.Merged, meta.FalsePos))
		}
	}
	// Scheduled and manual scans of a protected branch with remediation on
	// open fix pull requests for new findings.
	if remediate && (job.Trigger == "schedule" || job.Trigger == "manual") && len(findings) > 0 {
		queueFixJob(ctx, db, conn.ID, job.Repo, branch, job.Trigger, logger)
		res.Notes = append(res.Notes, "remediation queued")
	}
	return res, nil
}

// ── Schedule ──────────────────────────────────────────────────────────────────

// scheduleDue reports whether a scheduled run is due at now for a policy whose
// last run started at last.
func scheduleDue(p codeScanPolicy, now, last time.Time) bool {
	if p.Schedule == "off" || now.Hour() != p.ScheduleHour {
		return false
	}
	if p.Schedule == "weekly" && now.Weekday() != time.Monday {
		return false
	}
	if p.Schedule == "every5d" {
		return now.Sub(last) > 5*24*time.Hour-4*time.Hour
	}
	return now.Sub(last) > 20*time.Hour
}

func (a *CodeAutomation) runSchedule(ctx context.Context, now time.Time) {
	conns, err := a.db.ListDevOpsConnectors(ctx)
	if err != nil {
		return
	}
	for _, c := range conns {
		p := loadCodeScanPolicy(ctx, a.db, c.ID)
		if p.Schedule == "off" || len(p.Protected) == 0 {
			continue
		}
		key := "code.schedule.last." + strconv.FormatInt(c.ID, 10)
		var last time.Time
		if v, err := a.db.GetSetting(ctx, key); err == nil {
			last, _ = time.Parse(time.RFC3339, v)
		}
		if !scheduleDue(p, now, last) {
			continue
		}
		_ = a.db.SetSetting(ctx, key, now.Format(time.RFC3339))
		// Only protected branches are scanned on a schedule.
		day := now.Format("2006-01-02")
		for _, b := range p.Protected {
			// head_sha carries the date so one schedule run per day is queued.
			enqueueCodeJob(ctx, a.db, store.CodeScanJob{ConnectorID: c.ID, Kind: "branch", Trigger: "schedule",
				Repo: b.Repo, Ref: b.Branch, HeadSHA: "schedule:" + day}, nil)
		}
		a.logger.Info("code automation: scheduled scans queued", "connector", c.ID, "protected_branches", len(p.Protected))
	}
}

// knownRepos lists the repositories seen for a connector (synced commits and
// earlier scans), at most 200.
func knownRepos(ctx context.Context, db *store.DB, connID int64) []string {
	rows, err := db.QueryContext(ctx, `
		SELECT repo FROM (
			SELECT DISTINCT repo FROM devops_commits WHERE connector_id=$1
			UNION SELECT DISTINCT repo FROM sast_results WHERE connector_id=$1 AND repo <> ''
		) r WHERE repo <> '' ORDER BY repo LIMIT 200`, connID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if rows.Scan(&r) == nil {
			out = append(out, r)
		}
	}
	return out
}

// ── PR scans ──────────────────────────────────────────────────────────────────

// lineRange is an inclusive range of new-file line numbers changed by a PR.
type lineRange [2]int

var diffHunkRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// parseChangedLines reads `git diff --unified=0` output into the changed
// line ranges of each file (new path). Deleted files are left out.
func parseChangedLines(r io.Reader) map[string][]lineRange {
	out := map[string][]lineRange{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	file := ""
	for sc.Scan() {
		t := sc.Text()
		switch {
		case strings.HasPrefix(t, "+++ "):
			file = strings.TrimPrefix(strings.TrimPrefix(t, "+++ "), "b/")
			if file == "/dev/null" {
				file = ""
			} else if _, ok := out[file]; !ok {
				out[file] = nil
			}
		case strings.HasPrefix(t, "@@ ") && file != "":
			m := diffHunkRe.FindStringSubmatch(t)
			if m == nil {
				continue
			}
			start, _ := strconv.Atoi(m[1])
			n := 1
			if m[2] != "" {
				n, _ = strconv.Atoi(m[2])
			}
			if n > 0 {
				out[file] = append(out[file], lineRange{start, start + n - 1})
			}
		}
	}
	return out
}

// gatePRFindings keeps what the PR introduced:
//   - secrets from the PR's own commits (the history scan is range-limited);
//   - findings with a line number on a line the PR changed;
//   - file-level findings (dependencies, licences, IaC without a line) in a
//     file the PR changed that the base branch does not already have.
func gatePRFindings(findings []SASTFinding, changed map[string][]lineRange, baseline map[string]bool) []SASTFinding {
	var out []SASTFinding
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "SECRET-") {
			out = append(out, f)
			continue
		}
		ranges, touched := changed[f.File]
		if !touched {
			continue
		}
		if f.Line <= 0 {
			if !baseline[f.RuleID+"\x00"+f.File] {
				out = append(out, f)
			}
			continue
		}
		end := f.EndLine
		if end < f.Line {
			end = f.Line
		}
		for _, r := range ranges {
			if f.Line <= r[1] && end >= r[0] {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// prHeadRef is the ref that holds a PR's head commit on the base repository
// (it exists for PRs from forks too).
func prHeadRef(provider, pr, sourceRef string) string {
	switch provider {
	case "github":
		return "refs/pull/" + pr + "/head"
	case "gitlab":
		return "refs/merge-requests/" + pr + "/head"
	}
	if sourceRef != "" {
		return sourceRef
	}
	return "refs/pull/" + pr + "/merge"
}

// gitIn runs a hardened git command in dir.
func gitIn(ctx context.Context, dir, auth string, args ...string) ([]byte, error) {
	full := append(append([]string{}, gitHardening...), "-C", dir)
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = gitEnv(auth)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			msg := trimOut(ee.Stderr)
			return out, fmt.Errorf("git %s: %v: %s%s", args[0], err, msg, gitErrHint(msg))
		}
		return out, fmt.Errorf("git %s: %v", args[0], err)
	}
	return out, nil
}

// preparePRCheckout fetches the base branch and the PR head into dir, checks
// out the head, and returns the merge base.
func preparePRCheckout(ctx context.Context, conn *store.DevOpsConnector, job *store.CodeScanJob, dir string) (mergeBase, auth string, err error) {
	remote, auth, err := gitRemote(conn, job.Repo)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	if _, err := gitIn(ctx, dir, auth, "init", "-q"); err != nil {
		return "", "", err
	}
	head := prHeadRef(conn.Provider, job.Ref, job.HeadRef)
	fetch := func(extra ...string) error {
		args := append([]string{"fetch", "--quiet", "--no-tags"}, extra...)
		args = append(args, remote, "+refs/heads/"+job.BaseBranch+":refs/ow/base", "+"+head+":refs/ow/head")
		_, err := gitIn(ctx, dir, auth, args...)
		return err
	}
	if err := fetch("--depth=300"); err != nil {
		return "", "", err
	}
	if _, err := gitIn(ctx, dir, auth, "checkout", "-q", "--detach", "refs/ow/head"); err != nil {
		return "", "", err
	}
	mb, err := gitIn(ctx, dir, auth, "merge-base", "refs/ow/base", "refs/ow/head")
	if err != nil {
		// Histories longer than the shallow fetch: deepen once.
		_ = fetch("--deepen=3000")
		mb, err = gitIn(ctx, dir, auth, "merge-base", "refs/ow/base", "refs/ow/head")
	}
	if err != nil {
		// Still unknown: compare with the base tip.
		mb, err = gitIn(ctx, dir, auth, "rev-parse", "refs/ow/base")
		if err != nil {
			return "", "", err
		}
	}
	return strings.TrimSpace(string(mb)), auth, nil
}

func runPRScan(ctx context.Context, cfg *config.Config, db *store.DB, conn *store.DevOpsConnector, job *store.CodeScanJob, logger *slog.Logger) (codeJobResult, bool, error) {
	res := codeJobResult{Engines: engineReport{}}
	policy := loadCodeScanPolicy(ctx, db, conn.ID)
	rep := newPRReporter(conn, job)
	if rep != nil {
		if err := rep.SetStatus(ctx, "pending", "Code scan running"); err != nil {
			res.Notes = append(res.Notes, "status: "+err.Error())
		}
	}

	tmp, err := os.MkdirTemp("", fmt.Sprintf("codepr-%d-", job.ID))
	if err != nil {
		return res, false, err
	}
	defer os.RemoveAll(tmp)
	dir := filepath.Join(tmp, "head")
	mb, auth, err := preparePRCheckout(ctx, conn, job, dir)
	if err != nil {
		if rep != nil {
			_ = rep.SetStatus(ctx, "error", "Code scan could not fetch the pull request")
		}
		return res, false, err
	}
	res.Engines.set("source", "git")
	diff, err := gitIn(ctx, dir, auth, "diff", "--no-color", "--no-ext-diff", "--unified=0", "--find-renames", mb, "HEAD")
	if err != nil {
		return res, false, err
	}
	changed := parseChangedLines(strings.NewReader(string(diff)))

	// A PR into a protected branch is scanned with that branch's engines; the
	// business-logic engine reads only the files the PR changes.
	opts := scanOpts{History: true, LogRange: mb + "..HEAD", Semgrep: semgrepAvailable(), CodeQL: policy.PRCodeQL && codeqlAvailable()}
	if set, ok := policy.engineSetFor(job.Repo, job.BaseBranch); ok {
		only := map[string]bool{}
		for f := range changed {
			only[f] = true
		}
		opts.Engines, opts.BL = set, &blContext{cfg: cfg, db: db, OnlyFiles: only}
	}
	findings, _ := scanCheckout(ctx, conn, job.Repo, dir, opts, res.Engines, logger)
	if !policy.PRCodeQL && opts.Engines.on(engCodeQL) {
		res.Engines.set("codeql", "skipped: off for pull requests (policy)")
	}
	findings = deduplicateSASTFindings(findings)

	// Baseline for file-level findings: scan the merge base's dependency and
	// IaC files once, only when the PR has file-level findings at all.
	baseline := map[string]bool{}
	needBase := false
	for _, f := range findings {
		if f.Line <= 0 && !strings.HasPrefix(f.RuleID, "SECRET-") {
			if _, ok := changed[f.File]; ok {
				needBase = true
				break
			}
		}
	}
	if needBase {
		baseDir := filepath.Join(tmp, "base")
		if _, err := gitIn(ctx, dir, auth, "worktree", "add", "-q", "--detach", baseDir, mb); err == nil {
			for _, f := range baselineFileLevel(ctx, job.Repo, baseDir) {
				baseline[f.RuleID+"\x00"+f.File] = true
			}
		} else {
			res.Notes = append(res.Notes, "baseline: "+err.Error())
		}
	}
	kept, hidden := withoutDismissed(enrichFindings(ctx, db, conn.ID, gatePRFindings(findings, changed, baseline)))
	if hidden > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d finding(s) dismissed by triage were not reported", hidden))
	}
	// Correlate the PR's findings when the target branch's profile asks for
	// it. Severity is the highest of each group's members, so blocking is
	// unchanged by the model.
	if prof, ok := policy.profileFor(job.Repo, job.BaseBranch); ok && prof.Correlate && correlationAllowed(res.Engines) && len(kept) > 1 {
		if c, meta, err := correlateFindings(ctx, cfg, db, kept); err != nil {
			res.Notes = append(res.Notes, "correlation: "+err.Error())
		} else {
			kept = enrichFindings(ctx, db, conn.ID, c)
			res.Notes = append(res.Notes, fmt.Sprintf("correlated %d findings into %d", meta.Raw, meta.Findings))
		}
	}
	res.Findings, res.Counts = kept, countBySeverity(kept)

	blocked := false
	for _, f := range kept {
		if policy.blocks(f.Severity) {
			blocked = true
			break
		}
	}
	if rep != nil {
		var fixer func(SASTFinding) *fixSuggestion
		if policy.PRAIFixes {
			fixer = func(f SASTFinding) *fixSuggestion { return prFixSuggestion(ctx, cfg, db, f, dir) }
		}
		public, visErr := repoIsPublic(ctx, conn, job.Repo)
		if visErr != nil {
			res.Notes = append(res.Notes, "visibility unknown, reported as public: "+visErr.Error())
		}
		if public {
			fixer = nil
		}
		res.Reported = reportPR(ctx, db, rep, conn, job, policy, kept, blocked, public, dir, fixer)
	}
	return res, blocked, nil
}

// baselineFileLevel returns the dependency / licence / IaC findings that the
// merge base already has, so a PR is not blamed for them.
func baselineFileLevel(ctx context.Context, repo, dir string) []SASTFinding {
	if t, err := runTrivy(ctx, repo, dir); err == nil {
		return t.Findings
	}
	f, _ := runSCAOnDir(ctx, repo, dir)
	return f
}

// findingKey identifies a finding across PR updates: rule, file and the text
// of the flagged line (so it survives lines moving).
func findingKey(f SASTFinding, dir string) string {
	text := ""
	if f.Line > 0 {
		if b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.File))); err == nil {
			lines := strings.Split(string(b), "\n")
			if f.Line <= len(lines) {
				text = strings.TrimSpace(lines[f.Line-1])
			}
		}
	}
	sum := sha1.Sum([]byte(f.RuleID + "\x00" + f.File + "\x00" + text))
	return hex.EncodeToString(sum[:10])
}

// ── HTTP API ──────────────────────────────────────────────────────────────────

func handleGetCodeScanPolicy(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		writeJSON(w, 200, loadCodeScanPolicy(r.Context(), db, id))
	}
}

func handlePutCodeScanPolicy(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		if c, err := db.GetDevOpsConnectorRaw(r.Context(), id); err != nil || c == nil {
			writeJSON(w, 404, map[string]string{"error": "connector not found"})
			return
		}
		var p codeScanPolicy
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		for _, b := range p.Protected {
			if _, err := parseEngineIDs(b.Engines); err != nil {
				writeJSON(w, 400, map[string]string{"error": b.Repo + " " + b.Branch + ": " + err.Error()})
				return
			}
		}
		p = p.normalised()
		before := loadCodeScanPolicy(r.Context(), db, id)
		// The public-repository confirmation is kept from the stored policy;
		// a client cannot set it here.
		for i := range p.Protected {
			p.Protected[i].PublicAck = nil
			if old, ok := before.profileFor(p.Protected[i].Repo, p.Protected[i].Branch); ok {
				p.Protected[i].PublicAck = old.PublicAck
			}
		}
		b, _ := json.Marshal(p)
		if err := db.SetSetting(r.Context(), codePolicyKey(id), string(b)); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		// A newly protected branch is set up (webhook, branch protection)
		// unless the policy says to do it by hand.
		if !p.ManualSetup {
			stamp := "setup:" + time.Now().UTC().Format(time.RFC3339)
			for _, bp := range p.Protected {
				if _, had := before.profileFor(bp.Repo, bp.Branch); !had {
					enqueueCodeJob(r.Context(), db, store.CodeScanJob{ConnectorID: id, Kind: "setup", Trigger: "protected",
						Repo: bp.Repo, Ref: bp.Branch, HeadSHA: stamp}, nil)
				}
			}
		}
		writeJSON(w, 200, p)
	}
}

func handleListCodeScanJobs(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		jobs, err := db.ListCodeScanJobs(r.Context(), id, 100)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"jobs": jobs})
	}
}

func handleGetCodeScanJob(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("job"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		j, err := db.GetCodeScanJob(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, 200, j)
	}
}

// handleEnqueueCodeScan queues a branch scan now (POST {repo, branch}; no
// repo = every known repository).
func handleEnqueueCodeScan(db *store.DB, logger *slog.Logger) http.HandlerFunc {
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
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
		stamp := "manual:" + time.Now().UTC().Format(time.RFC3339)
		type target struct{ repo, ref string }
		var targets []target
		switch {
		case body.Repo != "":
			if body.Branch == "" {
				body.Branch = "HEAD"
			}
			targets = append(targets, target{body.Repo, body.Branch})
		default:
			// "Scan now": every protected branch; with none, each known
			// repository's default branch.
			policy := loadCodeScanPolicy(r.Context(), db, id)
			for _, b := range policy.Protected {
				targets = append(targets, target{b.Repo, b.Branch})
			}
			if len(targets) == 0 {
				for _, repo := range knownRepos(r.Context(), db, id) {
					targets = append(targets, target{repo, "HEAD"})
				}
			}
		}
		for _, t := range targets {
			enqueueCodeJob(r.Context(), db, store.CodeScanJob{ConnectorID: id, Kind: "branch", Trigger: "manual",
				Repo: t.repo, Ref: t.ref, HeadSHA: stamp}, logger)
		}
		writeJSON(w, 202, map[string]interface{}{"queued": len(targets)})
	}
}
