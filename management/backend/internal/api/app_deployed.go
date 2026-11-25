package api

// app_deployed.go - the code a service actually runs. Instances report the
// commit they were built from (OpenTelemetry vcs.* attributes, container image
// labels, or the git checkout they run from). For a service linked to a
// repository, the Code tab reads the scan of that exact commit; a commit with
// no scan is queued (job kind "commit", stored as branch "@<sha>"). The branch
// head is shown only while no commit is reported or its scan is pending.

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
	"obsidianwatch/management/internal/telemetry"
)

type appCommitScan struct {
	Status    string         `json:"status"` // scanned | queued | running | failed | short_id | repo_mismatch | none
	ScannedAt *time.Time     `json:"scanned_at,omitempty"`
	Counts    map[string]int `json:"counts,omitempty"`
	Error     string         `json:"error,omitempty"`
}

type appDeployment struct {
	Revision  string        `json:"revision"`
	Short     string        `json:"short"`
	Repo      string        `json:"repo,omitempty"`   // as reported by the instance
	Branch    string        `json:"branch,omitempty"` // as reported
	Source    string        `json:"source"`           // otel | oci | git
	Instances int           `json:"instances"`
	Hosts     []string      `json:"hosts"`
	Mismatch  bool          `json:"repo_mismatch,omitempty"`
	Primary   bool          `json:"primary,omitempty"`
	Scan      appCommitScan `json:"scan"`
	findings  []SASTFinding
}

// appDeployments groups live instances by the commit they report, most
// instances first.
func appDeployments(insts []appLiveInst) []appDeployment {
	by := map[string]*appDeployment{}
	var order []string
	for _, i := range insts {
		if i.VCSRevision == "" {
			continue
		}
		d := by[i.VCSRevision]
		if d == nil {
			short := i.VCSRevision
			if len(short) > 12 {
				short = short[:12]
			}
			d = &appDeployment{Revision: i.VCSRevision, Short: short, Repo: i.VCSRepo, Branch: i.VCSBranch, Source: i.VCSSource, Hosts: []string{}}
			by[i.VCSRevision] = d
			order = append(order, i.VCSRevision)
		}
		d.Instances++
		seen := false
		for _, h := range d.Hosts {
			seen = seen || h == i.Host
		}
		if !seen && len(d.Hosts) < 10 {
			d.Hosts = append(d.Hosts, i.Host)
		}
	}
	out := make([]appDeployment, 0, len(order))
	for _, r := range order {
		out = append(out, *by[r])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Instances > out[j].Instances })
	return out
}

// normRepoURL reduces a repository URL to host/path in lower case.
func normRepoURL(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	u = strings.Replace(u, ":", "/", 1) // github.com:org/repo (scp form, already stripped of user@)
	u = strings.TrimPrefix(u, "www.")
	u = strings.TrimSuffix(strings.TrimSuffix(u, "/"), ".git")
	u = strings.Replace(u, "/_git/", "/", 1) // Azure DevOps
	return u
}

// repoMatches reports whether a reported repository URL names the linked
// repository ("org/repo", or "org/project/repo" for Azure DevOps). An empty
// URL matches (nothing to contradict the link).
func repoMatches(linkRepo, reported string) bool {
	if reported == "" {
		return true
	}
	r := normRepoURL(reported)
	l := strings.ToLower(strings.Trim(linkRepo, "/"))
	return r == l || strings.HasSuffix(r, "/"+l)
}

func fullRevision(r string) bool { return len(r) == 40 || len(r) == 64 }

// appCommitScanFor finds the latest scan of a commit (a commit scan, or a
// branch scan whose head was that commit).
func appCommitScanFor(ctx context.Context, db *store.DB, connID int64, repo, rev string) ([]SASTFinding, time.Time, bool) {
	var raw []byte
	var at time.Time
	err := db.QueryRowContext(ctx, `
		SELECT findings, scanned_at FROM sast_results
		WHERE connector_id = $1 AND repo = $2 AND commit_sha <> ''
		  AND (commit_sha = $3 OR (length($3) < 40 AND commit_sha LIKE $3 || '%'))
		ORDER BY scanned_at DESC LIMIT 1`, connID, repo, rev).Scan(&raw, &at)
	if err != nil {
		return nil, time.Time{}, false
	}
	var f []SASTFinding
	_ = json.Unmarshal(raw, &f)
	return enrichFindings(ctx, db, connID, f), at, true
}

// appCommitJob returns the newest job for a commit scan.
func appCommitJob(ctx context.Context, db *store.DB, connID int64, repo, rev string) (status, errMsg string, finished time.Time) {
	var e *string
	var fin *time.Time
	if db.QueryRowContext(ctx, `SELECT status, error, finished_at FROM code_scan_jobs
		WHERE connector_id=$1 AND repo=$2 AND kind='commit' AND head_sha=$3 ORDER BY id DESC LIMIT 1`, connID, repo, rev).Scan(&status, &e, &fin) != nil {
		return "", "", time.Time{}
	}
	if e != nil {
		errMsg = *e
	}
	if fin != nil {
		finished = *fin
	}
	return
}

// appResolveDeployments fills the scan state of each deployment of a link.
func appResolveDeployments(ctx context.Context, db *store.DB, l store.ServiceCodeLink, deps []appDeployment) []appDeployment {
	out := make([]appDeployment, len(deps))
	copy(out, deps)
	for i := range out {
		d := &out[i]
		if !repoMatches(l.Repo, d.Repo) {
			d.Mismatch = true
			d.Scan.Status = "repo_mismatch"
			continue
		}
		if fs, at, ok := appCommitScanFor(ctx, db, l.ConnectorID, l.Repo, d.Revision); ok {
			t := at
			d.Scan = appCommitScan{Status: "scanned", ScannedAt: &t, Counts: map[string]int{}}
			for _, f := range fs {
				if !findingDismissed(f) {
					d.Scan.Counts[f.Severity]++
				}
			}
			d.findings = fs
			continue
		}
		if !fullRevision(d.Revision) {
			d.Scan.Status = "short_id"
			continue
		}
		st, msg, _ := appCommitJob(ctx, db, l.ConnectorID, l.Repo, d.Revision)
		switch st {
		case "queued", "running":
			d.Scan.Status = st
		case "failed":
			d.Scan.Status, d.Scan.Error = "failed", msg
		default:
			d.Scan.Status = "none"
		}
	}
	// the primary deployment is the matching one with the most instances
	for i := range out {
		if !out[i].Mismatch {
			out[i].Primary = true
			break
		}
	}
	return out
}

// ── Watcher: scan newly deployed commits ─────────────────────────────────────

type DeployedCommitWatcher struct {
	db, idb *store.DB
	logger  *slog.Logger
}

func NewDeployedCommitWatcher(db, backendDB *store.DB, logger *slog.Logger) *DeployedCommitWatcher {
	return &DeployedCommitWatcher{db: db, idb: appIngestDB(db, backendDB), logger: logger}
}

func (w *DeployedCommitWatcher) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(45 * time.Second):
	}
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		w.sweep(ctx, nil)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sweep queues a scan of every deployed commit of a linked service that has
// none (only the given services when ids is not nil). A commit whose scan
// failed in the last 6 hours is not retried yet.
func (w *DeployedCommitWatcher) sweep(ctx context.Context, ids []int64) int {
	if ids == nil {
		var span *telemetry.Span
		ctx, span = telemetry.StartJob(ctx, "deployed-commit.sweep")
		defer span.End()
	}
	links, err := w.db.ServiceCodeLinks(ctx, ids)
	if err != nil || len(links) == 0 {
		return 0
	}
	svc := map[int64][]store.ServiceCodeLink{}
	var sids []int64
	for _, l := range links {
		if _, ok := svc[l.ServiceID]; !ok {
			sids = append(sids, l.ServiceID)
		}
		svc[l.ServiceID] = append(svc[l.ServiceID], l)
	}
	insts := appLiveInstances(ctx, w.idb, sids, "", time.Now().Add(-runtimeFresh))
	bySvc := map[int64][]appLiveInst{}
	for _, i := range insts {
		bySvc[i.ServiceID] = append(bySvc[i.ServiceID], i)
	}
	queued := 0
	done := map[string]bool{}
	for sid, ls := range svc {
		for _, d := range appDeployments(bySvc[sid]) {
			if !fullRevision(d.Revision) {
				continue
			}
			for _, l := range ls {
				k := l.Repo + "\x00" + d.Revision
				if done[k] || !repoMatches(l.Repo, d.Repo) || queued >= 10 {
					continue
				}
				done[k] = true
				if _, _, ok := appCommitScanFor(ctx, w.db, l.ConnectorID, l.Repo, d.Revision); ok {
					continue
				}
				st, _, fin := appCommitJob(ctx, w.db, l.ConnectorID, l.Repo, d.Revision)
				if st == "queued" || st == "running" || (st == "failed" && time.Since(fin) < 6*time.Hour) {
					continue
				}
				ref := l.Branch
				if ref == "" {
					ref = "HEAD"
				}
				enqueueCodeJob(ctx, w.db, store.CodeScanJob{ConnectorID: l.ConnectorID, Kind: "commit", Trigger: "deployed",
					Repo: l.Repo, Ref: ref, HeadSHA: d.Revision}, w.logger)
				queued++
			}
		}
	}
	return queued
}
