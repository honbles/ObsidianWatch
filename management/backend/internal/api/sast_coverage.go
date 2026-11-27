package api

// sast_coverage.go - how much of a connector's code has been scanned: repositories scanned / repositories the
// provider reports, and branches scanned / branches the provider reports. Branch lists cost one provider call per
// repository, so they are cached for 30 minutes and fetched four at a time, for at most maxCoverageBranchRepos
// repositories (the totals are then marked partial).

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

const (
	maxCoverageBranchRepos = 300
	coverageBranchTTL      = 30 * time.Minute
)

type branchCacheEntry struct {
	names []string
	err   bool
	at    time.Time
}

var (
	coverageBranchMu    sync.Mutex
	coverageBranchCache = map[string]branchCacheEntry{}
)

// cachedBranches is providerBranches with a 30-minute cache per connector and repository.
func cachedBranches(ctx context.Context, conn *store.DevOpsConnector, repo string) ([]string, bool) {
	key := strconv.FormatInt(conn.ID, 10) + "/" + repo
	coverageBranchMu.Lock()
	e, ok := coverageBranchCache[key]
	coverageBranchMu.Unlock()
	if ok && time.Since(e.at) < coverageBranchTTL {
		return e.names, !e.err
	}
	names, err := providerBranches(ctx, conn, repo)
	coverageBranchMu.Lock()
	coverageBranchCache[key] = branchCacheEntry{names: names, err: err != nil, at: time.Now()}
	coverageBranchMu.Unlock()
	return names, err == nil
}

type repoCoverage struct {
	Repo            string    `json:"repo"`
	DefaultBranch   string    `json:"default_branch"`
	Scanned         bool      `json:"scanned"`
	LastScan        time.Time `json:"last_scan,omitzero"`
	BranchesTotal   int       `json:"branches_total"` // 0 when unknown
	BranchesScanned int       `json:"branches_scanned"`
	BranchesKnown   bool      `json:"branches_known"`
}

type sastCoverage struct {
	ReposTotal      int            `json:"repos_total"`
	ReposScanned    int            `json:"repos_scanned"`
	BranchesTotal   int            `json:"branches_total"`
	BranchesScanned int            `json:"branches_scanned"`
	BranchesPartial bool           `json:"branches_partial"` // some repositories' branch lists could not be read
	ReposPartial    bool           `json:"repos_partial"`    // the provider's repository list could not be read
	Repos           []repoCoverage `json:"repos"`
}

// scannedBranches returns, per repository, the branches with a stored result and the newest scan time. "HEAD" and
// "" stand for the default branch.
func scannedBranches(ctx context.Context, db *store.DB, connID int64) (map[string]map[string]bool, map[string]time.Time) {
	byRepo, last := map[string]map[string]bool{}, map[string]time.Time{}
	rows, err := db.QueryContext(ctx, `SELECT repo, COALESCE(branch,''), MAX(scanned_at) FROM sast_results
		WHERE connector_id=$1 AND repo<>'' AND COALESCE(branch,'') NOT LIKE '@%' GROUP BY 1, 2`, connID)
	if err != nil {
		return byRepo, last
	}
	defer rows.Close()
	for rows.Next() {
		var repo, branch string
		var at time.Time
		if rows.Scan(&repo, &branch, &at) != nil {
			continue
		}
		if byRepo[repo] == nil {
			byRepo[repo] = map[string]bool{}
		}
		byRepo[repo][branch] = true
		if at.After(last[repo]) {
			last[repo] = at
		}
	}
	return byRepo, last
}

func computeSASTCoverage(ctx context.Context, db *store.DB, conn *store.DevOpsConnector, logger *slog.Logger) sastCoverage {
	repos := listConnectorRepos(ctx, db, conn, logger)
	scanned, last := scannedBranches(ctx, db, conn.ID)
	reposPartial := false
	if len(repos) == 0 && len(scanned) > 0 {
		// The provider could not be reached and no commits are stored: count what was scanned, marked partial,
		// rather than 0 of 0.
		reposPartial = true
		for repo := range scanned {
			if repoInConnectorScope(conn, repo) {
				repos = append(repos, sastRepoInfo{Repo: repo, Branch: "HEAD"})
			}
		}
		sort.Slice(repos, func(i, j int) bool { return repos[i].Repo < repos[j].Repo })
	}
	cov := sastCoverage{Repos: make([]repoCoverage, len(repos)), ReposPartial: reposPartial}
	listed := map[string]bool{}
	for i, r := range repos {
		listed[r.Repo] = true
		cov.Repos[i] = repoCoverage{Repo: r.Repo, DefaultBranch: r.Branch, Scanned: len(scanned[r.Repo]) > 0, LastScan: last[r.Repo]}
	}
	// A scanned repository the provider no longer lists (deleted, renamed, access removed) is not counted: the
	// coverage is of what exists now.

	// Branch totals, four repositories at a time, the most recently scanned first.
	order := make([]int, len(cov.Repos))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return cov.Repos[order[a]].LastScan.After(cov.Repos[order[b]].LastScan) })
	if len(order) > maxCoverageBranchRepos {
		order = order[:maxCoverageBranchRepos]
		cov.BranchesPartial = true
	}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, i := range order {
		wg.Add(1)
		sem <- struct{}{}
		go func(rc *repoCoverage) {
			defer wg.Done()
			defer func() { <-sem }()
			names, ok := cachedBranches(ctx, conn, rc.Repo)
			if !ok {
				return
			}
			rc.BranchesKnown, rc.BranchesTotal = true, len(names)
			exists := map[string]bool{}
			for _, n := range names {
				exists[n] = true
			}
			for b := range scanned[rc.Repo] {
				name := b
				if name == "" || name == "HEAD" {
					name = rc.DefaultBranch
				}
				if exists[name] || name == "HEAD" {
					rc.BranchesScanned++
				}
			}
			if rc.BranchesScanned > rc.BranchesTotal {
				rc.BranchesScanned = rc.BranchesTotal
			}
		}(&cov.Repos[i])
	}
	wg.Wait()

	cov.ReposTotal = len(cov.Repos)
	for _, rc := range cov.Repos {
		if rc.Scanned {
			cov.ReposScanned++
		}
		if rc.BranchesKnown {
			cov.BranchesTotal += rc.BranchesTotal
			cov.BranchesScanned += rc.BranchesScanned
		} else {
			// The branch list could not be read: the scanned branches are counted, and the total is at least
			// that many (marked partial).
			n := len(scanned[rc.Repo])
			cov.BranchesTotal += n
			cov.BranchesScanned += n
			cov.BranchesPartial = true
		}
	}
	return cov
}

// handleSASTCoverage: GET /api/v1/devops-connectors/{id}/sast/coverage.
func handleSASTCoverage(db *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		conn, err := db.GetDevOpsConnectorRaw(r.Context(), connID)
		if err != nil || conn == nil {
			writeJSON(w, 404, map[string]string{"error": "connector not found"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		writeJSON(w, 200, computeSASTCoverage(ctx, db, conn, logger))
	}
}
