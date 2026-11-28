package api

// sast_commits.go - commit scans in the SAST tab.
//
// A branch scan replaces the branch's stored result; it is what findings,
// automation and fix pull requests use. A commit scan (POST /sast with
// ?commit=<sha>) scans exactly that commit and is stored as branch "@<sha>",
// never overwritten by later scans and never shown as current findings. The
// newest OW_SAST_COMMIT_SCANS_KEEP (default 50) per repository are kept, plus
// every pinned one.
//
//	GET  /sast/commits?repo=&branch=        recent commits of a branch (provider) and whether each was scanned
//	GET  /sast/commit-scans?repo=           the repository's stored commit scans
//	POST /sast/commit-scans/pin?repo=&sha=&pinned=1|0
//	DELETE /sast/commit-scans?repo=&sha=
//	GET  /sast/commit-scans/compare?repo=&sha=&branch=   fixed since / new since the commit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// commitScansKeep is how many unpinned commit scans a repository keeps.
func commitScansKeep() int {
	if n, err := strconv.Atoi(os.Getenv("OW_SAST_COMMIT_SCANS_KEEP")); err == nil && n > 0 {
		return min(n, 1000)
	}
	return 50
}

// pruneCommitScans drops the oldest unpinned commit scans of a repository.
func pruneCommitScans(ctx context.Context, db *store.DB, connID int64, repo string) {
	_, _ = db.ExecContext(ctx, `DELETE FROM sast_results WHERE connector_id=$1 AND repo=$2 AND branch LIKE '@%' AND NOT pinned AND id NOT IN (
		SELECT id FROM sast_results WHERE connector_id=$1 AND repo=$2 AND branch LIKE '@%' AND NOT pinned ORDER BY scanned_at DESC LIMIT $3)`,
		connID, repo, commitScansKeep())
}

// recordCommitScan stores which branch a commit scan was picked from and the
// commit's message and author (read from the checkout).
func recordCommitScan(ctx context.Context, db *store.DB, connID int64, repo, sha, ofBranch, msg, author string) {
	_, _ = db.ExecContext(ctx, `UPDATE sast_results SET of_branch=$4,
		commit_message=CASE WHEN $5<>'' THEN $5 ELSE commit_message END,
		commit_author=CASE WHEN $6<>'' THEN $6 ELSE commit_author END
		WHERE connector_id=$1 AND repo=$2 AND branch=$3`, connID, repo, "@"+sha, ofBranch, truncRunes(msg, 300), truncRunes(author, 120))
}

// gitCommitMeta is the subject line and author of the checked-out commit.
func gitCommitMeta(ctx context.Context, dir string) (msg, author string) {
	if out, err := exec.CommandContext(ctx, "git", "-C", dir, "log", "-1", "--format=%s%x00%an").Output(); err == nil {
		if p := strings.SplitN(strings.TrimSpace(string(out)), "\x00", 2); len(p) == 2 {
			return p[0], p[1]
		}
	}
	return "", ""
}

func truncRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

type commitInfo struct {
	SHA       string     `json:"sha"`
	Message   string     `json:"message"`
	Author    string     `json:"author"`
	Date      *time.Time `json:"date,omitempty"`
	ScannedAt *time.Time `json:"scanned_at,omitempty"`
}

// providerCommits lists the newest commits of a branch ("" or HEAD = the
// default branch), at most n.
func providerCommits(ctx context.Context, conn *store.DevOpsConnector, repo, branch string, n int) ([]commitInfo, error) {
	token := conn.Credentials["token"]
	if branch == "HEAD" {
		branch = ""
	}
	var out []commitInfo
	switch conn.Provider {
	case "github":
		h := map[string]string{"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"}
		u := fmt.Sprintf("https://api.github.com/repos/%s/commits?per_page=%d", repo, n)
		if branch != "" {
			u += "&sha=" + neturl.QueryEscape(branch)
		}
		var cs []struct {
			SHA    string `json:"sha"`
			Commit struct {
				Message string `json:"message"`
				Author  struct {
					Name string    `json:"name"`
					Date time.Time `json:"date"`
				} `json:"author"`
			} `json:"commit"`
		}
		if err := devopsJSON(ctx, "GET", u, h, nil, &cs); err != nil {
			return nil, err
		}
		for _, c := range cs {
			d := c.Commit.Author.Date
			out = append(out, commitInfo{SHA: c.SHA, Message: c.Commit.Message, Author: c.Commit.Author.Name, Date: &d})
		}
	case "gitlab":
		base := strings.TrimRight(conn.Credentials["base_url"], "/")
		if base == "" {
			base = "https://gitlab.com"
		}
		c := &gitlabClient{token: token, baseURL: base}
		p := fmt.Sprintf("/api/v4/projects/%s/repository/commits?per_page=%d", gitlabID(repo), n)
		if branch != "" {
			p += "&ref_name=" + neturl.QueryEscape(branch)
		}
		cs, err := gitlabGetAll[struct {
			ID         string    `json:"id"`
			Title      string    `json:"title"`
			AuthorName string    `json:"author_name"`
			Created    time.Time `json:"created_at"`
		}](ctx, c, p, 1)
		if err != nil {
			return nil, err
		}
		for _, x := range cs {
			d := x.Created
			out = append(out, commitInfo{SHA: x.ID, Message: x.Title, Author: x.AuthorName, Date: &d})
		}
	case "azuredevops":
		parts := strings.SplitN(repo, "/", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("bad repository %q", repo)
		}
		c := adoClientFor(conn)
		u := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/commits?$top=%d&api-version=7.0", c.baseURL, neturl.PathEscape(parts[1]), neturl.PathEscape(parts[2]), n)
		if branch != "" {
			u += "&searchCriteria.itemVersion.version=" + neturl.QueryEscape(branch)
		}
		var resp struct {
			Value []struct {
				CommitID string `json:"commitId"`
				Comment  string `json:"comment"`
				Author   struct {
					Name string    `json:"name"`
					Date time.Time `json:"date"`
				} `json:"author"`
			} `json:"value"`
		}
		h := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+token))}
		if err := devopsJSON(ctx, "GET", u, h, nil, &resp); err != nil {
			return nil, err
		}
		for _, x := range resp.Value {
			d := x.Author.Date
			out = append(out, commitInfo{SHA: x.CommitID, Message: x.Comment, Author: x.Author.Name, Date: &d})
		}
	default:
		return nil, fmt.Errorf("provider %q not supported", conn.Provider)
	}
	for i := range out {
		out[i].Message = truncRunes(strings.SplitN(strings.TrimSpace(out[i].Message), "\n", 2)[0], 200)
	}
	return out, nil
}

// commitScanConn resolves the connector and repository of a commit-scan request.
func commitScanConn(w http.ResponseWriter, r *http.Request, db *store.DB) (*store.DevOpsConnector, string, bool) {
	connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	repo := r.URL.Query().Get("repo")
	if err != nil || repo == "" {
		writeJSON(w, 400, map[string]string{"error": "connector id and repo are required"})
		return nil, "", false
	}
	conn, err := db.GetDevOpsConnectorRaw(r.Context(), connID)
	if err != nil || conn == nil {
		writeJSON(w, 404, map[string]string{"error": "connector not found"})
		return nil, "", false
	}
	if !repoInConnectorScope(conn, repo) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "repository is outside this connector's organization"})
		return nil, "", false
	}
	return conn, repo, true
}

func handleListBranchCommits(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, repo, ok := commitScanConn(w, r, db)
		if !ok {
			return
		}
		commits, perr := providerCommits(r.Context(), conn, repo, r.URL.Query().Get("branch"), 30)
		scanned := map[string]time.Time{}
		if rows, err := db.QueryContext(r.Context(), `SELECT substr(branch,2), scanned_at FROM sast_results
			WHERE connector_id=$1 AND repo=$2 AND branch LIKE '@%'`, conn.ID, repo); err == nil {
			for rows.Next() {
				var s string
				var t time.Time
				if rows.Scan(&s, &t) == nil {
					scanned[s] = t
				}
			}
			rows.Close()
		}
		for i := range commits {
			if t, ok := scanned[commits[i].SHA]; ok {
				t := t
				commits[i].ScannedAt = &t
			}
		}
		if commits == nil {
			commits = []commitInfo{}
		}
		resp := map[string]interface{}{"commits": commits}
		if perr != nil {
			resp["warning"] = "could not list commits from the provider: " + perr.Error()
		}
		writeJSON(w, 200, resp)
	}
}

type commitScanRow struct {
	SHA           string    `json:"sha"`
	Branch        string    `json:"branch"`
	Message       string    `json:"message"`
	Author        string    `json:"author"`
	ScannedAt     time.Time `json:"scanned_at"`
	Engine        string    `json:"engine"`
	FindingCount  int       `json:"finding_count"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	MediumCount   int       `json:"medium_count"`
	Pinned        bool      `json:"pinned"`
}

func handleListCommitScans(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, repo, ok := commitScanConn(w, r, db)
		if !ok {
			return
		}
		rows, err := db.QueryContext(r.Context(), `SELECT substr(branch,2), of_branch, commit_message, commit_author, scanned_at,
			COALESCE(engine,''), finding_count, critical_count, high_count, medium_count, pinned
			FROM sast_results WHERE connector_id=$1 AND repo=$2 AND branch LIKE '@%'
			ORDER BY pinned DESC, scanned_at DESC`, conn.ID, repo)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		defer rows.Close()
		out := []commitScanRow{}
		for rows.Next() {
			var c commitScanRow
			if rows.Scan(&c.SHA, &c.Branch, &c.Message, &c.Author, &c.ScannedAt, &c.Engine,
				&c.FindingCount, &c.CriticalCount, &c.HighCount, &c.MediumCount, &c.Pinned) == nil {
				out = append(out, c)
			}
		}
		writeJSON(w, 200, map[string]interface{}{"commit_scans": out, "keep": commitScansKeep()})
	}
}

func handlePinCommitScan(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, repo, ok := commitScanConn(w, r, db)
		if !ok {
			return
		}
		sha := r.URL.Query().Get("sha")
		pinned := r.URL.Query().Get("pinned") != "0"
		res, err := db.ExecContext(r.Context(), `UPDATE sast_results SET pinned=$4 WHERE connector_id=$1 AND repo=$2 AND branch=$3`,
			conn.ID, repo, "@"+sha, pinned)
		if n, _ := res.RowsAffected(); err != nil || n == 0 {
			writeJSON(w, 404, map[string]string{"error": "commit scan not found"})
			return
		}
		if !pinned {
			pruneCommitScans(r.Context(), db, conn.ID, repo)
		}
		writeJSON(w, 200, map[string]interface{}{"sha": sha, "pinned": pinned})
	}
}

func handleDeleteCommitScan(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, repo, ok := commitScanConn(w, r, db)
		if !ok {
			return
		}
		sha := r.URL.Query().Get("sha")
		if sha == "" {
			writeJSON(w, 400, map[string]string{"error": "sha is required"})
			return
		}
		res, err := db.ExecContext(r.Context(), `DELETE FROM sast_results WHERE connector_id=$1 AND repo=$2 AND branch=$3`, conn.ID, repo, "@"+sha)
		if n, _ := res.RowsAffected(); err != nil || n == 0 {
			writeJSON(w, 404, map[string]string{"error": "commit scan not found"})
			return
		}
		writeJSON(w, 200, map[string]string{"deleted": sha})
	}
}

// compareFindings splits findings into those only in the commit scan (fixed
// since: no longer on the branch), only on the branch (new since) and in both,
// matched by fingerprint (rule, file and code, not the line number).
func compareFindings(commit, branch []SASTFinding) (fixed, added []SASTFinding, same int) {
	key := func(f SASTFinding) string {
		if f.Fingerprint != "" {
			return f.Fingerprint
		}
		return findingFingerprint(f)
	}
	inBranch := map[string]int{}
	for _, f := range branch {
		inBranch[key(f)]++
	}
	inCommit := map[string]int{}
	for _, f := range commit {
		k := key(f)
		inCommit[k]++
		if inBranch[k] > 0 {
			inBranch[k]--
			same++
		} else {
			fixed = append(fixed, f)
		}
	}
	for _, f := range branch {
		k := key(f)
		if inCommit[k] > 0 {
			inCommit[k]--
		} else {
			added = append(added, f)
		}
	}
	sevSort := func(fs []SASTFinding) {
		sort.SliceStable(fs, func(i, j int) bool { return sevRank(fs[i].Severity) > sevRank(fs[j].Severity) })
	}
	sevSort(fixed)
	sevSort(added)
	return fixed, added, same
}

func handleCompareCommitScan(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, repo, ok := commitScanConn(w, r, db)
		if !ok {
			return
		}
		sha := r.URL.Query().Get("sha")
		branch := r.URL.Query().Get("branch")
		var cj []byte
		var cAt time.Time
		var ofBranch, cEngine string
		if err := db.QueryRowContext(r.Context(), `SELECT findings, scanned_at, of_branch, COALESCE(engine,'') FROM sast_results
			WHERE connector_id=$1 AND repo=$2 AND branch=$3`, conn.ID, repo, "@"+sha).Scan(&cj, &cAt, &ofBranch, &cEngine); err != nil {
			writeJSON(w, 404, map[string]string{"error": "commit scan not found"})
			return
		}
		if branch == "" {
			branch = ofBranch
		}
		if branch == "" {
			branch = "HEAD"
		}
		var bj []byte
		var bAt time.Time
		var bEngine string
		if err := db.QueryRowContext(r.Context(), `SELECT findings, scanned_at, COALESCE(engine,'') FROM sast_results
			WHERE connector_id=$1 AND repo=$2 AND branch=$3`, conn.ID, repo, branch).Scan(&bj, &bAt, &bEngine); err != nil {
			writeJSON(w, 404, map[string]string{"error": "branch " + branch + " has not been scanned yet: scan it first"})
			return
		}
		var cf, bf []SASTFinding
		_ = json.Unmarshal(cj, &cf)
		_ = json.Unmarshal(bj, &bf)
		fixed, added, same := compareFindings(cf, bf)
		if fixed == nil {
			fixed = []SASTFinding{}
		}
		if added == nil {
			added = []SASTFinding{}
		}
		resp := map[string]interface{}{
			"sha": sha, "branch": branch, "commit_scanned_at": cAt, "branch_scanned_at": bAt,
			"fixed": fixed, "new": added, "unchanged": same,
		}
		if cEngine != bEngine {
			resp["warning"] = "the two scans used different engines (" + cEngine + " vs " + bEngine + "): differences can come from the engines, not the code"
		}
		writeJSON(w, 200, resp)
	}
}
