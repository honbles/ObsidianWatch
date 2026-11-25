package api

// sast_branches.go - branch list for the SAST tab's Branch dropdown.
// GET /api/v1/devops-connectors/{id}/sast/branches?repo=<full name>
// returns the repository's branches from the provider (up to 300, default
// first) and, for each, when it was last scanned.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type branchInfo struct {
	Name      string     `json:"name"`
	Default   bool       `json:"default,omitempty"`
	ScannedAt *time.Time `json:"scanned_at,omitempty"`
}

// providerBranches lists branch names from the provider.
func providerBranches(ctx context.Context, conn *store.DevOpsConnector, repo string) ([]string, error) {
	token := conn.Credentials["token"]
	var names []string
	switch conn.Provider {
	case "github":
		h := map[string]string{"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"}
		for page := 1; page <= 3; page++ {
			var b []struct{ Name string }
			if err := devopsJSON(ctx, "GET", fmt.Sprintf("https://api.github.com/repos/%s/branches?per_page=100&page=%d", repo, page), h, nil, &b); err != nil {
				if page == 1 {
					return nil, err
				}
				break
			}
			for _, x := range b {
				names = append(names, x.Name)
			}
			if len(b) < 100 {
				break
			}
		}
	case "gitlab":
		base := strings.TrimRight(conn.Credentials["base_url"], "/")
		if base == "" {
			base = "https://gitlab.com"
		}
		c := &gitlabClient{token: token, baseURL: base}
		b, err := gitlabGetAll[struct{ Name string }](ctx, c, "/api/v4/projects/"+gitlabID(repo)+"/repository/branches?per_page=100", 3)
		if err != nil {
			return nil, err
		}
		for _, x := range b {
			names = append(names, x.Name)
		}
	case "azuredevops":
		parts := strings.SplitN(repo, "/", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("bad repository %q", repo)
		}
		c := adoClientFor(conn)
		var resp struct {
			Value []struct{ Name string } `json:"value"`
		}
		h := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+token))}
		u := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/refs?filter=heads/&$top=300&api-version=7.0", c.baseURL, neturl.PathEscape(parts[1]), neturl.PathEscape(parts[2]))
		if err := devopsJSON(ctx, "GET", u, h, nil, &resp); err != nil {
			return nil, err
		}
		for _, x := range resp.Value {
			names = append(names, strings.TrimPrefix(x.Name, "refs/heads/"))
		}
	}
	return names, nil
}

func handleListSASTBranches(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		repo := r.URL.Query().Get("repo")
		if err != nil || repo == "" {
			writeJSON(w, 400, map[string]string{"error": "connector id and repo are required"})
			return
		}
		def := r.URL.Query().Get("default")
		conn, err := db.GetDevOpsConnectorRaw(r.Context(), connID)
		if err != nil || conn == nil {
			writeJSON(w, 404, map[string]string{"error": "connector not found"})
			return
		}
		names, perr := providerBranches(r.Context(), conn, repo)
		// Last scan per branch; "HEAD" is the default branch.
		scanned := map[string]time.Time{}
		if rows, err := db.QueryContext(r.Context(), `SELECT COALESCE(branch,''), MAX(scanned_at) FROM sast_results
			WHERE connector_id=$1 AND repo=$2 AND branch NOT LIKE '@%' GROUP BY 1`, connID, repo); err == nil {
			for rows.Next() {
				var b string
				var t time.Time
				if rows.Scan(&b, &t) == nil {
					if b == "" || b == "HEAD" {
						b = def
					}
					if t.After(scanned[b]) {
						scanned[b] = t
					}
				}
			}
			rows.Close()
		}
		seen := map[string]bool{}
		var out []branchInfo
		add := func(n string) {
			if n == "" || seen[n] {
				return
			}
			seen[n] = true
			bi := branchInfo{Name: n, Default: n == def}
			if t, ok := scanned[n]; ok {
				t := t
				bi.ScannedAt = &t
			}
			out = append(out, bi)
		}
		add(def)
		for _, n := range names {
			add(n)
		}
		for n := range scanned { // scanned branches the provider no longer lists
			add(n)
		}
		if len(out) > 300 {
			out = out[:300]
		}
		sort.SliceStable(out[min(1, len(out)):], func(i, j int) bool {
			a, b := out[1+i], out[1+j]
			if (a.ScannedAt != nil) != (b.ScannedAt != nil) {
				return a.ScannedAt != nil
			}
			return a.Name < b.Name
		})
		resp := map[string]interface{}{"branches": out}
		if perr != nil {
			resp["warning"] = "could not list branches from the provider: " + perr.Error()
		}
		writeJSON(w, 200, resp)
	}
}
