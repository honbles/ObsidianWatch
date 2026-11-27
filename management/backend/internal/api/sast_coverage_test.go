package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"obsidianwatch/management/internal/store"
)

// hostRewrite sends every request to the test server, whatever host it names.
type hostRewrite struct{ target *url.URL }

func (h hostRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = h.target.Scheme, h.target.Host
	return http.DefaultTransport.RoundTrip(r)
}

// TestSASTCoverage: OW_TEST_COVERAGE_DSN must name a disposable database (its connectors and SAST results are deleted).
func TestSASTCoverage(t *testing.T) {
	dsn := os.Getenv("OW_TEST_COVERAGE_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_COVERAGE_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ctx := context.Background()
	// Only the migrations of the two tables used here (the full set needs the ingest backend's tables).
	for _, f := range []string{"015_devops_connectors.sql", "018_code_scan.sql", "020_sast_per_repo.sql",
		"075_sast_engines.sql", "081_sast_commit.sql"} {
		b, err := os.ReadFile("../store/migrations/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	_, _ = raw.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS uq_devops_connectors_provider_org ON devops_connectors (provider, org)`) // from 028
	db := &store.DB{DB: raw}
	_, _ = raw.Exec(`DELETE FROM sast_results`)
	_, _ = raw.Exec(`DELETE FROM devops_connectors`)
	id, _, err := db.UpsertDevOpsConnector(ctx, "github", "acme", "t", map[string]string{"token": "T"}, "s")
	if err != nil {
		t.Fatal(err)
	}
	// 150 repositories over two pages (only the first page used to be read); api has 3 branches, web 2.
	gh := http.NewServeMux()
	gh.HandleFunc("/orgs/acme/repos", func(w http.ResponseWriter, r *http.Request) {
		var out []map[string]string
		start, n := 0, 100
		if r.URL.Query().Get("page") == "2" {
			start, n = 100, 50
		} else if r.URL.Query().Get("page") != "1" {
			n = 0
		}
		for i := start; i < start+n; i++ {
			name := fmt.Sprintf("acme/r%03d", i)
			if i == 0 {
				name = "acme/api"
			} else if i == 1 {
				name = "acme/web"
			}
			out = append(out, map[string]string{"full_name": name, "default_branch": "main"})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	gh.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"full_name":"someone/else","default_branch":"main"}]`))
	})
	gh.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/acme/api/branches"):
			_, _ = w.Write([]byte(`[{"name":"main"},{"name":"dev"},{"name":"release"}]`))
		case strings.HasPrefix(r.URL.Path, "/repos/acme/web/branches"):
			_, _ = w.Write([]byte(`[{"name":"main"},{"name":"feature"}]`))
		default:
			_, _ = w.Write([]byte(`[{"name":"main"}]`))
		}
	})
	srv := httptest.NewServer(gh)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	old := devopsHTTP
	devopsHTTP = &http.Client{Transport: hostRewrite{u}}
	defer func() { devopsHTTP = old }()
	coverageBranchCache = map[string]branchCacheEntry{}

	conn, _ := db.GetDevOpsConnectorRaw(ctx, id)
	for _, rb := range [][2]string{{"acme/api", "HEAD"}, {"acme/api", "dev"}, {"acme/api", "gone"}, {"acme/web", "main"}, {"", "HEAD"}, {"acme/api", "@abc123"}, {"other/x", "HEAD"}} {
		if err := saveSASTResult(ctx, db, id, rb[0], rb[1], "", engineReport{}, nil, nil, 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	c := computeSASTCoverage(ctx, db, conn, slog.Default())
	if c.ReposTotal != 150 || c.ReposScanned != 2 {
		t.Fatalf("repos %d/%d, want 2/150", c.ReposScanned, c.ReposTotal)
	}
	// Branches: api 2 of 3 (HEAD=main, dev; "gone" no longer exists), web 1 of 2, 148 others 0 of 1.
	if c.BranchesTotal != 3+2+148 || c.BranchesScanned != 3 || c.BranchesPartial {
		t.Fatalf("branches %d/%d partial=%v", c.BranchesScanned, c.BranchesTotal, c.BranchesPartial)
	}
}
