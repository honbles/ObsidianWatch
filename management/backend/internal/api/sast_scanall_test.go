package api

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestMergeEngineReportAcrossRepos(t *testing.T) {
	agg := engineReport{}
	mergeEngineReport(agg, engineReport{"source": "git", "codeql": "ran", "codeql-languages": "javascript", "semgrep": "ran"}, "acme/web")
	mergeEngineReport(agg, engineReport{"source": "git", "codeql": "failed: database create: exit status 2: python extractor error", "semgrep": "ran"}, "acme/etl")
	mergeEngineReport(agg, engineReport{"source": "api", "codeql": "ran", "codeql-languages": "go,javascript", "codeql-failed": "python: boom"}, "acme/api")
	if agg["codeql"] != "ran" || agg["codeql-languages"] != "go,javascript" || agg["source"] != "git+api" {
		t.Fatalf("%v", agg)
	}
	if !strings.Contains(agg["codeql-failed"], "acme/etl: database create") || !strings.Contains(agg["codeql-failed"], "acme/api: python: boom") {
		t.Fatalf("failures per repository: %q", agg["codeql-failed"])
	}
	one := engineReport{}
	mergeEngineReport(one, engineReport{"codeql": "failed: x"}, "r")
	if !strings.HasPrefix(one["codeql"], "failed") {
		t.Fatal("failed everywhere stays failed")
	}
}

func TestToolErrTextKeepsTheReason(t *testing.T) {
	out := "Initializing database at /tmp/x.codeql-python.\nRunning build command: []\n" + strings.Repeat("[2026] progress line\n", 200) +
		"A fatal error occurred: Exit status 1 from command: [python3, setup.py]\nERROR: No Python 3 interpreter found\n"
	s := toolErrText([]byte(out))
	if !strings.Contains(s, "No Python 3 interpreter found") || strings.Contains(s, "Initializing database") {
		t.Fatalf("%q", s)
	}
	if s := toolErrText([]byte("short and plain")); s != "short and plain" {
		t.Fatal(s)
	}
}

func TestCorrelateAllRepos(t *testing.T) {
	dsn := os.Getenv("OW_TEST_COVERAGE_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_COVERAGE_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, f := range []string{"011_settings.sql", "015_devops_connectors.sql", "018_code_scan.sql", "020_sast_per_repo.sql",
		"075_sast_engines.sql", "078_code_triage.sql", "081_sast_commit.sql", "085_sast_correlation.sql"} {
		b, _ := os.ReadFile("../store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	_, _ = raw.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS uq_devops_connectors_provider_org ON devops_connectors (provider, org)`)
	db := &store.DB{DB: raw}
	ctx := context.Background()
	cid, _, err := db.UpsertDevOpsConnector(ctx, "github", "corr-all", "t", map[string]string{"token": "T"}, "s")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = raw.Exec(`DELETE FROM sast_results WHERE connector_id=$1`, cid)
	_ = db.SetSetting(ctx, "ai.anthropic_api_key", "")
	_ = db.SetSetting(ctx, "ai.send_source_snippets", "false")
	if _, err := correlateAllRepos(ctx, nil, db, cid, false); err == nil {
		t.Fatal("without an AI key the whole run is refused up front")
	}
	two := engineReport{"builtin": "ran", "semgrep": "ran"}
	_ = saveSASTResult(ctx, db, cid, "corr/a", "HEAD", "a", two, corrSample(), nil, 1, 1)
	_ = saveSASTResult(ctx, db, cid, "corr/b", "HEAD", "b", engineReport{"builtin": "ran"}, corrSample()[:1], nil, 1, 1)
	_ = saveSASTResult(ctx, db, cid, "", "HEAD", "", two, append(corrSample(), corrSample()[0]), nil, 2, 2)
	// Undo with nothing correlated is a no-op that still rebuilds the all-repos row.
	out, err := correlateAllRepos(ctx, nil, db, cid, true)
	if err != nil || out["done"].(int) != 0 {
		t.Fatalf("%v %v", err, out)
	}
	var n int
	_ = raw.QueryRow(`SELECT finding_count FROM sast_results WHERE connector_id=$1 AND repo=''`, cid).Scan(&n)
	if n != len(corrSample())+1 {
		t.Fatalf("all-repos row rebuilt from the repositories: %d", n)
	}
	_, _ = raw.Exec(`DELETE FROM sast_results WHERE connector_id=$1`, cid)
}

func TestSensitiveFilesFromOldCommitScan(t *testing.T) {
	hit := func(f string) bool {
		for _, p := range sensitiveFilePatterns {
			if matchesGlob(f, p) {
				return true
			}
		}
		return false
	}
	for _, f := range []string{"infra/terraform.tfstate", "deploy/kubeconfig", "wp-config.php"} {
		if !hit(f) {
			t.Errorf("%s should still be flagged at sync time", f)
		}
	}
	if hit("wp-config.php.sample") || hit("src/kubeconfig.go") {
		t.Error("samples and look-alike names must not match")
	}
}

func TestGitLabProjectsExplainsEmptyList(t *testing.T) {
	t.Setenv("OW_ALLOW_PRIVATE_DEVOPS", "true")
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/groups/") {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`[]`))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"message":"404 Not Found"}`))
	}))
	defer srv.Close()
	c := &gitlabClient{token: "t", baseURL: srv.URL}
	if _, err := gitlabProjects(context.Background(), c, "ITH-group"); err == nil || !strings.Contains(err.Error(), "member (Reporter or above)") {
		t.Fatalf("empty group: %v", err)
	}
	status = 403
	if _, err := gitlabProjects(context.Background(), c, "ITH-group"); err == nil || !strings.Contains(err.Error(), "auth error 403") {
		t.Fatalf("forbidden group: %v", err)
	}
}
