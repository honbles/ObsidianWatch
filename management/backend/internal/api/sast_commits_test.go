package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestCompareFindingsIgnoresLineMoves(t *testing.T) {
	a := SASTFinding{RuleID: "R1", File: "a.go", Line: 10, Severity: "high", Title: "SQL injection"}
	b := SASTFinding{RuleID: "R2", File: "b.go", Line: 3, Severity: "low", Title: "Weak hash"}
	c := SASTFinding{RuleID: "R3", File: "c.go", Line: 7, Severity: "critical", Title: "Secret"}
	moved := a
	moved.Line = 42
	fixed, added, same := compareFindings([]SASTFinding{a, b}, []SASTFinding{moved, c})
	if same != 1 || len(fixed) != 1 || fixed[0].RuleID != "R2" || len(added) != 1 || added[0].RuleID != "R3" {
		t.Fatalf("fixed=%v new=%v same=%d", fixed, added, same)
	}
	// Two identical findings in the commit, one left on the branch: one fixed.
	fixed, _, same = compareFindings([]SASTFinding{b, b}, []SASTFinding{b})
	if same != 1 || len(fixed) != 1 {
		t.Fatalf("duplicates counted: fixed=%d same=%d", len(fixed), same)
	}
}

func TestCommitScansKeepAndPin(t *testing.T) {
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
		"075_sast_engines.sql", "078_code_triage.sql", "081_sast_commit.sql", "085_sast_correlation.sql", "087_sast_commit_scans.sql"} {
		b, _ := os.ReadFile("../store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	_, _ = raw.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS uq_devops_connectors_provider_org ON devops_connectors (provider, org)`)
	db := &store.DB{DB: raw}
	ctx := context.Background()
	cid, _, err := db.UpsertDevOpsConnector(ctx, "github", "commit-keep", "t", map[string]string{"token": "T"}, "s")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = raw.Exec(`DELETE FROM sast_results WHERE connector_id=$1`, cid)
	t.Setenv("OW_SAST_COMMIT_SCANS_KEEP", "3")
	sha := func(i int) string { return fmt.Sprintf("%040x", i) }
	f1 := []SASTFinding{{RuleID: "R1", File: "a.go", Severity: "high", Title: "x"}}
	for i := 1; i <= 2; i++ {
		_ = saveSASTResult(ctx, db, cid, "commit-keep/web", "@"+sha(i), sha(i), engineReport{"builtin": "ran"}, f1, nil, 1, 1)
		_, _ = raw.Exec(`UPDATE sast_results SET scanned_at = NOW() - make_interval(hours => $2) WHERE connector_id=$1 AND branch=$3`, cid, 100-i, "@"+sha(i))
	}
	recordCommitScan(ctx, db, cid, "commit-keep/web", sha(1), "main", "first commit", "Ada")
	srv := http.NewServeMux()
	srv.HandleFunc("POST /c/{id}/pin", handlePinCommitScan(db))
	srv.HandleFunc("GET /c/{id}/list", handleListCommitScans(db))
	srv.HandleFunc("GET /c/{id}/compare", handleCompareCommitScan(db))
	call := func(method, path string) (int, map[string]interface{}) {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(method, fmt.Sprintf("/c/%d/%s", cid, path), nil))
		var m map[string]interface{}
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	if code, _ := call("POST", "pin?repo=commit-keep/web&sha="+sha(1)); code != 200 {
		t.Fatal("pin", code)
	}
	for i := 3; i <= 6; i++ {
		_ = saveSASTResult(ctx, db, cid, "commit-keep/web", "@"+sha(i), sha(i), engineReport{"builtin": "ran"}, nil, nil, 1, 1)
	}
	_, m := call("GET", "list?repo=commit-keep/web")
	list := m["commit_scans"].([]interface{})
	if len(list) != 4 { // the pinned one plus the 3 newest
		t.Fatalf("kept %d: %v", len(list), list)
	}
	first := list[0].(map[string]interface{})
	if first["sha"] != sha(1) || first["pinned"] != true || first["message"] != "first commit" || first["branch"] != "main" {
		t.Fatalf("pinned first with its commit details: %v", first)
	}
	if code, m := call("GET", "compare?repo=commit-keep/web&sha="+sha(1)); code != 404 || !strings.Contains(fmt.Sprint(m["error"]), "main has not been scanned") {
		t.Fatalf("compare without a branch scan: %d %v", code, m)
	}
	_ = saveSASTResult(ctx, db, cid, "commit-keep/web", "main", sha(9), engineReport{"builtin": "ran"}, []SASTFinding{{RuleID: "R7", File: "z.go", Severity: "medium", Title: "y"}}, nil, 1, 1)
	code, m := call("GET", "compare?repo=commit-keep/web&sha="+sha(1))
	if code != 200 || len(m["fixed"].([]interface{})) != 1 || len(m["new"].([]interface{})) != 1 {
		t.Fatalf("compare: %d %v", code, m)
	}
	// Unpinning prunes it back to the newest 3.
	_, _ = call("POST", "pin?repo=commit-keep/web&sha="+sha(1)+"&pinned=0")
	_, m = call("GET", "list?repo=commit-keep/web")
	if n := len(m["commit_scans"].([]interface{})); n != 3 {
		t.Fatalf("after unpin: %d", n)
	}
	_, _ = raw.Exec(`DELETE FROM sast_results WHERE connector_id=$1`, cid)
}
