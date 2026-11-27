package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"obsidianwatch/management/internal/store"
)

func corrSample() []SASTFinding {
	return []SASTFinding{
		{RuleID: "js/sql-injection", Engine: "codeql", File: "src/orders.js", Line: 40, Severity: "high", CWE: "CWE-89", Title: "SQL query built from user input", Snippet: "db.query(sql)"},
		{RuleID: "javascript.sqli", Engine: "semgrep", File: "src/orders.js", Line: 38, Severity: "critical", CWE: "CWE-89", Title: "Tainted SQL", Snippet: "const sql = 'SELECT ' + req.query.id", Fix: "Use parameters."},
		{RuleID: "JS021", Engine: "builtin", File: "src/orders.js", Line: 38, Severity: "high", CWE: "CWE-89", Title: "SQL concatenation", Snippet: "const sql = 'SELECT ' + req.query.id", TestCode: false},
		{RuleID: "BL-ACCESS-CONTROL", Engine: "business-logic", File: "src/orders.js", Line: 12, Severity: "high", CWE: "CWE-639", Title: "IDOR"},
		{RuleID: "A02-JS003", Engine: "builtin", File: "src/util.js", Line: 3, Severity: "low", Title: "Math.random"},
	}
}

func TestPlanCorrelation(t *testing.T) {
	raw := corrSample()
	batches, pass := planCorrelation(raw)
	if len(batches) != 1 || len(batches[0].idx) != 4 || len(pass) != 1 || raw[pass[0]].File != "src/util.js" {
		t.Fatalf("batches=%+v pass=%v", batches, pass)
	}
	// sorted by line within the file; ids are F1..F4
	if batches[0].items[0].Line != 12 || batches[0].items[3].ID != "F4" || batches[0].items[1].Family != "injection" {
		t.Fatalf("%+v", batches[0].items)
	}
}

func TestApplyGroupsGuardrails(t *testing.T) {
	raw := append(corrSample(), SASTFinding{RuleID: "X", Engine: "semgrep", File: "other.js", Line: 1, Severity: "low"},
		SASTFinding{RuleID: "Y", Engine: "builtin", File: "other.js", Line: 2, Severity: "low"})
	batches, _ := planCorrelation(raw)
	b := batches[0] // both files in one batch
	id := func(rule string) string {
		for k, i := range b.idx {
			if raw[i].RuleID == rule {
				return b.items[k].ID
			}
		}
		return ""
	}
	groups := []corrGroup{
		{Members: []string{id("js/sql-injection"), id("javascript.sqli"), id("JS021"), "F99", id("X")}, Title: "SQL injection in orders", Verdict: "confirmed", Confidence: 95},
		{Members: []string{id("JS021")}, Verdict: "false_positive"}, // already used
		{Members: []string{id("BL-ACCESS-CONTROL")}, Verdict: "weird"},
	}
	out, meta := applyGroups(raw, b, groups)
	if len(out) != 4 || len(out[0]) != 3 || meta[1].Verdict != "likely" || meta[2].Verdict != "uncorrelated" || meta[3].Verdict != "uncorrelated" {
		t.Fatalf("out=%v meta=%+v", out, meta)
	}
	c := buildCorrelated(raw, out[0], meta[0])
	// primary = the critical semgrep finding; severity is the max, never the model's
	if c.RuleID != "javascript.sqli" || c.Severity != "critical" || c.Title != "SQL injection in orders" || c.Engine != "codeql+semgrep+builtin" ||
		len(c.Correlation.Members) != 3 || c.Fix != "Use parameters." || c.Correlation.Verdict != "confirmed" {
		t.Fatalf("%+v %+v", c, c.Correlation)
	}
	if findingFingerprint(c) != findingFingerprint(raw[1]) {
		t.Fatal("a correlated finding keeps its primary member's fingerprint")
	}
	single := buildCorrelated(raw, []int{4}, corrGroup{Verdict: "single_engine", Title: "ignored for one member"})
	if single.Title != "Math.random" || single.Engine != "builtin" {
		t.Fatalf("%+v", single)
	}
}

func TestRanEngineIDs(t *testing.T) {
	ids := ranEngineIDs(engineReport{"source": "git", "builtin": "ran", "trivy": "ran", "osv": "ran", "semgrep": "missing", "gitleaks": "ran"})
	if strings.Join(ids, ",") != "builtin,secrets,dependencies" || !correlationAllowed(engineReport{"builtin": "ran", "codeql": "ran"}) ||
		correlationAllowed(engineReport{"trivy": "ran", "osv": "ran"}) {
		t.Fatalf("%v", ids)
	}
	p := codeScanPolicy{Protected: []branchProfile{{Repo: "a/b", Branch: "main", Engines: []string{"builtin"}, Correlate: true},
		{Repo: "a/b", Branch: "dev", Correlate: true}}}.normalised()
	if p.Protected[0].Correlate || !p.Protected[1].Correlate {
		t.Fatal("one engine cannot correlate; the default set can")
	}
}

// TestCorrelateStored correlates a stored result against a fake Anthropic API,
// then undoes it. OW_TEST_COVERAGE_DSN names a disposable database.
func TestCorrelateStored(t *testing.T) {
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
	_, _ = raw.Exec(`DELETE FROM code_fix_cache WHERE key LIKE 'corr:%'`)
	db := &store.DB{DB: raw}
	ctx := context.Background()
	_ = db.SetSetting(ctx, "ai.anthropic_api_key", "sk-test")
	_ = db.SetSetting(ctx, "ai.send_source_snippets", "true")
	_ = db.SetSetting(ctx, settingCodeModel, "")
	cid, _, err := db.UpsertDevOpsConnector(ctx, "github", "corr-test", "t", map[string]string{"token": "T"}, "s")
	if err != nil {
		t.Fatal(err)
	}
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		b, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		_ = json.Unmarshal(b, &req)
		// Group every SQL finding: find their ids in the prompt.
		var ids []string
		for _, line := range strings.Split(req.Messages[0].Content, "{") {
			if strings.Contains(line, "CWE-89") {
				if i := strings.Index(line, `"id":"`); i >= 0 {
					ids = append(ids, strings.SplitN(line[i+6:], `"`, 2)[0])
				}
			}
		}
		g, _ := json.Marshal(map[string]interface{}{"groups": []map[string]interface{}{{"members": ids, "title": "SQL injection in GET /orders",
			"detail": "req.query.id reaches db.query.", "verdict": "confirmed", "confidence": 92, "reason": "three engines agree"}}})
		out, _ := json.Marshal(map[string]interface{}{"content": []map[string]string{{"type": "text", "text": string(g)}}})
		_, _ = w.Write(out)
	}))
	defer srv.Close()
	old := anthropicURL
	anthropicURL = srv.URL
	defer func() { anthropicURL = old }()

	eng := engineReport{"builtin": "ran", "semgrep": "ran", "codeql": "ran", "business-logic": "ran"}
	if err := saveSASTResult(ctx, db, cid, "corr/api", "main", "abc", eng, corrSample(), nil, 1, 3); err != nil {
		t.Fatal(err)
	}
	meta, err := correlateStored(ctx, nil, db, cid, "corr/api", "main", false)
	if err != nil {
		t.Fatal(err)
	}
	// 5 raw: 3 SQL merged into 1, IDOR left out by the model (kept), util.js single engine.
	if meta.Raw != 5 || meta.Findings != 3 || meta.Merged != 1 || meta.Reviewed != 4 || calls != 1 {
		t.Fatalf("%+v calls=%d", meta, calls)
	}
	var fj, rj []byte
	var n, crit int
	_ = raw.QueryRow(`SELECT findings, raw_findings, finding_count, critical_count FROM sast_results WHERE connector_id=$1`, cid).Scan(&fj, &rj, &n, &crit)
	var stored, kept []SASTFinding
	_ = json.Unmarshal(fj, &stored)
	_ = json.Unmarshal(rj, &kept)
	if n != 3 || crit != 1 || len(kept) != 5 || stored[0].Correlation == nil || stored[0].Correlation.Verdict != "confirmed" || len(stored[0].Correlation.Members) != 3 {
		t.Fatalf("n=%d crit=%d raw=%d %+v", n, crit, len(kept), stored)
	}
	verdicts := map[string]string{}
	for _, f := range stored {
		verdicts[f.RuleID] = f.Correlation.Verdict
	}
	if verdicts["BL-ACCESS-CONTROL"] != "likely" || verdicts["A02-JS003"] != "single_engine" {
		t.Fatalf("%v", verdicts)
	}
	// Correlating again is answered from the cache and starts from the raw findings.
	if meta, err = correlateStored(ctx, nil, db, cid, "corr/api", "main", false); err != nil || meta.Cached != 1 || calls != 1 || meta.Raw != 5 {
		t.Fatalf("again: %v %+v calls=%d", err, meta, calls)
	}
	// A partial rescan merges with the raw findings, not the correlated ones.
	merged, _ := mergeStoredEngines(ctx, db, cid, "corr/api", "main", newEngineSet([]string{engBusinessLogic}), engineReport{}, nil, nil)
	if len(merged) != 4 {
		t.Fatalf("merge reads raw findings: %d", len(merged))
	}
	if err := uncorrelateStored(ctx, db, cid, "corr/api", "main"); err != nil {
		t.Fatal(err)
	}
	_ = raw.QueryRow(`SELECT finding_count FROM sast_results WHERE connector_id=$1`, cid).Scan(&n)
	if n != 5 {
		t.Fatalf("undo restores raw: %d", n)
	}
	// One engine: refused.
	_ = saveSASTResult(ctx, db, cid, "corr/api", "dev", "abc", engineReport{"builtin": "ran"}, corrSample()[:1], nil, 1, 1)
	if _, err := correlateStored(ctx, nil, db, cid, "corr/api", "dev", false); err == nil {
		t.Fatal("one engine must be refused")
	}
	_, _ = raw.Exec(`DELETE FROM sast_results WHERE connector_id=$1`, cid)
}
