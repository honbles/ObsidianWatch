package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestCodeModelAllowed(t *testing.T) {
	for m, want := range map[string]bool{
		"claude-opus-5-5": true, "claude-opus-5-6": true, "claude-opus-6": true, "claude-opus-6-1": true,
		"claude-opus-5-5-20261001": true, "claude-fable-5-2": true, "claude-mythos-5-2": true,
		"claude-opus-5": false, "claude-opus-5-4": false, "claude-opus-4-7": false,
		"claude-sonnet-5-5": false, "claude-haiku-5-5": false, "openai/gpt-oss-120b": false,
		"claude-fable-4": false, "": false, "claude-opus-5-5 ": true,
	} {
		if got := codeModelAllowed(m); got != want {
			t.Errorf("%q: got %v want %v", m, got, want)
		}
	}
}

func TestParseEngineIDs(t *testing.T) {
	ids, err := parseEngineIDs([]string{"business-logic", "opengrep", "builtin", "semgrep", " "})
	if err != nil || strings.Join(ids, ",") != "builtin,semgrep,business_logic" {
		t.Fatalf("%v %v", ids, err)
	}
	if _, err := parseEngineIDs([]string{"nope"}); err == nil {
		t.Fatal("unknown engine accepted")
	}
	var none engineSet
	if !none.on(engBuiltin) || none.on(engBusinessLogic) || none.partial() {
		t.Fatal("nil set is the default non-AI set")
	}
	s := newEngineSet([]string{engBusinessLogic})
	if !s.partial() || s.on(engBuiltin) || !s.on(engBusinessLogic) {
		t.Fatal("business-logic only set")
	}
	all := newEngineSet(append(defaultEngineIDs(), engBusinessLogic))
	if all.partial() {
		t.Fatal("every default engine chosen is not partial")
	}
}

func TestProtectedPolicy(t *testing.T) {
	p := codeScanPolicy{Protected: []branchProfile{
		{Repo: "acme/api", Branch: "refs/heads/main", Engines: []string{"builtin", "business_logic"}},
		{Repo: "ACME/api", Branch: "main"}, // duplicate
		{Repo: "acme/api", Branch: "HEAD"}, // not a branch
		{Repo: "", Branch: "x"},
		{Repo: "acme/web", Branch: "release"},
	}}.normalised()
	if len(p.Protected) != 2 || p.Protected[0].Branch != "main" {
		t.Fatalf("%+v", p.Protected)
	}
	if s, ok := p.engineSetFor("acme/api", "main"); !ok || !s.on(engBusinessLogic) || s.on(engSemgrep) {
		t.Fatal("profile engines")
	}
	if s, ok := p.engineSetFor("acme/web", "release"); !ok || s != nil {
		t.Fatal("empty profile = default engines")
	}
	if _, ok := p.engineSetFor("acme/web", "main"); ok {
		t.Fatal("not protected")
	}
	if b, ok := p.pushScanBranch("acme/web", "refs/heads/release", "main"); !ok || b != "release" {
		t.Fatal("push to protected branch scanned")
	}
	if _, ok := p.pushScanBranch("acme/web", "refs/heads/main", "main"); ok {
		t.Fatal("with protected branches, the default branch is not scanned unless protected")
	}
	if b, ok := (codeScanPolicy{}).pushScanBranch("acme/web", "refs/heads/main", "main"); !ok || b != "main" {
		t.Fatal("no protected branches: default branch push scanned")
	}
	if _, ok := (codeScanPolicy{}).pushScanBranch("acme/web", "refs/tags/v1", "main"); ok {
		t.Fatal("tags are not scanned")
	}
}

func TestBLCandidatesAndFindings(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(body), 0o644)
	}
	write("src/orders.js", "const r = express.Router()\nrouter.get('/orders/:id', h)\nrouter.post('/orders', c)\n")
	write("app/main.py", "@app.get('/users/{id}')\ndef u(id): pass\n")
	write("internal/h.go", "func H(w http.ResponseWriter, r *http.Request) {}\n")
	write("src/util.js", "export const add = (a, b) => a + b\n")
	write("node_modules/x/index.js", "app.get('/x', h)\n")
	write("test/orders.test.js", "router.get('/t', h)\n")
	write("src/big.js", "router.get('/a', h)\n"+strings.Repeat("// pad\n", 12000))
	c := blCandidates(dir, nil)
	var names []string
	big := false
	for _, x := range c {
		if x.tooBig {
			big = x.rel == "src/big.js"
			continue
		}
		names = append(names, x.rel)
	}
	if strings.Join(names, ",") != "src/orders.js,app/main.py,internal/h.go" || !big {
		t.Fatalf("%v big=%v", names, big)
	}
	if c := blCandidates(dir, map[string]bool{"app/main.py": true}); len(c) != 1 || c[0].rel != "app/main.py" {
		t.Fatalf("only files: %+v", c)
	}
	content := []byte("a\nb\nreturn db.find(req.params.id)\n")
	f := blFindings("acme/api", "src/orders.js", content, []blItem{
		{Category: "access-control", Title: "IDOR on order", Severity: "HIGH", CWE: "cwe-639", Line: 3, EndLine: 99, Route: "GET /orders/:id", Confidence: 90},
		{Category: "access-control", Title: "low confidence", Line: 3, Confidence: 30},
		{Category: "access-control", Title: "bad line", Line: 40, Confidence: 90},
		{Category: "weird", Title: "other", Severity: "extreme", Line: 1, Confidence: 70},
	})
	if len(f) != 2 || f[0].RuleID != "BL-ACCESS-CONTROL" || f[0].Severity != "high" || f[0].CWE != "CWE-639" ||
		f[0].EndLine != 3 || f[0].OWASP != "A01" || f[0].Engine != "business-logic" || !strings.HasPrefix(f[0].Detail, "Route: GET /orders/:id") ||
		f[0].Snippet != "return db.find(req.params.id)" || f[1].RuleID != "BL-OTHER" || f[1].Severity != "medium" {
		t.Fatalf("%+v", f)
	}
	if findingEngineID(f[0]) != engBusinessLogic {
		t.Fatal("engine id")
	}
}

// TestBusinessLogicEngine runs the engine against a fake Anthropic API and
// checks caching. OW_TEST_COVERAGE_DSN names a disposable database.
func TestBusinessLogicEngine(t *testing.T) {
	dsn := os.Getenv("OW_TEST_COVERAGE_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_COVERAGE_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, f := range []string{"011_settings.sql", "078_code_triage.sql"} {
		b, _ := os.ReadFile("../store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	_, _ = raw.Exec(`DELETE FROM code_fix_cache WHERE key LIKE 'bl:%'`)
	db := &store.DB{DB: raw}
	ctx := context.Background()
	_ = db.SetSetting(ctx, "ai.anthropic_api_key", "sk-test")
	_ = db.SetSetting(ctx, "ai.send_source_snippets", "true")
	_ = db.SetSetting(ctx, settingCodeModel, "claude-sonnet-5-5") // not allowed: the default is used
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		var req map[string]interface{}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		if req["model"] != defaultCodeModel || req["system"] == nil || r.Header.Get("x-api-key") != "sk-test" {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":{"message":"bad request from test"}}`))
			return
		}
		ans := `{"findings":[{"category":"access-control","title":"Any user can read any order","severity":"high","cwe":"CWE-639","line":2,"end_line":2,"route":"GET /orders/:id","detail":"No owner check.","fix":"Compare order.userId with req.user.id.","confidence":85}]}`
		out, _ := json.Marshal(map[string]interface{}{"content": []map[string]string{{"type": "text", "text": ans}}, "stop_reason": "end_turn"})
		_, _ = w.Write(out)
	}))
	defer srv.Close()
	old := anthropicURL
	anthropicURL = srv.URL
	defer func() { anthropicURL = old }()

	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "orders.js"), []byte("const router = require('express').Router()\nrouter.get('/orders/:id', async (req, res) => res.json(await Order.findById(req.params.id)))\n"), 0o644)
	bl := &blContext{db: db}
	eng := engineReport{}
	f, err := runBusinessLogic(ctx, bl, "acme/api", dir, eng, nil)
	if err != nil || len(f) != 1 || f[0].Line != 2 || calls != 1 {
		t.Fatalf("first run: %v %+v calls=%d", err, f, calls)
	}
	f, err = runBusinessLogic(ctx, bl, "acme/api", dir, eng, nil)
	if err != nil || len(f) != 1 || calls != 1 || !strings.Contains(eng["business-logic-files"], "1 from cache") {
		t.Fatalf("second run must come from the cache: %v calls=%d %q", err, calls, eng["business-logic-files"])
	}
	_ = os.WriteFile(filepath.Join(dir, "orders.js"), []byte("router.get('/orders/:id', h)\nchanged()\n"), 0o644)
	if _, err = runBusinessLogic(ctx, bl, "acme/api", dir, eng, nil); err != nil || calls != 2 {
		t.Fatalf("changed file is analysed again: %v calls=%d", err, calls)
	}
	_ = db.SetSetting(ctx, "ai.send_source_snippets", "false")
	if _, err = runBusinessLogic(ctx, bl, "acme/api", dir, eng, nil); err == nil {
		t.Fatal("source consent off must stop the engine")
	}
}

// TestMergeStoredEngines: a scan of some engines keeps the others' stored findings.
func TestMergeStoredEngines(t *testing.T) {
	dsn := os.Getenv("OW_TEST_COVERAGE_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_COVERAGE_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, f := range []string{"015_devops_connectors.sql", "018_code_scan.sql", "020_sast_per_repo.sql", "075_sast_engines.sql", "081_sast_commit.sql", "085_sast_correlation.sql"} {
		b, _ := os.ReadFile("../store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	db := &store.DB{DB: raw}
	ctx := context.Background()
	_, _ = raw.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS uq_devops_connectors_provider_org ON devops_connectors (provider, org)`)
	cid, _, err := db.UpsertDevOpsConnector(ctx, "github", "merge-test", "t", map[string]string{"token": "T"}, "s")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = raw.Exec(`DELETE FROM sast_results WHERE connector_id=$1`, cid)
	stored := []SASTFinding{
		{RuleID: "A03-JS001", File: "a.js", Line: 3, Engine: "builtin", Severity: "high"},
		{RuleID: "javascript.sqli", File: "a.js", Line: 3, Engine: "semgrep", Severity: "high"},
		{RuleID: "BL-ACCESS-CONTROL", File: "o.js", Line: 2, Engine: "business-logic", Severity: "high"},
	}
	if err := saveSASTResult(ctx, db, cid, "acme/api", "main", "abc", engineReport{"builtin": "ran", "semgrep": "ran", "business-logic": "ran"}, stored, []byte(`{"bom":1}`), 1, 2); err != nil {
		t.Fatal(err)
	}
	// Rerun only the business-logic engine: the new BL finding replaces the old; builtin and semgrep stay.
	eng := engineReport{"business-logic": "ran"}
	fresh := []SASTFinding{{RuleID: "BL-WORKFLOW", File: "c.js", Line: 9, Engine: "business-logic", Severity: "medium"}}
	out, sbom := mergeStoredEngines(ctx, db, cid, "acme/api", "main", newEngineSet([]string{engBusinessLogic}), eng, fresh, nil)
	var rules []string
	for _, f := range out {
		rules = append(rules, f.RuleID)
	}
	if strings.Join(rules, ",") != "BL-WORKFLOW,A03-JS001,javascript.sqli" || string(sbom) != `{"bom": 1}` && string(sbom) != `{"bom":1}` {
		t.Fatalf("%v sbom=%s", rules, sbom)
	}
	if eng["semgrep"] != "ran" || eng["builtin"] != "ran" {
		t.Fatalf("stored engine status kept: %v", eng)
	}
	// The default set is not partial: nothing is merged.
	out, _ = mergeStoredEngines(ctx, db, cid, "acme/api", "main", nil, engineReport{}, fresh, nil)
	if len(out) != 1 {
		t.Fatalf("full scan replaces: %v", out)
	}
	_, _ = raw.Exec(`DELETE FROM sast_results WHERE connector_id=$1`, cid)
}
