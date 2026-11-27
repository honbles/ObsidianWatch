package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"obsidianwatch/management/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rulesHit returns the rule IDs that fire on content in a file named name.
func rulesHit(name, content string) map[string]int {
	out := map[string]int{}
	for _, f := range runSASTRules("o/r", name, content) {
		out[f.RuleID]++
	}
	return out
}

// Cases from evaluating the built-in rules on OWASP Juice Shop, NodeGoat, PyGoat, WebGoat and DVWA.
func TestSASTRuleQuality(t *testing.T) {
	cases := []struct {
		name, file, line, rule string
		want                   bool
	}{
		// JavaScript SQL injection had no rule at all.
		{"sequelize template", "routes/login.ts", "models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)", "JS021", true},
		{"pg concat", "db.js", `pool.query("SELECT * FROM t WHERE id = " + req.params.id)`, "JS021", true},
		{"knex raw", "db.js", "knex.raw(`DELETE FROM t WHERE id = ${id}`)", "JS021", true},
		{"prisma unsafe", "db.ts", "prisma.$queryRawUnsafe(`SELECT * FROM t WHERE a = ${a}`)", "JS021", true},
		{"bound parameters", "db.js", `pool.query("SELECT * FROM t WHERE id = $1", [id])`, "JS021", false},
		{"no interpolation", "db.js", "db.query(`SELECT * FROM t`)", "JS021", false},
		// The SQL text of the injection is not a hardcoded credential.
		{"sql is not a credential", "routes/login.ts", "sequelize.query(`SELECT * FROM Users WHERE email = '${e}' AND password = '${p}' AND deletedAt IS NULL`)", "ANY001", false},
		{"real credential", "config.js", `const password = 'hunter2hunter2'`, "ANY001", true},
		// Importing helmet (a security middleware) is not a CORS wildcard.
		{"helmet import", "server.ts", "import helmet from 'helmet'", "A05-JS001", false},
		{"cors wildcard", "server.js", "app.use(cors({ origin: '*' }))", "A05-JS001", true},
		// A comparison with innerHTML is not a sink.
		{"innerHTML compare", "h.ts", "if (element.innerHTML === value) {", "JS001", false},
		{"innerHTML assign", "h.ts", "el.innerHTML = html", "JS001", true},
		{"innerHTML append", "h.ts", "el.innerHTML += html", "JS001", true},
		// Reading a token is not storing it.
		{"token read", "a.ts", "if (localStorage.getItem('token')) {", "A01-JS003", false},
		// JSON.parse cannot execute code.
		{"json parse", "r.ts", "id: JSON.parse(req.params.id)", "A08-JS001", false},
		{"node-serialize", "r.js", "const s = require('node-serialize')", "A08-JS001", true},
		// Terraform: creation_token and interpolated values are not secrets.
		{"tf creation_token", "efs.tf", `  creation_token = "${var.project_name}-data"`, "IAC001", false},
		{"tf kms key id", "kms.tf", `  kms_key_id = "alias/aws/s3"`, "IAC001", false},
		{"tf password", "db.tf", `  password = "SuperSecret123"`, "IAC001", true},
		{"tf interpolated password", "db.tf", `  password = "${var.db_password}"`, "IAC001", false},
		// New rules.
		{"angular bypass", "c.component.ts", "this.html = this.sanitizer.bypassSecurityTrustHtml(value)", "JS022", true},
		{"xxe libxml", "upload.ts", "libxml.parseXml(data, { noblanks: true, noent: true })", "JS023", true},
		{"open redirect", "index.js", "return res.redirect(req.query.url);", "JS024", true},
		{"fixed redirect", "index.js", `return res.redirect("/login");`, "JS024", false},
	}
	for _, c := range cases {
		got := rulesHit(c.file, c.line)[c.rule] > 0
		if got != c.want {
			t.Errorf("%s: rule %s on %q: got %v, want %v", c.name, c.rule, c.line, got, c.want)
		}
	}
}

// Every match in a file is reported (up to the cap), not only the first one.
func TestSASTRuleSeveralHitsPerFile(t *testing.T) {
	src := strings.Repeat("eval(a)\nok()\n", 3)
	if n := rulesHit("x.js", src)["JS002"]; n != 3 {
		t.Fatalf("JS002 hits: %d, want 3", n)
	}
	if n := rulesHit("x.js", strings.Repeat("eval(a)\n", 50))["JS002"]; n != maxRuleHitsPerFile {
		t.Fatalf("cap: %d, want %d", n, maxRuleHitsPerFile)
	}
}

func TestSASTDedupOverlappingRules(t *testing.T) {
	// Two built-in rules for eval on one line: one finding, the more severe.
	in := runSASTRules("o/r", "a.js", "const x = eval(input)")
	out := deduplicateSASTFindings(in)
	if len(in) < 2 || len(out) != 1 || out[0].Severity != "critical" {
		t.Fatalf("in %d, out %d (%v)", len(in), len(out), out)
	}
	// A built-in finding next to an engine finding with the same CWE is dropped; another CWE stays.
	eng := SASTFinding{RuleID: "javascript.lang.security.eval", Engine: "semgrep", Repo: "o/r", File: "a.js", Line: 2,
		CWE: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"}
	b1 := SASTFinding{RuleID: "JS002", Engine: "builtin", Repo: "o/r", File: "a.js", Line: 1, CWE: "CWE-95", Severity: "high"}
	b2 := SASTFinding{RuleID: "JS006", Engine: "builtin", Repo: "o/r", File: "a.js", Line: 1, CWE: "CWE-614", Severity: "medium"}
	b3 := SASTFinding{RuleID: "JS002", Engine: "builtin", Repo: "o/r", File: "a.js", Line: 40, CWE: "CWE-95", Severity: "high"}
	got := deduplicateSASTFindings([]SASTFinding{b1, b2, b3, eng})
	ids := map[string]int{}
	for _, f := range got {
		ids[f.RuleID+"@"+f.Engine]++
	}
	if len(got) != 3 || ids["JS002@builtin"] != 1 || ids["JS006@builtin"] != 1 || ids["javascript.lang.security.eval@semgrep"] != 1 {
		t.Fatalf("got %v", ids)
	}
}

// The directory scan of a clone skips .git, dependency trees, files no rule reads and oversized files.
func TestRunBuiltinRulesOnDirSkips(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("src/app.js", "eval(x)\n")
	write(".git/hooks/pre-commit.js", "eval(x)\n")
	write("node_modules/lib/index.js", "eval(x)\n")
	write("assets/logo.png", "eval(x)\n")
	write("big/huge.js", "eval(x)\n"+strings.Repeat("// padding\n", maxFileBytes/10))
	files := map[string]bool{}
	for _, f := range runBuiltinRulesOnDir("o/r", dir) {
		files[f.File] = true
	}
	if !files["src/app.js"] || len(files) != 1 {
		t.Fatalf("scanned %v, want only src/app.js", files)
	}
}

func TestCredentialSnippetsMasked(t *testing.T) {
	cases := map[string]string{
		`const password = 'hunter2hunter2'`:                           `const password = 'hu****'`,
		`DB_PASSWORD=SuperSecret123`:                                  `DB_PASSWORD=Su****`,
		`private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAA"`: `private_key = "--****"`,
		`api_key: "AKIAABCDEFGHIJKLMNOP"`:                             `api_key: "AK****"`,
	}
	for in, want := range cases {
		got := maskCredentialSnippet(in)
		if got != want {
			t.Errorf("mask(%q) = %q, want %q", in, got, want)
		}
		if again := maskCredentialSnippet(got); again != got {
			t.Errorf("not idempotent: %q -> %q", got, again)
		}
	}
	raw := SASTFinding{RuleID: "ANY001", CWE: "CWE-798", File: "a.js", Snippet: `const password = 'hunter2hunter2'`}
	fs := []SASTFinding{raw}
	out := deduplicateSASTFindings(fs)
	if strings.Contains(out[0].Snippet, "hunter2") {
		t.Fatalf("snippet not masked: %q", out[0].Snippet)
	}
	if findingFingerprint(raw) != findingFingerprint(out[0]) {
		t.Fatal("masking changed the fingerprint: triage decisions would be lost")
	}
	other := SASTFinding{RuleID: "JS002", CWE: "CWE-95", File: "a.js", Snippet: `eval("x")`}
	if deduplicateSASTFindings([]SASTFinding{other})[0].Snippet != `eval("x")` {
		t.Fatal("non-credential snippet changed")
	}
}

// A pull-request comment can be public: it must not name internal services or hosts.
func TestPRCommentHidesInfrastructure(t *testing.T) {
	f := SASTFinding{Title: "Vulnerable lodash", Severity: "high", RuleID: "CVE-1", Engine: "trivy",
		Reachability: &findingReach{Level: "loaded", Services: []string{"payments-api"}, Hosts: []string{"db-prod-01", "db-prod-02"}}}
	c := findingComment(f, "github", nil)
	if strings.Contains(c, "payments-api") || strings.Contains(c, "db-prod") {
		t.Fatalf("comment names infrastructure: %s", c)
	}
	if !strings.Contains(c, "1 service, 2 hosts") {
		t.Fatalf("comment lost the counts: %s", c)
	}
}

func TestWebhookBodyTooLarge(t *testing.T) {
	big := strings.Repeat("a", maxWebhookBody+10)
	for name, h := range map[string]http.HandlerFunc{
		"github": handleGitHubWebhook(nil, nil, slog.Default()),
		"gitlab": handleGitLabWebhook(nil, nil, slog.Default()),
		"ado":    handleADOWebhook(nil, nil, slog.Default()),
	} {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(big))
		r.SetPathValue("id", "999")
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: status %d, want 413", name, w.Code)
		}
	}
}

func TestRepoInConnectorScope(t *testing.T) {
	gh := &store.DevOpsConnector{Provider: "github", Org: "Acme"}
	gl := &store.DevOpsConnector{Provider: "gitlab", Org: "acme/platform"}
	glID := &store.DevOpsConnector{Provider: "gitlab", Org: "12345"}
	ado := &store.DevOpsConnector{Provider: "azuredevops", Org: "acme"}
	cases := []struct {
		c    *store.DevOpsConnector
		repo string
		want bool
	}{
		{gh, "acme/api", true}, {gh, "ACME/api", true}, {gh, "other/api", false}, {gh, "acmecorp/api", false},
		{gl, "acme/platform/api", true}, {gl, "acme/platform/sub/api", true}, {gl, "acme/other/api", false},
		{gl, "acme/platformx/api", false}, {gl, "acme/platform", false},
		{glID, "anything/at/all", true},
		{ado, "acme/Project/repo", true}, {ado, "other/Project/repo", false},
	}
	for _, c := range cases {
		if got := repoInConnectorScope(c.c, c.repo); got != c.want {
			t.Errorf("%s %q in %q: got %v, want %v", c.c.Provider, c.repo, c.c.Org, got, c.want)
		}
	}
}

// The token header is scoped to the provider's origin, so a redirect to another host does not receive it.
func TestGitAuthHeaderScoped(t *testing.T) {
	conn := &store.DevOpsConnector{Provider: "gitlab", Credentials: map[string]string{"token": "T", "base_url": "https://git.example.com"}}
	_, auth, err := gitRemote(conn, "grp/app")
	if err != nil {
		t.Fatal(err)
	}
	env := strings.Join(gitEnv(auth), "\n")
	if !strings.Contains(env, "GIT_CONFIG_KEY_0=http.https://git.example.com/.extraHeader") ||
		!strings.Contains(env, "GIT_CONFIG_VALUE_0=Authorization: Basic ") || strings.Contains(env, "\x00") {
		t.Fatalf("env: %s", env)
	}
}

func TestGoModuleDirs(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"go.mod", "svc/api/go.mod", "tools/go.mod", "vendor/x/go.mod", "testdata/m/go.mod", ".git/go.mod", "has space/go.mod"} {
		_ = os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755)
		_ = os.WriteFile(filepath.Join(dir, p), []byte("module x\n"), 0o644)
	}
	got := strings.Join(goModuleDirs(dir), ",")
	if got != ".,svc/api,tools" {
		t.Fatalf("modules: %s", got)
	}
	if got := goModuleDirs(t.TempDir()); len(got) != 1 || got[0] != "." {
		t.Fatalf("no go.mod: %v", got)
	}
}

// On a public repository a pull request gets counts only: no title, file or line of any finding.
func TestPublicPRSummaryHasNoDetails(t *testing.T) {
	fs := []SASTFinding{{Title: "SQL Injection", Severity: "critical", File: "routes/login.ts", Line: 34, RuleID: "JS021"}}
	s := publicPRSummary(defaultCodeScanPolicy().normalised(), fs, true)
	for _, leak := range []string{"SQL Injection", "routes/login.ts", "JS021", ":34"} {
		if strings.Contains(s, leak) {
			t.Fatalf("public summary contains %q:\n%s", leak, s)
		}
	}
	if !strings.Contains(s, "| 1 | 0 | 0 | 0 |") {
		t.Fatalf("counts missing:\n%s", s)
	}
}

func TestTestCodeLowered(t *testing.T) {
	paths := map[string]bool{
		"test/api/login.test.ts": true, "frontend/src/app/x.component.spec.ts": true, "pkg/db_test.go": true,
		"tests/test_views.py": true, "src/test/java/FooTest.java": true, "cypress/e2e/a.cy.js": true,
		"examples/basic/main.go": true, "routes/login.ts": false, "src/contest/entry.js": false, "lib/testing_utils.py": false,
		"attestation/verify.go": false,
	}
	for p, want := range paths {
		if isTestPath(p) != want {
			t.Errorf("isTestPath(%q) = %v", p, !want)
		}
	}
	fs := []SASTFinding{
		{RuleID: "JS002", Severity: "high", File: "test/a.test.js", CWE: "CWE-95"},
		{RuleID: "ANY001", Severity: "high", File: "test/a.test.js", CWE: "CWE-798"},
		{RuleID: "CVE-1", Severity: "critical", File: "test/package-lock.json", Package: "lodash"},
		{RuleID: "JS002", Severity: "high", File: "routes/a.js", CWE: "CWE-95"},
	}
	markTestCode(fs)
	markTestCode(fs) // a second pass changes nothing
	got := []string{fs[0].Severity, fs[1].Severity, fs[2].Severity, fs[3].Severity}
	if strings.Join(got, ",") != "medium,high,critical,high" || !fs[0].TestCode || fs[1].TestCode || fs[3].TestCode {
		t.Fatalf("got %v %+v", got, fs)
	}
}

func TestSASTEngineWarning(t *testing.T) {
	if sastEngineWarning(engineReport{"builtin": "ran", "semgrep": "ran"}) != "" || sastEngineWarning(engineReport{"codeql": "ran"}) != "" {
		t.Fatal("warned although a data-flow engine ran")
	}
	if sastEngineWarning(engineReport{"builtin": "ran", "semgrep": "missing: x", "codeql": "failed: y"}) == "" {
		t.Fatal("no warning with only built-in rules")
	}
	if scanEngineWarning(0, engineReport{}) != "" {
		t.Fatal("warning without any scanned repository")
	}
}

func TestScanSlotsLimit(t *testing.T) {
	t.Setenv("OW_SAST_MAX_CONCURRENT", "2")
	r1, _ := acquireScanSlot(t.Context())
	r2, _ := acquireScanSlot(t.Context())
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := acquireScanSlot(ctx); err == nil {
		t.Fatal("third scan got a slot")
	}
	r1()
	r1() // releasing twice frees one slot only
	r3, err := acquireScanSlot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r2()
	r3()
}
