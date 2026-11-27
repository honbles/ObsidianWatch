package api

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestParseChangedLinesAndGate(t *testing.T) {
	diff := `diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,0 +11,3 @@ def x():
+a
+b
+c
@@ -40 +43 @@
-old
+new
diff --git a/gone.py b/gone.py
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
diff --git a/package-lock.json b/package-lock.json
--- a/package-lock.json
+++ b/package-lock.json
@@ -5 +5 @@
-x
+y
`
	ch := parseChangedLines(strings.NewReader(diff))
	if len(ch["app.py"]) != 2 || ch["app.py"][0] != (lineRange{11, 13}) || ch["app.py"][1] != (lineRange{43, 43}) {
		t.Fatalf("ranges: %+v", ch)
	}
	if _, ok := ch["gone.py"]; ok {
		t.Fatal("deleted files are not changed lines")
	}
	in := []SASTFinding{
		{RuleID: "R1", File: "app.py", Line: 12},               // changed line
		{RuleID: "R2", File: "app.py", Line: 20},               // unchanged line
		{RuleID: "R3", File: "other.py", Line: 1},              // untouched file
		{RuleID: "SCA-CVE-1", File: "package-lock.json"},       // new in this PR
		{RuleID: "SCA-CVE-2", File: "package-lock.json"},       // already on base
		{RuleID: "SECRET-aws", File: "untouched.env", Line: 3}, // PR commits only
		{RuleID: "R4", File: "app.py", Line: 40, EndLine: 44},  // spans a change
	}
	out := gatePRFindings(in, ch, map[string]bool{"SCA-CVE-2\x00package-lock.json": true})
	var ids []string
	for _, f := range out {
		ids = append(ids, f.RuleID)
	}
	if strings.Join(ids, ",") != "R1,SCA-CVE-1,SECRET-aws,R4" {
		t.Fatalf("kept %v", ids)
	}
}

func TestPolicyAndSchedule(t *testing.T) {
	p := codeScanPolicy{BlockOn: "bogus", Schedule: "hourly", ScheduleHour: 99}.normalised()
	if p.BlockOn != "critical" || p.Schedule != "off" || p.ScheduleHour != 2 || p.MaxComments != 20 {
		t.Fatalf("normalised: %+v", p)
	}
	p.BlockOn = "high"
	if !p.blocks("CRITICAL") || !p.blocks("high") || p.blocks("medium") {
		t.Fatal("blocks")
	}
	p.BlockOn = "none"
	if p.blocks("critical") {
		t.Fatal("none never blocks")
	}
	mon := time.Date(2026, 11, 23, 2, 5, 0, 0, time.UTC) // a Monday
	d := codeScanPolicy{Schedule: "daily", ScheduleHour: 2}
	if !scheduleDue(d, mon, time.Time{}) || scheduleDue(d, mon, mon.Add(-time.Hour)) || scheduleDue(d, mon.Add(time.Hour), time.Time{}) {
		t.Fatal("daily")
	}
	w := codeScanPolicy{Schedule: "weekly", ScheduleHour: 2}
	if !scheduleDue(w, mon, time.Time{}) || scheduleDue(w, mon.AddDate(0, 0, 1), time.Time{}) {
		t.Fatal("weekly")
	}
}

// gitServer serves bare repositories under root over HTTPS with
// git http-backend, plus a recorder for GitLab API calls.
type apiCall struct {
	Method, Path, Query string
	Body                map[string]interface{}
}

func TestPRCheckoutScanAndReport(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	backend := strings.TrimSpace(func() string { o, _ := exec.Command(gitBin, "--exec-path").Output(); return string(o) }()) + "/git-http-backend"
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend not available")
	}
	root := t.TempDir()
	work := filepath.Join(t.TempDir(), "w")
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=dev", "GIT_AUTHOR_EMAIL=d@x", "GIT_COMMITTER_NAME=dev", "GIT_COMMITTER_EMAIL=d@x")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	_ = os.MkdirAll(work, 0o755)
	run(work, "init", "-q", "-b", "main")
	write := func(name, body string) { _ = os.WriteFile(filepath.Join(work, name), []byte(body), 0o644) }
	write("app.py", "import os\n\ndef run(cmd):\n    return cmd\n")
	run(work, "add", ".")
	run(work, "commit", "-qm", "base")
	run(work, "checkout", "-qb", "feature")
	write("app.py", "import os\n\ndef run(cmd):\n    os.system(cmd)\n    return cmd\n")
	write("cfg.py", "TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'\n")
	run(work, "add", ".")
	run(work, "commit", "-qm", "feature")
	bare := filepath.Join(root, "grp", "proj.git")
	_ = os.MkdirAll(filepath.Dir(bare), 0o755)
	run(root, "clone", "-q", "--bare", work, bare)
	run(bare, "update-ref", "refs/merge-requests/7/head", "refs/heads/feature")
	headSHA := func() string {
		o, _ := exec.Command(gitBin, "-C", bare, "rev-parse", "refs/heads/feature").Output()
		return strings.TrimSpace(string(o))
	}()

	var mu sync.Mutex
	var calls []apiCall
	mux := http.NewServeMux()
	mux.Handle("/grp/", &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}})
	mux.HandleFunc("/api/v4/", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		mu.Lock()
		calls = append(calls, apiCall{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, body})
		mu.Unlock()
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"visibility":"private","diff_refs":{"base_sha":"b","head_sha":"h","start_sha":"s"}}`))
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	// Let git and the guarded HTTP client trust the test server.
	certFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certFile, pemCert(srv), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", certFile)
	t.Setenv("GIT_SSL_CAINFO", certFile)
	t.Setenv("OW_ALLOW_PRIVATE_DEVOPS", "true")
	t.Setenv("HTTPS_PROXY", "") // the dial guard must not see a proxy here
	t.Setenv("https_proxy", "")
	oldHTTP := devopsHTTP
	devopsHTTP = srv.Client()
	defer func() { devopsHTTP = oldHTTP }()

	conn := &store.DevOpsConnector{ID: 1, Provider: "gitlab", Org: "grp", Credentials: map[string]string{"token": "T", "base_url": srv.URL}}
	job := &store.CodeScanJob{ID: 1, Kind: "pr", Repo: "grp/proj", Ref: "7", BaseBranch: "main", HeadSHA: headSHA}
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "head")
	mb, auth, err := preparePRCheckout(ctx, conn, job, dir)
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	diff, err := gitIn(ctx, dir, auth, "diff", "--no-color", "--unified=0", mb, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	changed := parseChangedLines(strings.NewReader(string(diff)))
	if len(changed["app.py"]) == 0 || len(changed["cfg.py"]) == 0 {
		t.Fatalf("changed: %+v", changed)
	}
	findings, _ := scanCheckout(ctx, conn, job.Repo, dir, scanOpts{History: true, LogRange: mb + "..HEAD"}, engineReport{}, slog.Default())
	kept := gatePRFindings(deduplicateSASTFindings(findings), changed, nil)
	var secret bool
	for _, f := range kept {
		if strings.HasPrefix(f.RuleID, "SECRET-") && f.File == "cfg.py" && f.Severity == "critical" {
			secret = true
		}
		if f.File == "app.py" && f.Line != 4 && f.Line != 0 {
			t.Errorf("finding outside the changed lines: %+v", f)
		}
	}
	if !secret {
		t.Fatalf("the PR's secret should be reported: %+v", kept)
	}

	rep := newPRReporter(conn, job)
	if err := rep.SetStatus(ctx, "failure", "1 new issue"); err != nil {
		t.Fatal(err)
	}
	if err := rep.Inline(ctx, []prInline{{Path: "app.py", Line: 4, Body: "x"}}, "summary"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	var sawStatus, sawNote, sawDiscussion bool
	for _, c := range calls {
		switch {
		case strings.Contains(c.Path, "/statuses/"+headSHA) && strings.Contains(c.Query, "state=failed"):
			sawStatus = true
		case strings.HasSuffix(c.Path, "/merge_requests/7/notes") && c.Body["body"] == "summary":
			sawNote = true
		case strings.HasSuffix(c.Path, "/merge_requests/7/discussions"):
			pos, _ := c.Body["position"].(map[string]interface{})
			sawDiscussion = pos["new_path"] == "app.py" && pos["new_line"] == float64(4) && pos["head_sha"] == "h"
		}
		if !strings.HasPrefix(c.Path, "/api/v4/projects/grp%2Fproj/") {
			t.Errorf("project path not encoded: %s", c.Path)
		}
	}
	if !sawStatus || !sawNote || !sawDiscussion {
		t.Fatalf("calls: %+v", calls)
	}
}

func pemCert(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func TestEvery5dSchedule(t *testing.T) {
	p := defaultCodeScanPolicy().normalised()
	if p.Schedule != "every5d" || p.ScheduleBranches != "all" {
		t.Fatalf("default %+v", p)
	}
	at := time.Date(2026, 11, 26, p.ScheduleHour, 0, 0, 0, time.UTC)
	if !scheduleDue(p, at, time.Time{}) {
		t.Fatal("first run must be due")
	}
	if scheduleDue(p, at, at.AddDate(0, 0, -3)) {
		t.Fatal("3 days after the last run is not due")
	}
	if !scheduleDue(p, at, at.AddDate(0, 0, -5)) {
		t.Fatal("5 days after the last run is due")
	}
	if scheduleDue(p, at.Add(time.Hour), time.Time{}) {
		t.Fatal("only at the schedule hour")
	}
	if (codeScanPolicy{ScheduleBranches: "default"}).normalised().ScheduleBranches != "default" {
		t.Fatal("default branch choice kept")
	}
}
