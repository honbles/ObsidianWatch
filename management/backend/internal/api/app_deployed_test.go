package api

import (
	"context"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"obsidianwatch/management/internal/store"
)

// A deployed commit that is no longer the branch head is fetched and checked
// out exactly.
func TestCloneCommitExact(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	backend := strings.TrimSpace(func() string { o, _ := exec.Command(gitBin, "--exec-path").Output(); return string(o) }()) + "/git-http-backend"
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend not available")
	}
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
	_ = os.WriteFile(filepath.Join(work, "v.txt"), []byte("deployed"), 0o644)
	run(work, "add", ".")
	run(work, "commit", "-qm", "v1")
	deployed := run(work, "rev-parse", "HEAD")
	_ = os.WriteFile(filepath.Join(work, "v.txt"), []byte("newer"), 0o644)
	run(work, "commit", "-qam", "v2")
	bare := filepath.Join(root, "grp", "proj.git")
	_ = os.MkdirAll(filepath.Dir(bare), 0o755)
	run(root, "clone", "-q", "--bare", work, bare)
	run(bare, "config", "uploadpack.allowReachableSHA1InWant", "true")

	mux := http.NewServeMux()
	mux.Handle("/grp/", &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	certFile := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(certFile, pemCert(srv), 0o644)
	t.Setenv("GIT_SSL_CAINFO", certFile)
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")

	conn := &store.DevOpsConnector{Provider: "gitlab", Credentials: map[string]string{"token": "t", "base_url": srv.URL}}
	dir := filepath.Join(t.TempDir(), "c")
	if err := cloneCommit(context.Background(), conn, "grp/proj", deployed, dir, 1); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "v.txt")); string(b) != "deployed" {
		t.Fatalf("checked out %q", b)
	}
	if gitHeadSHA(context.Background(), dir) != deployed {
		t.Fatal("head sha")
	}
	if err := cloneCommit(context.Background(), conn, "grp/proj", "abc1234", t.TempDir(), 1); err == nil {
		t.Fatal("a short id must be refused")
	}
}
