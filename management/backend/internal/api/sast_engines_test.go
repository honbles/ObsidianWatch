package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestGitRemoteURLs(t *testing.T) {
	cases := []struct {
		conn store.DevOpsConnector
		repo string
		want string
		user string
	}{
		{store.DevOpsConnector{Provider: "github", Credentials: map[string]string{"token": "T"}}, "acme/api", "https://github.com/acme/api.git", "x-access-token:T"},
		{store.DevOpsConnector{Provider: "gitlab", Credentials: map[string]string{"token": "T", "base_url": "https://git.example.com/"}}, "grp/sub/my proj", "https://git.example.com/grp/sub/my%20proj.git", "oauth2:T"},
		{store.DevOpsConnector{Provider: "azuredevops", Org: "o", Credentials: map[string]string{"token": "T"}}, "o/My Project/repo", "https://dev.azure.com/o/My%20Project/_git/repo", "pat:T"},
	}
	for _, c := range cases {
		u, h, err := gitRemote(&c.conn, c.repo)
		if err != nil || u != c.want {
			t.Errorf("%s: %q %v", c.conn.Provider, u, err)
		}
		if strings.Contains(u, "T@") || !strings.HasPrefix(h, "Authorization: Basic ") {
			t.Errorf("token must travel in the header only: %q %q", u, h)
		}
	}
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=dev", "GIT_AUTHOR_EMAIL=d@x", "GIT_COMMITTER_NAME=dev", "GIT_COMMITTER_EMAIL=d@x")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func TestBuiltinHistorySecrets(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q")
	write := func(name, body string) { _ = os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644) }
	write("config.py", "AWS = 'AKIAABCDEFGHIJKLMNOP'\n")
	write("app.py", "print('hi')\n")
	gitRun(t, dir, "add", ".")
	gitRun(t, dir, "commit", "-qm", "add config")
	write("config.py", "AWS = os.environ['AWS']\n")
	write("app.py", "print('hi')\ntoken = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'\n")
	gitRun(t, dir, "commit", "-qam", "move key")

	f, err := builtinHistorySecrets(context.Background(), "acme/x", dir, "", "")
	if err != nil || len(f) != 2 {
		t.Fatalf("findings: %v %+v", err, f)
	}
	bySev := map[string]SASTFinding{}
	for _, x := range f {
		bySev[x.Severity] = x
		if strings.Contains(x.Detail, "AKIAABCDEFGHIJKLMNOP") || strings.Contains(x.Detail, "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
			t.Fatalf("secret must be masked: %s", x.Detail)
		}
	}
	if bySev["high"].File != "config.py" || !strings.Contains(bySev["high"].Detail, "still in its history") {
		t.Fatalf("removed key: %+v", bySev["high"])
	}
	if bySev["critical"].File != "app.py" || bySev["critical"].Line != 2 {
		t.Fatalf("live token: %+v", bySev["critical"])
	}
}

func TestGitleaksReportParsing(t *testing.T) {
	bin := t.TempDir()
	// A stand-in gitleaks that writes a report to --report-path.
	script := `#!/bin/sh
while [ $# -gt 0 ]; do if [ "$1" = "--report-path" ]; then out="$2"; fi; shift; done
cat > "$out" <<'JSON'
[{"RuleID":"aws-access-token","Description":"AWS key","StartLine":3,"File":"a.env","Commit":"0123456789abcdef","Author":"eve","Date":"2026-01-02","Secret":"AKIAZZZZZZZZZZZZZZZZ"},
 {"RuleID":"aws-access-token","Description":"AWS key","StartLine":3,"File":"a.env","Commit":"fedcba","Author":"eve","Secret":"AKIAZZZZZZZZZZZZZZZZ"}]
JSON
`
	if err := os.WriteFile(filepath.Join(bin, "gitleaks"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(t.TempDir(), "r")
	_ = os.MkdirAll(repo, 0o755)
	_ = os.WriteFile(filepath.Join(repo, "a.env"), []byte("K=AKIAZZZZZZZZZZZZZZZZ\n"), 0o644)
	f, err := runGitleaks(context.Background(), filepath.Join(bin, "gitleaks"), "acme/r", repo, "", "")
	if err != nil || len(f) != 1 || f[0].Severity != "critical" || f[0].Engine != "gitleaks" || f[0].RuleID != "SECRET-aws-access-token" {
		t.Fatalf("gitleaks: %v %+v", err, f)
	}
}

const trivySample = `{"Results":[
 {"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm",
  "Packages":[{"Name":"lodash","Version":"4.17.15","Licenses":["MIT"],"Identifier":{"PURL":"pkg:npm/lodash@4.17.15"}},
              {"Name":"left-pad","Version":"1.0.0","Indirect":true,"Identifier":{"PURL":"pkg:npm/left-pad@1.0.0"}}],
  "Vulnerabilities":[{"VulnerabilityID":"CVE-2020-8203","PkgName":"lodash","InstalledVersion":"4.17.15","FixedVersion":"4.17.19","Severity":"HIGH","Title":"prototype pollution","CweIDs":["CWE-1321"]}]},
 {"Target":"Dockerfile","Class":"config","Type":"dockerfile",
  "Misconfigurations":[{"ID":"DS002","AVDID":"AVD-DS-0002","Title":"Image user should not be 'root'","Message":"Specify a non-root USER","Resolution":"Add USER","Severity":"HIGH","Status":"FAIL","CauseMetadata":{"StartLine":1,"EndLine":1}},
                       {"ID":"DS001","Title":"ok","Severity":"LOW","Status":"PASS"}]},
 {"Target":"LICENSE-deps","Class":"license",
  "Licenses":[{"Severity":"HIGH","Category":"restricted","PkgName":"gpl-lib","Name":"GPL-3.0"},
              {"Severity":"LOW","Category":"notice","PkgName":"mit-lib","Name":"MIT"}]}
]}`

func TestParseTrivyAndSBOM(t *testing.T) {
	res, err := parseTrivy([]byte(trivySample), "acme/web", true)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, f := range res.Findings {
		kinds[strings.SplitN(f.RuleID, "-", 2)[0]]++
	}
	if kinds["SCA"] != 1 || kinds["IAC"] != 1 || kinds["LICENSE"] != 1 || res.Components != 2 {
		t.Fatalf("kinds %v comps %d: %+v", kinds, res.Components, res.Findings)
	}
	var doc struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			PURL       string              `json:"purl"`
			Properties []map[string]string `json:"properties"`
		} `json:"components"`
		Vulnerabilities []struct {
			ID      string              `json:"id"`
			Affects []map[string]string `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(res.SBOM, &doc); err != nil || doc.BOMFormat != "CycloneDX" || len(doc.Components) != 2 {
		t.Fatalf("sbom: %v %s", err, res.SBOM)
	}
	if len(doc.Vulnerabilities) != 1 || doc.Vulnerabilities[0].Affects[0]["ref"] != "pkg:npm/lodash@4.17.15" {
		t.Fatalf("vuln affects: %+v", doc.Vulnerabilities)
	}
}

func TestPURLAndManifestSBOM(t *testing.T) {
	for in, want := range map[[3]string]string{
		{"npm", "@scope/pkg", "1.0.0"}:         "pkg:npm/@scope/pkg@1.0.0",
		{"Maven", "org.apache:commons", "2.0"}: "pkg:maven/org.apache/commons@2.0",
		{"Go", "github.com/a/b", "v1.2.3"}:     "pkg:golang/github.com/a/b@v1.2.3",
		{"PyPI", "requests", "2.31.0"}:         "pkg:pypi/requests@2.31.0",
		{"Unknown", "x", "1"}:                  "",
	} {
		if got := purlFor(in[0], in[1], in[2]); got != want {
			t.Errorf("%v: %q", in, got)
		}
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.31.0\nflask==3.0.0\n"), 0o644)
	comps := sbomFromManifests(dir)
	if len(comps) != 2 {
		t.Fatalf("components: %+v", comps)
	}
}

func TestCodeQLLanguageDetection(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string) {
		p := filepath.Join(dir, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte("x"), 0o644)
	}
	for _, f := range []string{"a.go", "b.go", "c.go", "d.go", "x.ts", "y.tsx", "z.js", "m.py", "n.py", "node_modules/q.js", "node_modules/r.js", "node_modules/s.js", "node_modules/t.js"} {
		mk(f)
	}
	langs := codeqlLanguages(dir)
	if len(langs) != 2 || langs[0].Lang != "go" || langs[0].BuildMode != "manual" || langs[1].Lang != "javascript" || langs[1].BuildMode != "none" {
		t.Fatalf("langs: %+v", langs)
	}
}

func TestEngineReportNames(t *testing.T) {
	r := engineReport{}
	r.set("trivy", "ran")
	r.set("codeql", "missing")
	r.set("builtin", "ran")
	if r.names() != "builtin+trivy" {
		t.Fatal(r.names())
	}
	_ = slog.Default()
}
