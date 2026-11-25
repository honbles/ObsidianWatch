package api

// sast_engines.go - Code step 2: the scanners that run on a full checkout.
//
//   - Source: a git clone of the repository (all three providers), so every
//     file is scanned and the full history of the scanned branch is available.
//     The API download (tree + per-file fetch, 1 000-file cap) is the fallback.
//   - Secrets: gitleaks over the whole history; without gitleaks, the built-in
//     secret patterns over `git log -p`. Each finding says whether the secret is
//     still in the current branch or only in history.
//   - Trivy: dependency vulnerabilities from every lockfile it understands
//     (transitive, pom, gradle, pnpm, Gemfile.lock, NuGet, Cargo, ...), IaC and
//     Dockerfile misconfigurations, and licences. Its package list becomes the
//     CycloneDX SBOM.
//   - CodeQL: every supported language in the repository, each with its build
//     mode (none for everything except Go), security-extended suite.
//   - Semgrep-compatible engine: opengrep or semgrep, with locally bundled
//     rules only.
//
// Every tool is optional: a missing one is reported in the scan's engine list
// and the others still run.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Engine status ─────────────────────────────────────────────────────────────

// engineReport records what ran for one scan, shown with the results.
type engineReport map[string]string

func (r engineReport) set(name, status string) { r[name] = status }

// names returns the engines that ran, sorted, joined with "+".
func (r engineReport) names() string {
	var ran []string
	for k, v := range r {
		if v == "ran" {
			ran = append(ran, k)
		}
	}
	sort.Strings(ran)
	if len(ran) == 0 {
		return "none"
	}
	return strings.Join(ran, "+")
}

func toolPath(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// ── Source acquisition: git clone ─────────────────────────────────────────────

// gitRemote returns the HTTPS clone URL for a repository and the Basic
// credentials git should send. The token travels in an http.extraHeader set
// through GIT_CONFIG_* environment variables, never in the URL or argv.
func gitRemote(conn *store.DevOpsConnector, repo string) (cloneURL, authHeader string, err error) {
	token := conn.Credentials["token"]
	basic := func(user string) string {
		return "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+token))
	}
	switch conn.Provider {
	case "github":
		owner, name, ok := strings.Cut(repo, "/")
		if !ok {
			return "", "", fmt.Errorf("bad repo %q", repo)
		}
		return fmt.Sprintf("https://github.com/%s/%s.git", neturl.PathEscape(owner), neturl.PathEscape(name)), basic("x-access-token"), nil
	case "gitlab":
		base := strings.TrimRight(conn.Credentials["base_url"], "/")
		if base == "" {
			base = "https://gitlab.com"
		}
		segs := strings.Split(strings.Trim(repo, "/"), "/")
		for i := range segs {
			segs[i] = neturl.PathEscape(segs[i])
		}
		return base + "/" + strings.Join(segs, "/") + ".git", basic("oauth2"), nil
	case "azuredevops":
		parts := strings.SplitN(repo, "/", 3)
		if len(parts) != 3 {
			return "", "", fmt.Errorf("bad Azure DevOps repo %q", repo)
		}
		c := adoClientFor(conn)
		return fmt.Sprintf("%s/%s/_git/%s", c.baseURL, neturl.PathEscape(parts[1]), neturl.PathEscape(parts[2])), basic("pat"), nil
	}
	return "", "", fmt.Errorf("unknown provider %q", conn.Provider)
}

// gitEnv is the environment for every git command on a cloned repository:
// no user/system config, no prompts, no LFS download, and the auth header.
func gitEnv(authHeader string) []string {
	env := append(scannerEnv(),
		"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_LFS_SKIP_SMUDGE=1", "GIT_ASKPASS=/bin/false",
	)
	if authHeader != "" {
		env = append(env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0="+authHeader)
	}
	return env
}

// gitHardening is passed with -c on every clone of an untrusted repository:
// hooks off, symlinks checked out as plain files (so no scanner follows a link
// out of the checkout), only https, no submodules, no redirects to other hosts.
var gitHardening = []string{
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.symlinks=false",
	"-c", "core.fsmonitor=false",
	"-c", "protocol.allow=never",
	"-c", "protocol.https.allow=always",
	"-c", "http.followRedirects=initial",
	"-c", "submodule.recurse=false",
	"-c", "advice.detachedHead=false",
}

// cloneRepo clones one branch ("HEAD" = the default branch). depth 0 clones
// the branch's whole history (needed for the secrets scan).
func cloneRepo(ctx context.Context, conn *store.DevOpsConnector, repo, branch, dir string, depth int) error {
	if toolPath("git") == "" {
		return fmt.Errorf("git not installed")
	}
	remote, auth, err := gitRemote(conn, repo)
	if err != nil {
		return err
	}
	args := append([]string{}, gitHardening...)
	args = append(args, "clone", "--quiet", "--no-tags", "--single-branch")
	if depth > 0 {
		args = append(args, "--depth", fmt.Sprint(depth))
	}
	if branch != "" && branch != "HEAD" && branch != "unknown" {
		args = append(args, "--branch", branch)
	}
	args = append(args, "--", remote, dir)
	cctx, cancel := context.WithTimeout(ctx, sastCloneTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", args...)
	cmd.Env = gitEnv(auth)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// git may echo the remote; it never contains the token, but trim anyway.
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("git clone: %v: %s%s", err, msg, gitErrHint(msg))
	}
	if mb := dirSizeMB(dir); mb > sastMaxRepoMB() {
		return fmt.Errorf("repository is %d MB, above the %d MB limit (OW_SAST_MAX_REPO_MB)", mb, sastMaxRepoMB())
	}
	return nil
}

const sastCloneTimeout = 5 * time.Minute

func sastMaxRepoMB() int64 {
	var n int64
	if _, err := fmt.Sscan(os.Getenv("OW_SAST_MAX_REPO_MB"), &n); err == nil && n > 0 {
		return n
	}
	return 2048
}

func dirSizeMB(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, e := d.Info(); e == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	return total >> 20
}

// countSourceFiles counts files the SAST engines will look at.
func countSourceFiles(dir string) int {
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || isVendorPath(d.Name()+"/")) {
			return filepath.SkipDir
		}
		if !d.IsDir() && isSourceFile(p) {
			n++
		}
		return nil
	})
	return n
}

// ── Secrets over the full history ─────────────────────────────────────────────

type gitleaksHit struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	File        string `json:"File"`
	Commit      string `json:"Commit"`
	Author      string `json:"Author"`
	Date        string `json:"Date"`
	Secret      string `json:"Secret"`
	Fingerprint string `json:"Fingerprint"`
}

// runHistorySecrets scans every commit of the cloned branch for secrets.
func runHistorySecrets(ctx context.Context, repo, dir, auth, logRange string, logger *slog.Logger) ([]SASTFinding, string, error) {
	if gl := toolPath("gitleaks"); gl != "" {
		f, err := runGitleaks(ctx, gl, repo, dir, auth, logRange)
		if err == nil {
			return f, "gitleaks", nil
		}
		logger.Warn("sast: gitleaks failed, using built-in history scan", "repo", repo, "err", err)
	}
	f, err := builtinHistorySecrets(ctx, repo, dir, auth, logRange)
	return f, "history", err
}

func runGitleaks(ctx context.Context, bin, repo, dir, auth, logRange string) ([]SASTFinding, error) {
	report := filepath.Join(filepath.Dir(dir), filepath.Base(dir)+".gitleaks.json")
	defer os.Remove(report)
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// Not --redact: the secret is needed to tell whether it is still in the
	// current branch. It is never stored; only a masked preview is kept.
	args := []string{"git", "--no-banner", "--exit-code", "0",
		"--report-format", "json", "--report-path", report, "--max-target-megabytes", "5"}
	if logRange != "" {
		args = append(args, "--log-opts="+logRange)
	}
	cmd := exec.CommandContext(cctx, bin, append(args, dir)...)
	cmd.Env = gitEnv(auth)
	if out, err := cmd.CombinedOutput(); err != nil {
		// gitleaks before 8.19 has no "git" sub-command.
		dargs := []string{"detect", "--no-banner", "--exit-code", "0",
			"--report-format", "json", "--report-path", report, "--source", dir}
		if logRange != "" {
			dargs = append(dargs, "--log-opts="+logRange)
		}
		cmd = exec.CommandContext(cctx, bin, dargs...)
		cmd.Env = gitEnv(auth)
		if out2, err2 := cmd.CombinedOutput(); err2 != nil {
			return nil, fmt.Errorf("%v: %s / %s", err2, trimOut(out), trimOut(out2))
		}
	}
	b, err := os.ReadFile(report)
	if err != nil {
		return nil, err
	}
	var hits []gitleaksHit
	if err := json.Unmarshal(b, &hits); err != nil {
		return nil, err
	}
	out := make([]SASTFinding, 0, len(hits))
	seen := map[string]bool{}
	for _, h := range hits {
		key := h.RuleID + "\x00" + h.File + "\x00" + h.Secret
		if seen[key] { // the same secret in many commits is one finding
			continue
		}
		seen[key] = true
		out = append(out, secretFinding(repo, dir, h.RuleID, h.Description, h.File, h.StartLine, h.Commit, h.Author, h.Date, h.Secret, "gitleaks"))
	}
	return out, nil
}

func trimOut(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// secretFinding builds one finding; the secret itself is masked.
func secretFinding(repo, dir, ruleID, desc, file string, line int, commit, author, date, secret, engine string) SASTFinding {
	live := secretInHead(dir, file, secret)
	sev, state := "high", "removed from the current branch but still in its history"
	if live {
		sev, state = "critical", "still present in the current branch"
	}
	short := commit
	if len(short) > 10 {
		short = short[:10]
	}
	if desc == "" {
		desc = ruleID
	}
	detail := fmt.Sprintf("%s (%s) introduced in commit %s", desc, maskSecret(secret), short)
	if author != "" {
		detail += " by " + author
	}
	if date != "" {
		detail += " on " + date
	}
	detail += "; " + state + "."
	return SASTFinding{
		RuleID: "SECRET-" + ruleID, Severity: sev, CWE: "CWE-798", OWASP: "A07:2021 Identification and Authentication Failures",
		Title: "Secret in repository history: " + desc, Detail: detail,
		Fix:  "Revoke and rotate the credential at its issuer first; removing it from the code or rewriting history does not invalidate it. Then move it to a secrets manager.",
		Repo: repo, File: file, Line: line, Engine: engine,
	}
}

func secretInHead(dir, file, secret string) bool {
	if secret == "" || file == "" {
		return false
	}
	p := filepath.Join(dir, filepath.FromSlash(file))
	if rel, err := filepath.Rel(dir, p); err != nil || strings.HasPrefix(rel, "..") {
		return false
	}
	b, err := os.ReadFile(p)
	return err == nil && strings.Contains(string(b), secret)
}

func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 8) + s[len(s)-2:]
}

var hunkRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// builtinHistorySecrets streams `git log -p` and applies the built-in secret
// patterns to added lines. Used when gitleaks is not installed.
func builtinHistorySecrets(ctx context.Context, repo, dir, auth, logRange string) ([]SASTFinding, error) {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	args := []string{"-C", dir, "log", "-p", "--no-color", "--no-ext-diff", "--unified=0",
		"--format=@@commit %H%x09%an%x09%aI", "--max-count=5000"}
	if logRange != "" {
		args = append(args, logRange, "--")
	}
	cmd := exec.CommandContext(cctx, "git", args...)
	cmd.Env = gitEnv(auth)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() { _ = cmd.Wait() }()
	return scanGitLogPatch(io.LimitReader(stdout, 512<<20), repo, dir), nil
}

// scanGitLogPatch parses `git log -p --unified=0` output.
func scanGitLogPatch(r io.Reader, repo, dir string) []SASTFinding {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var commit, author, date, file string
	line := 0
	var out []SASTFinding
	seen := map[string]bool{}
	for sc.Scan() {
		t := sc.Text()
		switch {
		case strings.HasPrefix(t, "@@commit "):
			parts := strings.SplitN(strings.TrimPrefix(t, "@@commit "), "\t", 3)
			commit, author, date = parts[0], "", ""
			if len(parts) == 3 {
				author, date = parts[1], parts[2]
			}
			file = ""
		case strings.HasPrefix(t, "+++ "):
			file = strings.TrimPrefix(strings.TrimPrefix(t, "+++ "), "b/")
			if file == "/dev/null" {
				file = ""
			}
		case strings.HasPrefix(t, "@@ "):
			if m := hunkRe.FindStringSubmatch(t); m != nil {
				fmt.Sscan(m[1], &line)
			}
		case strings.HasPrefix(t, "+") && file != "":
			added := t[1:]
			for _, p := range secretPatternsDef {
				if p.sev == "low" || p.sev == "medium" {
					continue // too noisy across a whole history
				}
				m := p.pattern.FindStringSubmatch(added)
				if m == nil {
					continue
				}
				secret := m[0]
				if len(m) > 1 && m[len(m)-1] != "" {
					secret = m[len(m)-1]
				}
				key := p.name + "\x00" + file + "\x00" + secret
				if seen[key] {
					continue
				}
				seen[key] = true
				id := strings.ToLower(strings.ReplaceAll(p.name, " ", "-"))
				out = append(out, secretFinding(repo, dir, id, p.name, file, line, commit, author, date, secret, "history"))
			}
			line++
		}
	}
	return out
}

// ── Trivy: dependencies, IaC, licences, SBOM ─────────────────────────────────

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Packages        []trivyPkg
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"VulnerabilityID"`
			PkgName          string   `json:"PkgName"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
			Severity         string   `json:"Severity"`
			Title            string   `json:"Title"`
			PrimaryURL       string   `json:"PrimaryURL"`
			CweIDs           []string `json:"CweIDs"`
			PkgIdentifier    struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
		} `json:"Vulnerabilities"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			AVDID         string `json:"AVDID"`
			Title         string `json:"Title"`
			Description   string `json:"Description"`
			Message       string `json:"Message"`
			Resolution    string `json:"Resolution"`
			Severity      string `json:"Severity"`
			Status        string `json:"Status"`
			PrimaryURL    string `json:"PrimaryURL"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
				EndLine   int `json:"EndLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
		Licenses []struct {
			Severity string `json:"Severity"`
			Category string `json:"Category"`
			PkgName  string `json:"PkgName"`
			FilePath string `json:"FilePath"`
			Name     string `json:"Name"`
		} `json:"Licenses"`
	} `json:"Results"`
}

type trivyPkg struct {
	Name       string   `json:"Name"`
	Version    string   `json:"Version"`
	Licenses   []string `json:"Licenses"`
	Indirect   bool     `json:"Indirect"`
	Identifier struct {
		PURL string `json:"PURL"`
	} `json:"Identifier"`
}

// trivyResult is what one Trivy run produced.
type trivyResult struct {
	Findings   []SASTFinding
	SBOM       []byte
	VulnRan    bool // dependency vulnerabilities were checked (OSV can be skipped)
	Components int
}

func trivyCacheDir() string {
	if d := os.Getenv("OW_TRIVY_CACHE_DIR"); d != "" {
		return d
	}
	return "/var/cache/trivy"
}

// trivyDBPresent reports whether the vulnerability database is in the cache.
func trivyDBPresent() bool {
	_, err := os.Stat(filepath.Join(trivyCacheDir(), "db", "trivy.db"))
	return err == nil
}

// scannerDBUpdates: the image ships the databases; refreshing them needs
// outbound access to the Trivy DB registry. Off with OW_SCANNER_DB_UPDATE=false.
func scannerDBUpdates() bool { return os.Getenv("OW_SCANNER_DB_UPDATE") != "false" }

func runTrivy(ctx context.Context, repo, dir string) (trivyResult, error) {
	bin := toolPath("trivy")
	if bin == "" {
		return trivyResult{}, errToolMissing
	}
	scanners := []string{"misconfig", "license"}
	vuln := trivyDBPresent() || scannerDBUpdates()
	if vuln {
		scanners = append([]string{"vuln"}, scanners...)
	}
	report := filepath.Join(filepath.Dir(dir), filepath.Base(dir)+".trivy.json")
	defer os.Remove(report)
	args := []string{"fs", "--quiet", "--format", "json", "--output", report,
		"--scanners", strings.Join(scanners, ","), "--list-all-pkgs",
		"--cache-dir", trivyCacheDir(), "--skip-check-update", "--offline-scan",
		"--exit-code", "0", "--timeout", "8m", "--skip-dirs", "**/node_modules,**/vendor,.git"}
	if !scannerDBUpdates() {
		args = append(args, "--skip-db-update", "--skip-java-db-update")
	}
	args = append(args, dir)
	cctx, cancel := context.WithTimeout(ctx, 9*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = append(scannerEnv(), "TRIVY_NO_PROGRESS=true", "TRIVY_DISABLE_TELEMETRY=true")
	if out, err := cmd.CombinedOutput(); err != nil {
		return trivyResult{}, fmt.Errorf("trivy: %v: %s", err, trimOut(out))
	}
	b, err := os.ReadFile(report)
	if err != nil {
		return trivyResult{}, err
	}
	return parseTrivy(b, repo, vuln)
}

var errToolMissing = fmt.Errorf("not installed")

func trivySev(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	}
	return "low"
}

func parseTrivy(b []byte, repo string, vulnRan bool) (trivyResult, error) {
	var rep trivyReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return trivyResult{}, err
	}
	res := trivyResult{VulnRan: vulnRan}
	var comps []sbomComponent
	seenPkg := map[string]bool{}
	for _, r := range rep.Results {
		for _, p := range r.Packages {
			key := p.Identifier.PURL
			if key == "" {
				key = r.Type + ":" + p.Name + "@" + p.Version
			}
			if seenPkg[key] {
				continue
			}
			seenPkg[key] = true
			comps = append(comps, sbomComponent{Name: p.Name, Version: p.Version, PURL: p.Identifier.PURL,
				Licenses: p.Licenses, Ecosystem: r.Type, File: r.Target, Indirect: p.Indirect})
		}
		for _, v := range r.Vulnerabilities {
			fix := "No fixed version is published yet; consider an alternative package or a compensating control."
			if v.FixedVersion != "" {
				fix = fmt.Sprintf("Upgrade %s to %s or later.", v.PkgName, v.FixedVersion)
			}
			cwe := "CWE-1104"
			if len(v.CweIDs) > 0 {
				cwe = v.CweIDs[0]
			}
			title := v.Title
			if title == "" {
				title = v.VulnerabilityID
			}
			res.Findings = append(res.Findings, SASTFinding{
				RuleID: "SCA-" + v.VulnerabilityID, Severity: trivySev(v.Severity), CWE: cwe,
				OWASP:  "A06:2021 Vulnerable and Outdated Components",
				Title:  fmt.Sprintf("%s in %s %s", v.VulnerabilityID, v.PkgName, v.InstalledVersion),
				Detail: strings.TrimSpace(title + " " + v.PrimaryURL), Fix: fix,
				Repo: repo, File: r.Target, Engine: "trivy",
				Ecosystem: trivyEcosystem(r.Type), Package: v.PkgName, Version: v.InstalledVersion,
			})
		}
		for _, m := range r.Misconfigurations {
			if m.Status != "" && m.Status != "FAIL" {
				continue
			}
			id := m.AVDID
			if id == "" {
				id = m.ID
			}
			detail := m.Message
			if detail == "" {
				detail = m.Description
			}
			res.Findings = append(res.Findings, SASTFinding{
				RuleID: "IAC-" + id, Severity: trivySev(m.Severity), CWE: "CWE-16",
				OWASP: "A05:2021 Security Misconfiguration", Title: m.Title,
				Detail: strings.TrimSpace(detail + " " + m.PrimaryURL), Fix: m.Resolution,
				Repo: repo, File: r.Target, Line: m.CauseMetadata.StartLine, EndLine: m.CauseMetadata.EndLine, Engine: "trivy",
			})
		}
		for _, l := range r.Licenses {
			cat := strings.ToLower(l.Category)
			if cat != "forbidden" && cat != "restricted" && cat != "reciprocal" {
				continue // notice / permissive / unencumbered / unknown are not findings
			}
			where := l.FilePath
			if where == "" {
				where = r.Target
			}
			subject := l.PkgName
			if subject == "" {
				subject = where
			}
			res.Findings = append(res.Findings, SASTFinding{
				RuleID: "LICENSE-" + strings.ToUpper(cat), Severity: trivySev(l.Severity),
				Title:  fmt.Sprintf("%s licence (%s): %s", l.Name, cat, subject),
				Detail: fmt.Sprintf("%s is licensed under %s, a %s licence. Check it against your distribution model and policy.", subject, l.Name, cat),
				Fix:    "Confirm the licence is acceptable for how this code is shipped, or replace the dependency.",
				Repo:   repo, File: where, Engine: "trivy",
			})
		}
	}
	res.Components = len(comps)
	res.SBOM = buildCycloneDX(repo, comps, res.Findings)
	return res, nil
}

// ── SBOM (CycloneDX 1.5 JSON) ─────────────────────────────────────────────────

type sbomComponent struct {
	Name, Version, PURL, Ecosystem, File string
	Licenses                             []string
	Indirect                             bool
}

// scaEcosystemPURL maps the built-in parser's ecosystems to purl types.
var scaEcosystemPURL = map[string]string{
	"npm": "npm", "PyPI": "pypi", "Go": "golang", "Maven": "maven", "RubyGems": "gem",
	"crates.io": "cargo", "Packagist": "composer", "NuGet": "nuget", "Pub": "pub", "Hex": "hex",
}

func purlFor(eco, name, version string) string {
	t := scaEcosystemPURL[eco]
	if t == "" {
		return ""
	}
	ns, n := "", name
	if t == "maven" {
		if g, a, ok := strings.Cut(name, ":"); ok {
			ns, n = g, a
		}
	} else if i := strings.LastIndex(name, "/"); i > 0 && (t == "npm" || t == "golang" || t == "composer") {
		ns, n = name[:i], name[i+1:]
	}
	p := "pkg:" + t + "/"
	if ns != "" {
		segs := strings.Split(ns, "/")
		for i := range segs {
			segs[i] = neturl.PathEscape(segs[i])
		}
		p += strings.Join(segs, "/") + "/"
	}
	p += neturl.PathEscape(n)
	if version != "" {
		p += "@" + neturl.PathEscape(version)
	}
	return p
}

// sbomFromManifests builds the component list from the built-in manifest
// parser when Trivy is not installed.
func sbomFromManifests(dir string) []sbomComponent {
	var comps []sbomComponent
	seen := map[string]bool{}
	files := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if d.IsDir() || files >= 200 || !isScaManifest(p) {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil || len(b) > 16<<20 {
			return nil
		}
		files++
		rel, _ := filepath.Rel(dir, p)
		for _, pk := range parseManifest(filepath.ToSlash(rel), b) {
			k := pk.Ecosystem + ":" + pk.Name + "@" + pk.Version
			if seen[k] {
				continue
			}
			seen[k] = true
			comps = append(comps, sbomComponent{Name: pk.Name, Version: pk.Version, Ecosystem: pk.Ecosystem,
				PURL: purlFor(pk.Ecosystem, pk.Name, pk.Version), File: pk.File})
		}
		return nil
	})
	return comps
}

func buildCycloneDX(repo string, comps []sbomComponent, findings []SASTFinding) []byte {
	type lic struct {
		License map[string]string `json:"license"`
	}
	type comp struct {
		Type       string              `json:"type"`
		BOMRef     string              `json:"bom-ref"`
		Name       string              `json:"name"`
		Version    string              `json:"version,omitempty"`
		PURL       string              `json:"purl,omitempty"`
		Licenses   []lic               `json:"licenses,omitempty"`
		Scope      string              `json:"scope,omitempty"`
		Properties []map[string]string `json:"properties,omitempty"`
	}
	type vuln struct {
		ID      string              `json:"id"`
		Ratings []map[string]string `json:"ratings,omitempty"`
		Detail  string              `json:"detail,omitempty"`
		Affects []map[string]string `json:"affects,omitempty"`
	}
	sort.Slice(comps, func(i, j int) bool {
		if comps[i].Name != comps[j].Name {
			return comps[i].Name < comps[j].Name
		}
		return comps[i].Version < comps[j].Version
	})
	out := make([]comp, 0, len(comps))
	refByName := map[string]string{}
	for i, c := range comps {
		ref := c.PURL
		if ref == "" {
			ref = fmt.Sprintf("comp-%d", i+1)
		}
		cc := comp{Type: "library", BOMRef: ref, Name: c.Name, Version: c.Version, PURL: c.PURL}
		for _, l := range c.Licenses {
			key := "name"
			if spdxLike(l) {
				key = "id"
			}
			cc.Licenses = append(cc.Licenses, lic{License: map[string]string{key: l}})
		}
		if c.Indirect {
			cc.Properties = append(cc.Properties, map[string]string{"name": "obsidianwatch:dependency", "value": "transitive"})
		}
		if c.File != "" {
			cc.Properties = append(cc.Properties, map[string]string{"name": "obsidianwatch:source-file", "value": c.File})
		}
		out = append(out, cc)
		refByName[strings.ToLower(c.Name)+"@"+c.Version] = ref
	}
	var vulns []vuln
	for _, f := range findings {
		if !strings.HasPrefix(f.RuleID, "SCA-") {
			continue
		}
		v := vuln{ID: strings.TrimPrefix(f.RuleID, "SCA-"), Detail: f.Detail,
			Ratings: []map[string]string{{"severity": f.Severity}}}
		// Title is "<id> in <pkg> <version>".
		if _, rest, ok := strings.Cut(f.Title, " in "); ok {
			if name, ver, ok2 := strings.Cut(rest, " "); ok2 {
				if ref := refByName[strings.ToLower(name)+"@"+ver]; ref != "" {
					v.Affects = []map[string]string{{"ref": ref}}
				}
			}
		}
		vulns = append(vulns, v)
	}
	doc := map[string]interface{}{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools":     map[string]interface{}{"components": []map[string]string{{"type": "application", "name": "ObsidianWatch"}}},
			"component": map[string]string{"type": "application", "name": repo, "bom-ref": "root"},
		},
		"components": out,
	}
	if len(vulns) > 0 {
		doc["vulnerabilities"] = vulns
	}
	b, _ := json.Marshal(doc)
	return b
}

var spdxIDRe = regexp.MustCompile(`^[A-Za-z0-9.+-]+$`)

func spdxLike(s string) bool { return spdxIDRe.MatchString(s) && !strings.Contains(s, " ") }

// ── CodeQL: every language, with the right build mode ────────────────────────

// codeqlLang describes one CodeQL language as the CLI names it.
type codeqlLang struct {
	Lang, Pack, Suite, BuildMode string
}

var codeqlByExt = map[string]codeqlLang{
	".go":   {"go", "go-queries", "go-security-extended.qls", "manual"},
	".js":   {"javascript", "javascript-queries", "javascript-security-extended.qls", "none"},
	".jsx":  {"javascript", "javascript-queries", "javascript-security-extended.qls", "none"},
	".mjs":  {"javascript", "javascript-queries", "javascript-security-extended.qls", "none"},
	".ts":   {"javascript", "javascript-queries", "javascript-security-extended.qls", "none"},
	".tsx":  {"javascript", "javascript-queries", "javascript-security-extended.qls", "none"},
	".py":   {"python", "python-queries", "python-security-extended.qls", "none"},
	".java": {"java", "java-queries", "java-security-extended.qls", "none"},
	".kt":   {"java", "java-queries", "java-security-extended.qls", "none"},
	".cs":   {"csharp", "csharp-queries", "csharp-security-extended.qls", "none"},
	".rb":   {"ruby", "ruby-queries", "ruby-security-extended.qls", "none"},
	".c":    {"cpp", "cpp-queries", "cpp-security-extended.qls", "none"},
	".cc":   {"cpp", "cpp-queries", "cpp-security-extended.qls", "none"},
	".cpp":  {"cpp", "cpp-queries", "cpp-security-extended.qls", "none"},
	".cxx":  {"cpp", "cpp-queries", "cpp-security-extended.qls", "none"},
	".h":    {"cpp", "cpp-queries", "cpp-security-extended.qls", "none"},
	".hpp":  {"cpp", "cpp-queries", "cpp-security-extended.qls", "none"},
	".rs":   {"rust", "rust-queries", "rust-security-extended.qls", "none"},
}

// codeqlLanguages returns the CodeQL languages present in dir, most files
// first, ignoring languages with fewer than 3 files.
func codeqlLanguages(dir string) []codeqlLang {
	counts := map[string]int{}
	byLang := map[string]codeqlLang{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor" || d.Name() == "third_party") {
			return filepath.SkipDir
		}
		if l, ok := codeqlByExt[strings.ToLower(filepath.Ext(p))]; ok && !d.IsDir() {
			counts[l.Lang]++
			byLang[l.Lang] = l
		}
		return nil
	})
	var out []codeqlLang
	for l, n := range counts {
		if n >= 3 {
			out = append(out, byLang[l])
		}
	}
	sort.Slice(out, func(i, j int) bool { return counts[out[i].Lang] > counts[out[j].Lang] })
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

// runCodeQLAll analyses every language found, sharing the caller's deadline.
func runCodeQLAll(ctx context.Context, repoDir, repoName string, logger *slog.Logger) ([]SASTFinding, []string, error) {
	langs := codeqlLanguages(repoDir)
	if len(langs) == 0 {
		return nil, nil, nil
	}
	var all []SASTFinding
	var done []string
	var lastErr error
	for _, l := range langs {
		if ctx.Err() != nil {
			break
		}
		f, err := runCodeQLLang(ctx, repoDir, repoName, l, logger)
		if err != nil {
			lastErr = err
			logger.Warn("sast: codeql language failed", "repo", repoName, "lang", l.Lang, "err", err)
			continue
		}
		done = append(done, l.Lang)
		all = append(all, f...)
	}
	if len(done) == 0 {
		return nil, nil, lastErr
	}
	return all, done, nil
}

func runCodeQLLang(ctx context.Context, repoDir, repoName string, l codeqlLang, logger *slog.Logger) ([]SASTFinding, error) {
	dbDir := repoDir + ".codeql-" + l.Lang
	defer os.RemoveAll(dbDir)
	env := scannerEnv()
	if l.Lang == "go" {
		// Go has no build-mode none. `go build` with cgo off runs no code
		// from the repository; the toolchain stays the installed one.
		env = append(env, "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOFLAGS=-mod=mod")
	}
	args := []string{"database", "create", dbDir,
		"--language=" + l.Lang, "--build-mode=" + l.BuildMode, "--source-root=" + repoDir,
		"--overwrite", "--threads=2"}
	if l.BuildMode == "manual" {
		// An explicit command rather than autobuild, so no Makefile or build
		// script from the repository is ever run.
		args = append(args, "--command=go build ./...")
	}
	create := exec.CommandContext(ctx, "codeql", args...)
	create.Env = env
	if out, err := create.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("database create: %v: %s", err, trimOut(out))
	}
	sarif := dbDir + ".sarif"
	defer os.Remove(sarif)
	analyze := exec.CommandContext(ctx, "codeql", "database", "analyze", dbDir,
		"--format=sarifv2.1.0", "--output="+sarif, "--threads=2",
		fmt.Sprintf("codeql/%s:codeql-suites/%s", l.Pack, l.Suite))
	analyze.Env = env
	if out, err := analyze.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("analyze: %v: %s", err, trimOut(out))
	}
	return parseSARIF(sarif, repoName, repoDir)
}

// ── Semgrep-compatible engine with bundled rules ──────────────────────────────

// semgrepRulesDir is the locally bundled rule set. No registry download is
// ever attempted: the Semgrep registry rules are under the Semgrep Rules
// License, which does not allow use in a product like this one.
func semgrepRulesDir() string {
	for _, d := range []string{os.Getenv("OW_SEMGREP_RULES"), "/opt/obsidianwatch/rules/opengrep", "/semgrep-rules"} {
		if d == "" {
			continue
		}
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d
		}
	}
	return ""
}

// semgrepEngine returns the binary to run (opengrep preferred) and its rules.
func semgrepEngine() (bin, rules string) {
	rules = semgrepRulesDir()
	if rules == "" {
		return "", ""
	}
	return toolPath("opengrep", "semgrep"), rules
}

// sastHistoryEnabled: full-history secret scanning clones the whole branch.
// Off with OW_SAST_SECRET_HISTORY=false (shallow clone, current files only).
func sastHistoryEnabled() bool { return os.Getenv("OW_SAST_SECRET_HISTORY") != "false" }

// nullJSON stores an empty document as SQL NULL.
func nullJSON(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}

// sastSourceWarning explains an empty scan: the repository could not be
// downloaded either way (usually the token's permissions).
func sastSourceWarning(scanned int, lastErr string) string {
	if scanned > 0 || lastErr == "" {
		return ""
	}
	return "No repository could be downloaded. Check that the connector token can read the repository. Last error: " + lastErr
}

// scanOpts selects what scanCheckout runs.
type scanOpts struct {
	History  bool   // the checkout has git history to scan for secrets
	LogRange string // limit the history scan to a commit range (base..head); "" = all
	Semgrep  bool
	CodeQL   bool
}

// scanCheckout runs every installed engine over one checked-out repository.
// It is shared by manual SAST scans, scheduled and on-push scans, and PR checks.
func scanCheckout(ctx context.Context, conn *store.DevOpsConnector, repo, repoDir string, opts scanOpts, engines engineReport, logger *slog.Logger) (out []SASTFinding, sbom []byte) {
	// Secrets across the branch history (only with a full clone).
	if opts.History {
		_, auth, _ := gitRemote(conn, repo)
		if f, eng, err := runHistorySecrets(ctx, repo, repoDir, auth, opts.LogRange, logger); err != nil {
			engines.set("secrets-history", "failed: "+err.Error())
		} else {
			engines.set(eng, "ran")
			out = append(out, f...)
		}
	} else {
		engines.set("secrets-history", "skipped: no full git history (API download or shallow clone)")
	}

	// Semgrep-compatible engine with bundled rules.
	if opts.Semgrep {
		semgrepCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		results, err := runSemgrep(semgrepCtx, repoDir, logger)
		cancel()
		if err != nil {
			engines.set("semgrep", "failed: "+err.Error())
			logger.Warn("sast: semgrep failed", "repo", repo, "err", err)
		} else {
			engines.set("semgrep", "ran")
			out = append(out, convertSemgrepFindings(results, repo, repoDir)...)
		}
	} else {
		engines.set("semgrep", "missing: no opengrep/semgrep binary or no bundled rules")
	}

	// Trivy: dependencies (transitive), IaC, Dockerfiles, licences, SBOM.
	trivyOut, trivyErr := runTrivy(ctx, repo, repoDir)
	switch {
	case trivyErr == errToolMissing:
		engines.set("trivy", "missing")
	case trivyErr != nil:
		engines.set("trivy", "failed: "+trivyErr.Error())
		logger.Warn("sast: trivy failed", "repo", repo, "err", trivyErr)
	default:
		engines.set("trivy", "ran")
		out = append(out, trivyOut.Findings...)
		sbom = trivyOut.SBOM
	}
	if sbom == nil {
		sbom = buildCycloneDX(repo, sbomFromManifests(repoDir), nil)
	}

	// OSV lookup of the built-in manifest parser, unless Trivy already
	// checked dependency vulnerabilities.
	if !trivyOut.VulnRan || trivyErr != nil {
		if scaFindingsList, scaErr := runSCAOnDir(ctx, repo, repoDir); scaErr != nil {
			engines.set("osv", "failed: "+scaErr.Error())
		} else {
			engines.set("osv", "ran")
			out = append(out, scaFindingsList...)
		}
	}

	// Built-in rules always run.
	out = append(out, runBuiltinRulesOnDir(repo, repoDir)...)
	engines.set("builtin", "ran")

	// CodeQL: every supported language in the repository.
	if opts.CodeQL {
		codeqlCtx, cancelCQ := context.WithTimeout(ctx, 12*time.Minute)
		codeqlFindings, langs, codeqlErr := runCodeQLAll(codeqlCtx, repoDir, repo, logger)
		cancelCQ()
		switch {
		case codeqlErr != nil:
			engines.set("codeql", "failed: "+codeqlErr.Error())
		case len(langs) == 0:
			engines.set("codeql", "skipped: no supported language")
		default:
			engines.set("codeql", "ran")
			engines.set("codeql-languages", strings.Join(langs, ","))
			out = append(out, codeqlFindings...)
		}
	} else {
		engines.set("codeql", "missing")
	}
	return out, sbom
}

// saveSASTResult upserts the stored result of a scan: one row per
// (connector, repository or '' for all, branch).
func saveSASTResult(ctx context.Context, db *store.DB, connID int64, repo, branch string, engines engineReport, findings []SASTFinding, sbom []byte, repos, files int) error {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	if findings == nil {
		findings = []SASTFinding{}
	}
	findingsJSON, _ := json.Marshal(findings)
	enginesJSON, _ := json.Marshal(engines)
	_, err := db.ExecContext(ctx, `
		INSERT INTO sast_results
			(connector_id, repo, branch, engine, repo_count, file_count, finding_count,
			 critical_count, high_count, medium_count, findings, engines, sbom)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (connector_id, repo, branch)
		DO UPDATE SET
			scanned_at    = NOW(),
			engine        = EXCLUDED.engine,
			repo_count    = EXCLUDED.repo_count,
			file_count    = EXCLUDED.file_count,
			finding_count = EXCLUDED.finding_count,
			critical_count= EXCLUDED.critical_count,
			high_count    = EXCLUDED.high_count,
			medium_count  = EXCLUDED.medium_count,
			findings      = EXCLUDED.findings,
			engines       = EXCLUDED.engines,
			sbom          = EXCLUDED.sbom,
			ai_summary    = NULL,
			ai_analysed_at= NULL`,
		connID, repo, branch, engines.names(), repos, files, len(findings),
		counts["critical"], counts["high"], counts["medium"],
		findingsJSON, enginesJSON, nullJSON(sbom))
	return err
}

// gitErrHint turns git's prompt failure into the likely cause.
func gitErrHint(msg string) string {
	if strings.Contains(msg, "could not read Username") || strings.Contains(msg, "Authentication failed") || strings.Contains(msg, "403") {
		return " (the provider rejected the token, or the token cannot read this repository)"
	}
	return ""
}

// trivyEcosystem maps Trivy's lockfile types to OSV ecosystem names (the ones
// the runtime inventory reports).
func trivyEcosystem(t string) string {
	switch t {
	case "npm", "yarn", "pnpm", "bun", "node-pkg":
		return "npm"
	case "pip", "pipenv", "poetry", "uv", "python-pkg", "conda-pkg":
		return "PyPI"
	case "gomod", "gobinary":
		return "Go"
	case "pom", "gradle", "jar", "sbt":
		return "Maven"
	case "nuget", "dotnet-core", "packages-props":
		return "NuGet"
	case "bundler", "gemspec":
		return "RubyGems"
	case "cargo", "rust-binary":
		return "crates.io"
	case "composer", "composer-vendor":
		return "Packagist"
	}
	return t
}
