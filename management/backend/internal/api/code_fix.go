package api

// code_fix.go - Code step 5: fix suggestions.
//
//   - Dependency findings get a deterministic fix (the fixed version, and the
//     command for the package manager), no AI involved.
//   - Code findings get an AI suggestion: the model sees the flagged lines
//     with up to 30 lines around them and returns a replacement for a line
//     range, an explanation, a confidence and whether the finding looks like
//     a false positive. The server checks the range and builds the diff
//     itself; the model's text is never applied to anything.
//
// Source leaves the server only when the operator allows it (setting
// ai.send_source_snippets = "true"), as for the other AI features. The code
// is fenced as untrusted input. Suggestions are cached per finding and file
// content, and rate limited.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
)

// fixSuggestion is returned to the UI and used in PR comments.
type fixSuggestion struct {
	Kind           string `json:"kind"` // dependency | code | none
	Explanation    string `json:"explanation"`
	Confidence     int    `json:"confidence,omitempty"`
	LikelyFalsePos bool   `json:"likely_false_positive,omitempty"`
	FalsePosReason string `json:"false_positive_reason,omitempty"`
	File           string `json:"file,omitempty"`
	StartLine      int    `json:"start_line,omitempty"`
	EndLine        int    `json:"end_line,omitempty"`
	Replacement    string `json:"replacement,omitempty"`
	Diff           string `json:"diff,omitempty"`
	Command        string `json:"command,omitempty"`
	Model          string `json:"model,omitempty"`
	Cached         bool   `json:"cached,omitempty"`
}

// ── Dependencies: no AI ───────────────────────────────────────────────────────

var fixedVersionRe = regexp.MustCompile(`(?i)(?:upgrade \S+ to|to) ([0-9][\w.\-+]*)( or later)?`)

func dependencyFix(f SASTFinding) fixSuggestion {
	fixed := ""
	if m := fixedVersionRe.FindStringSubmatch(f.Fix); m != nil {
		fixed = m[1]
	}
	s := fixSuggestion{Kind: "dependency", File: f.File}
	if fixed == "" {
		s.Explanation = "No fixed version is published for " + f.Package + " " + f.Version + ". Replace the package, or reduce exposure (it is " + reachWord(f) + ")."
		return s
	}
	s.Explanation = fmt.Sprintf("Upgrade %s from %s to %s or later, then regenerate %s.", f.Package, f.Version, fixed, filepath.Base(f.File))
	s.Command = packageUpgradeCommand(f.Ecosystem, f.Package, fixed, f.File)
	return s
}

func reachWord(f SASTFinding) string {
	if f.Reachability == nil {
		return "of unknown runtime status"
	}
	return map[string]string{"loaded": "loaded by a running service", "deployed": "deployed but not seen loaded",
		"not_running": "not seen running", "unknown": "of unknown runtime status"}[f.Reachability.Level]
}

func packageUpgradeCommand(eco, pkg, version, file string) string {
	base := strings.ToLower(filepath.Base(file))
	switch eco {
	case "npm":
		switch {
		case strings.Contains(base, "yarn"):
			return fmt.Sprintf("yarn up %s@%s", pkg, version)
		case strings.Contains(base, "pnpm"):
			return fmt.Sprintf("pnpm update %s@%s", pkg, version)
		}
		return fmt.Sprintf("npm install %s@%s", pkg, version)
	case "PyPI":
		switch {
		case strings.Contains(base, "poetry"):
			return fmt.Sprintf("poetry add %s@^%s", pkg, version)
		case strings.Contains(base, "pipfile"):
			return fmt.Sprintf("pipenv install %s>=%s", pkg, version)
		case strings.Contains(base, "uv.lock"):
			return fmt.Sprintf("uv add '%s>=%s'", pkg, version)
		}
		return fmt.Sprintf("pin %s>=%s in %s", pkg, version, filepath.Base(file))
	case "Go":
		return fmt.Sprintf("go get %s@v%s && go mod tidy", pkg, strings.TrimPrefix(version, "v"))
	case "Maven":
		return fmt.Sprintf("set the version of %s to %s in %s (or the dependencyManagement section that pins it)", pkg, version, filepath.Base(file))
	case "NuGet":
		return fmt.Sprintf("dotnet add package %s --version %s", pkg, version)
	case "RubyGems":
		return fmt.Sprintf("bundle update %s --conservative (to %s)", pkg, version)
	case "crates.io":
		return fmt.Sprintf("cargo update -p %s --precise %s", pkg, version)
	case "Packagist":
		return fmt.Sprintf("composer require %s:^%s", pkg, version)
	}
	return ""
}

// ── Code: AI ──────────────────────────────────────────────────────────────────

const fixContextLines = 30

// codeWindow returns the numbered lines around [start,end] and the window bounds.
func codeWindow(content string, start, end int) (text string, from, to int, lines []string) {
	lines = strings.Split(content, "\n")
	if start < 1 {
		start = 1
	}
	if end < start {
		end = start
	}
	from = start - fixContextLines
	if from < 1 {
		from = 1
	}
	to = end + fixContextLines
	if to > len(lines) {
		to = len(lines)
	}
	var b strings.Builder
	for i := from; i <= to; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, lines[i-1])
	}
	return b.String(), from, to, lines
}

// unifiedDiff renders replacing lines[start..end] (1-based) by repl.
func unifiedDiff(file string, lines []string, start, end int, repl string) string {
	newLines := strings.Split(strings.TrimSuffix(repl, "\n"), "\n")
	if repl == "" {
		newLines = nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n@@ -%d,%d +%d,%d @@\n", file, file, start, end-start+1, start, len(newLines))
	for i := start; i <= end && i <= len(lines); i++ {
		b.WriteString("-" + lines[i-1] + "\n")
	}
	for _, l := range newLines {
		b.WriteString("+" + l + "\n")
	}
	return b.String()
}

type aiFixReply struct {
	Explanation    string `json:"explanation"`
	Confidence     int    `json:"confidence"`
	LikelyFalsePos bool   `json:"likely_false_positive"`
	FalsePosReason string `json:"false_positive_reason"`
	StartLine      int    `json:"start_line"`
	EndLine        int    `json:"end_line"`
	Replacement    string `json:"replacement"`
}

var jsonObjRe = regexp.MustCompile(`(?s)\{.*\}`)

// parseAIFix validates the model's answer against the window it was shown.
func parseAIFix(text string, f SASTFinding, lines []string, from, to int) (fixSuggestion, error) {
	m := jsonObjRe.FindString(text)
	var r aiFixReply
	if m == "" || json.Unmarshal([]byte(m), &r) != nil {
		return fixSuggestion{}, fmt.Errorf("the model did not return the expected JSON")
	}
	s := fixSuggestion{Kind: "code", File: f.File, Explanation: truncate(r.Explanation, 2000), Confidence: clampInt(r.Confidence, 0, 100),
		LikelyFalsePos: r.LikelyFalsePos, FalsePosReason: truncate(r.FalsePosReason, 1000)}
	if r.StartLine == 0 && r.EndLine == 0 {
		return s, nil // explanation only (for example a false positive)
	}
	if r.StartLine < from || r.EndLine > to || r.EndLine < r.StartLine || r.EndLine-r.StartLine > 40 {
		return s, nil // a range outside what it saw is not trusted; keep the explanation
	}
	if len(r.Replacement) > 8000 {
		return s, nil
	}
	s.StartLine, s.EndLine, s.Replacement = r.StartLine, r.EndLine, r.Replacement
	s.Diff = unifiedDiff(f.File, lines, r.StartLine, r.EndLine, r.Replacement)
	return s, nil
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// aiCredentials returns the configured provider key and model.
func aiCredentials(ctx context.Context, cfg *config.Config, db *store.DB) (key, model string) {
	groqKey, anthropicKey := cfg.Groq.APIKey, cfg.Anthropic.APIKey
	if s, err := db.GetSettingsPrefix(ctx, "ai"); err == nil {
		if v := s["groq_api_key"]; v != "" {
			groqKey = v
		}
		if v := s["anthropic_api_key"]; v != "" {
			anthropicKey = v
		}
	}
	if groqKey != "" {
		return groqKey, groqModelName()
	}
	if anthropicKey != "" {
		return anthropicKey, anthropicModelName()
	}
	return "", ""
}

var errNoAI = fmt.Errorf("no AI provider is configured (Settings → AI)")
var errNoSource = fmt.Errorf("sending source code to the AI provider is off (setting ai.send_source_snippets); a fix needs the code")

// suggestCodeFix asks the model for a fix of one code finding, given the file content.
func suggestCodeFix(ctx context.Context, cfg *config.Config, db *store.DB, f SASTFinding, content string) (fixSuggestion, error) {
	key, model := aiCredentials(ctx, cfg, db)
	if key == "" {
		return fixSuggestion{}, errNoAI
	}
	if !aiSourceSnippetsAllowed(ctx, db) {
		return fixSuggestion{}, errNoSource
	}
	end := f.EndLine
	if end < f.Line {
		end = f.Line
	}
	window, from, to, lines := codeWindow(content, f.Line, end)
	sum := sha256.Sum256([]byte(f.RuleID + "\x00" + f.File + "\x00" + strconv.Itoa(f.Line) + "\x00" + window + "\x00" + model))
	cacheKey := hex.EncodeToString(sum[:16])
	var cached []byte
	if db.QueryRowContext(ctx, `SELECT body FROM code_fix_cache WHERE key=$1 AND created_at > NOW() - INTERVAL '30 days'`, cacheKey).Scan(&cached) == nil {
		var s fixSuggestion
		if json.Unmarshal(cached, &s) == nil {
			s.Cached = true
			return s, nil
		}
	}
	if !sourceAILimiter.Allow("fix") {
		return fixSuggestion{}, fmt.Errorf("AI rate limit reached; try again later")
	}
	meta, _ := json.Marshal(map[string]interface{}{"rule": f.RuleID, "title": f.Title, "detail": truncate(f.Detail, 800),
		"cwe": f.CWE, "severity": f.Severity, "file": f.File, "line": f.Line, "end_line": end, "engine": f.Engine})
	prompt := promptInjectionGuard + "\n\n" + fmt.Sprintf(`You are a senior application security engineer. A static analysis tool reported the finding below.
Decide whether it is a real vulnerability and, if it is, propose the smallest safe code change that fixes it without changing behaviour.

Rules:
- Only replace a contiguous range of the lines shown (line numbers as shown, inclusive, at most 40 lines).
- The replacement is the exact new text for those lines, with the file's indentation, no line numbers, no markdown.
- If the finding is a false positive or the fix needs changes outside the lines shown, set start_line and end_line to 0 and explain.
- Never add new dependencies unless unavoidable; prefer the language's standard library.

Return ONLY this JSON:
{"explanation":"what is wrong and what the change does (2-4 sentences)","confidence":0-100,"likely_false_positive":true|false,"false_positive_reason":"","start_line":N,"end_line":N,"replacement":"..."}

Finding:
%s

Code (%s, lines %d-%d):
%s`, fenceUntrusted("finding", string(meta)), f.File, from, to, fenceUntrusted("source", window))
	actx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	text, err := callVulnAI(actx, key, model, prompt)
	if err != nil {
		return fixSuggestion{}, fmt.Errorf("AI request failed: %w", err)
	}
	s, err := parseAIFix(text, f, lines, from, to)
	if err != nil {
		return s, err
	}
	s.Model = model
	if b, err := json.Marshal(s); err == nil {
		_, _ = db.ExecContext(ctx, `INSERT INTO code_fix_cache (key, body) VALUES ($1,$2)
			ON CONFLICT (key) DO UPDATE SET body=EXCLUDED.body, created_at=NOW()`, cacheKey, b)
	}
	return s, nil
}

// fetchFindingFile reads the flagged file from the provider at a branch.
func fetchFindingFile(ctx context.Context, conn *store.DevOpsConnector, repo, branch, file string) (string, error) {
	if branch == "" {
		branch = "HEAD"
	}
	token := conn.Credentials["token"]
	switch conn.Provider {
	case "gitlab":
		return fetchGitLabFileContent(ctx, token, conn.Credentials["base_url"], repo, file, branch)
	case "azuredevops":
		parts := strings.SplitN(repo, "/", 3)
		if len(parts) != 3 {
			return "", fmt.Errorf("bad repository %q", repo)
		}
		if branch == "HEAD" {
			branch = "main"
		}
		return fetchAzureFileContent(ctx, adoClientFor(conn), parts[1], parts[2], file, branch)
	}
	owner, name, ok := strings.Cut(repo, "/")
	if !ok {
		return "", fmt.Errorf("bad repository %q", repo)
	}
	return fetchGitHubFileContent(ctx, token, owner, name, file, branch)
}

// handleSuggestFix: POST /api/v1/devops-connectors/{id}/sast/fix
// {repo, branch, finding}.
func handleSuggestFix(cfg *config.Config, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		var body struct {
			Repo    string      `json:"repo"`
			Branch  string      `json:"branch"`
			Finding SASTFinding `json:"finding"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&body) != nil || body.Finding.RuleID == "" {
			writeJSON(w, 400, map[string]string{"error": "finding is required"})
			return
		}
		f := body.Finding
		if f.Package != "" {
			writeJSON(w, 200, dependencyFix(f))
			return
		}
		if f.File == "" || f.Line <= 0 {
			writeJSON(w, 200, fixSuggestion{Kind: "none", Explanation: "This finding has no line to change (for example a secret in history or a configuration issue). Follow its fix text."})
			return
		}
		// Check the AI prerequisites before reading anything from the provider.
		if key, _ := aiCredentials(r.Context(), cfg, db); key == "" {
			writeJSON(w, 412, map[string]string{"error": errNoAI.Error()})
			return
		}
		if !aiSourceSnippetsAllowed(r.Context(), db) {
			writeJSON(w, 412, map[string]string{"error": errNoSource.Error()})
			return
		}
		conn, err := db.GetDevOpsConnectorRaw(r.Context(), connID)
		if err != nil || conn == nil {
			writeJSON(w, 404, map[string]string{"error": "connector not found"})
			return
		}
		repo := body.Repo
		if repo == "" {
			repo = f.Repo
		}
		content, err := fetchFindingFile(r.Context(), conn, repo, body.Branch, f.File)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": "could not read the file from the provider: " + err.Error()})
			return
		}
		s, err := suggestCodeFix(r.Context(), cfg, db, f, content)
		switch {
		case err == errNoAI || err == errNoSource:
			writeJSON(w, 412, map[string]string{"error": err.Error()})
		case err != nil:
			writeJSON(w, 503, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, 200, s)
		}
	}
}

// prFixSuggestion builds the fix for a PR comment from the local checkout.
func prFixSuggestion(ctx context.Context, cfg *config.Config, db *store.DB, f SASTFinding, dir string) *fixSuggestion {
	if f.Package != "" {
		s := dependencyFix(f)
		return &s
	}
	if f.Line <= 0 || cfg == nil {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.File)))
	if err != nil || len(b) > 2<<20 {
		return nil
	}
	s, err := suggestCodeFix(ctx, cfg, db, f, string(b))
	if err != nil {
		return nil
	}
	return &s
}
