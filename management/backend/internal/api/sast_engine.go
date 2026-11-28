package api

// sast_engine.go - SAST engine using Semgrep for static analysis
//
// Flow:
//  1. List repos from connector's synced commits
//  2. Fetch file tree + source files from GitHub/GitLab API
//  3. Write files to a temp directory
//  4. Run: semgrep --config=/semgrep-rules --json /tmp/sast-{id}/
//  5. Parse Semgrep JSON output → SASTFinding structs
//  6. If semgrep unavailable → fall back to our built-in regex rules
//  7. Store results in DB

import (
	"regexp"
	"io/fs"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
)

const (
	// SA-04: raised from 300 files / 100 KB; files beyond the cap are chosen by
	// risk priority (see sastFilePriority) instead of arbitrary tree order.
	maxFilesPerRepo = 1000
	maxFileBytes    = 300000
)

// SASTFinding is a unified finding from either semgrep or our built-in rules
type SASTFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	CWE      string `json:"cwe"`
	OWASP    string `json:"owasp"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
	Repo     string `json:"repo"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	EndLine  int    `json:"end_line,omitempty"`
	Snippet  string `json:"snippet,omitempty"`
	Engine   string `json:"engine"` // "semgrep" | "builtin"
	// TestCode: the file is test, fixture or example code; the severity was lowered one level (see testcode.go).
	TestCode bool `json:"test_code,omitempty"`
	// Dependency findings: the package, for runtime reachability (step 4).
	Ecosystem    string        `json:"ecosystem,omitempty"`
	Package      string        `json:"package,omitempty"`
	Version      string        `json:"version,omitempty"`
	Reachability *findingReach `json:"reachability,omitempty"`
	// Triage (step 5), set when findings are read.
	Fingerprint string         `json:"fingerprint,omitempty"`
	Triage      *findingTriage `json:"triage,omitempty"`
	TriageHint  *triageHint    `json:"triage_hint,omitempty"`
	IssueURL    string         `json:"issue_url,omitempty"` // issue created from it on the platform
	// Correlation: set on the findings of a correlated result (sast_correlate.go).
	Correlation *corrInfo `json:"correlation,omitempty"`
}

// ── Semgrep JSON output types ─────────────────────────────────────────────────

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
	Errors  []semgrepError  `json:"errors"`
}

type semgrepResult struct {
	CheckID string        `json:"check_id"`
	Path    string        `json:"path"`
	Start   semgrepPos    `json:"start"`
	End     semgrepPos    `json:"end"`
	Extra   semgrepExtra  `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string         `json:"message"`
	Severity string         `json:"severity"`
	Metadata semgrepMeta    `json:"metadata"`
	Lines    string         `json:"lines"`
}

type semgrepMeta struct {
	CWE        interface{} `json:"cwe"`         // can be string or []string
	OWASP      interface{} `json:"owasp"`
	Confidence string      `json:"confidence"`
	Fix        string      `json:"fix"`
	Impact     string      `json:"impact"`
}

type semgrepError struct {
	Message string `json:"message"`
}

// ── Semgrep runner ────────────────────────────────────────────────────────────

// semgrepAvailable checks if semgrep is installed in the container
func semgrepAvailable() bool {
	bin, _ := semgrepEngine()
	return bin != ""
}

// extractFileLines reads actual source lines from a file for snippet display
func extractFileLines(filePath string, startLine, endLine int) string {
	data, err := os.ReadFile(filePath)
	if err != nil { return "" }
	lines := strings.Split(string(data), "\n")
	if startLine < 1 { startLine = 1 }
	ctxStart := startLine - 3
	if ctxStart < 1 { ctxStart = 1 }
	if endLine < startLine { endLine = startLine }
	ctxEnd := endLine + 2
	if ctxEnd > len(lines) { ctxEnd = len(lines) }
	var out []string
	for i := ctxStart; i <= ctxEnd && i <= len(lines); i++ {
		marker := "  "
		if i >= startLine && i <= endLine { marker = "> " }
		out = append(out, fmt.Sprintf("%s%d: %s", marker, i, lines[i-1]))
	}
	result := strings.Join(out, "\n")
	if len(result) > 500 { result = result[:500] + "…" }
	return result
}

// codeqlAvailable checks if CodeQL CLI is installed
func codeqlAvailable() bool {
	_, err := exec.LookPath("codeql")
	return err == nil
}

// parseSARIF parses a SARIF file from CodeQL and returns SASTFindings
func parseSARIF(sarifFile, repoName, baseDir string) ([]SASTFinding, error) {
	data, err := os.ReadFile(sarifFile)
	if err != nil { return nil, err }
	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Message struct{ Text string `json:"text"` } `json:"message"`
				Level   string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string `json:"uri"` } `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
							EndLine   int `json:"endLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Properties struct {
					Tags []string `json:"tags"`
				} `json:"properties"`
			} `json:"results"`
			Tool struct {
				Driver struct {
					Rules []struct {
						ID               string `json:"id"`
						Name             string `json:"name"`
						ShortDescription struct{ Text string `json:"text"` } `json:"shortDescription"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
						Properties       struct {
							Tags     []string `json:"tags"`
							Severity string   `json:"problem.severity"`
							LegacySev string  `json:"severity"`
							SecuritySeverity string `json:"security-severity"`
							Precision string  `json:"precision"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &sarif); err != nil { return nil, err }

	var findings []SASTFinding
	for _, run := range sarif.Runs {
		// Build rule map for metadata lookup
		ruleMap := map[string]struct{ Name, Desc, Sev string }{}
		for _, r := range run.Tool.Driver.Rules {
			problem := r.Properties.Severity
			if problem == "" { problem = r.Properties.LegacySev }
			if problem == "" { problem = r.DefaultConfiguration.Level }
			ruleMap[r.ID] = struct{ Name, Desc, Sev string }{r.Name, r.ShortDescription.Text,
				sarifSeverity(r.Properties.SecuritySeverity, problem)}
		}
		for _, result := range run.Results {
			if len(result.Locations) == 0 { continue }
			loc := result.Locations[0].PhysicalLocation
			filePath := strings.TrimPrefix(loc.ArtifactLocation.URI, "file://")
			filePath = strings.TrimPrefix(filePath, baseDir+"/")
			filePath = strings.TrimPrefix(filePath, "/")

			rule := ruleMap[result.RuleID]
			// The rule's rating wins; without rule metadata the result's own
			// SARIF level decides. (The rule default used to be forced to
			// "medium", so this fallback never ran and every CodeQL finding
			// without a "severity" property showed as medium.)
			sev := rule.Sev
			if sev == "" {
				sev = sarifSeverity("", result.Level)
			}
			if sev == "" { sev = "medium" }

			snippet := extractFileLines(filepath.Join(baseDir, filePath), loc.Region.StartLine, loc.Region.EndLine)
			findings = append(findings, SASTFinding{
				RuleID:   result.RuleID,
				Severity: sev,
				Title:    rule.Name,
				Detail:   result.Message.Text,
				Repo:     repoName,
				File:     filePath,
				Line:     loc.Region.StartLine,
				EndLine:  loc.Region.EndLine,
				Snippet:  snippet,
				Engine:   "codeql",
			})
		}
	}
	return findings, nil
}

// sarifSeverity rates a finding. CodeQL security queries carry a CVSS-style
// "security-severity" score, which maps to the GitHub code-scanning bands;
// otherwise the problem severity / SARIF level is used
// (error -> high, warning -> medium, note/recommendation -> low).
func sarifSeverity(securitySeverity, level string) string {
	if f, err := strconv.ParseFloat(strings.TrimSpace(securitySeverity), 64); err == nil {
		switch {
		case f >= 9.0:
			return "critical"
		case f >= 7.0:
			return "high"
		case f >= 4.0:
			return "medium"
		case f > 0:
			return "low"
		}
	}
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return "critical"
	case "error", "high":
		return "high"
	case "warning", "medium":
		return "medium"
	case "note", "recommendation", "low", "none":
		return "low"
	}
	return ""
}

// runSemgrep runs the Semgrep-compatible engine (opengrep or semgrep) with the
// locally bundled rules. Nothing is downloaded at scan time.
func runSemgrep(ctx context.Context, dir string, logger *slog.Logger) ([]semgrepResult, error) {
	bin, rules := semgrepEngine()
	if bin == "" {
		return nil, errToolMissing
	}
	args := []string{"scan", "--config", rules, "--json", "--quiet", "--no-rewrite-rule-ids",
		"--max-memory", "1000", "--timeout", "30", "--jobs", "2"}
	if filepath.Base(bin) == "semgrep" {
		args = append(args, "--metrics=off", "--disable-version-check") // SA-05
	} else {
		args = append(args, "--taint-intrafile") // opengrep: cross-function taint inside a file
	}
	args = append(args, dir)
	cmd := exec.CommandContext(ctx, bin, args...)
	_ = logger
	cmd.Env = scannerEnv()
	out, err := cmd.Output()
	if err != nil {
		// semgrep exits non-zero when it finds issues - that's expected
		// Only treat it as error if no output was produced
		if len(out) == 0 {
			return nil, fmt.Errorf("semgrep failed with no output: %w", err)
		}
	}

	var result semgrepOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	if len(result.Errors) > 0 {
		for _, e := range result.Errors {
			logger.Warn("sast: semgrep error", "msg", e.Message)
		}
	}

	return result.Results, nil
}

// convertSemgrepFindings converts semgrep results to our SASTFinding format
func convertSemgrepFindings(results []semgrepResult, repoName, baseDir string) []SASTFinding {
	var findings []SASTFinding
	for _, r := range results {
		// Strip the temp dir prefix from the file path
		relPath := strings.TrimPrefix(r.Path, baseDir+"/")

		// Extract repo from path (first component after baseDir)
		// baseDir = /tmp/sast-123/owner-repo
		// relPath = src/main.py
		file := relPath

		// Normalise severity
		sev := strings.ToLower(r.Extra.Severity)
		switch sev {
		case "error":   sev = "critical"
		case "warning": sev = "high"
		case "info":    sev = "medium"
		}

		// Extract CWE
		cwe := ""
		switch v := r.Extra.Metadata.CWE.(type) {
		case string:
			cwe = v
		case []interface{}:
			if len(v) > 0 {
				cwe = fmt.Sprintf("%v", v[0])
			}
		}

		// Extract OWASP
		owasp := ""
		switch v := r.Extra.Metadata.OWASP.(type) {
		case string:
			owasp = v
		case []interface{}:
			if len(v) > 0 {
				owasp = fmt.Sprintf("%v", v[0])
			}
		}

		// Read actual source lines from the file on disk
		// r.Extra.Lines from Semgrep often shows function context (e.g. "requires login")
		// rather than the exact matched line - reading the file directly is more accurate
		snippet := ""
		if fileData, err := os.ReadFile(r.Path); err == nil {
			fileLines := strings.Split(string(fileData), "\n")
			startL := r.Start.Line - 1 // convert to 0-indexed
			endL := r.End.Line - 1
			if startL < 0 { startL = 0 }
			if endL >= len(fileLines) { endL = len(fileLines) - 1 }
			if endL < startL { endL = startL }
			// Show 2 lines before for context
			ctxStart := startL - 2
			if ctxStart < 0 { ctxStart = 0 }
			var snippetParts []string
			for i := ctxStart; i <= endL+1 && i < len(fileLines); i++ {
				marker := "  "
				if i >= startL && i <= endL { marker = "> " }
				snippetParts = append(snippetParts, fmt.Sprintf("%s%d: %s", marker, i+1, fileLines[i]))
			}
			snippet = strings.Join(snippetParts, "\n")
			if len(snippet) > 500 { snippet = snippet[:500] + "…" }
		}
		// Fallback to semgrep lines field if file read failed
		if snippet == "" {
			snippet = strings.TrimSpace(r.Extra.Lines)
			if len(snippet) > 300 { snippet = snippet[:300] + "…" }
		}

		findings = append(findings, SASTFinding{
			RuleID:   r.CheckID,
			Severity: sev,
			CWE:      cwe,
			OWASP:    owasp,
			Title:    extractTitle(r.CheckID),
			Detail:   r.Extra.Message,
			Fix:      r.Extra.Metadata.Fix,
			Repo:     repoName,
			File:     file,
			Line:     r.Start.Line,
				EndLine:  r.End.Line,
			Snippet:  snippet,
			Engine:   "semgrep",
		})
	}
	return findings
}

// extractTitle converts a semgrep rule ID like "python.lang.security.audit.exec-detected"
// into a human-readable title like "Exec Detected"
func extractTitle(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	if len(parts) == 0 {
		return ruleID
	}
	last := parts[len(parts)-1]
	last = strings.ReplaceAll(last, "-", " ")
	words := strings.Fields(last)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// ── GitHub/GitLab file fetching ───────────────────────────────────────────────

type ghTreeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int    `json:"size"`
	URL  string `json:"url"`
}

type ghTreeResp struct {
	Tree      []ghTreeEntry `json:"tree"`
	Truncated bool          `json:"truncated"`
}

type ghFileContent struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

func fetchGitHubTree(ctx context.Context, token, owner, repo, branch string) ([]ghTreeEntry, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/trees/%s?recursive=1", owner, repo, branch)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := devopsHTTP.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API %d for %s/%s", resp.StatusCode, owner, repo)
	}
	var tree ghTreeResp
	json.NewDecoder(resp.Body).Decode(&tree)
	return tree.Tree, nil
}

// SA-02: ref is passed so the content matches the branch whose file tree
// was listed (previously the default branch's content was fetched against
// another branch's file list). "HEAD"/"" means the default branch.
func fetchGitHubFileContent(ctx context.Context, token, owner, repo, path, ref string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, escapePathSegments(path))
	if ref != "" && ref != "HEAD" && ref != "unknown" {
		url += "?ref=" + neturl.QueryEscape(ref)
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := devopsHTTP.Do(req)
	if err != nil { return "", err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { return "", fmt.Errorf("HTTP %d", resp.StatusCode) }
	var fc ghFileContent
	json.NewDecoder(resp.Body).Decode(&fc)
	if fc.Encoding == "base64" {
		cleaned := strings.ReplaceAll(fc.Content, "\n", "")
		decoded, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil { return "", err }
		return string(decoded), nil
	}
	return fc.Content, nil
}

func gitlabEncodeProject(projectID string) string {
	// GitLab needs namespace/project encoded as one path segment; the old
	// ReplaceAll only handled "/", so names with spaces, "+" or "#" broke.
	return gitlabID(projectID)
}

func fetchGitLabTree(ctx context.Context, token, baseURL, projectID, branch string) ([]ghTreeEntry, error) {
	if baseURL == "" { baseURL = "https://gitlab.com" }
	if branch == "" || branch == "unknown" { branch = "HEAD" }
	encoded := gitlabEncodeProject(projectID)
	// GitLab tree API - paginate to get all files (default per_page=20, max=100)
	var out []ghTreeEntry
	page := 1
	for {
		url := fmt.Sprintf("%s/api/v4/projects/%s/repository/tree?recursive=true&per_page=100&page=%d&ref=%s",
			strings.TrimRight(baseURL, "/"), encoded, page, neturl.QueryEscape(branch))
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("PRIVATE-TOKEN", token)
		resp, err := devopsHTTP.Do(req)
		if err != nil { return nil, err }
		var entries []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		}
		json.NewDecoder(resp.Body).Decode(&entries)
		resp.Body.Close()
		if len(entries) == 0 { break }
		for _, e := range entries {
			out = append(out, ghTreeEntry{Path: e.Path, Type: e.Type})
		}
		if len(entries) < 100 { break } // last page
		page++
		if page > 20 { break } // safety cap - max 2000 files
	}
	return out, nil
}

func fetchGitLabFileContent(ctx context.Context, token, baseURL, projectID, filePath, branch string) (string, error) {
	if baseURL == "" { baseURL = "https://gitlab.com" }
	if branch == "" || branch == "unknown" { branch = "HEAD" }
	encoded := gitlabEncodeProject(projectID)
	escapedPath := neturl.PathEscape(filePath)
	url := fmt.Sprintf("%s/api/v4/projects/%s/repository/files/%s/raw?ref=%s",
		strings.TrimRight(baseURL, "/"), encoded, escapedPath, neturl.QueryEscape(branch))
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("PRIVATE-TOKEN", token)
	resp, err := devopsHTTP.Do(req)
	if err != nil { return "", err }
	defer resp.Body.Close()
	if resp.StatusCode != 200 { return "", fmt.Errorf("GitLab API %d for %s", resp.StatusCode, filePath) }
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

// ── Main SAST handler ─────────────────────────────────────────────────────────

func handleSAST(cfg *config.Config, db *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		ctx := r.Context()

		conn, err := db.GetDevOpsConnectorRaw(ctx, connID)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "connector not found"})
			return
		}
		token := conn.Credentials["token"]
		if token == "" {
			writeJSON(w, 400, map[string]string{"error": "connector has no token"})
			return
		}

		// Optional filters - scan a specific repo and/or branch
		filterRepo   := r.URL.Query().Get("repo")
		filterBranch := r.URL.Query().Get("branch")
		// ?commit=<sha>: scan exactly that commit (picked from filterBranch's
		// history); stored as branch "@<sha>", kept as a snapshot.
		commitPick := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("commit")))
		if commitPick != "" && (filterRepo == "" || !fullSHARe.MatchString(commitPick)) {
			writeJSON(w, 400, map[string]string{"error": "commit needs a repository and a full commit id"})
			return
		}

		repoSet := map[string]bool{}
		defaultBranch := map[string]string{}

		if filterRepo != "" && !repoInConnectorScope(conn, filterRepo) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "repository is outside this connector's organization"})
			return
		}
		if filterRepo != "" {
			// Explicit repo selected - use it directly, no DB lookup needed
			// This allows scanning repos with no recent commits (no sync history)
			repoSet[filterRepo] = true
			branch := filterBranch
			if branch == "" { branch = "HEAD" }
			defaultBranch[filterRepo] = branch
		} else {
			// No filter - scan all repos from DB commits
			commits, err := db.ListDevOpsCommits(ctx, connID, "", 500)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": "failed to list commits"})
				return
			}
			for _, c := range commits {
				repoSet[c.Repo] = true
				if _, ok := defaultBranch[c.Repo]; !ok {
					branch := c.Branch
					if branch == "" || branch == "unknown" { branch = "HEAD" }
					defaultBranch[c.Repo] = branch
				}
			}
		}

		if len(repoSet) == 0 {
			writeJSON(w, 200, map[string]interface{}{
				"message":  "No repos found. Sync the connector first.",
				"findings": []SASTFinding{},
			})
			return
		}

		// Engines: ?engines=a,b; else a protected branch's profile; else the
		// default set. The AI business-logic engine is never in the default
		// set: it runs only when chosen (it costs tokens).
		saveBranch := filterBranch
		if saveBranch == "" { saveBranch = "HEAD" }
		if commitPick != "" {
			saveBranch = "@" + commitPick
		}
		var set engineSet
		var bl *blContext
		protSet, isProtected := engineSet(nil), false
		if filterRepo != "" && commitPick == "" { // a commit scan never uses a profile or triggers remediation
			protSet, isProtected = loadCodeScanPolicy(ctx, db, connID).engineSetFor(filterRepo, filterBranch)
		}
		if q := strings.TrimSpace(r.URL.Query().Get("engines")); q != "" {
			ids, perr := parseEngineIDs(strings.Split(q, ","))
			if perr != nil {
				writeJSON(w, 400, map[string]string{"error": perr.Error()})
				return
			}
			set = newEngineSet(ids)
		} else if isProtected {
			set = protSet
		}
		if set.on(engBusinessLogic) {
			if rerr := businessLogicReady(ctx, cfg, db); rerr != nil {
				writeJSON(w, 400, map[string]string{"error": "AI business logic: " + rerr.Error()})
				return
			}
			bl = &blContext{cfg: cfg, db: db}
		}

		useSemgrep := semgrepAvailable()
		useCodeQL  := codeqlAvailable()
		engines := engineReport{}
		var sbom []byte
		lastSourceErr := ""
		commitSHA := ""
		commitMsg, commitAuthor := "", ""
		engine := "builtin"

		logger.Info("sast: starting scan",
			"connector", conn.Org,
			"repos", len(repoSet),
			"semgrep", useSemgrep,
			"codeql", useCodeQL,
		)

		// Create a unique temp dir for this scan
		scanID := fmt.Sprintf("sast-%d-%d", connID, time.Now().UnixNano())
		tmpDir, err := os.MkdirTemp("", scanID)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to create temp dir"})
			return
		}
		defer os.RemoveAll(tmpDir) // always clean up

		var allFindings []SASTFinding
		scannedFiles := 0
		scannedRepos := 0

		for repo := range repoSet {
			select { case <-ctx.Done(): goto done; default: }

			parts := strings.SplitN(repo, "/", 2)
			if len(parts) != 2 { continue }
			owner, repoName := parts[0], parts[1]
			branch := defaultBranch[repo]
			// "unknown" is stored when GitHub didn't return a branch name
			// HEAD always resolves to the repo's default branch (main/master/etc)
			if branch == "" || branch == "unknown" { branch = "HEAD" }

			release, slotErr := acquireScanSlot(ctx)
			if slotErr != nil {
				release()
				goto done
			}
			repoSlug := strings.ReplaceAll(repo, "/", "-")
			repoDir := filepath.Join(tmpDir, repoSlug)

			// Source: git clone (every file, full branch history for the
			// secrets scan); the provider API is the fallback.
			source, historyOK := "git", false
			depth := 0
			if !sastHistoryEnabled() || !set.on(engSecrets) {
				depth = 1
			}
			var cloneErr error
			if commitPick != "" {
				cloneErr = cloneCommit(ctx, conn, repo, commitPick, repoDir, depth)
				if cloneErr != nil && depth == 0 {
					_ = os.RemoveAll(repoDir)
					cloneErr = cloneCommit(ctx, conn, repo, commitPick, repoDir, 1)
				} else if cloneErr == nil {
					historyOK = depth == 0
				}
				if cloneErr != nil { // the provider API can only fetch a branch, not a commit
					release()
					writeJSON(w, 400, map[string]string{"error": "could not fetch commit " + commitPick[:12] + ": " + cloneErr.Error()})
					return
				}
			} else {
				cloneErr = cloneRepo(ctx, conn, repo, branch, repoDir, depth)
			}
			if commitPick == "" && cloneErr != nil && depth == 0 {
				_ = os.RemoveAll(repoDir)
				logger.Warn("sast: full clone failed, trying shallow", "repo", repo, "err", cloneErr)
				cloneErr = cloneRepo(ctx, conn, repo, branch, repoDir, 1)
			} else if commitPick == "" && cloneErr == nil {
				historyOK = depth == 0
			}
			if cloneErr == nil {
				scannedFiles += countSourceFiles(repoDir)
				if filterRepo != "" {
					commitSHA = gitHeadSHA(ctx, repoDir)
				}
				if commitPick != "" {
					commitMsg, commitAuthor = gitCommitMeta(ctx, repoDir)
				}
			} else {
				_ = os.RemoveAll(repoDir)
				logger.Warn("sast: git clone failed, using the provider API", "repo", repo, "err", cloneErr)
				lastSourceErr = repo + ": " + cloneErr.Error()
				source = "api"
				n, ok := fetchRepoViaAPI(ctx, conn, token, repo, owner, repoName, branch, repoDir, logger)
				if !ok && ctx.Err() != nil {
					release()
					goto done
				}
				if !ok {
					release()
					continue
				}
				scannedFiles += n
			}
			engines.set("source", source)
			scannedRepos++

			// Each repository gets its own engine report; a scan of several
			// repositories merges them (mergeEngineReport) instead of letting the
			// last repository's statuses overwrite the others.
			repoEngines := engineReport{"source": source}
			repoFindings, repoSBOM := scanCheckout(ctx, conn, repo, repoDir, scanOpts{History: historyOK, CodeQL: useCodeQL, Semgrep: useSemgrep, Engines: set, BL: bl}, repoEngines, logger)
			if filterRepo != "" {
				for k, v := range repoEngines {
					engines[k] = v
				}
			} else {
				mergeEngineReport(engines, repoEngines, repo)
			}
			if filterRepo == "" {
				// "Scan all" also stores each repository's own result, so the repository page shows it and the
				// coverage counts the repository as scanned even when it has no findings.
				ownEngines := engineReport{}
				for k, v := range repoEngines {
					ownEngines[k] = v
				}
				ownF, ownSBOM := mergeStoredEngines(ctx, db, connID, repo, branch, set, ownEngines, append([]SASTFinding(nil), repoFindings...), repoSBOM)
				own := deduplicateSASTFindings(ownF)
				repoSBOM = ownSBOM
				sha := ""
				if source == "git" {
					sha = gitHeadSHA(ctx, repoDir)
				}
				if err := saveSASTResult(ctx, db, connID, repo, branch, sha, ownEngines, own, repoSBOM, 1, countSourceFiles(repoDir)); err != nil {
					logger.Warn("sast: failed to save repository result", "repo", repo, "err", err)
				}
			}
			allFindings = append(allFindings, repoFindings...)
			if repoSBOM != nil {
				sbom = repoSBOM
			}
			_ = os.RemoveAll(repoDir)
			release()
		}

	done:
		if filterRepo != "" && scannedRepos > 0 {
			// Keep the stored findings of the engines this scan did not run.
			allFindings, sbom = mergeStoredEngines(ctx, db, connID, filterRepo, saveBranch, set, engines, allFindings, sbom)
		}
		allFindings = deduplicateSASTFindings(allFindings)
		engine = engines.names()
		if filterRepo == "" {
			sbom = nil // an SBOM belongs to one repository
		}

		counts := map[string]int{}
		for _, f := range allFindings { counts[f.Severity]++ }

		dbErr := saveSASTResult(ctx, db, connID, filterRepo, saveBranch, commitSHA, engines, allFindings, sbom, scannedRepos, scannedFiles)
		if dbErr != nil {
			logger.Warn("sast: failed to save", "err", dbErr)
		} else if commitPick != "" && scannedRepos > 0 {
			recordCommitScan(ctx, db, connID, filterRepo, commitPick, filterBranch, commitMsg, commitAuthor)
		} else if isProtected && len(allFindings) > 0 {
			// A manual scan of a protected branch with remediation on opens
			// fix pull requests for new findings.
			if prof, _ := loadCodeScanPolicy(ctx, db, connID).profileFor(filterRepo, filterBranch); prof.Remediate {
				queueFixJob(context.WithoutCancel(ctx), db, connID, filterRepo, saveBranch, "manual", logger)
			}
		}

		logger.Info("sast: scan complete",
			"engine", engine,
			"repos", scannedRepos,
			"files", scannedFiles,
			"findings", len(allFindings),
		)

		writeJSON(w, 200, map[string]interface{}{
			"engine":        engine,
			"engines":       engines,
			"sbom_available": sbom != nil,
			"warning":       joinWarnings(sastSourceWarning(scannedRepos, lastSourceErr), chosenEngineWarning(scannedRepos, set, engines)),
			"engines_run":   set.ids(),
			"scanned_repos": scannedRepos,
			"scanned_files": scannedFiles,
			"finding_count": len(allFindings),
			"critical_count": counts["critical"],
			"high_count":    counts["high"],
			"medium_count":  counts["medium"],
			"low_count":     counts["low"],
			"findings":      enrichFindings(ctx, db, connID, allFindings),
		})
	}
}


// fetchRepoViaAPI is the fallback source download when git clone is not
// possible: the provider's tree API plus per-file fetches (GitHub: one
// tarball), capped at maxFilesPerRepo files. Returns the files written.
func fetchRepoViaAPI(ctx context.Context, conn *store.DevOpsConnector, token, repo, owner, repoName, branch, repoDir string, logger *slog.Logger) (files int, ok bool) {
	// Fetch file tree
	var tree []ghTreeEntry
	var treeErr error
	if conn.Provider == "gitlab" {
		tree, treeErr = fetchGitLabTree(ctx, token, conn.Credentials["base_url"], repo, branch)
	} else if conn.Provider == "azuredevops" {
		// Azure repo format: org/project/repoName
		azParts := strings.SplitN(repo, "/", 3)
		azOrg, azProj, azRepo := conn.Org, "", repo
		if len(azParts) == 3 { azOrg, azProj, azRepo = azParts[0], azParts[1], azParts[2] }
		_ = azOrg
		tree, treeErr = fetchAzureTree(ctx, adoClientFor(conn), azProj, azRepo, branch)
	} else {
		tree, treeErr = fetchGitHubTree(ctx, token, owner, repoName, branch)
	}
	if treeErr != nil {
		logger.Warn("sast: failed to fetch tree", "repo", repo, "err", treeErr)
		return 0, false
	}

	// Filter source files
	var sourceFiles []ghTreeEntry
	for _, f := range tree {
		if f.Type != "blob" { continue }
		if f.Size > sastSizeLimit(f.Path) { continue }
		if isVendorPath(f.Path) { continue }
		if isSourceFile(f.Path) {
			sourceFiles = append(sourceFiles, f)
		}
	}
	if len(sourceFiles) > maxFilesPerRepo {
		sort.SliceStable(sourceFiles, func(i, j int) bool {
			return sastFilePriority(sourceFiles[i].Path) < sastFilePriority(sourceFiles[j].Path)
		})
		logger.Warn("sast: repo exceeds file cap; scanning highest-risk files only",
			"repo", repo, "total", len(sourceFiles), "scanned", maxFilesPerRepo)
		sourceFiles = sourceFiles[:maxFilesPerRepo]
	}

	if err := os.MkdirAll(repoDir, 0755); err != nil { return 0, false }

	logger.Info("sast: fetching repo", "repo", repo, "files", len(sourceFiles))

	// SA-02: GitHub repos come down as a single tarball; fall back to
	// per-file fetching only if that fails.
	if conn.Provider != "gitlab" && conn.Provider != "azuredevops" {
		want := make(map[string]bool, len(sourceFiles))
		for _, f := range sourceFiles {
			want[f.Path] = true
		}
		if n, tarErr := fetchGitHubTarballFiles(ctx, token, owner, repoName, branch, repoDir, want); tarErr == nil && n > 0 {
			files += n
			sourceFiles = nil
		} else if tarErr != nil {
			logger.Warn("sast: tarball fetch failed, falling back to per-file", "repo", repo, "err", tarErr)
		}
	}

	// Fetch and write all files to disk
	for _, f := range sourceFiles {
		select { case <-ctx.Done(): return files, false; default: }

		var content string
		var fetchErr error
		if conn.Provider == "gitlab" {
			content, fetchErr = fetchGitLabFileContent(ctx, token,
				conn.Credentials["base_url"], repo, f.Path, branch)
		} else if conn.Provider == "azuredevops" {
			azParts2 := strings.SplitN(repo, "/", 3)
			azOrg2, azProj2, azRepo2 := conn.Org, "", repo
			if len(azParts2) == 3 { azOrg2, azProj2, azRepo2 = azParts2[0], azParts2[1], azParts2[2] }
			_ = azOrg2
			content, fetchErr = fetchAzureFileContent(ctx, adoClientFor(conn),
				azProj2, azRepo2, f.Path, branch)
		} else {
			content, fetchErr = fetchGitHubFileContent(ctx, token, owner, repoName, f.Path, branch)
		}
		if fetchErr != nil { continue }

		// Write file preserving directory structure
		filePath := filepath.Join(repoDir, f.Path)
		// SA-03: paths come from a provider API (possibly a self-hosted
		// server we don't control) - never write outside repoDir.
		if rel, relErr := filepath.Rel(repoDir, filePath); relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(f.Path) {
			logger.Warn("sast: skipping file with unsafe path", "path", f.Path)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil { continue }
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil { continue }
		files++
	}

	return files, true
}

// runBuiltinRulesOnDir runs our regex-based SAST rules on files in a directory
//
// It reads only source files under the size cap the API download uses: a clone holds every file (images,
// archives, generated data, up to OW_SAST_MAX_REPO_MB), and reading each whole into memory cost time and RAM
// for files no rule applies to. .git and dependency directories are skipped without being walked.
func runBuiltinRulesOnDir(repo, dir string) []SASTFinding {
	var findings []SASTFinding
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		relPath := strings.TrimPrefix(filepath.ToSlash(strings.TrimPrefix(path, dir)), "/")
		if d.IsDir() {
			if relPath != "" && isVendorPath(relPath+"/") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || isVendorPath(relPath) || !isSourceFile(relPath) {
			return nil
		}
		if info, ierr := d.Info(); ierr != nil || info.Size() > int64(sastSizeLimit(relPath)) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		findings = append(findings, runSASTRules(repo, relPath, string(content))...)
		return nil
	})
	return findings
}

// handleListSASTRepos returns all repos the connector token has access to.
// Queries the GitHub/GitLab API directly so it shows ALL repos, not just ones
// with recent commits.
func handleListSASTRepos(db *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		conn, err := db.GetDevOpsConnectorRaw(r.Context(), connID)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "connector not found"})
			return
		}
		out, perr := listConnectorRepos(r.Context(), db, conn, logger)
		resp := map[string]interface{}{
			"repos":  out,
			"count":  len(out),
			"source": conn.Provider + "_api",
		}
		if perr != "" {
			// Shown in the SAST tab: an empty list otherwise looks like "no repositories".
			resp["warning"] = "could not list repositories from " + conn.Provider + ": " + perr
		}
		writeJSON(w, 200, resp)
	}
}

// sastRepoInfo is one repository of a connector with its default branch.
type sastRepoInfo struct {
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
}

// listConnectorRepos lists the connector's repositories from the provider (the stored commits when that fails).
// GitHub is paged (100 per page, up to 2 000 repositories): only the first page used to be read, so an
// organization with more than 100 repositories showed only the 100 most recently pushed.
func listConnectorRepos(ctx context.Context, db *store.DB, conn *store.DevOpsConnector, logger *slog.Logger) ([]sastRepoInfo, string) {
	token := conn.Credentials["token"]
	var out []sastRepoInfo
	provErr := "" // why the provider list failed, when it did
	switch conn.Provider {
	case "azuredevops":
		client := adoClientFor(conn)
		projects, aerr := adoProjects(ctx, client, conn)
		if aerr != nil {
			provErr = aerr.Error()
		}
		if aerr == nil {
			for _, projName := range projects {
				var reposResp struct {
					Value []struct {
						Name          string `json:"name"`
						DefaultBranch string `json:"defaultBranch"`
					} `json:"value"`
				}
				repoURL := fmt.Sprintf("%s/%s/_apis/git/repositories?api-version=7.0", client.baseURL, neturl.PathEscape(projName))
				if err2 := client.getJSON(ctx, repoURL, &reposResp); err2 != nil {
					provErr = projName + ": " + err2.Error()
				} else {
					for _, rp := range reposResp.Value {
						branch := strings.TrimPrefix(rp.DefaultBranch, "refs/heads/")
						if branch == "" {
							branch = "main"
						}
						out = append(out, sastRepoInfo{Repo: fmt.Sprintf("%s/%s/%s", conn.Org, projName, rp.Name), Branch: branch})
					}
				}
			}
		}
	case "gitlab":
		baseURL := conn.Credentials["base_url"]
		if baseURL == "" {
			baseURL = "https://gitlab.com"
		}
		// The connector's own group/namespace, paged.
		glc := &gitlabClient{token: token, baseURL: baseURL, group: conn.Org}
		projects, gerr := gitlabProjects(ctx, glc, conn.Org)
		if gerr != nil {
			provErr = gerr.Error()
		}
		if gerr == nil {
			for _, p := range projects {
				if p.EmptyRepo || p.Archived {
					continue
				}
				branch := p.DefaultBranch
				if branch == "" {
					branch = "HEAD"
				}
				out = append(out, sastRepoInfo{Repo: p.PathWithNamespace, Branch: branch})
			}
			if len(out) == 0 && len(projects) > 0 {
				provErr = fmt.Sprintf("GitLab returned %d project(s), all empty or archived (a token user with only Guest access sees private projects as empty: Reporter or above is needed)", len(projects))
			}
		}
	default:
		// GitHub: the org endpoint and the authenticated user's own repositories, merged, only the connector's
		// own org/account.
		seen := map[string]bool{}
		for _, apiURL := range githubRepoListURLs(conn.Org) {
			for page := 1; page <= 20; page++ {
				var batch []struct {
					FullName      string `json:"full_name"`
					DefaultBranch string `json:"default_branch"`
				}
				req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s&page=%d", apiURL, page), nil)
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Accept", "application/vnd.github+json")
				resp, err := devopsHTTP.Do(req)
				if err != nil {
					provErr = err.Error()
					break
				}
				if resp.StatusCode != 200 {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
					resp.Body.Close()
					provErr = fmt.Sprintf("GitHub API %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
					break
				}
				_ = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&batch)
				resp.Body.Close()
				for _, rp := range batch {
					if !githubRepoBelongs(rp.FullName, conn.Org) || seen[rp.FullName] {
						continue
					}
					seen[rp.FullName] = true
					branch := rp.DefaultBranch
					if branch == "" {
						branch = "HEAD"
					}
					out = append(out, sastRepoInfo{Repo: rp.FullName, Branch: branch})
				}
				if len(batch) < 100 {
					break
				}
			}
		}
		logger.Info("sast: repo list", "connector", conn.ID, "count", len(out))
	}
	if len(out) > 0 {
		provErr = "" // GitHub: one of the two listings answered
	} else if provErr != "" {
		logger.Warn("sast: provider repository list failed", "connector", conn.ID, "provider", conn.Provider, "err", provErr)
	}
	// Fallback: repos from stored commits if the provider call failed.
	if len(out) == 0 {
		dbRepos, _ := db.ListDevOpsRepos(ctx, conn.ID)
		for _, rp := range dbRepos {
			branch := rp.Branch
			if branch == "" || branch == "unknown" {
				branch = "HEAD"
			}
			out = append(out, sastRepoInfo{Repo: rp.Repo, Branch: branch})
		}
	}
	// Repositories with stored scan results are listed too, so their results
	// stay reachable when the provider cannot be reached.
	if len(out) == 0 {
		if rows, err := db.QueryContext(ctx, `SELECT DISTINCT ON (repo) repo, branch FROM sast_results
			WHERE connector_id=$1 AND repo <> '' AND branch NOT LIKE '@%' ORDER BY repo, scanned_at DESC`, conn.ID); err == nil {
			for rows.Next() {
				var rp sastRepoInfo
				if rows.Scan(&rp.Repo, &rp.Branch) == nil {
					out = append(out, rp)
				}
			}
			rows.Close()
		}
	}
	return out, provErr
}

func handleGetSASTResults(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		// Optional repo filter - fetch result for specific repo
		filterRepo   := r.URL.Query().Get("repo")
		filterBranch := r.URL.Query().Get("branch")

		var result struct {
			ID            int64           `json:"id"`
			ConnectorID   int64           `json:"connector_id"`
			Repo          string          `json:"repo"`
			Branch        string          `json:"branch"`
			Engine        string          `json:"engine"`
			ScannedAt     time.Time       `json:"scanned_at"`
			RepoCount     int             `json:"scanned_repos"`
			FileCount     int             `json:"scanned_files"`
			FindingCount  int             `json:"finding_count"`
			CriticalCount int             `json:"critical_count"`
			HighCount     int             `json:"high_count"`
			MediumCount   int             `json:"medium_count"`
			Findings      json.RawMessage `json:"findings"`
			AISummary     *string         `json:"ai_summary,omitempty"`
			Engines       json.RawMessage `json:"engines,omitempty"`
			HasSBOM       bool            `json:"sbom_available"`
			// Correlation: the correlation summary when the findings are
			// correlated (null otherwise); Raw: the raw engine findings are shown.
			Correlation   json.RawMessage `json:"correlation"`
			Raw           bool            `json:"raw,omitempty"`
		}
		showRaw := r.URL.Query().Get("raw") == "1"

		var queryErr error
		if filterRepo != "" {
			// Fetch result for specific repo+branch
			branch := filterBranch
			if branch == "" { branch = "HEAD" }
			queryErr = db.QueryRowContext(r.Context(), `
				SELECT id, connector_id, COALESCE(repo,''), COALESCE(branch,''), COALESCE(engine,'semgrep'),
				       scanned_at, repo_count, file_count, finding_count,
				       critical_count, high_count, medium_count,
				       CASE WHEN $5 AND raw_findings IS NOT NULL THEN raw_findings ELSE findings END, ai_summary,
				       COALESCE(engines, '{}'::jsonb), sbom IS NOT NULL, COALESCE(correlation, 'null'::jsonb), $5 AND raw_findings IS NOT NULL
				FROM sast_results
				WHERE connector_id = $1 AND repo = $2
				  AND ($3 = '' OR branch = $3 OR ($4 AND branch IN ('', 'HEAD')))
				  AND (branch NOT LIKE '@%' OR branch = $3)
				ORDER BY scanned_at DESC LIMIT 1`, connID, filterRepo, filterBranch,
				// The default branch is stored as "HEAD" when it was scanned without a name.
				filterBranch == "HEAD" || (filterBranch != "" && filterBranch == r.URL.Query().Get("default")), showRaw,
			).Scan(&result.ID, &result.ConnectorID, &result.Repo, &result.Branch, &result.Engine,
				&result.ScannedAt, &result.RepoCount, &result.FileCount, &result.FindingCount,
				&result.CriticalCount, &result.HighCount, &result.MediumCount,
				&result.Findings, &result.AISummary, &result.Engines, &result.HasSBOM, &result.Correlation, &result.Raw)
			_ = branch
		} else {
			// No repo filter - fetch most recent scan for this connector
			queryErr = db.QueryRowContext(r.Context(), `
				SELECT id, connector_id, COALESCE(repo,''), COALESCE(branch,''), COALESCE(engine,'semgrep'),
				       scanned_at, repo_count, file_count, finding_count,
				       critical_count, high_count, medium_count, findings, ai_summary,
				       COALESCE(engines, '{}'::jsonb), sbom IS NOT NULL, COALESCE(correlation, 'null'::jsonb)
				FROM sast_results WHERE connector_id = $1 AND branch NOT LIKE '@%'
				ORDER BY scanned_at DESC LIMIT 1`, connID,
			).Scan(&result.ID, &result.ConnectorID, &result.Repo, &result.Branch, &result.Engine,
				&result.ScannedAt, &result.RepoCount, &result.FileCount, &result.FindingCount,
				&result.CriticalCount, &result.HighCount, &result.MediumCount,
				&result.Findings, &result.AISummary, &result.Engines, &result.HasSBOM, &result.Correlation)
		}
		if queryErr != nil {
			writeJSON(w, 200, map[string]interface{}{"scan": nil, "scans": []interface{}{}})
			return
		}
		result.Findings = enrichFindingsJSON(r.Context(), db, connID, result.Findings)
		resp := map[string]interface{}{"scan": result}
		if filterRepo == "" {
			// SAST runs one repository at a time, so "the latest scan" is only
			// the last repo scanned. scans carries the latest result for every
			// repository so the overview counts all of them.
			scans := latestSASTPerRepo(r.Context(), db, connID)
			for i := range scans {
				scans[i].Findings = enrichFindingsJSON(r.Context(), db, connID, scans[i].Findings)
			}
			resp["scans"] = scans
		}
		writeJSON(w, 200, resp)
	}
}

type sastRepoScan struct {
	Repo      string          `json:"repo"`
	Branch    string          `json:"branch"`
	Engine    string          `json:"engine"`
	ScannedAt time.Time       `json:"scanned_at"`
	Findings  json.RawMessage `json:"findings"`
}

func latestSASTPerRepo(ctx context.Context, db *store.DB, connID int64) []sastRepoScan {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT ON (COALESCE(repo,'')) COALESCE(repo,''), COALESCE(branch,''), COALESCE(engine,'semgrep'), scanned_at, findings
		FROM sast_results WHERE connector_id = $1 AND branch NOT LIKE '@%'
		ORDER BY COALESCE(repo,''), scanned_at DESC
		LIMIT 1000`, connID)
	if err != nil {
		return []sastRepoScan{}
	}
	defer rows.Close()
	out := []sastRepoScan{}
	for rows.Next() {
		var s sastRepoScan
		if rows.Scan(&s.Repo, &s.Branch, &s.Engine, &s.ScannedAt, &s.Findings) == nil {
			out = append(out, s)
		}
	}
	return out
}

// handleSASTSBOM serves the CycloneDX SBOM stored with a repository's latest
// SAST result: GET /api/v1/devops-connectors/{id}/sast/sbom?repo=&branch=
func handleSASTSBOM(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		repo := r.URL.Query().Get("repo")
		if err != nil || repo == "" {
			writeJSON(w, 400, map[string]string{"error": "connector id and repo are required"})
			return
		}
		branch := r.URL.Query().Get("branch")
		var sbom, findingsRaw []byte
		var gotBranch string
		var scannedAt time.Time
		q := `SELECT sbom, COALESCE(branch,''), scanned_at, findings FROM sast_results WHERE connector_id=$1 AND repo=$2 AND sbom IS NOT NULL`
		args := []interface{}{connID, repo}
		if branch != "" {
			q += ` AND branch=$3`
			args = append(args, branch)
		} else {
			q += ` AND branch NOT LIKE '@%'`
		}
		q += ` ORDER BY scanned_at DESC LIMIT 1`
		if err := db.QueryRowContext(r.Context(), q, args...).Scan(&sbom, &gotBranch, &scannedAt, &findingsRaw); err != nil || len(sbom) == 0 {
			writeJSON(w, 404, map[string]string{"error": "no SBOM for this repository yet; run a SAST scan of it"})
			return
		}
		if r.URL.Query().Get("view") == "1" {
			writeSBOMView(w, r, db, connID, repo, gotBranch, scannedAt, sbom, findingsRaw)
			return
		}
		name := strings.NewReplacer("/", "_", "\\", "_", "\"", "").Replace(repo)
		exportEvent(r, "sbom", repo, "cyclonedx")
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.cdx.json"`, name))
		_, _ = w.Write(sbom)
	}
}

func handleSASTAI(cfg *config.Config, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}

		if !sourceAILimiter.Allow("sast") {
			writeJSON(w, 429, map[string]string{"error": "AI analysis rate limit reached; try again later"})
			return
		}
		groqKey := cfg.Groq.APIKey
		anthropicKey := cfg.Anthropic.APIKey
		if s, err2 := db.GetSettingsPrefix(r.Context(), "ai"); err2 == nil {
			if v := s["groq_api_key"]; v != "" { groqKey = v }
			if v := s["anthropic_api_key"]; v != "" { anthropicKey = v }
		}
		if groqKey == "" && anthropicKey == "" {
			writeJSON(w, 503, map[string]string{"error": "No AI provider configured"})
			return
		}
		apiKey, model := groqKey, groqModelName()
		if apiKey == "" { apiKey, model = anthropicKey, anthropicModelName() }

		var findingsJSON []byte
		var scanID int64
		// The selected repository's result (the latest of the connector used
		// to be analysed whatever repository was on screen).
		if repo := r.URL.Query().Get("repo"); repo != "" {
			err = db.QueryRowContext(r.Context(), `
				SELECT id, findings FROM sast_results
				WHERE connector_id = $1 AND repo = $2 ORDER BY scanned_at DESC LIMIT 1`, connID, repo,
			).Scan(&scanID, &findingsJSON)
		} else {
			err = db.QueryRowContext(r.Context(), `
				SELECT id, findings FROM sast_results
				WHERE connector_id = $1 ORDER BY scanned_at DESC LIMIT 1`, connID,
			).Scan(&scanID, &findingsJSON)
		}
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "no scan results"})
			return
		}

		var findings []SASTFinding
		json.Unmarshal(findingsJSON, &findings)
		// Dismissed findings (false positive, accepted risk) are not sent.
		findings, _ = withoutDismissed(enrichFindings(r.Context(), db, connID, findings))

		type cf struct {
			Rule    string `json:"rule"`
			Sev     string `json:"sev"`
			CWE     string `json:"cwe"`
			Title   string `json:"title"`
			File    string `json:"file"`
			Line    int    `json:"line"`
			Snippet string `json:"snippet,omitempty"`
			Engine  string `json:"engine"`
		}
		withSnippets := aiSourceSnippetsAllowed(r.Context(), db)
		compact := make([]cf, 0, len(findings))
		for _, f := range findings {
			if len(compact) >= aiMaxFindings {
				break
			}
			snip := ""
			if withSnippets {
				snip = truncateRunes(f.Snippet, aiMaxSnippetRune)
			}
			compact = append(compact, cf{f.RuleID, f.Severity, f.CWE, f.Title, f.File, f.Line, snip, f.Engine})
		}
		compactJSON, _ := json.Marshal(compact)

		prompt := promptInjectionGuard + "\n\n" + fmt.Sprintf(`You are a senior application security engineer reviewing SAST findings.
These findings were produced by Semgrep (where engine="semgrep") and/or built-in rules.
Semgrep findings are generally high quality. Built-in findings may have more false positives.

Return ONLY this JSON - no markdown:
{
  "risk_score": <0-100>,
  "risk_label": "Critical|High|Medium|Low|Clean",
  "true_positive_rate": <0-100>,
  "executive_summary": "2-3 sentences for leadership",
  "critical_issues": [{"rule_id":"...","title":"...","file":"...","line":N,"why_critical":"...","fix":"..."}],
  "false_positive_indicators": ["..."],
  "systemic_issues": ["..."],
  "immediate_actions": ["..."],
  "developer_training": ["..."]
}

SAST findings (%d total, %d shown):
%s`, len(findings), len(compact), fenceUntrusted("sast_findings", string(compactJSON)))

		aiCtx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		text, err := callVulnAI(aiCtx, apiKey, model, prompt)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "AI failed: " + err.Error()})
			return
		}
		db.ExecContext(r.Context(), `
			UPDATE sast_results SET ai_summary=$1, ai_analysed_at=NOW() WHERE id=$2`,
			text, scanID)
		writeJSON(w, 200, map[string]interface{}{
			"content": []map[string]interface{}{{"type": "text", "text": text}},
		})
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isSourceFile(path string) bool {
	exts := []string{
		".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
		".go", ".java", ".kt", ".kts", ".scala", ".groovy", ".swift", ".m", ".mm", ".php",
		".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",
		".rb", ".cs", ".rs", ".lua", ".pl", ".pm", ".r", ".dart",
		".tf", ".tfvars", ".yaml", ".yml", ".toml", ".sql",
		".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".gradle", ".cfg", ".ini", ".properties", ".conf",
	}
	lower := strings.ToLower(path)
	base := lower
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	// Files identified by name rather than extension.
	switch {
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile."), base == "makefile", base == "jenkinsfile",
		base == "gemfile", base == "package.json", base == "requirements.txt", base == "go.mod",
		base == "package-lock.json", base == "cargo.lock", base == "composer.lock",
		base == "pipfile.lock", base == "poetry.lock", base == "yarn.lock", base == "pom.xml",
		base == "composer.json", base == "pipfile", base == "procfile", base == "vagrantfile",
		base == ".env" || strings.HasPrefix(base, ".env."), strings.HasSuffix(base, ".env"):
		return true
	}
	for _, ext := range exts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// isVendorPath skips third-party/dependency trees only. SA-04: matching is on
// whole path segments (a substring match skipped legitimate directories like
// config/env/), and attacker-controllable directories such as dist/, build/,
// testdata/, fixtures/ and mocks/ are now scanned.
func isVendorPath(path string) bool {
	skipDirs := map[string]bool{
		"vendor": true, "node_modules": true, ".git": true, "__pycache__": true,
		".venv": true, "venv": true, ".gradle": true, "site-packages": true, "bower_components": true,
	}
	lower := strings.ToLower(path)
	for _, seg := range strings.Split(lower, "/") {
		if skipDirs[seg] {
			return true
		}
	}
	return strings.HasSuffix(lower, ".min.js") || strings.HasSuffix(lower, ".bundle.js") || strings.HasSuffix(lower, "/bundle.js")
}

// sastFilePriority ranks files so that, when a repo exceeds maxFilesPerRepo,
// the highest-risk ones are scanned first (lower number = scan first).
func sastFilePriority(path string) int {
	l := strings.ToLower(path)
	base := l
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	switch {
	case strings.HasPrefix(l, ".github/workflows/"), base == ".gitlab-ci.yml", base == "jenkinsfile",
		base == "azure-pipelines.yml", strings.HasPrefix(l, ".circleci/"):
		return 0
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile."), strings.HasPrefix(base, ".env"),
		strings.HasSuffix(l, ".sh"), strings.HasSuffix(l, ".ps1"), strings.HasSuffix(l, ".tf"):
		return 1
	case base == "package.json", base == "requirements.txt", base == "go.mod", base == "pom.xml":
		return 2
	case strings.Contains(l, "test") || strings.Contains(l, "mock") || strings.Contains(l, "fixture"):
		return 4
	}
	return 3
}

func deduplicateSASTFindings(findings []SASTFinding) []SASTFinding {
	// Every scan path passes here before results are saved, posted or sent to AI: mask credential snippets and
	// lower findings in test code.
	maskFindingSnippets(findings)
	markTestCode(findings)
	// Phase 1: exact duplicates within one engine (repo+rule+file+line).
	exactSeen := map[string]bool{}
	var deduped []SASTFinding
	for _, f := range findings {
		key := f.Engine + "\x00" + f.Repo + "\x00" + f.RuleID + "\x00" + f.File + "\x00" + strconv.Itoa(f.Line)
		if !exactSeen[key] {
			exactSeen[key] = true
			deduped = append(deduped, f)
		}
	}

	// Phase 1b: two built-in rules on the same line with the same CWE report one issue (for example JS002 and
	// A03-JS003 both match eval): keep the more severe one.
	sevRank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
	builtinAt := map[string]int{}
	kept := deduped[:0:0]
	for _, f := range deduped {
		if f.Engine != "builtin" || f.CWE == "" {
			kept = append(kept, f)
			continue
		}
		key := f.Repo + "\x00" + f.File + "\x00" + strconv.Itoa(f.Line) + "\x00" + f.CWE
		if i, ok := builtinAt[key]; ok {
			if sevRank[f.Severity] > sevRank[kept[i].Severity] {
				kept[i] = f
			}
			continue
		}
		builtinAt[key] = len(kept)
		kept = append(kept, f)
	}
	deduped = kept

	// Phase 2: a CodeQL finding within two lines of a Semgrep finding in the
	// same file of the same repository is the same issue: tag the Semgrep
	// one and drop the CodeQL copy. Every other finding (built-in rules,
	// OSV dependency findings, unmatched CodeQL) is kept as is.
	type loc struct {
		repo, file string
		line       int
	}
	out := make([]SASTFinding, 0, len(deduped))
	semgrepAt := map[loc]int{} // location -> index in out
	for _, f := range deduped {
		if f.Engine == "semgrep" {
			semgrepAt[loc{f.Repo, f.File, f.Line}] = len(out)
		}
		if f.Engine != "codeql" {
			out = append(out, f)
		}
	}
	for _, f := range deduped {
		if f.Engine != "codeql" {
			continue
		}
		merged := false
		for dl := -2; dl <= 2 && !merged; dl++ {
			if idx, ok := semgrepAt[loc{f.Repo, f.File, f.Line + dl}]; ok {
				out[idx].Engine = "semgrep+codeql"
				merged = true
			}
		}
		if !merged {
			out = append(out, f)
		}
	}

	// Phase 3: the built-in rules always run next to opengrep/semgrep and CodeQL. A built-in finding with the
	// same CWE within two lines of an engine finding in the same file is the same issue: keep the engine's,
	// which has the better message and data flow.
	engineAt := map[loc][]string{}
	for _, f := range out {
		if f.Engine != "builtin" && f.Package == "" {
			if id := cweID(f.CWE); id != "" {
				k := loc{f.Repo, f.File, f.Line}
				engineAt[k] = append(engineAt[k], id)
			}
		}
	}
	if len(engineAt) == 0 {
		return out
	}
	covered := func(f SASTFinding, id string) bool {
		for dl := -2; dl <= 2; dl++ {
			for _, e := range engineAt[loc{f.Repo, f.File, f.Line + dl}] {
				if e == id {
					return true
				}
			}
		}
		return false
	}
	final := out[:0:0]
	for _, f := range out {
		if f.Engine == "builtin" {
			if id := cweID(f.CWE); id != "" && covered(f, id) {
				continue
			}
		}
		final = append(final, f)
	}
	return final
}

var cweIDRe = regexp.MustCompile(`(?i)CWE-\d+`)

// cweID is the bare "CWE-89" of a CWE field ("CWE-89: Improper Neutralization ..." from engine metadata).
func cweID(s string) string { return strings.ToUpper(cweIDRe.FindString(s)) }



// escapePathSegments URL-escapes each segment of a slash-separated path.
func escapePathSegments(p string) string {
	segs := strings.Split(p, "/")
	for i, sg := range segs {
		segs[i] = neturl.PathEscape(sg)
	}
	return strings.Join(segs, "/")
}

// sastSizeLimit allows dependency lockfiles to be larger than source files.
func sastSizeLimit(path string) int {
	if isScaManifest(path) {
		return 5 << 20
	}
	return maxFileBytes
}

// chosenEngineWarning warns about the engines that were chosen but did not run.
func chosenEngineWarning(scanned int, set engineSet, e engineReport) string {
	if scanned == 0 {
		return ""
	}
	var ws []string
	if set.on(engSemgrep) || set.on(engCodeQL) {
		ws = append(ws, sastEngineWarning(e))
	}
	if v := e["business-logic"]; strings.HasPrefix(v, "failed") {
		ws = append(ws, "AI business logic "+v+".")
	}
	return joinWarnings(ws...)
}

func scanEngineWarning(scanned int, e engineReport) string {
	if scanned == 0 {
		return ""
	}
	return sastEngineWarning(e)
}

func joinWarnings(ws ...string) string {
	var out []string
	for _, w := range ws {
		if w != "" {
			out = append(out, w)
		}
	}
	return strings.Join(out, " ")
}
