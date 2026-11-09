package api

// codescan.go — Code scanning for DevOps connectors
//
// Scans commit diffs and file trees for:
//   1. Secrets / credentials (API keys, passwords, tokens)
//   2. Dependency vulnerabilities (package.json, requirements.txt, go.mod, pom.xml)
//   3. Dangerous code patterns (eval, exec, SQL injection, XSS)
//   4. Sensitive file types (.env, .pem, .key, id_rsa)
//   5. AI-powered review summary

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
)

// ── Finding types ─────────────────────────────────────────────────────────────

type CodeFinding struct {
	Severity    string `json:"severity"`    // critical|high|medium|low|info
	Category    string `json:"category"`    // secret|dependency|dangerous_code|sensitive_file|config
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	File        string `json:"file"`
	Line        string `json:"line,omitempty"`
	Commit      string `json:"commit,omitempty"`
	CommitMsg   string `json:"commit_msg,omitempty"`
	Author      string `json:"author,omitempty"`
	Repo        string `json:"repo,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// ── Pattern definitions ───────────────────────────────────────────────────────

var secretPatternsDef = []struct {
	name    string
	pattern *regexp.Regexp
	sev     string
}{
	{"AWS Access Key",       regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`), "critical"},
	{"AWS Secret Key",       regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})`), "critical"},
	{"Private Key Block",    regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY`), "critical"},
	{"GitHub Token",         regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}`), "critical"},
	{"Slack Token",          regexp.MustCompile(`xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}`), "critical"},
	{"Stripe Key",           regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`), "critical"},
	{"Google API Key",       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "high"},
	{"JWT Token",            regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}`), "high"},
	{"Generic Password",     regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api_key|apikey|api_secret|auth_token|access_token)\s*[=:]\s*["']([^"'\s]{8,})`), "high"},
	{"DB Connection String", regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis|mongodb\+srv)://[^\s"'<>]+:[^\s"'<>@]+@`), "high"},
	{"Generic Token",        regexp.MustCompile(`(?i)(token|auth)\s*[=:]\s*["']([a-zA-Z0-9_\-\.]{32,})`), "medium"},
	{"IP + Port Hardcoded",  regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b`), "low"},
}

var codeScanSensitiveFiles = []struct {
	pattern *regexp.Regexp
	title   string
	sev     string
	fix     string
}{
	{regexp.MustCompile(`(?i)^\.env$|^\.env\.(local|prod|production|staging)$`), "Environment file committed", "critical", "Add .env to .gitignore and rotate all secrets"},
	{regexp.MustCompile(`(?i)\.(pem|key|p12|pfx|cer|crt)$`), "Certificate or private key file", "critical", "Remove from repo and rotate credentials"},
	{regexp.MustCompile(`(?i)^id_rsa$|^id_ecdsa$|^id_ed25519$`), "SSH private key", "critical", "Remove immediately and generate new SSH keys"},
	{regexp.MustCompile(`(?i)\.aws/credentials$`), "AWS credentials file", "critical", "Remove and rotate AWS keys"},
	{regexp.MustCompile(`(?i)(secrets?|credentials?)\.ya?ml$`), "Secrets file", "high", "Use a secrets manager instead of committing secrets"},
	{regexp.MustCompile(`(?i)terraform\.tfstate$`), "Terraform state file", "high", "Use remote state backend, add *.tfstate to .gitignore"},
	{regexp.MustCompile(`(?i)kubeconfig$`), "Kubernetes config file", "high", "Remove and rotate service account tokens"},
	{regexp.MustCompile(`(?i)wp-config\.php$`), "WordPress config (may contain DB credentials)", "medium", "Ensure no credentials are hardcoded"},
	{regexp.MustCompile(`(?i)database\.yml$|database\.yaml$`), "Database config file", "medium", "Ensure production credentials are not committed"},
}

var dangerousPatternsDef = []struct {
	name    string
	pattern *regexp.Regexp
	langs   []string // file extensions to apply to
	sev     string
	fix     string
}{
	{
		"eval() with user input", regexp.MustCompile(`eval\s*\([^)]*(?:req|request|params|query|body|input|user)[^)]*\)`),
		[]string{".js", ".ts", ".py", ".php", ".rb"}, "high",
		"Never pass user input to eval() — use safe alternatives",
	},
	{
		"exec() with user input", regexp.MustCompile(`exec\s*\([^)]*(?:req|request|params|query|body|input|user)[^)]*\)`),
		[]string{".js", ".ts", ".py", ".go", ".php"}, "high",
		"Use parameterized commands or validate/sanitize input",
	},
	{
		"SQL string concatenation", regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|WHERE).{0,100}["']\s*\+|["']\s*\+.{0,100}(SELECT|INSERT|UPDATE|DELETE)`),
		[]string{".js", ".ts", ".py", ".php", ".java", ".go", ".cs"}, "high",
		"Use parameterized queries / prepared statements",
	},
	{
		"innerHTML assignment", regexp.MustCompile(`\.innerHTML\s*=`),
		[]string{".js", ".ts", ".jsx", ".tsx", ".html"}, "medium",
		"Use textContent or sanitize with DOMPurify to prevent XSS",
	},
	{
		"Hardcoded localhost URL", regexp.MustCompile(`http://localhost|http://127\.0\.0\.1`),
		[]string{".js", ".ts", ".py", ".go", ".java", ".env"}, "low",
		"Use environment variables for URLs",
	},
	{
		"TODO: security comment", regexp.MustCompile(`(?i)TODO.*(?:security|auth|encrypt|sanitize|validate|fix.*vuln)`),
		[]string{".js", ".ts", ".py", ".go", ".java", ".cs", ".php"}, "info",
		"Address security-related TODOs before production deployment",
	},
	{
		"Disabled SSL verification", regexp.MustCompile(`(?i)(verify\s*=\s*False|InsecureSkipVerify|ssl_verify\s*=\s*false|rejectUnauthorized\s*:\s*false)`),
		[]string{".py", ".go", ".js", ".ts", ".yaml", ".yml"}, "high",
		"Enable SSL verification in production — disable only for local testing",
	},
	{
		"Hardcoded debug mode", regexp.MustCompile(`(?i)(DEBUG\s*=\s*True|debug\s*:\s*true)`),
		[]string{".py", ".env", ".yaml", ".yml", ".json"}, "medium",
		"Disable debug mode in production configuration",
	},
}

// ── Main scan logic ───────────────────────────────────────────────────────────

func scanCommitForFindings(commit store.DevOpsCommit) []CodeFinding {
	var findings []CodeFinding

	// Parse diff_summary
	var diffs []store.CommitFileDiff
	if commit.DiffSummary != nil {
		json.Unmarshal(commit.DiffSummary, &diffs)
	}

	for _, diff := range diffs {
		file := diff.File
		patch := diff.Patch

		// 1. Sensitive file names
		for _, sf := range codeScanSensitiveFiles {
			if sf.pattern.MatchString(file) {
				findings = append(findings, CodeFinding{
					Severity:    sf.sev,
					Category:    "sensitive_file",
					Title:       sf.title,
					Detail:      fmt.Sprintf("File '%s' should not be committed to source control", file),
					File:        file,
					Commit:      commit.ID,
					CommitMsg:   commit.Message,
					Author:      commit.AuthorUsername,
					Repo:        commit.Repo,
					Remediation: sf.fix,
				})
			}
		}

		if patch == "" {
			continue
		}

		// Only scan added lines (lines starting with +, not +++)
		var addedLines []string
		for i, line := range strings.Split(patch, "\n") {
			if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				addedLines = append(addedLines, fmt.Sprintf("%d:%s", i+1, line[1:]))
			}
		}
		addedContent := strings.Join(addedLines, "\n")

		// 2. Secret patterns
		for _, sp := range secretPatternsDef {
			if sp.pattern.MatchString(addedContent) {
				findings = append(findings, CodeFinding{
					Severity:    sp.sev,
					Category:    "secret",
					Title:       sp.name + " detected in commit",
					Detail:      fmt.Sprintf("Potential secret pattern '%s' found in %s", sp.name, file),
					File:        file,
					Commit:      commit.ID,
					CommitMsg:   commit.Message,
					Author:      commit.AuthorUsername,
					Repo:        commit.Repo,
					Remediation: "Remove the secret, rotate credentials, and use environment variables or a secrets manager",
				})
			}
		}

		// 3. Dangerous patterns (check file extension)
		fileExt := ""
		if idx := strings.LastIndex(file, "."); idx >= 0 {
			fileExt = strings.ToLower(file[idx:])
		}
		for _, dp := range dangerousPatternsDef {
			applies := false
			for _, ext := range dp.langs {
				if ext == fileExt || ext == "*" {
					applies = true
					break
				}
			}
			if !applies {
				continue
			}
			if dp.pattern.MatchString(addedContent) {
				findings = append(findings, CodeFinding{
					Severity:    dp.sev,
					Category:    "dangerous_code",
					Title:       dp.name,
					Detail:      fmt.Sprintf("Dangerous pattern found in %s", file),
					File:        file,
					Commit:      commit.ID,
					CommitMsg:   commit.Message,
					Author:      commit.AuthorUsername,
					Repo:        commit.Repo,
					Remediation: dp.fix,
				})
			}
		}

		// 4. Dependency file scanning
		scanDependencyFile(file, addedContent, commit, &findings)
	}

	return findings
}

// scanDependencyFile checks for known vulnerable dependencies
func scanDependencyFile(file, content string, commit store.DevOpsCommit, findings *[]CodeFinding) {
	base := file
	if idx := strings.LastIndex(file, "/"); idx >= 0 {
		base = file[idx+1:]
	}

	switch strings.ToLower(base) {
	case "package.json":
		// Check for known vulnerable npm packages
		knownVulnNPM := map[string]string{
			"lodash":      "< 4.17.21 has prototype pollution (CVE-2021-23337)",
			"axios":       "< 0.21.2 has SSRF vulnerability (CVE-2021-3749)",
			"log4js":      "< 6.4.0 has RCE vulnerability",
			"minimist":    "< 1.2.6 has prototype pollution (CVE-2021-44906)",
			"node-fetch":  "< 2.6.7 has ReDoS vulnerability",
			"xmlhttprequest": "< 1.8.0 has SSRF (CVE-2020-28502)",
			"marked":      "< 4.0.10 has XSS vulnerability",
			"ejs":         "< 3.1.7 has RCE vulnerability (CVE-2022-29078)",
		}
		for pkg, vuln := range knownVulnNPM {
			if regexp.MustCompile(`"` + pkg + `"\s*:`).MatchString(content) {
				*findings = append(*findings, CodeFinding{
					Severity:    "medium",
					Category:    "dependency",
					Title:       fmt.Sprintf("Potentially vulnerable npm package: %s", pkg),
					Detail:      vuln,
					File:        file,
					Commit:      commit.ID,
					Author:      commit.AuthorUsername,
					Repo:        commit.Repo,
					Remediation: fmt.Sprintf("Run `npm audit fix` and check for updates to %s", pkg),
				})
			}
		}

	case "requirements.txt", "pipfile", "pipfile.lock":
		knownVulnPy := map[string]string{
			"django":      "Many versions have known CVEs — ensure latest patch version",
			"flask":       "< 2.2.5 has vulnerabilities",
			"requests":    "< 2.28.2 has vulnerabilities",
			"pillow":      "Many versions have image parsing CVEs",
			"cryptography": "Older versions have known CVEs — keep updated",
			"pyyaml":      "< 6.0 has arbitrary code execution (CVE-2020-14343)",
			"urllib3":     "< 1.26.5 has CRLF injection vulnerability",
			"jinja2":      "< 3.1.2 has SSTI vulnerability",
		}
		for pkg, vuln := range knownVulnPy {
			if regexp.MustCompile(`(?i)` + pkg + `\s*[=<>!]+`).MatchString(content) {
				*findings = append(*findings, CodeFinding{
					Severity:    "medium",
					Category:    "dependency",
					Title:       fmt.Sprintf("Potentially vulnerable Python package: %s", pkg),
					Detail:      vuln,
					File:        file,
					Commit:      commit.ID,
					Author:      commit.AuthorUsername,
					Repo:        commit.Repo,
					Remediation: fmt.Sprintf("Run `pip audit` and update %s to latest version", pkg),
				})
			}
		}

	case "go.mod":
		// Check for known vulnerable Go modules
		knownVulnGo := map[string]string{
			"github.com/dgrijalva/jwt-go": "Deprecated, has critical CVE-2020-26160 — use github.com/golang-jwt/jwt",
			"github.com/form3tech-oss/jwt-go": "Has CVE-2020-26160 — use github.com/golang-jwt/jwt",
			"gopkg.in/yaml.v2": "< v2.4.0 has DOS vulnerability",
		}
		for pkg, vuln := range knownVulnGo {
			if strings.Contains(content, pkg) {
				*findings = append(*findings, CodeFinding{
					Severity:    "high",
					Category:    "dependency",
					Title:       fmt.Sprintf("Vulnerable Go module: %s", pkg),
					Detail:      vuln,
					File:        file,
					Commit:      commit.ID,
					Author:      commit.AuthorUsername,
					Repo:        commit.Repo,
					Remediation: "Run `go get -u` and check go.sum for the updated version",
				})
			}
		}
	}
}

// ── HTTP Handlers ─────────────────────────────────────────────────────────────

func handleCodeScan(cfg *config.Config, db *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid connector id"})
			return
		}
		ctx := r.Context()

		// Fetch last 500 commits for this connector
		commits, err := db.ListDevOpsCommits(ctx, connID, "", 500)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to list commits"})
			return
		}

		if len(commits) == 0 {
			writeJSON(w, 200, map[string]interface{}{
				"message":  "No commits to scan. Run a sync first.",
				"findings": []CodeFinding{},
			})
			return
		}

		// Scan all commits
		var allFindings []CodeFinding
		repoSet := map[string]bool{}
		fileSet := map[string]bool{}

		for _, commit := range commits {
			repoSet[commit.Repo] = true
			var diffs []store.CommitFileDiff
			if commit.DiffSummary != nil {
				json.Unmarshal(commit.DiffSummary, &diffs)
				for _, d := range diffs {
					fileSet[commit.Repo+":"+d.File] = true
				}
			}
			findings := scanCommitForFindings(commit)
			allFindings = append(allFindings, findings...)
		}

		// Deduplicate by title+file combo
		allFindings = deduplicateFindings(allFindings)

		// Count by severity
		counts := map[string]int{}
		for _, f := range allFindings {
			counts[f.Severity]++
		}

		findingsJSON, _ := json.Marshal(allFindings)

		// Save to DB
		_, dbErr := db.ExecContext(ctx, `
			INSERT INTO code_scan_results
				(connector_id, repo_count, file_count, finding_count,
				 critical_count, high_count, medium_count, findings)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			connID, len(repoSet), len(fileSet), len(allFindings),
			counts["critical"], counts["high"], counts["medium"],
			findingsJSON,
		)
		if dbErr != nil {
			logger.Warn("code scan: failed to save results", "err", dbErr)
		}

		writeJSON(w, 200, map[string]interface{}{
			"scanned_commits": len(commits),
			"repo_count":      len(repoSet),
			"file_count":      len(fileSet),
			"finding_count":   len(allFindings),
			"critical_count":  counts["critical"],
			"high_count":      counts["high"],
			"medium_count":    counts["medium"],
			"findings":        allFindings,
		})
	}
}

func handleGetCodeScanResults(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		var result struct {
			ID            int64           `json:"id"`
			ConnectorID   int64           `json:"connector_id"`
			ScannedAt     time.Time       `json:"scanned_at"`
			RepoCount     int             `json:"repo_count"`
			FileCount     int             `json:"file_count"`
			FindingCount  int             `json:"finding_count"`
			CriticalCount int             `json:"critical_count"`
			HighCount     int             `json:"high_count"`
			MediumCount   int             `json:"medium_count"`
			Findings      json.RawMessage `json:"findings"`
			AISummary     *string         `json:"ai_summary,omitempty"`
		}
		err = db.QueryRowContext(r.Context(), `
			SELECT id, connector_id, scanned_at, repo_count, file_count, finding_count,
			       critical_count, high_count, medium_count, findings, ai_summary
			FROM code_scan_results
			WHERE connector_id = $1
			ORDER BY scanned_at DESC
			LIMIT 1`, connID).Scan(
			&result.ID, &result.ConnectorID, &result.ScannedAt,
			&result.RepoCount, &result.FileCount, &result.FindingCount,
			&result.CriticalCount, &result.HighCount, &result.MediumCount,
			&result.Findings, &result.AISummary,
		)
		if err != nil {
			writeJSON(w, 200, map[string]interface{}{"scan": nil})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"scan": result})
	}
}

func handleCodeScanAI(cfg *config.Config, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}

		if !sourceAILimiter.Allow("codescan") {
			writeJSON(w, 429, map[string]string{"error": "AI analysis rate limit reached; try again later"})
			return
		}
		// Resolve AI keys
		groqKey := cfg.Groq.APIKey
		anthropicKey := cfg.Anthropic.APIKey
		if s, err := db.GetSettingsPrefix(r.Context(), "ai"); err == nil {
			if v := s["groq_api_key"]; v != "" { groqKey = v }
			if v := s["anthropic_api_key"]; v != "" { anthropicKey = v }
		}
		if groqKey == "" && anthropicKey == "" {
			writeJSON(w, 503, map[string]string{"error": "No AI provider configured"})
			return
		}
		apiKey, model := groqKey, "llama-3.3-70b-versatile"
		if apiKey == "" { apiKey, model = anthropicKey, "claude-sonnet-4-20250514" }

		// Get latest scan results
		var findingsJSON []byte
		var scanID int64
		err = db.QueryRowContext(r.Context(), `
			SELECT id, findings FROM code_scan_results
			WHERE connector_id = $1 ORDER BY scanned_at DESC LIMIT 1`, connID,
		).Scan(&scanID, &findingsJSON)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "no scan results found — run a scan first"})
			return
		}

		var findings []CodeFinding
		json.Unmarshal(findingsJSON, &findings)

		// Build compact findings summary for AI
		type compactFinding struct {
			Sev      string `json:"sev"`
			Category string `json:"cat"`
			Title    string `json:"title"`
			File     string `json:"file"`
			Author   string `json:"author,omitempty"`
			Repo     string `json:"repo"`
		}
		compact := make([]compactFinding, 0, len(findings))
		for _, f := range findings {
			if len(compact) >= aiMaxFindings {
				break
			}
			compact = append(compact, compactFinding{
				Sev: f.Severity, Category: f.Category,
				Title: f.Title, File: f.File,
				Author: f.Author, Repo: f.Repo,
			})
		}
		compactJSON, _ := json.Marshal(compact)

		prompt := promptInjectionGuard + "\n\n" + fmt.Sprintf(`You are a senior application security engineer reviewing code scan results.

You have been given code scan findings from a DevOps repository connector.
The findings include: secrets exposed in commits, sensitive files committed, dangerous code patterns, and vulnerable dependencies.

Analyse the findings and return ONLY this exact JSON — no markdown, no code blocks:
{
  "risk_score": <0-100>,
  "risk_label": "Critical|High|Medium|Low|Clean",
  "executive_summary": "2-3 sentences for engineering leadership — overall security posture and top risks",
  "top_issues": [
    {"title": "...", "detail": "...", "impact": "...", "fix": "..."}
  ],
  "patterns": "Are there repeated patterns suggesting systemic issues? (e.g. team not using secrets manager, legacy dependencies not updated)",
  "immediate_actions": ["action 1", "action 2", "action 3"],
  "process_recommendations": ["process change 1", "process change 2"],
  "positive_notes": ["things done right"]
}

Findings (%d total, %d shown):
%s`, len(findings), len(compact), fenceUntrusted("code_scan_findings", string(compactJSON)))

		aiCtx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		text, err := callVulnAI(aiCtx, apiKey, model, prompt)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "AI analysis failed: " + err.Error()})
			return
		}

		// Save AI summary to DB
		db.ExecContext(r.Context(), `
			UPDATE code_scan_results SET ai_summary = $1, ai_analysed_at = NOW()
			WHERE id = $2`, text, scanID)

		writeJSON(w, 200, map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": text},
			},
		})
	}
}

func deduplicateFindings(findings []CodeFinding) []CodeFinding {
	seen := map[string]bool{}
	var out []CodeFinding
	for _, f := range findings {
		key := f.Category + ":" + f.Title + ":" + f.File
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
