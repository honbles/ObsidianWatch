package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
)

// handleGetVulnScan returns the latest vulnerability.scan event for a host
func handleGetVulnScan(db *store.DB, backendDB *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		if host == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
			return
		}
		ctx := r.Context()
		// Try management DB first, then backend DB (F-10: exact host match)
		events, _, err := db.QueryEvents(ctx, store.EventFilter{
			HostExact: host,
			EventType: "vulnerability.scan",
			Limit:     1,
		})
		if (err != nil || len(events) == 0) && backendDB != nil {
			// Events are stored in the backend DB — try there too
			events, _, err = backendDB.QueryEvents(ctx, store.EventFilter{
				HostExact: host,
				EventType: "vulnerability.scan",
				Limit:     1,
			})
		}
		if err != nil || len(events) == 0 {
			writeJSON(w, http.StatusOK, map[string]interface{}{"scan": nil})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"scan": events[0]})
	}
}

// handleVulnAIAnalysis — runs AI analysis on a vulnerability scan result
func handleVulnAIAnalysis(cfg *config.Config, db *store.DB, backendDB *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ScanJSON string `json:"scan_json"`
			Host     string `json:"host"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}

		// Resolve AI keys
		groqKey := cfg.Groq.APIKey
		anthropicKey := cfg.Anthropic.APIKey
		if aiSettings, err := db.GetSettingsPrefix(r.Context(), "ai"); err == nil {
			if v := aiSettings["groq_api_key"]; v != "" {
				groqKey = v
			}
			if v := aiSettings["anthropic_api_key"]; v != "" {
				anthropicKey = v
			}
		}
		if groqKey == "" && anthropicKey == "" {
			writeJSON(w, 503, map[string]string{"error": "No AI provider configured. Add a Groq or Anthropic API key in Settings → AI."})
			return
		}

		apiKey, model := groqKey, groqModelName()
		if apiKey == "" {
			apiKey, model = anthropicKey, anthropicModelName()
		}

		ctx := r.Context()

		// Parse the scan
		var scan map[string]interface{}
		if err := json.Unmarshal([]byte(req.ScanJSON), &scan); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid scan JSON"})
			return
		}

		// ── NVD-powered CVE lookup + AI analysis ─────────────────────────────
		//
		// Phase 1: Query NVD (National Vulnerability Database) for real CVEs.
		//   - No AI guessing — real CVE IDs with real CVSS scores
		//   - Results cached 24h to avoid re-querying on every analysis
		//   - Rate limited to stay within NVD free tier (5 req/30s)
		//
		// Phase 2: Single AI call with confirmed CVEs + ports + findings.
		//   - AI produces narrative, attack surface, remediation plan
		//   - No package list sent to AI — just confirmed vulnerabilities

		pkgCount := 0
		var nvdFindings []CVEFinding

		if pkgs, ok := scan["packages"].([]interface{}); ok && len(pkgs) > 0 {
			pkgCount = len(pkgs)

			// Check host-level NVD cache first (24h TTL, avoids re-querying on every analysis)
			hostCacheKey := "nvd_findings:" + req.Host
			if cached, err := db.GetSetting(r.Context(), hostCacheKey); err == nil && cached != "" {
				if err2 := json.Unmarshal([]byte(cached), &nvdFindings); err2 == nil {
					logger.Info("nvd: using cached findings", "host", req.Host, "count", len(nvdFindings))
				} else {
					nvdFindings = nil
				}
			}

			// If no cache, query NVD
			if nvdFindings == nil {
				pkgMaps := make([]map[string]interface{}, 0, len(pkgs))
				for _, p := range pkgs {
					if pm, ok := p.(map[string]interface{}); ok {
						pkgMaps = append(pkgMaps, pm)
					}
				}

				// F-21: prefer OSV's distro feeds (exact version, back-port aware)
				// for Debian/Ubuntu/Alpine hosts; NVD keyword search is the fallback.
				osvDone := false
				if sys, ok := scan["system"].(map[string]interface{}); ok {
					rel, _ := sys["os_release"].(string)
					if eco := osvEcosystemFor(rel); eco != "" {
						osvCtx, osvCancel := context.WithTimeout(ctx, 20*time.Second)
						found, osvErr := osvHostFindings(osvCtx, eco, pkgMaps)
						osvCancel()
						if osvErr == nil {
							nvdFindings, osvDone = found, true
							if nvdFindings == nil {
								nvdFindings = []CVEFinding{}
							}
						} else {
							logger.Warn("osv: host lookup failed, falling back to NVD", "host", req.Host, "err", osvErr)
						}
					}
				}

				var nvdErr error
				if !osvDone {
					nvdKey := cfg.NVD.APIKey
					if s, err := db.GetSetting(r.Context(), "nvd_api_key"); err == nil && s != "" {
						nvdKey = s
					}
					nvdClient := NewNVDClient(nvdKey, logger)

					// Cap at 20s — stays within server write timeout
					nvdCtx, nvdCancel := context.WithTimeout(ctx, 20*time.Second)
					nvdFindings, nvdErr = nvdClient.LookupPackages(nvdCtx, pkgMaps, 4.0)
					nvdCancel()
				}

				if nvdErr != nil {
					logger.Warn("nvd: lookup timed out, proceeding with AI analysis only", "err", nvdErr)
				} else if len(nvdFindings) > 0 {
					// Cache findings per host for 24h
					if b, err := json.Marshal(nvdFindings); err == nil {
						_ = db.SetSetting(r.Context(), hostCacheKey, string(b))
					}
				}
			}
		}

		// Build the AI prompt with confirmed CVEs (no raw package list)
		analysisScan := map[string]interface{}{
			"host":               scan["host"],
			"os":                 scan["os"],
			"system":             scan["system"],
			"scanned_at":         scan["scanned_at"],
			"open_ports":         scan["open_ports"],
			"udp_ports":          scan["udp_ports"],
			"services":           scan["services"],
			"findings":           scan["findings"],
			"total_open":         scan["total_open"],
			"critical_count":     scan["critical_count"],
			"high_count":         scan["high_count"],
			"medium_count":       scan["medium_count"],
			"scan_duration_secs": scan["scan_duration_secs"],
			"total_packages":     pkgCount,
			"confirmed_cves":     nvdFindings, // real CVEs from NVD, not AI guesses
		}
		analysisScanJSON, _ := json.Marshal(analysisScan)

		aiCtx, cancel2 := context.WithTimeout(ctx, 60*time.Second)
		defer cancel2()

		finalPrompt := buildVulnAnalysisPrompt(string(analysisScanJSON), req.Host)
		finalText, err := callVulnAI(aiCtx, apiKey, model, finalPrompt)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "AI analysis failed: " + err.Error()})
			return
		}

		// Cache the result so re-opens are instant
		_ = db.SetSetting(r.Context(), "vuln_analysis:"+req.Host, finalText)

		writeJSON(w, 200, map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": finalText},
			},
		})
	}
}

// callVulnAI sends a prompt to the configured AI provider and returns the text response.
func callVulnAI(ctx context.Context, apiKey, model, prompt string) (string, error) {
	isGroq := !isAnthropicModel(model)

	var apiURL string
	body := map[string]interface{}{
		"model":       model,
		"max_tokens":  4096,
		"temperature": 0.1,
		"messages": []map[string]interface{}{
			{
				"role":    "system",
				"content": "You are a cybersecurity vulnerability analyst. Always respond with valid JSON only. No markdown, no code blocks, no explanations — just the raw JSON.",
			},
			{"role": "user", "content": prompt},
		},
	}

	if isGroq {
		delete(body, "max_tokens")
		groqTune(body, model, 4096)
		apiURL = "https://api.groq.com/openai/v1/chat/completions"
	} else {
		apiURL = "https://api.anthropic.com/v1/messages"
	}

	bodyBytes, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if isGroq {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	} else {
		httpReq.Header.Set("x-api-key", apiKey)
		httpReq.Header.Set("anthropic-version", "2023-06-01")
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	var text string
	if isGroq {
		if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if msg, ok := choice["message"].(map[string]interface{}); ok {
					text, _ = msg["content"].(string)
				}
			}
		}
	} else {
		if content, ok := result["content"].([]interface{}); ok {
			for _, block := range content {
				if b, ok := block.(map[string]interface{}); ok && b["type"] == "text" {
					text, _ = b["text"].(string)
				}
			}
		}
	}

	if text == "" {
		return "", fmt.Errorf("empty AI response")
	}

	// Strip markdown fences if present
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	return extractJSONObject(strings.TrimSpace(text)), nil
}

func buildVulnAnalysisPrompt(scanJSON, host string) string {
	return fmt.Sprintf(`You are an enterprise security engineer performing a vulnerability assessment review.

You have been given a full vulnerability scan result from host "%s" in JSON format.
The scan includes: open TCP/UDP ports with service versions, ALL installed packages (analyse every package for known CVEs and outdated versions — golang, php, python, openssl, nginx, ssh, mysql, etc.), running services, and security findings.

Analyse the scan data and return ONLY a valid JSON object — no markdown, no code blocks, no extra text.

Return this exact JSON structure:
{
  "executive_summary": "2-3 sentence plain English summary for a CISO — overall risk posture and top concerns",
  "risk_score": <integer 0-100 representing overall risk, 100=most critical>,
  "risk_label": "Critical|High|Medium|Low|Minimal",
  "critical_findings": [
    {"title": "...", "detail": "...", "cve_references": ["CVE-XXXX-XXXXX"], "affected": "service or component", "remediation": "specific fix command or action"}
  ],
  "high_findings": [
    {"title": "...", "detail": "...", "cve_references": [], "affected": "...", "remediation": "..."}
  ],
  "medium_findings": [
    {"title": "...", "detail": "...", "cve_references": [], "affected": "...", "remediation": "..."}
  ],
  "outdated_software": [
    {"name": "...", "installed_version": "...", "recommended_version": "...", "cves": ["..."], "upgrade_command": "..."}
  ],
  "attack_surface_summary": "paragraph describing what an attacker could do with the exposed services",
  "immediate_actions": ["highest priority action 1", "action 2", "action 3"],
  "remediation_plan": [
    {"priority": 1, "action": "...", "effort": "minutes|hours|days", "impact": "..."},
    {"priority": 2, "action": "...", "effort": "...", "impact": "..."}
  ],
  "compliance_notes": "brief note on any obvious compliance implications (PCI-DSS, SOC2, ISO27001, HIPAA)",
  "positive_findings": ["things that are configured correctly and should be maintained"]
}

Scan data:
%s`, host, scanJSON)
}

// filterInterestingPackages removes low-value system/lib packages that rarely
// have exploitable CVEs, reducing the number of AI calls needed.
func filterInterestingPackages(pkgs []interface{}) []interface{} {
	skipPrefixes := []string{
		"lib", "font", "fonts-", "python3-", "python-", "perl-", "ruby-",
		"php-", "gir1.2-", "golang-", "nodejs-", "gnome-", "kde-",
		"locale-", "language-", "xfonts-", "ttf-", "texlive-",
		"linux-image-", "linux-headers-", "linux-modules-",
		"grub-", "initramfs-", "plymouth-",
	}
	var out []interface{}
	for _, p := range pkgs {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := pm["name"].(string)
		if name == "" {
			continue
		}
		skip := false
		for _, prefix := range skipPrefixes {
			if strings.HasPrefix(strings.ToLower(name), prefix) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, p)
		}
	}
	return out
}

// saveAlertAnalysis extracts the AI text from the response and persists it
// against the alert so subsequent opens don't need to re-call the AI.
func saveAlertAnalysis(ctx context.Context, db *store.DB, req AlertAnalysisRequest, result map[string]interface{}) {
	if req.AlertID == 0 {
		return // no alert ID — can't save
	}
	// Extract text content from AI response
	text := ""
	if content, ok := result["content"].([]interface{}); ok {
		for _, block := range content {
			if b, ok := block.(map[string]interface{}); ok && b["type"] == "text" {
				text, _ = b["text"].(string)
			}
		}
	}
	if text == "" {
		return
	}
	_ = db.SaveAlertAIAnalysis(ctx, req.AlertID, text)
}

// handleGetVulnAnalysisCache returns the cached AI analysis for a host's vuln scan.
func handleGetVulnAnalysisCache(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		val, err := db.GetSetting(r.Context(), "vuln_analysis:"+host)
		if err != nil || val == "" {
			writeJSON(w, http.StatusOK, map[string]interface{}{"analysis": nil})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"analysis": val})
	}
}

// ── Root Cause Analysis ───────────────────────────────────────────────────────
