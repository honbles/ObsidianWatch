package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Sync Engine ───────────────────────────────────────────────────────────────

type ThreatIntelEngine struct {
	db     *store.DB
	logger *slog.Logger
	client *http.Client
}

func NewThreatIntelEngine(db *store.DB, logger *slog.Logger) *ThreatIntelEngine {
	return &ThreatIntelEngine{
		db:     db,
		logger: logger,
		client: &http.Client{Timeout: 300 * time.Second},
	}
}

func (e *ThreatIntelEngine) Run(ctx context.Context) {
	// Sync on startup
	e.syncAll(ctx)

	// Then daily at 02:00
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.syncAll(ctx)
		}
	}
}

func (e *ThreatIntelEngine) syncAll(ctx context.Context) {
	sources, err := e.db.ListThreatIntelSources(ctx)
	if err != nil {
		e.logger.Warn("threat-intel: list sources failed", "err", err)
		return
	}
	for _, src := range sources {
		if !src.Enabled {
			continue
		}
		e.logger.Info("threat-intel: syncing", "source", src.Name)
		syncStart := time.Now().Add(-1 * time.Minute)
		var syncErr error
		var count int
		switch src.Name {
		case "threatfox":
			count, syncErr = e.syncThreatFox(ctx, src.APIKey)
		case "otx":
			if src.APIKey == nil || *src.APIKey == "" {
				syncErr = fmt.Errorf("OTX API key not configured")
			} else {
				count, syncErr = e.syncOTX(ctx, *src.APIKey)
			}
		case "sigma":
			count, syncErr = e.syncSigma(ctx)
		}
		if syncErr != nil {
			e.logger.Warn("threat-intel: sync failed", "source", src.Name, "err", syncErr)
		} else {
			e.logger.Info("threat-intel: sync complete", "source", src.Name, "count", count)
		}
		e.db.SetThreatIntelSyncResult(ctx, src.Name, count, syncErr)
		if syncErr == nil && src.Name != "sigma" {
			e.retroHunt(ctx, src.Name, syncStart)
		}
	}
	// Clean expired IOCs
	e.db.DeleteExpiredIOCs(ctx)
	_ = e.db.PrunePrevalence(ctx, time.Now().AddDate(0, 0, -180))
	// F-16: location history is personal data; keep it for a bounded, configurable time.
	days := 90
	if v, _ := e.db.GetSetting(ctx, "location.retention_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 7 && n <= 3650 {
			days = n
		}
	}
	_ = e.db.PruneLocationHistory(ctx, time.Now().AddDate(0, 0, -days))
}

func (e *ThreatIntelEngine) SyncSource(ctx context.Context, name string, apiKey *string) {
	e.logger.Info("threat-intel: manual sync", "source", name)
	syncStart := time.Now().Add(-1 * time.Minute)
	var syncErr error
	var count int
	switch name {
	case "threatfox":
		count, syncErr = e.syncThreatFox(ctx, apiKey)
	case "otx":
		if apiKey == nil || *apiKey == "" {
			syncErr = fmt.Errorf("OTX API key not configured")
		} else {
			count, syncErr = e.syncOTX(ctx, *apiKey)
		}
	case "sigma":
		count, syncErr = e.syncSigma(ctx)
	default:
		return
	}
	if syncErr != nil {
		e.logger.Warn("threat-intel: sync failed", "source", name, "err", syncErr)
	} else {
		e.logger.Info("threat-intel: sync complete", "source", name, "count", count)
	}
	e.db.SetThreatIntelSyncResult(ctx, name, count, syncErr)
	if syncErr == nil && name != "sigma" {
		e.retroHunt(ctx, name, syncStart)
	}
}

func (e *ThreatIntelEngine) syncThreatFox(ctx context.Context, apiKey *string) (int, error) {
	// ThreatFox API — free API key required (get one at threatfox.abuse.ch)
	// Without a key you get HTTP 401
	if apiKey == nil || *apiKey == "" {
		return 0, fmt.Errorf("ThreatFox API key not configured — get a free key at threatfox.abuse.ch and add it in Intel Sources")
	}

	payload := map[string]interface{}{
		"query": "get_iocs",
		"days":  7,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://threatfox-api.abuse.ch/api/v1/", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", *apiKey)

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("ThreatFox request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return 0, fmt.Errorf("ThreatFox API key invalid or missing — check your key at threatfox.abuse.ch")
	}
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("ThreatFox HTTP %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return 0, fmt.Errorf("ThreatFox read body: %w", err)
	}

	var result struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			ID         string   `json:"id"`
			IOCValue   string   `json:"ioc"`
			IOCType    string   `json:"ioc_type"`
			ThreatType string   `json:"threat_type"`
			Malware    string   `json:"malware"`
			Confidence int      `json:"confidence_level"`
			Tags       []string `json:"tags"`
			ExpiresAt  string   `json:"expire_date"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		preview := string(respBody)
		if len(preview) > 300 {
			preview = preview[:300]
		}
		return 0, fmt.Errorf("ThreatFox decode failed: %w — response: %s", err, preview)
	}
	switch result.QueryStatus {
	case "ok":
		// good
	case "no_results":
		return 0, nil
	default:
		return 0, fmt.Errorf("ThreatFox query_status: %s", result.QueryStatus)
	}

	var iocs []store.IOCIndicator
	for _, d := range result.Data {
		iocType := normalizeTFType(d.IOCType)
		if iocType == "" {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(d.IOCValue))
		// Strip port from ip:port format
		if iocType == "ip" && strings.Contains(value, ":") {
			value = value[:strings.LastIndex(value, ":")]
		}
		if value == "" {
			continue
		}
		var expiresAt *time.Time
		if d.ExpiresAt != "" && d.ExpiresAt != "0000-00-00 00:00:00" {
			if t, err := time.Parse("2006-01-02 15:04:05", d.ExpiresAt); err == nil {
				expiresAt = &t
			}
		}
		iocs = append(iocs, store.IOCIndicator{
			Source:     "threatfox",
			IOCType:    iocType,
			Value:      value,
			Malware:    d.Malware,
			ThreatType: d.ThreatType,
			Confidence: d.Confidence,
			Severity:   confidenceToSeverity(d.Confidence),
			Tags:       strings.Join(d.Tags, ","),
			ExpiresAt:  expiresAt,
		})
	}

	return e.db.UpsertIOCs(ctx, iocs)
}

func normalizeTFType(t string) string {
	switch t {
	case "ip:port":
		return "ip"
	case "domain":
		return "domain"
	case "url":
		return "url"
	case "md5_hash", "sha1_hash", "sha256_hash":
		return "hash"
	default:
		return ""
	}
}

// ── OTX ──────────────────────────────────────────────────────────────────────

func (e *ThreatIntelEngine) syncOTX(ctx context.Context, apiKey string) (int, error) {
	syncSince := time.Now().AddDate(0, 0, -365)
	if lastSync, err2 := e.db.GetSetting(ctx, "ti.otx_last_sync"); err2 == nil && lastSync != "" {
		if t, err3 := time.Parse(time.RFC3339, lastSync); err3 == nil && time.Since(t) < 365*24*time.Hour {
			syncSince = t.Add(-1 * time.Hour)
		}
	}
	type otxResult struct {
		Next    *string `json:"next"`
		Results []struct {
			Name       string   `json:"name"`
			Tags       []string `json:"tags"`
			Indicators []struct {
				Type      string `json:"type"`
				Indicator string `json:"indicator"`
				Role      string `json:"role"`
			} `json:"indicators"`
		} `json:"results"`
	}
	var iocs []store.IOCIndicator
	nextURL := "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=100&modified_since=" +
		syncSince.Format(time.RFC3339)
	for page := 0; nextURL != "" && page < 50; page++ {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		req, err := http.NewRequestWithContext(ctx, "GET", nextURL, nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("X-OTX-API-KEY", apiKey)
		resp, err := e.client.Do(req)
		if err != nil {
			return 0, fmt.Errorf("OTX request (page %d): %w", page+1, err)
		}
		if resp.StatusCode == 403 {
			resp.Body.Close()
			return 0, fmt.Errorf("OTX invalid API key")
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return 0, fmt.Errorf("OTX status %d", resp.StatusCode)
		}
		var result otxResult
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return 0, fmt.Errorf("OTX decode (page %d): %w", page+1, err)
		}
		resp.Body.Close()
		for _, pulse := range result.Results {
			tags := strings.Join(pulse.Tags, ",")
			for _, ind := range pulse.Indicators {
				iocType := normalizeOTXType(ind.Type)
				if iocType == "" {
					continue
				}
				value := strings.ToLower(strings.TrimSpace(ind.Indicator))
				if value == "" {
					continue
				}
				iocs = append(iocs, store.IOCIndicator{
					Source: "otx", IOCType: iocType, Value: value,
					Malware: pulse.Name, ThreatType: ind.Role,
					Confidence: 70, Severity: 4, Tags: tags,
				})
			}
		}
		e.logger.Info("threat-intel: otx page fetched", "page", page+1,
			"pulses", len(result.Results), "iocs_so_far", len(iocs))
		if result.Next != nil && *result.Next != "" {
			nextURL = *result.Next
		} else {
			nextURL = ""
		}
	}
	count, err2 := e.db.UpsertIOCs(ctx, iocs)
	if err2 == nil && count > 0 {
		e.db.SetSetting(ctx, "ti.otx_last_sync", time.Now().Format(time.RFC3339))
	}
	return count, err2
}

func normalizeOTXType(t string) string {
	switch t {
	case "IPv4", "IPv6":
		return "ip"
	case "domain", "hostname":
		return "domain"
	case "URL":
		return "url"
	case "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256":
		return "hash"
	default:
		return ""
	}
}

// ── Sigma ─────────────────────────────────────────────────────────────────────

// D-13: the rule pack used to be pulled from GitHub's "releases/latest",
// with no version pin and no integrity check — a supply-chain risk, since
// whatever SigmaHQ (or anyone able to tamper with that endpoint) publishes
// next gets imported and matched against live security events sight
// unseen. syncSigma now requires an explicit pinned release tag and its
// expected SHA-256 (set via the ti.sigma_pinned_version /
// ti.sigma_pinned_sha256 settings, e.g. from the admin UI), and fails
// closed — importing nothing — if either is unset or the downloaded zip's
// hash doesn't match. Bumping the pin is a deliberate action: review the
// diff against the previous ruleset before updating these settings.
var (
	sigmaVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$`)
	sigmaSHARe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// The hash of the last sigma_core.zip that failed verification, so an admin
// can confirm it (by its first 8 characters, as shown on the GitHub release
// page) and pin it without retyping 64 characters.
var (
	sigmaSeenMu  sync.Mutex
	sigmaSeenVer string
	sigmaSeenSHA string
)

func recordSigmaSeen(version, sha string) {
	sigmaSeenMu.Lock()
	sigmaSeenVer, sigmaSeenSHA = version, sha
	sigmaSeenMu.Unlock()
}

func (e *ThreatIntelEngine) syncSigma(ctx context.Context) (int, error) {
	version, _ := e.db.GetSetting(ctx, "ti.sigma_pinned_version")
	expectedSHA, _ := e.db.GetSetting(ctx, "ti.sigma_pinned_sha256")
	version = strings.TrimSpace(version)
	expectedSHA = strings.ToLower(strings.TrimSpace(expectedSHA))
	if version == "" || expectedSHA == "" {
		return 0, fmt.Errorf("Sigma rule pack not configured: in Settings, set the Sigma release tag (a specific SigmaHQ release, never \"latest\") and its sigma_core.zip SHA-256. Tip: enter the tag and any 64-character hash, sync once, and the error will show the real hash to compare with the release page")
	}

	zipURL := fmt.Sprintf("https://github.com/SigmaHQ/sigma/releases/download/%s/sigma_core.zip", url.PathEscape(version))
	req, err := http.NewRequestWithContext(ctx, "GET", zipURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "tls:") {
			return 0, fmt.Errorf("Sigma download failed TLS verification (%w). The management server cannot validate github.com's certificate: check the server clock, install/update its CA certificates (ca-certificates), and check for a TLS-inspecting proxy that needs its CA added", err)
		}
		return 0, fmt.Errorf("Sigma download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("Sigma download status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024)) // 50MB limit
	if err != nil {
		return 0, fmt.Errorf("Sigma read: %w", err)
	}

	sum := sha256.Sum256(data)
	gotSHA := hex.EncodeToString(sum[:])
	if gotSHA != expectedSHA {
		recordSigmaSeen(version, gotSHA)
		return 0, fmt.Errorf("Sigma integrity check failed: downloaded %s but pinned ti.sigma_pinned_sha256 is %s — refusing to import unverified rules", gotSHA, expectedSHA)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0, fmt.Errorf("Sigma zip: %w", err)
	}

	// Clear old sigma rules before re-importing
	e.db.DeleteSigmaRulesBySource(ctx, "sigma")

	count := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || filepath.Ext(f.Name) != ".yml" {
			continue
		}
		// Only import relevant rule categories
		if !sigmaFileRelevant(f.Name) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(rc, 512*1024))
		rc.Close()
		if err != nil {
			continue
		}

		rule, err := parseSigmaRule(content)
		if err != nil || rule == nil {
			continue
		}

		if err := e.db.UpsertSigmaRule(ctx, *rule); err != nil {
			continue
		}
		count++
	}
	return count, nil
}

// sigmaFileRelevant returns true for rule categories we can match against our events.
func sigmaFileRelevant(path string) bool {
	path = strings.ToLower(path)
	relevant := []string{
		"windows/", "linux/", "macos/",
		"process_creation", "file_event", "file_change",
		"network_connection", "dns_query",
		"registry_event", "registry_set",
		"sysmon/", "builtin/",
	}
	for _, r := range relevant {
		if strings.Contains(path, r) {
			return true
		}
	}
	return false
}

// parseSigmaRule parses a Sigma YAML rule into our internal format.
// We do lightweight YAML parsing without a full YAML library to avoid dependencies.
func parseSigmaRule(data []byte) (*store.SigmaRule, error) {
	lines := strings.Split(string(data), "\n")
	rule := &store.SigmaRule{
		Enabled: true,
		Source:  "sigma",
	}

	var inDetection bool
	var detectionLines []string
	var inLogSource bool
	var logSourceLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if inDetection {
				detectionLines = append(detectionLines, line)
			}
			continue
		}

		// Top-level keys
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inDetection = false
			inLogSource = false
		}

		key, val, _ := strings.Cut(trimmed, ":")
		val = strings.TrimSpace(val)

		switch key {
		case "id":
			rule.ID = val
		case "title":
			rule.Title = val
		case "description":
			rule.Description = val
		case "status":
			rule.Status = val
		case "level":
			rule.Level = val
			rule.Severity = sigmaLevelToSeverity(val)
		case "detection":
			inDetection = true
			inLogSource = false
		case "logsource":
			inLogSource = true
			inDetection = false
		case "tags":
			// parse ATT&CK tags
		}

		if inDetection {
			detectionLines = append(detectionLines, line)
		}
		if inLogSource {
			logSourceLines = append(logSourceLines, line)
		}

		// Extract MITRE tags
		if strings.Contains(trimmed, "attack.t") {
			parts := strings.Fields(trimmed)
			for _, p := range parts {
				p = strings.Trim(p, "- '\"")
				if strings.HasPrefix(strings.ToLower(p), "attack.t") {
					tid := strings.TrimPrefix(strings.ToLower(p), "attack.")
					if rule.MITRE != "" {
						rule.MITRE += ","
					}
					rule.MITRE += strings.ToUpper(tid)
				}
			}
		}

		// Category from logsource
		if inLogSource {
			if strings.HasPrefix(trimmed, "category:") {
				rule.Category = strings.TrimSpace(strings.TrimPrefix(trimmed, "category:"))
			} else if strings.HasPrefix(trimmed, "product:") {
				if rule.Category == "" {
					rule.Category = strings.TrimSpace(strings.TrimPrefix(trimmed, "product:"))
				}
			}
		}
	}

	if rule.ID == "" || rule.Title == "" {
		return nil, fmt.Errorf("missing id or title")
	}

	rule.Detection = strings.Join(detectionLines, "\n")
	rule.LogSource = strings.Join(logSourceLines, "\n")

	// Skip experimental rules with no detection
	if rule.Detection == "" {
		return nil, fmt.Errorf("no detection block")
	}

	return rule, nil
}

func sigmaLevelToSeverity(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func confidenceToSeverity(confidence int) int {
	switch {
	case confidence >= 90:
		return 5
	case confidence >= 70:
		return 4
	case confidence >= 50:
		return 3
	case confidence >= 30:
		return 2
	default:
		return 1
	}
}
