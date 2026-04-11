package api

// nvd.go — NVD (National Vulnerability Database) CVE lookup
//
// Uses NVD API v2: https://nvd.nist.gov/developers/vulnerabilities
//
// Rate limits:
//   - Without API key: 5 requests / 30 seconds
//   - With API key:   50 requests / 30 seconds (get one free at nvd.nist.gov)
//
// Strategy:
//   1. For each installed package, build a CPE-style keyword query
//   2. Query NVD for CVEs matching that package + version
//   3. Return only CVEs with CVSS score >= 4.0 (medium+)
//   4. Cache results in memory for 24h to avoid re-querying

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── NVD response types ────────────────────────────────────────────────────────

type nvdResponse struct {
	ResultsPerPage int              `json:"resultsPerPage"`
	TotalResults   int              `json:"totalResults"`
	Vulnerabilities []nvdVulnItem  `json:"vulnerabilities"`
}

type nvdVulnItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
	Published    string           `json:"published"`
	LastModified string           `json:"lastModified"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
	Severity string      `json:"baseSeverity"`
}

type nvdCVSSData struct {
	BaseScore float64 `json:"baseScore"`
	VectorString string `json:"vectorString"`
}

// ── Result type ───────────────────────────────────────────────────────────────

type CVEFinding struct {
	PackageName    string  `json:"name"`
	InstalledVersion string `json:"installed_version"`
	CVEID          string  `json:"cve_id"`
	CVSSScore      float64 `json:"cvss_score"`
	Severity       string  `json:"severity"`
	Description    string  `json:"description"`
	Published      string  `json:"published"`
	URL            string  `json:"url"`
}

// ── In-memory cache ───────────────────────────────────────────────────────────

type cveCache struct {
	mu      sync.RWMutex
	entries map[string]cveCacheEntry
}

type cveCacheEntry struct {
	findings []CVEFinding
	at       time.Time
}

var globalCVECache = &cveCache{entries: map[string]cveCacheEntry{}}

func (c *cveCache) get(key string) ([]CVEFinding, bool) {
	c.mu.RLock(); defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok || time.Since(e.at) > 24*time.Hour { return nil, false }
	return e.findings, true
}

func (c *cveCache) set(key string, findings []CVEFinding) {
	c.mu.Lock(); defer c.mu.Unlock()
	c.entries[key] = cveCacheEntry{findings: findings, at: time.Now()}
}

// ── NVD client ────────────────────────────────────────────────────────────────

type NVDClient struct {
	apiKey  string
	logger  *slog.Logger
	limiter chan struct{} // rate limiter
}

func NewNVDClient(apiKey string, logger *slog.Logger) *NVDClient {
	// Conservative rate: 1 request per second regardless of key
	// This means 3000 packages takes ~50min — too slow for live requests
	// So we batch: query by package name only (not version), cache 24h
	limiter := make(chan struct{}, 1)
	go func() {
		ticker := time.NewTicker(350 * time.Millisecond) // ~2.8 req/s (safe with API key)
		defer ticker.Stop()
		for range ticker.C {
			select { case limiter <- struct{}{}: default: }
		}
	}()
	return &NVDClient{apiKey: apiKey, logger: logger, limiter: limiter}
}

func (c *NVDClient) query(ctx context.Context, keyword string, maxResults int) ([]nvdVulnItem, error) {
	// Rate limit
	select {
	case <-ctx.Done(): return nil, ctx.Err()
	case <-c.limiter:
	}

	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", fmt.Sprintf("%d", maxResults))
	params.Set("cvssV3Severity", "MEDIUM") // only medium+ by default

	reqURL := "https://services.nvd.nist.gov/rest/json/cves/2.0?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil { return nil, err }
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}
	req.Header.Set("User-Agent", "ObsidianWatch-SIEM/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("NVD rate limit hit — add an API key in Settings")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API error: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil { return nil, err }

	var result nvdResponse
	if err := json.Unmarshal(body, &result); err != nil { return nil, err }
	return result.Vulnerabilities, nil
}

// ── Package → CVE lookup ──────────────────────────────────────────────────────

// LookupPackage finds CVEs for a specific package name + version.
// Returns only CVEs with CVSS >= minScore.
func (c *NVDClient) LookupPackage(ctx context.Context, name, version string, minScore float64) ([]CVEFinding, error) {
	// Normalise name — strip debian epoch, build metadata
	cleanName    := normalisePackageName(name)
	cleanVersion := normaliseVersion(version)

	// Cache key = name:version
	cacheKey := cleanName + ":" + cleanVersion
	if cached, ok := globalCVECache.get(cacheKey); ok {
		return cached, nil
	}

	// Query NVD — keyword = "name version"
	// NVD full-text search is good enough for most cases
	keyword := cleanName
	if cleanVersion != "" {
		keyword = cleanName + " " + cleanVersion
	}

	vulns, err := c.query(ctx, keyword, 10)
	if err != nil {
		return nil, err
	}

	var findings []CVEFinding
	for _, item := range vulns {
		cve := item.CVE
		score, severity := extractCVSS(cve.Metrics)
		if score < minScore { continue }

		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" { desc = d.Value; break }
		}
		// Truncate description
		if len(desc) > 200 { desc = desc[:200] + "…" }

		findings = append(findings, CVEFinding{
			PackageName:      name,
			InstalledVersion: version,
			CVEID:            cve.ID,
			CVSSScore:        score,
			Severity:         severity,
			Description:      desc,
			Published:        cve.Published[:10], // just date
			URL:              "https://nvd.nist.gov/vuln/detail/" + cve.ID,
		})
	}

	// Sort by CVSS score descending
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].CVSSScore > findings[j].CVSSScore
	})

	globalCVECache.set(cacheKey, findings)
	return findings, nil
}

// LookupPackages runs NVD lookups for a batch of packages concurrently.
// Uses a worker pool to respect rate limits.
// Only queries packages that are commonly vulnerable (not system libs).
func (c *NVDClient) LookupPackages(ctx context.Context, packages []map[string]interface{}, minScore float64) ([]CVEFinding, error) {
	// Filter to packages worth querying — saves significant API calls
	interesting := filterNVDPackages(packages)

	if len(interesting) == 0 {
		return nil, nil
	}

	c.logger.Info("nvd: looking up CVEs", "packages", len(interesting), "total", len(packages))

	// Worker pool — 3 concurrent workers to stay within rate limits
	type workItem struct {
		name, version string
	}
	jobs := make(chan workItem, len(interesting))
	for _, pkg := range interesting {
		name, _    := pkg["name"].(string)
		version, _ := pkg["version"].(string)
		if name != "" {
			jobs <- workItem{name, version}
		}
	}
	close(jobs)

	var (
		mu       sync.Mutex
		findings []CVEFinding
		wg       sync.WaitGroup
	)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select { case <-ctx.Done(): return; default: }
				f, err := c.LookupPackage(ctx, job.name, job.version, minScore)
				if err != nil {
					c.logger.Debug("nvd: lookup failed", "pkg", job.name, "err", err)
					continue
				}
				if len(f) > 0 {
					mu.Lock()
					findings = append(findings, f...)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	// Sort final results by CVSS score
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].CVSSScore > findings[j].CVSSScore
	})

	c.logger.Info("nvd: lookup complete", "cves_found", len(findings))
	return findings, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// filterNVDPackages keeps packages that are likely to have CVEs.
// Skips pure system libraries, fonts, locales etc.
// This reduces API calls from 3000 to ~200-400 for a typical Linux system.
func filterNVDPackages(packages []map[string]interface{}) []map[string]interface{} {
	// Packages worth checking — user-facing software, servers, runtimes, tools
	worthChecking := []string{
		"openssl", "openssh", "nginx", "apache", "apache2", "httpd",
		"mysql", "mariadb", "postgresql", "mongodb", "redis", "memcached",
		"php", "python", "python3", "ruby", "perl", "node", "nodejs",
		"golang", "go", "java", "openjdk", "jdk", "jre",
		"bash", "sh", "zsh", "curl", "wget", "git", "sudo",
		"docker", "containerd", "kubernetes", "kubectl",
		"samba", "vsftpd", "proftpd", "bind", "bind9", "named",
		"postfix", "exim", "sendmail", "dovecot",
		"elasticsearch", "logstash", "kibana",
		"wordpress", "drupal", "joomla",
		"kernel", "linux", "glibc",
		"openssh-server", "openssh-client",
		"ssl", "tls", "libssl", "openldap",
		"vim", "nano", "emacs", "tmux", "screen",
		"rsync", "ssh", "scp", "sftp",
		"pip", "npm", "gem", "composer",
		"tomcat", "jetty", "spring",
		"log4j", "log4shell", "struts",
		"influxdb", "grafana", "prometheus",
		"jenkins", "gitlab", "github",
		"ansible", "puppet", "chef", "terraform",
		"vault", "consul", "nomad",
	}

	skipPrefixes := []string{
		"fonts-", "font-", "xfonts-", "ttf-",
		"language-", "locale-",
		"linux-image-", "linux-headers-", "linux-modules-",
		"initramfs-", "grub-", "plymouth-",
		"gir1.2-", "typelib-",
		"python3-doc", "python-doc",
	}

	var out []map[string]interface{}
	seen := map[string]bool{}

	for _, pkg := range packages {
		name, _ := pkg["name"].(string)
		if name == "" || seen[name] { continue }
		lname := strings.ToLower(name)

		// Skip known-boring prefixes
		skip := false
		for _, prefix := range skipPrefixes {
			if strings.HasPrefix(lname, prefix) { skip = true; break }
		}
		if skip { continue }

		// Check if it's in our interesting list or contains an interesting keyword
		interesting := false
		for _, kw := range worthChecking {
			if strings.Contains(lname, kw) { interesting = true; break }
		}

		// Also check if it looks like an application (no "lib" prefix for most)
		// but allow known lib packages like libssl, libcurl etc
		if !interesting {
			if strings.HasPrefix(lname, "lib") {
				importantLibs := []string{"libssl", "libcurl", "libssh", "libgnutls", "libexpat", "libxml", "libpng", "libjpeg", "libpq", "libmysql"}
				for _, il := range importantLibs {
					if strings.Contains(lname, il) { interesting = true; break }
				}
			} else {
				// Non-lib package — include it (developer tool, server, runtime, etc)
				interesting = true
			}
		}

		if interesting {
			out = append(out, pkg)
			seen[name] = true
		}
	}

	return out
}

func normalisePackageName(name string) string {
	// Remove version suffixes like "python3.11" → "python3"
	// Remove arch suffixes like "package:amd64" → "package"
	name = strings.Split(name, ":")[0]
	// Remove common debian epoch patterns
	name = strings.TrimSpace(name)
	return strings.ToLower(name)
}

func normaliseVersion(version string) string {
	// Strip debian epoch "1:" prefix
	if idx := strings.Index(version, ":"); idx >= 0 {
		version = version[idx+1:]
	}
	// Take only the version number part (before first -)
	parts := strings.SplitN(version, "-", 2)
	return strings.TrimSpace(parts[0])
}

func extractCVSS(metrics nvdMetrics) (float64, string) {
	// Prefer CVSSv3.1, then v3.0, then v2
	if len(metrics.CVSSV31) > 0 {
		m := metrics.CVSSV31[0]
		return m.CVSSData.BaseScore, cvssScoreToSeverity(m.CVSSData.BaseScore)
	}
	if len(metrics.CVSSV30) > 0 {
		m := metrics.CVSSV30[0]
		return m.CVSSData.BaseScore, cvssScoreToSeverity(m.CVSSData.BaseScore)
	}
	if len(metrics.CVSSV2) > 0 {
		m := metrics.CVSSV2[0]
		return m.CVSSData.BaseScore, cvssScoreToSeverity(m.CVSSData.BaseScore)
	}
	return 0, "Unknown"
}

func cvssScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0: return "Critical"
	case score >= 7.0: return "High"
	case score >= 4.0: return "Medium"
	case score > 0:    return "Low"
	default:           return "None"
	}
}
