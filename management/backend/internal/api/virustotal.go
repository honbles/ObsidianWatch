package api

// virustotal.go — Tiered hash reputation engine
//
// Pipeline (cheapest/fastest first, escalates only when needed):
//
//  Tier 0 — Team Cymru MHR (Malware Hash Registry)
//           DNS-based lookup, no API key, ~50ms per hash, very high throughput
//           Returns last_seen date + AV detection % for known malware
//
//  Tier 1 — MalwareBazaar (abuse.ch)
//           Free, no API key required, 100% confidence hits
//
//  Tier 2 — CIRCL HASHLOOKUP
//           Free, no API key, 100M+ known-good (NSRL) + malware hashes
//           Filters known-good system files — stops wasting paid API calls
//
//  Tier 3 — Hybrid Analysis (CrowdStrike Falcon Sandbox)
//           Free tier: 200 req/min, requires free API key
//
//  Tier 4 — VirusTotal (optional, paid enterprise tier)
//           Only queried if all above inconclusive AND VT key configured
//           Free tier: 4 req/min (queue + rate limit applies)
//           Enterprise: 20,000 req/min

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type VirusTotalEngine struct {
	db     *store.DB
	logger *slog.Logger
	client *http.Client
}

func NewVirusTotalEngine(db *store.DB, logger *slog.Logger) *VirusTotalEngine {
	return &VirusTotalEngine{
		db:     db,
		logger: logger,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (e *VirusTotalEngine) Run(ctx context.Context) {
	// Ingest ticker — check for new file hashes every 30 seconds
	ingestTicker := time.NewTicker(30 * time.Second)
	defer ingestTicker.Stop()

	// Run immediately on start
	e.ingestNewHashes(ctx)
	e.processQueue(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ingestTicker.C:
			e.ingestNewHashes(ctx)
			e.processQueue(ctx)
		}
	}
}

func (e *VirusTotalEngine) ingestNewHashes(ctx context.Context) {
	rows, err := e.db.QueryContext(ctx, `
		SELECT DISTINCT
			file_hash as hash,
			COALESCE(process_name, '') as file_name,
			host
		FROM events
		WHERE file_hash IS NOT NULL
		  AND file_hash != ''
		  AND time > NOW() - INTERVAL '24 hours'
		  AND (
		    file_path ILIKE '%\downloads\%' OR file_path ILIKE '%/downloads/%'
		    OR file_path ILIKE '%/tmp/%' OR file_path ILIKE '%\temp\%'
		    OR file_path ILIKE '%\windows\temp\%' OR file_path ILIKE '%/var/tmp/%'
		    OR file_path ILIKE '%/dev/shm/%' OR file_path ILIKE '%content.outlook%'
		    OR file_path ILIKE '%\appdata\local\temp\%'
		    OR (file_path ILIKE '%.exe' AND file_path NOT ILIKE '%\windows\system32\%' AND file_path NOT ILIKE '%\program files%')
		    OR file_path ILIKE '%.dll' OR file_path ILIKE '%.ps1' OR file_path ILIKE '%.sh'
		    OR process_name ILIKE '%wget%' OR process_name ILIKE '%curl%'
		    OR process_name ILIKE '%powershell%' OR process_name ILIKE '%python%'
		  )
		ORDER BY hash LIMIT 500
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	inserted, maliciousHits := 0, 0
	for rows.Next() {
		var hash, fileName, host string
		if err := rows.Scan(&hash, &fileName, &host); err != nil {
			continue
		}
		hash = normalizeHash(hash)
		if hash == "" || len(hash) < 8 {
			continue
		}
		var existingVerdict, existingFamily string
		var existingScore, existingTotal int
		e.db.QueryRowContext(ctx,
			`SELECT vt_verdict, COALESCE(vt_score,0), COALESCE(vt_total,0), COALESCE(vt_family,'')
			 FROM file_hash_cache WHERE hash = $1`, hash,
		).Scan(&existingVerdict, &existingScore, &existingTotal, &existingFamily)

		if existingVerdict == "malicious" {
			e.createHashAlert(ctx, hash, fileName, host, &hashResult{
				malicious: existingScore, total: existingTotal,
				verdict: "malicious", family: existingFamily,
				source: sourceFromFamily(existingFamily),
			})
			maliciousHits++
			e.db.ExecContext(ctx,
				`UPDATE file_hash_cache SET last_seen=NOW(), event_count=event_count+1 WHERE hash=$1`, hash)
			continue
		}
		if existingVerdict == "clean" {
			continue
		}
		if _, err := e.db.ExecContext(ctx, `
			INSERT INTO file_hash_cache (hash, file_name, vt_verdict, first_seen, last_seen, last_host)
			VALUES ($1, $2, 'queued', NOW(), NOW(), $3)
			ON CONFLICT (hash) DO UPDATE SET
				last_seen=NOW(), event_count=file_hash_cache.event_count+1,
				last_host=$3,
				file_name=CASE WHEN $2 != '' THEN $2 ELSE file_hash_cache.file_name END
		`, hash, fileName, host); err == nil {
			inserted++
		}
	}
	if inserted > 0 {
		e.logger.Info("hash-intel: new hashes queued", "count", inserted)
	}
	if maliciousHits > 0 {
		e.logger.Warn("hash-intel: known malicious hashes re-detected", "count", maliciousHits)
	}
}

func (e *VirusTotalEngine) processQueue(ctx context.Context) {
	rows, err := e.db.QueryContext(ctx, `
		SELECT hash, file_name, COALESCE(last_host,'') FROM file_hash_cache
		WHERE vt_verdict = 'queued' ORDER BY last_seen DESC LIMIT 50
	`)
	if err != nil {
		return
	}
	type hashRow struct{ hash, name, host string }
	var queue []hashRow
	for rows.Next() {
		var h hashRow
		rows.Scan(&h.hash, &h.name, &h.host)
		queue = append(queue, h)
	}
	rows.Close()
	if len(queue) == 0 {
		return
	}
	e.logger.Info("hash-intel: processing queue", "count", len(queue))

	vtAPIKey, _ := e.db.GetSetting(ctx, "ti.virustotal_api_key")
	haAPIKey, _ := e.db.GetSetting(ctx, "ti.hybrid_analysis_api_key")
	checked, malicious := 0, 0

	for _, item := range queue {
		select {
		case <-ctx.Done():
			return
		default:
		}
		e.logger.Info("hash-intel: checking hash", "hash", item.hash[:16]+"...", "file", item.name)
		result := e.tieredLookup(ctx, item.hash, haAPIKey, vtAPIKey)
		e.logger.Info("hash-intel: result",
			"hash", item.hash[:16]+"...", "verdict", result.verdict,
			"score", fmt.Sprintf("%d/%d", result.malicious, result.total),
			"source", result.source, "family", result.family,
		)
		family := result.family
		if result.source != "" && !strings.HasPrefix(family, result.source+":") {
			family = result.source + ":" + family
		}
		e.db.ExecContext(ctx, `
			UPDATE file_hash_cache SET
				vt_score=$1, vt_total=$2, vt_verdict=$3, vt_family=$4, vt_checked_at=NOW()
			WHERE hash=$5
		`, result.malicious, result.total, result.verdict, family, item.hash)
		checked++
		if result.verdict == "malicious" {
			malicious++
			e.createHashAlert(ctx, item.hash, item.name, item.host, result)
		}
		if result.source == "virustotal" {
			vtPlan, _ := e.db.GetSetting(ctx, "ti.virustotal_plan")
			time.Sleep(vtRateLimit(vtPlan))
		}
	}
	if checked > 0 {
		e.logger.Info("hash-intel: batch complete", "checked", checked, "malicious", malicious)
	}
}

// ── Tiered lookup ─────────────────────────────────────────────────────────────

func (e *VirusTotalEngine) tieredLookup(ctx context.Context, hash, haKey, vtKey string) *hashResult {
	// Tier 0: Team Cymru MHR — DNS, no key, ~50ms
	if r := e.checkMHR(ctx, hash); r != nil && r.verdict != "undetected" {
		e.logger.Info("hash-intel: mhr hit", "hash", hash[:16])
		return r
	}
	// Tier 1: MalwareBazaar — free, high confidence
	if r, err := e.checkMalwareBazaar(ctx, hash); err == nil && r != nil {
		e.logger.Info("hash-intel: malwarebazaar hit", "hash", hash[:16])
		return r
	}
	// Tier 2: CIRCL HASHLOOKUP — free, known-good filter
	if r, err := e.checkCIRCL(ctx, hash); err == nil && r != nil {
		e.logger.Info("hash-intel: circl hit", "hash", hash[:16])
		return r
	}
	// Tier 3: Hybrid Analysis — free tier, needs API key
	if haKey != "" {
		if r, err := e.checkHybridAnalysis(ctx, hash, haKey); err == nil && r != nil {
			e.logger.Info("hash-intel: hybrid-analysis hit", "hash", hash[:16])
			return r
		}
	}
	// Tier 4: VirusTotal — optional paid
	if vtKey != "" {
		if r, err := e.checkVirusTotal(ctx, hash, vtKey); err == nil && r != nil {
			e.logger.Info("hash-intel: virustotal hit", "hash", hash[:16])
			return r
		}
	}
	return &hashResult{verdict: "undetected", source: "all-tiers"}
}

// ── Tier 0: Team Cymru MHR ────────────────────────────────────────────────────

func (e *VirusTotalEngine) checkMHR(ctx context.Context, hash string) *hashResult {
	if len(hash) != 32 && len(hash) != 40 && len(hash) != 64 {
		return nil
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
	txtRecords, err := resolver.LookupTXT(ctx, hash+".malware.hash.cymru.com")
	if err != nil || len(txtRecords) == 0 {
		return &hashResult{verdict: "undetected", source: "mhr"}
	}
	for _, txt := range txtRecords {
		parts := strings.Fields(txt)
		if len(parts) < 2 {
			continue
		}
		var pct int
		fmt.Sscanf(parts[1], "%d", &pct)
		if pct > 0 {
			verdict := "suspicious"
			if pct >= 50 {
				verdict = "malicious"
			}
			return &hashResult{
				malicious: pct, total: 100, verdict: verdict,
				family: fmt.Sprintf("%d%% AV detection", pct), source: "mhr",
			}
		}
	}
	return &hashResult{verdict: "undetected", source: "mhr"}
}

// ── Tier 1: MalwareBazaar ─────────────────────────────────────────────────────

func (e *VirusTotalEngine) checkMalwareBazaar(ctx context.Context, hash string) (*hashResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://mb-api.abuse.ch/api/v1/",
		strings.NewReader("query=get_info&hash="+hash))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var data struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			Signature *string  `json:"signature"`
			Tags      []string `json:"tags"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	if data.QueryStatus != "ok" || len(data.Data) == 0 {
		return nil, nil
	}
	family := ""
	if data.Data[0].Signature != nil {
		family = *data.Data[0].Signature
	}
	if family == "" && len(data.Data[0].Tags) > 0 {
		family = strings.Join(data.Data[0].Tags, ",")
	}
	return &hashResult{malicious: 100, total: 100, verdict: "malicious", family: family, source: "malwarebazaar"}, nil
}

// ── Tier 2: CIRCL HASHLOOKUP ──────────────────────────────────────────────────

func (e *VirusTotalEngine) checkCIRCL(ctx context.Context, hash string) (*hashResult, error) {
	hashType := map[int]string{32: "md5", 40: "sha1", 64: "sha256"}[len(hash)]
	if hashType == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://hashlookup.circl.lu/lookup/%s/%s", hashType, hash), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CIRCL status %d", resp.StatusCode)
	}
	var data struct {
		KnownMalicious *string `json:"KnownMalicious"`
		ProductName    *string `json:"ProductName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	if data.KnownMalicious != nil && *data.KnownMalicious != "" {
		return &hashResult{malicious: 100, total: 100, verdict: "malicious", family: *data.KnownMalicious, source: "circl"}, nil
	}
	if data.ProductName != nil && *data.ProductName != "" {
		return &hashResult{verdict: "clean", family: *data.ProductName, source: "circl"}, nil
	}
	return nil, nil
}

// ── Tier 3: Hybrid Analysis ───────────────────────────────────────────────────

func (e *VirusTotalEngine) checkHybridAnalysis(ctx context.Context, hash, apiKey string) (*hashResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://www.hybrid-analysis.com/api/v2/search/hash",
		strings.NewReader("hash="+hash))
	if err != nil {
		return nil, err
	}
	req.Header.Set("api-key", apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "ObsidianWatch-SIEM/1.0")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 || resp.StatusCode == 204 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("hybrid-analysis status %d", resp.StatusCode)
	}
	var results []struct {
		Verdict       string   `json:"verdict"`
		ThreatScore   *int     `json:"threat_score"`
		MalwareFamily *string  `json:"vx_family"`
		Tags          []string `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, nil
	}
	r := results[0]
	score := 0
	if r.ThreatScore != nil {
		score = *r.ThreatScore
	}
	verdict := "undetected"
	switch strings.ToLower(r.Verdict) {
	case "malicious":
		verdict = "malicious"
	case "suspicious":
		verdict = "suspicious"
	case "no specific threat", "whitelisted":
		verdict = "clean"
	}
	family := ""
	if r.MalwareFamily != nil {
		family = *r.MalwareFamily
	}
	if family == "" && len(r.Tags) > 0 {
		family = strings.Join(r.Tags, ",")
	}
	return &hashResult{malicious: score, total: 100, verdict: verdict, family: family, source: "hybrid-analysis"}, nil
}

// ── Tier 4: VirusTotal ────────────────────────────────────────────────────────

func (e *VirusTotalEngine) checkVirusTotal(ctx context.Context, hash, apiKey string) (*hashResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", apiKey)
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return &hashResult{verdict: "undetected", source: "virustotal"}, nil
	}
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limited (429)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VT status %d", resp.StatusCode)
	}
	var data struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
				PopularThreatClassification struct {
					SuggestedThreatLabel string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	stats := data.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless
	verdict := "clean"
	if stats.Malicious >= 5 {
		verdict = "malicious"
	} else if stats.Malicious >= 2 || stats.Suspicious >= 5 {
		verdict = "suspicious"
	} else if total == 0 {
		verdict = "undetected"
	}
	return &hashResult{
		malicious: stats.Malicious, total: total, verdict: verdict,
		family: data.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel,
		source: "virustotal",
	}, nil
}

// ── Shared types & helpers ────────────────────────────────────────────────────

type hashResult struct {
	malicious int
	total     int
	verdict   string
	family    string
	source    string
}

// vtResult kept as alias — existing code referencing vtResult still compiles
type vtResult = hashResult

func (e *VirusTotalEngine) createHashAlert(ctx context.Context, hash, fileName, host string, result *hashResult) {
	label := strings.ToUpper(result.source)
	if label == "" {
		label = "HASH-INTEL"
	}
	title := fmt.Sprintf("[%s] Malicious File Hash — %s", label, fileName)
	if fileName == "" {
		title = fmt.Sprintf("[%s] Malicious File Hash — %s...", label, hash[:16])
	}
	// Dedup per host per hash per day — same file on same host today = one alert
	// But different day = new alert (re-infection or new download)
	dayKey := fmt.Sprintf("vt:hash:%s:%s:%s", host, hash, time.Now().UTC().Format("2006-01-02"))
	e.db.CreateAlertDeduped(ctx, store.Alert{
		Title: title,
		Description: fmt.Sprintf("%s: %d/%d detections.\nHost: %s\nHash: %s\nFamily: %s",
			label, result.malicious, result.total, host, hash, result.family),
		Severity:  5,
		Host:      host,
		EventType: "file",
		EventID:   dayKey,
	})
	e.logger.Warn("hash-intel: malicious hash detected",
		"hash", hash[:16], "file", fileName,
		"score", fmt.Sprintf("%d/%d", result.malicious, result.total),
		"source", result.source, "family", result.family,
	)
}

func vtRateLimit(plan string) time.Duration {
	switch plan {
	case "standard":
		return 120 * time.Millisecond
	case "premium", "enterprise":
		return 60 * time.Millisecond
	default:
		return 15 * time.Second
	}
}

func sourceFromFamily(family string) string {
	if idx := strings.Index(family, ":"); idx > 0 {
		return family[:idx]
	}
	return "hash-intel"
}

func normalizeHash(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))

	// Sysmon format: MD5=ABC,SHA256=DEF,SHA1=GHI (comma-separated key=value)
	if strings.Contains(raw, "=") {
		// Prefer SHA256, then SHA1, then MD5
		for _, prefix := range []string{"sha256=", "sha1=", "md5="} {
			for _, part := range strings.Split(raw, ",") {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, prefix) {
					h := strings.TrimPrefix(part, prefix)
					if len(h) == 64 || len(h) == 40 || len(h) == 32 {
						return h
					}
				}
			}
		}
	}

	// colon-separated format: sha256:ABC or md5:ABC
	if strings.Contains(raw, ":") {
		if parts := strings.SplitN(raw, ":", 2); len(parts) == 2 {
			h := strings.TrimSpace(parts[1])
			if len(h) == 64 || len(h) == 40 || len(h) == 32 {
				return h
			}
		}
	}

	// Raw hash
	if len(raw) == 64 || len(raw) == 32 || len(raw) == 40 {
		return raw
	}
	return ""
}

func handleListFileHashes(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		verdict := r.URL.Query().Get("verdict")
		query := `SELECT hash, hash_type, file_name, vt_score, vt_total, vt_verdict,
				         vt_family, vt_checked_at, first_seen, last_seen, event_count
				  FROM file_hash_cache`
		args := []interface{}{}
		if verdict != "" {
			query += " WHERE vt_verdict = $1"
			args = append(args, verdict)
		}
		query += " ORDER BY last_seen DESC LIMIT $" + fmt.Sprintf("%d", len(args)+1)
		args = append(args, 100)
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()
		type hashRow struct {
			Hash        string     `json:"hash"`
			HashType    string     `json:"hash_type"`
			FileName    string     `json:"file_name"`
			VTScore     *int       `json:"vt_score"`
			VTTotal     *int       `json:"vt_total"`
			VTVerdict   string     `json:"vt_verdict"`
			VTFamily    string     `json:"vt_family"`
			VTCheckedAt *time.Time `json:"vt_checked_at"`
			FirstSeen   time.Time  `json:"first_seen"`
			LastSeen    time.Time  `json:"last_seen"`
			EventCount  int        `json:"event_count"`
		}
		var hashes []hashRow
		for rows.Next() {
			var h hashRow
			if err := rows.Scan(&h.Hash, &h.HashType, &h.FileName,
				&h.VTScore, &h.VTTotal, &h.VTVerdict, &h.VTFamily,
				&h.VTCheckedAt, &h.FirstSeen, &h.LastSeen, &h.EventCount); err != nil {
				continue
			}
			hashes = append(hashes, h)
		}
		if hashes == nil {
			hashes = []hashRow{}
		}
		var total, malicious, suspicious, queued, clean int
		db.QueryRowContext(ctx, `SELECT COUNT(*),
			COUNT(*) FILTER (WHERE vt_verdict='malicious'),
			COUNT(*) FILTER (WHERE vt_verdict='suspicious'),
			COUNT(*) FILTER (WHERE vt_verdict='queued'),
			COUNT(*) FILTER (WHERE vt_verdict='clean')
			FROM file_hash_cache`).Scan(&total, &malicious, &suspicious, &queued, &clean)
		writeJSON(w, 200, map[string]interface{}{
			"hashes": hashes, "total": total, "malicious": malicious,
			"suspicious": suspicious, "queued": queued, "clean": clean,
		})
	}
}

func handleGetFileHash(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hash := r.PathValue("hash")
		var h struct {
			Hash        string     `json:"hash"`
			FileName    string     `json:"file_name"`
			VTScore     *int       `json:"vt_score"`
			VTTotal     *int       `json:"vt_total"`
			VTVerdict   string     `json:"vt_verdict"`
			VTFamily    string     `json:"vt_family"`
			VTCheckedAt *time.Time `json:"vt_checked_at"`
			FirstSeen   time.Time  `json:"first_seen"`
			LastSeen    time.Time  `json:"last_seen"`
			EventCount  int        `json:"event_count"`
		}
		err := db.QueryRowContext(r.Context(), `
			SELECT hash, file_name, vt_score, vt_total, vt_verdict, vt_family,
			       vt_checked_at, first_seen, last_seen, event_count
			FROM file_hash_cache WHERE hash = $1`, hash).Scan(
			&h.Hash, &h.FileName, &h.VTScore, &h.VTTotal, &h.VTVerdict,
			&h.VTFamily, &h.VTCheckedAt, &h.FirstSeen, &h.LastSeen, &h.EventCount)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "hash not found"})
			return
		}
		writeJSON(w, 200, h)
	}
}
