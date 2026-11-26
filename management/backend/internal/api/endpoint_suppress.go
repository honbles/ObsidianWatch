package api

// endpoint_suppress.go - suppression / allowlist rules for endpoint, IOC and
// Sigma detections (D-10, v2).
//
//   GET    /api/v1/suppressions            list (with 30-day suppressed counts)
//   POST   /api/v1/suppressions            create
//   PUT    /api/v1/suppressions/{id}       edit
//   DELETE /api/v1/suppressions/{id}
//   GET    /api/v1/suppressions/preview    rule IDs a (rule_id, match_mode) would cover
//
// Alert-source namespaces: built-in signatures use their own IDs, IOC alerts
// "IOC:<source>:<type>", Sigma alerts "SIGMA:<rule.id>".
//
// All matchers AND together; an empty matcher means "any".

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	pathpkg "path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

const (
	suppModeExact     = "exact"
	suppModePrefix    = "prefix"
	suppPrefixMinLen  = 8
	suppMaxExpiryDays = 365
)

type EndpointSuppression struct {
	ID             int64      `json:"id"`
	RuleID         string     `json:"rule_id"`
	MatchMode      string     `json:"match_mode"`
	Host           string     `json:"host"`
	ProcessName    string     `json:"process_name"`
	ImagePathGlob  string     `json:"image_path_glob"`
	ParentProcess  string     `json:"parent_process"`
	UserName       string     `json:"user_name"`
	CmdlineContain string     `json:"cmdline_contains"`
	FilePathGlob   string     `json:"file_path_glob"`
	FileHash       string     `json:"file_hash"`  // any of the event's hashes (MD5, SHA-1, SHA-256)
	IP             string     `json:"ip"`         // the event's source or destination IP
	DNSDomain      string     `json:"dns_domain"` // a DNS query for this domain or a subdomain of it
	Indicator      string     `json:"indicator"`  // the threat-intel indicator value an IOC alert matched
	SourceAlertID  *int64     `json:"source_alert_id,omitempty"`
	Reason         string     `json:"reason"`
	CreatedBy      string     `json:"created_by"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Permanent      bool       `json:"permanent"`
	CreatedAt      time.Time  `json:"created_at"`
	// Request-only convenience: expiry as a number of days from now.
	ExpiresInDays int `json:"expires_in_days,omitempty"`
	// Response-only.
	Suppressed30d int64 `json:"suppressed_30d"`
}

type suppHitKey struct {
	id   int64
	host string
	day  string
}

type endpointSuppressor struct {
	mu    sync.RWMutex
	rules []EndpointSuppression
	hmu   sync.Mutex
	hits  map[suppHitKey]int64
}

var endpointSupp = &endpointSuppressor{hits: map[suppHitKey]int64{}}

const suppCols = `id, rule_id, match_mode, host, process_name, image_path_glob, parent_process, user_name,
	cmdline_contains, file_path_glob, file_hash, ip, dns_domain, indicator, source_alert_id, reason, created_by, expires_at, permanent, created_at`

func scanSuppression(rows *sql.Rows) (EndpointSuppression, error) {
	var r EndpointSuppression
	var exp sql.NullTime
	err := rows.Scan(&r.ID, &r.RuleID, &r.MatchMode, &r.Host, &r.ProcessName, &r.ImagePathGlob, &r.ParentProcess,
		&r.UserName, &r.CmdlineContain, &r.FilePathGlob, &r.FileHash, &r.IP, &r.DNSDomain, &r.Indicator, &r.SourceAlertID,
		&r.Reason, &r.CreatedBy, &exp, &r.Permanent, &r.CreatedAt)
	if exp.Valid {
		t := exp.Time
		r.ExpiresAt = &t
	}
	return r, err
}

func loadEndpointSuppressions(ctx context.Context, db *store.DB) ([]EndpointSuppression, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+suppCols+` FROM endpoint_suppressions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EndpointSuppression
	for rows.Next() {
		if r, err := scanSuppression(rows); err == nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// refreshEndpointSuppressions flushes hit counters and reloads the rules
// (called once per evaluation cycle).
func refreshEndpointSuppressions(ctx context.Context, db *store.DB) {
	flushSuppressionHits(ctx, db)
	if rules, err := loadEndpointSuppressions(ctx, db); err == nil {
		endpointSupp.mu.Lock()
		endpointSupp.rules = rules
		endpointSupp.mu.Unlock()
	}
}

func flushSuppressionHits(ctx context.Context, db *store.DB) {
	endpointSupp.hmu.Lock()
	pending := endpointSupp.hits
	endpointSupp.hits = map[suppHitKey]int64{}
	endpointSupp.hmu.Unlock()
	for k, n := range pending {
		_, err := db.ExecContext(ctx, `
			INSERT INTO endpoint_suppression_hits (suppression_id, host, day, hits) VALUES ($1,$2,$3,$4)
			ON CONFLICT (suppression_id, host, day) DO UPDATE SET hits = endpoint_suppression_hits.hits + EXCLUDED.hits`,
			k.id, k.host, k.day, n)
		if err != nil { // keep the counts for the next flush
			endpointSupp.hmu.Lock()
			endpointSupp.hits[k] += n
			endpointSupp.hmu.Unlock()
		}
	}
}

// ── matching ─────────────────────────────────────────────────────────────────

func suppGlob(pattern, value string) bool {
	p := strings.ToLower(strings.ReplaceAll(pattern, `\`, "/"))
	v := strings.ToLower(strings.ReplaceAll(value, `\`, "/"))
	ok, err := pathpkg.Match(p, v)
	return err == nil && ok
}

func suppBase(s string) string { return strings.TrimSuffix(baseName(s), ".exe") }

// eventParent is the parent process image from raw parent_exe (Linux/macOS) or
// Sysmon ParentImage / 4688 ParentProcessName (Windows).
func eventParent(ev store.Event) string {
	if p := rawStringField(ev, "parent_exe"); p != "" {
		return p
	}
	d := sysmonData(ev)
	for _, k := range []string{"ParentImage", "ParentProcessName"} {
		if v := d[k]; v != "" {
			return v
		}
	}
	return ""
}

func eventImagePath(ev store.Event) string {
	if p := rawStringField(ev, "exe"); p != "" {
		return p
	}
	if ev.ImagePath != nil {
		return *ev.ImagePath
	}
	return ""
}

// eventHashes: the event's file hashes, lower case; Windows lists them as "SHA256=..,MD5=..".
func eventHashes(ev store.Event) []string {
	if ev.FileHash == nil {
		return nil
	}
	var out []string
	for _, part := range strings.Split(*ev.FileHash, ",") {
		h := strings.ToLower(strings.TrimSpace(part))
		if i := strings.Index(h, "="); i >= 0 {
			h = h[i+1:]
		}
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

// domainCovers: d is the suppressed domain, q a queried name; q matches d itself or any subdomain of it.
func domainCovers(d, q string) bool {
	d, q = strings.TrimSuffix(strings.ToLower(d), "."), strings.TrimSuffix(strings.ToLower(q), ".")
	return q == d || strings.HasSuffix(q, "."+d)
}

// suppressionMatches reports whether rule r suppresses sigID for ev at time now.
func suppressionMatches(r EndpointSuppression, sigID string, ev store.Event, now time.Time) bool {
	return suppressionMatchesIndicator(r, sigID, "", ev, now)
}

// suppressionMatchesIndicator also knows the threat-intel indicator value an IOC rule matched ("" otherwise).
func suppressionMatchesIndicator(r EndpointSuppression, sigID, indicator string, ev store.Event, now time.Time) bool {
	if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
		return false
	}
	switch {
	case r.RuleID == "":
		return false // rule-less suppressions are not allowed
	case r.MatchMode == suppModePrefix:
		if !strings.HasPrefix(sigID, r.RuleID) {
			return false
		}
	default: // exact
		if sigID != r.RuleID {
			return false
		}
	}
	if r.Host != "" && !strings.EqualFold(r.Host, ev.Host) {
		return false
	}
	if r.ProcessName != "" {
		if ev.ProcessName == nil || !strings.EqualFold(r.ProcessName, *ev.ProcessName) {
			return false
		}
	}
	if r.ImagePathGlob != "" && !suppGlob(r.ImagePathGlob, eventImagePath(ev)) {
		return false
	}
	if r.ParentProcess != "" && suppBase(r.ParentProcess) != suppBase(eventParent(ev)) {
		return false
	}
	if r.UserName != "" {
		u := ""
		if ev.UserName != nil {
			u = *ev.UserName
		}
		if !suppGlob(r.UserName, u) {
			return false
		}
	}
	if r.CmdlineContain != "" && !strings.Contains(cl(ev), strings.ToLower(r.CmdlineContain)) {
		return false
	}
	if r.FilePathGlob != "" {
		p := ""
		if ev.FilePath != nil {
			p = *ev.FilePath
		} else if ev.RegKey != nil {
			p = *ev.RegKey
		}
		if !suppGlob(r.FilePathGlob, p) {
			return false
		}
	}
	if r.Indicator != "" && !strings.EqualFold(r.Indicator, indicator) {
		return false
	}
	if r.FileHash != "" {
		found := false
		for _, h := range eventHashes(ev) {
			if h == strings.ToLower(r.FileHash) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.IP != "" && !(ev.SrcIP != nil && strings.EqualFold(*ev.SrcIP, r.IP) || ev.DstIP != nil && strings.EqualFold(*ev.DstIP, r.IP)) {
		return false
	}
	if r.DNSDomain != "" {
		q := ""
		if ev.EventType == "dns" && ev.DstIP != nil { // every agent stores the DNS query name in dst_ip
			q = *ev.DstIP
		} else if ev.Domain != nil {
			q = *ev.Domain
		}
		if q == "" || !domainCovers(r.DNSDomain, q) {
			return false
		}
	}
	return true
}

// endpointSuppressed reports whether a (rule, event) pair is suppressed and
// counts the suppressed match.
func endpointSuppressed(sigID string, ev store.Event) bool {
	return endpointSuppressedIndicator(sigID, "", ev)
}

// endpointSuppressedIndicator is endpointSuppressed for a threat-intel match on indicator.
func endpointSuppressedIndicator(sigID, indicator string, ev store.Event) bool {
	now := time.Now()
	endpointSupp.mu.RLock()
	var hit int64
	for _, r := range endpointSupp.rules {
		if suppressionMatchesIndicator(r, sigID, indicator, ev, now) {
			hit = r.ID
			break
		}
	}
	endpointSupp.mu.RUnlock()
	if hit == 0 {
		return false
	}
	endpointSupp.hmu.Lock()
	if len(endpointSupp.hits) < 10000 {
		endpointSupp.hits[suppHitKey{hit, ev.Host, now.UTC().Format("2006-01-02")}]++
	}
	endpointSupp.hmu.Unlock()
	return true
}

// ── validation ───────────────────────────────────────────────────────────────

// registeredRuleIDs: every built-in signature and rule-meta ID.
func registeredRuleIDs() []string {
	seen := map[string]bool{}
	for _, set := range allSignatureSets() {
		for _, s := range set {
			seen[s.ID] = true
		}
	}
	for _, m := range AllRuleMeta() {
		seen[m.ID] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func dynamicNamespace(id string) bool {
	return strings.HasPrefix(id, "IOC:") || strings.HasPrefix(id, "SIGMA:") || id == rareBinaryRuleID
}

// coveredRuleIDs lists the built-in IDs a (rule_id, mode) pair would suppress.
func coveredRuleIDs(ruleID, mode string) []string {
	var out []string
	for _, id := range registeredRuleIDs() {
		if (mode == suppModePrefix && strings.HasPrefix(id, ruleID)) || (mode != suppModePrefix && id == ruleID) {
			out = append(out, id)
		}
	}
	return out
}

// validateSuppression normalises req and returns an error message ("" = ok).
func validateSuppression(req *EndpointSuppression, now time.Time) string {
	req.Reason = strings.TrimSpace(req.Reason)
	req.RuleID = strings.TrimSpace(req.RuleID)
	if req.MatchMode == "" {
		req.MatchMode = suppModeExact
	}
	if req.MatchMode != suppModeExact && req.MatchMode != suppModePrefix {
		return "match_mode must be exact or prefix"
	}
	if req.Reason == "" || len(req.Reason) > 500 {
		return "reason is required (max 500 chars)"
	}
	if req.RuleID == "" {
		return "rule_id is required: suppressing all rules for a host/process is not allowed"
	}
	req.FileHash, req.IP = strings.ToLower(strings.TrimSpace(req.FileHash)), strings.TrimSpace(req.IP)
	req.DNSDomain, req.Indicator = strings.ToLower(strings.TrimSpace(req.DNSDomain)), strings.TrimSpace(req.Indicator)
	if req.IP != "" && net.ParseIP(req.IP) == nil {
		return "ip must be an IP address"
	}
	for _, f := range []string{req.RuleID, req.Host, req.ProcessName, req.ImagePathGlob, req.ParentProcess,
		req.UserName, req.CmdlineContain, req.FilePathGlob, req.FileHash, req.DNSDomain, req.Indicator} {
		if len(f) > 255 {
			return "field too long"
		}
	}
	for _, g := range []string{req.ImagePathGlob, req.FilePathGlob, req.UserName} {
		if g != "" {
			if _, err := pathpkg.Match(strings.ToLower(strings.ReplaceAll(g, `\`, "/")), ""); err != nil {
				return "invalid glob pattern"
			}
		}
	}
	if req.MatchMode == suppModePrefix && req.RuleID == "IOC:" && req.Indicator != "" {
		// one indicator value across every intel source: narrow by the indicator, not the rule
	} else if req.MatchMode == suppModePrefix {
		if len(req.RuleID) < suppPrefixMinLen {
			return fmt.Sprintf("prefix mode requires a rule_id prefix of at least %d characters", suppPrefixMinLen)
		}
		if !dynamicNamespace(req.RuleID) && len(coveredRuleIDs(req.RuleID, suppModePrefix)) == 0 {
			return "prefix does not match any registered rule ID"
		}
	} else if !dynamicNamespace(req.RuleID) && len(coveredRuleIDs(req.RuleID, suppModeExact)) == 0 {
		return "unknown rule_id (use a registered rule ID, IOC:<source>:<type> or SIGMA:<rule id>)"
	}
	// Expiry: required unless explicitly permanent; at most 365 days.
	if req.ExpiresInDays > 0 {
		t := now.AddDate(0, 0, req.ExpiresInDays)
		req.ExpiresAt = &t
	}
	if req.Permanent {
		req.ExpiresAt = nil
	} else {
		if req.ExpiresAt == nil {
			return "expires_at is required (max 365 days); set permanent=true for a permanent rule"
		}
		if !req.ExpiresAt.After(now) {
			return "expires_at must be in the future"
		}
		if req.ExpiresAt.After(now.AddDate(0, 0, suppMaxExpiryDays)) {
			return "expires_at is more than 365 days away"
		}
	}
	return ""
}

// ── handlers ─────────────────────────────────────────────────────────────────

func suppActor(r *http.Request) string {
	if c := auth.GetClaims(r); c != nil {
		return c.Username
	}
	return ""
}

func suppAuditDetail(s EndpointSuppression) string {
	exp := "none"
	if s.ExpiresAt != nil {
		exp = s.ExpiresAt.UTC().Format(time.RFC3339)
	}
	b, _ := json.Marshal(map[string]interface{}{
		"rule_id": s.RuleID, "mode": s.MatchMode, "host": s.Host, "process": s.ProcessName, "image": s.ImagePathGlob,
		"parent": s.ParentProcess, "user": s.UserName, "cmdline": s.CmdlineContain, "file": s.FilePathGlob,
		"hash": s.FileHash, "ip": s.IP, "domain": s.DNSDomain, "indicator": s.Indicator, "from_alert": s.SourceAlertID,
		"expires": exp, "permanent": s.Permanent, "reason": s.Reason,
	})
	return string(b)
}

func handleListSuppressions(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := loadEndpointSuppressions(r.Context(), db)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		if rules == nil {
			rules = []EndpointSuppression{}
		}
		// Suppressed-match counts (last 30 days), including not-yet-flushed ones.
		counts := map[int64]int64{}
		if rows, err := db.QueryContext(r.Context(),
			`SELECT suppression_id, COALESCE(SUM(hits),0) FROM endpoint_suppression_hits
			 WHERE day >= CURRENT_DATE - 30 GROUP BY suppression_id`); err == nil {
			for rows.Next() {
				var id, n int64
				if rows.Scan(&id, &n) == nil {
					counts[id] = n
				}
			}
			rows.Close()
		}
		endpointSupp.hmu.Lock()
		for k, n := range endpointSupp.hits {
			counts[k.id] += n
		}
		endpointSupp.hmu.Unlock()
		for i := range rules {
			rules[i].Suppressed30d = counts[rules[i].ID]
		}
		writeJSON(w, 200, map[string]interface{}{"rules": rules, "total": len(rules)})
	}
}

func handlePreviewSuppression() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleID := strings.TrimSpace(r.URL.Query().Get("rule_id"))
		mode := r.URL.Query().Get("match_mode")
		ids := coveredRuleIDs(ruleID, mode)
		if ids == nil {
			ids = []string{}
		}
		writeJSON(w, 200, map[string]interface{}{"rule_id": ruleID, "match_mode": mode, "covers": ids, "dynamic": dynamicNamespace(ruleID)})
	}
}

func handleCreateSuppression(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var req EndpointSuppression
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if msg := validateSuppression(&req, time.Now()); msg != "" {
			writeJSON(w, 400, map[string]string{"error": msg})
			return
		}
		actor := suppActor(r)
		var id int64
		err := db.QueryRowContext(r.Context(), `
			INSERT INTO endpoint_suppressions (rule_id, match_mode, host, process_name, image_path_glob, parent_process,
				user_name, cmdline_contains, file_path_glob, file_hash, ip, dns_domain, indicator, reason, created_by, expires_at, permanent)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING id`,
			req.RuleID, req.MatchMode, req.Host, req.ProcessName, req.ImagePathGlob, req.ParentProcess, req.UserName,
			req.CmdlineContain, req.FilePathGlob, req.FileHash, req.IP, req.DNSDomain, req.Indicator, req.Reason, actor, req.ExpiresAt, req.Permanent).Scan(&id)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not save rule"})
			return
		}
		db.WriteAudit(r.Context(), actor, "create_suppression", "suppression:"+strconv.FormatInt(id, 10), suppAuditDetail(req), clientIP(r))
		refreshEndpointSuppressions(r.Context(), db)
		req.ID, req.CreatedBy, req.CreatedAt = id, actor, time.Now()
		writeJSON(w, 201, req)
	}
}

func handleUpdateSuppression(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var req EndpointSuppression
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if msg := validateSuppression(&req, time.Now()); msg != "" {
			writeJSON(w, 400, map[string]string{"error": msg})
			return
		}
		res, err := db.ExecContext(r.Context(), `
			UPDATE endpoint_suppressions SET rule_id=$2, match_mode=$3, host=$4, process_name=$5, image_path_glob=$6,
				parent_process=$7, user_name=$8, cmdline_contains=$9, file_path_glob=$10, reason=$11, expires_at=$12, permanent=$13,
				file_hash=$14, ip=$15, dns_domain=$16, indicator=$17
			WHERE id=$1`,
			id, req.RuleID, req.MatchMode, req.Host, req.ProcessName, req.ImagePathGlob, req.ParentProcess, req.UserName,
			req.CmdlineContain, req.FilePathGlob, req.Reason, req.ExpiresAt, req.Permanent, req.FileHash, req.IP, req.DNSDomain, req.Indicator)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not save rule"})
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			writeJSON(w, 404, map[string]string{"error": "rule not found"})
			return
		}
		db.WriteAudit(r.Context(), suppActor(r), "update_suppression", "suppression:"+strconv.FormatInt(id, 10), suppAuditDetail(req), clientIP(r))
		refreshEndpointSuppressions(r.Context(), db)
		req.ID = id
		writeJSON(w, 200, req)
	}
}

func handleDeleteSuppression(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		res, err := db.ExecContext(r.Context(), `DELETE FROM endpoint_suppressions WHERE id=$1`, id)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "delete failed"})
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			writeJSON(w, 404, map[string]string{"error": "rule not found"})
			return
		}
		db.WriteAudit(r.Context(), suppActor(r), "delete_suppression", "suppression:"+strconv.FormatInt(id, 10), "", clientIP(r))
		refreshEndpointSuppressions(r.Context(), db)
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}
