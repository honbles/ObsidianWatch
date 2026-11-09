package store

import (
	"context"
	"database/sql"
	"time"
)

// ── Source config ─────────────────────────────────────────────────────────────

type ThreatIntelSource struct {
	ID        int
	Name      string
	Enabled   bool
	APIKey    *string
	LastSync  *time.Time
	LastError *string
	IOCCount  int
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (db *DB) ListThreatIntelSources(ctx context.Context) ([]ThreatIntelSource, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, enabled, api_key, last_sync, last_error, ioc_count, created_at, updated_at
		 FROM threat_intel_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []ThreatIntelSource
	for rows.Next() {
		var s ThreatIntelSource
		var apiKey, lastError sql.NullString
		var lastSync sql.NullTime
		if err := rows.Scan(&s.ID, &s.Name, &s.Enabled, &apiKey, &lastSync, &lastError,
			&s.IOCCount, &s.CreatedAt, &s.UpdatedAt); err != nil {
			continue
		}
		if apiKey.Valid {
			s.APIKey = &apiKey.String
		}
		if lastSync.Valid {
			s.LastSync = &lastSync.Time
		}
		if lastError.Valid {
			s.LastError = &lastError.String
		}
		sources = append(sources, s)
	}
	return sources, rows.Err()
}

func (db *DB) UpdateThreatIntelSource(ctx context.Context, name string, enabled bool, apiKey *string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE threat_intel_sources
		SET enabled = $1, api_key = $2, updated_at = NOW()
		WHERE name = $3
	`, enabled, apiKey, name)
	return err
}

func (db *DB) SetThreatIntelSyncResult(ctx context.Context, name string, iocCount int, syncErr error) error {
	errStr := (*string)(nil)
	if syncErr != nil {
		s := syncErr.Error()
		errStr = &s
	}
	// Get total IOC count for this source from the DB (not just newly inserted)
	var totalCount int
	db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM ioc_indicators WHERE source = $1 AND (expires_at IS NULL OR expires_at > NOW())`,
		name,
	).Scan(&totalCount)
	// Use total if available, otherwise use the sync count
	if totalCount > 0 {
		iocCount = totalCount
	}
	_, err := db.ExecContext(ctx, `
		UPDATE threat_intel_sources
		SET last_sync = NOW(), last_error = $1, ioc_count = $2, updated_at = NOW()
		WHERE name = $3
	`, errStr, iocCount, name)
	return err
}

// ── IOC indicators ────────────────────────────────────────────────────────────

type IOCIndicator struct {
	ID         int64
	Source     string
	IOCType    string
	Value      string
	Malware    string
	ThreatType string
	Confidence int
	Severity   int
	Tags       string
	ExpiresAt  *time.Time
	CreatedAt  time.Time
}

func (db *DB) UpsertIOCs(ctx context.Context, iocs []IOCIndicator) (int, error) {
	if len(iocs) == 0 {
		return 0, nil
	}
	inserted := 0
	for _, ioc := range iocs {
		res, err := db.ExecContext(ctx, `
			INSERT INTO ioc_indicators (source, ioc_type, value, malware, threat_type, confidence, severity, tags, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (source, ioc_type, value) DO UPDATE
			SET malware = $4, threat_type = $5, confidence = $6, severity = $7, tags = $8, expires_at = $9
		`, ioc.Source, ioc.IOCType, ioc.Value, ioc.Malware, ioc.ThreatType,
			ioc.Confidence, ioc.Severity, ioc.Tags, ioc.ExpiresAt)
		if err != nil {
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
	}
	return inserted, nil
}

func (db *DB) DeleteExpiredIOCs(ctx context.Context) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM ioc_indicators WHERE expires_at IS NOT NULL AND expires_at < NOW()`)
	return err
}

func (db *DB) DeleteIOCsBySource(ctx context.Context, source string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM ioc_indicators WHERE source = $1`, source)
	return err
}

// MatchIOC checks if a given value matches any active IOC.
func (db *DB) MatchIOC(ctx context.Context, iocType, value string) (*IOCIndicator, error) {
	var ioc IOCIndicator
	var malware, threatType, tags sql.NullString
	var expiresAt sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT id, source, ioc_type, value, malware, threat_type, confidence, severity, tags, expires_at, created_at
		FROM ioc_indicators
		WHERE ioc_type = $1 AND value = $2
		  AND (expires_at IS NULL OR expires_at > NOW())
		LIMIT 1
	`, iocType, value).Scan(
		&ioc.ID, &ioc.Source, &ioc.IOCType, &ioc.Value,
		&malware, &threatType, &ioc.Confidence, &ioc.Severity,
		&tags, &expiresAt, &ioc.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if malware.Valid {
		ioc.Malware = malware.String
	}
	if threatType.Valid {
		ioc.ThreatType = threatType.String
	}
	if tags.Valid {
		ioc.Tags = tags.String
	}
	if expiresAt.Valid {
		ioc.ExpiresAt = &expiresAt.Time
	}
	return &ioc, nil
}

// GetAllIOCsOfType returns all active IOCs of a given type for bulk matching.
func (db *DB) GetAllIOCsOfType(ctx context.Context, iocType string) (map[string]IOCIndicator, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, source, ioc_type, value, malware, threat_type, confidence, severity, tags, expires_at, created_at
		FROM ioc_indicators
		WHERE ioc_type = $1
		  AND (expires_at IS NULL OR expires_at > NOW())
	`, iocType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]IOCIndicator)
	for rows.Next() {
		var ioc IOCIndicator
		var malware, threatType, tags sql.NullString
		var expiresAt sql.NullTime
		if err := rows.Scan(&ioc.ID, &ioc.Source, &ioc.IOCType, &ioc.Value,
			&malware, &threatType, &ioc.Confidence, &ioc.Severity,
			&tags, &expiresAt, &ioc.CreatedAt); err != nil {
			continue
		}
		if malware.Valid {
			ioc.Malware = malware.String
		}
		if threatType.Valid {
			ioc.ThreatType = threatType.String
		}
		if tags.Valid {
			ioc.Tags = tags.String
		}
		if expiresAt.Valid {
			ioc.ExpiresAt = &expiresAt.Time
		}
		result[ioc.Value] = ioc
	}
	return result, rows.Err()
}

// ── Sigma rules ───────────────────────────────────────────────────────────────

type SigmaRule struct {
	ID          string
	Title       string
	Description string
	Status      string
	Level       string
	Severity    int
	Category    string
	MITRE       string
	LogSource   string
	Detection   string
	Enabled     bool
	Source      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (db *DB) UpsertSigmaRule(ctx context.Context, rule SigmaRule) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO sigma_rules (id, title, description, status, level, severity, category, mitre, logsource, detection, enabled, source, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
		ON CONFLICT (id) DO UPDATE
		SET title=$2, description=$3, status=$4, level=$5, severity=$6,
		    category=$7, mitre=$8, logsource=$9, detection=$10, source=$12, updated_at=NOW()
	`, rule.ID, rule.Title, rule.Description, rule.Status, rule.Level, rule.Severity,
		rule.Category, rule.MITRE, rule.LogSource, rule.Detection, rule.Enabled, rule.Source)
	return err
}

func (db *DB) ListSigmaRules(ctx context.Context, enabledOnly bool) ([]SigmaRule, error) {
	q := `SELECT id, title, description, status, level, severity, category, mitre, logsource, detection, enabled, source, created_at, updated_at
	      FROM sigma_rules`
	if enabledOnly {
		q += ` WHERE enabled = TRUE`
	}
	q += ` ORDER BY severity DESC, title`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []SigmaRule
	for rows.Next() {
		var r SigmaRule
		var desc, status, category, mitre, logsource sql.NullString
		if err := rows.Scan(&r.ID, &r.Title, &desc, &status, &r.Level, &r.Severity,
			&category, &mitre, &logsource, &r.Detection, &r.Enabled, &r.Source,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		if desc.Valid {
			r.Description = desc.String
		}
		if status.Valid {
			r.Status = status.String
		}
		if category.Valid {
			r.Category = category.String
		}
		if mitre.Valid {
			r.MITRE = mitre.String
		}
		if logsource.Valid {
			r.LogSource = logsource.String
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (db *DB) SetSigmaRuleEnabled(ctx context.Context, id string, enabled bool) error {
	_, err := db.ExecContext(ctx,
		`UPDATE sigma_rules SET enabled = $1, updated_at = NOW() WHERE id = $2`, enabled, id)
	return err
}

func (db *DB) DeleteSigmaRulesBySource(ctx context.Context, source string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM sigma_rules WHERE source = $1`, source)
	return err
}

func (db *DB) CountSigmaRules(ctx context.Context) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sigma_rules`).Scan(&n)
	return n, err
}

// StoreIOC upserts a single IOC indicator.
func (db *DB) StoreIOC(ctx context.Context, ioc IOCIndicator) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO ioc_indicators (source, ioc_type, value, malware, threat_type, confidence, severity, tags, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (source, ioc_type, value) DO UPDATE SET
			threat_type = EXCLUDED.threat_type,
			confidence  = EXCLUDED.confidence,
			severity    = EXCLUDED.severity,
			tags        = EXCLUDED.tags,
			expires_at  = EXCLUDED.expires_at`,
		ioc.Source, ioc.IOCType, ioc.Value, ioc.Malware, ioc.ThreatType,
		ioc.Confidence, ioc.Severity, ioc.Tags, ioc.ExpiresAt)
	return err
}

// GetIOCByTypeAndValue retrieves a single IOC by type and value.
func (db *DB) GetIOCByTypeAndValue(ctx context.Context, iocType, value string) (*IOCIndicator, error) {
	var ioc IOCIndicator
	err := db.QueryRowContext(ctx, `
		SELECT id, source, ioc_type, value, COALESCE(malware,''), COALESCE(threat_type,''),
		       confidence, severity, COALESCE(tags,''), expires_at, created_at
		FROM ioc_indicators
		WHERE ioc_type = $1 AND value = $2
		  AND (expires_at IS NULL OR expires_at > NOW())
		LIMIT 1`, iocType, value).Scan(
		&ioc.ID, &ioc.Source, &ioc.IOCType, &ioc.Value, &ioc.Malware, &ioc.ThreatType,
		&ioc.Confidence, &ioc.Severity, &ioc.Tags, &ioc.ExpiresAt, &ioc.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &ioc, nil
}

// GetSigmaRuleCount returns the total number of Sigma rules.
func (db *DB) GetSigmaRuleCount(ctx context.Context) (int, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sigma_rules`).Scan(&count)
	return count, err
}

// ListIOCsCreatedSince returns active IOCs first inserted at/after t (P-01).
func (db *DB) ListIOCsCreatedSince(ctx context.Context, source string, t time.Time) ([]IOCIndicator, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, source, ioc_type, value, COALESCE(malware,''), COALESCE(threat_type,''),
		       confidence, severity, created_at
		FROM ioc_indicators
		WHERE source = $1 AND created_at >= $2
		  AND ioc_type IN ('ip','domain','hash')
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY severity DESC, id
		LIMIT 20000`, source, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IOCIndicator
	for rows.Next() {
		var i IOCIndicator
		if err := rows.Scan(&i.ID, &i.Source, &i.IOCType, &i.Value, &i.Malware, &i.ThreatType,
			&i.Confidence, &i.Severity, &i.CreatedAt); err != nil {
			continue
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// RetroHuntHit is one retained event that matches a newly-arrived IOC.
type RetroHuntHit struct {
	EventID   string
	Time      time.Time
	AgentID   string
	Host      string
	OS        string
	EventType string
	Process   string
	Matched   string // the IOC value that matched (lower-cased)
}

// RetroHuntEvents searches retained events within `since` for any of the given
// IOC values of one type. Results are capped by limit.
func (db *DB) RetroHuntEvents(ctx context.Context, iocType string, values []string, since time.Time, limit int) ([]RetroHuntHit, error) {
	if len(values) == 0 {
		return nil, nil
	}
	var cond string
	switch iocType {
	case "ip":
		cond = `(dst_ip = ANY($1) OR src_ip = ANY($1))`
	case "domain":
		cond = `(domain = ANY($1) OR dst_ip = ANY($1))`
	case "hash":
		cond = `(file_hash = ANY($1))`
	default:
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, time, COALESCE(agent_id,''), COALESCE(host,''), COALESCE(os,''),
		       COALESCE(event_type,''), COALESCE(process_name,''),
		       COALESCE(NULLIF(dst_ip,''), NULLIF(src_ip,''), NULLIF(domain,''), COALESCE(file_hash,''))
		FROM events
		WHERE time >= $2 AND `+cond+`
		ORDER BY time DESC
		LIMIT $3`, pqStringArray(values), since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RetroHuntHit
	for rows.Next() {
		var h RetroHuntHit
		if err := rows.Scan(&h.EventID, &h.Time, &h.AgentID, &h.Host, &h.OS,
			&h.EventType, &h.Process, &h.Matched); err != nil {
			continue
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
