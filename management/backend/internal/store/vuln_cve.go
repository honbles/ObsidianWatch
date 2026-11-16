package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// CPECacheGet returns the cached NVD answer for one CPE (exact version), if
// it is newer than maxAge.
func (db *DB) CPECacheGet(ctx context.Context, cpe string, maxAge time.Duration) (findings json.RawMessage, total int, ok bool) {
	var at time.Time
	err := db.QueryRowContext(ctx, `SELECT fetched_at, total, findings FROM vuln_cpe_cache WHERE cpe = $1`, cpe).Scan(&at, &total, &findings)
	if err != nil || time.Since(at) > maxAge {
		return nil, 0, false
	}
	return findings, total, true
}

func (db *DB) CPECachePut(ctx context.Context, cpe string, total int, findings json.RawMessage) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO vuln_cpe_cache (cpe, fetched_at, total, findings) VALUES ($1, now(), $2, $3)
		ON CONFLICT (cpe) DO UPDATE SET fetched_at = now(), total = EXCLUDED.total, findings = EXCLUDED.findings`,
		cpe, total, findings)
	return err
}

// HostCVEGet returns a host's latest CVE result and the scan it was computed for.
func (db *DB) HostCVEGet(ctx context.Context, host string) (result json.RawMessage, scanAt, computedAt time.Time, ok bool) {
	var sa sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT result, scan_at, computed_at FROM vuln_host_cve WHERE host = $1`, host).Scan(&result, &sa, &computedAt)
	if err != nil {
		return nil, time.Time{}, time.Time{}, false
	}
	return result, sa.Time, computedAt, true
}

func (db *DB) HostCVEPut(ctx context.Context, host string, scanAt time.Time, result json.RawMessage) error {
	var sa interface{}
	if !scanAt.IsZero() {
		sa = scanAt.UTC()
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO vuln_host_cve (host, scan_at, computed_at, result) VALUES ($1, $2, now(), $3)
		ON CONFLICT (host) DO UPDATE SET scan_at = EXCLUDED.scan_at, computed_at = now(), result = EXCLUDED.result`,
		host, sa, result)
	return err
}
