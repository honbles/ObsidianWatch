package store

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// ScanPoint is one CSPM scan's severity counts.
type ScanPoint struct {
	ScannedAt time.Time `json:"scanned_at"`
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
	Low       int       `json:"low"`
	Passed    int       `json:"passed"`
	Total     int       `json:"total"`
}

const scanHistoryKeep = 180 * 24 * time.Hour

// parseCSPMKey splits "cspm:<provider>:<connector id>".
func parseCSPMKey(key string) (provider string, id int64, ok bool) {
	parts := strings.Split(key, ":")
	if len(parts) != 3 || parts[0] != "cspm" || parts[1] == "" {
		return "", 0, false
	}
	n, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return parts[1], n, true
}

// scanPointFromJSON reads the severity counts every CSPM result carries.
func scanPointFromJSON(value string) (ScanPoint, bool) {
	var p struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
		Passed   int `json:"passed"`
		Total    int `json:"total_findings"`
	}
	if json.Unmarshal([]byte(value), &p) != nil {
		return ScanPoint{}, false
	}
	return ScanPoint{Critical: p.Critical, High: p.High, Medium: p.Medium, Low: p.Low, Passed: p.Passed, Total: p.Total}, true
}

// recordScanHistory is called when a cspm:* setting is saved. Failures never
// affect the scan result itself.
func (db *DB) recordScanHistory(ctx context.Context, key, value string) {
	provider, id, ok := parseCSPMKey(key)
	if !ok {
		return
	}
	p, ok := scanPointFromJSON(value)
	if !ok {
		return
	}
	_, _ = db.ExecContext(ctx, `INSERT INTO cloud_scan_history (provider, connector_id, critical, high, medium, low, passed, total)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, provider, id, p.Critical, p.High, p.Medium, p.Low, p.Passed, p.Total)
	_, _ = db.ExecContext(ctx, `DELETE FROM cloud_scan_history WHERE connector_id=$1 AND provider=$2 AND scanned_at < $3`,
		id, provider, time.Now().Add(-scanHistoryKeep))
}

// ListScanHistory returns a connector's scans, oldest first.
func (db *DB) ListScanHistory(ctx context.Context, provider string, id int64, days int) ([]ScanPoint, error) {
	rows, err := db.QueryContext(ctx, `SELECT scanned_at, critical, high, medium, low, passed, total FROM cloud_scan_history
		WHERE connector_id=$1 AND provider=$2 AND scanned_at > $3 ORDER BY scanned_at ASC LIMIT 1000`,
		id, provider, time.Now().Add(-time.Duration(days)*24*time.Hour))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanPoint{}
	for rows.Next() {
		var p ScanPoint
		if rows.Scan(&p.ScannedAt, &p.Critical, &p.High, &p.Medium, &p.Low, &p.Passed, &p.Total) == nil {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}
