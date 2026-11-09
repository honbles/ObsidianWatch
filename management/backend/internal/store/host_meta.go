package store

import (
	"context"
	"strings"
)

// HostMeta is operator-supplied context about a host.
type HostMeta struct {
	Host        string   `json:"host"`
	Criticality string   `json:"criticality"`
	Tags        []string `json:"tags"`
}

func splitTags(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// WeightedSeverity raises the severity of alerts on critical hosts by one (max 5).
// Other criticalities never change severity, so alerts are not hidden or demoted.
func WeightedSeverity(sev int, criticality string) int {
	if criticality == "critical" && sev < 5 {
		return sev + 1
	}
	return sev
}

func (db *DB) GetHostCriticality(ctx context.Context, host string) string {
	if host == "" {
		return "normal"
	}
	var c string
	if db.QueryRowContext(ctx, `SELECT criticality FROM host_meta WHERE host=$1`, host).Scan(&c) != nil {
		return "normal"
	}
	return c
}

func (db *DB) ListHostMeta(ctx context.Context) ([]HostMeta, error) {
	rows, err := db.QueryContext(ctx, `SELECT host, criticality, tags FROM host_meta ORDER BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostMeta{}
	for rows.Next() {
		var m HostMeta
		var tags string
		if rows.Scan(&m.Host, &m.Criticality, &tags) == nil {
			m.Tags = splitTags(tags)
			out = append(out, m)
		}
	}
	return out, rows.Err()
}

func (db *DB) SetHostMeta(ctx context.Context, host, criticality string, tags []string, by string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO host_meta (host, criticality, tags, updated_by, updated_at) VALUES ($1,$2,$3,$4,NOW())
		ON CONFLICT (host) DO UPDATE SET criticality=EXCLUDED.criticality, tags=EXCLUDED.tags,
			updated_by=EXCLUDED.updated_by, updated_at=NOW()`, host, criticality, strings.Join(tags, ","), by)
	return err
}
