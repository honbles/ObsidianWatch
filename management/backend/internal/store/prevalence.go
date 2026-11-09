package store

import (
	"context"
	"strings"
	"time"
)

// PrevalenceObs is one aggregated observation of a key on a host.
type PrevalenceObs struct {
	Key   string
	Host  string
	Count int64
	At    time.Time
}

// RecordPrevalence upserts a batch of observations in one statement.
func (db *DB) RecordPrevalence(ctx context.Context, obs []PrevalenceObs) error {
	if len(obs) == 0 {
		return nil
	}
	keys := make([]string, len(obs))
	hosts := make([]string, len(obs))
	counts := make([]int64, len(obs))
	ats := make([]time.Time, len(obs))
	for i, o := range obs {
		keys[i], hosts[i], counts[i], ats[i] = o.Key, o.Host, o.Count, o.At
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO prevalence (key, host, first_seen, last_seen, seen_count)
		SELECT k, h, t, t, c FROM unnest($1::text[], $2::text[], $3::bigint[], $4::timestamptz[]) AS x(k, h, c, t)
		ON CONFLICT (key, host) DO UPDATE SET
			last_seen  = GREATEST(prevalence.last_seen, EXCLUDED.last_seen),
			first_seen = LEAST(prevalence.first_seen, EXCLUDED.first_seen),
			seen_count = prevalence.seen_count + EXCLUDED.seen_count`,
		pqStringArray(keys), pqStringArray(hosts), pqInt64Array(counts), pqTimeArray(ats))
	return err
}

type PrevalenceInfo struct {
	Key       string           `json:"key"`
	HostCount int              `json:"host_count"`
	FleetSize int              `json:"fleet_size"`
	FirstSeen *time.Time       `json:"first_seen"`
	FirstHost string           `json:"first_host,omitempty"`
	LastSeen  *time.Time       `json:"last_seen"`
	Hosts     []PrevalenceHost `json:"hosts"`
}

type PrevalenceHost struct {
	Host      string    `json:"host"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int64     `json:"seen_count"`
}

// GetPrevalence returns how many hosts have run `key` and which (first 50 by first_seen).
func (db *DB) GetPrevalence(ctx context.Context, key string) (*PrevalenceInfo, error) {
	info := &PrevalenceInfo{Key: key, Hosts: []PrevalenceHost{}}
	rows, err := db.QueryContext(ctx,
		`SELECT host, first_seen, last_seen, seen_count FROM prevalence WHERE key = $1 ORDER BY first_seen LIMIT 50`, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h PrevalenceHost
		if err := rows.Scan(&h.Host, &h.FirstSeen, &h.LastSeen, &h.Count); err != nil {
			continue
		}
		info.Hosts = append(info.Hosts, h)
	}
	var first, last *time.Time
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*), MIN(first_seen), MAX(last_seen) FROM prevalence WHERE key = $1`, key).
		Scan(&info.HostCount, &first, &last)
	info.FirstSeen, info.LastSeen = first, last
	if len(info.Hosts) > 0 {
		info.FirstHost = info.Hosts[0].Host
	}
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT host) FROM prevalence`).Scan(&info.FleetSize)
	return info, rows.Err()
}

// PrunePrevalence drops rows not seen for the retention window.
func (db *DB) PrunePrevalence(ctx context.Context, olderThan time.Time) error {
	_, err := db.ExecContext(ctx, `DELETE FROM prevalence WHERE last_seen < $1`, olderThan)
	return err
}

// PrevalenceHostCounts returns how many distinct hosts have seen each key.
func (db *DB) PrevalenceHostCounts(ctx context.Context, keys []string) (map[string]int, error) {
	out := map[string]int{}
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT key, COUNT(DISTINCT host) FROM prevalence WHERE key = ANY($1::text[]) GROUP BY key`, pqStringArray(keys))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if rows.Scan(&k, &n) == nil {
			out[k] = n
		}
	}
	return out, rows.Err()
}

// PrevalenceHistoryStart returns the oldest first_seen in the table (zero if empty).
func (db *DB) PrevalenceHistoryStart(ctx context.Context) (time.Time, error) {
	var t *time.Time
	if err := db.QueryRowContext(ctx, `SELECT MIN(first_seen) FROM prevalence`).Scan(&t); err != nil || t == nil {
		return time.Time{}, err
	}
	return *t, nil
}

// PrevalenceHistoryStartForPrefix is the earliest first_seen among keys with the
// given prefix (e.g. "hash:"), so a new kind of key starts its own warm-up
// period instead of inheriting the age of older, unrelated keys.
func (db *DB) PrevalenceHistoryStartForPrefix(ctx context.Context, prefix string) (time.Time, error) {
	var t *time.Time
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix)
	if err := db.QueryRowContext(ctx, `SELECT MIN(first_seen) FROM prevalence WHERE key LIKE $1 ESCAPE '\'`, esc+"%").Scan(&t); err != nil || t == nil {
		return time.Time{}, err
	}
	return *t, nil
}
