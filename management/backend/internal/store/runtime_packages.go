package store

import (
	"context"
	"strings"
	"time"
)

// RuntimePackage is one package seen in one running process context.
type RuntimePackage struct {
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	AgentID   string    `json:"agent_id"`
	Host      string    `json:"host"`
	Service   string    `json:"service,omitempty"`
	Container string    `json:"container,omitempty"`
	Exe       string    `json:"exe,omitempty"`
	Evidence  string    `json:"evidence"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// PackageNameKey normalises a package name for matching across scanners and
// the runtime inventory (PyPI treats -, _ and . alike and is case-insensitive;
// npm, Maven and NuGet names are compared case-insensitively).
func PackageNameKey(ecosystem, name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if ecosystem == "PyPI" {
		n = strings.NewReplacer("_", "-", ".", "-").Replace(n)
	}
	return n
}

// UpsertRuntimePackages records packages seen now. "loaded" is never
// downgraded to "deployed" while the row stays fresh.
func (db *DB) UpsertRuntimePackages(ctx context.Context, pkgs []RuntimePackage) error {
	if len(pkgs) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO runtime_packages (ecosystem, name_key, name, version, agent_id, host, service, container, exe, evidence, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)
		ON CONFLICT (ecosystem, name_key, version, agent_id, service, container, exe) DO UPDATE SET
			last_seen = GREATEST(runtime_packages.last_seen, EXCLUDED.last_seen),
			host = EXCLUDED.host,
			evidence = CASE WHEN runtime_packages.evidence = 'loaded' AND EXCLUDED.evidence = 'deployed'
			                 AND runtime_packages.last_seen > EXCLUDED.last_seen - INTERVAL '24 hours'
			                THEN 'loaded' ELSE EXCLUDED.evidence END`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, p := range pkgs {
		if _, err := stmt.ExecContext(ctx, p.Ecosystem, PackageNameKey(p.Ecosystem, p.Name), p.Name, p.Version, p.AgentID,
			p.Host, p.Service, p.Container, p.Exe, p.Evidence, p.LastSeen); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// FindRuntimePackage returns where ecosystem/name@version was seen since.
// An empty version matches every version.
func (db *DB) FindRuntimePackage(ctx context.Context, ecosystem, name, version string, since time.Time, limit int) ([]RuntimePackage, error) {
	q := `SELECT ecosystem, name, version, agent_id, host, service, container, exe, evidence, first_seen, last_seen
		FROM runtime_packages WHERE name_key=$1 AND last_seen >= $2`
	args := []interface{}{PackageNameKey(ecosystem, name), since}
	if ecosystem != "" {
		args = append(args, ecosystem)
		q += ` AND ecosystem=$3`
	}
	if version != "" {
		args = append(args, version)
		q += ` AND version=$` + itoaStore(len(args))
	}
	args = append(args, limit)
	q += ` ORDER BY (evidence='loaded') DESC, last_seen DESC LIMIT $` + itoaStore(len(args))
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuntimePackage
	for rows.Next() {
		var p RuntimePackage
		if err := rows.Scan(&p.Ecosystem, &p.Name, &p.Version, &p.AgentID, &p.Host, &p.Service, &p.Container, &p.Exe,
			&p.Evidence, &p.FirstSeen, &p.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RuntimeInventoryCoverage counts the hosts that reported an inventory since.
func (db *DB) RuntimeInventoryCoverage(ctx context.Context, since time.Time) int {
	var n int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT agent_id) FROM runtime_packages WHERE last_seen >= $1`, since).Scan(&n)
	return n
}

// PruneRuntimePackages deletes rows not seen for the given age.
func (db *DB) PruneRuntimePackages(ctx context.Context, olderThan time.Duration) {
	_, _ = db.ExecContext(ctx, `DELETE FROM runtime_packages WHERE last_seen < NOW() - make_interval(secs => $1)`, olderThan.Seconds())
}

func itoaStore(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
