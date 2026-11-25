package store

import (
	"context"
	"time"
)

// PreventionCandidate is an indicator eligible for agent-side blocking.
type PreventionCandidate struct {
	Type       string // ip | hash | domain
	Value      string
	Source     string // threatfox | feodo | manual | fleet
	Confidence int
	Malware    string
	Until      time.Time // the agent drops the entry after this, even offline
}

// PreventionCandidates returns indicators eligible for blocking, best first:
// manual entries, then by confidence, then most recently first seen.
// ThreatFox entries need confidence >= minConf and a first-seen date within
// maxAge; Feodo needs its "recommended" (actively seen) confidence of 90;
// OTX is never used (community-submitted, detection only). Hashes are
// SHA-256 only. Malicious fleet verdicts from file_hash_cache are added.
func (db *DB) PreventionCandidates(ctx context.Context, minConf int, maxAge time.Duration) ([]PreventionCandidate, error) {
	ageCut := time.Now().Add(-maxAge)
	rows, err := db.QueryContext(ctx, `
		SELECT ioc_type, value, source, confidence, COALESCE(malware,''),
		       CASE WHEN source = 'manual' THEN COALESCE(expires_at, NOW() + interval '365 days')
		            ELSE LEAST(COALESCE(expires_at, 'infinity'::timestamptz), COALESCE(first_seen, created_at) + make_interval(secs => $3))
		       END AS until
		FROM ioc_indicators
		WHERE ioc_type IN ('ip','hash','domain')
		  AND (expires_at IS NULL OR expires_at > NOW())
		  AND (source = 'manual'
		       OR (source = 'threatfox' AND confidence >= $1 AND COALESCE(first_seen, created_at) > $2)
		       OR (source = 'feodo' AND confidence >= 90))
		  AND (ioc_type <> 'hash' OR value ~ '^[0-9a-f]{64}$')
		ORDER BY (source = 'manual') DESC, confidence DESC, COALESCE(first_seen, created_at) DESC`,
		minConf, ageCut, maxAge.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PreventionCandidate
	for rows.Next() {
		var c PreventionCandidate
		if err := rows.Scan(&c.Type, &c.Value, &c.Source, &c.Confidence, &c.Malware, &c.Until); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// One detection protects every host: hashes the reputation lookups
	// judged malicious (several engines), seen in the fleet recently.
	fr, err := db.QueryContext(ctx, `
		SELECT hash, COALESCE(vt_family,''), last_seen FROM file_hash_cache
		WHERE hash_type = 'sha256' AND vt_verdict = 'malicious' AND COALESCE(vt_score,0) >= 5
		  AND last_seen > $1 ORDER BY vt_score DESC NULLS LAST LIMIT 50000`, ageCut)
	if err == nil {
		defer fr.Close()
		for fr.Next() {
			var c PreventionCandidate
			var last time.Time
			if fr.Scan(&c.Value, &c.Malware, &last) == nil {
				c.Type, c.Source, c.Confidence, c.Until = "hash", "fleet", 80, last.Add(maxAge)
				out = append(out, c)
			}
		}
	}
	return out, nil
}
