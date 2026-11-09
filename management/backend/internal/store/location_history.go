package store

import (
	"context"
	"time"
)

// LocationHop is a consecutive pair of recorded positions for an agent.
type LocationHop struct {
	AgentID               string
	Host                  string
	PrevTS, TS            time.Time
	PrevLat, PrevLng      float64
	Lat, Lng              float64
	PrevAcc, Acc          float64
	PrevCountry, Country  string
	PrevCity, City        string
	CountryInPriorHistory bool // country appeared earlier than this row
}

// RecentLocationHops returns the position transitions recorded since `since`.
func (db *DB) RecentLocationHops(ctx context.Context, since time.Time) ([]LocationHop, error) {
	rows, err := db.QueryContext(ctx, `
		WITH ordered AS (
			SELECT h.id, h.agent_id, h.ts, h.lat, h.lng, COALESCE(h.accuracy,0) AS acc,
			       COALESCE(h.country,'') AS country, COALESCE(h.city,'') AS city,
			       LAG(h.ts)  OVER w AS pts, LAG(h.lat) OVER w AS plat, LAG(h.lng) OVER w AS plng,
			       LAG(COALESCE(h.accuracy,0)) OVER w AS pacc,
			       LAG(COALESCE(h.country,'')) OVER w AS pcountry, LAG(COALESCE(h.city,'')) OVER w AS pcity
			FROM agent_location_history h
			WHERE h.ts > NOW() - INTERVAL '30 days'
			WINDOW w AS (PARTITION BY h.agent_id ORDER BY h.ts)
		)
		SELECT o.agent_id, COALESCE(a.hostname,''), o.pts, o.ts, o.plat, o.plng, o.lat, o.lng,
		       o.pacc, o.acc, o.pcountry, o.country, o.pcity, o.city,
		       EXISTS (SELECT 1 FROM agent_location_history x
		               WHERE x.agent_id = o.agent_id AND x.ts < o.ts AND x.country = o.country AND o.country <> '')
		FROM ordered o
		LEFT JOIN agents a ON a.id = o.agent_id
		WHERE o.pts IS NOT NULL AND o.ts > $1
		ORDER BY o.ts`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LocationHop
	for rows.Next() {
		var h LocationHop
		if err := rows.Scan(&h.AgentID, &h.Host, &h.PrevTS, &h.TS, &h.PrevLat, &h.PrevLng, &h.Lat, &h.Lng,
			&h.PrevAcc, &h.Acc, &h.PrevCountry, &h.Country, &h.PrevCity, &h.City, &h.CountryInPriorHistory); err != nil {
			continue
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// PruneLocationHistory deletes history older than the retention window (F-16).
func (db *DB) PruneLocationHistory(ctx context.Context, olderThan time.Time) error {
	_, err := db.ExecContext(ctx, `DELETE FROM agent_location_history WHERE ts < $1`, olderThan)
	return err
}
