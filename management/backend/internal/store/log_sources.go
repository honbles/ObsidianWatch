package store

import (
	"context"
	"time"
)

// LogSourceRow is one (agent, event_type, source) stream over the last 24h.
type LogSourceRow struct {
	AgentID   string    `json:"agent_id"`
	Host      string    `json:"host"`
	EventType string    `json:"event_type"`
	Source    string    `json:"source"`
	Last1h    int64     `json:"events_1h"`
	Last24h   int64     `json:"events_24h"`
	LastSeen  time.Time `json:"last_event"`
	EPS1h     float64   `json:"eps_1h"`
	Silent    bool      `json:"silent"`
}

// ListLogSources summarises ingestion per agent/collector stream (P-10). A
// stream is "silent" when it produced events in the past 24h but none in the
// last `silentAfter`.
func (db *DB) ListLogSources(ctx context.Context, silentAfter time.Duration) ([]LogSourceRow, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT COALESCE(agent_id,''), COALESCE(host,''), COALESCE(event_type,''), COALESCE(source,''),
		       COUNT(*) FILTER (WHERE time > NOW() - INTERVAL '1 hour'),
		       COUNT(*),
		       MAX(time)
		FROM events
		WHERE time > NOW() - INTERVAL '24 hours'
		  AND event_type NOT IN ('health')
		GROUP BY 1,2,3,4
		ORDER BY 1,3,4
		LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cut := time.Now().Add(-silentAfter)
	var out []LogSourceRow
	for rows.Next() {
		var r LogSourceRow
		if err := rows.Scan(&r.AgentID, &r.Host, &r.EventType, &r.Source, &r.Last1h, &r.Last24h, &r.LastSeen); err != nil {
			continue
		}
		r.EPS1h = float64(r.Last1h) / 3600.0
		r.Silent = r.LastSeen.Before(cut)
		out = append(out, r)
	}
	return out, rows.Err()
}
