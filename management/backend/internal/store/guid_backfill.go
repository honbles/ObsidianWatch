package store

import (
	"context"
	"time"
)

// BackfillProcessGUIDs fills events.process_guid / parent_process_guid from
// raw for rows ingested before migration 009, so the Alert Graph works on
// existing alerts. It walks the last `days` days in one-hour slices (bounded
// work per statement) and records completion in settings so it runs once.
func (db *DB) BackfillProcessGUIDs(ctx context.Context, days int) (int64, error) {
	const marker = "graph.guid_backfill_done"
	if v, _ := db.GetSetting(ctx, marker); v != "" {
		return 0, nil
	}
	var total int64
	end := time.Now().UTC().Truncate(time.Hour).Add(time.Hour)
	for t := end; t.After(end.AddDate(0, 0, -days)); t = t.Add(-time.Hour) {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		res, err := db.ExecContext(ctx, `
			UPDATE events SET
			  process_guid = COALESCE(NULLIF(raw->>'process_guid',''), NULLIF(raw->'event_data'->>'ProcessGuid',''), NULLIF(raw->'event_data'->>'SourceProcessGuid','')),
			  parent_process_guid = COALESCE(NULLIF(raw->>'parent_process_guid',''), NULLIF(raw->'event_data'->>'ParentProcessGuid',''))
			WHERE time >= $1 AND time < $2 AND process_guid IS NULL
			  AND (raw ? 'process_guid' OR raw->'event_data' ? 'ProcessGuid' OR raw->'event_data' ? 'SourceProcessGuid')`,
			t.Add(-time.Hour), t)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		time.Sleep(50 * time.Millisecond) // be gentle with the primary
	}
	return total, db.SetSetting(ctx, marker, time.Now().UTC().Format(time.RFC3339))
}
