package store

import "context"

// LinkAlertEntityCapped links an alert to an entity unless the alert already
// has max links of that kind. Used when a duplicate alert fires for a new
// process: the alert keeps accumulating anchors without growing unbounded.
func (db *DB) LinkAlertEntityCapped(ctx context.Context, alertID int64, kind, key string, max int) error {
	if alertID == 0 || kind == "" || key == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO alert_entities (alert_id, kind, key)
		SELECT $1,$2,$3
		WHERE (SELECT COUNT(*) FROM alert_entities WHERE alert_id=$1 AND kind=$2) < $4
		ON CONFLICT DO NOTHING`, alertID, kind, key, max)
	return err
}

// AlertEntities returns every (kind,key) linked to an alert, oldest first.
func (db *DB) AlertEntities(ctx context.Context, alertID int64) ([][2]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT kind, key FROM alert_entities WHERE alert_id=$1 ORDER BY ctid`, alertID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out = append(out, [2]string{k, v})
	}
	return out, rows.Err()
}
