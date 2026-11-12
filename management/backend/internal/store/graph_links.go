package store

import (
	"context"
	"strconv"
	"time"

	"github.com/lib/pq"
)

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

const graphEventCols = `id, time, agent_id, host, os, event_type, severity, source, raw,
		       pid, ppid, process_name, command_line, image_path, user_name, domain, logon_id,
		       src_ip, src_port, dst_ip, dst_port, proto,
		       reg_key, reg_value, reg_data, file_path, file_hash,
		       event_id, channel, record_id,
		       COALESCE(process_guid,''), COALESCE(parent_process_guid,'')`

// EventsByProcessGUIDs returns events whose process_guid is in guids, oldest
// first. One query for a whole set of processes (never one per process).
func (db *DB) EventsByProcessGUIDs(ctx context.Context, agentID string, guids []string, from, to time.Time, limit int) ([]Event, error) {
	return db.graphEvents(ctx, `agent_id=$1 AND process_guid = ANY($2) AND time BETWEEN $3 AND $4`, agentID, guids, from, to, limit)
}

// EventsByParentGUIDs returns events whose parent_process_guid is in guids
// (the process-create events of their children), oldest first.
func (db *DB) EventsByParentGUIDs(ctx context.Context, agentID string, guids []string, from, to time.Time, limit int) ([]Event, error) {
	return db.graphEvents(ctx, `agent_id=$1 AND parent_process_guid = ANY($2) AND time BETWEEN $3 AND $4`, agentID, guids, from, to, limit)
}

// EventsByPID is the no-GUID fallback: events for one pid on one agent.
func (db *DB) EventsByPID(ctx context.Context, agentID string, pid int, from, to time.Time, limit int) ([]Event, error) {
	return db.graphEvents(ctx, `agent_id=$1 AND pid = $2 AND time BETWEEN $3 AND $4`, agentID, pid, from, to, limit)
}

func (db *DB) graphEvents(ctx context.Context, where string, agentID string, key interface{}, from, to time.Time, limit int) ([]Event, error) {
	if limit <= 0 || limit > 20000 {
		limit = 5000
	}
	if g, ok := key.([]string); ok {
		key = pq.Array(g)
	}
	rows, err := db.QueryContext(ctx, `SELECT `+graphEventCols+` FROM events WHERE `+where+
		` ORDER BY time ASC LIMIT `+strconv.Itoa(limit), agentID, key, from.UTC(), to.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// AlertEntityMap returns, for the given keys of one entity kind, the newest
// alert IDs linked to each (up to perKey). One query for the whole graph.
func (db *DB) AlertEntityMap(ctx context.Context, kind string, keys []string, perKey int) (map[string][]int64, error) {
	out := map[string][]int64{}
	if len(keys) == 0 {
		return out, nil
	}
	if perKey <= 0 {
		perKey = 5
	}
	rows, err := db.QueryContext(ctx, `
		SELECT key, alert_id FROM (
		  SELECT key, alert_id, ROW_NUMBER() OVER (PARTITION BY key ORDER BY alert_id DESC) rn
		  FROM alert_entities WHERE kind=$1 AND key = ANY($2)
		) t WHERE rn <= $3 ORDER BY key, alert_id DESC`, kind, pq.Array(keys), perKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var id int64
		if err := rows.Scan(&k, &id); err != nil {
			return nil, err
		}
		out[k] = append(out[k], id)
	}
	return out, rows.Err()
}
