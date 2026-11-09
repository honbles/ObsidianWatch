package store

import (
	"context"
	"database/sql"
	"time"
)

// EngineCursor (D-01/D-02) is a named engine's persisted position in the
// events.ingested_at timeline. Replacing wall-clock polling windows with
// this means an engine that falls behind (slow processing, a restart, a
// burst of backlogged events) simply resumes exactly where it left off —
// it can never silently skip a range of events the way a fixed "now minus
// N minutes" window can when N is smaller than however long the gap was.
type EngineCursor struct {
	EngineName string    `json:"engine_name"`
	CursorAt   time.Time `json:"cursor_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// GetEngineCursor returns the engine's cursor, or the zero time if it has
// never run before (caller decides the initial catch-up window in that case).
func (db *DB) GetEngineCursor(ctx context.Context, engineName string) (time.Time, error) {
	var cursorAt time.Time
	err := db.QueryRowContext(ctx,
		`SELECT cursor_at FROM engine_cursors WHERE engine_name = $1`, engineName,
	).Scan(&cursorAt)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	return cursorAt, err
}

// AdvanceEngineCursor moves the engine's cursor forward. Called even when
// zero events were found, so a quiet period doesn't leave an engine
// perpetually re-scanning an ever-widening range on its next poll.
func (db *DB) AdvanceEngineCursor(ctx context.Context, engineName string, cursorAt time.Time) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO engine_cursors (engine_name, cursor_at, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (engine_name) DO UPDATE SET
			cursor_at  = EXCLUDED.cursor_at,
			updated_at = NOW()
		WHERE engine_cursors.cursor_at < EXCLUDED.cursor_at
	`, engineName, cursorAt.UTC())
	return err
}

// ListEngineCursors returns all known engine cursors, newest-updated first —
// used by the D-11 agent/engine health check to spot a stalled engine.
func (db *DB) ListEngineCursors(ctx context.Context) ([]EngineCursor, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT engine_name, cursor_at, updated_at FROM engine_cursors ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EngineCursor
	for rows.Next() {
		var c EngineCursor
		if err := rows.Scan(&c.EngineName, &c.CursorAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
