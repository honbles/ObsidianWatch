package store

import (
	"context"
	"database/sql"
	"time"
)

type DetectionSignatureState struct {
	ID        string
	Enabled   bool
	Severity  *int
	UpdatedAt time.Time
}

// GetSignatureStates returns enable/disable states for all signatures.
// Only rows that exist in the DB are returned — missing = use default (enabled).
func (db *DB) GetSignatureStates(ctx context.Context) (map[string]DetectionSignatureState, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, enabled, severity, updated_at FROM detection_signatures`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]DetectionSignatureState)
	for rows.Next() {
		var s DetectionSignatureState
		var sev sql.NullInt64
		if err := rows.Scan(&s.ID, &s.Enabled, &sev, &s.UpdatedAt); err != nil {
			continue
		}
		if sev.Valid {
			v := int(sev.Int64)
			s.Severity = &v
		}
		result[s.ID] = s
	}
	return result, rows.Err()
}

// SetSignatureEnabled enables or disables a signature by ID.
func (db *DB) SetSignatureEnabled(ctx context.Context, id string, enabled bool) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO detection_signatures (id, enabled, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (id) DO UPDATE SET enabled = $2, updated_at = NOW()
	`, id, enabled)
	return err
}

// SetSignatureSeverity overrides severity for a signature.
func (db *DB) SetSignatureSeverity(ctx context.Context, id string, severity int) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO detection_signatures (id, enabled, severity, updated_at)
		VALUES ($1, TRUE, $2, NOW())
		ON CONFLICT (id) DO UPDATE SET severity = $2, updated_at = NOW()
	`, id, severity)
	return err
}
