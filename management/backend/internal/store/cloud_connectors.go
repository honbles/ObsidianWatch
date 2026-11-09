package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type CloudConnector struct {
	ID           int64             `json:"id"`
	Provider     string            `json:"provider"`
	AccountID    string            `json:"account_id"`
	AccountLabel string            `json:"account_label"`
	Credentials  map[string]string `json:"credentials"`
	Status       string            `json:"status"`
	LastSync     *time.Time        `json:"last_sync"`
	LastError    *string           `json:"last_error"`
	EventCount   int64             `json:"event_count"`
	SyncCursor   string            `json:"sync_cursor"`
	CreatedAt    time.Time         `json:"created_at"`
}

func (db *DB) ListCloudConnectors(ctx context.Context) ([]CloudConnector, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, provider, account_id, account_label, credentials,
		       status, last_sync, last_error, event_count, COALESCE(sync_cursor,''), created_at
		FROM cloud_connectors ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CloudConnector
	for rows.Next() {
		var c CloudConnector
		var credsJSON []byte
		var lastSync sql.NullTime
		var lastError sql.NullString
		if err := rows.Scan(&c.ID, &c.Provider, &c.AccountID, &c.AccountLabel,
			&credsJSON, &c.Status, &lastSync, &lastError,
			&c.EventCount, &c.SyncCursor, &c.CreatedAt); err != nil {
			return nil, err
		}
		if lastSync.Valid {
			c.LastSync = &lastSync.Time
		}
		if lastError.Valid {
			c.LastError = &lastError.String
		}
		// Don't return secret values to frontend
		var creds map[string]string
		json.Unmarshal(credsJSON, &creds)
		openCreds(creds)
		safe := maskCreds(creds)
		c.Credentials = safe
		out = append(out, c)
	}
	return out, rows.Err()
}

func (db *DB) GetCloudConnectorRaw(ctx context.Context, id int64) (*CloudConnector, error) {
	var c CloudConnector
	var credsJSON []byte
	var lastSync sql.NullTime
	var lastError sql.NullString
	err := db.QueryRowContext(ctx, `
		SELECT id, provider, account_id, account_label, credentials,
		       status, last_sync, last_error, event_count, COALESCE(sync_cursor,''), created_at
		FROM cloud_connectors WHERE id = $1`, id).Scan(
		&c.ID, &c.Provider, &c.AccountID, &c.AccountLabel,
		&credsJSON, &c.Status, &lastSync, &lastError,
		&c.EventCount, &c.SyncCursor, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	if lastSync.Valid {
		c.LastSync = &lastSync.Time
	}
	if lastError.Valid {
		c.LastError = &lastError.String
	}
	json.Unmarshal(credsJSON, &c.Credentials)
	openCreds(c.Credentials)
	return &c, nil
}

func (db *DB) GetCloudConnectorByProvider(ctx context.Context, provider string) (*CloudConnector, error) {
	var c CloudConnector
	var credsJSON []byte
	var lastSync sql.NullTime
	var lastError sql.NullString
	err := db.QueryRowContext(ctx, `
		SELECT id, provider, account_id, account_label, credentials,
		       status, last_sync, last_error, event_count, COALESCE(sync_cursor,''), created_at
		FROM cloud_connectors WHERE provider = $1 LIMIT 1`, provider).Scan(
		&c.ID, &c.Provider, &c.AccountID, &c.AccountLabel,
		&credsJSON, &c.Status, &lastSync, &lastError,
		&c.EventCount, &c.SyncCursor, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	if lastSync.Valid {
		c.LastSync = &lastSync.Time
	}
	if lastError.Valid {
		c.LastError = &lastError.String
	}
	json.Unmarshal(credsJSON, &c.Credentials)
	openCreds(c.Credentials)
	return &c, nil
}

func (db *DB) UpsertCloudConnector(ctx context.Context, provider string, creds map[string]string) (int64, error) {
	credsJSON, _ := json.Marshal(sealCreds(creds)) // CC-07: encrypt at rest
	accountID := creds["account_id"]
	if accountID == "" {
		accountID = creds["project_id"]
	}
	if accountID == "" {
		accountID = creds["subscription_id"]
	}

	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO cloud_connectors (provider, account_id, credentials, status)
		VALUES ($1, $2, $3, 'pending')
		ON CONFLICT (provider, account_id) DO NOTHING
		RETURNING id`, provider, accountID, credsJSON).Scan(&id)
	if err == sql.ErrNoRows {
		// Already exists — update credentials
		err = db.QueryRowContext(ctx, `
			UPDATE cloud_connectors SET credentials=$1, updated_at=NOW()
			WHERE provider=$2 AND account_id=$3 RETURNING id`, credsJSON, provider, accountID).Scan(&id)
	}
	return id, err
}

// UpdateCloudConnectorStatus records the outcome of a sync attempt.
//
// G-01: sync_cursor is the per-connector watermark (the max log-source
// timestamp — e.g. GCP receiveTimestamp — successfully ingested). A failed
// or partial sync must never erase progress already made, so an empty
// cursor here leaves the existing one in place (COALESCE/NULLIF) instead
// of always overwriting it with NULL. Callers pass whatever cursor value
// reflects what was *actually* durably ingested, including on a partial
// failure — not just on full success — so a crash mid-sync doesn't lose
// the ground already covered.
func (db *DB) UpdateCloudConnectorStatus(ctx context.Context, id int64, status, lastError string, eventCount int64, cursor string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE cloud_connectors
		SET status=$1, last_error=NULLIF($2,''), last_sync=NOW(),
		    event_count=event_count+$3,
		    sync_cursor=COALESCE(NULLIF($4,''), sync_cursor),
		    updated_at=NOW()
		WHERE id=$5`, status, lastError, eventCount, cursor, id)
	return err
}

func (db *DB) DeleteCloudConnector(ctx context.Context, id int64) error {
	_, err := db.ExecContext(ctx, `DELETE FROM cloud_connectors WHERE id=$1`, id)
	return err
}

// UpdateCloudConnectorAccount sets the account_id and label after successful auth.
func (db *DB) UpdateCloudConnectorAccount(ctx context.Context, id int64, accountID, label string) {
	db.ExecContext(ctx,
		`UPDATE cloud_connectors SET account_id=$1, account_label=$2, updated_at=NOW() WHERE id=$3 AND (account_id IS NULL OR account_id='')`,
		accountID, label, id)
}

// SetCloudConnectorLabel sets a human-readable label unconditionally.
func (db *DB) SetCloudConnectorLabel(ctx context.Context, id int64, label string) {
	db.ExecContext(ctx, `UPDATE cloud_connectors SET account_label=$1, updated_at=NOW() WHERE id=$2`, label, id)
}
