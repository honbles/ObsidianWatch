package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// ── DevOps Connector ──────────────────────────────────────────────────────────

type DevOpsConnector struct {
	ID            int64             `json:"id"`
	Provider      string            `json:"provider"`
	Org           string            `json:"org"`
	Label         string            `json:"label"`
	Credentials   map[string]string `json:"credentials"`
	Status        string            `json:"status"`
	LastSync      *time.Time        `json:"last_sync"`
	LastError     *string           `json:"last_error"`
	EventCount    int64             `json:"event_count"`
	SyncCursor    string            `json:"sync_cursor"`
	WebhookSecret string            `json:"webhook_secret,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
}

func (db *DB) ListDevOpsConnectors(ctx context.Context) ([]DevOpsConnector, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, provider, org, label, credentials, status,
		       last_sync, last_error, event_count, sync_cursor, webhook_secret, created_at
		FROM devops_connectors ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DevOpsConnector
	for rows.Next() {
		var c DevOpsConnector
		var credsJSON []byte
		var lastSync sql.NullTime
		var lastError sql.NullString
		if err := rows.Scan(&c.ID, &c.Provider, &c.Org, &c.Label,
			&credsJSON, &c.Status, &lastSync, &lastError,
			&c.EventCount, &c.SyncCursor, &c.WebhookSecret, &c.CreatedAt); err != nil {
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
		c.WebhookSecret = openString(c.WebhookSecret)
		// Mask secrets in API responses (the webhook secret is shown once, at creation).
		safe := maskCreds(c.Credentials)
		c.WebhookSecret = ""
		c.Credentials = safe
		out = append(out, c)
	}
	return out, rows.Err()
}

func (db *DB) GetDevOpsConnectorRaw(ctx context.Context, id int64) (*DevOpsConnector, error) {
	var c DevOpsConnector
	var credsJSON []byte
	var lastSync sql.NullTime
	var lastError sql.NullString
	err := db.QueryRowContext(ctx, `
		SELECT id, provider, org, label, credentials, status,
		       last_sync, last_error, event_count, sync_cursor, webhook_secret, created_at
		FROM devops_connectors WHERE id = $1`, id).Scan(
		&c.ID, &c.Provider, &c.Org, &c.Label,
		&credsJSON, &c.Status, &lastSync, &lastError,
		&c.EventCount, &c.SyncCursor, &c.WebhookSecret, &c.CreatedAt)
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
	c.WebhookSecret = openString(c.WebhookSecret)
	return &c, nil
}

func (db *DB) UpsertDevOpsConnector(ctx context.Context, provider, org, label string, creds map[string]string, webhookSecret string) (int64, error) {
	credsJSON, _ := json.Marshal(sealCreds(creds)) // CC-07 / DO-10: encrypt at rest
	webhookSecret = sealString(webhookSecret)
	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO devops_connectors (provider, org, label, credentials, status, webhook_secret)
		VALUES ($1, $2, $3, $4, 'pending', $5)
		ON CONFLICT (provider, org) DO NOTHING
		RETURNING id`,
		provider, org, label, credsJSON, webhookSecret,
	).Scan(&id)
	if err != nil {
		// Try update if exists
		err = db.QueryRowContext(ctx, `
			UPDATE devops_connectors SET credentials=$1, label=$2, webhook_secret=$3, status='pending'
			WHERE provider=$4 AND org=$5 RETURNING id`,
			credsJSON, label, webhookSecret, provider, org,
		).Scan(&id)
	}
	return id, err
}

func (db *DB) UpdateDevOpsConnectorStatus(ctx context.Context, id int64, status, errMsg string, ingested int64, cursor string) {
	if errMsg != "" {
		db.ExecContext(ctx, `
			UPDATE devops_connectors
			SET status=$1, last_error=$2, last_sync=NOW(), sync_cursor=$3
			WHERE id=$4`, status, errMsg, cursor, id)
	} else {
		db.ExecContext(ctx, `
			UPDATE devops_connectors
			SET status=$1, last_error=NULL, last_sync=NOW(),
			    event_count=event_count+$2, sync_cursor=$3
			WHERE id=$4`, status, ingested, cursor, id)
	}
}

// SetDevOpsConnectorNote stores a non-fatal coverage note (DO-05) in
// last_error without changing the connector status.
func (db *DB) SetDevOpsConnectorNote(ctx context.Context, id int64, note string) {
	db.ExecContext(ctx, `UPDATE devops_connectors SET last_error=$1 WHERE id=$2`, note, id)
}

func (db *DB) DeleteDevOpsConnector(ctx context.Context, id int64) error {
	_, err := db.ExecContext(ctx, `DELETE FROM devops_connectors WHERE id=$1`, id)
	return err
}

// ── DevOps Commits ────────────────────────────────────────────────────────────

type DevOpsCommit struct {
	ID             string          `json:"id"`
	ConnectorID    int64           `json:"connector_id"`
	Repo           string          `json:"repo"`
	Branch         string          `json:"branch"`
	AuthorName     string          `json:"author_name"`
	AuthorEmail    string          `json:"author_email"`
	AuthorUsername string          `json:"author_username"`
	Message        string          `json:"message"`
	URL            string          `json:"url"`
	FilesChanged   int             `json:"files_changed"`
	Additions      int             `json:"additions"`
	Deletions      int             `json:"deletions"`
	DiffSummary    json.RawMessage `json:"diff_summary"`
	PushedAt       time.Time       `json:"pushed_at"`
	CreatedAt      time.Time       `json:"created_at"`
}

type CommitFileDiff struct {
	File      string `json:"file"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Status    string `json:"status"` // added | modified | removed
	Patch     string `json:"patch,omitempty"`
}

// commitKey scopes a commit id to (connector, repo) so identical SHAs in
// forks, mirrors or two connectors no longer overwrite each other (DO-09).
func commitKey(c DevOpsCommit) string {
	sum := sha256.Sum256([]byte(c.Repo))
	return fmt.Sprintf("%d:%s:%s", c.ConnectorID, hex.EncodeToString(sum[:4]), c.ID)
}

func (db *DB) UpsertDevOpsCommit(ctx context.Context, c DevOpsCommit) error {
	c.ID = commitKey(c)
	_, err := db.ExecContext(ctx, `
		INSERT INTO devops_commits
		  (id, connector_id, repo, branch, author_name, author_email, author_username,
		   message, url, files_changed, additions, deletions, diff_summary, pushed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (id) DO NOTHING`,
		c.ID, c.ConnectorID, c.Repo, c.Branch,
		c.AuthorName, c.AuthorEmail, c.AuthorUsername,
		c.Message, c.URL, c.FilesChanged, c.Additions, c.Deletions,
		c.DiffSummary, c.PushedAt)
	return err
}

func (db *DB) ListDevOpsCommits(ctx context.Context, connectorID int64, repo string, limit int) ([]DevOpsCommit, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if repo != "" {
		rows, err = db.QueryContext(ctx, `
			SELECT id, connector_id, repo, branch, author_name, author_email, author_username,
			       message, url, files_changed, additions, deletions, diff_summary, pushed_at, created_at
			FROM devops_commits WHERE connector_id=$1 AND repo=$2
			ORDER BY pushed_at DESC LIMIT $3`, connectorID, repo, limit)
	} else {
		rows, err = db.QueryContext(ctx, `
			SELECT id, connector_id, repo, branch, author_name, author_email, author_username,
			       message, url, files_changed, additions, deletions, diff_summary, pushed_at, created_at
			FROM devops_commits WHERE connector_id=$1
			ORDER BY pushed_at DESC LIMIT $2`, connectorID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DevOpsCommit
	for rows.Next() {
		var c DevOpsCommit
		if err := rows.Scan(&c.ID, &c.ConnectorID, &c.Repo, &c.Branch,
			&c.AuthorName, &c.AuthorEmail, &c.AuthorUsername,
			&c.Message, &c.URL, &c.FilesChanged, &c.Additions, &c.Deletions,
			&c.DiffSummary, &c.PushedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (db *DB) GetDevOpsCommit(ctx context.Context, id string) (*DevOpsCommit, error) {
	var c DevOpsCommit
	err := db.QueryRowContext(ctx, `
		SELECT id, connector_id, repo, branch, author_name, author_email, author_username,
		       message, url, files_changed, additions, deletions, diff_summary, pushed_at, created_at
		FROM devops_commits WHERE id=$1`, id).Scan(
		&c.ID, &c.ConnectorID, &c.Repo, &c.Branch,
		&c.AuthorName, &c.AuthorEmail, &c.AuthorUsername,
		&c.Message, &c.URL, &c.FilesChanged, &c.Additions, &c.Deletions,
		&c.DiffSummary, &c.PushedAt, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ListDevOpsConnectorsRaw returns connectors with raw credentials (for internal engine use only)
func (db *DB) ListDevOpsConnectorsRaw(ctx context.Context) ([]DevOpsConnector, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, provider, org, label, credentials, status,
		       last_sync, last_error, event_count, sync_cursor, webhook_secret, created_at
		FROM devops_connectors ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DevOpsConnector
	for rows.Next() {
		var c DevOpsConnector
		var credsJSON []byte
		var lastSync sql.NullTime
		var lastError sql.NullString
		if err := rows.Scan(&c.ID, &c.Provider, &c.Org, &c.Label,
			&credsJSON, &c.Status, &lastSync, &lastError,
			&c.EventCount, &c.SyncCursor, &c.WebhookSecret, &c.CreatedAt); err != nil {
			return nil, err
		}
		if lastSync.Valid { c.LastSync = &lastSync.Time }
		if lastError.Valid { c.LastError = &lastError.String }
		json.Unmarshal(credsJSON, &c.Credentials)
		openCreds(c.Credentials)
		c.WebhookSecret = openString(c.WebhookSecret)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListDevOpsRepos returns distinct repos and their default branches for a connector.
func (db *DB) ListDevOpsRepos(ctx context.Context, connectorID int64) ([]struct {
	Repo   string
	Branch string
}, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT ON (repo) repo, branch
		FROM devops_commits
		WHERE connector_id = $1
		ORDER BY repo, pushed_at DESC`, connectorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct {
		Repo   string
		Branch string
	}
	for rows.Next() {
		var r struct {
			Repo   string
			Branch string
		}
		if err := rows.Scan(&r.Repo, &r.Branch); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
