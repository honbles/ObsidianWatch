package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ── Credential Management ─────────────────────────────────────────────────────

type LRCredential struct {
	AgentID   string    `json:"agent_id"`
	Username  string    `json:"username"`
	Mode      string    `json:"mode"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpsertLRCredential records that an agent has a live-response session
// mode registered. M-05: this previously also stored a bcrypt hash AND a
// plaintext password, neither of which is read back anywhere in the
// backend — a DB leak handed over a live credential for every agent for
// nothing. Only the username (for display) and mode are persisted now.
func (db *DB) UpsertLRCredential(ctx context.Context, agentID, username, mode string) error {
	if mode == "" {
		mode = "direct-shell"
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO lr_credentials (agent_id, username, mode, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		ON CONFLICT (agent_id) DO UPDATE SET
			username   = EXCLUDED.username,
			mode       = EXCLUDED.mode,
			updated_at = NOW()
	`, agentID, username, mode)
	return err
}

// GetLRCredential fetches the stored credential record for an agent.
func (db *DB) GetLRCredential(ctx context.Context, agentID string) (username, mode string, err error) {
	err = db.QueryRowContext(ctx,
		`SELECT username, mode FROM lr_credentials WHERE agent_id = $1`,
		agentID,
	).Scan(&username, &mode)
	if err == sql.ErrNoRows {
		return "", "", fmt.Errorf("no live response credentials for agent %q", agentID)
	}
	return username, mode, err
}

// ListLRCredentials returns which agents have credentials registered.
func (db *DB) ListLRCredentials(ctx context.Context) ([]LRCredential, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT agent_id, username, mode, created_at, updated_at
		FROM lr_credentials ORDER BY updated_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []LRCredential
	for rows.Next() {
		var c LRCredential
		if err := rows.Scan(&c.AgentID, &c.Username, &c.Mode, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

// ── Session Management ────────────────────────────────────────────────────────

type LRSession struct {
	ID           int64      `json:"id"`
	AgentID      string     `json:"agent_id"`
	InitiatedBy  string     `json:"initiated_by"`
	SessionToken string     `json:"session_token,omitempty"`
	Protocol     string     `json:"protocol"`
	Status       string     `json:"status"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// CreateLRSession records a new session request and returns its ID.
func (db *DB) CreateLRSession(ctx context.Context, agentID, initiatedBy, token, protocol string) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO lr_sessions (agent_id, initiated_by, session_token, protocol, status, created_at)
		VALUES ($1, $2, $3, $4, 'pending', NOW())
		RETURNING id
	`, agentID, initiatedBy, token, protocol).Scan(&id)
	return id, err
}

// UpdateLRSessionStatus updates the status and timestamps of a session.
func (db *DB) UpdateLRSessionStatus(ctx context.Context, token, status string) error {
	var err error
	switch status {
	case "active":
		_, err = db.ExecContext(ctx,
			`UPDATE lr_sessions SET status=$1, started_at=NOW() WHERE session_token=$2`,
			status, token)
	case "closed", "failed":
		_, err = db.ExecContext(ctx,
			`UPDATE lr_sessions SET status=$1, ended_at=NOW() WHERE session_token=$2`,
			status, token)
	default:
		_, err = db.ExecContext(ctx,
			`UPDATE lr_sessions SET status=$1 WHERE session_token=$2`,
			status, token)
	}
	return err
}

// GetLRSession fetches a session by token.
func (db *DB) GetLRSession(ctx context.Context, token string) (*LRSession, error) {
	s := &LRSession{}
	err := db.QueryRowContext(ctx, `
		SELECT id, agent_id, initiated_by, session_token, protocol, status,
		       started_at, ended_at, created_at
		FROM lr_sessions WHERE session_token = $1
	`, token).Scan(
		&s.ID, &s.AgentID, &s.InitiatedBy, &s.SessionToken,
		&s.Protocol, &s.Status, &s.StartedAt, &s.EndedAt, &s.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ListLRSessions returns recent sessions, optionally filtered by agent.
func (db *DB) ListLRSessions(ctx context.Context, agentID string, limit int) ([]LRSession, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if agentID != "" {
		rows, err = db.QueryContext(ctx, `
			SELECT id, agent_id, initiated_by, session_token, protocol, status,
			       started_at, ended_at, created_at
			FROM lr_sessions WHERE agent_id = $1
			ORDER BY created_at DESC LIMIT $2
		`, agentID, limit)
	} else {
		rows, err = db.QueryContext(ctx, `
			SELECT id, agent_id, initiated_by, session_token, protocol, status,
			       started_at, ended_at, created_at
			FROM lr_sessions ORDER BY created_at DESC LIMIT $1
		`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []LRSession
	for rows.Next() {
		var s LRSession
		if err := rows.Scan(
			&s.ID, &s.AgentID, &s.InitiatedBy, &s.SessionToken,
			&s.Protocol, &s.Status, &s.StartedAt, &s.EndedAt, &s.CreatedAt,
		); err != nil {
			return nil, err
		}
		// Strip token from list view
		s.SessionToken = ""
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

// ClaimLRSession atomically moves a session from 'pending' to 'active'.
// A session token is therefore single-use (F-04): a second connection with
// the same token, or one after the session ended, finds no pending row.
func (db *DB) ClaimLRSession(ctx context.Context, token string) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE lr_sessions SET status='active', started_at=NOW()
		WHERE session_token=$1 AND status='pending'`, token)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// AppendLRTranscript records a chunk of session I/O. Total stored bytes per
// session are capped (2 MiB) so a noisy session can't fill the database.
func (db *DB) AppendLRTranscript(ctx context.Context, sessionID int64, direction string, data []byte) {
	if len(data) == 0 {
		return
	}
	if len(data) > 16<<10 {
		data = data[:16<<10]
	}
	_, _ = db.ExecContext(ctx, `
		INSERT INTO lr_transcripts (session_id, direction, data)
		SELECT $1, $2, $3
		WHERE COALESCE((SELECT SUM(octet_length(data)) FROM lr_transcripts WHERE session_id=$1), 0) < 2097152`,
		sessionID, direction, data)
}
