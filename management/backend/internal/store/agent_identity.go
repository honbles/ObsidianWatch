package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// EnrollmentToken is an agent enrollment token (plain value is never stored).
type EnrollmentToken struct {
	ID        int64      `json:"id"`
	Label     string     `json:"label"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	MaxUses   int        `json:"max_uses"`
	Uses      int        `json:"uses"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RevokedBy *string    `json:"revoked_by,omitempty"`
}

// AgentIdentity is an enrolled, certificate-backed agent identity.
type AgentIdentity struct {
	AgentID      string     `json:"agent_id"`
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	TokenID      *int64     `json:"token_id,omitempty"`
	TokenLabel   *string    `json:"token_label,omitempty"`
	EnrolledAt   time.Time  `json:"enrolled_at"`
	EnrolledFrom string     `json:"enrolled_from"`
	CertSerial   string     `json:"cert_serial"`
	CertNotAfter time.Time  `json:"cert_not_after"`
	RenewedAt    *time.Time `json:"renewed_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokedBy    *string    `json:"revoked_by,omitempty"`
	RevokeReason *string    `json:"revoke_reason,omitempty"`
}

func (db *DB) CreateEnrollmentToken(ctx context.Context, hash, label, by string, expires time.Time, maxUses int) (EnrollmentToken, error) {
	var t EnrollmentToken
	err := db.QueryRowContext(ctx, `
		INSERT INTO agent_enrollment_tokens (token_hash, label, created_by, expires_at, max_uses)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, label, created_by, created_at, expires_at, max_uses, uses, revoked_at, revoked_by`,
		hash, label, by, expires, maxUses).Scan(&t.ID, &t.Label, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.RevokedAt, &t.RevokedBy)
	return t, err
}

func (db *DB) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, label, created_by, created_at, expires_at, max_uses, uses, revoked_at, revoked_by
		FROM agent_enrollment_tokens ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EnrollmentToken{}
	for rows.Next() {
		var t EnrollmentToken
		if err := rows.Scan(&t.ID, &t.Label, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.RevokedAt, &t.RevokedBy); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ErrNotFound is returned when nothing matched (or it was already revoked).
var ErrNotFound = errors.New("store: not found")

func (db *DB) RevokeEnrollmentToken(ctx context.Context, id int64, by string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE agent_enrollment_tokens SET revoked_at = NOW(), revoked_by = $2
		WHERE id = $1 AND revoked_at IS NULL`, id, by)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (db *DB) ListAgentIdentities(ctx context.Context) ([]AgentIdentity, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT i.agent_id, i.hostname, i.os, i.token_id, t.label, i.enrolled_at, i.enrolled_from,
		       i.cert_serial, i.cert_not_after, i.renewed_at, i.revoked_at, i.revoked_by, i.revoke_reason
		FROM agent_identities i LEFT JOIN agent_enrollment_tokens t ON t.id = i.token_id
		ORDER BY i.enrolled_at DESC LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentIdentity{}
	for rows.Next() {
		var a AgentIdentity
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.OS, &a.TokenID, &a.TokenLabel, &a.EnrolledAt, &a.EnrolledFrom,
			&a.CertSerial, &a.CertNotAfter, &a.RenewedAt, &a.RevokedAt, &a.RevokedBy, &a.RevokeReason); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (db *DB) RevokeAgentIdentity(ctx context.Context, agentID, by, reason string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE agent_identities SET revoked_at = NOW(), revoked_by = $2, revoke_reason = $3
		WHERE agent_id = $1 AND revoked_at IS NULL`, agentID, by, reason)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (db *DB) RevokedAgentIDs(ctx context.Context) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT agent_id FROM agent_identities WHERE revoked_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AgentCACert returns the agent CA certificate published by the ingest
// backend, or "" when none has been published yet.
func (db *DB) AgentCACert(ctx context.Context) (string, error) {
	var pem string
	err := db.QueryRowContext(ctx, `SELECT cert_pem FROM agent_ca WHERE id = 1`).Scan(&pem)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return pem, err
}
