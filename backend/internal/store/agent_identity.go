package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	// ErrTokenInvalid covers unknown, expired, revoked and used-up tokens
	// alike, so a caller cannot probe which one it hit.
	ErrTokenInvalid = errors.New("store: enrollment token invalid")
	// ErrIdentityRevoked is returned when renewing a revoked identity.
	ErrIdentityRevoked = errors.New("store: agent identity revoked")
)

// AgentIdentity is one enrolled agent certificate identity.
type AgentIdentity struct {
	AgentID      string
	Hostname     string
	OS           string
	TokenID      *int64
	CertSerial   string
	CertNotAfter time.Time
	EnrolledFrom string
}

// ConsumeEnrollmentToken atomically spends one use of a live token.
func (db *DB) ConsumeEnrollmentToken(ctx context.Context, tokenHash string) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, `
		UPDATE agent_enrollment_tokens SET uses = uses + 1
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW() AND uses < max_uses
		RETURNING id`, tokenHash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrTokenInvalid
	}
	return id, err
}

// CreateAgentIdentity records a newly issued identity.
func (db *DB) CreateAgentIdentity(ctx context.Context, in AgentIdentity) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO agent_identities (agent_id, hostname, os, token_id, enrolled_from, cert_serial, cert_not_after)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		in.AgentID, in.Hostname, in.OS, in.TokenID, in.EnrolledFrom, in.CertSerial, in.CertNotAfter)
	return err
}

// RenewAgentIdentity records a renewed certificate unless the identity is revoked.
func (db *DB) RenewAgentIdentity(ctx context.Context, agentID, serial string, notAfter time.Time) error {
	res, err := db.ExecContext(ctx, `
		UPDATE agent_identities SET cert_serial = $2, cert_not_after = $3, renewed_at = NOW()
		WHERE agent_id = $1 AND revoked_at IS NULL`, agentID, serial, notAfter)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrIdentityRevoked
	}
	return nil
}

// RevokedAgentIDs lists every revoked identity, for the revocation cache.
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

// PublishAgentCA stores the agent CA certificate (public part only) so the
// management server can verify tunnel certificates without the CA key.
func (db *DB) PublishAgentCA(ctx context.Context, certPEM string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO agent_ca (id, cert_pem) VALUES (1, $1)
		ON CONFLICT (id) DO UPDATE SET cert_pem = EXCLUDED.cert_pem, updated_at = NOW()
		WHERE agent_ca.cert_pem <> EXCLUDED.cert_pem`, certPEM)
	return err
}
