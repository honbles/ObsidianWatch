package store

import (
	"context"
	"strings"
	"time"

	"obsidianwatch/management/internal/telemetry"
)

type AuditEntry struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
	IPAddress string    `json:"ip_address"`
}

func (db *DB) WriteAudit(ctx context.Context, username, action, target, detail, ip string) {
	// Fire-and-forget - audit failures should never break the main request
	db.ExecContext(ctx, `
		INSERT INTO audit_log (username, action, target, detail, ip_address)
		VALUES ($1, $2, $3, $4, $5)
	`, username, action, target, detail, ip)
	auditEvent(ctx, username, action, target, ip)
}

// auditEvent mirrors an audit entry as a security event (Tier 2 helper): sign-ins
// become auth.login, downloads data.export, everything else admin.action.
func auditEvent(ctx context.Context, username, action, target, ip string) {
	// "api:<method>" entries are the generic record of every write; the
	// handlers' own entries (create_user, ...) are the ones worth an event.
	if !telemetry.Enabled() || strings.HasPrefix(action, "api:") {
		return
	}
	typ, id, _ := strings.Cut(target, ":")
	if id == "" {
		typ, id = "", target
	}
	switch action {
	case "login":
		telemetry.Event(ctx, "auth.login", "outcome", "success", "method", "password", "user", username, "client.address", ip)
	case "login_failed":
		telemetry.Event(ctx, "auth.login", "outcome", "failure", "method", "password", "reason", "invalid_credentials",
			"user", username, "client.address", ip)
	case "logout", "nl_search":
	case "export_events":
		telemetry.Event(ctx, "data.export", "outcome", "success", "object_type", "events", "user", username, "client.address", ip)
	case "response_collect_download":
		telemetry.Event(ctx, "data.export", "outcome", "success", "object_type", "collected_file", "object_id", id,
			"user", username, "client.address", ip)
	default:
		telemetry.Event(ctx, "admin.action", "action", action, "outcome", "success", "target_type", typ, "target_id", id,
			"user", username, "client.address", ip)
	}
}

func (db *DB) ListAuditLog(ctx context.Context, limit, offset int) ([]AuditEntry, int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var total int64
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&total)

	rows, err := db.QueryContext(ctx, `
		SELECT id, created_at, username, action, target, detail, ip_address
		FROM audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.CreatedAt, &e.Username, &e.Action, &e.Target, &e.Detail, &e.IPAddress); err != nil {
			return nil, 0, err
		}
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}
