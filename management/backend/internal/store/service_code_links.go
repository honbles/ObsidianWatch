package store

import (
	"context"
	"time"

	"github.com/lib/pq"
)

// ServiceCodeLink ties a monitored service to a repository branch.
type ServiceCodeLink struct {
	ID          int64     `json:"id"`
	ServiceID   int64     `json:"service_id"`
	ConnectorID int64     `json:"connector_id"`
	Repo        string    `json:"repo"`
	Branch      string    `json:"branch"`
	IsDefault   bool      `json:"is_default"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// ServiceCodeLinks returns the links of the given services (all when ids is nil).
func (db *DB) ServiceCodeLinks(ctx context.Context, ids []int64) ([]ServiceCodeLink, error) {
	q := `SELECT id, service_id, connector_id, repo, branch, is_default, created_by, created_at FROM service_code_links`
	args := []interface{}{}
	if ids != nil {
		q += ` WHERE service_id = ANY($1)`
		args = append(args, pq.Array(ids))
	}
	q += ` ORDER BY service_id, id`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ServiceCodeLink{}
	for rows.Next() {
		var l ServiceCodeLink
		if err := rows.Scan(&l.ID, &l.ServiceID, &l.ConnectorID, &l.Repo, &l.Branch, &l.IsDefault, &l.CreatedBy, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// UpsertServiceCodeLink adds a link, or changes the branch of an existing one.
func (db *DB) UpsertServiceCodeLink(ctx context.Context, l ServiceCodeLink) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO service_code_links (service_id, connector_id, repo, branch, is_default, created_by)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (service_id, connector_id, repo) DO UPDATE SET branch = EXCLUDED.branch, is_default = EXCLUDED.is_default
		RETURNING id`, l.ServiceID, l.ConnectorID, l.Repo, l.Branch, l.IsDefault, l.CreatedBy).Scan(&id)
	return id, err
}

// DeleteServiceCodeLink removes one link of a service.
func (db *DB) DeleteServiceCodeLink(ctx context.Context, serviceID, linkID int64) (bool, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM service_code_links WHERE id = $1 AND service_id = $2`, linkID, serviceID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeleteServiceCodeLinksForConnector removes the links to a removed connector.
func (db *DB) DeleteServiceCodeLinksForConnector(ctx context.Context, connID int64) {
	_, _ = db.ExecContext(ctx, `DELETE FROM service_code_links WHERE connector_id = $1`, connID)
}
