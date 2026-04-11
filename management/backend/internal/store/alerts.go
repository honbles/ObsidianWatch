package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type Alert struct {
	ID             int64      `json:"id"`
	CreatedAt      time.Time  `json:"created_at"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Severity       int        `json:"severity"`
	Status         string     `json:"status"`
	AgentID        string     `json:"agent_id"`
	Host           string     `json:"host"`
	EventType      string     `json:"event_type"`
	EventID        string     `json:"event_id"`
	SourceEventID  string     `json:"source_event_id,omitempty"`
	AcknowledgedBy *string    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	AssignedTo     *string    `json:"assigned_to,omitempty"`
	CaseNotes      *string    `json:"case_notes,omitempty"`
	ClosedBy       *string    `json:"closed_by,omitempty"`
	ClosedAt       *time.Time `json:"closed_at,omitempty"`
	ReviewComment  *string    `json:"review_comment,omitempty"`
	AIAnalysis     *string    `json:"ai_analysis,omitempty"`
	AIAnalysedAt   *string    `json:"ai_analysed_at,omitempty"`
}

func (db *DB) ListAlerts(ctx context.Context, status string, limit int) ([]Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `
		SELECT id, created_at, title, description, severity, status,
		       COALESCE(agent_id,''), COALESCE(host,''), COALESCE(event_type,''),
		       COALESCE(event_id,''), COALESCE(source_event_id,''), acknowledged_by, acknowledged_at,
		       assigned_to, case_notes, closed_by, closed_at, review_comment,
		       ai_analysis, ai_analysed_at
		FROM alerts`
	args := []interface{}{}
	if status != "" {
		query += ` WHERE status = $1`
		args = append(args, status)
	}
	query += fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d`, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(
			&a.ID, &a.CreatedAt, &a.Title, &a.Description, &a.Severity, &a.Status,
			&a.AgentID, &a.Host, &a.EventType, &a.EventID, &a.SourceEventID,
			&a.AcknowledgedBy, &a.AcknowledgedAt,
			&a.AssignedTo, &a.CaseNotes, &a.ClosedBy, &a.ClosedAt, &a.ReviewComment,
		&a.AIAnalysis, &a.AIAnalysedAt,
		); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func (db *DB) CreateAlert(ctx context.Context, a Alert) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO alerts (title, description, severity, status, agent_id, host, event_type, event_id, source_event_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id
	`, a.Title, a.Description, a.Severity, "open",
		a.AgentID, a.Host, a.EventType, a.EventID,
		nullableStr(a.SourceEventID),
	).Scan(&id)
	return id, err
}

func (db *DB) AcknowledgeAlert(ctx context.Context, id int64, username string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE alerts
		SET status = 'acknowledged', acknowledged_by = $1, acknowledged_at = NOW()
		WHERE id = $2 AND status = 'open'
	`, username, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("alert not found or already acknowledged")
	}
	return nil
}

func (db *DB) CloseAlert(ctx context.Context, id int64, username string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE alerts SET status = 'closed', acknowledged_by = $1, acknowledged_at = NOW()
		WHERE id = $2
	`, username, id)
	return err
}

// CountAlertsByStatus returns open/acknowledged/closed counts.
func (db *DB) CountAlertsByStatus(ctx context.Context) (map[string]int64, error) {
	rows, err := db.QueryContext(ctx, `SELECT status, COUNT(*) FROM alerts GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]int64{"open": 0, "acknowledged": 0, "closed": 0}
	for rows.Next() {
		var status string
		var count int64
		rows.Scan(&status, &count)
		result[status] = count
	}
	return result, nil
}

// AlertExists checks if an alert already exists for a given event to avoid duplicates.
func (db *DB) AlertExists(ctx context.Context, eventID string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE event_id = $1`, eventID).Scan(&count)
	return count > 0, err
}

// CreateAlertDeduped inserts an alert only if no alert with the same event_id exists.
// Returns (id, true, nil) if created, (0, false, nil) if duplicate, (0, false, err) on error.
// This is atomic via INSERT ... ON CONFLICT DO NOTHING — safe against race conditions.
func (db *DB) CreateAlertDeduped(ctx context.Context, a Alert) (int64, bool, error) {
	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO alerts (title, description, severity, status, agent_id, host, event_type, event_id, source_event_id)
		VALUES ($1,$2,$3,'open',$4,$5,$6,$7,$8)
		ON CONFLICT (event_id) WHERE event_id IS NOT NULL AND event_id != '' DO NOTHING
		RETURNING id
	`, a.Title, a.Description, a.Severity,
		nullableStr(a.AgentID), nullableStr(a.Host), nullableStr(a.EventType),
		nullableStr(a.EventID), nullableStr(a.SourceEventID),
	).Scan(&id)
	if err != nil {
		// sql.ErrNoRows means ON CONFLICT DO NOTHING fired — it's a duplicate, not an error
		if err == sql.ErrNoRows {
			return 0, false, nil
		}
		return 0, false, err
	}
	return id, true, nil
}

// GetAlert fetches a single alert by ID.
func (db *DB) GetAlert(ctx context.Context, id int64) (*Alert, error) {
	var a Alert
	err := db.QueryRowContext(ctx, `
		SELECT id, created_at, title, description, severity, status,
		       COALESCE(agent_id,''), COALESCE(host,''), COALESCE(event_type,''),
		       COALESCE(event_id,''), COALESCE(source_event_id,''), acknowledged_by, acknowledged_at,
		       assigned_to, case_notes, closed_by, closed_at, review_comment,
		       ai_analysis, ai_analysed_at
		FROM alerts WHERE id = $1
	`, id).Scan(
		&a.ID, &a.CreatedAt, &a.Title, &a.Description, &a.Severity, &a.Status,
		&a.AgentID, &a.Host, &a.EventType, &a.EventID, &a.SourceEventID,
		&a.AcknowledgedBy, &a.AcknowledgedAt,
		&a.AssignedTo, &a.CaseNotes, &a.ClosedBy, &a.ClosedAt, &a.ReviewComment,
		&a.AIAnalysis, &a.AIAnalysedAt,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// AssignAlert assigns an alert to a user and creates a case.
func (db *DB) AssignAlert(ctx context.Context, id int64, assignedTo, assignedBy string, notes string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE alerts
		SET status = 'acknowledged',
		    assigned_to = $1,
		    acknowledged_by = $2,
		    acknowledged_at = NOW(),
		    case_notes = NULLIF($3, '')
		WHERE id = $4 AND status = 'open'
	`, assignedTo, assignedBy, notes, id)
	return err
}

// UpdateCaseNotes updates the notes on an acknowledged alert.
func (db *DB) UpdateCaseNotes(ctx context.Context, id int64, notes string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE alerts SET case_notes = $1 WHERE id = $2
	`, notes, id)
	return err
}

// CloseAlertWithReview closes an alert and records a review comment.
func (db *DB) CloseAlertWithReview(ctx context.Context, id int64, username, comment string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE alerts
		SET status = 'closed',
		    closed_by = $1,
		    closed_at = NOW(),
		    review_comment = NULLIF($2, ''),
		    acknowledged_by = COALESCE(acknowledged_by, $1),
		    acknowledged_at = COALESCE(acknowledged_at, NOW())
		WHERE id = $3
	`, username, comment, id)
	return err
}

func nullableStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// ListAlertsForHost returns alerts for a specific host since a given time.
func (db *DB) ListAlertsForHost(ctx context.Context, host string, since time.Time) ([]Alert, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, created_at, title, description, severity, status,
		       COALESCE(agent_id,''), COALESCE(host,''), COALESCE(event_type,''),
		       COALESCE(event_id,''), COALESCE(source_event_id,''), acknowledged_by, acknowledged_at,
		       assigned_to, case_notes, closed_by, closed_at, review_comment,
		       ai_analysis, ai_analysed_at
		FROM alerts
		WHERE host = $1 AND created_at >= $2
		ORDER BY severity DESC, created_at DESC
		LIMIT 500`,
		host, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(
			&a.ID, &a.CreatedAt, &a.Title, &a.Description, &a.Severity, &a.Status,
			&a.AgentID, &a.Host, &a.EventType, &a.EventID, &a.SourceEventID,
			&a.AcknowledgedBy, &a.AcknowledgedAt,
			&a.AssignedTo, &a.CaseNotes, &a.ClosedBy, &a.ClosedAt, &a.ReviewComment,
		&a.AIAnalysis, &a.AIAnalysedAt,
		); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// SaveAlertAIAnalysis persists the AI analysis JSON for an alert.
func (db *DB) SaveAlertAIAnalysis(ctx context.Context, id int64, analysisJSON string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE alerts
		SET ai_analysis = $1::jsonb, ai_analysed_at = NOW()
		WHERE id = $2`,
		analysisJSON, id,
	)
	return err
}
