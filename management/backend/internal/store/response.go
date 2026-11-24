package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ResponseAction is one action sent to an agent.
type ResponseAction struct {
	ID          string          `json:"id"`
	AgentID     string          `json:"agent_id"`
	Hostname    string          `json:"hostname"`
	Action      string          `json:"action"`
	Params      json.RawMessage `json:"params"`
	Status      string          `json:"status"`
	Message     string          `json:"message"`
	Result      json.RawMessage `json:"result,omitempty"`
	RequestedBy string          `json:"requested_by"`
	Reason      string          `json:"reason,omitempty"`
	AlertID     string          `json:"alert_id,omitempty"`
	RequestedAt time.Time       `json:"requested_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
}

func (db *DB) CreateResponseAction(ctx context.Context, a ResponseAction) error {
	if len(a.Params) == 0 {
		a.Params = json.RawMessage(`{}`)
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO response_actions (id, agent_id, hostname, action, params, status, message, requested_by, reason, alert_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		a.ID, a.AgentID, a.Hostname, a.Action, a.Params, a.Status, a.Message, a.RequestedBy, a.Reason, a.AlertID)
	return err
}

func (db *DB) CompleteResponseAction(ctx context.Context, id, status, message string, result json.RawMessage) error {
	if len(result) == 0 {
		result = nil
	}
	_, err := db.ExecContext(ctx, `
		UPDATE response_actions SET status=$2, message=$3, result=$4, completed_at=now() WHERE id=$1`,
		id, status, message, result)
	return err
}

func (db *DB) SetResponseActionStatus(ctx context.Context, id, status string) error {
	_, err := db.ExecContext(ctx, `UPDATE response_actions SET status=$2 WHERE id=$1 AND completed_at IS NULL`, id, status)
	return err
}

// ListResponseActions returns recent actions, newest first; agentID "" = fleet-wide.
func (db *DB) ListResponseActions(ctx context.Context, agentID string, limit int) ([]ResponseAction, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `SELECT id, agent_id, hostname, action, params, status, message, result, requested_by, reason, alert_id, requested_at, completed_at
	      FROM response_actions`
	var args []interface{}
	if agentID != "" {
		q += ` WHERE agent_id = $1`
		args = append(args, agentID)
	}
	q += fmt.Sprintf(` ORDER BY requested_at DESC LIMIT %d`, limit)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ResponseAction{}
	for rows.Next() {
		var a ResponseAction
		var res []byte
		var done sql.NullTime
		if err := rows.Scan(&a.ID, &a.AgentID, &a.Hostname, &a.Action, &a.Params, &a.Status, &a.Message, &res, &a.RequestedBy, &a.Reason, &a.AlertID, &a.RequestedAt, &done); err != nil {
			return nil, err
		}
		if res != nil {
			a.Result = res
		}
		if done.Valid {
			t := done.Time
			a.CompletedAt = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RespState is the desired vs reported isolation state of an agent.
type RespState struct {
	AgentID         string     `json:"agent_id"`
	DesiredIsolated bool       `json:"desired_isolated"`
	DesiredTTLMin   int        `json:"desired_ttl_min"`
	DesiredExpires  *time.Time `json:"desired_expires_at,omitempty"`
	Isolated        bool       `json:"isolated"`
	IsolatedSince   *time.Time `json:"isolated_since,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	Quarantined     int        `json:"quarantined"`
	ReportedAt      *time.Time `json:"reported_at,omitempty"`
}

func (db *DB) GetRespState(ctx context.Context, agentID string) RespState {
	s := RespState{AgentID: agentID}
	var since, exp, rep, dexp sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT desired_isolated, desired_ttl_min, desired_expires_at, isolated, isolated_since, expires_at, quarantined, reported_at
		FROM agent_response_state WHERE agent_id=$1`, agentID).Scan(&s.DesiredIsolated, &s.DesiredTTLMin, &dexp, &s.Isolated, &since, &exp, &s.Quarantined, &rep)
	if err != nil {
		return s
	}
	if dexp.Valid {
		s.DesiredExpires = &dexp.Time
	}
	if since.Valid {
		s.IsolatedSince = &since.Time
	}
	if exp.Valid {
		s.ExpiresAt = &exp.Time
	}
	if rep.Valid {
		s.ReportedAt = &rep.Time
	}
	return s
}

// SetDesiredIsolation records what the analyst wants; the reconciler and the
// live action make the agent match it.
func (db *DB) SetDesiredIsolation(ctx context.Context, agentID string, want bool, ttlMin int) error {
	var exp interface{}
	if want && ttlMin > 0 {
		exp = time.Now().UTC().Add(time.Duration(ttlMin) * time.Minute)
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO agent_response_state (agent_id, desired_isolated, desired_ttl_min, desired_expires_at) VALUES ($1,$2,$3,$4)
		ON CONFLICT (agent_id) DO UPDATE SET desired_isolated=$2, desired_ttl_min=$3, desired_expires_at=$4`, agentID, want, ttlMin, exp)
	return err
}

// SetReportedState stores what the agent says its state is.
func (db *DB) SetReportedState(ctx context.Context, agentID string, isolated bool, since, expires *time.Time, quarantined int) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO agent_response_state (agent_id, isolated, isolated_since, expires_at, quarantined, reported_at)
		VALUES ($1,$2,$3,$4,$5,now())
		ON CONFLICT (agent_id) DO UPDATE SET isolated=$2, isolated_since=$3, expires_at=$4, quarantined=$5, reported_at=now()`,
		agentID, isolated, since, expires, quarantined)
	return err
}

// IsolatedAgents lists agents that are isolated or have an isolation pending.
func (db *DB) IsolatedAgents(ctx context.Context) ([]RespState, error) {
	rows, err := db.QueryContext(ctx, `SELECT agent_id, desired_isolated, isolated, isolated_since, expires_at
		FROM agent_response_state WHERE desired_isolated OR isolated`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RespState{}
	for rows.Next() {
		var s RespState
		var since, exp sql.NullTime
		if err := rows.Scan(&s.AgentID, &s.DesiredIsolated, &s.Isolated, &since, &exp); err != nil {
			return nil, err
		}
		if since.Valid {
			s.IsolatedSince = &since.Time
		}
		if exp.Valid {
			s.ExpiresAt = &exp.Time
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ── Live fleet hunts ─────────────────────────────────────────────────────────

type FleetHunt struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Match       string     `json:"match"`
	Path        string     `json:"path,omitempty"`
	RequestedBy string     `json:"requested_by"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	AgentsTotal int        `json:"agents_total"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"` // set when the hunt waits for offline hosts
	WaitMode    string     `json:"wait_mode,omitempty"`  // "", 1h, 24h, 7d, until_done
	// summary, filled by ListFleetHunts / GetFleetHunt
	Responded int `json:"responded"`
	Hosts     int `json:"hosts_with_hits"`
	Rows      int `json:"total_rows"`
	Queued    int `json:"queued"` // hosts still waiting to come online
	Skipped   int `json:"skipped"`
	Expired   int `json:"expired"`
}

type FleetHuntResult struct {
	AgentID     string          `json:"agent_id"`
	Hostname    string          `json:"hostname"`
	OS          string          `json:"os"`
	Status      string          `json:"status"`
	Message     string          `json:"message"`
	Columns     json.RawMessage `json:"columns"`
	Rows        json.RawMessage `json:"rows"`
	RowCount    int             `json:"row_count"`
	Truncated   bool            `json:"truncated"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	WasQueued   bool            `json:"was_queued"` // the host was offline when the hunt started
	QueuedAt    *time.Time      `json:"queued_at,omitempty"`
	SentAt      *time.Time      `json:"ran_at,omitempty"` // when the question reached the host (real run time)
	State       string          `json:"state"`            // running | answered | queued | expired | skipped
	Late        bool            `json:"late"`             // answered after waiting for the host
}

// HuntResultState maps a stored status to the per-host state the result
// view shows (spec E1).
func HuntResultState(status string) string {
	switch status {
	case "pending":
		return "running"
	case "ok", "failed", "timeout":
		return "answered"
	case "queued", "expired", "skipped":
		return status
	case "offline": // rows written before E1
		return "skipped"
	}
	return status
}

// CreateFleetHunt stores a hunt and one result row per target. initial gives the starting status of
// targets that are not asked now: "queued" (waiting for the host to reconnect, until expires) or
// "skipped" (offline and the hunt does not wait). Every other target starts "pending" and is sent now.
func (db *DB) CreateFleetHunt(ctx context.Context, h FleetHunt, targets []Agent, initial map[string]string, expires *time.Time) error {
	if expires == nil {
		for _, st := range initial {
			if st == "queued" {
				return fmt.Errorf("store: a hunt that queues hosts needs an expiry")
			}
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO fleet_hunts (id, name, kind, match, path, requested_by, agents_total, expires_at, wait_mode) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		h.ID, h.Name, h.Kind, h.Match, h.Path, h.RequestedBy, len(targets), expires, h.WaitMode); err != nil {
		return err
	}
	for _, a := range targets {
		status, wq, msg := "pending", false, ""
		switch initial[a.ID] {
		case "queued":
			status, wq = "queued", true
		case "skipped":
			status, msg = "skipped", "host was offline; the hunt did not wait for it"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO fleet_hunt_results (hunt_id, agent_id, hostname, os, status, message, was_queued, queued_at, sent_at, completed_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7, CASE WHEN $7 THEN now() END, CASE WHEN $5='pending' THEN now() END, CASE WHEN $5='skipped' THEN now() END)`,
			h.ID, a.ID, a.Hostname, a.OS, status, msg, wq); err != nil {
			return err
		}
	}
	// A hunt where no host is asked or waited for is complete at once.
	if _, err := tx.ExecContext(ctx, `UPDATE fleet_hunts SET completed_at=now() WHERE id=$1
		AND NOT EXISTS (SELECT 1 FROM fleet_hunt_results WHERE hunt_id=$1 AND status IN ('pending','queued'))`, h.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) CompleteHuntResult(ctx context.Context, huntID, agentID, status, message string, columns, rows json.RawMessage, rowCount int, truncated bool) error {
	if len(columns) == 0 {
		columns = json.RawMessage(`[]`)
	}
	if len(rows) == 0 {
		rows = json.RawMessage(`[]`)
	}
	_, err := db.ExecContext(ctx, `UPDATE fleet_hunt_results SET status=$3, message=$4, columns=$5, rows=$6, row_count=$7, truncated=$8, completed_at=now()
		WHERE hunt_id=$1 AND agent_id=$2 AND status='pending'`, huntID, agentID, status, message, columns, rows, rowCount, truncated)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE fleet_hunts SET completed_at=now() WHERE id=$1 AND completed_at IS NULL
		AND NOT EXISTS (SELECT 1 FROM fleet_hunt_results WHERE hunt_id=$1 AND status IN ('pending','queued'))`, huntID)
	return err
}

// QueuedHunt is a question waiting for an offline host.
type QueuedHunt struct{ ID, Kind, Match, Path string }

// ClaimQueuedHunts atomically moves this agent's queued, unexpired hunt results to pending and returns
// the questions to send. Called when the agent's tunnel connects.
func (db *DB) ClaimQueuedHunts(ctx context.Context, agentID string) ([]QueuedHunt, error) {
	rows, err := db.QueryContext(ctx, `UPDATE fleet_hunt_results r SET status='pending', sent_at=now()
		FROM fleet_hunts h WHERE r.hunt_id=h.id AND r.agent_id=$1 AND r.status='queued'
		  AND (h.expires_at IS NULL OR h.expires_at > now())
		RETURNING h.id, h.kind, h.match, h.path`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QueuedHunt
	for rows.Next() {
		var q QueuedHunt
		if err := rows.Scan(&q.ID, &q.Kind, &q.Match, &q.Path); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// ExpireQueuedHunts ends the wait for hosts that never came back before their hunt's deadline.
func (db *DB) ExpireQueuedHunts(ctx context.Context) error {
	if _, err := db.ExecContext(ctx, `UPDATE fleet_hunt_results r SET status='expired',
		message='host did not come online before the wait window ended', completed_at=now()
		FROM fleet_hunts h WHERE r.hunt_id=h.id AND r.status='queued' AND h.expires_at IS NOT NULL AND h.expires_at < now()`); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `UPDATE fleet_hunts SET completed_at=now() WHERE completed_at IS NULL
		AND NOT EXISTS (SELECT 1 FROM fleet_hunt_results r WHERE r.hunt_id=fleet_hunts.id AND r.status IN ('pending','queued'))`)
	return err
}

// TimeoutHunt marks every still-pending result of a hunt as timed out.
func (db *DB) TimeoutHunt(ctx context.Context, huntID string) error {
	if _, err := db.ExecContext(ctx, `UPDATE fleet_hunt_results SET status='timeout', message='no answer from the agent in time', completed_at=now()
		WHERE hunt_id=$1 AND status='pending'`, huntID); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `UPDATE fleet_hunts SET completed_at=now() WHERE id=$1 AND completed_at IS NULL`, huntID)
	return err
}

const huntSummarySQL = `
	SELECT h.id, h.name, h.kind, h.match, h.path, h.requested_by, h.created_at, h.completed_at, h.agents_total, h.expires_at, h.wait_mode,
	       COALESCE(SUM(CASE WHEN r.status IN ('ok','failed','timeout') THEN 1 ELSE 0 END),0),
	       COALESCE(SUM(CASE WHEN r.row_count>0 THEN 1 ELSE 0 END),0),
	       COALESCE(SUM(r.row_count),0),
	       COALESCE(SUM(CASE WHEN r.status='queued' THEN 1 ELSE 0 END),0),
	       COALESCE(SUM(CASE WHEN r.status IN ('skipped','offline') THEN 1 ELSE 0 END),0),
	       COALESCE(SUM(CASE WHEN r.status='expired' THEN 1 ELSE 0 END),0)
	FROM fleet_hunts h LEFT JOIN fleet_hunt_results r ON r.hunt_id = h.id`

func scanHunt(sc interface{ Scan(...interface{}) error }) (FleetHunt, error) {
	var h FleetHunt
	var done, exp sql.NullTime
	err := sc.Scan(&h.ID, &h.Name, &h.Kind, &h.Match, &h.Path, &h.RequestedBy, &h.CreatedAt, &done, &h.AgentsTotal, &exp, &h.WaitMode, &h.Responded, &h.Hosts, &h.Rows, &h.Queued, &h.Skipped, &h.Expired)
	if done.Valid {
		t := done.Time
		h.CompletedAt = &t
	}
	if exp.Valid {
		t := exp.Time
		h.ExpiresAt = &t
	}
	return h, err
}

func (db *DB) ListFleetHunts(ctx context.Context, limit int) ([]FleetHunt, error) {
	if limit <= 0 || limit > 200 {
		limit = 30
	}
	_ = db.ExpireQueuedHunts(ctx)
	rows, err := db.QueryContext(ctx, huntSummarySQL+fmt.Sprintf(` GROUP BY h.id ORDER BY h.created_at DESC LIMIT %d`, limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FleetHunt{}
	for rows.Next() {
		h, err := scanHunt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (db *DB) GetFleetHunt(ctx context.Context, id string) (*FleetHunt, []FleetHuntResult, error) {
	_ = db.ExpireQueuedHunts(ctx)
	h, err := scanHunt(db.QueryRowContext(ctx, huntSummarySQL+` WHERE h.id=$1 GROUP BY h.id`, id))
	if err != nil {
		return nil, nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT agent_id, hostname, os, status, message, columns, rows, row_count, truncated, completed_at, was_queued, queued_at, sent_at
		FROM fleet_hunt_results WHERE hunt_id=$1 ORDER BY row_count DESC, hostname`, id)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	res := []FleetHuntResult{}
	for rows.Next() {
		var r FleetHuntResult
		var done, qat, sat sql.NullTime
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.OS, &r.Status, &r.Message, &r.Columns, &r.Rows, &r.RowCount, &r.Truncated, &done, &r.WasQueued, &qat, &sat); err != nil {
			return nil, nil, err
		}
		if sat.Valid {
			t := sat.Time
			r.SentAt = &t
		}
		r.State = HuntResultState(r.Status)
		r.Late = r.WasQueued && r.State == "answered"
		if qat.Valid {
			t := qat.Time
			r.QueuedAt = &t
		}
		if done.Valid {
			t := done.Time
			r.CompletedAt = &t
		}
		res = append(res, r)
	}
	return &h, res, rows.Err()
}

// ── Historical hunt: per-host rollup of a query over stored events ───────────

type HuntHost struct {
	AgentID    string    `json:"agent_id"`
	Host       string    `json:"host"`
	Count      int64     `json:"count"`
	First      time.Time `json:"first"`
	Last       time.Time `json:"last"`
	EventTypes []string  `json:"event_types"`
	Sample     string    `json:"sample"`
}

// HuntRollup answers "which hosts match this query, and how often" using the
// same filters and KQL expression as the Events page.
func (db *DB) HuntRollup(ctx context.Context, f EventFilter, limit int) ([]HuntHost, int64, error) {
	where, args, err := buildEventWhere(f)
	if err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var totalHosts int64
	_ = db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT COALESCE(NULLIF(agent_id,''), host)) FROM events WHERE `+where, args...).Scan(&totalHosts)
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`
		SELECT COALESCE(NULLIF(agent_id,''),''), COALESCE(host,''), COUNT(*), MIN(time), MAX(time),
		       (ARRAY_AGG(DISTINCT event_type))[1:6],
		       COALESCE((ARRAY_AGG(COALESCE(NULLIF(command_line,''), NULLIF(file_path,''), NULLIF(image_path,''), NULLIF(dst_ip,''), '') ORDER BY time DESC))[1], '')
		FROM events WHERE %s
		GROUP BY 1, 2
		ORDER BY COUNT(*) DESC
		LIMIT %d`, where, limit), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: hunt rollup: %w", err)
	}
	defer rows.Close()
	out := []HuntHost{}
	for rows.Next() {
		var h HuntHost
		var types sql.NullString
		if err := rows.Scan(&h.AgentID, &h.Host, &h.Count, &h.First, &h.Last, &types, &h.Sample); err != nil {
			return nil, 0, err
		}
		if types.Valid {
			h.EventTypes = strings.Split(strings.Trim(types.String, "{}"), ",")
		}
		if len(h.Sample) > 300 {
			h.Sample = h.Sample[:300]
		}
		out = append(out, h)
	}
	return out, totalHosts, rows.Err()
}
