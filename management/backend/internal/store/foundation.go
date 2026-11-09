package store

// foundation.go — shared by the Network and Application builds. Owned by the
// integration owner. Do not edit from a side branch.

import (
	"context"
	"encoding/json"
)

// LinkAlertEntity records that an alert concerns an entity. Idempotent.
func (db *DB) LinkAlertEntity(ctx context.Context, alertID int64, kind, key string) error {
	if alertID == 0 || kind == "" || key == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `INSERT INTO alert_entities (alert_id, kind, key)
		VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, alertID, kind, key)
	return err
}

// AlertIDsForEntity returns the newest alert IDs linked to an entity.
func (db *DB) AlertIDsForEntity(ctx context.Context, kind, key string, limit int) ([]int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.QueryContext(ctx, `SELECT alert_id FROM alert_entities
		WHERE kind=$1 AND key=$2 ORDER BY alert_id DESC LIMIT $3`, kind, key, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// EntitiesForAlert returns "kind" -> keys linked to an alert.
func (db *DB) EntitiesForAlert(ctx context.Context, alertID int64) (map[string][]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT kind, key FROM alert_entities WHERE alert_id=$1 ORDER BY kind, key`, alertID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = append(out[k], v)
	}
	return out, rows.Err()
}

// RuleSetting is one row of rule_settings.
type RuleSetting struct {
	RuleID    string          `json:"rule_id"`
	ScopeKind string          `json:"scope_kind"`
	ScopeID   string          `json:"scope_id"`
	Enabled   bool            `json:"enabled"`
	Observe   bool            `json:"observe"`
	Params    json.RawMessage `json:"params"`
	Allowlist json.RawMessage `json:"allowlist"`
	UpdatedBy string          `json:"updated_by"`
}

// ListRuleSettings returns all settings, optionally only for one rule.
func (db *DB) ListRuleSettings(ctx context.Context, ruleID string) ([]RuleSetting, error) {
	q := `SELECT rule_id, scope_kind, scope_id, enabled, observe, params, allowlist, updated_by FROM rule_settings`
	args := []any{}
	if ruleID != "" {
		q += ` WHERE rule_id=$1`
		args = append(args, ruleID)
	}
	q += ` ORDER BY rule_id, scope_kind, scope_id`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleSetting
	for rows.Next() {
		var s RuleSetting
		var p, a []byte
		if err := rows.Scan(&s.RuleID, &s.ScopeKind, &s.ScopeID, &s.Enabled, &s.Observe, &p, &a, &s.UpdatedBy); err != nil {
			return nil, err
		}
		s.Params, s.Allowlist = json.RawMessage(p), json.RawMessage(a)
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpsertRuleSetting inserts or replaces one setting row.
func (db *DB) UpsertRuleSetting(ctx context.Context, s RuleSetting) error {
	if len(s.Params) == 0 {
		s.Params = json.RawMessage(`{}`)
	}
	if len(s.Allowlist) == 0 {
		s.Allowlist = json.RawMessage(`[]`)
	}
	_, err := db.ExecContext(ctx, `INSERT INTO rule_settings
		(rule_id, scope_kind, scope_id, enabled, observe, params, allowlist, updated, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,now(),$8)
		ON CONFLICT (rule_id, scope_kind, scope_id) DO UPDATE SET
		  enabled=EXCLUDED.enabled, observe=EXCLUDED.observe, params=EXCLUDED.params,
		  allowlist=EXCLUDED.allowlist, updated=now(), updated_by=EXCLUDED.updated_by`,
		s.RuleID, s.ScopeKind, s.ScopeID, s.Enabled, s.Observe, string(s.Params), string(s.Allowlist), s.UpdatedBy)
	return err
}
