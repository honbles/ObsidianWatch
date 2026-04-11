package store

import (
	"context"
	"time"
)

type AlertRule struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Enabled         bool      `json:"enabled"`
	EventType       string    `json:"event_type"`
	Severity        int       `json:"severity"`
	HostMatch       string    `json:"host_match"`
	UserMatch       string    `json:"user_match"`
	ProcessMatch    string    `json:"process_match"`
	CommandLineMatch string   `json:"command_line_match"`
	SrcIPMatch      string    `json:"src_ip_match"`
	DstIPMatch      string    `json:"dst_ip_match"`
	DNSMatch        string    `json:"dns_match"`
	OSMatch         string    `json:"os_match"`
	SourceMatch     string    `json:"source_match"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
}

func (db *DB) ListAlertRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, description, enabled, event_type, severity,
		       host_match, user_match, process_match,
		       command_line_match, src_ip_match, dst_ip_match, dns_match, os_match, source_match,
		       created_by, created_at
		FROM alert_rules ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []AlertRule
	for rows.Next() {
		var r AlertRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Enabled, &r.EventType,
			&r.Severity, &r.HostMatch, &r.UserMatch, &r.ProcessMatch,
			&r.CommandLineMatch, &r.SrcIPMatch, &r.DstIPMatch, &r.DNSMatch, &r.OSMatch, &r.SourceMatch,
			&r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (db *DB) GetAlertRule(ctx context.Context, id int64) (*AlertRule, error) {
	var r AlertRule
	err := db.QueryRowContext(ctx, `
		SELECT id, name, description, enabled, event_type, severity,
		       host_match, user_match, process_match,
		       command_line_match, src_ip_match, dst_ip_match, dns_match, os_match, source_match,
		       created_by, created_at
		FROM alert_rules WHERE id = $1
	`, id).Scan(&r.ID, &r.Name, &r.Description, &r.Enabled, &r.EventType,
		&r.Severity, &r.HostMatch, &r.UserMatch, &r.ProcessMatch,
		&r.CommandLineMatch, &r.SrcIPMatch, &r.DstIPMatch, &r.DNSMatch, &r.OSMatch, &r.SourceMatch,
		&r.CreatedBy, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (db *DB) CreateAlertRule(ctx context.Context, r AlertRule) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO alert_rules (name, description, enabled, event_type, severity,
		    host_match, user_match, process_match,
		    command_line_match, src_ip_match, dst_ip_match, dns_match, os_match, source_match,
		    created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id
	`, r.Name, r.Description, r.Enabled, r.EventType, r.Severity,
		r.HostMatch, r.UserMatch, r.ProcessMatch,
		r.CommandLineMatch, r.SrcIPMatch, r.DstIPMatch, r.DNSMatch, r.OSMatch, r.SourceMatch,
		r.CreatedBy).Scan(&id)
	return id, err
}

func (db *DB) UpdateAlertRule(ctx context.Context, r AlertRule) error {
	_, err := db.ExecContext(ctx, `
		UPDATE alert_rules SET name=$1, description=$2, enabled=$3, event_type=$4,
		severity=$5, host_match=$6, user_match=$7, process_match=$8,
		command_line_match=$9, src_ip_match=$10, dst_ip_match=$11, dns_match=$12, os_match=$13, source_match=$14
		WHERE id=$15
	`, r.Name, r.Description, r.Enabled, r.EventType, r.Severity,
		r.HostMatch, r.UserMatch, r.ProcessMatch,
		r.CommandLineMatch, r.SrcIPMatch, r.DstIPMatch, r.DNSMatch, r.OSMatch, r.SourceMatch,
		r.ID)
	return err
}

func (db *DB) DeleteAlertRule(ctx context.Context, id int64) error {
	_, err := db.ExecContext(ctx, `DELETE FROM alert_rules WHERE id = $1`, id)
	return err
}

func (db *DB) GetEnabledRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, description, enabled, event_type, severity,
		       host_match, user_match, process_match,
		       command_line_match, src_ip_match, dst_ip_match, dns_match, os_match, source_match,
		       created_by, created_at
		FROM alert_rules WHERE enabled = TRUE ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []AlertRule
	for rows.Next() {
		var r AlertRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Enabled, &r.EventType,
			&r.Severity, &r.HostMatch, &r.UserMatch, &r.ProcessMatch,
			&r.CommandLineMatch, &r.SrcIPMatch, &r.DstIPMatch, &r.DNSMatch, &r.OSMatch, &r.SourceMatch,
			&r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}
