package store

import (
	"context"
	"fmt"
	"time"
)

// Agent represents a registered agent in the fleet.
type Agent struct {
	ID         string    `json:"id"`
	Hostname   string    `json:"hostname"`
	OS         string    `json:"os"`
	Version    string    `json:"version"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	LastIP     string    `json:"last_ip"`
	EventCount int64     `json:"event_count"`
}

// UpsertAgent inserts or updates agent metadata on each batch received.
// last_ip comes from the HTTP request RemoteAddr.
func (db *DB) UpsertAgent(ctx context.Context, id, hostname, os, version, remoteIP, installKey string, eventCount int) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO agents (id, hostname, os, version, first_seen, last_seen, last_ip, event_count, install_key)
		VALUES ($1, $2, $3, $4, NOW(), NOW(), $5, $6, NULLIF($7, ''))
		ON CONFLICT (id) DO UPDATE SET
			hostname    = EXCLUDED.hostname,
			os          = EXCLUDED.os,
			version     = EXCLUDED.version,
			last_seen   = NOW(),
			last_ip     = EXCLUDED.last_ip,
			event_count = agents.event_count + EXCLUDED.event_count,
			install_key = COALESCE(NULLIF(EXCLUDED.install_key, ''), agents.install_key)
	`, id, hostname, os, version, remoteIP, eventCount, installKey)
	if err != nil {
		return fmt.Errorf("store: upsert agent: %w", err)
	}
	return nil
}

// ListAgents returns all known agents ordered by last_seen descending.
func (db *DB) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, hostname, os, version, first_seen, last_seen,
		       COALESCE(last_ip, ''), event_count
		FROM agents
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list agents: %w", err)
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(
			&a.ID, &a.Hostname, &a.OS, &a.Version,
			&a.FirstSeen, &a.LastSeen, &a.LastIP, &a.EventCount,
		); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// GetAgent returns a single agent by ID.
func (db *DB) GetAgent(ctx context.Context, id string) (*Agent, error) {
	var a Agent
	err := db.QueryRowContext(ctx, `
		SELECT id, hostname, os, version, first_seen, last_seen,
		       COALESCE(last_ip, ''), event_count
		FROM agents WHERE id = $1
	`, id).Scan(
		&a.ID, &a.Hostname, &a.OS, &a.Version,
		&a.FirstSeen, &a.LastSeen, &a.LastIP, &a.EventCount,
	)
	if err != nil {
		return nil, fmt.Errorf("store: get agent %q: %w", id, err)
	}
	return &a, nil
}

// UpdateAgentLocation stores the latest known position for an agent.
func (db *DB) UpdateAgentLocation(ctx context.Context, agentID string, lat, lng, accuracy float64, source, city, country string) error {
	// Try matching by agent UUID first, then fall back to hostname.
	// The location collector may send either the UUID or the hostname as agent_id.
	result, err := db.ExecContext(ctx, `
		UPDATE agents
		SET lat = $2, lng = $3, location_accuracy = $4,
		    location_source = $5, location_city = $6, location_country = $7,
		    location_updated = NOW()
		WHERE id = $1 OR hostname = $1
	`, agentID, lat, lng, accuracy, source, city, country)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	return nil
}
