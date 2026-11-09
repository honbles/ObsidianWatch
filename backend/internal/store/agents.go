package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
// UpsertAgent records an ingest batch's sender. installKey is only ever
// used on first registration (the INSERT branch) — I-02: ingest trusts
// agent_id/host/os/install_key straight from the request body, and this
// used to let any ingest batch (authenticated with nothing more than the
// one fleet-wide API key baked into every agent binary) silently replace
// an existing agent's install_key with an attacker-chosen value on every
// single call (`COALESCE(NULLIF(EXCLUDED.install_key,”), ...)` prefers
// the incoming key whenever it's non-empty). Since the install key is
// meant to be the one thing that can authorize an uninstall, that was a
// way to hijack it without ever touching the host. The ON CONFLICT path
// now always keeps the key already on file, full stop — an attacker who
// can forge ingest batches gains nothing against it anymore.
func (db *DB) UpsertAgent(ctx context.Context, id, hostname, os, version, remoteIP, installKey string, eventCount int) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO agents (id, hostname, os, version, first_seen, last_seen, last_ip, event_count, install_key_hash)
		VALUES ($1, $2, $3, $4, NOW(), NOW(), $5, $6, NULLIF($7, ''))
		ON CONFLICT (id) DO UPDATE SET
			hostname    = EXCLUDED.hostname,
			os          = EXCLUDED.os,
			version     = EXCLUDED.version,
			last_seen   = NOW(),
			last_ip     = EXCLUDED.last_ip,
			event_count = agents.event_count + EXCLUDED.event_count
			-- install_key intentionally omitted: never updated once set.
	`, id, hostname, os, version, remoteIP, eventCount, hashIngestKey(installKey))
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

// hashIngestKey stores install keys hashed (F-03); empty stays empty.
func hashIngestKey(k string) string {
	if k == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:])
}
