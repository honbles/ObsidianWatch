package store

import (
	"context"
	"fmt"
	"time"
)

type Agent struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	Version      string    `json:"version"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	LastIP       string    `json:"last_ip"`
	EventCount   int64     `json:"event_count"`
	InstallKey   string    `json:"install_key"`
	TamperLocked bool      `json:"tamper_locked"`
	// Location
	Lat              *float64   `json:"lat,omitempty"`
	Lng              *float64   `json:"lng,omitempty"`
	LocationAccuracy *float64   `json:"location_accuracy,omitempty"`
	LocationSource   string     `json:"location_source,omitempty"`
	LocationCity     string     `json:"location_city,omitempty"`
	LocationCountry  string     `json:"location_country,omitempty"`
	LocationUpdated  *time.Time `json:"location_updated,omitempty"`
	// Computed
	Online bool `json:"online"`
}

// ListAgents returns all agents. An agent is online if last_seen < 2 minutes ago.
func (db *DB) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, hostname, os, version, first_seen, last_seen,
		       COALESCE(last_ip, ''), event_count,
		       COALESCE(install_key, ''), COALESCE(tamper_locked, false),
		       lat, lng, location_accuracy, COALESCE(location_source,''),
		       COALESCE(location_city,''), COALESCE(location_country,''), location_updated
		FROM agents
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list agents: %w", err)
	}
	defer rows.Close()

	cutoff := time.Now().Add(-2 * time.Minute)
	var agents []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(
			&a.ID, &a.Hostname, &a.OS, &a.Version,
			&a.FirstSeen, &a.LastSeen, &a.LastIP, &a.EventCount,
			&a.InstallKey, &a.TamperLocked,
			&a.Lat, &a.Lng, &a.LocationAccuracy, &a.LocationSource,
			&a.LocationCity, &a.LocationCountry, &a.LocationUpdated,
		); err != nil {
			return nil, err
		}
		a.Online = a.LastSeen.After(cutoff)
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// AgentStats returns event counts per agent for the last 24 hours.
func (db *DB) AgentStats(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT agent_id, host, COUNT(*) as event_count,
		       MAX(severity) as max_severity
		FROM events
		WHERE time > NOW() - INTERVAL '24 hours'
		GROUP BY agent_id, host
		ORDER BY event_count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var agentID, host string
		var count int64
		var maxSev int
		if err := rows.Scan(&agentID, &host, &count, &maxSev); err != nil {
			return nil, err
		}
		results = append(results, map[string]interface{}{
			"agent_id":    agentID,
			"host":        host,
			"event_count": count,
			"max_severity": maxSev,
		})
	}
	return results, rows.Err()
}

// GetAgent fetches a single agent by ID.
func (db *DB) GetAgent(ctx context.Context, id string) (*Agent, error) {
	agents, err := db.ListAgents(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range agents {
		if a.ID == id {
			return &a, nil
		}
	}
	return nil, fmt.Errorf("agent not found: %s", id)
}

func (db *DB) GetAgentByInstallKey(ctx context.Context, key string) (*Agent, error) {
	var a Agent
	err := db.QueryRowContext(ctx, `
		SELECT id, hostname, os, version, first_seen, last_seen,
		       COALESCE(last_ip,''), event_count,
		       COALESCE(install_key,''), COALESCE(tamper_locked,false)
		FROM agents WHERE install_key = $1
	`, key).Scan(
		&a.ID, &a.Hostname, &a.OS, &a.Version,
		&a.FirstSeen, &a.LastSeen, &a.LastIP, &a.EventCount,
		&a.InstallKey, &a.TamperLocked,
	)
	if err != nil {
		return nil, err
	}
	a.Online = a.LastSeen.After(time.Now().Add(-2 * time.Minute))
	return &a, nil
}

// SetInstallKey updates the install/tamper key for an agent.
// Uses UPSERT so it works even if the agent hasn't connected yet.
func (db *DB) SetInstallKey(ctx context.Context, agentID, key, os string) error {
	if os == "" {
		os = "unknown"
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO agents (id, hostname, os, version, first_seen, last_seen, install_key, tamper_locked)
		VALUES ($1, $1, $3, '0.0.0', NOW(), NOW(), $2, true)
		ON CONFLICT (id) DO UPDATE SET
			install_key   = EXCLUDED.install_key,
			os            = EXCLUDED.os,
			tamper_locked = true
	`, agentID, key, os)
	return err
}

// SetTamperLock enables or disables tamper protection for an agent.
func (db *DB) SetTamperLock(ctx context.Context, agentID string, locked bool) error {
	_, err := db.ExecContext(ctx,
		`UPDATE agents SET tamper_locked = $1 WHERE id = $2`,
		locked, agentID)
	return err
}

// RegenerateInstallKey generates a new install key for an agent.
func (db *DB) RegenerateInstallKey(ctx context.Context, agentID string) (string, error) {
	var key string
	err := db.QueryRowContext(ctx, `
		UPDATE agents
		SET install_key = encode(gen_random_bytes(16), 'hex')
		WHERE id = $1
		RETURNING install_key
	`, agentID).Scan(&key)
	return key, err
}

// UpdateAgentLocation stores the latest known position for an agent.
func (db *DB) UpdateAgentLocation(ctx context.Context, agentID string, lat, lng, accuracy float64, source, city, country string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE agents
		SET lat = $2, lng = $3, location_accuracy = $4,
		    location_source = $5, location_city = $6, location_country = $7,
		    location_updated = NOW()
		WHERE id = $1
	`, agentID, lat, lng, accuracy, source, city, country)
	return err
}

// GetAgentLocations returns all agents that have a known location.
func (db *DB) GetAgentLocations(ctx context.Context) ([]Agent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, hostname, os, version, first_seen, last_seen,
		       COALESCE(last_ip,''), event_count,
		       COALESCE(install_key,''), COALESCE(tamper_locked,false),
		       lat, lng, location_accuracy, COALESCE(location_source,''),
		       COALESCE(location_city,''), COALESCE(location_country,''), location_updated
		FROM agents
		WHERE lat IS NOT NULL AND lng IS NOT NULL
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cutoff := time.Now().Add(-2 * time.Minute)
	var agents []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(
			&a.ID, &a.Hostname, &a.OS, &a.Version,
			&a.FirstSeen, &a.LastSeen, &a.LastIP, &a.EventCount,
			&a.InstallKey, &a.TamperLocked,
			&a.Lat, &a.Lng, &a.LocationAccuracy, &a.LocationSource,
			&a.LocationCity, &a.LocationCountry, &a.LocationUpdated,
		); err != nil {
			return nil, err
		}
		a.Online = a.LastSeen.After(cutoff)
		agents = append(agents, a)
	}
	return agents, rows.Err()
}
