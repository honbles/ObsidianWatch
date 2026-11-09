package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// hashInstallKey returns the hex SHA-256 of an install key (F-03). Keys are
// 128-bit random values, so an unsalted fast hash is adequate.
func hashInstallKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

const installKeyPresent = `CASE WHEN COALESCE(install_key_hash,'') <> '' OR COALESCE(install_key,'') <> '' THEN 'set' ELSE '' END`

type Agent struct {
	ID            string    `json:"id"`
	Hostname      string    `json:"hostname"`
	OS            string    `json:"os"`
	Version       string    `json:"version"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	LastIP        string    `json:"last_ip"`
	EventCount    int64     `json:"event_count"`
	InstallKey    string    `json:"install_key,omitempty"` // always empty on reads (F-03)
	HasInstallKey bool      `json:"has_install_key"`
	TamperLocked  bool      `json:"tamper_locked"`
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
		       `+installKeyPresent+`, COALESCE(tamper_locked, false),
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
		a.HasInstallKey, a.InstallKey = a.InstallKey != "", ""
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
			"agent_id":     agentID,
			"host":         host,
			"event_count":  count,
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
		       `+installKeyPresent+`, COALESCE(tamper_locked,false)
		FROM agents WHERE install_key_hash = $1 OR install_key = $2
	`, hashInstallKey(key), key).Scan(
		&a.ID, &a.Hostname, &a.OS, &a.Version,
		&a.FirstSeen, &a.LastSeen, &a.LastIP, &a.EventCount,
		&a.InstallKey, &a.TamperLocked,
	)
	if err != nil {
		return nil, err
	}
	a.HasInstallKey, a.InstallKey = a.InstallKey != "", ""
	a.Online = a.LastSeen.After(time.Now().Add(-2 * time.Minute))
	return &a, nil
}

// SetInstallKey records an agent's install/tamper key on first
// registration. Uses UPSERT so it works even if the agent hasn't
// connected yet.
//
// I-02: this is reachable with nothing more than the one fleet-wide API
// key baked into every agent binary (see handleAgentRegisterKey) — not an
// admin-authenticated action. It used to unconditionally overwrite
// whatever install_key was already on file, which means anyone holding
// that one shared key could silently replace any agent's uninstall key at
// any time, not just at genuine first install, and then use the key they
// just planted to pass tamper-lock verification and uninstall the agent —
// defeating the very guarantee tamper protection exists for ("only the
// key can uninstall the agent" only holds if the key can't be swapped out
// from under the agent). The key is now set once and never silently
// replaced by this path: WHERE excludes any row that already has a
// non-empty install_key, so a repeat/forged call against an
// already-registered agent is a no-op. Re-issuing a key for a real
// reinstall goes through RegenerateInstallKey instead, which requires an
// authenticated admin session.
func (db *DB) SetInstallKey(ctx context.Context, agentID, key, os string) error {
	if os == "" {
		os = "unknown"
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO agents (id, hostname, os, version, first_seen, last_seen, install_key_hash, tamper_locked)
		VALUES ($1, $1, $3, '0.0.0', NOW(), NOW(), $2, true)
		ON CONFLICT (id) DO UPDATE SET
			install_key_hash = EXCLUDED.install_key_hash,
			install_key      = NULL,
			os               = EXCLUDED.os,
			tamper_locked    = true
		WHERE COALESCE(agents.install_key, '') = '' AND COALESCE(agents.install_key_hash, '') = ''
	`, agentID, hashInstallKey(key), os)
	return err
}

// SetTamperLock enables or disables tamper protection for an agent.
func (db *DB) SetTamperLock(ctx context.Context, agentID string, locked bool) error {
	_, err := db.ExecContext(ctx,
		`UPDATE agents SET tamper_locked = $1 WHERE id = $2`,
		locked, agentID)
	return err
}

// RegenerateInstallKey issues a new install key. Only the hash is stored; the
// plaintext is returned once to the caller (F-03).
func (db *DB) RegenerateInstallKey(ctx context.Context, agentID string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	key := hex.EncodeToString(buf)
	res, err := db.ExecContext(ctx, `
		UPDATE agents SET install_key_hash = $2, install_key = NULL WHERE id = $1`,
		agentID, hashInstallKey(key))
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", fmt.Errorf("agent not found: %s", agentID)
	}
	return key, nil
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
	if err != nil {
		return err
	}
	// F-17: keep a history, but only when the agent has moved (>~1km) or
	// the last sample is older than 6h, so a stationary host doesn't write a
	// row per heartbeat. Best-effort: history failure never fails the update.
	_, _ = db.ExecContext(ctx, `
		INSERT INTO agent_location_history (agent_id, lat, lng, accuracy, source, city, country)
		SELECT $1, $2::float8, $3::float8, $4, $5, $6, $7
		WHERE NOT EXISTS (
			SELECT 1 FROM agent_location_history
			WHERE agent_id = $1 AND ts > NOW() - INTERVAL '6 hours'
			  AND abs(lat - $2::float8) < 0.01 AND abs(lng - $3::float8) < 0.01)`,
		agentID, lat, lng, accuracy, source, city, country)
	return nil
}

// GetAgentLocations returns all agents that have a known location.
func (db *DB) GetAgentLocations(ctx context.Context) ([]Agent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, hostname, os, version, first_seen, last_seen,
		       COALESCE(last_ip,''), event_count,
		       `+installKeyPresent+`, COALESCE(tamper_locked,false),
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
		a.HasInstallKey, a.InstallKey = a.InstallKey != "", ""
		a.Online = a.LastSeen.After(cutoff)
		agents = append(agents, a)
	}
	return agents, rows.Err()
}
