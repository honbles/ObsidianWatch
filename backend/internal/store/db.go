package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/lib/pq" // PostgreSQL / TimescaleDB driver

	"obsidianwatch/backend/internal/config"
)

// DB wraps the standard sql.DB with helpers for the SIEM store.
type DB struct {
	*sql.DB
	logger *slog.Logger
}

// Connect opens a connection pool to TimescaleDB and verifies connectivity.
func Connect(cfg config.DatabaseConfig, logger *slog.Logger) (*DB, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Verify the connection is live.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	logger.Info("database connected", "host", cfg.Host, "db", cfg.Name)
	return &DB{DB: db, logger: logger}, nil
}

// HealthCheck pings the database and returns an error if unhealthy.
func (db *DB) HealthCheck(ctx context.Context) error {
	return db.PingContext(ctx)
}

// GetAgentAPIKey reads the agent API key from the settings table.
// Returns empty string if not set (falls back to config file key).
func (db *DB) GetAgentAPIKey(ctx context.Context) string {
	var val string
	err := db.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE key = 'setup.agent_api_key' LIMIT 1`,
	).Scan(&val)
	if err != nil {
		return ""
	}
	return val
}
