package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"obsidianwatch/management/internal/telemetry"
	"time"

	_ "github.com/lib/pq"
	"obsidianwatch/management/internal/config"
)

type DB struct {
	*sql.DB
	logger *slog.Logger
	dsn    string // for LISTEN connections, which cannot come from the pool
}

func Connect(cfg config.DatabaseConfig, logger *slog.Logger) (*DB, error) {
	db, err := sql.Open(telemetry.DriverName, cfg.DSN()) // lib/pq with spans for traced requests
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	logger.Info("database connected", "host", cfg.Host, "db", cfg.Name)
	return &DB{DB: db, logger: logger, dsn: cfg.DSN()}, nil
}

func (db *DB) HealthCheck(ctx context.Context) error {
	return db.PingContext(ctx)
}
