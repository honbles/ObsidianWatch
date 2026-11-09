package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"obsidianwatch/backend/internal/api"
	"obsidianwatch/backend/internal/config"
	"obsidianwatch/backend/internal/store"
	"obsidianwatch/backend/internal/store/migrations"
)

func main() {
	cfgPath := flag.String("config", "server.yaml", "path to server config file")
	flag.Parse()

	// ── Config ──────────────────────────────────────────────────────────
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	// ── Logger ──────────────────────────────────────────────────────────
	logger := buildLogger(cfg.Log.Level, cfg.Log.Format)
	go watchRestartSignal(logger) // M-08

	// ── Database ────────────────────────────────────────────────────────
	db, err := store.Connect(cfg.Database, logger)
	if err != nil {
		logger.Error("database connection failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	// Run schema migrations automatically on startup.
	ctx := context.Background()
	if err := migrations.Run(ctx, db.DB, logger); err != nil {
		logger.Error("migrations failed", "err", err)
		os.Exit(1)
	}

	// ── HTTP Server ─────────────────────────────────────────────────────
	applyRetention(ctx, db, cfg, logger)

	srv, err := api.New(cfg, db, logger)
	if err != nil {
		logger.Error("server init failed", "err", err)
		os.Exit(1)
	}

	// Start in background goroutine.
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		logger.Info("shutting down", "signal", sig)
	case err := <-errCh:
		logger.Error("server error", "err", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "err", err)
	}
	logger.Info("server stopped")
}

func buildLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

// applyRetention (H-05) makes the events retention window configurable and
// optionally enables chunk compression. Best-effort: errors are logged.
func applyRetention(ctx context.Context, db *store.DB, cfg *config.Config, logger *slog.Logger) {
	days := cfg.Server.RetentionDays
	if days <= 0 {
		days = 90
	}
	if days < 7 || days > 3650 {
		logger.Warn("retention_days out of range (7-3650); using 90", "value", days)
		days = 90
	}
	interval := fmt.Sprintf("%d days", days)
	if _, err := db.ExecContext(ctx, `SELECT remove_retention_policy('events', if_exists => TRUE)`); err != nil {
		logger.Warn("retention: remove old policy failed", "err", err)
	}
	if _, err := db.ExecContext(ctx, `SELECT add_retention_policy('events', $1::interval, if_not_exists => TRUE)`, interval); err != nil {
		logger.Warn("retention: apply failed", "err", err)
	} else {
		logger.Info("retention policy applied", "days", days)
	}
	if cfg.Server.EnableCompression {
		if _, err := db.ExecContext(ctx, `ALTER TABLE events SET (timescaledb.compress, timescaledb.compress_segmentby = 'agent_id', timescaledb.compress_orderby = 'time DESC')`); err != nil {
			logger.Warn("compression: not available (needs TimescaleDB Community)", "err", err)
			return
		}
		if _, err := db.ExecContext(ctx, `SELECT add_compression_policy('events', INTERVAL '7 days', if_not_exists => TRUE)`); err != nil {
			logger.Warn("compression: policy failed", "err", err)
		}
	}
}
