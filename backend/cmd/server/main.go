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
