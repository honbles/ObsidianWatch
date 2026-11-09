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

	"obsidianwatch/management/internal/api"
	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
	"obsidianwatch/management/internal/store/migrations"
)

func main() {
	cfgPath := flag.String("config", "server.yaml", "path to server config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	logger := buildLogger(cfg.Log.Level, cfg.Log.Format)

	// Management database
	if err := store.RequireSecretsKey(); err != nil {
		logger.Error("startup refused", "err", err)
		os.Exit(1)
	}
	db, err := store.Connect(cfg.Database, logger)
	if err != nil {
		logger.Error("management db connection failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx := context.Background()
	if err := migrations.Run(ctx, db.DB, logger); err != nil {
		logger.Error("migrations failed", "err", err)
		os.Exit(1)
	}

	// Seed default admin user if no users exist yet (M-06: random one-time password)
	seededPassword, err := db.SeedAdmin(ctx)
	if err != nil {
		logger.Error("seed admin failed", "err", err)
		os.Exit(1)
	}
	if seededPassword != "" {
		fmt.Println("=================================================================")
		fmt.Println("  First-run admin account created:")
		fmt.Println("    username: admin")
		fmt.Printf("    password: %s\n", seededPassword)
		fmt.Println("  This password is shown only once and is not stored anywhere.")
		fmt.Println("  Log in and change it immediately.")
		fmt.Println("=================================================================")
	}

	// Auto-populate Agent Builder defaults from cert-init metadata
	agentAPIKey := os.Getenv("AGENT_API_KEY")
	api.SeedAgentBuilderDefaults(ctx, db, agentAPIKey)

	// Backend database (read-only access to agent events and locations)
	backendDB, err := store.Connect(cfg.BackendDB, logger)
	if err != nil {
		// Non-fatal — management works without backend DB, just loses location data
		logger.Warn("backend db connection failed — location data unavailable", "err", err)
		backendDB = nil
	}
	if backendDB != nil {
		defer backendDB.Close()
	}

	srv := api.New(cfg, db, backendDB, logger)

	// Run server with a cancellable context so engines shut down cleanly
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(runCtx); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		logger.Info("shutting down", "signal", sig)
	case err := <-errCh:
		logger.Error("server error", "err", err)
	}

	runCancel() // stop alert/detection/threat intel engines

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
