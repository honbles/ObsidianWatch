//go:build windows

package main

// enroll.go - the agent's identity: certificate enrollment at install or
// first start, and one-time registration of the install key, both through
// the backend and authenticated by the agent certificate (no API key).

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"obsidianwatch/agent/internal/config"
	"obsidianwatch/agent/internal/identity"
)

const dataDir = `C:\ProgramData\ObsidianWatch`

func backendRoots(cfg *config.Config) *x509.CertPool {
	pemData := []byte(cfg.Forwarder.CACertPEM)
	if len(pemData) == 0 && cfg.Forwarder.CAFile != "" {
		pemData, _ = os.ReadFile(cfg.Forwarder.CAFile)
	}
	if len(pemData) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemData)
	return pool
}

func newIdentity(cfg *config.Config, hostname string, logger *slog.Logger) (*identity.Manager, error) {
	if cfg.Forwarder.EnrollToken == "" && cfg.Forwarder.APIKey != "" {
		return nil, errors.New("this agent was built with an API key, which the server no longer accepts; rebuild it in the Agent builder (it now embeds an enrollment token) and reinstall")
	}
	if cfg.Forwarder.BackendURL == "" {
		return nil, errors.New("no backend_url in the agent configuration")
	}
	hardenDataDir()
	return identity.New(identity.Options{
		BackendURL: cfg.Forwarder.BackendURL,
		Token:      cfg.Forwarder.EnrollToken,
		RootCAs:    backendRoots(cfg),
		Dir:        dataDir,
		Hostname:   hostname,
		OS:         "windows",
		Version:    cfg.Agent.Version,
		Logger:     logger,
	})
}

func registeredMarker() string { return filepath.Join(dataDir, "install-key-registered") }

func registerInstallKeyOnce(cfg *config.Config, m *identity.Manager, key string) error {
	if key == "" {
		return nil
	}
	if b, err := os.ReadFile(registeredMarker()); err == nil && string(b) == m.AgentID() {
		return nil
	}
	if err := registerInstallKey(cfg.Forwarder.BackendURL, cfg.Forwarder.CACertPEM, m.AgentID(), key); err != nil {
		return err
	}
	return os.WriteFile(registeredMarker(), []byte(m.AgentID()), 0o600)
}

func enrollNow(cfg *config.Config, m *identity.Manager, installKey string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := m.Ensure(ctx); err != nil {
		return fmt.Errorf("enrollment: %w", err)
	}
	identity.SetActive(m)
	return registerInstallKeyOnce(cfg, m, installKey)
}

func startIdentity(ctx context.Context, cfg *config.Config, m *identity.Manager, logger *slog.Logger) error {
	if err := m.Ensure(ctx); err != nil {
		return err
	}
	identity.SetActive(m)
	go m.Run(ctx)
	go func() {
		key, _ := config.ReadInstallKey()
		for attempt := 0; ; attempt++ {
			err := registerInstallKeyOnce(cfg, m, key)
			if err == nil {
				return
			}
			logger.Warn("install key: registration failed, retrying", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(attempt+1) * time.Minute):
			}
		}
	}()
	return nil
}
