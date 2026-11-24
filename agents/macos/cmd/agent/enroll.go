//go:build darwin

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

	"obsidianwatch/macos-agent/internal/config"
	"obsidianwatch/macos-agent/internal/identity"
	"obsidianwatch/macos-agent/internal/service"
)

// backendRoots trusts the backend's server certificate.
func backendRoots(cfg *config.Config) *x509.CertPool {
	pemData := []byte(cfg.Forwarder.CACertPEM)
	if len(pemData) == 0 && cfg.Forwarder.CAFile != "" {
		pemData, _ = os.ReadFile(cfg.Forwarder.CAFile)
	}
	if len(pemData) == 0 {
		return nil // system roots (a publicly trusted backend certificate)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemData)
	return pool
}

func newIdentity(cfg *config.Config, hostname, osName string, logger *slog.Logger) (*identity.Manager, error) {
	if cfg.Forwarder.EnrollToken == "" && cfg.Forwarder.APIKey != "" {
		return nil, errors.New("this agent was built with an API key, which the server no longer accepts; rebuild it in the Agent builder (it now embeds an enrollment token) and reinstall")
	}
	if cfg.Forwarder.BackendURL == "" {
		return nil, errors.New("no backend_url in the agent configuration")
	}
	return identity.New(identity.Options{
		BackendURL: cfg.Forwarder.BackendURL,
		Token:      cfg.Forwarder.EnrollToken,
		RootCAs:    backendRoots(cfg),
		Dir:        service.QueueDir,
		Hostname:   hostname,
		OS:         osName,
		Version:    agentVersion,
		Logger:     logger,
	})
}

func registeredMarker() string { return filepath.Join(service.QueueDir, "install-key-registered") }

// registerInstallKey sends the install key once per identity.
func registerInstallKey(cfg *config.Config, m *identity.Manager, hostname, key string) error {
	if key == "" {
		return nil
	}
	if b, err := os.ReadFile(registeredMarker()); err == nil && string(b) == m.AgentID() {
		return nil
	}
	if err := service.RegisterInstallKey(cfg.Forwarder.BackendURL, cfg.Forwarder.CAFile, cfg.Forwarder.CACertPEM, m.AgentID(), hostname, key); err != nil {
		return err
	}
	_ = os.MkdirAll(service.QueueDir, 0o700)
	return os.WriteFile(registeredMarker(), []byte(m.AgentID()), 0o600)
}

// enrollAtInstall runs from "install": enroll now (bounded) and register.
func enrollAtInstall(cfg *config.Config, m *identity.Manager, hostname string) func(string) error {
	return func(installKey string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := m.Ensure(ctx); err != nil {
			return fmt.Errorf("enrollment: %w", err)
		}
		identity.SetActive(m)
		return registerInstallKey(cfg, m, hostname, installKey)
	}
}

// startIdentity blocks until the agent has a certificate, then keeps it
// renewed and registers the install key if that has not happened yet.
func startIdentity(ctx context.Context, cfg *config.Config, m *identity.Manager, hostname string, logger *slog.Logger) error {
	if m.State() != identity.StateValid {
		logger.Info("identity: enrolling with the backend", "backend", cfg.Forwarder.BackendURL)
	}
	if err := m.Ensure(ctx); err != nil {
		return err
	}
	identity.SetActive(m)
	go m.Run(ctx)
	go func() {
		key, _ := config.ReadInstallKey()
		for attempt := 0; ; attempt++ {
			err := registerInstallKey(cfg, m, hostname, key)
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
