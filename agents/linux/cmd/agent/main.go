//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"obsidianwatch/linux-agent/internal/collector"
	"obsidianwatch/linux-agent/internal/config"
	"obsidianwatch/linux-agent/internal/forwarder"
	"obsidianwatch/linux-agent/internal/parser"
	"obsidianwatch/linux-agent/internal/service"
	"obsidianwatch/linux-agent/pkg/schema"
)

const agentVersion = "0.3.1"

func main() {
	// The config is embedded in the binary at compile time by the Agent Builder.
	// No -config flag or agent.yaml file needed — just run:
	//   sudo ./obsidianwatch-linux-agent install
	//   sudo ./obsidianwatch-linux-agent uninstall
	flag.Parse()

	args := flag.Args()
	subcmd := ""
	if len(args) > 0 {
		subcmd = args[0]
	}

	// LoadEmbedded uses the baked-in config; falls back to agent.yaml for dev builds.
	cfg, err := config.LoadEmbedded("agent.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	hostname, _ := os.Hostname()
	agentID := cfg.Agent.ID
	if agentID == "" {
		agentID = resolveAgentID(hostname)
	}

	switch subcmd {
	case "install":
		self, _ := os.Executable()
		err := service.Install(service.InstallConfig{
			BinarySrc:           self,
			ManagementURL:       cfg.Forwarder.ManagementURL,
			CAFile:              cfg.Forwarder.CAFile,
			CACertPEM:           cfg.Forwarder.CACertPEM,
			ManagementCACertPEM: cfg.Forwarder.ManagementCACertPEM,
			AgentID:             agentID,
			Hostname:            hostname,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Install failed: %v\n", err)
			os.Exit(1)
		}
		return

	case "uninstall":
		err := service.Uninstall(cfg.Forwarder.ManagementURL, cfg.Forwarder.CAFile, agentID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Uninstall failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Normal run
	logger := buildLogger(cfg.Log.Level)
	logger.Info("ObsidianWatch Linux agent starting",
		"version", agentVersion, "agent_id", agentID, "host", hostname)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	rawCh := make(chan schema.Event, 2000)
	filteredCh := make(chan schema.Event, 2000)

	hostInfo := parser.ResolveHostInfo(agentID, agentVersion)
	norm := parser.NewNormalizer(logger)
	enrich := parser.NewEnricher(hostInfo, logger)

	q, err := forwarder.NewQueue(cfg.Queue.DBPath, cfg.Queue.MaxRows, logger)
	if err != nil {
		logger.Error("Failed to create queue", "err", err)
		os.Exit(1)
	}
	defer q.Close()

	fwdCfg := forwarder.ForwarderConfig{
		InstallKey:    cfg.Forwarder.InstallKey,
		BackendURL:    cfg.Forwarder.BackendURL,
		BatchSize:     cfg.Forwarder.BatchSize,
		FlushInterval: cfg.Forwarder.FlushInterval,
		CertFile:      cfg.Forwarder.CertFile,
		KeyFile:       cfg.Forwarder.KeyFile,
		CAFile:        cfg.Forwarder.CAFile,
		CACertPEM:     cfg.Forwarder.CACertPEM,
		APIKey:        cfg.Forwarder.APIKey,
	}
	fwd, err := forwarder.NewHTTPForwarder(fwdCfg, q, agentID, hostname, agentVersion, logger)
	if err != nil {
		logger.Error("Failed to create forwarder", "err", err)
		os.Exit(1)
	}

	rlCfg := collector.RateLimitConfig{
		MaxPerSecond: cfg.Collector.RateLimit.MaxPerSecond,
		DedupeWindow: cfg.Collector.RateLimit.DedupeWindow,
	}
	limiter := collector.NewRateLimiter(rlCfg)

	// Normalizer → filteredCh
	go func() {
		for ev := range rawCh {
			enrich.Enrich(&ev)
			if err := norm.Normalize(&ev); err != nil {
				continue
			}
			if limiter.Allow(&ev) {
				select {
				case filteredCh <- ev:
				default:
					collector.GlobalHealth.EventsDropped.Add(1)
				}
			}
		}
	}()

	// Enqueue
	go func() {
		for ev := range filteredCh {
			fwd.Enqueue([]schema.Event{ev})
			collector.GlobalHealth.EventsForwarded.Add(1)
		}
	}()

	activeCollectors := []string{}

	if cfg.Collector.Journald.Enabled {
		activeCollectors = append(activeCollectors, "journald")
		j := collector.NewJournaldCollector(collector.JournaldConfig{Enabled: true}, agentID, hostname, rawCh, logger)
		go func() { j.Run(ctx) }()
	}

	if cfg.Collector.Process.Enabled {
		activeCollectors = append(activeCollectors, "process")
		p := collector.NewProcessCollector(collector.ProcessCollectorConfig{
			Enabled: true, PollInterval: cfg.Collector.Process.PollInterval,
		}, agentID, hostname, rawCh, logger)
		go func() { p.Run(ctx) }()
	}

	if cfg.Collector.Network.Enabled {
		activeCollectors = append(activeCollectors, "network")
		n := collector.NewNetworkCollector(collector.NetworkCollectorConfig{
			Enabled: true, PollInterval: cfg.Collector.Network.PollInterval,
		}, agentID, hostname, rawCh, logger)
		go func() { n.Run(ctx) }()
	}

	if cfg.Collector.DNS.Enabled {
		activeCollectors = append(activeCollectors, "dns")
		d := collector.NewDNSCollector(collector.DNSCollectorConfig{Enabled: true}, agentID, hostname, rawCh, logger)
		go func() { d.Run(ctx) }()
	}

	if cfg.Collector.FIM.Enabled {
		activeCollectors = append(activeCollectors, "fim")
		dirs := make([]collector.FIMDirConfig, len(cfg.Collector.FIM.Dirs))
		for i, d := range cfg.Collector.FIM.Dirs {
			dirs[i] = collector.FIMDirConfig{Path: d.Path, Recursive: d.Recursive, Exclude: d.Exclude}
		}
		fim := collector.NewFIMCollector(collector.FIMCollectorConfig{Enabled: true, Dirs: dirs}, agentID, hostname, rawCh, logger)
		go func() { fim.Run(ctx) }()
	}

	if cfg.Collector.ConfigMon.Enabled {
		activeCollectors = append(activeCollectors, "configmon")
		cm := collector.NewConfigMonCollector(collector.ConfigMonConfig{
			Enabled: true, Paths: cfg.Collector.ConfigMon.Paths,
		}, agentID, hostname, rawCh, logger)
		go func() { cm.Run(ctx) }()
	}

	if cfg.Collector.Health.Enabled {
		activeCollectors = append(activeCollectors, "health")
		h := collector.NewHealthReporter(cfg.Collector.Health.Interval,
			agentID, hostname, agentVersion, activeCollectors, rawCh, logger)
		go func() { h.Run(ctx) }()
	}

	// Vulnerability scanner — full TCP port scan of localhost every 5 days
	{
		vs := collector.NewVulnScanner(collector.VulnScannerConfig{
			Enabled:      true,
			ScanInterval: 5 * 24 * time.Hour,
			Concurrency:  50,
		}, agentID, hostname, "linux", rawCh, logger)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("vuln: panic recovered", "err", r)
				}
			}()
			vs.Run(ctx)
		}()
	}

	// Location collector — always runs, posts to backend every 30 minutes
	{
		loc := collector.NewLocationCollector(
			30*time.Minute,
			agentID, hostname,
			cfg.Forwarder.BackendURL, cfg.Forwarder.APIKey,
			cfg.Forwarder.CAFile, cfg.Forwarder.CACertPEM,
			rawCh, logger,
		)
		go func() { loc.Run(ctx) }()
		activeCollectors = append(activeCollectors, "location")
	}

	// Live Response — SSH tunnel for analyst terminal access
	{
		lr := collector.NewLiveResponseCollector(
			agentID, hostname,
			cfg.Forwarder.ManagementURL,
			cfg.Forwarder.APIKey,
			cfg.Forwarder.CAFile,
			cfg.Forwarder.CAFile,
			logger,
		)
		// Pass embedded CA PEM so tunnel TLS works when no ca_file is set on disk
		caPEM := cfg.Forwarder.ManagementCACertPEM
		if caPEM == "" { caPEM = cfg.Forwarder.CACertPEM }
		if caPEM != "" { lr.SetCAPEM(caPEM) }
		go func() { lr.Run(ctx) }()
		activeCollectors = append(activeCollectors, "live-response")
	}

	go func() { fwd.Run(ctx) }()

	logger.Info("All collectors running", "count", len(activeCollectors), "collectors", activeCollectors)
	<-ctx.Done()
	logger.Info("Shutting down...")
}

func buildLogger(level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func resolveAgentID(hostname string) string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(path); err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id
			}
		}
	}
	return hostname
}


