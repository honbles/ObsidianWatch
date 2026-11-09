//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"obsidianwatch/macos-agent/internal/collector"
	"obsidianwatch/macos-agent/internal/config"
	"obsidianwatch/macos-agent/internal/forwarder"
	"obsidianwatch/macos-agent/internal/parser"
	"obsidianwatch/macos-agent/internal/service"
	"obsidianwatch/macos-agent/pkg/schema"
)

const agentVersion = "0.3.1"

func main() {
	// Config is embedded in the binary at compile time by the Agent Builder.
	// Just run: sudo ./obsidianwatch-macos-agent install
	flag.Parse()

	args := flag.Args()
	subcmd := ""
	if len(args) > 0 {
		subcmd = args[0]
	}

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
			APIKey:              cfg.Forwarder.APIKey,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Install failed: %v\n", err)
			os.Exit(1)
		}
		return

	case "uninstall":
		err := service.Uninstall(cfg.Forwarder.ManagementURL, cfg.Forwarder.CAFile, uninstallCA(cfg.Forwarder.ManagementCACertPEM, cfg.Forwarder.CACertPEM), cfg.Forwarder.APIKey, agentID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Uninstall failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Normal run
	logger := buildLogger(cfg.Log.Level)
	logger.Info("ObsidianWatch macOS agent starting",
		"version", agentVersion,
		"agent_id", agentID,
		"hostname", hostname,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Raw event channel (collectors → normalizer → rate limiter → forwarder)
	rawCh := make(chan schema.Event, 2048)
	normalizedCh := make(chan schema.Event, 2048)
	filteredCh := make(chan schema.Event, 2048)

	// Normalizer pipeline
	norm := parser.NewNormalizer(logger)
	go func() {
		for ev := range rawCh {
			e := ev // copy
			if err := norm.Normalize(&e); err == nil {
				select {
				case normalizedCh <- e:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Rate limiter pipeline
	if cfg.Collector.RateLimit.Enabled {
		rl := collector.NewRateLimiter(collector.RateLimitConfig{
			MaxPerSecond: cfg.Collector.RateLimit.MaxPerSecond,
			DedupeWindow: cfg.Collector.RateLimit.DedupeWindow,
		})
		go collector.FilteredChannel(normalizedCh, filteredCh, rl)
	} else {
		go func() {
			for ev := range normalizedCh {
				filteredCh <- ev
			}
		}()
	}

	// Queue
	q, err := forwarder.NewQueue(cfg.Queue.DBPath, cfg.Queue.MaxRows, logger)
	if err != nil {
		logger.Error("Failed to create queue", "err", err)
		os.Exit(1)
	}
	defer q.Close()

	// Forwarder
	fwdCfg := forwarder.ForwarderConfig{
		InstallKey:    cfg.Forwarder.InstallKey,
		BackendURL:    cfg.Forwarder.BackendURL,
		BatchSize:     cfg.Forwarder.BatchSize,
		FlushInterval: cfg.Forwarder.FlushInterval,
		CAFile:        cfg.Forwarder.CAFile,
		CACertPEM:     cfg.Forwarder.CACertPEM,
		APIKey:        cfg.Forwarder.APIKey,
	}
	fwd, err := forwarder.NewHTTPForwarder(fwdCfg, q, agentID, hostname, agentVersion, logger)
	if err != nil {
		logger.Error("Failed to create forwarder", "err", err)
		os.Exit(1)
	}

	go func() {
		for ev := range filteredCh {
			fwd.Enqueue([]schema.Event{ev})
			collector.GlobalHealth.EventsForwarded.Add(1)
		}
	}()

	activeCollectors := []string{}

	if cfg.Collector.Syslog.Enabled {
		activeCollectors = append(activeCollectors, "syslog")
		s := collector.NewSyslogCollector(collector.SyslogConfig{Enabled: true}, agentID, hostname, rawCh, logger)
		go func() { s.Run(ctx) }()
	}

	if cfg.Collector.Process.Enabled {
		activeCollectors = append(activeCollectors, "process")
		p := collector.NewProcessCollector(collector.ProcessCollectorConfig{
			Enabled: true, PollInterval: cfg.Collector.Process.PollInterval,
		}, agentID, hostname, rawCh, logger)
		go func() { p.Run(ctx) }()
		// A-01 interim: Endpoint Security exec events via eslogger (macOS 13+),
		// catching short-lived processes the poller misses. Falls back silently.
		es := collector.NewESExecCollector(agentID, hostname, rawCh, logger)
		go func() { es.Run(ctx) }()
	}

	if cfg.Collector.Network.Enabled {
		activeCollectors = append(activeCollectors, "network")
		n := collector.NewNetworkCollector(collector.NetworkCollectorConfig{
			Enabled: true, PollInterval: cfg.Collector.Network.PollInterval,
		}, agentID, hostname, rawCh, logger)
		go func() { n.Run(ctx) }()
	}

	{
		activeCollectors = append(activeCollectors, "usb")
		u := collector.NewUSBCollector(agentID, hostname, rawCh, logger)
		go func() { u.Run(ctx) }()
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
		// Use AuditFIMCollector (auditpipe/praudit) for PID-attributed file events
		// Falls back to kqueue FIM if auditpipe is unavailable
		fim := collector.NewAuditFIMCollector(collector.FIMCollectorConfig{Enabled: true, Dirs: dirs}, agentID, hostname, rawCh, logger)
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
		}, agentID, hostname, "darwin", rawCh, logger)
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
			cfg.Forwarder.AllowInsecureTLS,
			rawCh, logger,
		)
		go func() { loc.Run(ctx) }()
		activeCollectors = append(activeCollectors, "location")
	}

	// Live Response — analyst terminal access. H-2: opt-in only.
	if cfg.LiveResponse.Enabled {
		lr := collector.NewLiveResponseCollector(
			agentID, hostname,
			cfg.Forwarder.ManagementURL,
			cfg.Forwarder.APIKey,
			cfg.Forwarder.CAFile,
			cfg.Forwarder.CAFile,
			logger,
		)
		go func() { lr.Run(ctx) }()
		activeCollectors = append(activeCollectors, "live-response")
	}

	go func() { fwd.Run(ctx) }()

	logger.Info("All collectors running", "count", len(activeCollectors), "collectors", activeCollectors)
	<-ctx.Done()
	logger.Info("Shutting down...")
	// D-12: tell the server we are going away before we do. The signal reaching
	// us means a stop/kill-TERM was requested (service stop, uninstall, or a
	// deliberate attempt to blind the host).
	{
		raw, _ := json.Marshal(map[string]interface{}{
			"reason": "shutdown signal received", "pid": os.Getpid(), "agent_version": agentVersion,
		})
		fwd.SendFinal(schema.Event{
			ID:        fmt.Sprintf("agent-tamper:%s:%d", agentID, time.Now().UnixNano()),
			OS:        "darwin",
			EventType: "agent.tamper",
			Severity:  schema.Severity(4),
			Source:    "agent",
			Raw:       raw,
		})
	}
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

// resolveAgentID uses the macOS hardware UUID as a stable agent ID.
func resolveAgentID(hostname string) string {
	// ioreg -rd1 -c IOPlatformExpertDevice prints the hardware UUID
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					id := strings.Trim(strings.TrimSpace(parts[1]), `"`)
					if id != "" {
						return id
					}
				}
			}
		}
	}
	return hostname
}

// uninstallCA picks the CA PEM for management-server calls: the management CA
// if embedded, otherwise the backend CA.
func uninstallCA(mgmtCA, backendCA string) string {
	if mgmtCA != "" {
		return mgmtCA
	}
	return backendCA
}
