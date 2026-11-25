package config

// config_app.go - OWNED BY THE APPLICATION BUILD. Extend this struct freely.
// Everything defaults to off: no eBPF sensor, no OTLP receiver.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"obsidianwatch/linux-agent/internal/ebpf"
	"obsidianwatch/linux-agent/internal/obi"
	"obsidianwatch/linux-agent/internal/otel"
	"obsidianwatch/linux-agent/pkg/schema"
)

// AppMonitoringConfig is the `app_monitoring:` block written by the Agent Builder
// when the app-server profile is selected.
type AppMonitoringConfig struct {
	Enabled bool `yaml:"enabled"`

	OTLP OTLPConfig `yaml:"otlp"`

	// Ebpf configures the host runtime sensor (Linux). Off unless the app-server profile enables it.
	Ebpf EbpfConfig `yaml:"ebpf"`

	// UserHashKey is the per-organization HMAC key for user identifiers (spec section 9).
	// Empty means user identifiers are not sent at all.
	UserHashKey string `yaml:"user_hash_key"`
	// CleartextServices ("name|environment") opted into cleartext user identifiers.
	CleartextServices []string `yaml:"cleartext_services"`
	// ClientIPDefault is full | truncated | off; ClientIPByService overrides per "name|environment".
	ClientIPDefault   string            `yaml:"client_ip_default"`
	ClientIPByService map[string]string `yaml:"client_ip_by_service"`

	SlowMs              int            `yaml:"slow_ms"`
	SlowMsByService     map[string]int `yaml:"slow_ms_by_service"`
	BaselineSamplePct   float64        `yaml:"baseline_sample_pct"`
	MaxRoutesPerService int            `yaml:"max_routes_per_service"`
	MaxOpenTraces       int            `yaml:"max_open_traces"`
	FlushInterval       time.Duration  `yaml:"flush_interval"`
	// SettingsPollInterval is how often per-service settings (client-address mode, cleartext
	// user ids, latency target) are pulled from the backend; default 5 minutes.
	SettingsPollInterval time.Duration `yaml:"settings_poll_interval"`
}

// EbpfConfig configures the host runtime sensor. Mode "auto" takes the best tier the host allows:
// kernel programs (build tag ebpf), then the proc connector, then /proc polling.
type EbpfConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Mode         string        `yaml:"mode"`          // auto | ebpf | procevent | poll
	PollInterval time.Duration `yaml:"poll_interval"` // default 2s
	Environment  string        `yaml:"environment"`   // deployment environment given to discovered services
	WatchDirs    []string      `yaml:"watch_dirs"`    // extra web/upload directories for file events
	SecretFiles  []string      `yaml:"secret_files"`  // extra credential files to watch for reads
	// Requests turns on request tracing without code changes: the agent runs the
	// bundled OpenTelemetry eBPF Instrumentation (OBI) for discovered services.
	Requests RequestsConfig `yaml:"requests"`
}

// RequestsConfig configures eBPF request tracing (OBI).
type RequestsConfig struct {
	Enabled    bool          `yaml:"enabled"`
	Path       string        `yaml:"path"`        // default /usr/local/lib/obsidianwatch/obi
	MinRestart time.Duration `yaml:"min_restart"` // shortest time between restarts for new ports (default 10m)
}

// OTLPConfig selects where the receiver listens. Only loopback addresses and Unix
// sockets are accepted.
type OTLPConfig struct {
	Listen string `yaml:"listen"` // default 127.0.0.1:4318 (OTLP/HTTP)
	Socket string `yaml:"socket"` // optional Unix socket path, e.g. for containers
}

// ApplyDefaults fills zero values. Call it before Validate.
func (c *AppMonitoringConfig) ApplyDefaults() {
	if c.OTLP.Listen == "" && c.OTLP.Socket == "" {
		c.OTLP.Listen = "127.0.0.1:4318"
	}
	if c.ClientIPDefault == "" {
		c.ClientIPDefault = "full"
	}
	if c.SlowMs <= 0 {
		c.SlowMs = 1000
	}
	if c.BaselineSamplePct == 0 {
		c.BaselineSamplePct = 1
	}
	if c.MaxRoutesPerService <= 0 {
		c.MaxRoutesPerService = 500
	}
	if c.MaxOpenTraces <= 0 {
		c.MaxOpenTraces = 2000
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = 30 * time.Second
	}
}

// Validate rejects anything that would expose the receiver beyond the host.
func (c *AppMonitoringConfig) Validate() error {
	if c.OTLP.Listen != "" {
		host, _, err := net.SplitHostPort(c.OTLP.Listen)
		if err != nil {
			return fmt.Errorf("app_monitoring.otlp.listen: %w", err)
		}
		if host != "localhost" {
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				return fmt.Errorf("app_monitoring.otlp.listen %q must be a loopback address; the receiver never binds a routable address", c.OTLP.Listen)
			}
		}
	}
	for _, m := range append([]string{c.ClientIPDefault}, mapValues(c.ClientIPByService)...) {
		if m != "full" && m != "truncated" && m != "off" {
			return fmt.Errorf("app_monitoring: client ip mode %q must be full, truncated or off", m)
		}
	}
	switch c.Ebpf.Mode {
	case "", "auto", "ebpf", "procevent", "poll":
	default:
		return fmt.Errorf("app_monitoring.ebpf.mode %q must be auto, ebpf, procevent or poll", c.Ebpf.Mode)
	}
	if c.BaselineSamplePct < 0 || c.BaselineSamplePct > 100 {
		return fmt.Errorf("app_monitoring.baseline_sample_pct must be between 0 and 100")
	}
	return nil
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// StartAppMonitoring starts the OTLP receiver when the app-server profile is on. It is
// called from the [APP-COLLECTORS] block in main. Application security events are sent
// into events - the agent's NORMAL event channel (normaliser, own-activity filter, rate
// limiter) - never straight to the forwarder, so each carries the sender's pid and ppid.
func (c *Config) StartAppMonitoring(ctx context.Context, agentID, hostname string, events chan<- schema.Event,
	version string, logger *slog.Logger, active *[]string) {
	app := c.AppMonitoring
	if !app.Enabled {
		return
	}
	app.ApplyDefaults()
	if err := app.Validate(); err != nil {
		logger.Error("app monitoring disabled: invalid configuration", "err", err)
		return
	}
	svc, err := otel.New(otel.Options{
		AgentID: agentID, Hostname: hostname,
		Receiver: otel.ReceiverOptions{Listen: app.OTLP.Listen, Socket: app.OTLP.Socket},
		Sender: otel.SenderOptions{
			BackendURL: c.Forwarder.BackendURL, APIKey: c.Forwarder.APIKey,
			CACertPEM: c.Forwarder.CACertPEM, CAFile: c.Forwarder.CAFile,
			CertFile: c.Forwarder.CertFile, KeyFile: c.Forwarder.KeyFile, Version: version,
		},
		Agg: otel.AggOptions{SlowMs: app.SlowMs, SlowMsBy: app.SlowMsByService, BaselinePct: app.BaselineSamplePct,
			MaxRoutes: app.MaxRoutesPerService, MaxOpenTraces: app.MaxOpenTraces},
		UserHashKey: app.UserHashKey, CleartextServices: app.CleartextServices,
		ClientIPDefault: app.ClientIPDefault, ClientIPByService: app.ClientIPByService,
		FlushInterval: app.FlushInterval, ConfigInterval: app.SettingsPollInterval,
		Emit: func(ev schema.Event) bool {
			select {
			case events <- ev:
				return true
			default:
				return false // channel full: drop and count, never block the receiver
			}
		},
		Logger: logger,
	})
	if err != nil {
		logger.Error("app monitoring disabled", "err", err)
		return
	}
	*active = append(*active, "app-otlp")
	go func() {
		if err := svc.Run(ctx); err != nil {
			logger.Error("app monitoring stopped", "err", err)
		}
	}()
	if app.Ebpf.Enabled {
		// The sensor's events use the SAME non-blocking path into the agent's normal channel, so the
		// own-activity filter sees every one of them with its pid and ppid.
		sensor := ebpf.New(ebpf.Options{
			AgentID: agentID, Hostname: hostname, Mode: app.Ebpf.Mode, PollInterval: app.Ebpf.PollInterval,
			Environment: app.Ebpf.Environment, WatchDirs: app.Ebpf.WatchDirs, SecretFiles: app.Ebpf.SecretFiles,
			Emit: func(ev schema.Event) bool {
				select {
				case events <- ev:
					return true
				default:
					return false
				}
			},
			ServicePIDs: svc.InstrumentedPIDs, Discovered: c.discoveredSink(ctx, svc, app, logger, active), Logger: logger,
		})
		*active = append(*active, "app-sensor")
		go func() {
			if err := sensor.Run(ctx); err != nil {
				if errors.Is(err, ebpf.ErrUnsupported) {
					logger.Info("host runtime sensor is Linux-only; not running on this platform")
				} else {
					logger.Warn("host runtime sensor not running", "err", err)
				}
			}
		}()
	}
}

// discoveredSink feeds discovered services to the aggregator and, when request
// tracing is on and the obi binary is installed, to the OBI runner.
func (c *Config) discoveredSink(ctx context.Context, svc *otel.Service, app AppMonitoringConfig, logger *slog.Logger, active *[]string) func([]otel.BatchInstance) {
	rq := app.Ebpf.Requests
	if !rq.Enabled {
		return svc.AddDiscovered
	}
	path := rq.Path
	if path == "" {
		path = "/usr/local/lib/obsidianwatch/obi"
	}
	if !obi.Available(path) {
		logger.Warn("request tracing is on but the obi binary is missing; discovered services stay host-only", "path", path)
		return svc.AddDiscovered
	}
	if app.OTLP.Listen == "" {
		logger.Warn("request tracing needs the OTLP receiver on a loopback TCP address (app_monitoring.otlp.listen)")
		return svc.AddDiscovered
	}
	runner := obi.New(obi.Options{Path: path, StateDir: "/var/lib/obsidianwatch/obi", OTLPEndpoint: "http://" + app.OTLP.Listen,
		MinRestart: rq.MinRestart, Instrumented: svc.InstrumentedPIDs, Logger: logger})
	svc.Recv.SetProxy(runner)
	*active = append(*active, "app-requests-ebpf")
	go func() {
		if err := runner.Run(ctx); err != nil {
			logger.Warn("request tracing (OBI) stopped", "err", err)
		}
	}()
	return func(list []otel.BatchInstance) {
		svc.AddDiscovered(list)
		runner.Update(list)
	}
}
