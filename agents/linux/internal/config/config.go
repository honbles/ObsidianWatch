package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	LiveResponse LiveResponseConfig `yaml:"live_response"` // H-2: opt-in remote shell
	Agent        AgentConfig        `yaml:"agent"`
	Collector    CollectorConfig    `yaml:"collector"`
	Forwarder    ForwarderConfig    `yaml:"forwarder"`
	Queue        QueueConfig        `yaml:"queue"`
	Log          LogConfig          `yaml:"log"`
}

type AgentConfig struct {
	ID      string `yaml:"id"`
	Version string `yaml:"version"`
}

type CollectorConfig struct {
	Journald  JournaldConfig  `yaml:"journald"`
	Process   ProcessConfig   `yaml:"process"`
	Network   NetworkConfig   `yaml:"network"`
	DNS       DNSConfig       `yaml:"dns"`
	FIM       FIMConfig       `yaml:"fim"`
	ConfigMon ConfigMonConfig `yaml:"config_monitor"` // /etc watcher (equiv to registry)
	Health    HealthConfig    `yaml:"health"`
	AppLogs   []AppLogConfig  `yaml:"app_logs"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

type JournaldConfig struct {
	Enabled bool `yaml:"enabled"`
}

type ProcessConfig struct {
	Enabled      bool          `yaml:"enabled"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

type NetworkConfig struct {
	Enabled      bool          `yaml:"enabled"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

type DNSConfig struct {
	Enabled bool `yaml:"enabled"`
}

type FIMConfig struct {
	Enabled bool           `yaml:"enabled"`
	Dirs    []FIMDirConfig `yaml:"dirs"`
}

type FIMDirConfig struct {
	Path      string   `yaml:"path"`
	Recursive bool     `yaml:"recursive"`
	Exclude   []string `yaml:"exclude"`
}

// ConfigMonConfig monitors Linux config files — equivalent to Windows registry monitoring.
type ConfigMonConfig struct {
	Enabled bool     `yaml:"enabled"`
	Paths   []string `yaml:"paths"`
}

type HealthConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
}

type AppLogConfig struct {
	Name      string `yaml:"name"`
	Path      string `yaml:"path"`
	Format    string `yaml:"format"`
	EventType string `yaml:"event_type"`
	Severity  int    `yaml:"severity"`
}

type RateLimitConfig struct {
	Enabled      bool          `yaml:"enabled"`
	MaxPerSecond int           `yaml:"max_per_second"`
	DedupeWindow time.Duration `yaml:"dedupe_window"`
}

type ForwarderConfig struct {
	InstallKey          string        `yaml:"install_key"`
	ManagementURL       string        `yaml:"management_url"`
	BackendURL          string        `yaml:"backend_url"`
	BatchSize           int           `yaml:"batch_size"`
	FlushInterval       time.Duration `yaml:"flush_interval"`
	CertFile            string        `yaml:"cert_file"`
	KeyFile             string        `yaml:"key_file"`
	CAFile              string        `yaml:"ca_file"`
	CACertPEM           string        `yaml:"ca_cert_pem"`
	ManagementCACertPEM string        `yaml:"management_ca_cert_pem"` // CA for management HTTPS; falls back to CACertPEM if empty
	APIKey              string        `yaml:"api_key"`
	// AllowInsecureTLS (L-05): must be explicitly opted into. Without a CA
	// configured, BuildTLSConfig now hard-fails rather than silently
	// falling back to InsecureSkipVerify, which previously made the agent
	// accept ANY cert for every backend connection whenever the CA was unset.
	AllowInsecureTLS bool `yaml:"allow_insecure_tls"`
}

type QueueConfig struct {
	DBPath  string `yaml:"db_path"`
	MaxRows int    `yaml:"max_rows"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %q: %w", path, err)
	}
	defer f.Close()

	cfg := defaults()
	if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: decode: %w", err)
	}
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}
	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Agent: AgentConfig{Version: "0.3.1"},
		Collector: CollectorConfig{
			Journald: JournaldConfig{Enabled: true},
			Process:  ProcessConfig{Enabled: true, PollInterval: 2 * time.Second},
			Network:  NetworkConfig{Enabled: true, PollInterval: 10 * time.Second},
			DNS:      DNSConfig{Enabled: true},
			FIM: FIMConfig{
				Enabled: true,
				Dirs: []FIMDirConfig{
					// Use /usr/bin directly — /bin is a symlink on Ubuntu 22+
					{Path: "/usr/bin", Recursive: false},
					{Path: "/usr/sbin", Recursive: false},
					{Path: "/usr/local/bin", Recursive: false},
					{Path: "/usr/local/sbin", Recursive: false},
					{Path: "/tmp", Recursive: false, Exclude: []string{"*.log"}},
					{Path: "/var/tmp", Recursive: false},
					{Path: "/home", Recursive: true},
					{Path: "/etc", Recursive: false},
				},
			},
			ConfigMon: ConfigMonConfig{
				Enabled: true,
				Paths: []string{
					"/etc/passwd",
					"/etc/shadow",
					"/etc/sudoers",
					"/etc/sudoers.d",
					"/etc/ssh/sshd_config",
					"/etc/cron.d",
					"/etc/cron.daily",
					"/etc/cron.weekly",
					"/etc/crontab",
					"/etc/hosts",
					"/etc/ld.so.preload",
					"/etc/systemd/system",
					"/root/.ssh",
				},
			},
			Health:    HealthConfig{Enabled: true, Interval: 60 * time.Second},
			RateLimit: RateLimitConfig{Enabled: true, MaxPerSecond: 500, DedupeWindow: 5 * time.Second},
		},
		Forwarder: ForwarderConfig{
			BatchSize:     200,
			FlushInterval: 5 * time.Second,
		},
		Queue: QueueConfig{
			DBPath:  "/var/lib/obsidianwatch/queue",
			MaxRows: 100_000,
		},
		Log: LogConfig{Level: "info", Format: "json"},
	}
}

func validate(cfg *Config) error {
	if cfg.Forwarder.BackendURL == "" {
		return fmt.Errorf("forwarder.backend_url is required")
	}
	if cfg.Forwarder.BatchSize <= 0 {
		return fmt.Errorf("forwarder.batch_size must be > 0")
	}
	return nil
}

// LoadEmbedded loads config from the string baked in at compile time.
// Falls back to reading from path if EmbeddedConfig is empty (dev builds).
func LoadEmbedded(fallbackPath string) (*Config, error) {
	if EmbeddedConfig != "" {
		cfg := defaults()
		if err := yaml.NewDecoder(strings.NewReader(EmbeddedConfig)).Decode(cfg); err != nil {
			return nil, fmt.Errorf("config: decode embedded: %w", err)
		}
		if err := validate(cfg); err != nil {
			return nil, fmt.Errorf("config: validate embedded: %w", err)
		}
		return cfg, nil
	}
	// Fallback: read from file (dev / manual deployments)
	return Load(fallbackPath)
}

const installKeyFile = "/etc/obsidianwatch/.install_key"

// This replaces the old approach of patching agent.yaml on disk,
// which no longer exists when the config is embedded in the binary.
func PersistInstallKey(key string) error {
	if err := os.MkdirAll(installKeyDir(), 0700); err != nil {
		return err
	}
	return writeSecretFile(installKeyFile, []byte(key))
}

// writeSecretFile writes data with mode 0600 and also tightens the mode of a
// file that already existed (os.WriteFile keeps an old file's permissions, so
// a key first written with a looser umask would otherwise stay readable).
func writeSecretFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// ReadInstallKey reads the persisted install key from the state file.
func ReadInstallKey() (string, error) {
	data, err := os.ReadFile(installKeyFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func installKeyDir() string  { return "/etc/obsidianwatch" }
func InstallKeyFile() string { return installKeyFile }

// BuildTLSConfig (L-05) builds a *tls.Config trusting caPEM if provided.
// If caPEM is empty and allowInsecure is false, it HARD-FAILS instead of
// the old behavior of silently setting InsecureSkipVerify: true — that
// previous fallback meant any MITM could present any certificate and the
// agent would accept it without complaint whenever the CA wasn't wired up
// correctly, which is exactly the situation (misconfiguration) where you
// most need TLS to fail loudly rather than quietly do nothing.
func BuildTLSConfig(caPEM []byte, allowInsecure bool) (*tls.Config, error) {
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("tls: failed to parse CA certificate")
		}
		return &tls.Config{RootCAs: pool}, nil
	}
	if allowInsecure {
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	return nil, fmt.Errorf("tls: no CA certificate configured and allow_insecure_tls is false — refusing to connect without verifying the server certificate")
}

// LiveResponseConfig gates the analyst remote-shell tunnel. Off unless the
// agent was built (or configured) with live_response.enabled: true.
type LiveResponseConfig struct {
	Enabled bool `yaml:"enabled"`
}
