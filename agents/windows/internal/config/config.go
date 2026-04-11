package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Agent     AgentConfig     `yaml:"agent"`
	Collector CollectorConfig `yaml:"collector"`
	Forwarder ForwarderConfig `yaml:"forwarder"`
	Queue     QueueConfig     `yaml:"queue"`
	Log       LogConfig       `yaml:"log"`
}

type AgentConfig struct {
	ID      string `yaml:"id"`
	Version string `yaml:"version"`
}

type CollectorConfig struct {
	EventLog EventLogConfig `yaml:"event_log"`
	Sysmon   SysmonConfig   `yaml:"sysmon"`
	Network  NetworkConfig  `yaml:"network"`
	Process  ProcessConfig  `yaml:"process"`
	Registry RegistryConfig `yaml:"registry"`
	DNS      DNSConfig      `yaml:"dns"`
	FIM      FIMConfig      `yaml:"fim"`
	Health   HealthConfig   `yaml:"health"`
	AppLogs  []AppLogConfig `yaml:"app_logs"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

type EventLogConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Channels     []string      `yaml:"channels"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

type SysmonConfig struct {
	Enabled bool `yaml:"enabled"`
}

type NetworkConfig struct {
	Enabled      bool          `yaml:"enabled"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

type ProcessConfig struct {
	Enabled bool `yaml:"enabled"`
}

type RegistryConfig struct {
	Enabled bool     `yaml:"enabled"`
	Keys    []string `yaml:"keys"`
}

type DNSConfig struct {
	Enabled bool `yaml:"enabled"`
}

type FIMConfig struct {
	Enabled bool            `yaml:"enabled"`
	Dirs    []FIMDirConfig  `yaml:"dirs"`
}

type FIMDirConfig struct {
	Path      string   `yaml:"path"`
	Recursive bool     `yaml:"recursive"`
	Exclude   []string `yaml:"exclude"`
}

type HealthConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
}

// AppLogConfig describes a single application log file to tail.
type AppLogConfig struct {
	Name      string `yaml:"name"`
	Path      string `yaml:"path"`
	Format    string `yaml:"format"`    // json | text | combined
	EventType string `yaml:"event_type"`
	Severity  int    `yaml:"severity"`
}

// RateLimitConfig controls per-source event rate limiting.
type RateLimitConfig struct {
	Enabled      bool          `yaml:"enabled"`
	MaxPerSecond int           `yaml:"max_per_second"`
	DedupeWindow time.Duration `yaml:"dedupe_window"`
}

type ForwarderConfig struct {
	InstallKey    string `yaml:"install_key"`     // tamper protection key
	ManagementURL string `yaml:"management_url"`  // ObsidianWatch management platform URL e.g. http://192.168.1.140
	BackendURL    string        `yaml:"backend_url"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	CertFile      string        `yaml:"cert_file"`
	KeyFile       string        `yaml:"key_file"`
	CAFile           string        `yaml:"ca_file"`           // CA cert for backend :8443
	CACertPEM        string        `yaml:"ca_cert_pem"`        // CA cert PEM inline (used when config is embedded in binary)
	ManagementCAFile string        `yaml:"management_ca_file"` // CA cert for management :443 (if HTTPS; falls back to ca_file if empty)
	ManagementCACertPEM string     `yaml:"management_ca_cert_pem"` // inline PEM for management CA (embedded binary)
	APIKey           string        `yaml:"api_key"`
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
		Agent: AgentConfig{Version: "0.3.2"},
		Collector: CollectorConfig{
			EventLog: EventLogConfig{
				Enabled:      true,
				Channels:     []string{"Security", "System", "Application"},
				PollInterval: 5 * time.Second,
			},
			Sysmon:  SysmonConfig{Enabled: true},
			Network: NetworkConfig{Enabled: true, PollInterval: 30 * time.Second},
			Process: ProcessConfig{Enabled: true},
			Registry: RegistryConfig{
				Enabled: true,
				Keys: []string{
					`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
					`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
					`HKLM\SYSTEM\CurrentControlSet\Services`,
					`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
				},
			},
			DNS: DNSConfig{Enabled: true},
			FIM: FIMConfig{
				Enabled: true,
				Dirs: []FIMDirConfig{
					{Path: `C:\Windows\System32`, Recursive: false,
						Exclude: []string{"*.log", "*.tmp", "*.etl"}},
					{Path: `C:\Windows\SysWOW64`, Recursive: false,
						Exclude: []string{"*.log", "*.tmp", "*.etl"}},
				},
			},
			Health: HealthConfig{Enabled: true, Interval: 60 * time.Second},
			RateLimit: RateLimitConfig{
				Enabled:      true,
				MaxPerSecond: 500,
				DedupeWindow: 5 * time.Second,
			},
		},
		Forwarder: ForwarderConfig{
			BatchSize:     200,
			FlushInterval: 5 * time.Second,
		},
		Queue: QueueConfig{
			DBPath:  `C:\ProgramData\ObsidianWatch\queue`,
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

// We never rewrite the whole config — that would mangle duration fields
// (5s → 5000000000) and lose comments/formatting.

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

const installKeyFile = "C:\\\\ProgramData\\\\ObsidianWatch\\\\.install_key"

// This replaces the old approach of patching agent.yaml on disk,
// which no longer exists when the config is embedded in the binary.
func PersistInstallKey(key string) error {
	if err := os.MkdirAll(installKeyDir(), 0755); err != nil {
		return err
	}
	return os.WriteFile(installKeyFile, []byte(key), 0600)
}

// ReadInstallKey reads the persisted install key from the state file.
func ReadInstallKey() (string, error) {
	data, err := os.ReadFile(installKeyFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func installKeyDir() string { return `C:\ProgramData\ObsidianWatch` }
func InstallKeyFile() string { return installKeyFile }
