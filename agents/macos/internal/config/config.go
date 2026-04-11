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
	Syslog    SyslogConfig    `yaml:"syslog"`
	Process   ProcessConfig   `yaml:"process"`
	Network   NetworkConfig   `yaml:"network"`
	DNS       DNSConfig       `yaml:"dns"`
	FIM       FIMConfig       `yaml:"fim"`
	ConfigMon ConfigMonConfig `yaml:"config_monitor"`
	Health    HealthConfig    `yaml:"health"`
	AppLogs   []AppLogConfig  `yaml:"app_logs"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

type SyslogConfig struct {
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

// ConfigMonConfig monitors macOS sensitive config files — equivalent to Windows registry monitoring.
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
	InstallKey    string        `yaml:"install_key"`
	ManagementURL string        `yaml:"management_url"`
	BackendURL    string        `yaml:"backend_url"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	CertFile      string        `yaml:"cert_file"`
	KeyFile       string        `yaml:"key_file"`
	CAFile        string        `yaml:"ca_file"`
	CACertPEM           string        `yaml:"ca_cert_pem"`
	ManagementCACertPEM string        `yaml:"management_ca_cert_pem"` // CA for management HTTPS; falls back to CACertPEM if empty
	APIKey        string        `yaml:"api_key"`
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
			Syslog:  SyslogConfig{Enabled: true},
			Process: ProcessConfig{Enabled: true, PollInterval: 2 * time.Second},
			Network: NetworkConfig{Enabled: true, PollInterval: 30 * time.Second},
			DNS:     DNSConfig{Enabled: true},
			FIM: FIMConfig{
				Enabled: true,
				Dirs: []FIMDirConfig{
					{Path: "/usr/bin", Recursive: false},
					{Path: "/usr/sbin", Recursive: false},
					{Path: "/usr/local/bin", Recursive: false},
					{Path: "/bin", Recursive: false},
					{Path: "/sbin", Recursive: false},
					{Path: "/private/tmp", Recursive: false, Exclude: []string{"*.log"}},
					{Path: "/tmp", Recursive: false},
				},
			},
			ConfigMon: ConfigMonConfig{
				Enabled: true,
				Paths: []string{
					"/etc/passwd",
					"/etc/sudoers",
					"/etc/sudoers.d",
					"/etc/ssh/sshd_config",
					"/etc/hosts",
					"/private/etc/passwd",
					"/private/etc/sudoers",
					"/private/etc/ssh/sshd_config",
					"/Library/LaunchDaemons",
					"/Library/LaunchAgents",
					"/System/Library/LaunchDaemons",
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

func installKeyDir() string { return "/etc/obsidianwatch" }
func InstallKeyFile() string { return installKeyFile }
