package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Auth     AuthConfig     `yaml:"auth"`
	Log      LogConfig      `yaml:"log"`
}

type ServerConfig struct {
	ListenAddr    string        `yaml:"listen_addr"`
	TLSCertFile   string        `yaml:"tls_cert_file"`
	TLSKeyFile    string        `yaml:"tls_key_file"`
	TLSCAFile     string        `yaml:"tls_ca_file"` // for mTLS client verification
	ReadTimeout   time.Duration `yaml:"read_timeout"`
	WriteTimeout  time.Duration `yaml:"write_timeout"`
	MaxBatchSize  int           `yaml:"max_batch_size"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Name     string `yaml:"name"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"ssl_mode"`
	// Connection pool
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

// DSN returns the PostgreSQL connection string.
func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		d.Host, d.Port, d.Name, d.User, d.Password, d.SSLMode,
	)
}

type AuthConfig struct {
	// APIKeys is the list of accepted X-API-Key values.
	// In production, use a secrets manager rather than plain text here.
	APIKeys []string `yaml:"api_keys"`
	// MTLSEnabled — if true, require a valid client certificate.
	// cert validation is done using TLSCAFile in ServerConfig.
	MTLSEnabled bool `yaml:"mtls_enabled"`
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
		Server: ServerConfig{
			ListenAddr:   ":8443",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			MaxBatchSize: 1000,
		},
		Database: DatabaseConfig{
			Host:            "localhost",
			Port:            5432,
			Name:            "obsidianwatch",
			User:            "obsidianwatch",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    10,
			ConnMaxLifetime: 5 * time.Minute,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

func validate(cfg *Config) error {
	if cfg.Database.Password == "" {
		return fmt.Errorf("database.password is required")
	}
	if !cfg.Auth.MTLSEnabled && len(cfg.Auth.APIKeys) == 0 {
		return fmt.Errorf("auth: at least one api_key or mtls_enabled must be set")
	}
	return nil
}
