package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	NVD NVDConfig `yaml:"nvd"`
	Server    ServerConfig    `yaml:"server"`
	Database  DatabaseConfig  `yaml:"database"`
	BackendDB DatabaseConfig  `yaml:"backend_db"`
	Auth      AuthConfig      `yaml:"auth"`
	SMTP      SMTPConfig      `yaml:"smtp"`
	Anthropic AnthropicConfig `yaml:"anthropic"`
	Groq      GroqConfig      `yaml:"groq"`
	Log       LogConfig       `yaml:"log"`
}

type AnthropicConfig struct {
	APIKey string `yaml:"api_key"`
}

type GroqConfig struct {
	APIKey string `yaml:"api_key"`
}

type NVDConfig struct {
	APIKey string `yaml:"api_key"` // optional — raises rate limit from 5/30s to 50/30s
}

type ServerConfig struct {
	ListenAddr   string        `yaml:"listen_addr"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	CORSOrigins  []string      `yaml:"cors_origins"`
	AgentAPIKey  string        `yaml:"agent_api_key"` // shared key agents use for tunnel auth
	// TLS — auto-detected from /app/certs/ if present
	TLSCertFile  string        `yaml:"tls_cert_file"`  // default: /app/certs/server.crt
	TLSKeyFile   string        `yaml:"tls_key_file"`   // default: /app/certs/server.key
	TLSEnabled   bool          `yaml:"tls_enabled"`    // auto-set to true if cert files exist
}

type DatabaseConfig struct {
	Host            string        `yaml:"host"`
	Port            int           `yaml:"port"`
	Name            string        `yaml:"name"`
	User            string        `yaml:"user"`
	Password        string        `yaml:"password"`
	SSLMode         string        `yaml:"ssl_mode"`
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		d.Host, d.Port, d.Name, d.User, d.Password, d.SSLMode,
	)
}

type AuthConfig struct {
	JWTSecret     string        `yaml:"jwt_secret"`
	TokenDuration time.Duration `yaml:"token_duration"`
}

type SMTPConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Host       string   `yaml:"host"`
	Port       int      `yaml:"port"`
	Username   string   `yaml:"username"`
	Password   string   `yaml:"password"`
	From       string   `yaml:"from"`
	To         []string `yaml:"to"`
	MinSeverity int     `yaml:"min_severity"`
	UseTLS     bool     `yaml:"use_tls"`
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
	return cfg, validate(cfg)
}

func defaults() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddr:   ":8080",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			CORSOrigins:  []string{"*"},
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
		Auth: AuthConfig{
			TokenDuration: 24 * time.Hour,
		},
		SMTP: SMTPConfig{
			Enabled:     false,
			Port:        587,
			MinSeverity: 4,
			UseTLS:      true,
		},
		Log: LogConfig{Level: "info", Format: "json"},
	}
}

func validate(cfg *Config) error {
	if cfg.Database.Password == "" {
		return fmt.Errorf("database.password is required")
	}
	if cfg.Auth.JWTSecret == "" {
		return fmt.Errorf("auth.jwt_secret is required")
	}
	return nil
}
