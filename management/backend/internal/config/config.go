package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	NVD       NVDConfig       `yaml:"nvd"`
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
	TLSCertFile string `yaml:"tls_cert_file"` // default: /app/certs/server.crt
	TLSKeyFile  string `yaml:"tls_key_file"`  // default: /app/certs/server.key
	TLSEnabled  bool   `yaml:"tls_enabled"`   // auto-set to true if cert files exist
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
	Enabled     bool     `yaml:"enabled"`
	Host        string   `yaml:"host"`
	Port        int      `yaml:"port"`
	Username    string   `yaml:"username"`
	Password    string   `yaml:"password"`
	From        string   `yaml:"from"`
	To          []string `yaml:"to"`
	MinSeverity int      `yaml:"min_severity"`
	UseTLS      bool     `yaml:"use_tls"`
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
	applyEnvOverrides(cfg)
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
			// M-07: cut from 24h to 4h to shrink the window a stolen token
			// remains usable.
			TokenDuration: 4 * time.Hour,
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

// M-09: these are the exact placeholder values that have appeared in
// .env.example / docker-compose defaults. Starting with one of them left in
// place means the DB password, JWT signing secret, or agent API key is
// public knowledge (it's in the repo), so refuse to start rather than run
// insecurely by accident.
func isPlaceholderSecret(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "changeme", "change-me", "changeme123", "password", "secret", "":
		return true
	}
	return strings.HasPrefix(v, "changeme-") || strings.HasPrefix(v, "change-me-")
}

func validate(cfg *Config) error {
	if cfg.Database.Password == "" || isPlaceholderSecret(cfg.Database.Password) {
		return fmt.Errorf("database.password is required and must not be a placeholder value")
	}
	if cfg.Auth.JWTSecret == "" || isPlaceholderSecret(cfg.Auth.JWTSecret) {
		return fmt.Errorf("auth.jwt_secret is required and must not be a placeholder value")
	}
	if len(cfg.Auth.JWTSecret) < 32 {
		return fmt.Errorf("auth.jwt_secret must be at least 32 characters (HS256 key strength); generate one with `openssl rand -hex 32`")
	}
	if cfg.Server.AgentAPIKey != "" && isPlaceholderSecret(cfg.Server.AgentAPIKey) {
		return fmt.Errorf("agent_api_key must not be a placeholder value")
	}
	return nil
}

// applyEnvOverrides fills placeholder/empty secrets from the environment so a
// clean `docker compose up` works from .env alone (H-1). Real values already
// present in the YAML always win.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("DB_PASSWORD"); v != "" && isPlaceholderSecret(cfg.Database.Password) {
		cfg.Database.Password = v
	}
	if v := os.Getenv("DB_PASSWORD"); v != "" && isPlaceholderSecret(cfg.BackendDB.Password) {
		cfg.BackendDB.Password = v
	}
	if v := os.Getenv("AGENT_API_KEY"); v != "" && isPlaceholderSecret(cfg.Server.AgentAPIKey) {
		cfg.Server.AgentAPIKey = v
	}
	if v := os.Getenv("JWT_SECRET"); v != "" && isPlaceholderSecret(cfg.Auth.JWTSecret) {
		cfg.Auth.JWTSecret = v
	}
}
