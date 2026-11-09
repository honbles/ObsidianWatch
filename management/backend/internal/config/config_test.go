package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodSecret = "0123456789abcdef0123456789abcdef"

func TestValidate(t *testing.T) {
	mk := func(db, jwt, agent string) *Config {
		c := defaults()
		c.Database.Password, c.Auth.JWTSecret, c.Server.AgentAPIKey = db, jwt, agent
		return c
	}
	cases := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{"ok", mk("dbpass-xyz", goodSecret, ""), ""},
		{"ok with agent key", mk("dbpass-xyz", goodSecret, "agent-key-123"), ""},
		{"empty db password", mk("", goodSecret, ""), "database.password"},
		{"placeholder db password", mk("changeme", goodSecret, ""), "database.password"},
		{"placeholder jwt", mk("dbpass-xyz", "changeme-please", ""), "jwt_secret"},
		{"short jwt", mk("dbpass-xyz", "short-but-not-placeholder", ""), "at least 32"},
		{"placeholder agent key", mk("dbpass-xyz", goodSecret, "change-me-agent"), "agent_api_key"},
	}
	for _, c := range cases {
		err := validate(c.cfg)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: want error containing %q, got %v", c.name, c.wantErr, err)
		}
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	y := "database:\n  password: dbpass-xyz\nauth:\n  jwt_secret: " + goodSecret + "\n"
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.ListenAddr != ":8080" || c.Auth.TokenDuration.Hours() != 4 || c.Database.Port != 5432 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestEnvOverridesFillPlaceholders(t *testing.T) {
	t.Setenv("DB_PASSWORD", "real-db-pw")
	t.Setenv("JWT_SECRET", "0123456789abcdef0123456789abcdef")
	t.Setenv("AGENT_API_KEY", "real-agent-key")
	cfg := defaults()
	cfg.Database.Password = "changeme"
	cfg.BackendDB.Password = "changeme"
	cfg.Auth.JWTSecret = "changeme-generate"
	cfg.Server.AgentAPIKey = "changeme-generate-a-real-key"
	applyEnvOverrides(cfg)
	if cfg.Database.Password != "real-db-pw" || cfg.BackendDB.Password != "real-db-pw" ||
		cfg.Auth.JWTSecret != "0123456789abcdef0123456789abcdef" || cfg.Server.AgentAPIKey != "real-agent-key" {
		t.Fatalf("placeholders not replaced: %+v", cfg)
	}
	cfg.Database.Password = "explicit"
	applyEnvOverrides(cfg)
	if cfg.Database.Password != "explicit" {
		t.Fatal("explicit YAML value must win over env")
	}
}
