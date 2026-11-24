package api

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAppProfileYAMLOffByDefault(t *testing.T) {
	if got := appProfileYAML(AgentBuilderConfig{UserHashSeed: "k"}); got != "" {
		t.Fatalf("must be empty when the profile is off: %q", got)
	}
}

func TestAppProfileYAMLContent(t *testing.T) {
	y := appProfileYAML(AgentBuilderConfig{EnableAppProfile: true, UserHashSeed: "org-key", AppOTLPSocket: "/run/ow/otlp.sock", AppClientIPMode: "TRUNCATED", AppSensorMode: "Poll", AppEnvironment: "prod"})
	var out struct {
		App struct {
			Enabled bool `yaml:"enabled"`
			OTLP    struct {
				Listen string `yaml:"listen"`
				Socket string `yaml:"socket"`
			} `yaml:"otlp"`
			Key  string `yaml:"user_hash_key"`
			Mode string `yaml:"client_ip_default"`
			Ebpf struct {
				Enabled     bool   `yaml:"enabled"`
				Mode        string `yaml:"mode"`
				Environment string `yaml:"environment"`
			} `yaml:"ebpf"`
		} `yaml:"app_monitoring"`
	}
	if err := yaml.Unmarshal([]byte(y), &out); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, y)
	}
	a := out.App
	if !a.Enabled || a.OTLP.Listen != "127.0.0.1:4318" || a.OTLP.Socket != "/run/ow/otlp.sock" || a.Mode != "truncated" || len(a.Key) != 64 {
		t.Fatalf("%+v", a)
	}
	if !a.Ebpf.Enabled || a.Ebpf.Mode != "poll" || a.Ebpf.Environment != "prod" {
		t.Fatalf("the host sensor is part of the profile: %+v", a.Ebpf)
	}
	if strings.Contains(y, "org-key") {
		t.Fatal("the API key itself must never be written into the profile")
	}
	if appUserHashKey("org-key") != a.Key || appUserHashKey("other") == a.Key || appUserHashKey("") != "" {
		t.Fatal("key derivation must be stable per organization")
	}
}

func TestAppProfileYAMLRejectsHostileValues(t *testing.T) {
	for _, sock := range []string{"relative.sock", "/run/../etc/x", "/run/a\nlive_response:\n  enabled: true", "/run/\"x", "/" + strings.Repeat("a", 300)} {
		y := appProfileYAML(AgentBuilderConfig{EnableAppProfile: true, AppOTLPSocket: sock, AppClientIPMode: "full\nlive_response: x",
			AppSensorMode: "auto\nlive_response: x", AppEnvironment: "prod\nlive_response:\n  enabled: true"})
		if strings.Contains(y, "socket:") || strings.Contains(y, "live_response") {
			t.Fatalf("hostile value accepted (%q):\n%s", sock, y)
		}
		var v map[string]any
		if err := yaml.Unmarshal([]byte(y), &v); err != nil {
			t.Fatal(err)
		}
	}
}

// The profile must compose with the real builder output as one valid document.
func TestAppProfileComposesWithBuilder(t *testing.T) {
	y := buildAgentYAML(AgentBuilderConfig{Platform: "linux", BackendURL: "https://b:8443", ManagementURL: "https://m", UserHashSeed: "k", EnableAppProfile: true})
	var v map[string]any
	if err := yaml.Unmarshal([]byte(y), &v); err != nil {
		t.Fatalf("combined YAML invalid: %v", err)
	}
	if _, ok := v["app_monitoring"]; !ok {
		t.Fatal("app_monitoring block missing from builder output")
	}
	if off := buildAgentYAML(AgentBuilderConfig{Platform: "linux", BackendURL: "https://b:8443", ManagementURL: "https://m", UserHashSeed: "k"}); strings.Contains(off, "app_monitoring") {
		t.Fatal("block must be absent when off")
	}
}

func TestAppProfileSensorDefaults(t *testing.T) {
	y := appProfileYAML(AgentBuilderConfig{EnableAppProfile: true, AppSensorMode: "kernel"}) // not a valid tier: falls back to auto
	if !strings.Contains(y, "mode: auto") || strings.Contains(y, "environment:") {
		t.Fatalf("%s", y)
	}
}

// Builds carry an enrollment token, never an API key.
func TestBuilderYAMLCarriesEnrollmentToken(t *testing.T) {
	for _, p := range []string{"linux", "windows", "macos"} {
		y := buildAgentYAML(AgentBuilderConfig{Platform: p, BackendURL: "https://b:8443", EnrollToken: "owe_tok"})
		var v struct {
			Forwarder map[string]any `yaml:"forwarder"`
		}
		if err := yaml.Unmarshal([]byte(y), &v); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if v.Forwarder["enroll_token"] != "owe_tok" {
			t.Errorf("%s: enroll_token missing: %v", p, v.Forwarder)
		}
		if _, ok := v.Forwarder["api_key"]; ok {
			t.Errorf("%s: api_key must not be in a build", p)
		}
	}
}
