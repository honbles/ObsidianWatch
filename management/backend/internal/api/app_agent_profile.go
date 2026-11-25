package api

// app_agent_profile.go - OWNED BY THE APPLICATION BUILD. Returns the extra
// top-level YAML ("app_monitoring:") appended to endpoint agent configs.
// Returns "" when cfg.EnableAppProfile is false.
//
// The receiver listens on loopback only (and optionally a Unix socket). The user-hash
// key is derived from the organization's agent API key, so every agent of one
// organization pseudonymises user identifiers identically without the management
// server storing another secret. Rotating the agent API key therefore changes the
// pseudonyms; that is documented in docs/app.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var appSocketRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,200}$`)
var appEnvRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// appUserHashKey derives the per-organization HMAC key (empty when there is no API key).
func appUserHashKey(seed string) string {
	if seed == "" {
		return ""
	}
	m := hmac.New(sha256.New, []byte(seed))
	m.Write([]byte("obsidianwatch/app-monitoring/user-hash/v1"))
	return hex.EncodeToString(m.Sum(nil))
}

func appProfileYAML(cfg AgentBuilderConfig) string {
	if !cfg.EnableAppProfile {
		return ""
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.AppClientIPMode))
	if mode != "truncated" && mode != "off" {
		mode = "full"
	}
	var b strings.Builder
	b.WriteString("\napp_monitoring:\n")
	b.WriteString("  enabled: true\n")
	b.WriteString("  otlp:\n")
	b.WriteString("    listen: \"127.0.0.1:4318\"\n") // loopback only; never a routable address
	if sock := strings.TrimSpace(cfg.AppOTLPSocket); appSocketRe.MatchString(sock) && !strings.Contains(sock, "..") {
		fmt.Fprintf(&b, "    socket: %q\n", sock)
	}
	if k := appUserHashKey(cfg.UserHashSeed); k != "" {
		fmt.Fprintf(&b, "  user_hash_key: %q\n", k)
	}
	fmt.Fprintf(&b, "  client_ip_default: %s\n", mode)
	// The host runtime sensor is part of the app-server profile (Linux agents run it; other platforms ignore it).
	sensor := strings.ToLower(strings.TrimSpace(cfg.AppSensorMode))
	if sensor != "procevent" && sensor != "poll" {
		sensor = "auto"
	}
	b.WriteString("  ebpf:\n    enabled: true\n")
	fmt.Fprintf(&b, "    mode: %s\n", sensor)
	if env := strings.TrimSpace(cfg.AppEnvironment); appEnvRe.MatchString(env) {
		fmt.Fprintf(&b, "    environment: %q\n", env)
	}
	if cfg.AppRequestsEBPF {
		b.WriteString("    requests:\n      enabled: true\n")
	}
	b.WriteString("  slow_ms: 1000\n")
	b.WriteString("  baseline_sample_pct: 1\n")
	return b.String()
}
