package api

// agent_builder.go — on-demand agent compilation with embedded config.
//
// Flow when admin clicks "Download {platform}":
//  1. Generate the agent.yaml YAML string from admin's parameters
//  2. Write it into agents/{platform}/internal/config/embedded.go as a Go constant
//  3. Run `go build` — the config is now baked into the binary
//  4. Restore embedded.go to the empty stub
//  5. Save the compiled binary to the cache
//  6. Save a ready-to-download zip to the cache (binary + INSTALL.md only)
//  7. Stream the zip to the browser
//
// Subsequent downloads of the same platform skip compilation and serve
// the saved zip directly — instant download, no recompilation needed.
//
// Routes:
//   GET  /api/v1/agent-builder/status          — per-platform build status + zip info
//   POST /api/v1/agent-builder/build           — trigger background compile
//   POST /api/v1/agent-builder/download        — compile + save + stream zip
//   GET  /api/v1/agent-builder/download/{platform} — serve saved zip
//   GET  /api/v1/agent-builder/settings        — saved API keys (masked)

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"obsidianwatch/management/internal/store"
)

// ── Platform definitions ──────────────────────────────────────────────────────

type platformDef struct {
	GOOS           string
	GOARCH         string
	CGO            string
	SourceDir      string // path inside Docker image
	MainPkg        string
	BinaryName     string // compiled binary filename
	EmbeddedGoFile string // path to the embedded.go stub to overwrite
}

var platforms = map[string]platformDef{
	"linux": {
		GOOS: "linux", GOARCH: "amd64", CGO: "0",
		SourceDir:      "/agent-src/linux",
		MainPkg:        "./cmd/agent",
		BinaryName:     "obsidianwatch-linux-agent",
		EmbeddedGoFile: "/agent-src/linux/internal/config/embedded.go",
	},
	"windows": {
		GOOS: "windows", GOARCH: "amd64", CGO: "0",
		SourceDir:      "/agent-src/windows",
		MainPkg:        "./cmd/agent",
		BinaryName:     "obsidianwatch-win-agent.exe",
		EmbeddedGoFile: "/agent-src/windows/internal/config/embedded.go",
	},
	"macos": {
		GOOS: "darwin", GOARCH: "amd64", CGO: "0",
		SourceDir:      "/agent-src/macos",
		MainPkg:        "./cmd/agent",
		BinaryName:     "obsidianwatch-macos-agent",
		EmbeddedGoFile: "/agent-src/macos/internal/config/embedded.go",
	},
	"network": {
		GOOS: "linux", GOARCH: "amd64", CGO: "0",
		SourceDir:      "/agent-src/network",
		MainPkg:        "./cmd/probe",
		BinaryName:     "obsidianwatch-network-probe",
		EmbeddedGoFile: "/agent-src/network/internal/config/embedded.go",
	},
}

const (
	agentCacheBase = "/var/lib/obsidianwatch/agent-cache"
	embeddedStub   = `package config

// EmbeddedConfig holds the agent.yaml baked in at compile time by the Agent Builder.
// Empty in development builds — falls back to reading agent.yaml from disk.
// DO NOT EDIT — overwritten by Agent Builder before each compile.
var EmbeddedConfig = ""
`
)

// ── Build state ───────────────────────────────────────────────────────────────

type buildState struct {
	mu       sync.RWMutex
	building map[string]bool
	lastErr  map[string]string
}

var builds = &buildState{
	building: map[string]bool{},
	lastErr:  map[string]string{},
}

func (b *buildState) start(platform string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.building[platform] {
		return false
	}
	b.building[platform] = true
	delete(b.lastErr, platform)
	return true
}

func (b *buildState) finish(platform string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.building[platform] = false
	if err != nil {
		b.lastErr[platform] = err.Error()
	} else {
		delete(b.lastErr, platform)
	}
}

func (b *buildState) isBuilding(p string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.building[p]
}

// ── Cache path helpers ────────────────────────────────────────────────────────

func cachedBinaryPath(platform string) string {
	p, ok := platforms[platform]
	if !ok {
		return ""
	}
	return filepath.Join(agentCacheBase, platform, p.BinaryName)
}

func cachedZipPath(platform string) string {
	p, ok := platforms[platform]
	if !ok {
		return ""
	}
	_ = p
	return filepath.Join(agentCacheBase, platform, "obsidianwatch-"+platform+"-agent.zip")
}

func platformStatus(platform string) map[string]interface{} {
	builds.mu.RLock()
	isBuilding := builds.building[platform]
	lastErr, hasErr := builds.lastErr[platform]
	builds.mu.RUnlock()

	result := map[string]interface{}{
		"platform": platform,
		"building": isBuilding,
	}

	if info, err := os.Stat(cachedBinaryPath(platform)); err == nil {
		result["has_binary"] = true
		result["binary_built_at"] = info.ModTime().UTC().Format(time.RFC3339)
		result["binary_size"] = info.Size()
	} else {
		result["has_binary"] = false
	}

	if info, err := os.Stat(cachedZipPath(platform)); err == nil {
		result["has_zip"] = true
		result["zip_built_at"] = info.ModTime().UTC().Format(time.RFC3339)
		result["zip_size"] = info.Size()
	} else {
		result["has_zip"] = false
	}

	if hasErr {
		result["last_error"] = lastErr
	}
	return result
}

// ── Compile ───────────────────────────────────────────────────────────────────

// writeEmbeddedConfig injects the YAML string into the agent's embedded.go file
// so it gets compiled into the binary. Must be followed by restoreEmbeddedStub.
func writeEmbeddedConfig(platform, yamlContent string) error {
	p := platforms[platform]
	// Escape backticks in yaml (shouldn't exist but be safe)
	safe := strings.ReplaceAll(yamlContent, "`", "`+\"`\"+`")
	content := "package config\n\n// DO NOT EDIT — written by Agent Builder before compile, restored after.\nvar EmbeddedConfig = `" + safe + "`\n"
	return os.WriteFile(p.EmbeddedGoFile, []byte(content), 0644)
}

func restoreEmbeddedStub(platform string) {
	p := platforms[platform]
	os.WriteFile(p.EmbeddedGoFile, []byte(embeddedStub), 0644)
}

func compilePlatform(platform, yamlContent string) error {
	p, ok := platforms[platform]
	if !ok {
		return fmt.Errorf("unknown platform: %s", platform)
	}

	outDir := filepath.Join(agentCacheBase, platform)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	outPath := filepath.Join(outDir, p.BinaryName)

	// Inject config into embedded.go before compiling
	if err := writeEmbeddedConfig(platform, yamlContent); err != nil {
		return fmt.Errorf("write embedded config: %w", err)
	}
	// Always restore stub when done, even on error
	defer restoreEmbeddedStub(platform)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "build",
		"-ldflags", "-s -w",
		"-o", outPath,
		p.MainPkg,
	)
	cmd.Dir = p.SourceDir
	cmd.Env = append(os.Environ(),
		"GOOS="+p.GOOS,
		"GOARCH="+p.GOARCH,
		"CGO_ENABLED="+p.CGO,
		"GOPATH=/root/go",
		"GOCACHE=/root/.cache/go-build",
		"GOMODCACHE=/root/go/pkg/mod",
		"GOPROXY=off",      // use only modules cached during docker build — no network
		"GONOSUMDB=*",      // skip sum database lookup
		"GONOSUMCHECK=*",
		"GOFLAGS=-mod=readonly", // never update go.sum at runtime
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("go build failed: %s", string(out))
	}
	return nil
}

// buildAndSaveZip compiles the agent and saves a zip to the cache.
func buildAndSaveZip(platform string, cfg AgentBuilderConfig) error {
	yamlContent := buildAgentYAML(cfg)

	if err := compilePlatform(platform, yamlContent); err != nil {
		return err
	}

	// Build the zip and save it to disk
	zipPath := cachedZipPath(platform)
	f, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("create zip: %w", err)
	}
	defer f.Close()

	if err := writeAgentZip(f, platform); err != nil {
		os.Remove(zipPath)
		return fmt.Errorf("write zip: %w", err)
	}
	return nil
}

// writeAgentZip writes the agent zip (binary + INSTALL.md) to any writer.
func writeAgentZip(w io.Writer, platform string) error {
	p := platforms[platform]
	binaryPath := cachedBinaryPath(platform)

	binaryFile, err := os.Open(binaryPath)
	if err != nil {
		return fmt.Errorf("open binary: %w", err)
	}
	defer binaryFile.Close()
	binaryInfo, _ := binaryFile.Stat()

	zw := zip.NewWriter(w)
	defer zw.Close()

	// Binary with executable permissions
	fh := &zip.FileHeader{Name: p.BinaryName, Method: zip.Deflate}
	fh.SetMode(0755)
	fh.Modified = binaryInfo.ModTime()
	bw, _ := zw.CreateHeader(fh)
	io.Copy(bw, binaryFile)

	// INSTALL.md
	rw, _ := zw.Create("INSTALL.md")
	rw.Write([]byte(buildInstallReadme(platform)))

	return nil
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func handleAgentBuildStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := map[string]interface{}{}
		for name := range platforms {
			result[name] = platformStatus(name)
		}
		writeJSON(w, 200, result)
	}
}

// handleAgentBuild triggers a fresh compile + zip save in the background.
// Requires the full config params so the YAML can be embedded.
func handleAgentBuild(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg AgentBuilderConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil || cfg.Platform == "" {
			writeJSON(w, 400, map[string]string{"error": "platform and config params required"})
			return
		}
		if _, ok := platforms[cfg.Platform]; !ok {
			writeJSON(w, 400, map[string]string{"error": "unknown platform"})
			return
		}

		// Save API keys whenever the admin triggers a build
		if m := buildSettingsMap(cfg); len(m) > 0 {
			db.SetSettingsMap(r.Context(), m)
		}
		saveThreatIntelKeys(r.Context(), db, cfg)

		if !builds.start(cfg.Platform) {
			writeJSON(w, 409, map[string]string{"error": "build already in progress"})
			return
		}
		go func() {
			builds.finish(cfg.Platform, buildAndSaveZip(cfg.Platform, cfg))
		}()
		writeJSON(w, 202, map[string]string{"status": "building"})
	}
}

// handleAgentBuilderDownload compiles + saves zip (if not cached), then streams it.
func handleAgentBuilderDownload(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg AgentBuilderConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if cfg.Platform == "" {
			writeJSON(w, 400, map[string]string{"error": "platform required"})
			return
		}
		if cfg.BackendURL == "" || cfg.ManagementURL == "" || cfg.AgentAPIKey == "" {
			writeJSON(w, 400, map[string]string{"error": "backend_url, management_url, and agent_api_key are required"})
			return
		}

		// Save API keys — AI keys to settings table, threat intel keys to threat_intel_sources
		if m := buildSettingsMap(cfg); len(m) > 0 {
			db.SetSettingsMap(r.Context(), m)
		}
		saveThreatIntelKeys(r.Context(), db, cfg)

		// Compile + save zip if not already cached
		zipPath := cachedZipPath(cfg.Platform)
		if _, err := os.Stat(zipPath); err != nil {
			if builds.isBuilding(cfg.Platform) {
				writeJSON(w, 409, map[string]string{"error": "build already in progress — try again shortly"})
				return
			}
			if !builds.start(cfg.Platform) {
				writeJSON(w, 409, map[string]string{"error": "build already in progress"})
				return
			}
			buildErr := buildAndSaveZip(cfg.Platform, cfg)
			builds.finish(cfg.Platform, buildErr)
			if buildErr != nil {
				writeJSON(w, 500, map[string]string{"error": "compilation failed: " + buildErr.Error()})
				return
			}
		}

		serveZip(w, r, cfg.Platform)
	}
}

// handleAgentDownloadCached serves the saved zip for a platform directly.
// This is what the dashboard download buttons hit — no config params needed.
func handleAgentDownloadCached() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		platform := r.PathValue("platform")
		if _, ok := platforms[platform]; !ok {
			writeJSON(w, 400, map[string]string{"error": "unknown platform"})
			return
		}
		if _, err := os.Stat(cachedZipPath(platform)); err != nil {
			writeJSON(w, 404, map[string]string{"error": "agent not built yet — use the Agent Builder to compile first"})
			return
		}
		serveZip(w, r, platform)
	}
}

func serveZip(w http.ResponseWriter, r *http.Request, platform string) {
	zipPath := cachedZipPath(platform)
	f, err := os.Open(zipPath)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not open cached zip"})
		return
	}
	defer f.Close()

	info, _ := f.Stat()
	ts := info.ModTime().Format("20060102")
	zipName := fmt.Sprintf("obsidianwatch-%s-agent-%s.zip", platform, ts)

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, zipName))
	if info != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	}
	io.Copy(w, f)
}

func handleAgentBuilderSettings(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// AI keys
		ai, _ := db.GetSettingsPrefix(r.Context(), "ai")

		// Threat intel keys from threat_intel_sources table
		sources, _ := db.ListThreatIntelSources(r.Context())
		hasThreatFox, hasOTX := false, false
		for _, s := range sources {
			if s.Name == "threatfox" && s.APIKey != nil && *s.APIKey != "" {
				hasThreatFox = true
			}
			if s.Name == "otx" && s.APIKey != nil && *s.APIKey != "" {
				hasOTX = true
			}
		}

		// Pre-filled defaults from cert-init (empty string if not seeded)
		setup, _ := db.GetSettingsPrefix(r.Context(), "setup")

		writeJSON(w, 200, map[string]interface{}{
			// Key status badges
			"has_groq_key":      ai["groq_api_key"] != "",
			"has_anthropic_key": ai["anthropic_api_key"] != "",
			"has_threatfox_key": hasThreatFox,
			"has_otx_key":       hasOTX,
			// Pre-filled Agent Builder defaults
			"default_backend_url":    setup["backend_url"],
			"default_management_url": setup["management_url"],
			"default_ca_cert":        setup["ca_cert"],
			"default_agent_api_key":  setup["agent_api_key"],
		})
	}
}

// ── Config types and helpers ──────────────────────────────────────────────────

type AgentBuilderConfig struct {
	Platform        string `json:"platform"`
	BackendURL      string `json:"backend_url"`
	ManagementURL   string `json:"management_url"`
	AgentAPIKey     string `json:"agent_api_key"`
	CACert          string `json:"ca_cert"`
	GroqAPIKey      string `json:"groq_api_key"`
	AnthropicAPIKey string `json:"anthropic_api_key"`
	ThreatFoxAPIKey string `json:"threatfox_api_key"`
	OTXAPIKey           string `json:"otx_api_key"`
	ManagementCACert    string `json:"management_ca_cert"` // CA for management HTTPS (self-signed); leave empty if HTTP or trusted cert
	SiteName           string `json:"site_name"`              // Network probe site name
}

func buildSettingsMap(cfg AgentBuilderConfig) map[string]string {
	// Only AI keys go to the settings table — they are read back by handleAIAnalysis.
	// Threat intel keys go directly to threat_intel_sources via saveThreatIntelKeys.
	m := map[string]string{}
	if cfg.GroqAPIKey != ""      { m["ai.groq_api_key"]      = cfg.GroqAPIKey }
	if cfg.AnthropicAPIKey != "" { m["ai.anthropic_api_key"] = cfg.AnthropicAPIKey }
	return m
}

// saveThreatIntelKeys writes ThreatFox and OTX keys directly into the
// threat_intel_sources table and enables those sources.
func saveThreatIntelKeys(ctx context.Context, db *store.DB, cfg AgentBuilderConfig) {
	if cfg.ThreatFoxAPIKey != "" {
		key := cfg.ThreatFoxAPIKey
		db.UpdateThreatIntelSource(ctx, "threatfox", true, &key)
	}
	if cfg.OTXAPIKey != "" {
		key := cfg.OTXAPIKey
		db.UpdateThreatIntelSource(ctx, "otx", true, &key)
	}
}

func buildAgentYAML(cfg AgentBuilderConfig) string {
	switch cfg.Platform {
	case "windows":
		return buildWindowsYAML(cfg)
	case "macos":
		return buildMacOSYAML(cfg)
	case "network":
		return buildNetworkProbeYAML(cfg)
	default:
		return buildLinuxYAML(cfg)
	}
}



// yamlLiteral formats a string as a YAML literal block scalar indented by indent.
// Returns quoted empty string if s is empty.
func yamlLiteral(s string) string {
	if strings.TrimSpace(s) == "" {
		return "\"\"\n"
	}
	var sb strings.Builder
	sb.WriteString("|\n")
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		sb.WriteString("    " + line + "\n")
	}
	return sb.String()
}


func buildNetworkProbeYAML(cfg AgentBuilderConfig) string {
	return fmt.Sprintf(`probe:
  version: "0.1.0"
  site_name: %q
  location: ""

forwarder:
  backend_url: %q
  management_url: %q
  api_key: %q
  ca_cert_pem: %s
  batch_size: 200
  flush_interval: "10s"
  summary_interval: "5m"

syslog:
  enabled: true
  udp_addr: ":514"
  tcp_addr: ":514"
  buffer_size: 65536

netflow:
  enabled: true
  addr: ":2055"
  sflow_addr: ":6343"
  summary_interval: "5m"

snmp:
  enabled: true
  poll_interval: "60s"
  targets: []

arp:
  enabled: true
  poll_interval: "30s"
  interfaces: ["eth0"]

detection:
  port_scan_threshold: 20
  port_scan_window: 60
  brute_force_threshold: 10
  bandwidth_spike_multiplier: 3.0
  lateral_movement_enabled: true
  internal_subnets:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"

store:
  db_path: "/var/lib/obsidianwatch-probe/state.db"
  retention_days: 7

log:
  level: "info"
  format: "json"
`, cfg.SiteName, cfg.BackendURL, cfg.ManagementURL, cfg.AgentAPIKey, yamlLiteral(cfg.CACert))
}


func buildLinuxYAML(cfg AgentBuilderConfig) string {
	return fmt.Sprintf(`agent:
  id: ""
  version: "0.3.1"

forwarder:
  backend_url: %q
  management_url: %q
  ca_file: ""
  ca_cert_pem: %s
  management_ca_cert_pem: %s
  api_key: %q
  install_key: ""
  batch_size: 200
  flush_interval: 5s

queue:
  db_path: "/var/lib/obsidianwatch/queue"
  max_rows: 100000

collector:
  journald:
    enabled: true
  process:
    enabled: true
    poll_interval: 2s
  network:
    enabled: true
    poll_interval: 30s
  dns:
    enabled: true
  fim:
    enabled: true
    dirs:
      - path: /home
        recursive: true
        exclude: ["*.log", "*.cache", ".git"]
      - path: /root
        recursive: true
        exclude: ["*.log", ".cache"]
      - path: /tmp
        recursive: false
        exclude: ["*.log", "*.tmp"]
      - path: /var/tmp
        recursive: false
      - path: /etc
        recursive: false
      - path: /opt
        recursive: false
  config_monitor:
    enabled: true
    paths:
      - /etc/passwd
      - /etc/shadow
      - /etc/sudoers
      - /etc/ssh/sshd_config
      - /etc/hosts
      - /etc/systemd/system
      - /root/.ssh
  health:
    enabled: true
    interval: 60s
  rate_limit:
    enabled: true
    max_per_second: 500
    dedupe_window: 5s

log:
  level: "info"
  format: "json"
`, cfg.BackendURL, cfg.ManagementURL, yamlLiteral(cfg.CACert), yamlLiteral(cfg.ManagementCACert), cfg.AgentAPIKey)
}

func buildMacOSYAML(cfg AgentBuilderConfig) string {
	return fmt.Sprintf(`agent:
  id: ""
  version: "0.3.1"

forwarder:
  backend_url: %q
  management_url: %q
  ca_file: ""
  ca_cert_pem: %s
  management_ca_cert_pem: %s
  api_key: %q
  install_key: ""
  batch_size: 200
  flush_interval: 5s

queue:
  db_path: "/var/lib/obsidianwatch/queue"
  max_rows: 100000

collector:
  syslog:
    enabled: true
  process:
    enabled: true
    poll_interval: 2s
  network:
    enabled: true
    poll_interval: 30s
  dns:
    enabled: true
  fim:
    enabled: true
    dirs:
      - path: /usr/bin
        recursive: false
      - path: /usr/local/bin
        recursive: false
      - path: /private/tmp
        recursive: false
  config_monitor:
    enabled: true
    paths:
      - /etc/passwd
      - /etc/sudoers
      - /etc/ssh/sshd_config
      - /Library/LaunchDaemons
      - /Library/LaunchAgents
  health:
    enabled: true
    interval: 60s
  rate_limit:
    enabled: true
    max_per_second: 500
    dedupe_window: 5s

log:
  level: "info"
  format: "json"
`, cfg.BackendURL, cfg.ManagementURL, yamlLiteral(cfg.CACert), yamlLiteral(cfg.ManagementCACert), cfg.AgentAPIKey)
}

func buildWindowsYAML(cfg AgentBuilderConfig) string {
	return fmt.Sprintf(`agent:
  id: ""
  version: "0.2.0"

collector:
  event_log:
    enabled: true
    channels:
      - Security
      - System
      - Application
      - Microsoft-Windows-PowerShell/Operational
    poll_interval: 5s
  sysmon:
    enabled: true
  network:
    enabled: true
    poll_interval: 30s
  process:
    enabled: true
  registry:
    enabled: true
    keys:
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
      - HKLM\SYSTEM\CurrentControlSet\Services
      - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  dns:
    enabled: true
  fim:
    enabled: true
    dirs:
      - path: "C:\\Windows\\System32"
        recursive: false
        exclude: ["*.log", "*.tmp", "*.etl"]
  health:
    enabled: true
    interval: 60s
  rate_limit:
    enabled: true
    max_per_second: 500
    dedupe_window: 5s
  app_logs: []

forwarder:
  backend_url: %q
  management_url: %q
  ca_file: ""
  ca_cert_pem: %s
  management_ca_cert_pem: %s
  api_key: %q
  install_key: ""
  batch_size: 200
  flush_interval: 5s

queue:
  db_path: "C:\\ProgramData\\ObsidianWatch\\queue"
  max_rows: 100000

log:
  level: "info"
  format: "json"
`, cfg.BackendURL, cfg.ManagementURL, yamlLiteral(cfg.CACert), yamlLiteral(cfg.ManagementCACert), cfg.AgentAPIKey)
}

func buildInstallReadme(platform string) string {
	var sb strings.Builder
	sb.WriteString("# ObsidianWatch Agent\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s UTC\n\n", time.Now().UTC().Format("2006-01-02 15:04:05")))
	sb.WriteString("The configuration is embedded in the binary. No config file needed.\n\n")
	switch platform {
	case "linux":
		sb.WriteString("## Install\n```bash\nchmod +x obsidianwatch-linux-agent\nsudo ./obsidianwatch-linux-agent install\n```\n\n")
		sb.WriteString("## Uninstall\n```bash\nsudo ./obsidianwatch-linux-agent uninstall\n```\n")
	case "macos":
		sb.WriteString("## Install\n```bash\nchmod +x obsidianwatch-macos-agent\nsudo ./obsidianwatch-macos-agent install\n```\n\n")
		sb.WriteString("## Uninstall\n```bash\nsudo ./obsidianwatch-macos-agent uninstall\n```\n")
	case "windows":
		sb.WriteString("## Install (run as Administrator)\n```powershell\n.\\obsidianwatch-win-agent.exe install\n```\n\n")
		sb.WriteString("## Uninstall\n```powershell\n.\\obsidianwatch-win-agent.exe uninstall\n```\n")
	}
	sb.WriteString("\nInstall key is auto-generated and visible on the dashboard: Agents → shield icon.\n")
	return sb.String()
}

// SeedAgentBuilderDefaults reads cert-init metadata and the backend server.yaml
// to pre-populate Agent Builder defaults in the DB on first startup.
// Called from main.go after migrations. Does NOT mark setup as complete.
func SeedAgentBuilderDefaults(ctx context.Context, db *store.DB, agentAPIKey string) {
	// Read cert metadata written by cert-init
	metaPath := "/app/certs/cert-meta.json"
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return // cert-meta.json not found — manual cert setup, skip
	}

	var meta struct {
		PrivateIP     string `json:"private_ip"`
		PublicIP      string `json:"public_ip"`
		BackendDomain string `json:"backend_domain"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return
	}

	// Read CA cert
	caCert, err := os.ReadFile("/app/certs/ca.crt")
	if err != nil {
		return
	}

	// If AGENT_API_KEY env var set (legacy), use it — otherwise leave blank for wizard
	if agentAPIKey == "" {
		agentAPIKey = readBackendAPIKey("/app/backend-server.yaml")
	}

	// Determine backend URL — prefer domain, then public IP, then private IP
	backendHost := meta.PrivateIP
	if meta.PublicIP != "" {
		backendHost = meta.PublicIP
	}
	if meta.BackendDomain != "" {
		backendHost = meta.BackendDomain
	}
	backendURL := "https://" + backendHost + ":8443"
	// Management UI now serves HTTPS on 443
	mgmtURL := "https://" + meta.PrivateIP
	if meta.BackendDomain != "" {
		mgmtURL = "https://" + meta.BackendDomain
	}

	// Always update CA cert and URLs — cert may have been regenerated
	// Only skip if already seeded AND we're not updating critical values
	existing, _ := db.GetSetting(ctx, "setup.seeded")

	settings := map[string]string{
		"setup.ca_cert": string(caCert), // always update — cert may be regenerated
	}
	if agentAPIKey != "" {
		settings["setup.agent_api_key"] = agentAPIKey
	}

	if existing != "true" {
		// First time — also set URLs
		settings["setup.backend_url"]    = backendURL
		settings["setup.management_url"] = mgmtURL
	}

	db.SetSettingsMap(ctx, settings)
	db.SetSetting(ctx, "setup.seeded", "true")
}

// readBackendAPIKey reads the first API key from the backend server.yaml file.
func readBackendAPIKey(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Simple YAML parse — look for api_keys list
	var cfg struct {
		Auth struct {
			APIKeys []string `yaml:"api_keys"`
		} `yaml:"auth"`
	}
	if err := yaml.NewDecoder(strings.NewReader(string(data))).Decode(&cfg); err != nil {
		return ""
	}
	if len(cfg.Auth.APIKeys) > 0 {
		return cfg.Auth.APIKeys[0]
	}
	return ""
}
