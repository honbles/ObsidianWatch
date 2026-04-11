package api

// setup.go — first-run setup wizard API.
//
// Routes:
//   GET  /api/v1/setup/status   — returns whether setup is complete + current values
//   POST /api/v1/setup/complete — saves settings, optionally adds domain to cert, clears agent cache

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

const (
	certDir      = "/app/certs"
	agentCachDir = "/var/lib/obsidianwatch/agent-cache"
)

type SetupStatus struct {
	IsComplete    bool   `json:"is_complete"`
	PrivateIP     string `json:"private_ip"`
	PublicIP      string `json:"public_ip"`
	BackendDomain string `json:"backend_domain"`
	BackendURL    string `json:"backend_url"`
	ManagementURL string `json:"management_url"`
	HasAgentKey   bool   `json:"has_agent_key"`
	HasGroqKey    bool   `json:"has_groq_key"`
}

type SetupRequest struct {
	BackendDomain   string `json:"backend_domain"`
	BackendURL      string `json:"backend_url"`
	ManagementURL   string `json:"management_url"`
	AgentAPIKey     string `json:"agent_api_key"`
	GroqAPIKey      string `json:"groq_api_key"`
	AnthropicAPIKey string `json:"anthropic_api_key"`
	ThreatFoxAPIKey string `json:"threatfox_api_key"`
	OTXAPIKey       string `json:"otx_api_key"`
}

func handleSetupStatus(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		meta := readCertMeta()
		settings, _ := db.GetSettingsPrefix(r.Context(), "setup")
		ai, _ := db.GetSettingsPrefix(r.Context(), "ai")

		status := SetupStatus{
			IsComplete:    settings["seeded"] == "true",
			PrivateIP:     meta.PrivateIP,
			PublicIP:      meta.PublicIP,
			BackendDomain: settings["backend_domain"],
			BackendURL:    settings["backend_url"],
			ManagementURL: settings["management_url"],
			HasAgentKey:   settings["agent_api_key"] != "",
			HasGroqKey:    ai["groq_api_key"] != "",
		}
		writeJSON(w, 200, status)
	}
}

func handleSetupComplete(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SetupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}

		// If domain provided, regenerate server cert with domain added to SAN
		if req.BackendDomain != "" {
			if err := regenerateCertWithDomain(req.BackendDomain); err != nil {
				writeJSON(w, 500, map[string]string{"error": "cert regeneration failed: " + err.Error()})
				return
			}
		}

		// Re-read CA cert (may have changed)
		caCert, _ := os.ReadFile(filepath.Join(certDir, "ca.crt"))

		// Determine URLs
		meta := readCertMeta()
		backendURL := req.BackendURL
		if backendURL == "" {
			host := meta.PrivateIP
			if meta.PublicIP != "" {
				host = meta.PublicIP
			}
			if req.BackendDomain != "" {
				host = req.BackendDomain
			}
			backendURL = "https://" + host + ":8443"
		}
		mgmtURL := req.ManagementURL
		if mgmtURL == "" {
			mgmtURL = "http://" + meta.PrivateIP
		}

		// Save all settings to DB
		settings := map[string]string{
			"setup.backend_url":    backendURL,
			"setup.management_url": mgmtURL,
			"setup.backend_domain": req.BackendDomain,
			"setup.seeded":         "true",
		}
		if len(caCert) > 0 {
			settings["setup.ca_cert"] = string(caCert)
		}
		if req.AgentAPIKey != "" {
			settings["setup.agent_api_key"] = req.AgentAPIKey

			// Write the key into both server.yaml files so backend and
			// management stay in sync with what agents will have embedded.
			if err := writeAPIKeyToBackendConfig("/app/backend-server.yaml", req.AgentAPIKey); err != nil {
				writeJSON(w, 500, map[string]string{"error": "failed to write backend config: " + err.Error()})
				return
			}
			if err := writeAPIKeyToMgmtConfig("/app/server.yaml", req.AgentAPIKey); err != nil {
				writeJSON(w, 500, map[string]string{"error": "failed to write mgmt config: " + err.Error()})
				return
			}
			// Restart the backend container so it reloads server.yaml with the new API key
			go func() {
				time.Sleep(500 * time.Millisecond)
				restartBackendContainer()
			}()
		}
		db.SetSettingsMap(r.Context(), settings)

		// Save AI keys
		if req.GroqAPIKey != "" {
			db.SetSetting(r.Context(), "ai.groq_api_key", req.GroqAPIKey)
		}
		if req.AnthropicAPIKey != "" {
			db.SetSetting(r.Context(), "ai.anthropic_api_key", req.AnthropicAPIKey)
		}

		// Save threat intel keys directly to threat_intel_sources table
		if req.ThreatFoxAPIKey != "" {
			key := req.ThreatFoxAPIKey
			db.UpdateThreatIntelSource(r.Context(), "threatfox", true, &key)
		}
		if req.OTXAPIKey != "" {
			key := req.OTXAPIKey
			db.UpdateThreatIntelSource(r.Context(), "otx", true, &key)
		}

		// Clear agent cache — compiled binaries may have old CA cert embedded
		clearAgentCache()

		writeJSON(w, 200, map[string]string{"status": "ok", "backend_url": backendURL})
	}
}

// regenerateCertWithDomain re-signs the server cert adding the domain as a SAN.
// The CA key/cert are preserved — only server.key/server.crt change.
func regenerateCertWithDomain(domain string) error {
	sanCnf := filepath.Join(certDir, "san.cnf")

	// Read existing san.cnf to get current IPs
	existing, err := os.ReadFile(sanCnf)
	if err != nil {
		return fmt.Errorf("read san.cnf: %w", err)
	}

	// Add DNS entry to alt_names section if not already there
	content := string(existing)
	dnsEntry := "DNS.1 = " + domain
	if !strings.Contains(content, dnsEntry) {
		// Insert before the closing of alt_names section
		content = strings.TrimRight(content, "\n") + "\n" + dnsEntry + "\n"
		if err := os.WriteFile(sanCnf, []byte(content), 0644); err != nil {
			return fmt.Errorf("write san.cnf: %w", err)
		}
	}

	srvKey := filepath.Join(certDir, "server.key")
	srvCsr := filepath.Join(certDir, "server.csr")
	srvCrt := filepath.Join(certDir, "server.crt")
	caCrt  := filepath.Join(certDir, "ca.crt")
	caKey  := filepath.Join(certDir, "ca.key")

	// Generate new server key and CSR
	cmds := [][]string{
		{"openssl", "genrsa", "-out", srvKey, "2048"},
		{"openssl", "req", "-new", "-key", srvKey, "-out", srvCsr,
			"-subj", "/CN=obsidianwatch-backend", "-config", sanCnf},
		{"openssl", "x509", "-req", "-days", "3650",
			"-in", srvCsr, "-CA", caCrt, "-CAkey", caKey, "-CAcreateserial",
			"-extensions", "v3_req", "-extfile", sanCnf, "-out", srvCrt},
	}

	for _, args := range cmds {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("openssl error: %s — %s", err, string(out))
		}
	}

	// Update domain in cert-meta.json
	meta := readCertMeta()
	meta.BackendDomain = domain
	writeCertMeta(meta)

	return nil
}

// restartBackendContainer restarts the obsidianwatch-backend Docker container
// so it reloads server.yaml and picks up the newly written API key.
func restartBackendContainer() {
	exec.Command("docker", "restart", "obsidianwatch-backend").Run()
}

func clearAgentCache() {
	for _, platform := range []string{"linux", "windows", "macos"} {
		dir := filepath.Join(agentCachDir, platform)
		os.RemoveAll(dir)
		os.MkdirAll(dir, 0755)
	}
}

// writeAPIKeyToBackendConfig replaces auth.api_keys in the backend server.yaml.
// Uses simple line-based replacement to avoid reformatting the whole file.
func writeAPIKeyToBackendConfig(path, apiKey string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	result := make([]string, 0, len(lines))
	inAPIKeys := false
	replaced := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "api_keys:") {
			result = append(result, line)
			inAPIKeys = true
			continue
		}
		if inAPIKeys && strings.HasPrefix(trimmed, "- ") {
			if !replaced {
				result = append(result, `    - "`+apiKey+`"`)
				replaced = true
			}
			// skip old key lines
			continue
		}
		if inAPIKeys && !strings.HasPrefix(trimmed, "- ") && trimmed != "" {
			inAPIKeys = false
		}
		result = append(result, line)
	}
	return os.WriteFile(path, []byte(strings.Join(result, "\n")), 0644)
}

// writeAPIKeyToMgmtConfig replaces server.agent_api_key in management server.yaml.
func writeAPIKeyToMgmtConfig(path, apiKey string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, "agent_api_key:") {
			// Preserve indentation
			indent := ""
			for _, ch := range line {
				if ch == ' ' {
					indent += " "
				} else {
					break
				}
			}
			result = append(result, indent+`agent_api_key: "`+apiKey+`"`)
		} else {
			result = append(result, line)
		}
	}
	return os.WriteFile(path, []byte(strings.Join(result, "\n")), 0644)
}

type certMeta struct {
	PrivateIP     string `json:"private_ip"`
	PublicIP      string `json:"public_ip"`
	BackendDomain string `json:"backend_domain"`
}

func readCertMeta() certMeta {
	data, err := os.ReadFile(filepath.Join(certDir, "cert-meta.json"))
	if err != nil {
		return certMeta{}
	}
	var m certMeta
	json.Unmarshal(data, &m)
	return m
}

func writeCertMeta(m certMeta) {
	data, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(certDir, "cert-meta.json"), data, 0644)
}
