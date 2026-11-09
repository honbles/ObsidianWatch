package api

// setup.go — first-run setup wizard API.
//
// Routes:
//   GET  /api/v1/setup/status   — returns whether setup is complete + current values
//   POST /api/v1/setup/complete — saves settings, optionally adds domain to cert, clears agent cache

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// M-01: once setup has been completed once (setup.seeded=true), the setup
// wizard endpoints must require a valid admin session — otherwise anyone who
// can reach the management API can silently rewrite the agent API key, SMTP
// credentials, AI provider keys, and even re-sign the server's TLS cert for
// a new domain, with no authentication at all.
var (
	validHostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	validAPIKeyRe   = regexp.MustCompile(`^[A-Za-z0-9_\-\.]{8,256}$`)
)

func isValidHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	return validHostnameRe.MatchString(h)
}

func isValidAPIKeyFormat(k string) bool {
	return validAPIKeyRe.MatchString(k)
}

// requireSetupAuth returns the authenticated username if setup has already
// been completed and the request carries a valid admin JWT, "" (anonymous,
// allowed) if setup has not been completed yet, or writes a 401 and returns
// ("", false) if setup is complete and auth is missing/invalid.
func requireSetupAuth(db *store.DB, jwt *auth.JWTService, w http.ResponseWriter, r *http.Request) (string, bool) {
	settings, _ := db.GetSettingsPrefix(r.Context(), "setup")
	if settings["seeded"] != "true" {
		// First run — no admin account exists yet to authenticate with.
		return "", true
	}
	header := r.Header.Get("Authorization")
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		writeJSON(w, 401, map[string]string{"error": "setup already completed; admin authentication required"})
		return "", false
	}
	claims, err := jwt.Verify(parts[1])
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "invalid or expired token"})
		return "", false
	}
	// C-2: any valid JWT (e.g. a viewer) must not be able to re-run setup.
	if claims.Role != "admin" {
		writeJSON(w, 403, map[string]string{"error": "admin role required"})
		return "", false
	}
	return claims.Username, true
}

// validHTTPURL accepts only absolute http(s) URLs with a host.
func validHTTPURL(raw string, httpsOnly bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return u.Scheme == "http" && !httpsOnly
}

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

func handleSetupStatus(db *store.DB, jwtSvc *auth.JWTService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, _ := db.GetSettingsPrefix(r.Context(), "setup")
		ai, _ := db.GetSettingsPrefix(r.Context(), "ai")
		isComplete := settings["seeded"] == "true"

		status := SetupStatus{
			IsComplete:  isComplete,
			HasAgentKey: settings["agent_api_key"] != "",
			HasGroqKey:  ai["groq_api_key"] != "",
		}

		// M-01: network topology (private/public IP, backend domain/URL) is
		// only useful to the first-run wizard before an admin exists. Once
		// setup is complete, only an authenticated admin should see it —
		// otherwise an unauthenticated caller can map internal network
		// layout for free.
		authed := false
		if isComplete {
			header := r.Header.Get("Authorization")
			parts := strings.SplitN(header, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				if _, err := jwtSvc.Verify(parts[1]); err == nil {
					authed = true
				}
			}
		}
		if !isComplete || authed {
			meta := readCertMeta()
			status.PrivateIP = meta.PrivateIP
			status.PublicIP = meta.PublicIP
			status.BackendDomain = settings["backend_domain"]
			status.BackendURL = settings["backend_url"]
			status.ManagementURL = settings["management_url"]
		}
		writeJSON(w, 200, status)
	}
}

func handleSetupComplete(db *store.DB, jwtSvc *auth.JWTService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := requireSetupAuth(db, jwtSvc, w, r)
		if !ok {
			return
		}

		var req SetupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}

		// M-01: validate attacker-reachable string fields before they ever
		// touch a shell command (openssl -subj/san.cnf) or get written
		// verbatim into a YAML config file.
		if req.BackendDomain != "" && !isValidHostname(req.BackendDomain) {
			writeJSON(w, 400, map[string]string{"error": "invalid backend_domain: must be a valid hostname"})
			return
		}
		if req.BackendURL != "" && !validHTTPURL(req.BackendURL, true) {
			writeJSON(w, 400, map[string]string{"error": "invalid backend_url: must be an https URL"})
			return
		}
		if req.ManagementURL != "" && !validHTTPURL(req.ManagementURL, true) {
			writeJSON(w, 400, map[string]string{"error": "invalid management_url: must be an https URL"})
			return
		}
		if req.AgentAPIKey != "" && !isValidAPIKeyFormat(req.AgentAPIKey) {
			writeJSON(w, 400, map[string]string{"error": "invalid agent_api_key format"})
			return
		}

		certNote := ""
		// If a domain is provided, record it (cert SAN is handled by cert-init)
		if req.BackendDomain != "" {
			// H-3: the CA private key is no longer reachable from this
			// service, so the certificate cannot be re-signed here. The domain
			// is recorded; add it to EXTRA_SAN_DNS in .env and re-run
			// `docker compose up cert-init` to put it in the certificate.
			certNote = "Domain recorded. To add it to the TLS certificate set EXTRA_SAN_DNS=" + req.BackendDomain + " in .env and run: docker compose up cert-init"
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
			mgmtURL = "https://" + meta.PrivateIP
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

		if actor == "" {
			actor = "setup-wizard"
		}
		db.WriteAudit(r.Context(), actor, "setup_complete", "", "domain="+req.BackendDomain, clientIP(r))

		writeJSON(w, 200, map[string]string{"status": "ok", "backend_url": backendURL, "cert_note": certNote})
	}
}

// restartBackendContainer restarts the obsidianwatch-backend Docker container
// so it reloads server.yaml and picks up the newly written API key.
func restartBackendContainer() {
	// M-08: no docker.sock access anymore — signal via shared volume file mtime instead.
	_ = os.MkdirAll("/var/run/obsidianwatch", 0755)
	_ = os.WriteFile("/var/run/obsidianwatch/restart-signal", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
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
