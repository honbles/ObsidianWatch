package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/notify"
	"obsidianwatch/management/internal/store"
)

func handleListUsers(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := db.ListUsers(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"users": users})
	}
}

func handleCreateUser(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		if claims.Role != "admin" {
			writeJSON(w, 403, map[string]string{"error": "admin only"})
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if body.Username == "" || body.Password == "" {
			writeJSON(w, 400, map[string]string{"error": "username and password required"})
			return
		}
		if err := validateUsername(body.Username); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if body.Role != "admin" && body.Role != "analyst" && body.Role != "viewer" {
			body.Role = "analyst"
		}
		if err := validatePassword(body.Password, body.Username, ""); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		user, err := db.CreateUser(r.Context(), body.Username, body.Password, body.Role)
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": "username already exists"})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "create_user", body.Username, body.Role, clientIP(r))
		writeJSON(w, 201, user)
	}
}

func handleDeleteUser(db *store.DB, jwt *auth.JWTService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		if claims.Role != "admin" {
			writeJSON(w, 403, map[string]string{"error": "admin only"})
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		// An admin deleting their own account is the easy way to lock everyone
		// out (especially the last admin); require another admin to do it.
		if id == claims.UserID {
			writeJSON(w, 400, map[string]string{"error": "you cannot delete your own account"})
			return
		}
		if err := db.DeleteUser(r.Context(), id); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to delete user"})
			return
		}
		jwt.RevokeUser(id) // a deleted user's existing tokens must stop working immediately
		db.WriteAudit(r.Context(), claims.Username, "delete_user", fmt.Sprintf("user:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

func handleListAuditLog(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		entries, total, err := db.ListAuditLog(r.Context(), limit, offset)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"entries": entries, "total": total})
	}
}

// ── Stats ─────────────────────────────────────────────────────────────────────

func smtpConfigFromDB(ctx context.Context, db *store.DB) config.SMTPConfig {
	m, _ := db.GetSettingsPrefix(ctx, "smtp")
	port, _ := strconv.Atoi(m["port"])
	if port == 0 {
		port = 587
	}
	minSev, _ := strconv.Atoi(m["min_severity"])
	if minSev == 0 {
		minSev = 4
	}
	var to []string
	if m["to"] != "" {
		for _, r := range strings.Split(m["to"], ",") {
			if r = strings.TrimSpace(r); r != "" {
				to = append(to, r)
			}
		}
	}
	return config.SMTPConfig{
		Enabled:     m["enabled"] == "true",
		Host:        m["host"],
		Port:        port,
		Username:    m["username"],
		Password:    m["password"],
		From:        m["from"],
		To:          to,
		MinSeverity: minSev,
		UseTLS:      m["use_tls"] != "false",
	}
}

func handleGetSMTPSettings(cfg *config.Config, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dbCfg := smtpConfigFromDB(r.Context(), db)
		smtpCfg := dbCfg
		if smtpCfg.Host == "" {
			smtpCfg = cfg.SMTP
		}
		writeJSON(w, 200, map[string]interface{}{
			"enabled":      smtpCfg.Enabled,
			"host":         smtpCfg.Host,
			"port":         smtpCfg.Port,
			"username":     smtpCfg.Username,
			"from":         smtpCfg.From,
			"to":           smtpCfg.To,
			"min_severity": smtpCfg.MinSeverity,
			"use_tls":      smtpCfg.UseTLS,
			"has_password": smtpCfg.Password != "",
		})
	}
}

func handleSaveSMTPSettings(db *store.DB, mailer *notify.Mailer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled     bool     `json:"enabled"`
			Host        string   `json:"host"`
			Port        int      `json:"port"`
			Username    string   `json:"username"`
			Password    string   `json:"password"`
			From        string   `json:"from"`
			To          []string `json:"to"`
			MinSeverity int      `json:"min_severity"`
			UseTLS      bool     `json:"use_tls"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if body.Port == 0 {
			body.Port = 587
		}
		if body.MinSeverity == 0 {
			body.MinSeverity = 4
		}
		ctx := r.Context()
		if body.Password == "" {
			body.Password, _ = db.GetSetting(ctx, "smtp.password")
		}
		values := map[string]string{
			"enabled":      fmt.Sprintf("%v", body.Enabled),
			"host":         body.Host,
			"port":         strconv.Itoa(body.Port),
			"username":     body.Username,
			"password":     body.Password,
			"from":         body.From,
			"to":           strings.Join(body.To, ","),
			"min_severity": strconv.Itoa(body.MinSeverity),
			"use_tls":      fmt.Sprintf("%v", body.UseTLS),
		}
		if err := db.SetSettingsPrefix(ctx, "smtp", values); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to save"})
			return
		}
		mailer.UpdateConfig(config.SMTPConfig{
			Enabled: body.Enabled, Host: body.Host, Port: body.Port,
			Username: body.Username, Password: body.Password,
			From: body.From, To: body.To,
			MinSeverity: body.MinSeverity, UseTLS: body.UseTLS,
		})
		writeJSON(w, 200, map[string]string{"status": "saved"})
	}
}

func handleTestSMTP(mailer *notify.Mailer, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := smtpConfigFromDB(r.Context(), db)
		if cfg.Host == "" {
			writeJSON(w, 400, map[string]string{"error": "SMTP not configured — save settings first"})
			return
		}
		testMailer := notify.NewMailer(cfg)
		if err := testMailer.TestConnection(); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "test email sent"})
	}
}

// ── Detection Signatures ───────────────────────────────────────────────────────

// handleGetAPIKeys returns all configured API keys (masked)
// Keys are stored with dot-prefix: ai.groq_api_key, ai.anthropic_api_key,
// nvd_api_key (bare), ti.threatfox_api_key etc.
// handleGetAPIKeys returns all configured API keys (masked).
// Storage locations:
//
//	AI keys  → settings table as "ai.groq_api_key", "ai.anthropic_api_key"
//	NVD      → settings table as "nvd_api_key"
//	TI feeds → threat_intel_sources table (threatfox, otx)
//	Other TI → settings table as "ti.virustotal_api_key" etc.
func handleGetAPIKeys(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		result := map[string]interface{}{}

		maskVal := func(uiKey, val string) {
			if val == "" {
				result[uiKey] = ""
				return
			}
			if len(val) > 8 {
				result[uiKey] = val[:4] + strings.Repeat("•", 8)
			} else {
				result[uiKey] = strings.Repeat("•", len(val))
			}
			result[uiKey+"_set"] = true
		}

		// AI + NVD + other TI keys from settings table
		settingsKeys := map[string]string{
			"groq_api_key":            "ai.groq_api_key",
			"anthropic_api_key":       "ai.anthropic_api_key",
			"nvd_api_key":             "nvd_api_key",
			"virustotal_api_key":      "ti.virustotal_api_key",
			"hybrid_analysis_api_key": "ti.hybrid_analysis_api_key",
			"abuseipdb_api_key":       "ti.abuseipdb_api_key",
		}
		for uiKey, storeKey := range settingsKeys {
			val, _ := db.GetSetting(ctx, storeKey)
			maskVal(uiKey, val)
		}

		// Local model: URL and model name are not secrets, so they are returned
		// as-is so the admin can see what is configured; the optional key is masked.
		if v, _ := db.GetSetting(ctx, settingLocalURL); v != "" {
			result["local_llm_url"], result["local_llm_url_set"] = v, true
		}
		if v, _ := db.GetSetting(ctx, settingLocalModel); v != "" {
			result["local_llm_model"], result["local_llm_model_set"] = v, true
		}
		kv, _ := db.GetSetting(ctx, settingLocalKey)
		maskVal("local_llm_api_key", kv)

		// Sigma pin (non-secret): shown so the admin can see what is configured.
		for _, k := range []struct{ field, key string }{{"sigma_pinned_version", "ti.sigma_pinned_version"}, {"sigma_pinned_sha256", "ti.sigma_pinned_sha256"}} {
			if v, _ := db.GetSetting(ctx, k.key); v != "" {
				result[k.field], result[k.field+"_set"] = v, true
			}
		}

		// Model names are not secrets; show the effective value.
		refreshAIModels(ctx, db)
		result["groq_model"], result["anthropic_model"] = groqModelName(), anthropicModelName()

		// ThreatFox + OTX from threat_intel_sources table
		if sources, err := db.ListThreatIntelSources(ctx); err == nil {
			for _, src := range sources {
				switch src.Name {
				case "threatfox":
					if src.APIKey != nil {
						maskVal("threatfox_api_key", *src.APIKey)
					} else {
						result["threatfox_api_key"] = ""
					}
				case "otx":
					if src.APIKey != nil {
						maskVal("otx_api_key", *src.APIKey)
					} else {
						result["otx_api_key"] = ""
					}
				}
			}
		}

		writeJSON(w, 200, result)
	}
}

// handleSaveAPIKeys saves API keys to their correct storage locations.
func handleSaveAPIKeys(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		ctx := r.Context()
		saved := []string{}

		save := func(uiKey, storeKey string) {
			v, ok := body[uiKey]
			if !ok || strings.Contains(v, "•") {
				return
			} // skip if absent or masked
			_ = db.SetSetting(ctx, storeKey, v)
			saved = append(saved, uiKey)
		}

		// Settings table keys
		save("groq_api_key", "ai.groq_api_key")
		save("anthropic_api_key", "ai.anthropic_api_key")
		save("nvd_api_key", "nvd_api_key")
		save("virustotal_api_key", "ti.virustotal_api_key")
		save("hybrid_analysis_api_key", "ti.hybrid_analysis_api_key")
		save("abuseipdb_api_key", "ti.abuseipdb_api_key")

		// Self-hosted model for natural-language search (P-14/P-15).
		if v, ok := body["local_llm_url"]; ok {
			u, err := validateLocalLLMURL(v)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": "local model URL: " + err.Error()})
				return
			}
			_ = db.SetSetting(ctx, settingLocalURL, u)
			saved = append(saved, "local_llm_url")
		}
		if v, ok := body["local_llm_model"]; ok {
			v = strings.TrimSpace(v)
			if len(v) > 100 {
				writeJSON(w, 400, map[string]string{"error": "local model name too long"})
				return
			}
			_ = db.SetSetting(ctx, settingLocalModel, v)
			saved = append(saved, "local_llm_model")
		}
		save("local_llm_api_key", settingLocalKey)

		for _, m := range []struct{ field, key string }{{"groq_model", settingGroqModel}, {"anthropic_model", settingAnthropicModel}} {
			if v, ok := body[m.field]; ok {
				v = strings.TrimSpace(v)
				if v != "" && !validModelName(v) {
					writeJSON(w, 400, map[string]string{"error": m.field + ": invalid model name"})
					return
				}
				_ = db.SetSetting(ctx, m.key, v)
				saved = append(saved, m.field)
			}
		}
		refreshAIModels(ctx, db)

		if v, ok := body["sigma_pinned_version"]; ok {
			v = strings.TrimSpace(v)
			if v != "" && !sigmaVersionRe.MatchString(v) {
				writeJSON(w, 400, map[string]string{"error": "sigma_pinned_version must be a release tag such as r2025-01-01 (never 'latest')"})
				return
			}
			_ = db.SetSetting(ctx, "ti.sigma_pinned_version", v)
			saved = append(saved, "sigma_pinned_version")
		}
		if v, ok := body["sigma_pinned_sha256"]; ok {
			v = strings.ToLower(strings.TrimSpace(v))
			if v != "" && !sigmaSHARe.MatchString(v) {
				writeJSON(w, 400, map[string]string{"error": "sigma_pinned_sha256 must be 64 hex characters"})
				return
			}
			_ = db.SetSetting(ctx, "ti.sigma_pinned_sha256", v)
			saved = append(saved, "sigma_pinned_sha256")
		}

		// ThreatFox → threat_intel_sources table
		if v, ok := body["threatfox_api_key"]; ok && !strings.Contains(v, "•") {
			_ = db.UpdateThreatIntelSource(ctx, "threatfox", v != "", func() *string {
				if v == "" {
					return nil
				}
				return &v
			}())
			saved = append(saved, "threatfox_api_key")
		}
		// OTX → threat_intel_sources table
		if v, ok := body["otx_api_key"]; ok && !strings.Contains(v, "•") {
			_ = db.UpdateThreatIntelSource(ctx, "otx", v != "", func() *string {
				if v == "" {
					return nil
				}
				return &v
			}())
			saved = append(saved, "otx_api_key")
		}

		writeJSON(w, 200, map[string]interface{}{"saved": saved})
	}
}

// handleToggleSigma enables or disables ALL Sigma rules at once.
func handleToggleSigma(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		val := "true"
		if !body.Enabled {
			val = "false"
		}
		if err := db.SetSetting(r.Context(), "detection.sigma_enabled", val); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true, "enabled": body.Enabled})
	}
}

// ── IP ISP/ASN Lookup ─────────────────────────────────────────────────────────

// handleSigmaPinSeen: POST /api/v1/threat-intel-sources/sigma/pin-seen
// {"prefix":"45ccbd62"}. The admin supplies the first 8 hex characters of the
// sigma_core.zip digest from the GitHub release page; if they match the hash
// the server actually downloaded, that full hash is pinned. Verification still
// happens against GitHub's page — it just avoids retyping 64 characters.
func handleSigmaPinSeen(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Prefix string `json:"prefix"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid body")
			return
		}
		prefix := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(body.Prefix), "sha256:")))
		sigmaSeenMu.Lock()
		ver, sha := sigmaSeenVer, sigmaSeenSHA
		sigmaSeenMu.Unlock()
		if sha == "" {
			writeJSONError(w, http.StatusConflict, "no downloaded hash to confirm — press Sync now first")
			return
		}
		if len(prefix) < 8 || !strings.HasPrefix(sha, prefix) {
			writeJSONError(w, http.StatusBadRequest, "those characters do not match the hash the server downloaded (starts "+sha[:8]+")")
			return
		}
		cur, _ := db.GetSetting(r.Context(), "ti.sigma_pinned_version")
		if strings.TrimSpace(cur) != ver {
			writeJSONError(w, http.StatusConflict, "release tag changed since the download — press Sync now again")
			return
		}
		_ = db.SetSetting(r.Context(), "ti.sigma_pinned_sha256", sha)
		writeJSON(w, 200, map[string]string{"status": "pinned", "sha256": sha})
	}
}
