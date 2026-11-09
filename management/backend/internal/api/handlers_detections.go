package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

func handleListDetections(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type SigInfo struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Severity    int    `json:"severity"`
			MITRE       string `json:"mitre"`
			Category    string `json:"category"`
			Enabled     bool   `json:"enabled"`
		}
		states, _ := db.GetSignatureStates(r.Context())

		// Combine all per-OS signature sets plus DNS blocklist for the UI listing
		allSigs := make([]ThreatSig, 0, 500)
		allSigs = append(allSigs,
			linuxSignatures...,
		)
		allSigs = append(allSigs, usbSignatures...)
		allSigs = append(allSigs, softwareSignatures...)
		allSigs = append(allSigs, windowsSignatures...)
		allSigs = append(allSigs, windowsTamperSignatures...)
		allSigs = append(allSigs, windowsUSBSignatures...)
		allSigs = append(allSigs, windowsAccountSignatures...)
		allSigs = append(allSigs, remoteSessionSignatures...)
		allSigs = append(allSigs, linuxAccountSignatures...)
		allSigs = append(allSigs, macosSignatures...)
		allSigs = append(allSigs, endpointAgentSignatures...)
		allSigs = append(allSigs, dnsCatSignatures...)
		allSigs = append(allSigs, dcSignatures...)
		allSigs = append(allSigs, devopsSignatures...)
		allSigs = append(allSigs, networkSignatures...)
		// Cloud — base + extended cross-cloud
		allSigs = append(allSigs, cloudSignaturesExtended...)
		allSigs = append(allSigs, cloudReconSignatures...)
		allSigs = append(allSigs, cloudNetworkSignatures...)
		allSigs = append(allSigs, cloudLateralSignatures...)
		allSigs = append(allSigs, cloudComputeAbuseSignatures...)
		allSigs = append(allSigs, awsExtraSignatures...)
		// GCP-specific rules (cloud_gcp_sigs.go)
		allSigs = append(allSigs, gcpIAMSignatures...)
		allSigs = append(allSigs, gcpCredentialSignatures...)
		allSigs = append(allSigs, gcpComputeSignatures...)
		allSigs = append(allSigs, gcpDataSignatures...)
		allSigs = append(allSigs, gcpNetworkSignatures...)
		allSigs = append(allSigs, gcpDefenseEvasionSignatures...)
		allSigs = append(allSigs, gcpPersistenceSignatures...)
		allSigs = append(allSigs, gcpSCCSignatures...)
		allSigs = append(allSigs, gcpTelemetrySignatures...)
		allSigs = append(allSigs, gcpPolicySignatures...)
		allSigs = append(allSigs, gcpEscalationSignatures...)
		// Azure-specific rules (cloud_azure_sigs.go)
		allSigs = append(allSigs, azureIAMSignatures...)
		allSigs = append(allSigs, entraIdentitySignatures...)
		allSigs = append(allSigs, azureComputeSignatures...)
		allSigs = append(allSigs, azureDataSignatures...)
		allSigs = append(allSigs, azureNetworkSignatures...)
		allSigs = append(allSigs, azureDefenseEvasionSignatures...)
		allSigs = append(allSigs, azureDefenderSignatures...)
		allSigs = append(allSigs, azureResourceSignatures...)
		allSigs = append(allSigs, azureAuditSignatures...)

		out := make([]SigInfo, len(allSigs))
		for i, s := range allSigs {
			enabled := true
			sev := s.Severity
			if state, ok := states[s.ID]; ok {
				enabled = state.Enabled
				if state.Severity != nil {
					sev = *state.Severity
				}
			}
			out[i] = SigInfo{s.ID, s.Name, s.Description, sev, s.MITRE, s.Category, enabled}
		}
		// Sigma rules — just return enabled/disabled state (single toggle for all)
		sigmaEnabled := true
		if v, _ := db.GetSetting(r.Context(), "detection.sigma_enabled"); v == "false" {
			sigmaEnabled = false
		}
		sigmaCount, _ := db.GetSigmaRuleCount(r.Context())
		writeJSON(w, 200, map[string]interface{}{
			"signatures":    out,
			"count":         len(out),
			"sigma_enabled": sigmaEnabled,
			"sigma_count":   sigmaCount,
		})
	}
}

// handleListSASTRules returns all SAST rules for the detections page
func handleListSASTRules(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type RuleInfo struct {
			ID       string `json:"id"`
			Lang     string `json:"lang"`
			Severity string `json:"severity"`
			CWE      string `json:"cwe"`
			OWASP    string `json:"owasp"`
			Title    string `json:"title"`
			Detail   string `json:"detail"`
			Fix      string `json:"fix"`
		}
		out := make([]RuleInfo, len(SASTRules))
		for i, r := range SASTRules {
			out[i] = RuleInfo{r.ID, r.Lang, r.Severity, r.CWE, r.OWASP, r.Title, r.Detail, r.Fix}
		}
		writeJSON(w, 200, map[string]interface{}{"rules": out, "count": len(out)})
	}
}

func handleToggleDetection(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var body struct {
			Enabled  *bool `json:"enabled"`
			Severity *int  `json:"severity"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if body.Enabled != nil {
			if err := db.SetSignatureEnabled(r.Context(), id, *body.Enabled); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
		}
		if body.Severity != nil {
			if err := db.SetSignatureSeverity(r.Context(), id, *body.Severity); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

// ── Threat Intel Sources ──────────────────────────────────────────────────────

func handleListThreatIntelSources(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		sources, err := db.ListThreatIntelSources(ctx)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		liveCounts := make(map[string]int)
		if rows, err2 := db.QueryContext(ctx,
			`SELECT source, COUNT(*) FROM ioc_indicators
			 WHERE expires_at IS NULL OR expires_at > NOW() GROUP BY source`); err2 == nil {
			defer rows.Close()
			for rows.Next() {
				var src string
				var cnt int
				if rows.Scan(&src, &cnt) == nil {
					liveCounts[src] = cnt
				}
			}
		}
		type SourceOut struct {
			ID        int        `json:"id"`
			Name      string     `json:"name"`
			Enabled   bool       `json:"enabled"`
			HasAPIKey bool       `json:"has_api_key"`
			LastSync  *time.Time `json:"last_sync"`
			LastError *string    `json:"last_error"`
			IOCCount  int        `json:"ioc_count"`
		}
		out := make([]SourceOut, len(sources))
		for i, s := range sources {
			cnt := liveCounts[s.Name]
			if cnt == 0 {
				cnt = s.IOCCount
			}
			out[i] = SourceOut{
				ID:        s.ID,
				Name:      s.Name,
				Enabled:   s.Enabled,
				HasAPIKey: s.APIKey != nil && *s.APIKey != "",
				LastSync:  s.LastSync,
				LastError: s.LastError,
				IOCCount:  cnt,
			}
		}
		writeJSON(w, 200, map[string]interface{}{"sources": out})
	}
}

func handleUpdateThreatIntelSource(db *store.DB, engine *ThreatIntelEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		var body struct {
			Enabled *bool   `json:"enabled"`
			APIKey  *string `json:"api_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}

		sources, _ := db.ListThreatIntelSources(r.Context())
		var current *store.ThreatIntelSource
		for _, s := range sources {
			if s.Name == name {
				c := s
				current = &c
				break
			}
		}
		if current == nil {
			writeJSON(w, 404, map[string]string{"error": "source not found"})
			return
		}

		enabled := current.Enabled
		if body.Enabled != nil {
			enabled = *body.Enabled
		}
		apiKey := current.APIKey
		if body.APIKey != nil {
			apiKey = body.APIKey
		}

		if err := db.UpdateThreatIntelSource(r.Context(), name, enabled, apiKey); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}

		// If just enabled, trigger an immediate sync in background
		if body.Enabled != nil && *body.Enabled && !current.Enabled {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				engine.SyncSource(ctx, name, apiKey)
			}()
		}

		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

func handleTriggerSync(engine *ThreatIntelEngine, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		sources, _ := db.ListThreatIntelSources(r.Context())
		var apiKey *string
		for _, s := range sources {
			if s.Name == name {
				apiKey = s.APIKey
				break
			}
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			engine.SyncSource(ctx, name, apiKey)
		}()
		writeJSON(w, 200, map[string]string{"status": "sync started"})
	}
}

// handleSetTamperLock (F-01): the real protection against unauthorized
// uninstall is enforced on the agent itself — chattr +i on Linux, a
// restrictive service DACL on Windows, chflags uchg on macOS — and only
// lifts once the correct install key is entered locally. This dashboard
// flag is just a record of that state for display; it must never be the
// thing that GRANTS protection; the agent decides that, not an API call.
// So this endpoint only ever accepts clearing it (e.g. after a verified
// support override or key rotation), never setting it, and requires a
// reason for the audit trail.
func handleSetTamperLock(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		var body struct {
			Locked bool   `json:"locked"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if body.Locked {
			writeJSON(w, 400, map[string]string{"error": "tamper lock cannot be set from the dashboard; it is only ever set by the agent itself on install"})
			return
		}
		body.Reason = strings.TrimSpace(body.Reason)
		if body.Reason == "" {
			writeJSON(w, 400, map[string]string{"error": "reason is required to clear tamper lock"})
			return
		}
		if len(body.Reason) > 500 {
			writeJSON(w, 400, map[string]string{"error": "reason too long (max 500 characters)"})
			return
		}
		if err := db.SetTamperLock(r.Context(), agentID, false); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		claims := auth.GetClaims(r)
		db.WriteAudit(r.Context(), claims.Username, "clear_tamper_lock", agentID, body.Reason, clientIP(r))
		writeJSON(w, 200, map[string]bool{"locked": false})
	}
}

func handleRegenerateKey(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		key, err := db.RegenerateInstallKey(r.Context(), agentID)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		claims := auth.GetClaims(r)
		db.WriteAudit(r.Context(), claims.Username, "regenerate_install_key", agentID, "", clientIP(r))
		writeJSON(w, 200, map[string]string{"install_key": key})
	}
}

// ── Case Management ───────────────────────────────────────────────────────────
