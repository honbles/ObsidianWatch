package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
)

func handleListCloudConnectors(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connectors, err := db.ListCloudConnectors(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if connectors == nil {
			connectors = []store.CloudConnector{}
		}
		writeJSON(w, 200, map[string]interface{}{"connectors": connectors})
	}
}

func handleSaveCloudConnector(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider    string            `json:"provider"`
			Credentials map[string]string `json:"credentials"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Provider == "" {
			writeJSON(w, 400, map[string]string{"error": "provider and credentials required"})
			return
		}
		id, err := db.UpsertCloudConnector(r.Context(), req.Provider, req.Credentials)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"id": id, "status": "saved"})
	}
}

func handleTestCloudConnector(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider    string            `json:"provider"`
			Credentials map[string]string `json:"credentials"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		switch req.Provider {
		case "aws":
			creds, credErr := resolveAWSCreds(r.Context(), req.Credentials)
			if credErr != nil {
				writeJSON(w, 400, map[string]string{"error": credErr.Error()})
				return
			}
			accountID, err := testAWSConnection(r.Context(), creds)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": "ok", "account_id": accountID})

		case "azure":
			err := testAzureConnection(r.Context(),
				req.Credentials["tenant_id"],
				req.Credentials["client_id"],
				req.Credentials["client_secret"],
				firstAzureSub(req.Credentials["subscription_id"]))
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": "ok", "subscription_id": req.Credentials["subscription_id"]})

		case "gcp":
			projectID, err := testGCPConnection(r.Context(), req.Credentials["service_account"])
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			resp := map[string]interface{}{"status": "ok", "project_id": projectID}
			// G-23: per-feature permission check (best effort; never fails the test).
			var sa gcpServiceAccount
			if json.Unmarshal([]byte(req.Credentials["service_account"]), &sa) == nil {
				pid := firstGCPProject(req.Credentials["project_id"])
				if pid == "" {
					pid = projectID
				}
				if tok, terr := getGCPToken(r.Context(), sa); terr == nil && pid != "" {
					if feats, perr := testGCPPermissions(r.Context(), tok, pid); perr == nil {
						resp["features"] = feats
						resp["recommended_roles"] = gcpRecommendedRoles
					} else {
						resp["features_error"] = perr.Error()
					}
				}
			}
			writeJSON(w, 200, resp)

		default:
			writeJSON(w, 400, map[string]string{"error": "unsupported provider: " + req.Provider})
		}
	}
}

func handleDeleteCloudConnector(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		var id int64
		fmt.Sscanf(idStr, "%d", &id)
		if err := db.DeleteCloudConnector(r.Context(), id); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}

func handleSyncCloudConnector(db *store.DB, engine *CloudConnectorEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		var id int64
		fmt.Sscanf(idStr, "%d", &id)
		go engine.SyncOne(context.Background(), id)
		writeJSON(w, 200, map[string]string{"status": "sync started"})
	}
}

// ── AI Chat ───────────────────────────────────────────────────────────────────
// handleAIChat handles follow-up analyst questions about an alert.
// Receives the original alert context + conversation history + new question.

// handleRunCSPM runs a CSPM scan for a cloud connector
func handleRunCSPM(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}

		conn, err := db.GetCloudConnectorRaw(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "connector not found"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()

		switch conn.Provider {
		case "gcp":
			mctx, mcancel := context.WithTimeout(r.Context(), 15*time.Minute)
			defer mcancel()
			result, err := RunGCPCSPMForConnector(mctx, conn.Credentials, conn.AccountID)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			resultJSON, _ := json.Marshal(result)
			db.SetSetting(r.Context(), fmt.Sprintf("cspm:gcp:%d", id), string(resultJSON))
			writeJSON(w, 200, result)
		case "azure":
			tenantID := conn.Credentials["tenant_id"]
			clientID := conn.Credentials["client_id"]
			clientSecret := conn.Credentials["client_secret"]
			actx, acancel := context.WithTimeout(r.Context(), 15*time.Minute)
			defer acancel()
			result, err := RunAzureCSPMForConnector(actx, tenantID, clientID, clientSecret, conn.Credentials["subscription_id"], conn.AccountID)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			result.ConnectorID = id
			applyAzureSuppression(result)
			resultJSON, _ := json.Marshal(result)
			db.SetSetting(r.Context(), fmt.Sprintf("cspm:azure:%d", id), string(resultJSON))
			writeJSON(w, 200, result)
		case "aws":
			creds, cerr := resolveAWSCreds(ctx, conn.Credentials)
			if cerr != nil {
				writeJSON(w, 400, map[string]string{"error": cerr.Error()})
				return
			}
			result, err := RunAWSCSPM(ctx, creds, conn.AccountID)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			result.ConnectorID = id
			resultJSON, _ := json.Marshal(result)
			db.SetSetting(r.Context(), fmt.Sprintf("cspm:aws:%d", id), string(resultJSON))
			writeJSON(w, 200, result)
		default:
			writeJSON(w, 400, map[string]string{"error": "CSPM supported for GCP, Azure and AWS only"})
		}
	}
}

// handleGetCSPM returns the latest CSPM scan result
func handleGetCSPM(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}

		provider := "gcp"
		if conn, cerr := db.GetCloudConnectorRaw(r.Context(), id); cerr == nil && (conn.Provider == "azure" || conn.Provider == "aws") {
			provider = conn.Provider
		}
		val, err := db.GetSetting(r.Context(), fmt.Sprintf("cspm:%s:%d", provider, id))
		if err != nil || val == "" {
			writeJSON(w, 200, map[string]interface{}{"findings": []interface{}{}, "total_findings": 0})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(val))
	}
}

// handleCSPMAIExplain — AI explanation for a CSPM finding or AI summary of full scan
// cspmExplainLimiter: 20 AI explain calls per IP per 10 minutes (G-24).
var cspmExplainLimiter = NewRateLimiter(10*time.Minute, 20)

func handleCSPMAIExplain(cfg *config.Config, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Prompt  string      `json:"prompt"`
			Finding interface{} `json:"finding,omitempty"`
		}
		// G-24 (interim): this endpoint forwards a client-built prompt to a paid
		// LLM, so bound it — request body cap, prompt length cap, per-IP rate
		// limit. (Full fix: accept a finding ID and build the prompt server-side.)
		if !cspmExplainLimiter.Allow(clientIP(r)) {
			writeJSON(w, 429, map[string]string{"error": "too many AI requests, try again later"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if len(req.Prompt) == 0 || len(req.Prompt) > 12000 {
			writeJSON(w, 400, map[string]string{"error": "prompt must be 1-12000 characters"})
			return
		}

		// Resolve AI keys
		groqKey := cfg.Groq.APIKey
		anthropicKey := cfg.Anthropic.APIKey
		if aiSettings, err := db.GetSettingsPrefix(r.Context(), "ai"); err == nil {
			if v := aiSettings["groq_api_key"]; v != "" {
				groqKey = v
			}
			if v := aiSettings["anthropic_api_key"]; v != "" {
				anthropicKey = v
			}
		}
		if groqKey == "" && anthropicKey == "" {
			writeJSON(w, 503, map[string]string{"error": "No AI provider configured. Add a Groq or Anthropic API key in Settings → AI."})
			return
		}

		apiKey, model := groqKey, groqModelName()
		if apiKey == "" {
			apiKey, model = anthropicKey, anthropicModelName()
		}

		aiCtx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()

		text, err := callVulnAI(aiCtx, apiKey, model, req.Prompt)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "AI analysis failed: " + err.Error()})
			return
		}

		writeJSON(w, 200, map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": text},
			},
		})
	}
}

// handleRunCIS runs a CIS Benchmark scan (GCP: CIS GCP Foundation v2.0; Azure: CIS Azure Foundation v2.0)
func handleRunCIS(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		conn, err := db.GetCloudConnectorRaw(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "not found"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
		defer cancel()

		if conn.Provider == "azure" {
			tenantID := conn.Credentials["tenant_id"]
			clientID := conn.Credentials["client_id"]
			clientSecret := conn.Credentials["client_secret"]
			result, err := RunAzureCISForConnector(ctx, tenantID, clientID, clientSecret, conn.Credentials["subscription_id"], conn.AccountID)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			resultJSON, _ := json.Marshal(result)
			db.SetSetting(r.Context(), fmt.Sprintf("cis:azure:%d", id), string(resultJSON))
			writeJSON(w, 200, result)
			return
		}

		if conn.Provider == "aws" {
			creds, cerr := resolveAWSCreds(ctx, conn.Credentials)
			if cerr != nil {
				writeJSON(w, 400, map[string]string{"error": cerr.Error()})
				return
			}
			cspm, err := RunAWSCSPM(ctx, creds, conn.AccountID)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			result := AWSCISFromCSPM(cspm, conn.AccountID, id)
			resultJSON, _ := json.Marshal(result)
			db.SetSetting(r.Context(), fmt.Sprintf("cis:aws:%d", id), string(resultJSON))
			writeJSON(w, 200, result)
			return
		}
		result, err := RunGCPCISForConnector(ctx, conn.Credentials, conn.AccountID)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		resultJSON, _ := json.Marshal(result)
		db.SetSetting(r.Context(), fmt.Sprintf("cis:gcp:%d", id), string(resultJSON))
		writeJSON(w, 200, result)
	}
}

// handleGetCIS returns the latest CIS scan result
func handleGetCIS(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}

		// Try provider-specific key
		provider := "gcp"
		if conn, cerr := db.GetCloudConnectorRaw(r.Context(), id); cerr == nil && (conn.Provider == "azure" || conn.Provider == "aws") {
			provider = conn.Provider
		}
		val, err := db.GetSetting(r.Context(), fmt.Sprintf("cis:%s:%d", provider, id))
		if err != nil || val == "" {
			writeJSON(w, 200, map[string]interface{}{"controls": []interface{}{}, "total_checks": 0})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(val))
	}
}

// handleGetCompliance returns the latest compliance framework report for a connector
func handleGetCompliance(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}

		// Try GCP first, then Azure
		key := fmt.Sprintf("compliance:gcp:%d", id)
		val, err := db.GetSetting(r.Context(), key)
		if err != nil || val == "" {
			key = fmt.Sprintf("compliance:azure:%d", id)
			val, err = db.GetSetting(r.Context(), key)
		}
		if err != nil || val == "" {
			key = fmt.Sprintf("compliance:aws:%d", id)
			val, err = db.GetSetting(r.Context(), key)
		}
		if err != nil || val == "" {
			writeJSON(w, 200, map[string]interface{}{
				"message":  "No compliance report yet — run a CSPM scan first",
				"controls": []interface{}{},
				"scores":   []interface{}{},
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(val))
	}
}

// handleRunCompliance triggers an on-demand compliance mapping from the latest CSPM result
func handleRunCompliance(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}

		// Load existing CSPM result and remap compliance
		// Detect provider to use correct storage key
		cspmProvider := "gcp"
		compProvider := "gcp"
		if conn, cerr := db.GetCloudConnectorRaw(r.Context(), id); cerr == nil && conn.Provider == "aws" {
			// AWS maps from the benchmark result so unrun checks stay NOT_ASSESSED.
			val, verr := db.GetSetting(r.Context(), fmt.Sprintf("cis:aws:%d", id))
			if verr != nil || val == "" {
				writeJSON(w, 404, map[string]string{"error": "no AWS benchmark result found — run the CIS benchmark scan first"})
				return
			}
			var cis CISAzureResult
			if json.Unmarshal([]byte(val), &cis) != nil {
				writeJSON(w, 500, map[string]string{"error": "failed to parse AWS benchmark result"})
				return
			}
			report := AWSComplianceFromCIS(&cis, id, conn.AccountID)
			if b, merr := json.Marshal(report); merr == nil {
				db.SetSetting(r.Context(), fmt.Sprintf("compliance:aws:%d", id), string(b))
			}
			writeJSON(w, 200, report)
			return
		}
		if conn, cerr := db.GetCloudConnectorRaw(r.Context(), id); cerr == nil && conn.Provider == "azure" {
			cspmProvider = "azure"
			compProvider = "azure"
		}

		cspmKey := fmt.Sprintf("cspm:%s:%d", cspmProvider, id)
		cspmVal, cspmErr := db.GetSetting(r.Context(), cspmKey)
		if cspmErr != nil || cspmVal == "" {
			writeJSON(w, 404, map[string]string{"error": "no CSPM result found — run a scan first"})
			return
		}

		// For Azure, bridge AzureCSPMResult into CSPMResult for MapToCompliance
		var cspmResult CSPMResult
		if cspmProvider == "azure" {
			var azResult AzureCSPMResult
			if err := json.Unmarshal([]byte(cspmVal), &azResult); err != nil {
				writeJSON(w, 500, map[string]string{"error": "failed to parse Azure CSPM result"})
				return
			}
			cspmResult = CSPMResult{
				ConnectorID:   id,
				ProjectID:     azResult.SubscriptionID,
				ScannedAt:     azResult.ScannedAt,
				Findings:      azResult.Findings,
				TotalFindings: azResult.TotalFindings,
				Critical:      azResult.Critical,
				High:          azResult.High,
				Medium:        azResult.Medium,
				Low:           azResult.Low,
				Passed:        azResult.Passed,
				NotAssessed:   azResult.NotAssessed,
			}
		} else {
			if err := json.Unmarshal([]byte(cspmVal), &cspmResult); err != nil {
				writeJSON(w, 500, map[string]string{"error": "failed to parse CSPM result"})
				return
			}
		}

		cspmResult.ConnectorID = id
		report := MapToCompliance(&cspmResult)
		report.ConnectorID = id
		if compJSON, compErr := json.Marshal(report); compErr == nil {
			db.SetSetting(r.Context(), fmt.Sprintf("compliance:%s:%d", compProvider, id), string(compJSON))
		}
		writeJSON(w, 200, report)
	}
}
