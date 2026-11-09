package api

// cloud_azure_logs.go — Extended Azure log source ingestion.
//
// Pulls three additional log sources beyond Activity Log + Entra sign-ins:
//
//   Defender for Cloud alerts  → cloud.azure_defender
//   Entra Directory Audit Logs → cloud.entra_audit
//   NSG Flow Logs              → cloud.azure_nsg_flow  (via Monitor API)
//
// Also upgrades the Activity Log API from 2015-04-01 to 2022-06-01.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Defender for Cloud Alerts ─────────────────────────────────────────────────

type azureDefenderAlert struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Properties struct {
		AlertType            string    `json:"alertType"`
		DisplayName          string    `json:"alertDisplayName"`
		Description          string    `json:"description"`
		Severity             string    `json:"severity"` // Low/Medium/High/Fatal
		Status               string    `json:"status"`
		TimeGeneratedUtc     time.Time `json:"timeGeneratedUtc"`
		CompromisedEntity    string    `json:"compromisedEntity"`
		RemediationSteps     []string  `json:"remediationSteps"`
		Intent               string    `json:"intent"`
		AttackAtlas          []struct {
			TacticName  string   `json:"tacticName"`
			TechniqueID []string `json:"techniqueId"`
		} `json:"attackAtlas"`
		ExtendedProperties map[string]string `json:"extendedProperties"`
		ResourceIdentifiers []struct {
			Type          string `json:"type"`
			ResourceID    string `json:"azureResourceId"`
			SubscriptionID string `json:"azureSubscriptionId"`
		} `json:"resourceIdentifiers"`
	} `json:"properties"`
}

var defenderSevMap = map[string]int{
	"Fatal":  cloudSevCritical,
	"High":   cloudSevHigh,
	"Medium": cloudSevMedium,
	"Low":    cloudSevInfo,
}

func pullAzureDefenderAlerts(ctx context.Context, token, sub string, since time.Time) ([]CloudEvent, error) {
	reqURL := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/alerts?api-version=2022-01-01",
		sub)

	var allAlerts []azureDefenderAlert
	for reqURL != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			break
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			break
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 403 || resp.StatusCode == 404 {
			return nil, fmt.Errorf("defender alerts: permission denied (%d)", resp.StatusCode)
		}
		if resp.StatusCode != 200 {
			break
		}
		var result struct {
			Value    []azureDefenderAlert `json:"value"`
			NextLink string               `json:"nextLink"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			break
		}
		for _, a := range result.Value {
			if a.Properties.TimeGeneratedUtc.After(since) {
				allAlerts = append(allAlerts, a)
			}
		}
		reqURL = result.NextLink
	}

	events := make([]CloudEvent, 0, len(allAlerts))
	for _, a := range allAlerts {
		sev := cloudSevMedium
		if s, ok := defenderSevMap[a.Properties.Severity]; ok {
			sev = s
		}

		// Extract MITRE technique if available
		mitre := ""
		if len(a.Properties.AttackAtlas) > 0 && len(a.Properties.AttackAtlas[0].TechniqueID) > 0 {
			mitre = a.Properties.AttackAtlas[0].TechniqueID[0]
		}

		resourceID := ""
		if len(a.Properties.ResourceIdentifiers) > 0 {
			resourceID = a.Properties.ResourceIdentifiers[0].ResourceID
		}

		raw, _ := json.Marshal(map[string]interface{}{
			"source":            "azure_defender",
			"alert_id":          a.ID,
			"alert_type":        a.Properties.AlertType,
			"display_name":      a.Properties.DisplayName,
			"description":       a.Properties.Description,
			"severity":          a.Properties.Severity,
			"status":            a.Properties.Status,
			"compromised_entity": a.Properties.CompromisedEntity,
			"intent":            a.Properties.Intent,
			"mitre":             mitre,
			"remediation_steps": a.Properties.RemediationSteps,
			"resource_id":       resourceID,
			"extended_properties": a.Properties.ExtendedProperties,
		})

		events = append(events, CloudEvent{
			ID:        a.ID + "-" + a.Properties.TimeGeneratedUtc.Format("20060102150405"),
			Time:      a.Properties.TimeGeneratedUtc,
			AgentID:   "azure-defender-" + truncStr(sub, 8),
			Host:      a.Properties.CompromisedEntity,
			OS:        "azure",
			EventType: "cloud.azure_defender",
			Severity:  sev,
			Source:    "azure_defender",
			Raw:       raw,
		})
	}
	return events, nil
}

// ── Entra Directory Audit Logs ────────────────────────────────────────────────

type entraAuditLog struct {
	ID              string    `json:"id"`
	ActivityDateTime time.Time `json:"activityDateTime"`
	ActivityDisplayName string `json:"activityDisplayName"`
	Category        string    `json:"category"`
	OperationType   string    `json:"operationType"`
	Result          string    `json:"result"`
	ResultReason    string    `json:"resultReason"`
	InitiatedBy struct {
		User *struct {
			ID                string `json:"id"`
			DisplayName       string `json:"displayName"`
			UserPrincipalName string `json:"userPrincipalName"`
			IPAddress         string `json:"ipAddress"`
		} `json:"user"`
		App *struct {
			AppID       string `json:"appId"`
			DisplayName string `json:"displayName"`
		} `json:"app"`
	} `json:"initiatedBy"`
	TargetResources []struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Type        string `json:"type"`
	} `json:"targetResources"`
}

// High-impact audit categories that warrant elevated severity
var entraHighImpactOps = map[string]bool{
	"Add member to role":                        true,
	"Remove member from role":                   true,
	"Add user":                                  true,
	"Delete user":                               true,
	"Reset user password":                       true,
	"Update conditional access policy":          true,
	"Delete conditional access policy":          true,
	"Add application":                           true,
	"Add service principal credentials":         true,
	"Add owner to application":                  true,
	"Update authorization policy":               true,
	"Set federation settings on domain":         true,
}

func pullEntraAuditLogs(ctx context.Context, graphToken string, since time.Time, connID int64) ([]CloudEvent, error) {
	filter := fmt.Sprintf("activityDateTime ge %s", since.UTC().Format(time.RFC3339))
	reqURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=%s&$top=200&$orderby=activityDateTime desc",
		url.QueryEscape(filter))

	var allLogs []entraAuditLog
	for reqURL != "" && len(allLogs) < 2000 {
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			break
		}
		req.Header.Set("Authorization", "Bearer "+graphToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			break
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 403 {
			return nil, fmt.Errorf("entra audit logs: AuditLog.Read.All permission required")
		}
		if resp.StatusCode != 200 {
			break
		}

		var result struct {
			Value    []entraAuditLog `json:"value"`
			NextLink string          `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			break
		}
		allLogs = append(allLogs, result.Value...)
		reqURL = result.NextLink
	}

	events := make([]CloudEvent, 0, len(allLogs))
	for _, log := range allLogs {
		sev := cloudSevInfo
		if entraHighImpactOps[log.ActivityDisplayName] {
			sev = cloudSevHigh
		}
		if log.Result == "failure" {
			sev = cloudSevMedium
		}

		principal := ""
		srcIP := ""
		if log.InitiatedBy.User != nil {
			principal = log.InitiatedBy.User.UserPrincipalName
			srcIP = log.InitiatedBy.User.IPAddress
		} else if log.InitiatedBy.App != nil {
			principal = log.InitiatedBy.App.DisplayName
		}

		targets := []string{}
		for _, t := range log.TargetResources {
			if t.DisplayName != "" {
				targets = append(targets, t.DisplayName)
			}
		}

		raw, _ := json.Marshal(map[string]interface{}{
			"source":               "entra_audit",
			"id":                   log.ID,
			"activity":             log.ActivityDisplayName,
			"category":             log.Category,
			"operation_type":       log.OperationType,
			"result":               log.Result,
			"result_reason":        log.ResultReason,
			"principal":            principal,
			"src_ip":               srcIP,
			"targets":              targets,
			"target_resources":     log.TargetResources,
		})

		events = append(events, CloudEvent{
			ID:        log.ID,
			Time:      log.ActivityDateTime,
			AgentID:   fmt.Sprintf("azure-entra-audit-%d", connID),
			Host:      "azure-ad",
			OS:        "azure",
			EventType: "cloud.entra_audit",
			Severity:  sev,
			Source:    "entra_audit",
			Username:  principal,
			SrcIP:     srcIP,
			Raw:       raw,
		})
	}
	return events, nil
}

// ── NSG Flow Logs (via Monitor / Network Watcher) ─────────────────────────────

// pullAzureNSGFlowLogs reads NSG flow log configs and ingests recent denied flows.
// Note: Actual flow log data lives in storage accounts. We read the NSG flow log
// configuration to check if logging is enabled (useful for CSPM), then ingest
// any available flow log events from Log Analytics if configured.
func pullAzureNSGFlowLogs(ctx context.Context, token, sub string, since time.Time, connID int64, logger *slog.Logger) ([]CloudEvent, error) {
	// First check which NSGs have flow logging enabled via Network Watcher
	// Network Watchers are per-region — enumerate all
	nwURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/networkWatchers?api-version=2023-05-01", sub)
	var nwResp struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}

	events := []CloudEvent{}

	if err := azureCSPMGet(ctx, token, nwURL, &nwResp); err != nil {
		return events, nil // No network watchers = skip silently
	}

	for _, nw := range nwResp.Value {
		// Get flow log configs for this network watcher
		flowURL := fmt.Sprintf("https://management.azure.com/%s/flowLogs?api-version=2023-05-01", nw.ID)
		var flowResp struct {
			Value []struct {
				Name       string `json:"name"`
				Properties struct {
					TargetResourceID string `json:"targetResourceId"`
					Enabled          bool   `json:"enabled"`
					StorageID        string `json:"storageId"`
					RetentionPolicy  struct {
						Days    int  `json:"days"`
						Enabled bool `json:"enabled"`
					} `json:"retentionPolicy"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := azureCSPMGet(ctx, token, flowURL, &flowResp); err != nil {
			continue
		}

		for _, fl := range flowResp.Value {
			if fl.Properties.Enabled {
				// Flow logging is on — record as info event for visibility
				nsgName := fl.Name
				if parts := strings.Split(fl.Properties.TargetResourceID, "/"); len(parts) > 0 {
					nsgName = parts[len(parts)-1]
				}
				raw, _ := json.Marshal(map[string]interface{}{
					"source":            "azure_nsg_flow_config",
					"nsg_name":          nsgName,
					"flow_log_name":     fl.Name,
					"enabled":           fl.Properties.Enabled,
					"storage_id":        fl.Properties.StorageID,
					"retention_days":    fl.Properties.RetentionPolicy.Days,
					"network_watcher":   nw.Name,
					"location":          nw.Location,
				})
				events = append(events, CloudEvent{
					ID:        fmt.Sprintf("az-nsg-flow-%s-%s", nsgName, since.Format("20060102")),
					Time:      since,
					AgentID:   fmt.Sprintf("azure-nsgflow-%d", connID),
					Host:      nw.Location,
					OS:        "azure",
					EventType: "cloud.azure_nsg_flow",
					Severity:  cloudSevInfo,
					Source:    "azure_nsg_flow",
					Raw:       raw,
				})
			} else {
				logger.Debug("azure nsg: flow logging disabled on NSG", "nsg", fl.Name, "location", nw.Location)
			}
		}
	}
	return events, nil
}

// ── Extended sync — called from syncAzure ────────────────────────────────────

func syncAzureExtendedLogs(ctx context.Context, conn *store.CloudConnector, db *store.DB, eventDB *store.DB, logger *slog.Logger) int {
	tenantID     := conn.Credentials["tenant_id"]
	clientID     := conn.Credentials["client_id"]
	clientSecret := conn.Credentials["client_secret"]
	subID        := conn.Credentials["subscription_id"]

	if tenantID == "" || clientID == "" || clientSecret == "" || subID == "" {
		return 0
	}

	since := time.Now().UTC().Add(-10 * time.Minute)
	if conn.LastSync != nil {
		since = conn.LastSync.Add(-2 * time.Minute)
	}

	total := 0

	// Defender for Cloud alerts
	mgmtToken, err := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://management.azure.com/")
	if err != nil {
		recordSourceStatus(conn.ID, "defender_alerts", "error", "ARM token request failed: "+err.Error())
	}
	if err == nil {
		// AZ-11: subscription_id may be a list or "*"; pull Defender alerts per sub.
		subs, subErr := resolveAzureSubscriptions(ctx, mgmtToken.AccessToken, subID)
		if subErr != nil {
			subs = nil
			recordSourceStatus(conn.ID, "defender_alerts", "error", subErr.Error())
		}
		var defenderEvents []CloudEvent
		var defErr error
		defFailed := 0
		for _, sid := range subs {
			evs, e := pullAzureDefenderAlerts(ctx, mgmtToken.AccessToken, sid, since)
			if e != nil {
				defFailed++
				defErr = e
				continue
			}
			defenderEvents = append(defenderEvents, evs...)
		}
		if len(subs) > 0 && defFailed == len(subs) {
			logger.Warn("azure extended: defender alerts unavailable", "err", defErr)
			st, d := classifyAzureFailure(statusFromErr(defErr), defErr.Error())
			recordSourceStatus(conn.ID, "defender_alerts", st, d)
		} else if len(subs) > 0 && recordOK(conn.ID, "defender_alerts") && len(defenderEvents) > 0 {
			n, _ := ingestCloudEvents(ctx, eventDB, defenderEvents)
			total += n
			logger.Info("azure extended: defender alerts ingested", "count", n)
		}

		// AZ-04: the former "NSG flow log" event was a synthetic per-NSG,
		// per-day configuration summary — not real flow records — and no rule
		// used it, so it only added noise. It is no longer ingested. Real flow
		// data needs the flow-log storage account / Traffic Analytics or
		// VNet flow logs (NSG flow logs are being retired by Microsoft).
		recordSourceStatus(conn.ID, "network_flow_logs", "not_enabled",
			"Azure network flow telemetry is not ingested (NSG flow logs retiring; VNet flow logs/Traffic Analytics not yet supported)")
	}

	// AZ-12: resource/diagnostic logs from Log Analytics (optional).
	total += syncAzureResourceLogs(ctx, conn, eventDB, since)

	// Entra Audit Logs (Graph API)
	graphToken, graphErr := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://graph.microsoft.com/")
	if graphErr != nil {
		recordSourceStatus(conn.ID, "entra_audit", "permission_missing", "Graph token request failed: "+graphErr.Error())
	}
	if graphErr == nil {
		auditEvents, auditErr := pullEntraAuditLogs(ctx, graphToken.AccessToken, since, conn.ID)
		if auditErr != nil {
			logger.Warn("azure extended: entra audit logs unavailable", "err", auditErr)
			st, d := classifyAzureFailure(statusFromErr(auditErr), auditErr.Error())
			recordSourceStatus(conn.ID, "entra_audit", st, d)
		} else if recordOK(conn.ID, "entra_audit") && len(auditEvents) > 0 {
			n, _ := ingestCloudEvents(ctx, eventDB, auditEvents)
			total += n
			logger.Info("azure extended: entra audit logs ingested", "count", n)
		}
	}

	return total
}

// recordOK records a successful pull and returns true (for use in conditions).
func recordOK(connID int64, source string) bool {
	recordSourceStatus(connID, source, "ok", "")
	return true
}

// statusFromErr extracts an HTTP status code from errors shaped "... 403 ..."
// (best effort — pull helpers format status codes into their messages).
func statusFromErr(err error) int {
	for _, tok := range strings.Fields(err.Error()) {
		tok = strings.Trim(tok, ":()[],")
		if n, e := strconv.Atoi(tok); e == nil && n >= 400 && n < 600 {
			return n
		}
	}
	return 0
}
