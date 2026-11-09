package api

// cloud_aws_securityhub.go — Security Hub findings → events (CR-01).
// Pulls active HIGH/CRITICAL findings updated since the last sync from the
// connector's home region (the aggregation region when cross-region
// aggregation is on). GuardDuty findings are excluded — they are pulled
// directly and would otherwise be ingested twice.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type securityHubFinding struct {
	ID          string `json:"Id"`
	ProductName string `json:"ProductName"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Region      string `json:"Region"`
	AccountID   string `json:"AwsAccountId"`
	UpdatedAt   string `json:"UpdatedAt"`
	Severity    struct {
		Label string `json:"Label"`
	} `json:"Severity"`
	Types     []string `json:"Types"`
	Resources []struct {
		Type string `json:"Type"`
		ID   string `json:"Id"`
	} `json:"Resources"`
}

func securityHubToCloudEvent(f securityHubFinding, connectorID int64) CloudEvent {
	sev := cloudSevMedium
	switch strings.ToUpper(f.Severity.Label) {
	case "CRITICAL":
		sev = cloudSevCritical
	case "HIGH":
		sev = cloudSevHigh
	}
	t, err := time.Parse(time.RFC3339Nano, f.UpdatedAt)
	if err != nil {
		t = time.Now().UTC()
	}
	host := f.Region
	rtype, rid := "", ""
	if len(f.Resources) > 0 {
		rtype, rid = f.Resources[0].Type, f.Resources[0].ID
		host = rid
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"source": "securityhub", "connector_id": connectorID, "finding_id": f.ID,
		"product": f.ProductName, "title": f.Title, "description": f.Description,
		"severity_label": strings.ToUpper(f.Severity.Label), "region": f.Region,
		"account_id": f.AccountID, "types": f.Types, "resource_type": rtype, "resource_id": rid,
	})
	// The ID includes the update time so a re-opened finding raises a new event.
	return CloudEvent{
		ID: fmt.Sprintf("%s@%s", f.ID, f.UpdatedAt), Time: t,
		AgentID: fmt.Sprintf("aws-securityhub-%d", connectorID), Host: host, OS: "aws",
		EventType: "cloud.securityhub", Severity: sev, Source: "securityhub", Raw: raw,
	}
}

func securityHubFilters(since, now time.Time) map[string]interface{} {
	eq := func(v string) map[string]string { return map[string]string{"Value": v, "Comparison": "EQUALS"} }
	return map[string]interface{}{
		"SeverityLabel":  []map[string]string{eq("CRITICAL"), eq("HIGH")},
		"RecordState":    []map[string]string{eq("ACTIVE")},
		"WorkflowStatus": []map[string]string{eq("NEW"), eq("NOTIFIED")},
		"ProductName":    []map[string]string{{"Value": "GuardDuty", "Comparison": "NOT_EQUALS"}},
		"UpdatedAt":      []map[string]string{{"Start": since.UTC().Format(time.RFC3339), "End": now.UTC().Format(time.RFC3339)}},
	}
}

func pullSecurityHub(ctx context.Context, creds awsCreds, conn *store.CloudConnector, eventDB *store.DB, logger *slog.Logger) int {
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	if conn.LastSync != nil {
		since = conn.LastSync.Add(-2 * time.Minute)
	}
	host := "securityhub." + creds.Region + ".amazonaws.com"
	total, next := 0, ""
	for page := 0; page < 10; page++ {
		payload := map[string]interface{}{"Filters": securityHubFilters(since, now), "MaxResults": 100}
		if next != "" {
			payload["NextToken"] = next
		}
		body, _ := json.Marshal(payload)
		b, code, err := awsRESTPost(ctx, creds, "securityhub", host, "/findings", string(body))
		if err != nil {
			recordSourceStatus(conn.ID, "securityhub", "error", err.Error())
			return total
		}
		if code != 200 {
			st := "error"
			if code == 403 {
				st = "permission_missing"
				if strings.Contains(string(b), "InvalidAccessException") {
					recordSourceStatus(conn.ID, "securityhub", "not_enabled", "Security Hub is not enabled in "+creds.Region)
					return total
				}
			}
			recordSourceStatus(conn.ID, "securityhub", st, fmt.Sprintf("GetFindings returned %d", code))
			return total
		}
		var resp struct {
			Findings  []securityHubFinding `json:"Findings"`
			NextToken string               `json:"NextToken"`
		}
		if json.Unmarshal(b, &resp) != nil {
			recordSourceStatus(conn.ID, "securityhub", "error", "unparseable response")
			return total
		}
		events := make([]CloudEvent, 0, len(resp.Findings))
		for _, f := range resp.Findings {
			events = append(events, securityHubToCloudEvent(f, conn.ID))
		}
		n, _ := ingestCloudEvents(ctx, eventDB, events)
		total += n
		if resp.NextToken == "" {
			break
		}
		next = resp.NextToken
	}
	recordSourceStatus(conn.ID, "securityhub", "ok", "")
	if total > 0 {
		logger.Info("securityhub: ingested findings", "connector", conn.ID, "count", total)
	}
	return total
}
