package api

// AZ-12: Azure resource (diagnostic) logs via a Log Analytics workspace.
//
// Resource logs (Key Vault audit, AKS kube-audit, Azure Firewall, App Service
// audit) are not exposed by ARM; they are routed by diagnostic settings to a
// workspace, storage account or Event Hub. This pulls them from a workspace
// with a server-side KQL filter so only security-relevant categories leave
// Azure. Connector credential: workspace_id (one ID or a comma list).
// The app registration needs "Log Analytics Reader" on the workspace.

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

var azureLogAnalyticsBase = "https://api.loganalytics.io/v1"

const azureResourceLogLimit = 5000

// azureResourceKQL builds the filtered query. Missing diagnostic columns are
// tolerated with column_ifexists so a sparse workspace doesn't fail the query.
func azureResourceKQL(since time.Time) string {
	cols := []string{"ResourceId", "ResourceType", "Category", "OperationName", "ResultType",
		"ResultSignature", "CallerIPAddress", "requestUri_s", "identity_claim_upn_s",
		"identity_claim_appid_g", "clientInfo_s", "httpStatusCode_d", "msg_s", "log_s",
		"properties_s", "action_s"}
	var ext []string
	var proj []string
	for _, c := range cols {
		ext = append(ext, fmt.Sprintf(`%s = tostring(column_ifexists("%s", ""))`, c, c))
		proj = append(proj, c)
	}
	return fmt.Sprintf(`AzureDiagnostics
| where TimeGenerated > datetime(%s)
| where (ResourceType == "VAULTS" and Category == "AuditEvent")
    or (ResourceType == "MANAGEDCLUSTERS" and Category in ("kube-audit-admin", "guard"))
    or (ResourceType == "AZUREFIREWALLS" and Category in ("AzureFirewallNetworkRule", "AzureFirewallApplicationRule"))
    or (ResourceType == "SITES" and Category == "AppServiceAuditLogs")
| extend %s
| project TimeGenerated, %s
| order by TimeGenerated asc
| take %d`, since.UTC().Format("2006-01-02T15:04:05.0000000Z"), strings.Join(ext, ", "), strings.Join(proj, ", "), azureResourceLogLimit)
}

type azureLARow map[string]string

func parseAzureLAResponse(body []byte) ([]azureLARow, error) {
	var r struct {
		Tables []struct {
			Columns []struct {
				Name string `json:"name"`
			} `json:"columns"`
			Rows [][]interface{} `json:"rows"`
		} `json:"tables"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("log analytics: bad response: %w", err)
	}
	if r.Error != nil {
		return nil, fmt.Errorf("log analytics: %s", r.Error.Message)
	}
	if len(r.Tables) == 0 {
		return nil, nil
	}
	t := r.Tables[0]
	out := make([]azureLARow, 0, len(t.Rows))
	for _, row := range t.Rows {
		m := azureLARow{}
		for i, c := range t.Columns {
			if i < len(row) && row[i] != nil {
				m[c.Name] = fmt.Sprint(row[i])
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func pullAzureResourceLogs(ctx context.Context, token, workspaceID string, since time.Time) ([]CloudEvent, error) {
	payload, _ := json.Marshal(map[string]string{"query": azureResourceKQL(since)})
	req, err := http.NewRequestWithContext(ctx, "POST", azureLogAnalyticsBase+"/workspaces/"+workspaceID+"/query", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("log analytics query %d: %s", resp.StatusCode, truncStr(string(body), 200))
	}
	rows, err := parseAzureLAResponse(body)
	if err != nil {
		return nil, err
	}
	evs := make([]CloudEvent, 0, len(rows))
	for _, row := range rows {
		if ev, ok := azureResourceRowToEvent(row, workspaceID); ok {
			evs = append(evs, ev)
		}
	}
	return evs, nil
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func azureResourceRowToEvent(row azureLARow, workspaceID string) (CloudEvent, bool) {
	ts, err := time.Parse(time.RFC3339Nano, row["TimeGenerated"])
	if err != nil {
		return CloudEvent{}, false
	}
	rid := row["ResourceId"]
	host := rid
	if i := strings.LastIndex(rid, "/"); i >= 0 {
		host = rid[i+1:]
	}
	sev := cloudSevInfo
	res := strings.ToLower(row["ResultType"] + " " + row["ResultSignature"])
	if containsAny(res, "forbidden", "unauthorized", "denied", "401", "403") {
		sev = cloudSevMedium
	}
	if row["Category"] == "guard" {
		sev = cloudSevMedium
	}
	user := row["identity_claim_upn_s"]
	if user == "" {
		user = row["identity_claim_appid_g"]
	}
	// Truncate large free-text columns so one noisy row can't bloat storage.
	for _, k := range []string{"log_s", "msg_s", "properties_s"} {
		row[k] = truncStr(row[k], 4000)
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"source": "azure_resource_log", "workspace_id": workspaceID,
		"resource_id": rid, "resource_type": row["ResourceType"], "category": row["Category"],
		"operation": row["OperationName"], "result": row["ResultType"], "result_signature": row["ResultSignature"],
		"caller_ip": row["CallerIPAddress"], "request_uri": row["requestUri_s"], "user": user,
		"client_info": row["clientInfo_s"], "http_status": row["httpStatusCode_d"],
		"action": row["action_s"], "message": row["msg_s"], "log": row["log_s"], "properties": row["properties_s"],
	})
	h := sha1.Sum([]byte(workspaceID + "|" + row["TimeGenerated"] + "|" + rid + "|" + row["Category"] + "|" + row["OperationName"] + "|" + row["CallerIPAddress"] + "|" + row["requestUri_s"] + "|" + row["log_s"] + "|" + row["msg_s"]))
	return CloudEvent{
		ID: "azres-" + hex.EncodeToString(h[:10]), Time: ts, AgentID: "azure-resource-log",
		Host: host, OS: "azure", EventType: "cloud.azure_resource", Severity: sev,
		Source: "azure_resource_log", Username: user, SrcIP: row["CallerIPAddress"], Raw: raw,
	}, true
}

// syncAzureResourceLogs pulls resource logs for each configured workspace.
func syncAzureResourceLogs(ctx context.Context, conn *store.CloudConnector, eventDB *store.DB, since time.Time) int {
	ws := splitAzureList(conn.Credentials["workspace_id"])
	if len(ws) == 0 {
		return 0
	}
	tok, err := getAzureToken(ctx, conn.Credentials["tenant_id"], conn.Credentials["client_id"], conn.Credentials["client_secret"], "https://api.loganalytics.io/")
	if err != nil {
		recordSourceStatus(conn.ID, "azure_resource_logs", "error", "Log Analytics token request failed: "+err.Error())
		return 0
	}
	total, failed := 0, 0
	var msgs []string
	for _, w := range ws {
		evs, perr := pullAzureResourceLogs(ctx, tok.AccessToken, w, since)
		if perr != nil {
			failed++
			msgs = append(msgs, w+": "+perr.Error())
			continue
		}
		n, _ := ingestCloudEvents(ctx, eventDB, evs)
		total += n
	}
	switch {
	case failed == len(ws):
		st, d := classifyAzureFailure(statusFromErr(fmt.Errorf("%s", strings.Join(msgs, "; "))), strings.Join(msgs, "; "))
		recordSourceStatus(conn.ID, "azure_resource_logs", st, d)
	case failed > 0:
		recordSourceStatus(conn.ID, "azure_resource_logs", "partial", strings.Join(msgs, "; "))
	default:
		recordSourceStatus(conn.ID, "azure_resource_logs", "ok", "")
	}
	return total
}

func splitAzureList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\n' }) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ── Signatures (cloud.azure_resource) ────────────────────────────────────────

var azureResourceSignatures = []ThreatSig{
	{
		ID: "C-AZ-RES-001", Name: "Key Vault: Access Denied",
		Description: "A Key Vault request was rejected (401/403). Repeated denials against secrets or keys can indicate probing with stolen or mis-scoped credentials.",
		Severity:    3, MITRE: "T1555", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			if ev.EventType != "cloud.azure_resource" {
				return false
			}
			raw := strings.ToLower(rawStr(ev))
			return strings.Contains(raw, `"resource_type":"vaults"`) &&
				containsAny(raw, `"result":"forbidden"`, `"result":"unauthorized"`, `"result_signature":"403"`, `"result_signature":"401"`, `"result_signature":"forbidden"`)
		},
	},
	{
		ID: "C-AZ-RES-002", Name: "AKS: Anonymous Kubernetes API Access",
		Description: "The AKS audit log shows requests from system:anonymous, which should not have meaningful access to the API server.",
		Severity:    4, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "cloud.azure_resource" &&
				strings.Contains(strings.ToLower(rawStr(ev)), "system:anonymous")
		},
	},
}
