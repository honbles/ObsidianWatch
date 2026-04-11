package api

// cloud_azure.go — Microsoft Azure Activity Log puller.
//
// Uses Azure REST API with OAuth2 client credentials flow.
// Pulls Azure Monitor Activity Log (equivalent of AWS CloudTrail).
//
// Required Azure app registration permissions:
//   Microsoft.Insights/eventtypes/values/Read  (Activity Log)
//   Directory.Read.All (optional — for Entra ID sign-in logs)
//
// Setup:
//   1. Azure Portal → App registrations → New registration
//   2. Certificates & secrets → New client secret
//   3. Subscriptions → Access control (IAM) → Add role assignment
//      Role: Monitoring Reader, assign to your app registration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// azureToken holds an OAuth2 access token with expiry
type azureToken struct {
	AccessToken string    `json:"access_token"`
	ExpiresIn   int       `json:"expires_in"`
	ExpiresAt   time.Time `json:"-"`
}

// getAzureToken retrieves an OAuth2 token using client credentials flow
func getAzureToken(ctx context.Context, tenantID, clientID, clientSecret, resource string) (*azureToken, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", tenantID)

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"resource":      {resource},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		json.Unmarshal(body, &errResp)
		return nil, fmt.Errorf("auth failed: %s", errResp.ErrorDescription)
	}

	var token azureToken
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn-60) * time.Second)
	return &token, nil
}

// azureActivityEvent represents an Azure Activity Log event
type azureActivityEvent struct {
	ID             string    `json:"id"`
	EventTimestamp time.Time `json:"eventTimestamp"`
	EventName      struct {
		Value string `json:"value"`
	} `json:"eventName"`
	Category struct {
		Value string `json:"value"`
	} `json:"category"`
	OperationName struct {
		Value string `json:"value"`
	} `json:"operationName"`
	Status struct {
		Value string `json:"value"`
	} `json:"status"`
	Level            string `json:"level"`
	ResourceID       string `json:"resourceId"`
	ResourceGroupName string `json:"resourceGroupName"`
	ResourceProviderName struct {
		Value string `json:"value"`
	} `json:"resourceProviderName"`
	Caller          string `json:"caller"`
	CorrelationID   string `json:"correlationId"`
	Description     string `json:"description"`
	Properties      json.RawMessage `json:"properties"`
	HTTPRequest     struct {
		ClientIPAddress string `json:"clientIpAddress"`
		Method          string `json:"method"`
		URI             string `json:"uri"`
	} `json:"httpRequest"`
}

// pullAzureActivityLog fetches Activity Log events for a subscription
func pullAzureActivityLog(ctx context.Context, token, subscriptionID string, since time.Time, nextLink string) ([]azureActivityEvent, string, error) {
	var reqURL string
	if nextLink != "" {
		reqURL = nextLink
	} else {
		filter := fmt.Sprintf("eventTimestamp ge '%s'", since.UTC().Format(time.RFC3339))
		reqURL = fmt.Sprintf(
			"https://management.azure.com/subscriptions/%s/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&$filter=%s",
			subscriptionID, url.QueryEscape(filter))
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("activity log API: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("activity log API %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Value    []azureActivityEvent `json:"value"`
		NextLink string               `json:"nextLink"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, "", fmt.Errorf("parse activity log: %w", err)
	}
	return result.Value, result.NextLink, nil
}

// azureSeverityMap maps Azure levels to our severity scale
var azureSeverityMap = map[string]int{
	"Critical":    cloudSevCritical,
	"Error":       cloudSevHigh,
	"Warning":     cloudSevMedium,
	"Informational": cloudSevInfo,
	"Verbose":     cloudSevInfo,
}

// azureSensitiveOps are operation names that warrant higher severity
var azureSensitiveOps = []string{
	"Microsoft.Authorization/roleAssignments/write",
	"Microsoft.Authorization/roleDefinitions/write",
	"Microsoft.KeyVault/vaults/delete",
	"Microsoft.KeyVault/vaults/secrets/write",
	"Microsoft.Network/networkSecurityGroups/write",
	"Microsoft.Compute/virtualMachines/delete",
	"Microsoft.Storage/storageAccounts/delete",
	"Microsoft.Sql/servers/delete",
	"Microsoft.AAD/users/delete",
	"microsoft.aad/users/strongAuthenticationMethods/delete",
}

func azureEventToCloudEvent(e azureActivityEvent, connectorID int64) CloudEvent {
	sev := cloudSevInfo
	if s, ok := azureSeverityMap[e.Level]; ok {
		sev = s
	}
	opLower := strings.ToLower(e.OperationName.Value)
	for _, op := range azureSensitiveOps {
		if strings.ToLower(op) == opLower {
			if sev < cloudSevHigh {
				sev = cloudSevHigh
			}
			break
		}
	}
	if e.Status.Value == "Failed" && sev < cloudSevMedium {
		sev = cloudSevMedium
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"source":           "azure_activity_log",
		"connector_id":     connectorID,
		"event_id":         e.ID,
		"operation_name":   e.OperationName.Value,
		"event_name":       e.EventName.Value,
		"category":         e.Category.Value,
		"status":           e.Status.Value,
		"level":            e.Level,
		"resource_id":      e.ResourceID,
		"resource_group":   e.ResourceGroupName,
		"resource_provider": e.ResourceProviderName.Value,
		"caller":           e.Caller,
		"correlation_id":   e.CorrelationID,
		"description":      e.Description,
		"http_request":     e.HTTPRequest,
		"properties":       e.Properties,
	})

	// Extract region from resourceId (e.g. /subscriptions/.../resourceGroups/rg/providers/...)
	host := "azure"
	if parts := strings.Split(e.ResourceID, "/"); len(parts) > 4 {
		host = parts[4] // resourceGroups name as location fallback
	}

	return CloudEvent{
		ID:        e.ID + "-" + e.EventTimestamp.Format("20060102150405"),
		Time:      e.EventTimestamp,
		AgentID:   fmt.Sprintf("azure-activitylog-%d", connectorID),
		Host:      host,
		OS:        "azure",
		EventType: "cloud.azure_activity",
		Severity:  sev,
		Source:    "azure_activity_log",
		Username:  e.Caller,
		SrcIP:     e.HTTPRequest.ClientIPAddress,
		Raw:       raw,
	}
}

// testAzureConnection verifies Azure credentials by getting a token and listing subscriptions
func testAzureConnection(ctx context.Context, tenantID, clientID, clientSecret, subscriptionID string) error {
	token, err := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://management.azure.com/")
	if err != nil {
		return err
	}

	// Verify subscription access
	reqURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s?api-version=2020-01-01", subscriptionID)
	req, _ := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("subscription check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("subscription access denied (%d): %s", resp.StatusCode, string(body[:func() int { if 200 < len(body) { return 200 }; return len(body) }()]))
	}
	return nil
}

// syncAzure pulls Azure Activity Log events
func syncAzure(ctx context.Context, conn *store.CloudConnector, db *store.DB, eventDB *store.DB, logger *slog.Logger) (int, string, error) {
	tenantID     := conn.Credentials["tenant_id"]
	clientID     := conn.Credentials["client_id"]
	clientSecret := conn.Credentials["client_secret"]
	subID        := conn.Credentials["subscription_id"]

	if tenantID == "" || clientID == "" || clientSecret == "" || subID == "" {
		return 0, "", fmt.Errorf("missing Azure credentials (tenant_id, client_id, client_secret, subscription_id required)")
	}

	token, err := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://management.azure.com/")
	if err != nil {
		return 0, "", fmt.Errorf("Azure auth: %w", err)
	}

	since := time.Now().UTC().Add(-24 * time.Hour)
	if conn.LastSync != nil {
		since = conn.LastSync.Add(-2 * time.Minute)
	}

	// Restore cursor (nextLink from previous sync)
	nextLink := ""
	if strings.HasPrefix(conn.SyncCursor, "azure:") {
		nextLink = strings.TrimPrefix(conn.SyncCursor, "azure:")
	}

	var totalIngested int
	var newCursor string

	for {
		events, next, err := pullAzureActivityLog(ctx, token.AccessToken, subID, since, nextLink)
		if err != nil {
			return totalIngested, newCursor, err
		}

		cloudEvents := make([]CloudEvent, 0, len(events))
		for _, e := range events {
			cloudEvents = append(cloudEvents, azureEventToCloudEvent(e, conn.ID))
		}
		n, _ := ingestCloudEvents(ctx, eventDB, cloudEvents)
		totalIngested += n

		if next == "" {
			break
		}
		newCursor = "azure:" + next
		nextLink = next

		select {
		case <-ctx.Done():
			return totalIngested, newCursor, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}

	// Also pull Entra ID sign-in logs (requires AuditLog.Read.All Graph permission)
	entraCount, _ := pullEntraSignIns(ctx, tenantID, clientID, clientSecret, since, conn, eventDB)
	totalIngested += entraCount

	return totalIngested, newCursor, nil
}

// ── Entra ID (Azure AD) Sign-in Logs ─────────────────────────────────────────

type entraSignIn struct {
	ID                     string    `json:"id"`
	CreatedDateTime        time.Time `json:"createdDateTime"`
	UserDisplayName        string    `json:"userDisplayName"`
	UserPrincipalName      string    `json:"userPrincipalName"`
	AppDisplayName         string    `json:"appDisplayName"`
	IPAddress              string    `json:"ipAddress"`
	ClientAppUsed          string    `json:"clientAppUsed"`
	ConditionalAccessStatus string   `json:"conditionalAccessStatus"`
	Status                 struct {
		ErrorCode      int    `json:"errorCode"`
		FailureReason  string `json:"failureReason"`
	} `json:"status"`
	Location struct {
		City            string `json:"city"`
		CountryOrRegion string `json:"countryOrRegion"`
	} `json:"location"`
	RiskLevelDuringSignIn  string `json:"riskLevelDuringSignIn"`
	RiskState              string `json:"riskState"`
}

func pullEntraSignIns(ctx context.Context, tenantID, clientID, clientSecret string, since time.Time, conn *store.CloudConnector, eventDB *store.DB) (int, error) {
	// Entra ID uses Microsoft Graph API with a different resource scope
	token, err := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://graph.microsoft.com/")
	if err != nil {
		// Not all app registrations have Graph API permissions — skip silently
		return 0, nil
	}

	filter := fmt.Sprintf("createdDateTime ge %s", since.UTC().Format(time.RFC3339))
	reqURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=%s&$top=100",
		url.QueryEscape(filter))

	total := 0
	for reqURL != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			break
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			break
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 403 {
			// No permission for sign-in logs — skip silently
			break
		}
		if resp.StatusCode != 200 {
			break
		}

		var result struct {
			Value    []entraSignIn `json:"value"`
			NextLink string        `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			break
		}

		events := make([]CloudEvent, 0, len(result.Value))
		for _, s := range result.Value {
			events = append(events, entraSignInToCloudEvent(s, conn.ID))
		}
		n, _ := ingestCloudEvents(ctx, eventDB, events)
		total += n

		reqURL = result.NextLink
	}
	return total, nil
}

var azureRiskMap = map[string]int{
	"high":   cloudSevHigh,
	"medium": cloudSevMedium,
	"low":    cloudSevInfo,
	"none":   cloudSevInfo,
}

func entraSignInToCloudEvent(s entraSignIn, connectorID int64) CloudEvent {
	sev := cloudSevInfo
	if s.Status.ErrorCode != 0 {
		sev = cloudSevMedium // Failed sign-in
	}
	if r, ok := azureRiskMap[s.RiskLevelDuringSignIn]; ok && r > sev {
		sev = r
	}
	if s.RiskState == "atRisk" || s.RiskState == "confirmedCompromised" {
		sev = cloudSevHigh
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"source":                   "entra_signin",
		"connector_id":             connectorID,
		"id":                       s.ID,
		"user_display_name":        s.UserDisplayName,
		"user_principal_name":      s.UserPrincipalName,
		"app_display_name":         s.AppDisplayName,
		"client_app_used":          s.ClientAppUsed,
		"conditional_access_status": s.ConditionalAccessStatus,
		"status":                   s.Status,
		"location":                 s.Location,
		"risk_level":               s.RiskLevelDuringSignIn,
		"risk_state":               s.RiskState,
	})

	return CloudEvent{
		ID:        s.ID,
		Time:      s.CreatedDateTime,
		AgentID:   fmt.Sprintf("azure-entra-%d", connectorID),
		Host:      "azure-ad",
		OS:        "azure",
		EventType: "cloud.entra_signin",
		Severity:  sev,
		Source:    "entra_id",
		Username:  s.UserPrincipalName,
		SrcIP:     s.IPAddress,
		Raw:       raw,
	}
}
