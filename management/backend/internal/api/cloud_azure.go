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
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// flexInt unmarshals a JSON number or a numeric string.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("not a number: %q", s)
	}
	*f = flexInt(n)
	return nil
}

// azureToken holds an OAuth2 access token with expiry
type azureToken struct {
	AccessToken string    `json:"access_token"`
	ExpiresIn   flexInt   `json:"expires_in"` // v1 endpoint returns a string, v2 a number
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
		return nil, fmt.Errorf("auth failed: %s%s", errResp.ErrorDescription, azureAuthHint(errResp.ErrorDescription))
	}

	var token azureToken
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	token.ExpiresAt = time.Now().Add(time.Duration(int(token.ExpiresIn)-60) * time.Second)
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
	Level                string `json:"level"`
	ResourceID           string `json:"resourceId"`
	ResourceGroupName    string `json:"resourceGroupName"`
	ResourceProviderName struct {
		Value string `json:"value"`
	} `json:"resourceProviderName"`
	Caller        string          `json:"caller"`
	CorrelationID string          `json:"correlationId"`
	Description   string          `json:"description"`
	Properties    json.RawMessage `json:"properties"`
	HTTPRequest   struct {
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
			"https://management.azure.com/subscriptions/%s/providers/microsoft.insights/eventtypes/management/values?api-version=2022-06-01&$filter=%s",
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
	"Critical":      cloudSevCritical,
	"Error":         cloudSevHigh,
	"Warning":       cloudSevMedium,
	"Informational": cloudSevInfo,
	"Verbose":       cloudSevInfo,
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
		"source":            "azure_activity_log",
		"connector_id":      connectorID,
		"event_id":          e.ID,
		"operation_name":    e.OperationName.Value,
		"event_name":        e.EventName.Value,
		"category":          e.Category.Value,
		"status":            e.Status.Value,
		"level":             e.Level,
		"resource_id":       e.ResourceID,
		"resource_group":    e.ResourceGroupName,
		"subscription_id":   azureSubFromResourceID(e.ResourceID),
		"resource_provider": e.ResourceProviderName.Value,
		"caller":            e.Caller,
		"correlation_id":    e.CorrelationID,
		"description":       e.Description,
		"http_request":      e.HTTPRequest,
		"properties":        e.Properties,
	})

	// Extract region from resourceId (e.g. /subscriptions/.../resourceGroups/rg/providers/...)
	host := "azure"
	subID := ""
	if parts := strings.Split(e.ResourceID, "/"); len(parts) > 4 {
		subID = parts[2]
		host = parts[4]
		// AZ-11: prefix the subscription so identical resource-group names in
		// different subscriptions no longer collide in dedup and correlation.
		if len(subID) >= 8 {
			host = strings.ToLower(subID[:8]) + "/" + host
		}
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
		return fmt.Errorf("subscription access denied (%d): %s", resp.StatusCode, string(body[:func() int {
			if 200 < len(body) {
				return 200
			}
			return len(body)
		}()]))
	}
	return nil
}

// syncAzure pulls Azure Activity Log events
func syncAzure(ctx context.Context, conn *store.CloudConnector, db *store.DB, eventDB *store.DB, logger *slog.Logger) (int, string, error) {
	tenantID := conn.Credentials["tenant_id"]
	clientID := conn.Credentials["client_id"]
	clientSecret := conn.Credentials["client_secret"]
	subID := conn.Credentials["subscription_id"]

	if tenantID == "" || clientID == "" || clientSecret == "" || subID == "" {
		return 0, "", fmt.Errorf("missing Azure credentials (tenant_id, client_id, client_secret, subscription_id required)")
	}

	token, err := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://management.azure.com/")
	if err != nil {
		return 0, "", fmt.Errorf("Azure auth: %w", err)
	}

	// AZ-01/G-01: watermark on eventTimestamp, not a persisted nextLink.
	// nextLink is only valid for continuing *this* paginated request — a
	// sync that read more than one page used to persist the last nextLink
	// as the cursor, so the following sync resumed mid-page instead of
	// from the new `since`, re-reading older pages (or worse, skipping
	// ahead) instead of resuming cleanly. nextLink now stays local to this
	// one sync call; only a time-based cursor is ever persisted.
	since := time.Now().UTC().Add(-24 * time.Hour)
	if conn.SyncCursor != "" {
		if t, err := time.Parse(time.RFC3339Nano, conn.SyncCursor); err == nil {
			since = t.Add(-2 * time.Minute)
		}
	} else if conn.LastSync != nil {
		since = conn.LastSync.Add(-2 * time.Minute)
	}
	cursorFloor := since

	// AZ-11: subscription_id may be a comma-separated list or "*" (every
	// enabled subscription the app registration can read).
	subIDs, derr := resolveAzureSubscriptions(ctx, token.AccessToken, subID)
	if derr != nil {
		return 0, "", derr
	}
	var totalIngested int
	maxSeen := cursorFloor
	var subErrs []string

	pullSub := func(subID string) error {
		nextLink := ""
		for {
			events, next, err := pullAzureActivityLog(ctx, token.AccessToken, subID, since, nextLink)
			if err != nil {
				return err
			}
			cloudEvents := make([]CloudEvent, 0, len(events))
			for _, e := range events {
				if e.EventTimestamp.After(maxSeen) {
					maxSeen = e.EventTimestamp
				}
				// AZ-05: skip Started/Accepted/InProgress intermediates.
				if azureIntermediateStatus(e.Status.Value) {
					continue
				}
				cloudEvents = append(cloudEvents, azureEventToCloudEvent(e, conn.ID))
			}
			n, _ := ingestCloudEvents(ctx, eventDB, cloudEvents)
			totalIngested += n
			if next == "" {
				return nil
			}
			nextLink = next
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	for _, id := range subIDs {
		if err := pullSub(id); err != nil {
			if ctx.Err() != nil {
				return totalIngested, azureCursorString(maxSeen, cursorFloor), err
			}
			subErrs = append(subErrs, id+": "+err.Error())
		}
	}
	if len(subErrs) > 0 && len(subErrs) == len(subIDs) {
		return totalIngested, azureCursorString(maxSeen, cursorFloor), fmt.Errorf("all subscriptions failed: %s", strings.Join(subErrs, "; "))
	}
	if len(subErrs) > 0 {
		recordSourceStatus(conn.ID, "azure_activity", "partial", strings.Join(subErrs, "; "))
	}

	newCursor := azureCursorString(maxSeen, cursorFloor)

	// Also pull Entra ID sign-in logs (requires AuditLog.Read.All Graph permission)
	entraCount, _ := pullEntraSignIns(ctx, tenantID, clientID, clientSecret, since, conn, eventDB)
	totalIngested += entraCount

	return totalIngested, newCursor, nil
}

// azureCursorString returns the new watermark to persist, or "" (meaning
// "leave the stored cursor unchanged") if nothing in this run advanced it
// past where the run started.
func azureCursorString(maxSeen, floor time.Time) string {
	if !maxSeen.After(floor) {
		return ""
	}
	return maxSeen.UTC().Format(time.RFC3339Nano)
}

// ── Entra ID (Azure AD) Sign-in Logs ─────────────────────────────────────────

type entraSignIn struct {
	ID                      string    `json:"id"`
	CreatedDateTime         time.Time `json:"createdDateTime"`
	UserDisplayName         string    `json:"userDisplayName"`
	UserPrincipalName       string    `json:"userPrincipalName"`
	AppDisplayName          string    `json:"appDisplayName"`
	IPAddress               string    `json:"ipAddress"`
	ClientAppUsed           string    `json:"clientAppUsed"`
	ConditionalAccessStatus string    `json:"conditionalAccessStatus"`
	Status                  struct {
		ErrorCode     int    `json:"errorCode"`
		FailureReason string `json:"failureReason"`
	} `json:"status"`
	Location struct {
		City            string `json:"city"`
		CountryOrRegion string `json:"countryOrRegion"`
	} `json:"location"`
	RiskLevelDuringSignIn string `json:"riskLevelDuringSignIn"`
	RiskState             string `json:"riskState"`
	// AZ-03 (service principal / managed identity sign-ins, beta endpoint)
	ServicePrincipalName string `json:"servicePrincipalName"`
	ServicePrincipalID   string `json:"servicePrincipalId"`
	SignInKind           string `json:"-"`
	// AZ-03: fields that were previously dropped.
	UserID                    string `json:"userId"`
	ResourceDisplayName       string `json:"resourceDisplayName"`
	CorrelationID             string `json:"correlationId"`
	IsInteractive             bool   `json:"isInteractive"`
	AuthenticationRequirement string `json:"authenticationRequirement"`
	DeviceDetail              struct {
		DeviceID        string `json:"deviceId"`
		DisplayName     string `json:"displayName"`
		OperatingSystem string `json:"operatingSystem"`
		Browser         string `json:"browser"`
		IsCompliant     bool   `json:"isCompliant"`
		IsManaged       bool   `json:"isManaged"`
		TrustType       string `json:"trustType"`
	} `json:"deviceDetail"`
	MfaDetail struct {
		AuthMethod string `json:"authMethod"`
		AuthDetail string `json:"authDetail"`
	} `json:"mfaDetail"`
	AppliedConditionalAccessPolicies []struct {
		DisplayName string `json:"displayName"`
		Result      string `json:"result"`
	} `json:"appliedConditionalAccessPolicies"`
}

func pullEntraSignIns(ctx context.Context, tenantID, clientID, clientSecret string, since time.Time, conn *store.CloudConnector, eventDB *store.DB) (int, error) {
	n, err := pullEntraSignInsKind(ctx, tenantID, clientID, clientSecret, since, conn, eventDB, "", "")
	// Service principal and managed identity sign-ins exist only on the beta
	// endpoint and are tracked as a separate source so a failure here cannot
	// mask the interactive pull.
	m, _ := pullEntraSignInsKind(ctx, tenantID, clientID, clientSecret, since, conn, eventDB, "service_principal",
		"(signInEventTypes/any(t: t eq 'servicePrincipal') or signInEventTypes/any(t: t eq 'managedIdentity'))")
	return n + m, err
}

func pullEntraSignInsKind(ctx context.Context, tenantID, clientID, clientSecret string, since time.Time, conn *store.CloudConnector, eventDB *store.DB, kind, extraFilter string) (int, error) {
	source, version := "entra_signins", "v1.0"
	if kind != "" {
		source, version = "entra_signins_sp", "beta"
	}
	// Entra ID uses Microsoft Graph API with a different resource scope
	token, err := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://graph.microsoft.com/")
	if err != nil {
		recordSourceStatus(conn.ID, source, "permission_missing", "Graph token request failed: "+err.Error())
		return 0, nil
	}

	filter := fmt.Sprintf("createdDateTime ge %s", since.UTC().Format(time.RFC3339))
	if extraFilter != "" {
		filter += " and " + extraFilter
	}
	reqURL := fmt.Sprintf(
		"https://graph.microsoft.com/%s/auditLogs/signIns?$filter=%s&$top=100",
		version, url.QueryEscape(filter))

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

		if resp.StatusCode != 200 {
			st, d := classifyAzureFailure(resp.StatusCode, string(body))
			recordSourceStatus(conn.ID, source, st, d)
			break
		}
		recordSourceStatus(conn.ID, source, "ok", "")

		var result struct {
			Value    []entraSignIn `json:"value"`
			NextLink string        `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			break
		}

		events := make([]CloudEvent, 0, len(result.Value))
		for _, s := range result.Value {
			s.SignInKind = kind
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
		"source":                     "entra_signin",
		"connector_id":               connectorID,
		"id":                         s.ID,
		"user_display_name":          s.UserDisplayName,
		"user_principal_name":        s.UserPrincipalName,
		"app_display_name":           s.AppDisplayName,
		"client_app_used":            s.ClientAppUsed,
		"conditional_access_status":  s.ConditionalAccessStatus,
		"status":                     s.Status,
		"location":                   s.Location,
		"risk_level":                 s.RiskLevelDuringSignIn,
		"risk_state":                 s.RiskState,
		"user_id":                    s.UserID,
		"resource":                   s.ResourceDisplayName,
		"correlation_id":             s.CorrelationID,
		"is_interactive":             s.IsInteractive,
		"authentication_requirement": s.AuthenticationRequirement,
		"device":                     s.DeviceDetail,
		"mfa":                        s.MfaDetail,
		"ca_policies":                s.AppliedConditionalAccessPolicies,
		"sign_in_kind":               s.SignInKind,
		"service_principal_name":     s.ServicePrincipalName,
		"service_principal_id":       s.ServicePrincipalID,
	})
	// AZ-03: Host was the constant "azure-ad", collapsing every user's alerts
	// into one per rule per hour. Use the account as the entity instead.
	host := "azure-ad"
	if s.UserPrincipalName != "" {
		host = strings.ToLower(s.UserPrincipalName)
	} else if s.SignInKind == "service_principal" {
		name := s.ServicePrincipalName
		if name == "" {
			name = s.AppDisplayName
		}
		host = "sp:" + strings.ToLower(name)
	}

	return CloudEvent{
		ID:        s.ID,
		Time:      s.CreatedDateTime,
		AgentID:   fmt.Sprintf("azure-entra-%d", connectorID),
		Host:      host,
		OS:        "azure",
		EventType: "cloud.entra_signin",
		Severity:  sev,
		Source:    "entra_id",
		Username:  s.UserPrincipalName,
		SrcIP:     s.IPAddress,
		Raw:       raw,
	}
}

// azureIntermediateStatus reports Activity Log statuses that are progress
// markers rather than outcomes (AZ-05).
func azureIntermediateStatus(status string) bool {
	switch strings.ToLower(status) {
	case "started", "accepted", "in progress", "inprogress", "updated", "resolved":
		return true
	}
	return false
}

// azureStatusAllows gates Azure Activity Log events by outcome (AZ-05):
// "change" rules fire only on Succeeded operations, so a failed attempt no
// longer alerts as if the change happened. Rules that are explicitly about
// failed/denied/brute-force activity still see Failed entries.
func azureStatusAllows(sig ThreatSig, ev store.Event) bool {
	if ev.EventType != "cloud.azure_activity" || len(ev.Raw) == 0 {
		return true
	}
	var r struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(ev.Raw, &r) != nil || !strings.EqualFold(r.Status, "failed") {
		return true
	}
	n := strings.ToLower(sig.Name)
	return strings.Contains(n, "fail") || strings.Contains(n, "denied") ||
		strings.Contains(n, "brute") || strings.Contains(n, "unauthor")
}

func azureSubFromResourceID(id string) string {
	if parts := strings.Split(id, "/"); len(parts) > 2 && strings.EqualFold(parts[1], "subscriptions") {
		return parts[2]
	}
	return ""
}

// resolveAzureSubscriptions expands the connector's subscription setting.
func resolveAzureSubscriptions(ctx context.Context, token, setting string) ([]string, error) {
	setting = strings.TrimSpace(setting)
	if setting != "*" {
		var ids []string
		for _, p := range strings.FieldsFunc(setting, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			ids = append(ids, p)
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("no subscription_id configured")
		}
		return ids, nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://management.azure.com/subscriptions?api-version=2020-01-01", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("list subscriptions: HTTP %d", resp.StatusCode)
	}
	ids := parseAzureSubscriptionList(body)
	if len(ids) == 0 {
		return nil, fmt.Errorf("the app registration cannot see any enabled subscription")
	}
	return ids, nil
}

func parseAzureSubscriptionList(body []byte) []string {
	var r struct {
		Value []struct {
			ID    string `json:"subscriptionId"`
			State string `json:"state"`
		} `json:"value"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil
	}
	var ids []string
	for _, v := range r.Value {
		if v.ID != "" && strings.EqualFold(v.State, "Enabled") {
			ids = append(ids, v.ID)
		}
	}
	return ids
}

// firstAzureSub returns the first concrete subscription ID from a connector
// setting that may be a list or "*" (which has no single ID to scan).
func firstAzureSub(setting string) string {
	if strings.TrimSpace(setting) == "*" {
		return ""
	}
	ids, err := resolveAzureSubscriptions(context.Background(), "", setting)
	if err != nil || len(ids) == 0 {
		return strings.TrimSpace(setting)
	}
	return ids[0]
}

// azureAuthHint adds a plain-language fix for the most common Entra errors.
func azureAuthHint(desc string) string {
	switch {
	case strings.Contains(desc, "AADSTS7000215"):
		return " — HINT: you entered the secret's ID. In Azure portal → App registrations → Certificates & secrets, copy the secret VALUE (shown only once when created); if it is gone, create a new secret and copy its Value."
	case strings.Contains(desc, "AADSTS7000222"):
		return " — HINT: the client secret has expired. Create a new secret and use its Value."
	case strings.Contains(desc, "AADSTS700016"):
		return " — HINT: the Client ID was not found in this tenant. Check the Application (client) ID and Directory (tenant) ID on the app's Overview page."
	case strings.Contains(desc, "AADSTS90002") || strings.Contains(desc, "AADSTS900023"):
		return " — HINT: the Tenant ID is wrong. Use the Directory (tenant) ID from the app's Overview page."
	}
	return ""
}
