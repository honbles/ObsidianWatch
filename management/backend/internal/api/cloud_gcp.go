package api

// cloud_gcp.go — Google Cloud Platform Audit Log puller.
//
// Uses GCP Cloud Logging API with service account JWT authentication.
// Pulls Cloud Audit Logs (Admin Activity + Data Access + System Event).
//
// Required IAM roles:
//   roles/logging.viewer   (or roles/logging.privateLogViewer for Data Access logs)
//
// Setup:
//   1. GCP Console → IAM → Service Accounts → Create Service Account
//   2. Assign role: Logging Viewer
//   3. Create JSON key → download → paste into the Service Account JSON field

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// gcpServiceAccount is the structure of a GCP service account JSON key file
type gcpServiceAccount struct {
	Type               string `json:"type"`
	ProjectID          string `json:"project_id"`
	PrivateKeyID       string `json:"private_key_id"`
	PrivateKey         string `json:"private_key"`
	ClientEmail        string `json:"client_email"`
	TokenURI           string `json:"token_uri"`
	gcpExternalAccount        // G-19: set when Type == "external_account"
}

// gcpJWT creates a signed JWT for service account authentication
func gcpJWT(sa gcpServiceAccount, scope string) (string, error) {
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss":   sa.ClientEmail,
		"scope": scope,
		"aud":   sa.TokenURI,
		"iat":   now,
		"exp":   now + 3600,
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sigInput := header + "." + payload

	// Parse PEM private key
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("invalid private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("expected RSA private key")
	}

	// Sign with RS256 (SHA256withRSA)
	hash := sha256.Sum256([]byte(sigInput))
	digest := hash[:]

	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	return sigInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// validateGCPTokenURI requires https and a Google-owned host.
func validateGCPTokenURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return fmt.Errorf("invalid token_uri in service account JSON")
	}
	h := strings.ToLower(u.Hostname())
	if h != "oauth2.googleapis.com" && h != "accounts.google.com" && h != "www.googleapis.com" {
		return fmt.Errorf("token_uri host %q is not a Google OAuth endpoint", h)
	}
	return nil
}

// getGCPToken exchanges a JWT for an OAuth2 access token
func getGCPToken(ctx context.Context, sa gcpServiceAccount) (string, error) {
	if sa.Type == "external_account" {
		return gcpExternalAccountToken(ctx, sa.gcpExternalAccount, "https://www.googleapis.com/auth/logging.read")
	}
	// G-18: token_uri comes from the pasted service-account JSON and is the
	// POST target for a freshly signed JWT — an attacker-chosen value would
	// leak a valid assertion and give an SSRF primitive. Only Google's own
	// OAuth endpoints are accepted.
	if err := validateGCPTokenURI(sa.TokenURI); err != nil {
		return "", err
	}
	jwt, err := gcpJWT(sa, "https://www.googleapis.com/auth/logging.read")
	if err != nil {
		return "", err
	}

	body := "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + jwt
	req, err := http.NewRequestWithContext(ctx, "POST", sa.TokenURI, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		// G-18: don't echo the response body into errors (they end up in
		// last_error and the UI) — it can contain account details.
		_ = respBody
		return "", fmt.Errorf("GCP auth failed (status %d)", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}
	return result.AccessToken, nil
}

// gcpLogEntry is a GCP Cloud Logging log entry
type gcpLogEntry struct {
	InsertID string `json:"insertId"`
	// Timestamp is when the logged event occurred; ReceiveTimestamp is when
	// Cloud Logging actually received/indexed it, which can lag Timestamp
	// by minutes. G-01/G-02: we cursor and filter on ReceiveTimestamp, not
	// Timestamp, since that's the field that determines when an entry
	// actually becomes visible to a poll — cursoring on Timestamp is what
	// let entries silently fall outside the sync window.
	ReceiveTimestamp time.Time `json:"receiveTimestamp"`
	Timestamp        time.Time `json:"timestamp"`
	LogName          string    `json:"logName"`
	Resource         struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
	Severity     string            `json:"severity"`
	ProtoPayload json.RawMessage   `json:"protoPayload"`
	JSONPayload  json.RawMessage   `json:"jsonPayload"`
	TextPayload  string            `json:"textPayload"`
	HTTPRequest  json.RawMessage   `json:"httpRequest"`
	Labels       map[string]string `json:"labels"`
	Operation    struct {
		ID       string `json:"id"`
		Producer string `json:"producer"`
	} `json:"operation"`
}

// pullGCPLogs fetches audit log entries using the Cloud Logging API
func pullGCPLogs(ctx context.Context, token, projectID string, since time.Time, pageToken string) ([]gcpLogEntry, string, error) {
	// G-01: filter and cursor on receiveTimestamp (when Cloud Logging
	// actually indexed the entry), not timestamp (when the event occurred).
	// Audit entries can be received 5+ minutes after they happened, so
	// filtering on timestamp made the sync watermark lie about what had
	// actually been durably ingested.
	filter := fmt.Sprintf(
		// G-16: system_event logs were pulled but never used, and Data Access
		// logs generated by Google-managed service agents are pure noise —
		// both are excluded server-side.
		`(logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity" OR logName="projects/%s/logs/cloudaudit.googleapis.com%%2Fpolicy" OR (logName="projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access" AND NOT protoPayload.authenticationInfo.principalEmail:"gcp-sa-" AND NOT protoPayload.authenticationInfo.principalEmail:"@cloudservices.gserviceaccount.com")) AND receiveTimestamp>="%s"`,
		projectID, projectID, projectID, since.UTC().Format(time.RFC3339Nano))

	payload := map[string]interface{}{
		"resourceNames": []string{"projects/" + projectID},
		"filter":        filter,
		// Oldest-first: a sync that's interrupted partway (timeout, error,
		// crash) has still durably ingested a contiguous prefix of the
		// range, so the cursor can safely advance to the last entry seen
		// rather than losing or re-scanning the whole window.
		"orderBy":  "receiveTimestamp asc",
		"pageSize": 100,
	}
	if pageToken != "" {
		payload["pageToken"] = pageToken
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://logging.googleapis.com/v2/entries:list",
		strings.NewReader(string(body)))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("GCP logging API: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("GCP logging API %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Entries       []gcpLogEntry `json:"entries"`
		NextPageToken string        `json:"nextPageToken"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, "", fmt.Errorf("parse GCP logs: %w", err)
	}
	return result.Entries, result.NextPageToken, nil
}

// gcpSeverityMap maps GCP log severity to our scale
var gcpSeverityMap = map[string]int{
	"EMERGENCY": cloudSevCritical,
	"ALERT":     cloudSevCritical,
	"CRITICAL":  cloudSevCritical,
	"ERROR":     cloudSevHigh,
	"WARNING":   cloudSevMedium,
	"NOTICE":    cloudSevMedium,
	"INFO":      cloudSevInfo,
	"DEBUG":     cloudSevInfo,
	"DEFAULT":   cloudSevInfo,
}

func gcpEntryToCloudEvent(e gcpLogEntry, connectorID int64) CloudEvent {
	sev := cloudSevInfo
	if s, ok := gcpSeverityMap[e.Severity]; ok {
		sev = s
	}

	// Extract method name and principal from protoPayload (AuditLog format)
	var methodName, principalEmail, callerIP string
	statusCode := 0
	var protoPayload map[string]interface{}
	if len(e.ProtoPayload) > 0 {
		json.Unmarshal(e.ProtoPayload, &protoPayload)
		if m, ok := protoPayload["methodName"].(string); ok {
			methodName = m
		}
		if ai, ok := protoPayload["authenticationInfo"].(map[string]interface{}); ok {
			if pe, ok := ai["principalEmail"].(string); ok {
				principalEmail = pe
			}
		}
		if ri, ok := protoPayload["requestMetadata"].(map[string]interface{}); ok {
			if ip, ok := ri["callerIp"].(string); ok {
				callerIP = ip
			}
		}
		if st, ok := protoPayload["status"].(map[string]interface{}); ok {
			if c, ok := st["code"].(float64); ok {
				statusCode = int(c)
			}
		}
		// Elevate severity for sensitive operations
		sensitiveGCPOps := []string{
			"SetIamPolicy", "DeleteBucket", "DeleteProject", "DeleteServiceAccount",
			"CreateServiceAccountKey", "DisableServiceAccount", "DeleteCryptoKey",
		}
		for _, op := range sensitiveGCPOps {
			if strings.Contains(methodName, op) && sev < cloudSevHigh && statusCode == 0 {
				sev = cloudSevHigh
				break
			}
		}
		// G-14: severity reflects method risk and outcome, not just the log
		// level (Admin Activity logs are almost all NOTICE). Read-only
		// methods are informational; failed calls are never "high" for the
		// change they attempted, but access-denied is kept at Medium so
		// probing stays visible (and rules can key on outcome=failed).
		if statusCode == 0 && sev < cloudSevHigh && gcpReadOnlyMethod(methodName) {
			sev = cloudSevInfo
		}
		if statusCode != 0 && sev > cloudSevMedium {
			sev = cloudSevMedium
		}
		if (statusCode == 7 || statusCode == 16) && sev < cloudSevMedium {
			sev = cloudSevMedium // PERMISSION_DENIED / UNAUTHENTICATED
		}
	}

	// Determine log type from logName
	logType := "audit"
	if strings.Contains(e.LogName, "data_access") {
		logType = "data_access"
	} else if strings.Contains(e.LogName, "system_event") {
		logType = "system_event"
	} else if strings.Contains(e.LogName, "%2Fpolicy") || strings.HasSuffix(e.LogName, "/policy") {
		logType = "policy_denied" // G-15: VPC-SC / org-policy denials
	}

	host := e.Resource.Labels["project_id"]
	if h := e.Resource.Labels["zone"]; h != "" {
		host = h
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"source":       "gcp_audit_log",
		"connector_id": connectorID,
		"insert_id":    e.InsertID,
		"log_name":     e.LogName,
		"log_type":     logType,
		"resource":     e.Resource,
		"severity":     e.Severity,
		"method_name":  methodName,
		"status_code":  statusCode,
		"outcome": func() string {
			if statusCode == 0 {
				return "succeeded"
			}
			return "failed"
		}(),
		"iam_grants":    gcpIAMGrantsFromPayload(e.ProtoPayload),
		"proto_payload": e.ProtoPayload,
		"json_payload":  e.JSONPayload,
		"text_payload":  e.TextPayload,
		"labels":        e.Labels,
		"operation":     e.Operation,
	})

	return CloudEvent{
		ID:        e.InsertID,
		Time:      e.Timestamp,
		AgentID:   fmt.Sprintf("gcp-auditlog-%d", connectorID),
		Host:      host,
		OS:        "gcp",
		EventType: "cloud.gcp_audit",
		Severity:  sev,
		Source:    "gcp_audit_log",
		Username:  principalEmail,
		SrcIP:     callerIP,
		Raw:       raw,
	}
}

// testGCPConnection verifies GCP credentials by attempting to get a token
func testGCPConnection(ctx context.Context, saJSON string) (string, error) {
	var sa gcpServiceAccount
	if err := json.Unmarshal([]byte(saJSON), &sa); err != nil {
		return "", fmt.Errorf("invalid service account JSON: %w", err)
	}
	if sa.Type != "service_account" && sa.Type != "external_account" {
		return "", fmt.Errorf("expected service_account or external_account type, got %s", sa.Type)
	}
	if _, err := getGCPToken(ctx, sa); err != nil {
		return "", err
	}
	return sa.ProjectID, nil
}

// syncGCP pulls GCP Cloud Audit Log entries
func syncGCP(ctx context.Context, conn *store.CloudConnector, db *store.DB, eventDB *store.DB, logger *slog.Logger) (int, string, error) {
	saJSON := conn.Credentials["service_account"]
	if saJSON == "" {
		return 0, "", fmt.Errorf("missing GCP service account JSON")
	}

	var sa gcpServiceAccount
	if err := json.Unmarshal([]byte(saJSON), &sa); err != nil {
		return 0, "", fmt.Errorf("invalid service account JSON: %w", err)
	}

	token, err := getGCPToken(ctx, sa)
	if err != nil {
		return 0, "", fmt.Errorf("GCP auth: %w", err)
	}

	// G-21: one connector may cover several projects (comma list, or "*"
	// with org_id/folder_id discovery).
	projects, err := resolveGCPProjects(ctx, sa, conn.Credentials["project_id"], conn.Credentials["org_id"], conn.Credentials["folder_id"])
	if err != nil {
		recordSourceStatus(conn.ID, "gcp_audit", "error", err.Error())
		return 0, "", err
	}

	// Auto-populate account_id and label from service account if not set
	if conn.AccountID == "" {
		acct := projects[0]
		if len(projects) > 1 {
			acct = fmt.Sprintf("%s (+%d)", projects[0], len(projects)-1)
		}
		db.UpdateCloudConnectorAccount(ctx, conn.ID, acct, sa.ClientEmail)
	}

	// G-01: since comes from the per-connector sync_cursor (max
	// receiveTimestamp ingested), not last_sync. The safety margin covers
	// entries sharing the cursor's second that hadn't committed yet.
	since := time.Now().UTC().Add(-24 * time.Hour)
	if conn.SyncCursor != "" {
		if t, err := time.Parse(time.RFC3339Nano, conn.SyncCursor); err == nil {
			since = t.Add(-30 * time.Second)
		}
	} else if conn.LastSync != nil {
		since = conn.LastSync.Add(-2 * time.Minute)
	}
	cursorFloor := since

	var totalIngested int
	maxReceived := cursorFloor

	// Page tokens are session-scoped and expire, so pagination always starts
	// fresh from the time range; the cursor is only a timestamp watermark.
	pullProject := func(projectID string) error {
		pageToken := ""
		for {
			entries, next, err := pullGCPLogs(ctx, token, projectID, since, pageToken)
			if err != nil {
				return err
			}
			cloudEvents := make([]CloudEvent, 0, len(entries))
			for _, e := range entries {
				cloudEvents = append(cloudEvents, gcpEntryToCloudEvent(e, conn.ID))
				if e.ReceiveTimestamp.After(maxReceived) {
					maxReceived = e.ReceiveTimestamp
				}
			}
			n, _ := ingestCloudEvents(ctx, eventDB, cloudEvents)
			totalIngested += n
			if next == "" {
				return nil
			}
			pageToken = next
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	}

	var projErrs []string
	permMissing := false
	for _, pid := range projects {
		if err := pullProject(pid); err != nil {
			if ctx.Err() != nil {
				return totalIngested, gcpCursorString(maxReceived, cursorFloor), err
			}
			if strings.Contains(err.Error(), "403") {
				permMissing = true
			}
			projErrs = append(projErrs, pid+": "+err.Error())
		}
	}
	if len(projErrs) > 0 {
		st := "error"
		if permMissing {
			st = "permission_missing"
		}
		if len(projErrs) < len(projects) {
			st = "partial"
		}
		recordSourceStatus(conn.ID, "gcp_audit", st, strings.Join(projErrs, "; "))
		if len(projErrs) == len(projects) {
			// Cursor advances only as far as data actually ingested.
			return totalIngested, gcpCursorString(maxReceived, cursorFloor), fmt.Errorf("all projects failed: %s", strings.Join(projErrs, "; "))
		}
		// A failed project is retried from the same watermark next run,
		// but a healthy project's later entries would move it past the
		// failed one's gap; hold the cursor back so nothing is skipped.
		return totalIngested, "", nil
	}
	recordSourceStatus(conn.ID, "gcp_audit", "ok", "")
	return totalIngested, gcpCursorString(maxReceived, cursorFloor), nil
}

// gcpCursorString returns the new watermark to persist, or "" (meaning
// "leave the stored cursor unchanged" — see UpdateCloudConnectorStatus) if
// no entry advanced it past where this run started.
func gcpCursorString(maxReceived, floor time.Time) string {
	if !maxReceived.After(floor) {
		return ""
	}
	return maxReceived.UTC().Format(time.RFC3339Nano)
}

// gcpReadOnlyMethod reports whether the final segment of a GCP methodName is
// a read-only verb (get/list/describe/…).
func gcpReadOnlyMethod(m string) bool {
	if i := strings.LastIndex(m, "."); i >= 0 {
		m = m[i+1:]
	}
	m = strings.ToLower(m)
	for _, p := range []string{"get", "list", "describe", "read", "lookup", "query", "search", "test", "check"} {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}
