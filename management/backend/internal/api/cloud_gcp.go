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
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// gcpServiceAccount is the structure of a GCP service account JSON key file
type gcpServiceAccount struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	TokenURI                string `json:"token_uri"`
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

// getGCPToken exchanges a JWT for an OAuth2 access token
func getGCPToken(ctx context.Context, sa gcpServiceAccount) (string, error) {
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
		return "", fmt.Errorf("GCP auth failed (%d): %s", resp.StatusCode, string(respBody))
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
	InsertID  string    `json:"insertId"`
	Timestamp time.Time `json:"timestamp"`
	LogName   string    `json:"logName"`
	Resource  struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
	Severity       string          `json:"severity"`
	ProtoPayload   json.RawMessage `json:"protoPayload"`
	JSONPayload    json.RawMessage `json:"jsonPayload"`
	TextPayload    string          `json:"textPayload"`
	Labels         map[string]string `json:"labels"`
	Operation      struct {
		ID       string `json:"id"`
		Producer string `json:"producer"`
	} `json:"operation"`
}

// pullGCPLogs fetches audit log entries using the Cloud Logging API
func pullGCPLogs(ctx context.Context, token, projectID string, since time.Time, pageToken string) ([]gcpLogEntry, string, error) {
	filter := fmt.Sprintf(
		`logName=("projects/%s/logs/cloudaudit.googleapis.com%%2Factivity" OR "projects/%s/logs/cloudaudit.googleapis.com%%2Fdata_access" OR "projects/%s/logs/cloudaudit.googleapis.com%%2Fsystem_event") AND timestamp>="%s"`,
		projectID, projectID, projectID, since.UTC().Format(time.RFC3339))

	payload := map[string]interface{}{
		"resourceNames": []string{"projects/" + projectID},
		"filter":        filter,
		"orderBy":       "timestamp desc",
		"pageSize":      100,
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
		// Elevate severity for sensitive operations
		sensitiveGCPOps := []string{
			"SetIamPolicy", "DeleteBucket", "DeleteProject", "DeleteServiceAccount",
			"CreateServiceAccountKey", "DisableServiceAccount", "DeleteCryptoKey",
		}
		for _, op := range sensitiveGCPOps {
			if strings.Contains(methodName, op) && sev < cloudSevHigh {
				sev = cloudSevHigh
				break
			}
		}
	}

	// Determine log type from logName
	logType := "audit"
	if strings.Contains(e.LogName, "data_access") {
		logType = "data_access"
	} else if strings.Contains(e.LogName, "system_event") {
		logType = "system_event"
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
		"proto_payload": e.ProtoPayload,
		"json_payload": e.JSONPayload,
		"text_payload": e.TextPayload,
		"labels":       e.Labels,
		"operation":    e.Operation,
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
	if sa.Type != "service_account" {
		return "", fmt.Errorf("expected service_account type, got %s", sa.Type)
	}
	if _, err := getGCPToken(ctx, sa); err != nil {
		return "", err
	}
	return sa.ProjectID, nil
}

// syncGCP pulls GCP Cloud Audit Log entries
func syncGCP(ctx context.Context, conn *store.CloudConnector, db *store.DB, eventDB *store.DB, logger *slog.Logger) (int, string, error) {
	saJSON := conn.Credentials["service_account"]
	projectID := conn.Credentials["project_id"]

	if saJSON == "" {
		return 0, "", fmt.Errorf("missing GCP service account JSON")
	}

	var sa gcpServiceAccount
	if err := json.Unmarshal([]byte(saJSON), &sa); err != nil {
		return 0, "", fmt.Errorf("invalid service account JSON: %w", err)
	}
	if projectID == "" {
		projectID = sa.ProjectID
	}
	if projectID == "" {
		return 0, "", fmt.Errorf("project_id required")
	}

	token, err := getGCPToken(ctx, sa)
	if err != nil {
		return 0, "", fmt.Errorf("GCP auth: %w", err)
	}

	// Auto-populate account_id and label from service account if not set
	if conn.AccountID == "" && projectID != "" {
		db.UpdateCloudConnectorAccount(ctx, conn.ID, projectID, sa.ClientEmail)
	}

	since := time.Now().UTC().Add(-24 * time.Hour)
	if conn.LastSync != nil {
		since = conn.LastSync.Add(-2 * time.Minute)
	}

	// GCP page tokens are session-scoped — they expire and cannot be reused
	// across sync runs. Always start pagination fresh from the time range.
	pageToken := ""
	// Intentionally ignore conn.SyncCursor for GCP — using it causes
	// "page_token doesn't match arguments" 400 errors.

	var totalIngested int
	var newCursor string

	for {
		entries, next, err := pullGCPLogs(ctx, token, projectID, since, pageToken)
		if err != nil {
			return totalIngested, newCursor, err
		}

		cloudEvents := make([]CloudEvent, 0, len(entries))
		for _, e := range entries {
			cloudEvents = append(cloudEvents, gcpEntryToCloudEvent(e, conn.ID))
		}
		n, _ := ingestCloudEvents(ctx, eventDB, cloudEvents)
		totalIngested += n

		if next == "" {
			break
		}
		// Don't save GCP page tokens — they expire between sync runs
		pageToken = next

		select {
		case <-ctx.Done():
			return totalIngested, newCursor, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}

	return totalIngested, newCursor, nil
}
