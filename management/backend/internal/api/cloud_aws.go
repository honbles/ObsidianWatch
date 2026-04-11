package api

// cloud_aws.go — AWS CloudTrail log puller.
//
// Supports two modes:
//   1. LookupEvents API  — no S3 config needed, pulls last 90 days, 50 events/call
//   2. S3 bucket mode    — reads gzip CloudTrail log files directly from S3
//
// Uses AWS Signature Version 4 — no external SDK.
//
// Required IAM permissions:
//   cloudtrail:LookupEvents          (LookupEvents mode)
//   s3:ListBucket + s3:GetObject     (S3 mode)
//   sts:GetCallerIdentity            (connection test)

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

const (
	cloudSevInfo     = 1
	cloudSevMedium   = 3
	cloudSevHigh     = 4
	cloudSevCritical = 5
)

// sensitiveOps are CloudTrail event names that warrant higher severity
var sensitiveOps = map[string]int{
	"DeleteTrail":                    cloudSevHigh,
	"StopLogging":                    cloudSevHigh,
	"DeleteBucket":                   cloudSevHigh,
	"PutBucketPolicy":                cloudSevMedium,
	"PutBucketAcl":                   cloudSevMedium,
	"CreateUser":                     cloudSevMedium,
	"AttachUserPolicy":               cloudSevMedium,
	"AttachRolePolicy":               cloudSevMedium,
	"CreateAccessKey":                cloudSevHigh,
	"ConsoleLogin":                   cloudSevMedium,
	"PasswordUpdated":                cloudSevMedium,
	"AuthorizeSecurityGroupIngress":  cloudSevMedium,
	"DeleteSecurityGroup":            cloudSevMedium,
	"ModifyInstanceAttribute":        cloudSevMedium,
	"RunInstances":                   cloudSevInfo,
	"TerminateInstances":             cloudSevMedium,
	"CreateRole":                     cloudSevMedium,
	"DeleteRole":                     cloudSevMedium,
	"PutRolePolicy":                  cloudSevHigh,
	"AssumeRoleWithWebIdentity":      cloudSevMedium,
	"GetSecretValue":                 cloudSevMedium,
	"DeleteSecret":                   cloudSevHigh,
	"DisableKey":                     cloudSevHigh,
	"ScheduleKeyDeletion":            cloudSevHigh,
}

// ── AWS SigV4 ─────────────────────────────────────────────────────────────────

type awsCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func awsSign(req *http.Request, creds awsCreds, service string, body []byte) {
	now := time.Now().UTC()
	date := now.Format("20060102")
	datetime := now.Format("20060102T150405Z")

	if body == nil {
		body = []byte{}
	}
	bodyHash := sha256Hex(body)
	req.Header.Set("X-Amz-Date", datetime)
	req.Header.Set("X-Amz-Content-Sha256", bodyHash)
	if req.Host == "" {
		req.Host = req.URL.Host
	}

	headers := map[string]string{
		"host":                 req.Host,
		"x-amz-content-sha256": bodyHash,
		"x-amz-date":          datetime,
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		headers["content-type"] = ct
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonHeaders, signedHeadersB strings.Builder
	for i, k := range keys {
		canonHeaders.WriteString(k + ":" + headers[k] + "\n")
		if i > 0 {
			signedHeadersB.WriteString(";")
		}
		signedHeadersB.WriteString(k)
	}
	signedHeaders := signedHeadersB.String()

	q := req.URL.Query()
	qkeys := make([]string, 0, len(q))
	for k := range q {
		qkeys = append(qkeys, k)
	}
	sort.Strings(qkeys)
	var canonQuery strings.Builder
	for i, k := range qkeys {
		if i > 0 {
			canonQuery.WriteString("&")
		}
		canonQuery.WriteString(url.QueryEscape(k) + "=" + url.QueryEscape(q.Get(k)))
	}

	canonRequest := strings.Join([]string{
		req.Method, req.URL.Path, canonQuery.String(),
		canonHeaders.String(), signedHeaders, bodyHash,
	}, "\n")

	credScope := date + "/" + creds.Region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + datetime + "\n" + credScope + "\n" + sha256Hex([]byte(canonRequest))

	sigKey := hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256(
		[]byte("AWS4"+creds.SecretAccessKey), date),
		creds.Region), service), "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(sigKey, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID, credScope, signedHeaders, sig))
}

// ── Test connection ────────────────────────────────────────────────────────────

func testAWSConnection(ctx context.Context, creds awsCreds) (string, error) {
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	req, err := http.NewRequestWithContext(ctx, "POST", "https://sts.amazonaws.com/", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	awsSign(req, creds, "sts", body)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("STS request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("invalid credentials — STS returned %d", resp.StatusCode)
	}
	for _, line := range strings.Split(string(respBody), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "<Account>") {
			return strings.TrimSuffix(strings.TrimPrefix(line, "<Account>"), "</Account>"), nil
		}
	}
	return "unknown", nil
}

// ── LookupEvents API ──────────────────────────────────────────────────────────

type lookupEvent struct {
	EventID         string    `json:"EventId"`
	EventName       string    `json:"EventName"`
	EventTime       time.Time `json:"EventTime"`
	EventSource     string    `json:"EventSource"`
	Username        string    `json:"Username"`
	SourceIPAddress string    `json:"SourceIPAddress"`
	CloudTrailEvent string    `json:"CloudTrailEvent"`
}

func lookupCloudTrailEvents(ctx context.Context, creds awsCreds, startTime time.Time, nextToken string) ([]lookupEvent, string, error) {
	endpoint := fmt.Sprintf("https://cloudtrail.%s.amazonaws.com/", creds.Region)
	payload := map[string]interface{}{"MaxResults": 50, "StartTime": startTime.Unix()}
	if nextToken != "" {
		payload["NextToken"] = nextToken
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents")
	awsSign(req, creds, "cloudtrail", body)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("cloudtrail API: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("cloudtrail API %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Events    []lookupEvent `json:"Events"`
		NextToken string        `json:"NextToken"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, "", fmt.Errorf("cloudtrail parse: %w", err)
	}
	return result.Events, result.NextToken, nil
}

// ── S3 CloudTrail log reader ───────────────────────────────────────────────────

type cloudTrailRecord struct {
	EventID         string          `json:"eventID"`
	EventTime       string          `json:"eventTime"`
	EventName       string          `json:"eventName"`
	EventSource     string          `json:"eventSource"`
	EventType       string          `json:"eventType"`
	AWSRegion       string          `json:"awsRegion"`
	SourceIPAddress string          `json:"sourceIPAddress"`
	UserAgent       string          `json:"userAgent"`
	ErrorCode       string          `json:"errorCode"`
	ErrorMessage    string          `json:"errorMessage"`
	RequestParameters json.RawMessage `json:"requestParameters"`
	ResponseElements  json.RawMessage `json:"responseElements"`
	UserIdentity    struct {
		Type      string `json:"type"`
		ARN       string `json:"arn"`
		AccountID string `json:"accountId"`
		UserName  string `json:"userName"`
	} `json:"userIdentity"`
}

func listS3Objects(ctx context.Context, creds awsCreds, bucket, prefix, contToken string) ([]string, string, error) {
	endpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", bucket, creds.Region)
	params := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {"100"}}
	if contToken != "" {
		params.Set("continuation-token", contToken)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, "", err
	}
	awsSign(req, creds, "s3", nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("s3 list %d: %s", resp.StatusCode, string(body))
	}

	var keys []string
	var nextToken string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "<Key>") && strings.HasSuffix(line, "</Key>") {
			key := strings.TrimSuffix(strings.TrimPrefix(line, "<Key>"), "</Key>")
			if strings.HasSuffix(key, ".json.gz") || strings.HasSuffix(key, ".json") {
				keys = append(keys, key)
			}
		}
		if strings.HasPrefix(line, "<NextContinuationToken>") {
			nextToken = strings.TrimSuffix(strings.TrimPrefix(line, "<NextContinuationToken>"), "</NextContinuationToken>")
		}
	}
	return keys, nextToken, nil
}

func getS3Object(ctx context.Context, creds awsCreds, bucket, key string) ([]cloudTrailRecord, error) {
	endpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, creds.Region, key)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	awsSign(req, creds, "s3", nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("s3 get %d: %s", resp.StatusCode, key)
	}

	var reader io.Reader = resp.Body
	if strings.HasSuffix(key, ".gz") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	var result struct {
		Records []cloudTrailRecord `json:"Records"`
	}
	if err := json.NewDecoder(reader).Decode(&result); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return result.Records, nil
}

// ── Converters ────────────────────────────────────────────────────────────────

func cloudTrailRecordToCloudEvent(r cloudTrailRecord, connectorID int64) CloudEvent {
	t, _ := time.Parse(time.RFC3339, r.EventTime)
	if t.IsZero() {
		t = time.Now()
	}

	sev := cloudSevInfo
	if r.ErrorCode != "" {
		sev = cloudSevMedium
	}
	if s, ok := sensitiveOps[r.EventName]; ok {
		if s > sev {
			sev = s
		}
		if r.ErrorCode != "" && sev < cloudSevCritical {
			sev++
		}
	}

	username := r.UserIdentity.UserName
	if username == "" {
		username = r.UserIdentity.ARN
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"source": "cloudtrail", "connector_id": connectorID,
		"event_id": r.EventID, "event_name": r.EventName,
		"event_source": r.EventSource, "event_type": r.EventType,
		"aws_region": r.AWSRegion, "source_ip": r.SourceIPAddress,
		"user_agent": r.UserAgent, "error_code": r.ErrorCode,
		"error_message": r.ErrorMessage, "user_identity": r.UserIdentity,
		"request_parameters": r.RequestParameters,
		"response_elements": r.ResponseElements,
	})

	return CloudEvent{
		ID:        r.EventID,
		Time:      t,
		AgentID:   fmt.Sprintf("aws-cloudtrail-%d", connectorID),
		Host:      r.AWSRegion,
		OS:        "aws",
		EventType: "cloud.cloudtrail",
		Severity:  sev,
		Source:    "cloudtrail",
		Username:  username,
		SrcIP:     r.SourceIPAddress,
		Raw:       raw,
	}
}

func lookupEventToCloudEvent(e lookupEvent, connectorID int64) CloudEvent {
	sev := cloudSevInfo
	if s, ok := sensitiveOps[e.EventName]; ok {
		sev = s
	}

	// Parse the inner CloudTrailEvent JSON to get full details including
	// request_parameters, user_identity, response_elements etc.
	// This is what makes LookupEvents mode as rich as S3 mode.
	var inner map[string]interface{}
	if e.CloudTrailEvent != "" {
		json.Unmarshal([]byte(e.CloudTrailEvent), &inner)
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"source":       "cloudtrail",
		"connector_id": connectorID,
		"event_id":     e.EventID,
		"event_name":   e.EventName,
		"event_source": e.EventSource,
		"source_ip":    e.SourceIPAddress,
		"username":     e.Username,
		// Include full event detail from embedded CloudTrailEvent JSON
		"request_parameters": inner["requestParameters"],
		"response_elements":  inner["responseElements"],
		"user_identity":      inner["userIdentity"],
		"error_code":         inner["errorCode"],
		"error_message":      inner["errorMessage"],
		"user_agent":         inner["userAgent"],
		"aws_region":         inner["awsRegion"],
		// Raw full event for broad matching
		"_full": e.CloudTrailEvent,
	})

	return CloudEvent{
		ID:        e.EventID,
		Time:      e.EventTime,
		AgentID:   fmt.Sprintf("aws-cloudtrail-%d", connectorID),
		Host:      func() string {
			if r, ok := inner["awsRegion"].(string); ok && r != "" {
				return r
			}
			return "aws"
		}(),
		OS:        "aws",
		EventType: "cloud.cloudtrail",
		Severity:  sev,
		Source:    "cloudtrail",
		Username:  e.Username,
		SrcIP:     e.SourceIPAddress,
		Raw:       raw,
	}
}

// ── Main sync ─────────────────────────────────────────────────────────────────

func syncAWS(ctx context.Context, conn *store.CloudConnector, db *store.DB, eventDB *store.DB, logger *slog.Logger) (int, string, error) {
	creds := awsCreds{
		AccessKeyID:     conn.Credentials["access_key_id"],
		SecretAccessKey: conn.Credentials["secret_access_key"],
		Region:          conn.Credentials["region"],
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return 0, "", fmt.Errorf("missing AWS credentials")
	}
	if creds.Region == "" {
		creds.Region = "us-east-1"
	}

	s3Bucket := conn.Credentials["s3_bucket"]
	var totalIngested int
	var newCursor string

	if s3Bucket != "" {
		// S3 mode — check today and yesterday's prefixes
		now := time.Now().UTC()
		prefixes := []string{
			fmt.Sprintf("AWSLogs/%s/CloudTrail/%s/%s/", conn.AccountID, creds.Region, now.Format("2006/01/02")),
			fmt.Sprintf("AWSLogs/%s/CloudTrail/%s/%s/", conn.AccountID, creds.Region, now.AddDate(0, 0, -1).Format("2006/01/02")),
		}
		if conn.SyncCursor == "" {
			// First run: also check 2 days ago
			prefixes = append(prefixes, fmt.Sprintf("AWSLogs/%s/CloudTrail/%s/%s/",
				conn.AccountID, creds.Region, now.AddDate(0, 0, -2).Format("2006/01/02")))
		}

		for _, prefix := range prefixes {
			var contToken string
			if strings.HasPrefix(conn.SyncCursor, "s3:"+prefix) {
				contToken = strings.TrimPrefix(conn.SyncCursor, "s3:"+prefix+":")
			}

			for {
				keys, nextToken, err := listS3Objects(ctx, creds, s3Bucket, prefix, contToken)
				if err != nil {
					logger.Warn("cloudtrail: S3 list failed", "prefix", prefix, "err", err)
					break
				}
				for _, key := range keys {
					records, err := getS3Object(ctx, creds, s3Bucket, key)
					if err != nil {
						logger.Warn("cloudtrail: skip S3 object", "key", key, "err", err)
						continue
					}
					events := make([]CloudEvent, 0, len(records))
					for _, r := range records {
						events = append(events, cloudTrailRecordToCloudEvent(r, conn.ID))
					}
					n, _ := ingestCloudEvents(ctx, eventDB, events)
					totalIngested += n
				}
				if nextToken == "" {
					break
				}
				newCursor = "s3:" + prefix + ":" + nextToken
				contToken = nextToken
			}
		}
	} else {
		// LookupEvents mode
		startTime := time.Now().UTC().Add(-24 * time.Hour)
		if conn.LastSync != nil {
			startTime = conn.LastSync.Add(-2 * time.Minute)
		}

		var nextToken string
		for {
			events, token, err := lookupCloudTrailEvents(ctx, creds, startTime, nextToken)
			if err != nil {
				return totalIngested, newCursor, err
			}
			cloudEvents := make([]CloudEvent, 0, len(events))
			for _, e := range events {
				cloudEvents = append(cloudEvents, lookupEventToCloudEvent(e, conn.ID))
			}
			n, _ := ingestCloudEvents(ctx, eventDB, cloudEvents)
			totalIngested += n

			if token == "" {
				break
			}
			nextToken = token
			select {
			case <-ctx.Done():
				return totalIngested, newCursor, ctx.Err()
			case <-time.After(300 * time.Millisecond):
			}
		}
	}

	// Always pull GuardDuty findings regardless of S3/LookupEvents mode
	gdCount := pullGuardDuty(ctx, creds, conn, eventDB, logger)
	totalIngested += gdCount

	return totalIngested, newCursor, nil
}

// ── GuardDuty findings ───────────────────────────────────────────────────────

type guardDutyFinding struct {
	AccountID   string    `json:"AccountId"`
	Region      string    `json:"Region"`
	ID          string    `json:"Id"`
	Type        string    `json:"Type"`
	Title       string    `json:"Title"`
	Description string    `json:"Description"`
	Severity    float64   `json:"Severity"`
	CreatedAt   time.Time `json:"CreatedAt"`
	UpdatedAt   time.Time `json:"UpdatedAt"`
	Service     struct {
		Action struct {
			ActionType     string `json:"ActionType"`
			NetworkConnectionAction struct {
				RemoteIPDetails struct {
					IPAddressV4 string `json:"IpAddressV4"`
				} `json:"RemoteIpDetails"`
			} `json:"NetworkConnectionAction"`
		} `json:"Action"`
	} `json:"Service"`
	Resource struct {
		ResourceType  string `json:"ResourceType"`
		InstanceDetails struct {
			InstanceID string `json:"InstanceId"`
		} `json:"InstanceDetails"`
	} `json:"Resource"`
}

func listGuardDutyDetectors(ctx context.Context, creds awsCreds) ([]string, error) {
	endpoint := fmt.Sprintf("https://guardduty.%s.amazonaws.com/detector", creds.Region)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	awsSign(req, creds, "guardduty", nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 403 || resp.StatusCode == 404 {
		return nil, nil // GuardDuty not enabled — skip silently
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("guardduty list detectors %d", resp.StatusCode)
	}

	var result struct {
		DetectorIDs []string `json:"DetectorIds"`
	}
	json.Unmarshal(body, &result)
	return result.DetectorIDs, nil
}

func listGuardDutyFindings(ctx context.Context, creds awsCreds, detectorID string, updatedAt time.Time) ([]guardDutyFinding, error) {
	// Step 1: List finding IDs
	endpoint := fmt.Sprintf("https://guardduty.%s.amazonaws.com/detector/%s/findings", creds.Region, detectorID)
	filterPayload := map[string]interface{}{
		"MaxResults": 50,
		"FindingCriteria": map[string]interface{}{
			"Criterion": map[string]interface{}{
				"updatedAt": map[string]interface{}{
					"Gte": updatedAt.UnixMilli(),
				},
			},
		},
	}
	body, _ := json.Marshal(filterPayload)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	awsSign(req, creds, "guardduty", body)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("guardduty list findings %d: %s", resp.StatusCode, string(respBody))
	}

	var listResult struct {
		FindingIDs []string `json:"FindingIds"`
	}
	if err := json.Unmarshal(respBody, &listResult); err != nil || len(listResult.FindingIDs) == 0 {
		return nil, nil
	}

	// Step 2: Get finding details
	getEndpoint := fmt.Sprintf("https://guardduty.%s.amazonaws.com/detector/%s/findings/get", creds.Region, detectorID)
	getPayload := map[string]interface{}{"FindingIds": listResult.FindingIDs}
	getBody, _ := json.Marshal(getPayload)
	getReq, err := http.NewRequestWithContext(ctx, "POST", getEndpoint, strings.NewReader(string(getBody)))
	if err != nil {
		return nil, err
	}
	getReq.Header.Set("Content-Type", "application/json")
	awsSign(getReq, creds, "guardduty", getBody)

	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		return nil, err
	}
	defer getResp.Body.Close()
	getBody2, _ := io.ReadAll(getResp.Body)

	var getResult struct {
		Findings []guardDutyFinding `json:"Findings"`
	}
	json.Unmarshal(getBody2, &getResult)
	return getResult.Findings, nil
}

func guardDutyFindingToCloudEvent(f guardDutyFinding, connectorID int64) CloudEvent {
	// Map GuardDuty severity (1-10) to our scale (1-5)
	sev := cloudSevInfo
	switch {
	case f.Severity >= 7:
		sev = cloudSevHigh
	case f.Severity >= 4:
		sev = cloudSevMedium
	default:
		sev = cloudSevInfo
	}
	if f.Severity >= 9 {
		sev = cloudSevCritical
	}

	srcIP := f.Service.Action.NetworkConnectionAction.RemoteIPDetails.IPAddressV4

	raw, _ := json.Marshal(map[string]interface{}{
		"source":       "guardduty",
		"connector_id": connectorID,
		"finding_id":   f.ID,
		"finding_type": f.Type,
		"title":        f.Title,
		"description":  f.Description,
		"severity":     f.Severity,
		"region":       f.Region,
		"resource":     f.Resource,
		"service":      f.Service,
	})

	host := f.Region
	if f.Resource.InstanceDetails.InstanceID != "" {
		host = f.Resource.InstanceDetails.InstanceID
	}

	return CloudEvent{
		ID:        f.ID,
		Time:      f.UpdatedAt,
		AgentID:   fmt.Sprintf("aws-guardduty-%d", connectorID),
		Host:      host,
		OS:        "aws",
		EventType: "cloud.guardduty",
		Severity:  sev,
		Source:    "guardduty",
		SrcIP:     srcIP,
		Raw:       raw,
	}
}

// pullGuardDuty fetches GuardDuty findings and appends them to the sync
func pullGuardDuty(ctx context.Context, creds awsCreds, conn *store.CloudConnector, eventDB *store.DB, logger *slog.Logger) int {
	detectors, err := listGuardDutyDetectors(ctx, creds)
	if err != nil || len(detectors) == 0 {
		return 0
	}

	since := time.Now().UTC().Add(-24 * time.Hour)
	if conn.LastSync != nil {
		since = conn.LastSync.Add(-2 * time.Minute)
	}

	total := 0
	for _, det := range detectors {
		findings, err := listGuardDutyFindings(ctx, creds, det, since)
		if err != nil {
			logger.Warn("guardduty: fetch failed", "detector", det, "err", err)
			continue
		}
		events := make([]CloudEvent, 0, len(findings))
		for _, f := range findings {
			events = append(events, guardDutyFindingToCloudEvent(f, conn.ID))
		}
		n, _ := ingestCloudEvents(ctx, eventDB, events)
		total += n
	}
	return total
}
