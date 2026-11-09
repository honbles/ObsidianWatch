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
	"encoding/xml"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
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
	"DeleteTrail":                   cloudSevHigh,
	"StopLogging":                   cloudSevHigh,
	"DeleteBucket":                  cloudSevHigh,
	"PutBucketPolicy":               cloudSevMedium,
	"PutBucketAcl":                  cloudSevMedium,
	"CreateUser":                    cloudSevMedium,
	"AttachUserPolicy":              cloudSevMedium,
	"AttachRolePolicy":              cloudSevMedium,
	"CreateAccessKey":               cloudSevHigh,
	"ConsoleLogin":                  cloudSevMedium,
	"PasswordUpdated":               cloudSevMedium,
	"AuthorizeSecurityGroupIngress": cloudSevMedium,
	"DeleteSecurityGroup":           cloudSevMedium,
	"ModifyInstanceAttribute":       cloudSevMedium,
	"RunInstances":                  cloudSevInfo,
	"TerminateInstances":            cloudSevMedium,
	"CreateRole":                    cloudSevMedium,
	"DeleteRole":                    cloudSevMedium,
	"PutRolePolicy":                 cloudSevHigh,
	"AssumeRoleWithWebIdentity":     cloudSevMedium,
	"GetSecretValue":                cloudSevMedium,
	"DeleteSecret":                  cloudSevHigh,
	"DisableKey":                    cloudSevHigh,
	"ScheduleKeyDeletion":           cloudSevHigh,
}

// ── AWS SigV4 ─────────────────────────────────────────────────────────────────

type awsCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // temporary credentials (AssumeRole / STS)
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
	now := awsNow() // AW-09: corrected for learned clock skew
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
		"x-amz-date":           datetime,
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		headers["content-type"] = ct
	}
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
		headers["x-amz-security-token"] = creds.SessionToken
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

	resp, err := awsClient.Do(req)
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

	resp, err := awsClient.Do(req)
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
	EventID           string          `json:"eventID"`
	EventTime         string          `json:"eventTime"`
	EventName         string          `json:"eventName"`
	EventSource       string          `json:"eventSource"`
	EventType         string          `json:"eventType"`
	AWSRegion         string          `json:"awsRegion"`
	SourceIPAddress   string          `json:"sourceIPAddress"`
	UserAgent         string          `json:"userAgent"`
	ErrorCode         string          `json:"errorCode"`
	ErrorMessage      string          `json:"errorMessage"`
	RequestParameters json.RawMessage `json:"requestParameters"`
	ResponseElements  json.RawMessage `json:"responseElements"`
	// AW-04: keep the full userIdentity (accessKeyId, principalId,
	// sessionContext incl. MFA/issuer, invokedBy…) instead of reducing it to
	// four fields, plus the other attribution-relevant CloudTrail fields.
	UserIdentity        json.RawMessage `json:"userIdentity"`
	AdditionalEventData json.RawMessage `json:"additionalEventData"`
	ReadOnly            *bool           `json:"readOnly"`
	RecipientAccountID  string          `json:"recipientAccountId"`
	Resources           json.RawMessage `json:"resources"`
	ManagementEvent     *bool           `json:"managementEvent"`
	VPCEndpointID       string          `json:"vpcEndpointId"`
}

// userIdentityBasics extracts the commonly used fields from a raw userIdentity.
func userIdentityBasics(raw json.RawMessage) (typ, arn, account, user string) {
	var u struct {
		Type      string `json:"type"`
		ARN       string `json:"arn"`
		AccountID string `json:"accountId"`
		UserName  string `json:"userName"`
	}
	_ = json.Unmarshal(raw, &u)
	return u.Type, u.ARN, u.AccountID, u.UserName
}

// listS3Objects lists one page of CloudTrail log objects under prefix,
// starting after startAfter (AW-02). The response is real XML (S3 returns it
// on a single line, so line-splitting missed keys), parsed with encoding/xml.
func listS3Objects(ctx context.Context, creds awsCreds, bucket, bucketRegion, prefix, startAfter, contToken string) ([]string, string, error) {
	if bucketRegion == "" {
		bucketRegion = creds.Region
	}
	endpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", bucket, bucketRegion)
	params := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {"100"}}
	if contToken != "" {
		params.Set("continuation-token", contToken)
	} else if startAfter != "" {
		params.Set("start-after", startAfter)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, "", err
	}
	awsSign(req, creds, "s3", nil)

	resp, err := awsClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("s3 list %d: %s", resp.StatusCode, string(body)[:minInt(300, len(body))])
	}

	var lr struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
		NextContinuationToken string `xml:"NextContinuationToken"`
	}
	if err := xml.Unmarshal(body, &lr); err != nil {
		return nil, "", fmt.Errorf("s3 list parse: %w", err)
	}
	var keys []string
	for _, c := range lr.Contents {
		if strings.HasSuffix(c.Key, ".json.gz") || strings.HasSuffix(c.Key, ".json") {
			keys = append(keys, c.Key)
		}
	}
	return keys, lr.NextContinuationToken, nil
}

func getS3Object(ctx context.Context, creds awsCreds, bucket, bucketRegion, key string) ([]cloudTrailRecord, error) {
	if bucketRegion == "" {
		bucketRegion = creds.Region
	}
	endpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, bucketRegion, key)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	awsSign(req, creds, "s3", nil)

	resp, err := awsClient.Do(req)
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

	_, uiARN, _, username := userIdentityBasics(r.UserIdentity)
	if username == "" {
		username = uiARN
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"source": "cloudtrail", "connector_id": connectorID,
		"event_id": r.EventID, "event_name": r.EventName,
		"event_source": r.EventSource, "event_type": r.EventType,
		"aws_region": r.AWSRegion, "source_ip": r.SourceIPAddress,
		"user_agent": r.UserAgent, "error_code": r.ErrorCode,
		"error_message": r.ErrorMessage, "user_identity": r.UserIdentity,
		"request_parameters": r.RequestParameters,
		"response_elements":  r.ResponseElements,
		"additional_event_data": r.AdditionalEventData, "read_only": r.ReadOnly,
		"recipient_account_id": r.RecipientAccountID, "resources": r.Resources,
		"management_event": r.ManagementEvent, "vpc_endpoint_id": r.VPCEndpointID,
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
		"additional_event_data": inner["additionalEventData"],
		"read_only":             inner["readOnly"],
		"recipient_account_id":  inner["recipientAccountId"],
		"resources":             inner["resources"],
		"management_event":      inner["managementEvent"],
		"vpc_endpoint_id":       inner["vpcEndpointId"],
		// Raw full event for broad matching
		"_full": e.CloudTrailEvent,
	})

	return CloudEvent{
		ID:      e.EventID,
		Time:    e.EventTime,
		AgentID: fmt.Sprintf("aws-cloudtrail-%d", connectorID),
		Host: func() string {
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
	creds, credErr := resolveAWSCreds(ctx, conn.Credentials)
	if credErr != nil {
		return 0, "", credErr
	}

	s3Bucket := conn.Credentials["s3_bucket"]
	var totalIngested int
	var newCursor string

	if s3Bucket != "" {
		// S3 mode (AW-02): per-prefix "last processed key" cursor (StartAfter)
		// so objects are never re-downloaded; iterates accounts x regions
		// (and organization trail layout) instead of one hard-coded prefix.
		bucketRegion := conn.Credentials["s3_bucket_region"]
		prefixes := s3TrailPrefixes(conn, creds.Region, time.Now().UTC())
		cursors := map[string]string{}
		if strings.HasPrefix(conn.SyncCursor, "{") {
			json.Unmarshal([]byte(conn.SyncCursor), &cursors)
		}
		newCursors := map[string]string{}
		for _, prefix := range prefixes {
			last := cursors[prefix]
			newCursors[prefix] = last
			var contToken string
		pageLoop:
			for {
				keys, nextToken, err := listS3Objects(ctx, creds, s3Bucket, bucketRegion, prefix, last, contToken)
				if err != nil {
					logger.Warn("cloudtrail: S3 list failed", "prefix", prefix, "err", err)
					recordSourceStatus(conn.ID, "cloudtrail_s3", "error", err.Error())
					break
				}
				for _, key := range keys {
					records, err := getS3Object(ctx, creds, s3Bucket, bucketRegion, key)
					if err != nil {
						logger.Warn("cloudtrail: S3 object failed", "key", key, "err", err)
						// Retry on the next sync, but give up after 3 attempts so one
						// corrupt object can't block the prefix forever.
						if s3FailCount(key) < 3 {
							break pageLoop
						}
						logger.Error("cloudtrail: skipping S3 object after repeated failures", "key", key)
					}
					events := make([]CloudEvent, 0, len(records))
					for _, r := range records {
						events = append(events, cloudTrailRecordToCloudEvent(r, conn.ID))
					}
					n, _ := ingestCloudEvents(ctx, eventDB, events)
					totalIngested += n
					newCursors[prefix] = key
					last = key
				}
				if nextToken == "" {
					recordSourceStatus(conn.ID, "cloudtrail_s3", "ok", "")
					break
				}
				contToken = nextToken
			}
		}
		if b, err := json.Marshal(newCursors); err == nil {
			newCursor = string(b)
		}
	} else {
		// LookupEvents mode.
		//
		// AW-01/G-01: this used to watermark on conn.LastSync, which
		// UpdateCloudConnectorStatus bumps to NOW() on every run including
		// a failed one — so a throttle error partway through a sync still
		// advanced the window past whatever pages hadn't been read yet,
		// permanently losing them. Now it watermarks on conn.SyncCursor
		// (max CloudTrail EventTime actually ingested, like the GCP/Azure
		// cursors), which only ever advances to what was truly ingested —
		// including on a partial failure, never past it.
		startTime := time.Now().UTC().Add(-24 * time.Hour)
		if conn.SyncCursor != "" {
			if t, err := time.Parse(time.RFC3339Nano, conn.SyncCursor); err == nil {
				startTime = t.Add(-2 * time.Minute)
			}
		} else if conn.LastSync != nil {
			startTime = conn.LastSync.Add(-2 * time.Minute)
		}
		cursorFloor := startTime
		maxSeen := cursorFloor

		var nextToken string
		for {
			events, token, err := lookupCloudTrailEvents(ctx, creds, startTime, nextToken)
			if err != nil {
				st := "error"
				if strings.Contains(err.Error(), "403") || strings.Contains(strings.ToLower(err.Error()), "accessdenied") {
					st = "permission_missing"
				}
				recordSourceStatus(conn.ID, "cloudtrail", st, err.Error())
				return totalIngested, awsCursorString(maxSeen, cursorFloor), err
			}
			recordSourceStatus(conn.ID, "cloudtrail", "ok", "")
			cloudEvents := make([]CloudEvent, 0, len(events))
			for _, e := range events {
				cloudEvents = append(cloudEvents, lookupEventToCloudEvent(e, conn.ID))
				if e.EventTime.After(maxSeen) {
					maxSeen = e.EventTime
				}
			}
			n, _ := ingestCloudEvents(ctx, eventDB, cloudEvents)
			totalIngested += n

			if token == "" {
				break
			}
			nextToken = token
			select {
			case <-ctx.Done():
				return totalIngested, awsCursorString(maxSeen, cursorFloor), ctx.Err()
			case <-time.After(300 * time.Millisecond):
			}
		}
		newCursor = awsCursorString(maxSeen, cursorFloor)
	}

	// Always pull GuardDuty findings regardless of S3/LookupEvents mode
	gdCount := pullGuardDuty(ctx, creds, conn, eventDB, logger)
	totalIngested += gdCount
	totalIngested += pullSecurityHub(ctx, creds, conn, eventDB, logger)

	return totalIngested, newCursor, nil
}

// awsCursorString returns the new LookupEvents watermark to persist, or ""
// (leave the stored cursor unchanged) if nothing in this run advanced it
// past where the run started.
func awsCursorString(maxSeen, floor time.Time) string {
	if !maxSeen.After(floor) {
		return ""
	}
	return maxSeen.UTC().Format(time.RFC3339Nano)
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
			ActionType              string `json:"ActionType"`
			NetworkConnectionAction struct {
				RemoteIPDetails struct {
					IPAddressV4 string `json:"IpAddressV4"`
				} `json:"RemoteIpDetails"`
			} `json:"NetworkConnectionAction"`
		} `json:"Action"`
	} `json:"Service"`
	Resource struct {
		ResourceType    string `json:"ResourceType"`
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

	resp, err := awsClient.Do(req)
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
	// AW-06: paginate with NextToken (bounded), fetch details in chunks of 50.
	const maxPages = 20
	var all []guardDutyFinding
	nextToken := ""
	listEndpoint := fmt.Sprintf("https://guardduty.%s.amazonaws.com/detector/%s/findings", creds.Region, detectorID)
	getEndpoint := fmt.Sprintf("https://guardduty.%s.amazonaws.com/detector/%s/findings/get", creds.Region, detectorID)
	for page := 0; page < maxPages; page++ {
		payload := map[string]interface{}{
			"MaxResults": 50,
			"FindingCriteria": map[string]interface{}{
				"Criterion": map[string]interface{}{
					"updatedAt": map[string]interface{}{"Gte": updatedAt.UnixMilli()},
				},
			},
		}
		if nextToken != "" {
			payload["NextToken"] = nextToken
		}
		body, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, "POST", listEndpoint, strings.NewReader(string(body)))
		if err != nil {
			return all, err
		}
		req.Header.Set("Content-Type", "application/json")
		awsSign(req, creds, "guardduty", body)
		resp, err := awsClient.Do(req)
		if err != nil {
			return all, err
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return all, fmt.Errorf("guardduty list findings %d: %s", resp.StatusCode, string(respBody))
		}
		var lr struct {
			FindingIDs []string `json:"FindingIds"`
			NextToken  string   `json:"NextToken"`
		}
		if err := json.Unmarshal(respBody, &lr); err != nil {
			return all, err
		}
		if len(lr.FindingIDs) > 0 {
			getBody, _ := json.Marshal(map[string]interface{}{"FindingIds": lr.FindingIDs})
			getReq, err := http.NewRequestWithContext(ctx, "POST", getEndpoint, strings.NewReader(string(getBody)))
			if err != nil {
				return all, err
			}
			getReq.Header.Set("Content-Type", "application/json")
			awsSign(getReq, creds, "guardduty", getBody)
			getResp, err := awsClient.Do(getReq)
			if err != nil {
				return all, err
			}
			gb, _ := io.ReadAll(getResp.Body)
			getResp.Body.Close()
			if getResp.StatusCode != 200 {
				return all, fmt.Errorf("guardduty get findings %d: %s", getResp.StatusCode, string(gb))
			}
			var gr struct {
				Findings []guardDutyFinding `json:"Findings"`
			}
			if err := json.Unmarshal(gb, &gr); err != nil {
				return all, err
			}
			all = append(all, gr.Findings...)
		}
		if lr.NextToken == "" {
			break
		}
		nextToken = lr.NextToken
	}
	return all, nil
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
	if err != nil {
		st := "error"
		if strings.Contains(err.Error(), "403") || strings.Contains(strings.ToLower(err.Error()), "accessdenied") {
			st = "permission_missing"
		}
		recordSourceStatus(conn.ID, "guardduty", st, err.Error())
		return 0
	}
	if len(detectors) == 0 {
		recordSourceStatus(conn.ID, "guardduty", "not_enabled", "no GuardDuty detector in region "+creds.Region)
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
			recordSourceStatus(conn.ID, "guardduty", "error", err.Error())
			continue
		}
		recordSourceStatus(conn.ID, "guardduty", "ok", "")
		events := make([]CloudEvent, 0, len(findings))
		for _, f := range findings {
			events = append(events, guardDutyFindingToCloudEvent(f, conn.ID))
		}
		n, _ := ingestCloudEvents(ctx, eventDB, events)
		total += n
	}
	return total
}

// awsErrorAllows gates CloudTrail events by outcome (AW-07): a call that
// returned an errorCode (AccessDenied, UnauthorizedOperation, …) did not
// change anything, but almost no rule looked at errorCode, so failed calls
// alerted like successful ones. Rules about failures/denials/brute force
// still see them.
func awsErrorAllows(sig ThreatSig, ev store.Event) bool {
	if ev.EventType != "cloud.cloudtrail" || len(ev.Raw) == 0 {
		return true
	}
	var r struct {
		ErrorCode interface{} `json:"error_code"`
	}
	if json.Unmarshal(ev.Raw, &r) != nil {
		return true
	}
	if code, _ := r.ErrorCode.(string); code == "" {
		return true
	}
	n := strings.ToLower(sig.Name)
	return strings.Contains(n, "fail") || strings.Contains(n, "denied") ||
		strings.Contains(n, "brute") || strings.Contains(n, "unauthor") ||
		strings.Contains(n, "recon") || strings.Contains(n, "enumerat")
}

// s3TrailPrefixes builds the date-scoped CloudTrail prefixes to read.
// Credentials (all optional):
//
//	s3_account_ids  comma-separated account IDs (default: the connector account)
//	s3_regions      comma-separated regions (default: the connector region)
//	s3_org_id       AWS Organizations ID (o-xxxx) for org trails
func s3TrailPrefixes(conn *store.CloudConnector, defRegion string, now time.Time) []string {
	split := func(v, def string) []string {
		var out []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		if len(out) == 0 && def != "" {
			out = []string{def}
		}
		return out
	}
	accounts := split(conn.Credentials["s3_account_ids"], conn.AccountID)
	regions := split(conn.Credentials["s3_regions"], defRegion)
	orgID := strings.TrimSpace(conn.Credentials["s3_org_id"])
	days := 3 // today, yesterday, day before (late-delivered logs)
	var prefixes []string
	for d := 0; d < days; d++ {
		date := now.AddDate(0, 0, -d).Format("2006/01/02")
		for _, acct := range accounts {
			for _, reg := range regions {
				if orgID != "" {
					prefixes = append(prefixes, fmt.Sprintf("AWSLogs/%s/%s/CloudTrail/%s/%s/", orgID, acct, reg, date))
				} else {
					prefixes = append(prefixes, fmt.Sprintf("AWSLogs/%s/CloudTrail/%s/%s/", acct, reg, date))
				}
			}
		}
	}
	return prefixes
}

var (
	s3FailMu sync.Mutex
	s3Fails  = map[string]int{}
)

// s3FailCount records a failure for key and returns the new count.
func s3FailCount(key string) int {
	s3FailMu.Lock()
	defer s3FailMu.Unlock()
	if len(s3Fails) > 10000 {
		s3Fails = map[string]int{}
	}
	s3Fails[key]++
	return s3Fails[key]
}
