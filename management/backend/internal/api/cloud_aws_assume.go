package api

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AW-03: cross-account access with STS AssumeRole + ExternalId, and support
// for session tokens, instead of only a long-lived IAM-user key. Connector
// credentials: access_key_id / secret_access_key (/ session_token) are the
// *base* identity; when role_arn is set the connector assumes that role and
// every API call uses the temporary credentials (cached until near expiry).

var awsRoleARNRe = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$`)

type assumedCreds struct {
	creds   awsCreds
	expires time.Time
}

var (
	assumeMu    sync.Mutex
	assumeCache = map[string]assumedCreds{}
)

// H-6: region and bucket names are interpolated into hostnames; allowlist them.
var (
	awsRegionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$`)
	awsBucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

type stsAssumeRoleResp struct {
	Credentials struct {
		AccessKeyID     string `xml:"AccessKeyId"`
		SecretAccessKey string `xml:"SecretAccessKey"`
		SessionToken    string `xml:"SessionToken"`
		Expiration      string `xml:"Expiration"`
	} `xml:"AssumeRoleResult>Credentials"`
}

// resolveAWSCreds builds the credentials to use for a connector, performing
// AssumeRole when role_arn is configured.
func resolveAWSCreds(ctx context.Context, c map[string]string) (awsCreds, error) {
	base := awsCreds{
		AccessKeyID:     c["access_key_id"],
		SecretAccessKey: c["secret_access_key"],
		SessionToken:    c["session_token"],
		Region:          c["region"],
	}
	if base.Region == "" {
		base.Region = "us-east-1"
	}
	if !awsRegionRe.MatchString(base.Region) {
		return base, fmt.Errorf("invalid AWS region")
	}
	if b := c["s3_bucket"]; b != "" && !awsBucketRe.MatchString(b) {
		return base, fmt.Errorf("invalid s3_bucket name")
	}
	if r := c["s3_bucket_region"]; r != "" && !awsRegionRe.MatchString(r) {
		return base, fmt.Errorf("invalid s3_bucket_region")
	}
	if base.AccessKeyID == "" || base.SecretAccessKey == "" {
		return base, fmt.Errorf("missing AWS credentials")
	}
	roleARN := strings.TrimSpace(c["role_arn"])
	if roleARN == "" {
		return base, nil
	}
	if !awsRoleARNRe.MatchString(roleARN) {
		return base, fmt.Errorf("role_arn is not a valid IAM role ARN")
	}
	externalID := c["external_id"]
	cacheKey := roleARN + "|" + externalID + "|" + base.AccessKeyID
	assumeMu.Lock()
	if ac, ok := assumeCache[cacheKey]; ok && time.Until(ac.expires) > 5*time.Minute {
		assumeMu.Unlock()
		out := ac.creds
		out.Region = base.Region
		return out, nil
	}
	assumeMu.Unlock()

	form := url.Values{
		"Action":          {"AssumeRole"},
		"Version":         {"2011-06-15"},
		"RoleArn":         {roleARN},
		"RoleSessionName": {"obsidianwatch"},
		"DurationSeconds": {"3600"},
	}
	if externalID != "" {
		form.Set("ExternalId", externalID)
	}
	body := []byte(form.Encode())
	signCreds := base
	signCreds.Region = "us-east-1" // global STS endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://sts.amazonaws.com/", strings.NewReader(string(body)))
	if err != nil {
		return base, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	awsSign(req, signCreds, "sts", body)
	resp, err := awsClient.Do(req)
	if err != nil {
		return base, fmt.Errorf("STS AssumeRole request failed: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return base, fmt.Errorf("AssumeRole denied (HTTP %d): check the role trust policy and ExternalId", resp.StatusCode)
	}
	var r stsAssumeRoleResp
	if err := xml.Unmarshal(data, &r); err != nil || r.Credentials.AccessKeyID == "" {
		return base, fmt.Errorf("unexpected AssumeRole response")
	}
	exp, _ := time.Parse(time.RFC3339, r.Credentials.Expiration)
	if exp.IsZero() {
		exp = time.Now().Add(50 * time.Minute)
	}
	out := awsCreds{
		AccessKeyID:     r.Credentials.AccessKeyID,
		SecretAccessKey: r.Credentials.SecretAccessKey,
		SessionToken:    r.Credentials.SessionToken,
		Region:          base.Region,
	}
	assumeMu.Lock()
	assumeCache[cacheKey] = assumedCreds{creds: out, expires: exp}
	assumeMu.Unlock()
	return out, nil
}
