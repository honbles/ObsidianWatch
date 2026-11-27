package api

// AW-10: per-bucket S3 hardening checks beyond public-access-block.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

const awsMaxHardenedBuckets = 200

type awsS3Probe struct {
	versioningXML []byte
	versioningOK  bool
	loggingXML    []byte
	loggingOK     bool
	policy        string // empty when there is no bucket policy
	policyOK      bool
	aclXML        []byte
	aclOK         bool
}

func awsS3BucketFindings(bucket string, p awsS3Probe) ([]CSPMFinding, bool) {
	var out []CSPMFinding
	mk := func(title, sev, desc, rem, mitre string) {
		out = append(out, CSPMFinding{Title: title, Severity: sev, Category: "storage", Resource: bucket,
			ResourceType: "s3_bucket", Description: desc, Remediation: rem, MITRE: mitre})
	}
	if p.versioningOK {
		var v struct {
			Status string `xml:"Status"`
		}
		_ = xml.Unmarshal(p.versioningXML, &v)
		if v.Status != "Enabled" {
			mk(fmt.Sprintf("S3 bucket '%s' does not have versioning enabled", bucket), "low",
				"Without versioning, overwritten or deleted objects (including by ransomware or a compromised credential) cannot be recovered.",
				"Enable versioning, and MFA delete for critical buckets.", "T1485")
		}
	}
	if p.loggingOK {
		if !strings.Contains(string(p.loggingXML), "<LoggingEnabled>") {
			mk(fmt.Sprintf("S3 bucket '%s' has no server access logging", bucket), "low",
				"Object-level access to this bucket is not recorded in server access logs.",
				"Enable server access logging or CloudTrail data events for the bucket.", "T1562.008")
		}
	}
	if p.policyOK && p.policy != "" {
		public, tlsOnly := awsBucketPolicyFacts(p.policy)
		if public {
			mk(fmt.Sprintf("S3 bucket '%s' has a bucket policy that allows public access", bucket), "high",
				"A statement allows Principal \"*\" without a restricting condition.",
				"Restrict the principal or add conditions (VPC endpoint, source account), and enable Block Public Access.", "T1530")
		}
		if !tlsOnly {
			mk(fmt.Sprintf("S3 bucket '%s' policy does not require TLS", bucket), "low",
				"Nothing denies requests that do not use HTTPS (aws:SecureTransport).",
				"Add a Deny statement for aws:SecureTransport = false.", "T1040")
		}
	} else if p.policyOK {
		mk(fmt.Sprintf("S3 bucket '%s' policy does not require TLS", bucket), "low",
			"The bucket has no policy, so plain-HTTP requests are not denied.",
			"Add a Deny statement for aws:SecureTransport = false.", "T1040")
	}
	if p.aclOK && strings.Contains(string(p.aclXML), "http://acs.amazonaws.com/groups/global/AllUsers") {
		mk(fmt.Sprintf("S3 bucket '%s' ACL grants access to everyone", bucket), "high",
			"The bucket ACL contains a grant to the AllUsers group.",
			"Remove the grant, set Object Ownership to BucketOwnerEnforced and enable Block Public Access.", "T1530")
	}
	return out, p.versioningOK || p.loggingOK || p.policyOK || p.aclOK
}

// awsBucketPolicyFacts reports whether the policy has an unconditioned
// Allow for Principal "*", and whether it denies non-TLS requests.
func awsBucketPolicyFacts(doc string) (public, tlsOnly bool) {
	var pd struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &pd) != nil {
		return
	}
	type stmt struct {
		Effect    string          `json:"Effect"`
		Principal json.RawMessage `json:"Principal"`
		Condition json.RawMessage `json:"Condition"`
	}
	var list []stmt
	if json.Unmarshal(pd.Statement, &list) != nil {
		var one stmt
		if json.Unmarshal(pd.Statement, &one) != nil {
			return
		}
		list = []stmt{one}
	}
	starPrincipal := func(raw json.RawMessage) bool {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s == "*"
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) == nil {
			if a, ok := m["AWS"]; ok {
				var s2 string
				if json.Unmarshal(a, &s2) == nil {
					return s2 == "*"
				}
				var l []string
				if json.Unmarshal(a, &l) == nil {
					for _, x := range l {
						if x == "*" {
							return true
						}
					}
				}
			}
		}
		return false
	}
	for _, s := range list {
		cond := strings.ReplaceAll(strings.ToLower(string(s.Condition)), " ", "")
		if strings.EqualFold(s.Effect, "Allow") && starPrincipal(s.Principal) && (len(s.Condition) == 0 || string(s.Condition) == "null") {
			public = true
		}
		if strings.EqualFold(s.Effect, "Deny") && strings.Contains(cond, "aws:securetransport") && strings.Contains(cond, `"false"`) {
			tlsOnly = true
		}
	}
	return
}

// runAWSS3Hardening probes up to awsMaxHardenedBuckets buckets (8 at a time).
func runAWSS3Hardening(ctx context.Context, creds awsCreds, buckets []string, add func([]CSPMFinding), skip func(string, string), passed *int) {
	if len(buckets) > awsMaxHardenedBuckets {
		buckets = buckets[:awsMaxHardenedBuckets]
		skip("s3_hardening", fmt.Sprintf("only the first %d buckets were checked", awsMaxHardenedBuckets))
	}
	type res struct {
		f  []CSPMFinding
		ok bool
	}
	results := make([]res, len(buckets))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, b := range buckets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, b string) {
			defer wg.Done()
			defer func() { <-sem }()
			var p awsS3Probe
			if body, c, err := awsBucketGet(ctx, creds, b, "?versioning"); err == nil && c == 200 {
				p.versioningXML, p.versioningOK = body, true
			}
			if body, c, err := awsBucketGet(ctx, creds, b, "?logging"); err == nil && c == 200 {
				p.loggingXML, p.loggingOK = body, true
			}
			if body, c, err := awsBucketGet(ctx, creds, b, "?policy"); err == nil {
				if c == 200 {
					p.policy, p.policyOK = string(body), true
				} else if c == 404 {
					p.policyOK = true // NoSuchBucketPolicy
				}
			}
			if body, c, err := awsBucketGet(ctx, creds, b, "?acl"); err == nil && c == 200 {
				p.aclXML, p.aclOK = body, true
			}
			f, ok := awsS3BucketFindings(b, p)
			results[i] = res{f, ok}
		}(i, b)
	}
	wg.Wait()
	denied := 0
	for _, r := range results {
		if !r.ok {
			denied++
			continue
		}
		if len(r.f) == 0 {
			*passed++
		}
		add(r.f)
	}
	if denied > 0 {
		skip("s3_hardening", fmt.Sprintf("%d bucket(s) could not be read - grant s3:GetBucketVersioning/Logging/Policy/Acl (SecurityAudit)", denied))
	}
}

// ── Bucket regions ───────────────────────────────────────────────────────────

// Per-bucket S3 requests must go to the bucket's own region and be signed
// for it. They used to go to <bucket>.s3.amazonaws.com signed for us-east-1,
// which S3 refuses for buckets in any other region (AuthorizationHeaderMalformed
// / redirect), so those buckets were silently reported as unreadable.
var awsBucketRegions sync.Map // bucket name -> region

// awsBucketRegion finds a bucket's region: GetBucketLocation on the global
// endpoint, else the x-amz-bucket-region header S3 sends even on errors.
func awsBucketRegion(ctx context.Context, creds awsCreds, bucket string) (string, error) {
	if v, ok := awsBucketRegions.Load(bucket); ok {
		return v.(string), nil
	}
	if !awsBucketRe.MatchString(bucket) {
		return "", fmt.Errorf("unexpected bucket name %q", bucket)
	}
	g := creds
	g.Region = "us-east-1"
	region := ""
	if body, code, err := awsS3Get(ctx, g, "s3.amazonaws.com", "/"+bucket+"?location"); err == nil && code == 200 {
		var lc struct {
			Value string `xml:",chardata"`
		}
		if xml.Unmarshal(body, &lc) == nil {
			region = strings.TrimSpace(lc.Value)
			switch region {
			case "":
				region = "us-east-1"
			case "EU":
				region = "eu-west-1"
			}
		}
	}
	if region == "" {
		if req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://s3.amazonaws.com/"+bucket, nil); err == nil {
			awsSign(req, g, "s3", nil)
			if resp, err := awsClient.Do(req); err == nil {
				region = resp.Header.Get("X-Amz-Bucket-Region")
				resp.Body.Close()
			}
		}
	}
	if !awsRegionRe.MatchString(region) {
		return "", fmt.Errorf("could not determine the region of bucket %s", bucket)
	}
	awsBucketRegions.Store(bucket, region)
	return region, nil
}

// awsBucketGet reads a bucket subresource (for example "?versioning") from
// the bucket's own regional endpoint, signed for that region.
func awsBucketGet(ctx context.Context, creds awsCreds, bucket, sub string) ([]byte, int, error) {
	region, err := awsBucketRegion(ctx, creds, bucket)
	if err != nil {
		return nil, 0, err
	}
	rc := creds
	rc.Region = region
	host, path := bucket+".s3."+region+".amazonaws.com", "/"+sub
	if strings.Contains(bucket, ".") { // dotted names break TLS on virtual-hosted endpoints
		host, path = "s3."+region+".amazonaws.com", "/"+bucket+sub
	}
	return awsS3Get(ctx, rc, host, path)
}

// awsAccountPABOn reports whether account-level S3 Block Public Access has all
// four settings on (S3 Control GetPublicAccessBlock). Unknown counts as off.
func awsAccountPABOn(ctx context.Context, creds awsCreds, accountID string) bool {
	if len(accountID) != 12 {
		return false
	}
	for _, c := range accountID {
		if c < '0' || c > '9' {
			return false
		}
	}
	rc := creds
	if rc.Region == "" || !awsRegionRe.MatchString(rc.Region) {
		rc.Region = "us-east-1"
	}
	host := accountID + ".s3-control." + rc.Region + ".amazonaws.com"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/v20180820/configuration/publicAccessBlock", nil)
	if err != nil {
		return false
	}
	req.Header.Set("x-amz-account-id", accountID)
	awsSign(req, rc, "s3", nil)
	resp, err := awsClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	var c struct {
		A bool `xml:"BlockPublicAcls"`
		B bool `xml:"IgnorePublicAcls"`
		C bool `xml:"BlockPublicPolicy"`
		D bool `xml:"RestrictPublicBuckets"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return xml.Unmarshal(b, &c) == nil && c.A && c.B && c.C && c.D
}
