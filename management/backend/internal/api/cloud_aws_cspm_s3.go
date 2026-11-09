package api

// AW-10: per-bucket S3 hardening checks beyond public-access-block.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
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
			host := b + ".s3.amazonaws.com"
			if body, c, err := awsS3Get(ctx, creds, host, "/?versioning"); err == nil && c == 200 {
				p.versioningXML, p.versioningOK = body, true
			}
			if body, c, err := awsS3Get(ctx, creds, host, "/?logging"); err == nil && c == 200 {
				p.loggingXML, p.loggingOK = body, true
			}
			if body, c, err := awsS3Get(ctx, creds, host, "/?policy"); err == nil {
				if c == 200 {
					p.policy, p.policyOK = string(body), true
				} else if c == 404 {
					p.policyOK = true // NoSuchBucketPolicy
				}
			}
			if body, c, err := awsS3Get(ctx, creds, host, "/?acl"); err == nil && c == 200 {
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
		skip("s3_hardening", fmt.Sprintf("%d bucket(s) could not be read — grant s3:GetBucketVersioning/Logging/Policy/Acl (SecurityAudit)", denied))
	}
}
