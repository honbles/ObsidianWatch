package api

// AW-10 (first slice): AWS CSPM. Read-only checks over IAM account posture,
// security groups, S3 public access blocks and CloudTrail coverage, using the
// same hand-signed client as ingestion. Needs SecurityAudit / ReadOnlyAccess.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func awsQueryCall(ctx context.Context, creds awsCreds, service, host, form string) ([]byte, int, error) {
	body := []byte(form)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+host+"/", strings.NewReader(form))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	awsSign(req, creds, service, body)
	resp, err := awsClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return b, resp.StatusCode, nil
}

// ── IAM ──────────────────────────────────────────────────────────────────────

type awsSummaryMap struct {
	Entries []struct {
		Key   string `xml:"key"`
		Value int    `xml:"value"`
	} `xml:"GetAccountSummaryResult>SummaryMap>entry"`
}

func awsIAMFindings(summaryXML []byte, policyStatus int, policyXML []byte) []CSPMFinding {
	var out []CSPMFinding
	var s awsSummaryMap
	if xml.Unmarshal(summaryXML, &s) == nil {
		m := map[string]int{}
		for _, e := range s.Entries {
			m[e.Key] = e.Value
		}
		if v, ok := m["AccountMFAEnabled"]; ok && v == 0 {
			out = append(out, CSPMFinding{Title: "Root account has no MFA", Severity: "critical", Category: "iam",
				Description: "The AWS root user has full control of the account and is not protected by MFA.",
				Resource:    "root", ResourceType: "iam_root", MITRE: "T1078.004",
				Remediation: "Enable a hardware or virtual MFA device for the root user."})
		}
		if m["AccountAccessKeysPresent"] > 0 {
			out = append(out, CSPMFinding{Title: "Root account has active access keys", Severity: "high", Category: "iam",
				Description: "Root access keys give unrestricted programmatic access and cannot be scoped.",
				Resource:    "root", ResourceType: "iam_root", MITRE: "T1078.004",
				Remediation: "Delete root access keys and use IAM roles."})
		}
	}
	if policyStatus == 404 {
		out = append(out, CSPMFinding{Title: "No IAM account password policy", Severity: "medium", Category: "iam",
			Description: "No password policy is set, so IAM users may use weak passwords.",
			Resource:    "account", ResourceType: "iam_password_policy", MITRE: "T1110",
			Remediation: "Set a password policy with a minimum length of 14 and rotation/reuse rules."})
	} else if policyStatus == 200 {
		var p struct {
			Min int `xml:"GetAccountPasswordPolicyResult>PasswordPolicy>MinimumPasswordLength"`
		}
		if xml.Unmarshal(policyXML, &p) == nil && p.Min > 0 && p.Min < 14 {
			out = append(out, CSPMFinding{Title: fmt.Sprintf("IAM password policy minimum length is %d", p.Min), Severity: "low", Category: "iam",
				Description: "Short minimum password length weakens console password strength.",
				Resource:    "account", ResourceType: "iam_password_policy", MITRE: "T1110",
				Remediation: "Require at least 14 characters."})
		}
	}
	return out
}

// ── EC2 security groups ──────────────────────────────────────────────────────

type awsSG struct {
	ID    string `xml:"groupId"`
	Name  string `xml:"groupName"`
	Perms []struct {
		Proto string   `xml:"ipProtocol"`
		From  string   `xml:"fromPort"`
		To    string   `xml:"toPort"`
		V4    []string `xml:"ipRanges>item>cidrIp"`
		V6    []string `xml:"ipv6Ranges>item>cidrIpv6"`
	} `xml:"ipPermissions>item"`
}

func awsSGFindings(sgXML []byte, region string) []CSPMFinding {
	var r struct {
		Groups []awsSG `xml:"securityGroupInfo>item"`
	}
	if xml.Unmarshal(sgXML, &r) != nil {
		return nil
	}
	var out []CSPMFinding
	for _, g := range r.Groups {
		for _, p := range g.Perms {
			open := false
			for _, c := range p.V4 {
				if c == "0.0.0.0/0" {
					open = true
				}
			}
			for _, c := range p.V6 {
				if c == "::/0" {
					open = true
				}
			}
			if !open {
				continue
			}
			res := fmt.Sprintf("%s (%s) %s", g.ID, g.Name, region)
			port := p.From
			if p.To != "" && p.To != p.From {
				port = p.From + "-" + p.To
			}
			switch {
			case p.Proto == "-1":
				out = append(out, CSPMFinding{Title: "Security group allows all traffic from the internet", Severity: "critical", Category: "network",
					Description: "Security group " + g.ID + " allows every protocol and port from 0.0.0.0/0.",
					Resource:    res, ResourceType: "security_group", MITRE: "T1190",
					Remediation: "Restrict ingress to required ports and trusted CIDR ranges."})
			case p.From == "22" || p.From == "3389" || (p.From != "" && p.From != "80" && p.From != "443" && p.To != p.From):
				sev := "medium"
				if p.From == "22" || p.From == "3389" {
					sev = "high"
				}
				out = append(out, CSPMFinding{Title: fmt.Sprintf("Security group exposes port %s to the internet", port), Severity: sev, Category: "network",
					Description: "Security group " + g.ID + " allows " + p.Proto + "/" + port + " from 0.0.0.0/0 or ::/0.",
					Resource:    res, ResourceType: "security_group", MITRE: "T1190",
					Remediation: "Limit the source to a VPN/bastion CIDR or use SSM Session Manager."})
			}
		}
	}
	return out
}

// ── S3 ───────────────────────────────────────────────────────────────────────

func awsS3PABFinding(bucket string, status int, body []byte) (*CSPMFinding, bool) {
	mk := func(sev, title, desc string) *CSPMFinding {
		return &CSPMFinding{Title: title, Severity: sev, Category: "storage", Description: desc, Resource: bucket,
			ResourceType: "s3_bucket", MITRE: "T1530",
			Remediation: "Enable all four S3 Block Public Access settings on the bucket (and the account)."}
	}
	switch status {
	case 404:
		return mk("medium", fmt.Sprintf("S3 bucket '%s' has no Block Public Access configuration", bucket),
			"Without Block Public Access, a mistaken ACL or policy can expose the bucket's data."), false
	case 200:
		var c struct {
			A bool `xml:"BlockPublicAcls"`
			B bool `xml:"IgnorePublicAcls"`
			C bool `xml:"BlockPublicPolicy"`
			D bool `xml:"RestrictPublicBuckets"`
		}
		if xml.Unmarshal(body, &c) == nil && !(c.A && c.B && c.C && c.D) {
			return mk("medium", fmt.Sprintf("S3 bucket '%s' has Block Public Access partly disabled", bucket),
				"One or more Block Public Access settings are off."), false
		}
		return nil, true
	}
	return nil, false // access denied / unknown: not assessed
}

// ── CloudTrail ───────────────────────────────────────────────────────────────

func awsTrailFindings(body []byte) []CSPMFinding {
	var r struct {
		Trails []struct {
			Name        string `json:"Name"`
			MultiRegion bool   `json:"IsMultiRegionTrail"`
			Validation  bool   `json:"LogFileValidationEnabled"`
		} `json:"trailList"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil
	}
	multi := false
	var out []CSPMFinding
	for _, t := range r.Trails {
		if t.MultiRegion {
			multi = true
		}
		if !t.Validation {
			out = append(out, CSPMFinding{Title: fmt.Sprintf("CloudTrail '%s' has log file validation disabled", t.Name), Severity: "low", Category: "logging",
				Description: "Without validation, tampering with delivered log files cannot be detected.",
				Resource:    t.Name, ResourceType: "cloudtrail", MITRE: "T1562.008", Remediation: "Enable log file validation."})
		}
	}
	if !multi {
		out = append(out, CSPMFinding{Title: "No multi-region CloudTrail trail", Severity: "high", Category: "logging",
			Description: "Activity in other regions would not be recorded by a single-region trail.",
			Resource:    "account", ResourceType: "cloudtrail", MITRE: "T1562.008",
			Remediation: "Create a multi-region trail delivering to a protected S3 bucket."})
	}
	return out
}

// RunAWSCSPM runs all checks; individual check failures are recorded, not fatal.
func RunAWSCSPM(ctx context.Context, creds awsCreds, accountID string) (*CSPMResult, error) {
	start := time.Now()
	res := &CSPMResult{ProjectID: accountID, ScannedAt: start}
	add := func(f []CSPMFinding) { res.Findings = append(res.Findings, f...) }
	skip := func(check, why string) {
		res.NotAssessed = append(res.NotAssessed, NotAssessedCheck{Check: check, Reason: why})
	}

	iamCreds := creds
	iamCreds.Region = "us-east-1" // IAM is global, signed for us-east-1

	// IAM
	sumB, sumC, err := awsQueryCall(ctx, iamCreds, "iam", "iam.amazonaws.com", "Action=GetAccountSummary&Version=2010-05-08")
	if err != nil || sumC != 200 {
		skip("iam_account", "GetAccountSummary denied or failed — grant iam:GetAccountSummary / SecurityAudit")
	} else {
		polB, polC, perr := awsQueryCall(ctx, iamCreds, "iam", "iam.amazonaws.com", "Action=GetAccountPasswordPolicy&Version=2010-05-08")
		if perr != nil || (polC != 200 && polC != 404) {
			polC = 0
		}
		add(awsIAMFindings(sumB, polC, polB))
		res.Passed++
		runAWSCSPMIAM(ctx, iamCreds, polB, polC, add, skip, &res.Passed)
	}

	// Regional checks (security groups, RDS, EBS defaults) across every enabled
	// region, capped at awsMaxRegions. Falls back to the connector region.
	regions := []string{creds.Region}
	if rb, rc, rerr := awsQueryCall(ctx, creds, "ec2", "ec2."+creds.Region+".amazonaws.com", "Action=DescribeRegions&Version=2016-11-15"); rerr == nil && rc == 200 {
		if rs := awsRegionsFromXML(rb); len(rs) > 0 {
			regions = rs
		}
	} else {
		skip("regions", "DescribeRegions denied or failed — only "+creds.Region+" was scanned")
	}
	if len(regions) > awsMaxRegions {
		regions = regions[:awsMaxRegions]
		skip("regions", fmt.Sprintf("only the first %d regions were scanned", awsMaxRegions))
	}
	// Regions are scanned four at a time; results merge under a mutex.
	var mu sync.Mutex
	var rwg sync.WaitGroup
	rsem := make(chan struct{}, 4)
	for _, region := range regions {
		rwg.Add(1)
		rsem <- struct{}{}
		go func(region string) {
			defer rwg.Done()
			defer func() { <-rsem }()
			rc := creds
			rc.Region = region
			var lf []CSPMFinding
			type sk struct{ c, w string }
			var lsk []sk
			lpassed := 0
			ladd := func(f []CSPMFinding) { lf = append(lf, f...) }
			lskip := func(c, w string) { lsk = append(lsk, sk{c, w}) }
			sgB, sgC, err := awsQueryCall(ctx, rc, "ec2", "ec2."+region+".amazonaws.com", "Action=DescribeSecurityGroups&Version=2016-11-15")
			if err != nil || sgC != 200 {
				lskip("security_groups", "DescribeSecurityGroups denied or failed in "+region)
			} else {
				ladd(awsSGFindings(sgB, region))
				ladd(awsDefaultSGFindings(sgB, region))
				lpassed++
			}
			runAWSCSPMExtra(ctx, rc, ladd, lskip, &lpassed)
			runAWSCSPMRegional(ctx, rc, region == creds.Region, ladd, lskip, &lpassed)
			mu.Lock()
			add(lf)
			for _, x := range lsk {
				skip(x.c, x.w)
			}
			res.Passed += lpassed
			mu.Unlock()
		}(region)
	}
	rwg.Wait()

	// CloudTrail
	body := []byte("{}")
	req, rerr := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("https://cloudtrail.%s.amazonaws.com/", creds.Region), strings.NewReader(string(body)))
	if rerr == nil {
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.DescribeTrails")
		awsSign(req, creds, "cloudtrail", body)
		if resp, derr := awsClient.Do(req); derr == nil {
			tb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			if resp.StatusCode == 200 {
				add(awsTrailFindings(tb))
				res.Passed++
			} else {
				skip("cloudtrail", fmt.Sprintf("DescribeTrails returned %d", resp.StatusCode))
			}
		} else {
			skip("cloudtrail", derr.Error())
		}
	}

	// S3
	lb, lc, err := awsS3Get(ctx, iamCreds, "s3.amazonaws.com", "/")
	if err != nil || lc != 200 {
		skip("s3_public_access", "ListBuckets denied or failed")
	} else {
		var buckets struct {
			Names []string `xml:"Buckets>Bucket>Name"`
		}
		_ = xml.Unmarshal(lb, &buckets)
		if len(buckets.Names) > awsMaxBuckets {
			buckets.Names = buckets.Names[:awsMaxBuckets]
			skip("s3_public_access", fmt.Sprintf("only the first %d buckets were checked", awsMaxBuckets))
		}
		// Bounded concurrency: one signed request per bucket.
		type pabRes struct {
			f  *CSPMFinding
			ok bool
		}
		results := make([]pabRes, len(buckets.Names))
		sem := make(chan struct{}, 8)
		var wg sync.WaitGroup
		for i, b := range buckets.Names {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, b string) {
				defer wg.Done()
				defer func() { <-sem }()
				pb, pc, perr := awsS3Get(ctx, iamCreds, b+".s3.amazonaws.com", "/?publicAccessBlock")
				if perr != nil {
					return
				}
				f, ok := awsS3PABFinding(b, pc, pb)
				results[i] = pabRes{f, ok}
			}(i, b)
		}
		wg.Wait()
		for _, r := range results {
			if r.f != nil {
				add([]CSPMFinding{*r.f})
			} else if r.ok {
				res.Passed++
			}
		}
		runAWSS3Hardening(ctx, iamCreds, buckets.Names, add, skip, &res.Passed)
	}

	for i := range res.Findings {
		f := &res.Findings[i]
		sum := sha256.Sum256([]byte(accountID + "\x00" + f.Title + "\x00" + f.Resource))
		f.ID = "aws-" + hex.EncodeToString(sum[:])[:12]
		f.Status = "open"
		if activeAWSSuppressor != nil && activeAWSSuppressor.ShouldSuppress(*f, accountID) {
			f.Status = "suppressed"
		}
		f.ScannedAt = start
		if f.Status == "suppressed" {
			continue
		}
		switch f.Severity {
		case "critical":
			res.Critical++
		case "high":
			res.High++
		case "medium":
			res.Medium++
		case "low":
			res.Low++
		}
	}
	res.TotalFindings = res.Critical + res.High + res.Medium + res.Low
	res.ScanDuration = time.Since(start).Round(time.Millisecond).String()
	return res, nil
}

func awsS3Get(ctx context.Context, creds awsCreds, host, path string) ([]byte, int, error) {
	u, err := url.Parse("https://" + host + path)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	awsSign(req, creds, "s3", nil)
	resp, err := awsClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return b, resp.StatusCode, nil
}

const (
	awsMaxRegions = 20
	awsMaxBuckets = 500
)

func awsRegionsFromXML(b []byte) []string {
	var r struct {
		Names []string `xml:"regionInfo>item>regionName"`
	}
	if xml.Unmarshal(b, &r) != nil {
		return nil
	}
	return r.Names
}
