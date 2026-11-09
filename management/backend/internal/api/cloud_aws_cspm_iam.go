package api

// AW-10: per-user IAM posture from the IAM credential report, a deeper
// password-policy check and over-permissive customer-managed policies.

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type awsCredRow map[string]string

func parseAWSCredentialReport(b []byte) []awsCredRow {
	r := csv.NewReader(strings.NewReader(string(b)))
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil || len(recs) < 2 {
		return nil
	}
	head := recs[0]
	var out []awsCredRow
	for _, rec := range recs[1:] {
		row := awsCredRow{}
		for i, h := range head {
			if i < len(rec) {
				row[h] = rec[i]
			}
		}
		out = append(out, row)
	}
	return out
}

func awsDaysSince(ts string, now time.Time) (int, bool) {
	switch ts {
	case "", "N/A", "no_information", "not_supported":
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0, false
	}
	return int(now.Sub(t).Hours() / 24), true
}

func awsCredReportFindings(rows []awsCredRow, now time.Time) ([]CSPMFinding, int) {
	var out []CSPMFinding
	passed := 0
	for _, r := range rows {
		user := r["user"]
		if user == "" || user == "<root_account>" {
			continue
		}
		bad := false
		add := func(title, sev, desc, rem string) {
			bad = true
			out = append(out, CSPMFinding{Title: title, Severity: sev, Category: "iam", Resource: user,
				ResourceType: "iam_user", Description: desc, Remediation: rem, MITRE: "T1078.004"})
		}
		if r["password_enabled"] == "true" && r["mfa_active"] != "true" {
			add(fmt.Sprintf("IAM user '%s' has a console password but no MFA", user), "high",
				"A console user without MFA can be taken over with only a stolen or guessed password.",
				"Enrol an MFA device for the user or remove console access.")
		}
		if r["password_enabled"] == "true" {
			if d, ok := awsDaysSince(r["password_last_used"], now); ok && d > 90 {
				add(fmt.Sprintf("IAM user '%s' has not signed in for %d days", user, d), "low",
					"Dormant console credentials widen the attack surface.", "Disable or remove unused console access.")
			}
		}
		for _, n := range []string{"1", "2"} {
			if r["access_key_"+n+"_active"] != "true" {
				continue
			}
			if d, ok := awsDaysSince(r["access_key_"+n+"_last_rotated"], now); ok && d > 90 {
				add(fmt.Sprintf("IAM user '%s' access key %s is %d days old", user, n, d), "medium",
					"Long-lived access keys increase the window in which a leaked key stays useful.",
					"Rotate access keys at least every 90 days, or move to roles with temporary credentials.")
			}
			if d, ok := awsDaysSince(r["access_key_"+n+"_last_used_date"], now); ok && d > 45 {
				add(fmt.Sprintf("IAM user '%s' access key %s unused for %d days", user, n, d), "low",
					"An active but unused key is a standing credential nobody is watching.", "Deactivate or delete unused access keys.")
			} else if !ok {
				if age, aok := awsDaysSince(r["access_key_"+n+"_last_rotated"], now); aok && age > 45 {
					add(fmt.Sprintf("IAM user '%s' access key %s has never been used", user, n), "low",
						"An active key that has never been used is an unnecessary credential.", "Delete the key if it is not needed.")
				}
			}
		}
		if !bad {
			passed++
		}
	}
	return out, passed
}

// awsPasswordPolicyExtraFindings covers reuse prevention and maximum age
// (minimum length is already checked in awsIAMFindings).
func awsPasswordPolicyExtraFindings(policyXML []byte) []CSPMFinding {
	var p struct {
		Reuse  int  `xml:"GetAccountPasswordPolicyResult>PasswordPolicy>PasswordReusePrevention"`
		MaxAge int  `xml:"GetAccountPasswordPolicyResult>PasswordPolicy>MaxPasswordAge"`
		Expire bool `xml:"GetAccountPasswordPolicyResult>PasswordPolicy>ExpirePasswords"`
	}
	if xml.Unmarshal(policyXML, &p) != nil {
		return nil
	}
	var out []CSPMFinding
	if p.Reuse < 24 {
		out = append(out, CSPMFinding{Title: "IAM password policy does not prevent reuse of the last 24 passwords", Severity: "low",
			Category: "iam", Resource: "account", ResourceType: "iam_password_policy", MITRE: "T1110",
			Description: "Users can cycle back to old passwords.", Remediation: "Set password reuse prevention to 24."})
	}
	if !p.Expire || p.MaxAge == 0 || p.MaxAge > 90 {
		out = append(out, CSPMFinding{Title: "IAM password policy does not expire passwords within 90 days", Severity: "low",
			Category: "iam", Resource: "account", ResourceType: "iam_password_policy", MITRE: "T1110",
			Description: "Passwords never expire or live longer than 90 days.", Remediation: "Set the maximum password age to 90 days or less."})
	}
	return out
}

// awsAdminPolicyFindings inspects customer-managed policies from
// GetAccountAuthorizationDetails (documents are URL-encoded JSON) and flags
// any that allow all actions on all resources.
func awsAdminPolicyFindings(detailsXML []byte) []CSPMFinding {
	var d struct {
		Policies []struct {
			Name     string `xml:"PolicyName"`
			Attached int    `xml:"AttachmentCount"`
			Versions []struct {
				Doc     string `xml:"Document"`
				Default bool   `xml:"IsDefaultVersion"`
			} `xml:"PolicyVersionList>member"`
		} `xml:"GetAccountAuthorizationDetailsResult>Policies>member"`
	}
	if xml.Unmarshal(detailsXML, &d) != nil {
		return nil
	}
	var out []CSPMFinding
	for _, p := range d.Policies {
		for _, v := range p.Versions {
			if !v.Default {
				continue
			}
			doc, err := url.QueryUnescape(v.Doc)
			if err != nil {
				doc = v.Doc
			}
			if awsPolicyAllowsAll(doc) {
				sev := "medium"
				if p.Attached > 0 {
					sev = "high"
				}
				out = append(out, CSPMFinding{Title: fmt.Sprintf("Customer-managed policy '%s' allows all actions on all resources", p.Name),
					Severity: sev, Category: "iam", Resource: p.Name, ResourceType: "iam_policy", MITRE: "T1098",
					Description: "A policy granting \"*:*\" is equivalent to full administrator access for anything it is attached to.",
					Remediation: "Replace the wildcard with the specific actions and resources the workload needs."})
			}
		}
	}
	return out
}

func awsPolicyAllowsAll(doc string) bool {
	var pd struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &pd) != nil {
		return false
	}
	type stmt struct {
		Effect   string          `json:"Effect"`
		Action   json.RawMessage `json:"Action"`
		Resource json.RawMessage `json:"Resource"`
	}
	var list []stmt
	if json.Unmarshal(pd.Statement, &list) != nil {
		var one stmt
		if json.Unmarshal(pd.Statement, &one) != nil {
			return false
		}
		list = []stmt{one}
	}
	hasStar := func(raw json.RawMessage) bool {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s == "*"
		}
		var a []string
		if json.Unmarshal(raw, &a) == nil {
			for _, x := range a {
				if x == "*" {
					return true
				}
			}
		}
		return false
	}
	for _, s := range list {
		if strings.EqualFold(s.Effect, "Allow") && hasStar(s.Action) && hasStar(s.Resource) {
			return true
		}
	}
	return false
}

// runAWSCSPMIAM runs the extra IAM checks; failures are recorded, not fatal.
func runAWSCSPMIAM(ctx context.Context, iamCreds awsCreds, policyBody []byte, policyCode int, add func([]CSPMFinding), skip func(string, string), passed *int) {
	if policyCode == 200 {
		add(awsPasswordPolicyExtraFindings(policyBody))
	}
	// Credential report: request generation, poll until complete.
	var report []byte
	for i := 0; i < 8 && report == nil; i++ {
		gb, gc, err := awsQueryCall(ctx, iamCreds, "iam", "iam.amazonaws.com", "Action=GenerateCredentialReport&Version=2010-05-08")
		if err != nil || gc != 200 {
			skip("iam_credential_report", "GenerateCredentialReport denied or failed — grant iam:GenerateCredentialReport / SecurityAudit")
			break
		}
		var st struct {
			State string `xml:"GenerateCredentialReportResult>State"`
		}
		_ = xml.Unmarshal(gb, &st)
		if st.State == "COMPLETE" {
			rb, rc, rerr := awsQueryCall(ctx, iamCreds, "iam", "iam.amazonaws.com", "Action=GetCredentialReport&Version=2010-05-08")
			if rerr != nil || rc != 200 {
				skip("iam_credential_report", "GetCredentialReport denied or failed")
				break
			}
			var c struct {
				Content string `xml:"GetCredentialReportResult>Content"`
			}
			if xml.Unmarshal(rb, &c) == nil {
				if dec, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(c.Content)); derr == nil {
					report = dec
				}
			}
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(1500 * time.Millisecond):
		}
	}
	if report != nil {
		f, p := awsCredReportFindings(parseAWSCredentialReport(report), time.Now())
		add(f)
		*passed += p
	}
	runAWSRoleTrust(ctx, iamCreds, add, skip, passed)
	// Over-permissive customer-managed policies (paged).
	marker := ""
	for page := 0; page < 5; page++ {
		form := "Action=GetAccountAuthorizationDetails&Version=2010-05-08&Filter.member.1=LocalManagedPolicy&MaxItems=100"
		if marker != "" {
			form += "&Marker=" + url.QueryEscape(marker)
		}
		b, c, err := awsQueryCall(ctx, iamCreds, "iam", "iam.amazonaws.com", form)
		if err != nil || c != 200 {
			skip("iam_policies", "GetAccountAuthorizationDetails denied or failed — grant iam:GetAccountAuthorizationDetails / SecurityAudit")
			return
		}
		add(awsAdminPolicyFindings(b))
		var t struct {
			Trunc  bool   `xml:"GetAccountAuthorizationDetailsResult>IsTruncated"`
			Marker string `xml:"GetAccountAuthorizationDetailsResult>Marker"`
		}
		if xml.Unmarshal(b, &t) != nil || !t.Trunc || t.Marker == "" {
			break
		}
		marker = t.Marker
	}
	*passed++
}
