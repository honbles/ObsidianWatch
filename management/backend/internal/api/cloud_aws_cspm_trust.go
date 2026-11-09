package api

// cloud_aws_cspm_trust.go — IAM role trust-policy checks.
//   - trust open to any AWS principal ("*") without a condition  → critical
//   - trust granted to another account with no condition at all  → medium
//     (no sts:ExternalId / source constraint: confused-deputy risk)

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/url"
	"regexp"
	"strings"
)

var awsAcctInARN = regexp.MustCompile(`^arn:aws[a-z-]*:iam::(\d{12}):`)

func awsRoleTrustFindings(detailsXML []byte) []CSPMFinding {
	var d struct {
		Roles []struct {
			Name  string `xml:"RoleName"`
			ARN   string `xml:"Arn"`
			Trust string `xml:"AssumeRolePolicyDocument"`
		} `xml:"GetAccountAuthorizationDetailsResult>RoleDetailList>member"`
	}
	if xml.Unmarshal(detailsXML, &d) != nil {
		return nil
	}
	var out []CSPMFinding
	for _, r := range d.Roles {
		own := ""
		if m := awsAcctInARN.FindStringSubmatch(r.ARN); m != nil {
			own = m[1]
		}
		doc, err := url.QueryUnescape(r.Trust)
		if err != nil {
			doc = r.Trust
		}
		var pd struct {
			Statement json.RawMessage `json:"Statement"`
		}
		if json.Unmarshal([]byte(doc), &pd) != nil {
			continue
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
				continue
			}
			list = []stmt{one}
		}
		wild, foreign := false, ""
		for _, s := range list {
			if !strings.EqualFold(s.Effect, "Allow") {
				continue
			}
			hasCond := len(s.Condition) > 0 && string(s.Condition) != "null" && string(s.Condition) != "{}"
			var aws []string
			var str string
			var obj struct {
				AWS json.RawMessage `json:"AWS"`
			}
			if json.Unmarshal(s.Principal, &str) == nil {
				aws = []string{str}
			} else if json.Unmarshal(s.Principal, &obj) == nil && len(obj.AWS) > 0 {
				if json.Unmarshal(obj.AWS, &str) == nil {
					aws = []string{str}
				} else {
					_ = json.Unmarshal(obj.AWS, &aws)
				}
			}
			for _, p := range aws {
				if p == "*" && !hasCond {
					wild = true
				}
				if m := awsAcctInARN.FindStringSubmatch(p); m != nil && own != "" && m[1] != own && !hasCond {
					foreign = m[1]
				} else if len(p) == 12 && own != "" && p != own && !hasCond && strings.Trim(p, "0123456789") == "" {
					foreign = p
				}
			}
		}
		switch {
		case wild:
			out = append(out, CSPMFinding{Title: "IAM role '" + r.Name + "' can be assumed by any AWS principal", Severity: "critical", Category: "iam",
				Resource: r.Name, ResourceType: "iam_role", MITRE: "T1078.004",
				Description: "The trust policy allows Principal \"*\" with no condition, so any AWS account can assume this role.",
				Remediation: "Restrict the trust policy to specific principals and add conditions such as aws:PrincipalOrgID."})
		case foreign != "":
			out = append(out, CSPMFinding{Title: "IAM role '" + r.Name + "' trusts account " + foreign + " without conditions", Severity: "medium", Category: "iam",
				Resource: r.Name, ResourceType: "iam_role", MITRE: "T1199",
				Description: "Cross-account trust with no condition (such as sts:ExternalId) is open to the confused-deputy problem.",
				Remediation: "Require sts:ExternalId or aws:PrincipalOrgID in the trust policy, or remove trust you do not recognise."})
		}
	}
	return out
}

func runAWSRoleTrust(ctx context.Context, iamCreds awsCreds, add func([]CSPMFinding), skip func(string, string), passed *int) {
	marker := ""
	for page := 0; page < 10; page++ {
		form := "Action=GetAccountAuthorizationDetails&Version=2010-05-08&Filter.member.1=Role&MaxItems=100"
		if marker != "" {
			form += "&Marker=" + url.QueryEscape(marker)
		}
		b, c, err := awsQueryCall(ctx, iamCreds, "iam", "iam.amazonaws.com", form)
		if err != nil || c != 200 {
			skip("iam_role_trust", "GetAccountAuthorizationDetails (roles) denied or failed")
			return
		}
		add(awsRoleTrustFindings(b))
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
