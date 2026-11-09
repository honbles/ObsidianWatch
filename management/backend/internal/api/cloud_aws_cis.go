package api

// AW-10: AWS "CIS-inspired" benchmark. Each control is evaluated from the CSPM
// result: FAIL when a matching finding exists, UNKNOWN when the check that
// would have produced it could not run, otherwise PASS. Control IDs are our own
// (the topics follow the CIS AWS Foundations Benchmark, whose numbering we do
// not reproduce) and coverage is stated explicitly in the result.

import (
	"fmt"
	"strings"
	"time"
)

type awsCISDef struct {
	id, section, title, desc, remediation, mitre string
	level                                        int
	checks                                       []string // CSPM check names whose NotAssessed entry makes this UNKNOWN
	match                                        func(CSPMFinding) bool
}

func titleHas(subs ...string) func(CSPMFinding) bool {
	return func(f CSPMFinding) bool {
		for _, s := range subs {
			if strings.Contains(f.Title, s) {
				return true
			}
		}
		return false
	}
}

var awsCISDefs = []awsCISDef{
	{"IAM-01", "IAM", "No access keys for the root account", "Root access keys give unrestricted programmatic access.", "Delete root access keys.", "T1078.004", 1,
		[]string{"iam_account"}, titleHas("Root account has active access keys")},
	{"IAM-02", "IAM", "MFA enabled for the root account", "The root user must be protected by MFA.", "Enable hardware or virtual MFA for root.", "T1078.004", 1,
		[]string{"iam_account"}, titleHas("Root account has no MFA")},
	{"IAM-03", "IAM", "Password policy requires at least 14 characters", "Short passwords weaken console authentication.", "Set a minimum length of 14.", "T1110", 1,
		[]string{"iam_account"}, titleHas("No IAM account password policy", "IAM password policy minimum length")},
	{"IAM-04", "IAM", "Password policy prevents reuse of the last 24 passwords", "Reuse lets users cycle back to old passwords.", "Set reuse prevention to 24.", "T1110", 1,
		[]string{"iam_account"}, titleHas("does not prevent reuse")},
	{"IAM-05", "IAM", "Passwords expire within 90 days", "Non-expiring passwords stay useful after leaks.", "Set maximum password age to 90 days.", "T1110", 1,
		[]string{"iam_account"}, titleHas("does not expire passwords")},
	{"IAM-06", "IAM", "MFA enabled for every console user", "Console users without MFA can be taken over with a password alone.", "Enrol MFA or remove console access.", "T1078.004", 1,
		[]string{"iam_credential_report"}, titleHas("console password but no MFA")},
	{"IAM-07", "IAM", "Access keys rotated within 90 days", "Old keys widen the window for leaked credentials.", "Rotate keys every 90 days or use roles.", "T1078.004", 1,
		[]string{"iam_credential_report"}, titleHas("access key 1 is", "access key 2 is")},
	{"IAM-08", "IAM", "Unused credentials disabled (45 days)", "Dormant credentials are unmonitored standing access.", "Disable or delete unused passwords and keys.", "T1078.004", 1,
		[]string{"iam_credential_report"}, titleHas("has not signed in for", "unused for", "has never been used")},
	{"IAM-09", "IAM", "No customer-managed policy grants *:*", "A wildcard policy is full administrator access.", "Scope policies to required actions and resources.", "T1098", 1,
		[]string{"iam_policies"}, titleHas("allows all actions on all resources")},
	{"IAM-10", "IAM", "No role trust policy is open to any principal or unconstrained other accounts", "An open trust policy lets outsiders assume the role.", "Restrict trusted principals and add ExternalId / PrincipalOrgID conditions.", "T1078.004", 1,
		[]string{"iam_role_trust"}, titleHas("can be assumed by any AWS principal", "without conditions")},
	{"STO-01", "Storage", "S3 Block Public Access enabled on every bucket", "A mistaken ACL or policy can otherwise expose data.", "Enable all four Block Public Access settings.", "T1530", 1,
		[]string{"s3_public_access"}, titleHas("Block Public Access")},
	{"STO-02", "Storage", "No S3 bucket is public through policy or ACL", "Public buckets expose data to the internet.", "Remove public principals and ACL grants.", "T1530", 1,
		[]string{"s3_hardening"}, titleHas("allows public access", "ACL grants access to everyone")},
	{"STO-03", "Storage", "S3 buckets require TLS", "Without a deny on aws:SecureTransport, plain HTTP is accepted.", "Add a TLS-only deny statement.", "T1040", 2,
		[]string{"s3_hardening"}, titleHas("policy does not require TLS")},
	{"STO-04", "Storage", "S3 versioning enabled", "Versioning allows recovery from overwrite or deletion.", "Enable versioning.", "T1485", 2,
		[]string{"s3_hardening"}, titleHas("does not have versioning enabled")},
	{"STO-05", "Storage", "EBS encryption by default in every region", "Unencrypted volumes expose data at rest.", "Enable EBS encryption by default.", "T1530", 2,
		[]string{"ebs_default_encryption"}, titleHas("EBS encryption by default is disabled")},
	{"STO-06", "Storage", "No public EBS snapshots", "Public snapshots can be copied by anyone.", "Make snapshots private.", "T1530", 1,
		[]string{"ebs_public_snapshots"}, titleHas("is public")},
	{"STO-07", "Storage", "RDS instances encrypted and not public", "Public or unencrypted databases are high risk.", "Disable public access and enable encryption.", "T1190", 1,
		[]string{"rds"}, titleHas("RDS instance is publicly accessible", "RDS storage is not encrypted")},
	{"STO-08", "Storage", "KMS customer-managed keys rotate", "Keys without rotation stay valid indefinitely.", "Enable automatic rotation.", "T1552", 2,
		[]string{"kms_rotation"}, titleHas("has rotation disabled")},
	{"LOG-01", "Logging", "A multi-region CloudTrail trail exists", "Without it, activity in some regions is not recorded.", "Create a multi-region trail.", "T1562.008", 1,
		[]string{"cloudtrail"}, titleHas("No multi-region CloudTrail trail")},
	{"LOG-02", "Logging", "CloudTrail log file validation enabled", "Validation detects tampering with delivered logs.", "Enable log file validation.", "T1070", 2,
		[]string{"cloudtrail"}, titleHas("log file validation disabled")},
	{"LOG-03", "Logging", "AWS Config recorder enabled in every region", "No history of configuration changes otherwise.", "Create a configuration recorder.", "T1562.008", 2,
		[]string{"config_recorder"}, titleHas("AWS Config recorder is not set up")},
	{"LOG-04", "Logging", "VPC flow logs enabled", "Network traffic is otherwise not recorded.", "Create flow logs for each VPC.", "T1562.008", 2,
		[]string{"vpc_flow_logs"}, titleHas("has no flow logs")},
	{"LOG-05", "Logging", "GuardDuty enabled in every region", "Managed threat detection is off otherwise.", "Enable GuardDuty.", "T1562.001", 2,
		[]string{"guardduty"}, titleHas("GuardDuty is not enabled")},
	{"LOG-06", "Logging", "Security Hub enabled", "No aggregated findings or control checks otherwise.", "Enable Security Hub.", "T1562.001", 2,
		[]string{"security_hub"}, titleHas("Security Hub is not enabled")},
	{"LOG-07", "Logging", "S3 server access logging enabled", "Object access is not recorded otherwise.", "Enable access logging or CloudTrail data events.", "T1562.008", 2,
		[]string{"s3_hardening"}, titleHas("no server access logging")},
	{"NET-01", "Network", "No security group allows all traffic from the internet", "An open group exposes everything attached to it.", "Restrict ingress.", "T1190", 1,
		[]string{"security_groups"}, titleHas("allows all traffic from the internet")},
	{"NET-02", "Network", "No security group exposes admin or wide port ranges to the internet", "SSH/RDP and wide ranges are common entry points.", "Limit sources or use SSM.", "T1190", 1,
		[]string{"security_groups"}, titleHas("exposes port")},
	{"NET-03", "Network", "Default security groups allow no traffic", "Resources inherit the default group.", "Remove all rules from default groups.", "T1021", 2,
		[]string{"security_groups"}, titleHas("Default security group")},
}

// AWSCISFromCSPM evaluates the CIS-inspired controls against a CSPM result.
func AWSCISFromCSPM(c *CSPMResult, accountID string, connID int64) *CISAzureResult {
	out := &CISAzureResult{ConnectorID: connID, SubscriptionID: accountID, ScannedAt: time.Now().UTC()}
	notAssessed := map[string]string{}
	for _, n := range c.NotAssessed {
		notAssessed[n.Check] = n.Reason
	}
	for _, d := range awsCISDefs {
		ctl := CISControl{ID: d.id, Section: d.section, Title: d.title, Description: d.desc, Level: d.level,
			Remediation: d.remediation, MITRE: d.mitre, Status: "PASS", Evidence: "No matching findings"}
		var hits []string
		for _, f := range c.Findings {
			if f.Status == "suppressed" {
				continue
			}
			if d.match(f) {
				hits = append(hits, f.Resource)
			}
		}
		if len(hits) > 0 {
			ctl.Status = "FAIL"
			show := hits
			if len(show) > 5 {
				show = show[:5]
			}
			ctl.Evidence = fmt.Sprintf("%d finding(s): %s", len(hits), strings.Join(show, ", "))
			if len(hits) > 5 {
				ctl.Evidence += fmt.Sprintf(" (+%d more)", len(hits)-5)
			}
		} else {
			for _, ch := range d.checks {
				if why, ok := notAssessed[ch]; ok {
					ctl.Status = "UNKNOWN"
					ctl.Evidence = "Not assessed: " + why
					break
				}
			}
		}
		out.Controls = append(out.Controls, ctl)
	}
	t := tallyCIS(out.Controls)
	out.TotalChecks, out.Passed, out.Failed, out.Unknown = t.total, t.passed, t.failed, t.unknown
	out.ScorePercent, out.Level1Score, out.Level2Score = t.score, t.l1, t.l2
	out.Errors = c.Errors
	out.Benchmark = "AWS security benchmark (CIS AWS Foundations topics, subset)"
	out.ControlsImplemented = len(out.Controls)
	out.CoverageNote = fmt.Sprintf("%d automated controls drawn from the CIS AWS Foundations Benchmark topics; control IDs are our own and the full benchmark is not covered. UNKNOWN controls could not be evaluated with the permissions granted. Not a CIS certification result.", len(out.Controls))
	return out
}
