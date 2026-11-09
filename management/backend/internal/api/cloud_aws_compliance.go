package api

// cloud_aws_compliance.go — framework mapping for AWS, derived from the AWS
// CIS-style benchmark result (not from raw findings, so a check that did not
// run shows NOT_ASSESSED rather than a false pass). The mapping is indicative:
// each framework control lists the benchmark checks that provide evidence for
// its theme. It is not an attestation.

import (
	"sort"
	"strings"
)

type awsFrameworkControl struct {
	Framework, ID, Title string
	Checks               []string
}

var awsFrameworkMap = []awsFrameworkControl{
	// SOC 2
	{"SOC2", "CC6.1", "Logical access and data protection", []string{"IAM-01", "IAM-02", "IAM-06", "IAM-09", "IAM-10", "STO-01", "STO-02", "STO-05", "STO-06", "STO-07", "STO-08"}},
	{"SOC2", "CC6.2", "Credential lifecycle", []string{"IAM-07", "IAM-08"}},
	{"SOC2", "CC6.6", "Network boundary protection", []string{"NET-01", "NET-02", "NET-03"}},
	{"SOC2", "CC6.7", "Protection of data in transit", []string{"STO-03"}},
	{"SOC2", "CC7.1", "Detection of vulnerabilities and threats", []string{"LOG-03", "LOG-05", "LOG-06"}},
	{"SOC2", "CC7.2", "Monitoring of system activity", []string{"LOG-01", "LOG-02", "LOG-04", "LOG-07"}},
	{"SOC2", "A1.2", "Backup and recovery", []string{"STO-04"}},
	// PCI-DSS v4.0
	{"PCI-DSS", "1.3.1", "Inbound traffic restricted", []string{"NET-01", "NET-02", "NET-03"}},
	{"PCI-DSS", "3.5.1", "Stored account data rendered unreadable", []string{"STO-05", "STO-07", "STO-08"}},
	{"PCI-DSS", "4.2.1", "Strong cryptography in transit", []string{"STO-03"}},
	{"PCI-DSS", "7.2.1", "Least-privilege access", []string{"IAM-01", "IAM-09", "IAM-10"}},
	{"PCI-DSS", "8.2.6", "Inactive accounts removed or disabled", []string{"IAM-08"}},
	{"PCI-DSS", "8.3.6", "Minimum password length", []string{"IAM-03"}},
	{"PCI-DSS", "8.3.7", "Password reuse restricted", []string{"IAM-04"}},
	{"PCI-DSS", "8.3.9", "Passwords changed periodically", []string{"IAM-05"}},
	{"PCI-DSS", "8.4.2", "MFA for access", []string{"IAM-02", "IAM-06"}},
	{"PCI-DSS", "10.2.1", "Audit logs enabled", []string{"LOG-01", "LOG-03", "LOG-07"}},
	{"PCI-DSS", "10.3.4", "Audit log integrity", []string{"LOG-02"}},
	{"PCI-DSS", "11.5.1", "Intrusion detection", []string{"LOG-05", "LOG-06"}},
	// ISO 27001:2022
	{"ISO27001", "A.5.15", "Access control", []string{"IAM-01", "IAM-09", "IAM-10"}},
	{"ISO27001", "A.5.17", "Authentication information", []string{"IAM-03", "IAM-04", "IAM-05", "IAM-07"}},
	{"ISO27001", "A.8.3", "Information access restriction", []string{"STO-01", "STO-02", "STO-06"}},
	{"ISO27001", "A.8.5", "Secure authentication", []string{"IAM-02", "IAM-06", "IAM-08"}},
	{"ISO27001", "A.8.13", "Information backup", []string{"STO-04"}},
	{"ISO27001", "A.8.15", "Logging", []string{"LOG-01", "LOG-02", "LOG-03", "LOG-07"}},
	{"ISO27001", "A.8.16", "Monitoring activities", []string{"LOG-04", "LOG-05", "LOG-06"}},
	{"ISO27001", "A.8.20", "Network security", []string{"NET-01", "NET-02", "NET-03"}},
	{"ISO27001", "A.8.24", "Use of cryptography", []string{"STO-03", "STO-05", "STO-07", "STO-08"}},
	// NIST 800-53 R5
	{"NIST-800-53", "AC-2", "Account management", []string{"IAM-07", "IAM-08"}},
	{"NIST-800-53", "AC-3", "Access enforcement", []string{"IAM-09", "IAM-10", "STO-01", "STO-02", "STO-06"}},
	{"NIST-800-53", "AC-6", "Least privilege", []string{"IAM-01", "IAM-09"}},
	{"NIST-800-53", "AU-2", "Event logging", []string{"LOG-01", "LOG-03", "LOG-07"}},
	{"NIST-800-53", "AU-9", "Protection of audit information", []string{"LOG-02"}},
	{"NIST-800-53", "CP-9", "System backup", []string{"STO-04"}},
	{"NIST-800-53", "IA-2", "Identification and authentication (MFA)", []string{"IAM-02", "IAM-06"}},
	{"NIST-800-53", "IA-5", "Authenticator management", []string{"IAM-03", "IAM-04", "IAM-05", "IAM-07"}},
	{"NIST-800-53", "SC-7", "Boundary protection", []string{"NET-01", "NET-02", "NET-03"}},
	{"NIST-800-53", "SC-8", "Transmission confidentiality", []string{"STO-03"}},
	{"NIST-800-53", "SC-28", "Protection of information at rest", []string{"STO-05", "STO-07", "STO-08"}},
	{"NIST-800-53", "SI-4", "System monitoring", []string{"LOG-04", "LOG-05", "LOG-06"}},
}

// AWSComplianceFromCIS maps an AWS benchmark result onto framework controls.
// A control FAILs when every contributing check fails, is PARTIAL when some fail,
// NOT_ASSESSED when nothing failed but a check did not run, otherwise PASS.
func AWSComplianceFromCIS(c *CISAzureResult, connID int64, accountID string) *ComplianceReport {
	rep := &ComplianceReport{ConnectorID: connID, ProjectID: accountID, ScannedAt: c.ScannedAt,
		Disclaimer: "Indicative mapping of the AWS benchmark checks to control themes. Not an audit or attestation of compliance; controls marked NOT_ASSESSED had a check that did not complete."}
	status := map[string]string{}
	for _, ctl := range c.Controls {
		status[ctl.ID] = ctl.Status
	}
	scores := map[string]*FrameworkScore{}
	for _, m := range awsFrameworkMap {
		fails, pass, unk := []string{}, 0, []string{}
		for _, id := range m.Checks {
			switch status[id] {
			case "FAIL":
				fails = append(fails, id)
			case "PASS":
				pass++
			default:
				unk = append(unk, id)
			}
		}
		fs := scores[m.Framework]
		if fs == nil {
			fs = &FrameworkScore{Framework: m.Framework}
			scores[m.Framework] = fs
		}
		fs.Total++
		ctl := ComplianceControl{ControlID: m.ID, Framework: m.Framework, Title: m.Title,
			Description: "Evidence from checks: " + strings.Join(m.Checks, ", ")}
		switch {
		case len(fails) > 0 && pass == 0 && len(unk) == 0:
			ctl.Status, ctl.Reason = "FAIL", "Failing checks: "+strings.Join(fails, ", ")
			fs.Failed++
		case len(fails) > 0:
			ctl.Status, ctl.Reason = "PARTIAL", "Failing checks: "+strings.Join(fails, ", ")
			fs.Partial++
		case len(unk) > 0:
			ctl.Status, ctl.Reason = "NOT_ASSESSED", "Checks not completed: "+strings.Join(unk, ", ")
			fs.NotAssessed++
		default:
			ctl.Status = "PASS"
			fs.Passed++
		}
		rep.Controls = append(rep.Controls, ctl)
	}
	names := make([]string, 0, len(scores))
	for n := range scores {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fs := scores[n]
		if assessed := fs.Total - fs.NotAssessed; assessed > 0 {
			fs.ScorePercent = float64(fs.Passed) / float64(assessed) * 100
		}
		rep.TotalPassed += fs.Passed
		rep.TotalFailed += fs.Failed
		rep.TotalNotAssessed += fs.NotAssessed
		rep.Scores = append(rep.Scores, *fs)
	}
	return rep
}
