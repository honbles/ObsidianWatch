package api

import "testing"

func TestAWSCISFromCSPM(t *testing.T) {
	c := &CSPMResult{
		Findings: []CSPMFinding{
			{Title: "Root account has no MFA", Resource: "root"},
			{Title: "S3 bucket 'a' has no Block Public Access configuration", Resource: "a"},
			{Title: "S3 bucket 'b' has Block Public Access partly disabled", Resource: "b"},
		},
		NotAssessed: []NotAssessedCheck{{Check: "kms_rotation", Reason: "denied"}},
	}
	r := AWSCISFromCSPM(c, "123", 7)
	byID := map[string]CISControl{}
	for _, x := range r.Controls {
		byID[x.ID] = x
	}
	if byID["IAM-02"].Status != "FAIL" || byID["STO-01"].Status != "FAIL" {
		t.Fatalf("expected FAILs: %+v %+v", byID["IAM-02"], byID["STO-01"])
	}
	if byID["STO-08"].Status != "UNKNOWN" {
		t.Fatalf("kms not assessed should be UNKNOWN: %+v", byID["STO-08"])
	}
	if byID["IAM-01"].Status != "PASS" {
		t.Fatalf("IAM-01 should pass: %+v", byID["IAM-01"])
	}
	if r.Failed != 2 || r.Unknown != 1 || r.TotalChecks != len(awsCISDefs) || r.ConnectorID != 7 {
		t.Fatalf("%+v", r)
	}
	seen := map[string]bool{}
	for _, d := range awsCISDefs {
		if seen[d.id] || d.match == nil || len(d.checks) == 0 {
			t.Fatalf("bad def %s", d.id)
		}
		seen[d.id] = true
	}
}
