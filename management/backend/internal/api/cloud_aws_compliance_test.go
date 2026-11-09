package api

import "testing"

func TestAWSFrameworkMapReferencesRealChecks(t *testing.T) {
	known := map[string]bool{}
	for _, d := range awsCISDefs {
		known[d.id] = true
	}
	for _, m := range awsFrameworkMap {
		for _, id := range m.Checks {
			if !known[id] {
				t.Errorf("%s %s references unknown check %s", m.Framework, m.ID, id)
			}
		}
	}
}

func TestAWSComplianceStatuses(t *testing.T) {
	c := &CISAzureResult{}
	for _, d := range awsCISDefs {
		c.Controls = append(c.Controls, CISControl{ID: d.id, Status: "PASS"})
	}
	set := func(id, st string) {
		for i := range c.Controls {
			if c.Controls[i].ID == id {
				c.Controls[i].Status = st
			}
		}
	}
	get := func(rep *ComplianceReport, fw, id string) string {
		for _, x := range rep.Controls {
			if x.Framework == fw && x.ControlID == id {
				return x.Status
			}
		}
		return "?"
	}
	rep := AWSComplianceFromCIS(c, 1, "1")
	if rep.TotalFailed != 0 || rep.TotalNotAssessed != 0 {
		t.Fatalf("all-pass: %+v", rep.Scores)
	}
	set("STO-03", "FAIL") // sole check of SOC2 CC6.7
	set("IAM-02", "FAIL") // one of two for PCI 8.4.2
	set("LOG-05", "UNKNOWN")
	rep = AWSComplianceFromCIS(c, 1, "1")
	if get(rep, "SOC2", "CC6.7") != "FAIL" || get(rep, "PCI-DSS", "8.4.2") != "PARTIAL" || get(rep, "PCI-DSS", "11.5.1") != "NOT_ASSESSED" {
		t.Fatalf("statuses wrong: %v %v %v", get(rep, "SOC2", "CC6.7"), get(rep, "PCI-DSS", "8.4.2"), get(rep, "PCI-DSS", "11.5.1"))
	}
	if len(rep.Scores) != 4 {
		t.Fatalf("want 4 frameworks, got %d", len(rep.Scores))
	}
}
