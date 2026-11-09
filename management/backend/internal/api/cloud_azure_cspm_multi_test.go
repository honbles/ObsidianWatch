package api

import "testing"

func TestMergeAzureCSPM(t *testing.T) {
	a := &AzureCSPMResult{Findings: []CSPMFinding{{ID: "a", Resource: "vm1"}}, High: 1, Passed: 2, DefenderFindings: 1}
	b := &AzureCSPMResult{Findings: []CSPMFinding{{ID: "b", Resource: "vm1"}}, Medium: 1, DefenderEnabled: true}
	m := mergeAzureCSPM([]string{"s1", "s2", "s3"}, []*AzureCSPMResult{a, b, nil}, map[string]string{"s3": "denied"})
	if m.TotalFindings != 2 || m.High != 1 || m.Medium != 1 || m.Passed != 2 || !m.DefenderEnabled || m.DefenderFindings != 1 {
		t.Fatalf("%+v", m)
	}
	if m.Findings[1].Resource != "s2 / vm1" || len(m.Errors) != 1 || len(m.NotAssessed) != 1 {
		t.Fatalf("%+v", m)
	}
	if mergeAzureCSPM([]string{"s1"}, []*AzureCSPMResult{a}, nil) != a {
		t.Fatal("single sub must pass through")
	}
}
