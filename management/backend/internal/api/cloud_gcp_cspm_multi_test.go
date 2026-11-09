package api

import "testing"

func TestMergeGCPCSPM(t *testing.T) {
	a := &CSPMResult{Findings: []CSPMFinding{{ID: "x", Resource: "fw1"}}, High: 1, Passed: 3}
	b := &CSPMResult{Findings: []CSPMFinding{{ID: "y", Resource: "fw1"}}, Critical: 1, Passed: 2,
		NotAssessed: []NotAssessedCheck{{Check: "kms", Reason: "r"}}}
	m := mergeGCPCSPM([]string{"p1", "p2", "p3"}, []*CSPMResult{a, b, nil}, map[string]string{"p3": "403"})
	if m.TotalFindings != 2 || m.High != 1 || m.Critical != 1 || m.Passed != 5 {
		t.Fatalf("%+v", m)
	}
	if m.Findings[0].Resource != "p1 / fw1" || m.Findings[1].ID != "y" {
		t.Fatalf("%+v", m.Findings)
	}
	if len(m.Errors) != 1 || len(m.NotAssessed) != 2 {
		t.Fatalf("errs=%v na=%v", m.Errors, m.NotAssessed)
	}
	single := mergeGCPCSPM([]string{"p1"}, []*CSPMResult{a}, nil)
	if single != a {
		t.Fatal("single project result must pass through unchanged")
	}
}
