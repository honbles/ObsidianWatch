package api

import "testing"

func TestMergeGCPCIS(t *testing.T) {
	a := &CISResult{Controls: []CISControl{{ID: "1.1", Title: "t", Level: 1, Status: "PASS"}, {ID: "1.2", Title: "u", Level: 2, Status: "FAIL"}}}
	b := &CISResult{Controls: []CISControl{{ID: "1.1", Title: "t", Level: 1, Status: "FAIL"}, {ID: "1.3", Title: "v", Level: 1, Status: "UNKNOWN"}}}
	m := mergeGCPCIS([]string{"p1", "p2", "p3"}, []*CISResult{a, b, nil}, map[string]string{"p3": "boom"})
	if m.TotalChecks != 4 || m.Passed != 1 || m.Failed != 2 || m.Unknown != 1 {
		t.Fatalf("%+v", m)
	}
	if m.ScorePercent < 33.3 || m.ScorePercent > 33.4 {
		t.Fatalf("score %v", m.ScorePercent)
	}
	if m.Controls[0].Title != "[p1] t" || len(m.Errors) != 1 {
		t.Fatalf("%+v", m.Controls[0])
	}
	if mergeGCPCIS([]string{"p1"}, []*CISResult{a}, nil) != a {
		t.Fatal("single scope must pass through")
	}
}

func TestMergeAzureCISScoring(t *testing.T) {
	a := &CISAzureResult{Controls: []CISControl{{ID: "1", Level: 1, Status: "PASS"}}, Benchmark: "B"}
	b := &CISAzureResult{Controls: []CISControl{{ID: "1", Level: 1, Status: "PASS"}}}
	m := mergeAzureCIS([]string{"s1", "s2"}, []*CISAzureResult{a, b}, nil)
	if m.ScorePercent != 100 || m.Level1Score != 100 || m.Benchmark != "B" || m.TotalChecks != 2 {
		t.Fatalf("%+v", m)
	}
}
