package api

import "testing"

func TestCSPMForProjectStripsPrefix(t *testing.T) {
	c := &CSPMResult{Findings: []CSPMFinding{{Resource: "p1 / vm1"}, {Resource: "p2 / vm1"}}}
	got := cspmForProject(c, "p2", true)
	if len(got.Findings) != 1 || got.Findings[0].Resource != "vm1" {
		t.Fatalf("%+v", got.Findings)
	}
	if cspmForProject(c, "p2", false) != c {
		t.Fatal("single project must be untouched")
	}
}

func TestMergeBlastNamespacing(t *testing.T) {
	mk := func() *BlastRadiusResult {
		return &BlastRadiusResult{
			Nodes:         []BlastNode{{ID: "vm:a", Risk: "high"}, {ID: "sa:x@p", Risk: "none"}, {ID: "internet:public"}},
			Edges:         []BlastEdge{{From: "internet:public", To: "vm:a"}, {From: "vm:a", To: "sa:x@p"}},
			HighRiskPaths: []BlastPath{{StartNode: "internet:public", Path: []string{"internet:public", "vm:a"}}},
		}
	}
	m := mergeBlast(1, []string{"p1", "p2"}, []*BlastRadiusResult{mk(), mk()}, nil)
	// vm nodes split per project; internet and SA nodes shared.
	if m.Summary.TotalNodes != 4 {
		t.Fatalf("nodes=%d", m.Summary.TotalNodes)
	}
	if m.Summary.HighRiskNodes != 2 || m.Summary.CriticalPaths != 2 {
		t.Fatalf("%+v", m.Summary)
	}
	if m.HighRiskPaths[1].Path[1] != "p2|vm:a" || m.HighRiskPaths[1].Path[0] != "internet:public" {
		t.Fatalf("%+v", m.HighRiskPaths[1])
	}
}

func TestAzureCSPMForSub(t *testing.T) {
	c := &AzureCSPMResult{Findings: []CSPMFinding{{Resource: "s1 / vm"}, {Resource: "s2 / vm"}}}
	g := azureCSPMForSub(c, "s1", true)
	if len(g.Findings) != 1 || g.Findings[0].Resource != "vm" {
		t.Fatalf("%+v", g.Findings)
	}
}
