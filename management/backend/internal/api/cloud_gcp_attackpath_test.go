package api

import "testing"

func TestLinkSAIdentitiesEnablesAttackPath(t *testing.T) {
	n := func(id, typ string) *BlastNode { return &BlastNode{ID: id, Name: id, Type: typ, Risk: "none"} }
	nodes := map[string]*BlastNode{
		"internet:public":                  n("internet:public", "internet"),
		"vm:web":                           n("vm:web", "vm"),
		"sa:app@p.iam.gserviceaccount.com": n("sa:app@p.iam.gserviceaccount.com", "service_account"),
		"principal:serviceAccount:app@p.iam.gserviceaccount.com": n("principal:serviceAccount:app@p.iam.gserviceaccount.com", "service_account"),
		"role:roles/owner": n("role:roles/owner", "iam_role"),
	}
	edges := []*BlastEdge{
		{From: "internet:public", To: "vm:web", Relationship: "can_reach", RiskBoost: true},
		{From: "vm:web", To: "sa:app@p.iam.gserviceaccount.com", Relationship: "uses_sa", RiskBoost: true},
		{From: "principal:serviceAccount:app@p.iam.gserviceaccount.com", To: "role:roles/owner", Relationship: "has_role", RiskBoost: true},
	}
	if p := traceHighRiskPaths(nodes, edges); len(p) != 0 {
		t.Fatalf("unlinked graph should have no owner path, got %d", len(p))
	}
	added := linkSAIdentities(nodes, edges)
	if len(added) != 1 {
		t.Fatalf("want 1 identity edge, got %d", len(added))
	}
	if again := linkSAIdentities(nodes, append(edges, added...)); len(again) != 0 {
		t.Fatal("linking must be idempotent")
	}
	paths := traceHighRiskPaths(nodes, append(edges, added...))
	found := false
	for _, p := range paths {
		if p.EndPrivilege == "project_owner_or_editor" && p.StartNode == "internet:public" && len(p.Path) == 5 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected internet->vm->sa->principal->owner path, got %+v", paths)
	}
}

func TestTracePathsSeverityOrdered(t *testing.T) {
	n := func(id, typ, risk string) *BlastNode { return &BlastNode{ID: id, Name: id, Type: typ, Risk: risk} }
	nodes := map[string]*BlastNode{
		"internet:public":  n("internet:public", "internet", "none"),
		"secret:s":         n("secret:s", "secret", "none"),
		"role:roles/owner": n("role:roles/owner", "iam_role", "critical"),
	}
	edges := []*BlastEdge{
		{From: "internet:public", To: "secret:s", Relationship: "x", RiskBoost: true},
		{From: "internet:public", To: "role:roles/owner", Relationship: "has_role", RiskBoost: true},
	}
	p := traceHighRiskPaths(nodes, edges)
	if len(p) != 2 || p[0].Severity != "critical" {
		t.Fatalf("critical path must sort first: %+v", p)
	}
}
