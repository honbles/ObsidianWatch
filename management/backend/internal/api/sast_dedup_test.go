package api

import "testing"

func TestDeduplicateSASTKeepsAllEngines(t *testing.T) {
	in := []SASTFinding{
		{Engine: "builtin", Repo: "a", RuleID: "r1", File: "x.go", Line: 3},
		{Engine: "builtin", Repo: "a", RuleID: "r1", File: "x.go", Line: 3}, // exact duplicate
		{Engine: "builtin", Repo: "b", RuleID: "r1", File: "x.go", Line: 3}, // other repository
		{Engine: "osv", Repo: "a", RuleID: "GHSA-1", File: "go.mod", Line: 1},
		{Engine: "codeql", Repo: "a", RuleID: "q", File: "y.go", Line: 10}, // before any semgrep: no panic
		{Engine: "semgrep", Repo: "a", RuleID: "s", File: "y.go", Line: 11},
		{Engine: "codeql", Repo: "a", RuleID: "q2", File: "z.go", Line: 5}, // nothing near: kept
	}
	out := deduplicateSASTFindings(in)
	count := map[string]int{}
	for _, f := range out {
		count[f.Engine]++
	}
	if count["builtin"] != 2 || count["osv"] != 1 || count["semgrep+codeql"] != 1 || count["codeql"] != 1 || len(out) != 5 {
		t.Fatalf("unexpected result: %+v", out)
	}
}
