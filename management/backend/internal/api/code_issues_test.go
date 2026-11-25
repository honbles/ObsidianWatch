package api

import (
	"strings"
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestIssueGrouping(t *testing.T) {
	fs := []SASTFinding{
		{RuleID: "SECRET-aws", Severity: "critical", Title: "Secret in repository history: AWS key", File: "a.py", Line: 3, Fingerprint: "f1"},
		{RuleID: "SECRET-aws", Severity: "high", Title: "Secret in repository history: AWS key", File: "b.py", Line: 9, Fingerprint: "f2"},
		{RuleID: "SCA-CVE-1", Severity: "high", Title: "CVE-1 in lodash 4.17.15", File: "package-lock.json", Ecosystem: "npm", Package: "lodash", Version: "4.17.15", Fingerprint: "f3"},
		{RuleID: "SCA-CVE-2", Severity: "critical", Title: "CVE-2 in lodash 4.17.15", File: "package-lock.json", Ecosystem: "npm", Package: "lodash", Version: "4.17.15", Fingerprint: "f4"},
		{RuleID: "PY-EVAL", Severity: "medium", Title: "eval", File: "c.py", Line: 1, Fingerprint: "f5"},
		{RuleID: "PY-EXEC", Severity: "high", Title: "exec", File: "d.py", Line: 1, Fingerprint: "f6", Triage: &findingTriage{Status: "false_positive"}},
	}
	gs := groupFindings(fs, "high")
	if len(gs) != 2 || gs[0].Count != 2 || gs[1].Count != 2 || gs[0].Severity != "critical" || gs[1].Severity != "critical" {
		t.Fatalf("groups: %+v", gs)
	}
	conn := &store.DevOpsConnector{Provider: "github"}
	body := issueBody(conn, "acme/api", "main", gs[0])
	if !strings.Contains(body, "https://github.com/acme/api/blob/main/a.py#L3") || !strings.Contains(body, "Rotate the credential") {
		t.Fatalf("body: %s", body)
	}
	if len(groupFindings(fs, "critical")) != 2 || len(groupFindings(fs, "medium")) != 3 {
		t.Fatal("severity filter")
	}
}
