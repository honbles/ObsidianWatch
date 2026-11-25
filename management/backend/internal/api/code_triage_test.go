package api

import (
	"strings"
	"testing"
	"time"
)

func TestFingerprintSurvivesLineMoves(t *testing.T) {
	a := SASTFinding{RuleID: "R", File: "app.py", Line: 10, Snippet: "  9: x\n> 10: os.system(cmd)\n  11: y"}
	b := SASTFinding{RuleID: "R", File: "app.py", Line: 42, Snippet: "  41: other\n> 42: os.system(cmd)\n  43: z"}
	c := SASTFinding{RuleID: "R", File: "app.py", Line: 42, Snippet: "> 42: subprocess.call(cmd)"}
	if findingFingerprint(a) != findingFingerprint(b) || findingFingerprint(a) == findingFingerprint(c) {
		t.Fatal("fingerprint must follow the flagged code, not the line number")
	}
	d1 := SASTFinding{RuleID: "SCA-CVE-1", File: "package-lock.json", Package: "lodash", Version: "4.17.15"}
	d2 := d1
	d2.Version = "4.17.21"
	if findingFingerprint(d1) == findingFingerprint(d2) {
		t.Fatal("a different dependency version is a different finding")
	}
}

func TestTriageIndexDecisionsRulesAndHints(t *testing.T) {
	ix := &triageIndex{decisions: map[string]findingTriage{}, byRepo: map[string]*triageStats{},
		byRule: map[string]map[string]int{}, confirmedAnywhere: map[string]int{}}
	decided := SASTFinding{RuleID: "R1", File: "src/a.py", Snippet: "> 1: eval(x)", Repo: "acme/api"}
	ix.decisions["acme/api\x00"+findingFingerprint(decided)] = findingTriage{Status: "false_positive", At: time.Now()}
	ix.rules = []triageRuleRow{{ID: 7, Repo: "", RuleID: "R2", PathPrefix: "tests/", Status: "accepted_risk", Reason: "test code"}}
	ix.byRepo["acme/api\x00R3"] = &triageStats{dismissed: 4, confirmed: 1, dirs: map[string]int{"fixtures/data": 3}}
	ix.byRepo["acme/api\x00R4"] = &triageStats{confirmed: 3, dirs: map[string]int{}}
	ix.byRule["R5"] = map[string]int{"a": 1, "b": 2, "c": 1}

	f1 := decided
	ix.apply(&f1)
	f2 := SASTFinding{RuleID: "R2", File: "tests/test_x.py", Repo: "other/repo"}
	ix.apply(&f2)
	f2b := SASTFinding{RuleID: "R2", File: "src/x.py", Repo: "other/repo"}
	ix.apply(&f2b)
	f3 := SASTFinding{RuleID: "R3", File: "fixtures/data/sample.py", Repo: "acme/api"}
	ix.apply(&f3)
	f4 := SASTFinding{RuleID: "R4", File: "x.go", Repo: "acme/api"}
	ix.apply(&f4)
	f5 := SASTFinding{RuleID: "R5", File: "y.go", Repo: "d"}
	ix.apply(&f5)

	if !findingDismissed(f1) || f1.Triage.Status != "false_positive" {
		t.Fatalf("decision: %+v", f1.Triage)
	}
	if !findingDismissed(f2) || f2.Triage.RuleID != 7 || findingDismissed(f2b) {
		t.Fatalf("rule with path prefix: %+v %+v", f2.Triage, f2b.Triage)
	}
	if f3.TriageHint == nil || f3.TriageHint.Suggestion != "likely_false_positive" || f3.TriageHint.Rule.PathPrefix != "fixtures/data/" || findingDismissed(f3) {
		t.Fatalf("learned hint: %+v", f3.TriageHint)
	}
	if f4.TriageHint == nil || f4.TriageHint.Suggestion != "likely_true_positive" {
		t.Fatalf("confirmed hint: %+v", f4.TriageHint)
	}
	if f5.TriageHint == nil || !strings.Contains(f5.TriageHint.Basis, "3 repositories") || f5.TriageHint.Rule.Repo != "" {
		t.Fatalf("cross-repo hint: %+v", f5.TriageHint)
	}
	kept, hidden := withoutDismissed([]SASTFinding{f1, f2, f2b, f3})
	if hidden != 2 || len(kept) != 2 {
		t.Fatalf("withoutDismissed: %d %d", len(kept), hidden)
	}
}

func TestParseAIFixValidation(t *testing.T) {
	content := "a\nb\nc\nd\ne\n"
	f := SASTFinding{RuleID: "R", File: "x.py", Line: 3}
	_, from, to, lines := codeWindow(content, 3, 3)
	ok, err := parseAIFix("Here: {\"explanation\":\"use safe call\",\"confidence\":85,\"start_line\":3,\"end_line\":3,\"replacement\":\"C\"}", f, lines, from, to)
	if err != nil || ok.Diff != "--- a/x.py\n+++ b/x.py\n@@ -3,1 +3,1 @@\n-c\n+C\n" || ok.Confidence != 85 {
		t.Fatalf("valid: %+v %v", ok, err)
	}
	out, _ := parseAIFix(`{"explanation":"x","start_line":1,"end_line":999,"replacement":"zzz"}`, f, lines, from, to)
	if out.Diff != "" || out.Replacement != "" {
		t.Fatal("a range outside the window must be dropped")
	}
	fp, _ := parseAIFix(`{"explanation":"not reachable","likely_false_positive":true,"false_positive_reason":"constant input","start_line":0,"end_line":0}`, f, lines, from, to)
	if !fp.LikelyFalsePos || fp.Diff != "" {
		t.Fatal("false positive verdict")
	}
	if _, err := parseAIFix("no json here", f, lines, from, to); err == nil {
		t.Fatal("garbage must fail")
	}
}

func TestDependencyFixAndPRBlocks(t *testing.T) {
	d := dependencyFix(SASTFinding{RuleID: "SCA-CVE-1", Ecosystem: "npm", Package: "lodash", Version: "4.17.15", File: "package-lock.json", Fix: "Upgrade lodash to 4.17.21 or later."})
	if d.Command != "npm install lodash@4.17.21" {
		t.Fatalf("npm: %+v", d)
	}
	if c := packageUpgradeCommand("Go", "golang.org/x/net", "0.23.0", "go.mod"); c != "go get golang.org/x/net@v0.23.0 && go mod tidy" {
		t.Fatal(c)
	}
	f := SASTFinding{Line: 5}
	one := &fixSuggestion{Kind: "code", StartLine: 5, EndLine: 5, Replacement: "safe()", Diff: "x", Confidence: 80}
	if b := fixBlock(f, "github", one); !strings.Contains(b, "```suggestion\nsafe()\n```") {
		t.Fatalf("github suggestion: %q", b)
	}
	if b := fixBlock(f, "gitlab", one); !strings.Contains(b, "```suggestion:-0+0") {
		t.Fatalf("gitlab suggestion: %q", b)
	}
	if b := fixBlock(f, "azuredevops", one); !strings.Contains(b, "```diff") {
		t.Fatalf("ado diff: %q", b)
	}
}
