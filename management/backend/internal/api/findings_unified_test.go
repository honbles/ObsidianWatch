package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMergeUnifiedDedupAndSort(t *testing.T) {
	now := time.Now()
	sast := fromSAST(1, now, json.RawMessage(`[{"rule_id":"R1","severity":"HIGH","title":"Hardcoded secret","repo":"o/app","file":"a.go","line":10,"fix":"rotate"},
		{"rule_id":"R2","severity":"low","title":"Weak hash","repo":"o/app","file":"b.go","line":3}]`))
	code := fromCodeScan(1, now, json.RawMessage(`[{"severity":"critical","category":"secret","title":"Hardcoded secret","file":"a.go","line":"10","repo":"o/app"}]`))
	post := fromPosture(1, `{"findings":[{"severity":"medium","title":"No branch protection","detail":"d","resource":"o/app","fix":"enable"}],"scanned_at":"2026-11-01T00:00:00Z"}`)
	got := mergeUnified(append(append(sast, code...), post...))
	if len(got) != 3 {
		t.Fatalf("want 3 after collapsing the duplicate secret finding, got %d: %+v", len(got), got)
	}
	if got[0].Severity != "critical" || len(got[0].Sources) != 2 || got[0].Remediation != "rotate" {
		t.Fatalf("merged finding wrong: %+v", got[0])
	}
	if got[1].Severity != "medium" || got[2].Severity != "low" {
		t.Fatalf("not sorted by severity: %v %v", got[1].Severity, got[2].Severity)
	}
	ids := map[string]bool{}
	for _, f := range got {
		if f.ID == "" || ids[f.ID] {
			t.Fatalf("ids must be set and unique: %+v", got)
		}
		ids[f.ID] = true
	}
}

func TestNormSeverity(t *testing.T) {
	for in, want := range map[string]string{"CRITICAL": "critical", "error": "high", "Warning": "medium", "moderate": "medium", "": "info", "weird": "info"} {
		if normSeverity(in) != want {
			t.Errorf("%q -> %q, want %q", in, normSeverity(in), want)
		}
	}
}
