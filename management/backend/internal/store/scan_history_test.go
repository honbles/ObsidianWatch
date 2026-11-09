package store

import "testing"

func TestParseCSPMKeyAndPoint(t *testing.T) {
	if p, id, ok := parseCSPMKey("cspm:aws:12"); !ok || p != "aws" || id != 12 {
		t.Fatal("valid key rejected")
	}
	for _, bad := range []string{"cis:aws:1", "cspm:aws", "cspm::1", "cspm:aws:x", "cspm:aws:1:2"} {
		if _, _, ok := parseCSPMKey(bad); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
	pt, ok := scanPointFromJSON(`{"critical":2,"high":3,"medium":4,"low":5,"passed":6,"total_findings":14,"findings":[]}`)
	if !ok || pt.Critical != 2 || pt.Passed != 6 || pt.Total != 14 {
		t.Fatalf("%+v", pt)
	}
	if _, ok := scanPointFromJSON("not json"); ok {
		t.Fatal("bad json accepted")
	}
}
