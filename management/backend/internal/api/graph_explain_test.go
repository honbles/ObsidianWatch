package api

import (
	"context"
	"strings"
	"testing"
)

func TestExplainNodes(t *testing.T) {
	g, err := BuildAlertGraph(context.Background(), chainFixture(), chainInput())
	if err != nil {
		t.Fatal(err)
	}
	ps := nodeByLabel(g, "powershell.exe")
	for _, want := range []string{"Started by cmd.exe", "the process the alert fired on", "203.0.113.7", "curl.exe"} {
		if !strings.Contains(ps.Explain, want) {
			t.Errorf("anchor explain missing %q: %s", want, ps.Explain)
		}
	}
	curl := nodeByLabel(g, "curl.exe")
	if !strings.Contains(curl.Explain, "temp or user-writable") {
		t.Errorf("curl explain: %s", curl.Explain)
	}
	ip := nodeByLabel(g, "203.0.113.7")
	if ip == nil || !strings.Contains(ip.Explain, "public internet address") || !strings.Contains(ip.Explain, "contacted by powershell.exe") {
		t.Errorf("ip explain: %+v", ip)
	}
}

func TestParseGraphAnalysisRejectsInvention(t *testing.T) {
	g, _ := BuildAlertGraph(context.Background(), chainFixture(), chainInput())
	raw := "```json\n" + `{"summary":"s","verdict":"definitely_evil","confidence":"certain",
	 "nodes":{"proc:a1:{PS}":"real node","proc:a1:{INVENTED}":"made up"},"next_steps":["a","b","c","d","e"]}` + "\n```"
	a, err := parseGraphAnalysis(raw, g)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Nodes) != 1 || a.Nodes["proc:a1:{PS}"] == "" {
		t.Errorf("nodes not filtered: %+v", a.Nodes)
	}
	if a.Verdict != "unclear" || a.Confident != "low" || len(a.NextSteps) != 4 {
		t.Errorf("clamp failed: %+v", a)
	}
	if _, err := parseGraphAnalysis("no json here", g); err == nil {
		t.Error("expected error on non-JSON")
	}
}

func TestGraphPromptFencesData(t *testing.T) {
	g, _ := BuildAlertGraph(context.Background(), chainFixture(), chainInput())
	p := buildGraphPrompt(g)
	if !strings.Contains(p, "[UNTRUSTED:nodes]") || !strings.Contains(p, "[UNTRUSTED:edges]") || !strings.Contains(p, "proc:a1:{PS}") {
		t.Errorf("prompt shape wrong")
	}
}
