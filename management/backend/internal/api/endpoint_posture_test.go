package api

import (
	"encoding/json"
	"testing"
)

func TestPostureChecksMapsAndFiltersAgentReport(t *testing.T) {
	raw := json.RawMessage(`{"os":"windows","posture":[
		{"id":"EC-W-001","status":"pass"},
		{"id":"EC-W-005","status":"FAIL","detail":"Public profile off"},
		{"id":"EC-W-006","status":"unknown","detail":"needs admin"},
		{"id":"EC-W-099","status":"fail"},
		{"id":"EC-W-002","status":"banana"},
		{"id":"EC-W-005","status":"pass"}]}`)
	got := postureChecks(raw)
	if len(got) != 3 {
		t.Fatalf("expected 3 known checks, got %d: %+v", len(got), got)
	}
	by := map[string]HostCheck{}
	for _, c := range got {
		by[c.ID] = c
	}
	if by["EC-W-005"].Status != "fail" || by["EC-W-005"].Detail != "Public profile off" {
		t.Errorf("duplicate must keep the worst status: %+v", by["EC-W-005"])
	}
	if by["EC-W-001"].Detail != "" || by["EC-W-001"].Fix == "" || by["EC-W-001"].Title == "" {
		t.Errorf("catalog text should come from the backend: %+v", by["EC-W-001"])
	}
	if by["EC-W-006"].Status != "unknown" {
		t.Errorf("unknown must be preserved, not treated as pass: %+v", by["EC-W-006"])
	}
}

func TestEndpointChecksWindowsSkipsLinuxPackageChecks(t *testing.T) {
	raw := json.RawMessage(`{"os":"windows","packages":[{"Name":"Chrome","Version":"1"}],"open_ports":[{"port":3389}],"posture":[]}`)
	for _, c := range endpointChecks(raw) {
		switch c.ID {
		case "HC-001", "HC-003", "HC-004", "HC-005", "HC-009", "HC-011":
			t.Errorf("Linux package check %s must not run on Windows", c.ID)
		}
	}
	found := false
	for _, c := range endpointChecks(raw) {
		if c.ID == "HC-008" && c.Status == "fail" {
			found = true
		}
	}
	if !found {
		t.Error("exposed RDP port should still be flagged on Windows")
	}
}

func TestEndpointChecksLinuxKeepsPackageChecks(t *testing.T) {
	raw := json.RawMessage(`{"os":"linux","packages":[{"Name":"telnetd","Version":"1"}]}`)
	failed := false
	for _, c := range endpointChecks(raw) {
		if c.ID == "HC-001" && c.Status == "fail" {
			failed = true
		}
	}
	if !failed {
		t.Error("legacy package check should still run on Linux")
	}
}

func TestPostureCatalogComplete(t *testing.T) {
	for id, d := range endpointPostureCatalog {
		if d.Title == "" || d.Fix == "" || d.Category == "" || d.OS == "" {
			t.Errorf("%s: incomplete catalog entry", id)
		}
		switch d.Severity {
		case "critical", "high", "medium", "low":
		default:
			t.Errorf("%s: bad severity %q", id, d.Severity)
		}
	}
}
