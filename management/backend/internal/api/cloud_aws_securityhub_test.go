package api

import (
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestSecurityHubEventAndSig(t *testing.T) {
	f := securityHubFinding{ID: "arn:f/1", ProductName: "Inspector", Title: "CVE", Region: "eu-west-1", UpdatedAt: "2026-11-07T08:00:00Z"}
	f.Severity.Label = "critical"
	f.Resources = append(f.Resources, struct {
		Type string `json:"Type"`
		ID   string `json:"Id"`
	}{"AwsEc2Instance", "i-1"})
	ev := securityHubToCloudEvent(f, 7)
	if ev.EventType != "cloud.securityhub" || ev.Host != "i-1" || ev.Severity != cloudSevCritical || !strings.HasSuffix(ev.ID, "@2026-11-07T08:00:00Z") {
		t.Fatalf("event: %+v", ev)
	}
	se := store.Event{EventType: ev.EventType, Raw: ev.Raw}
	hit := map[string]bool{}
	for _, set := range everySigSets() {
		for _, sig := range set {
			if sig.Match(se) {
				hit[sig.ID] = true
			}
		}
	}
	if !hit["C-AWS-048"] || hit["C-AWS-049"] {
		t.Fatalf("sig hits: %v", hit)
	}
}

func TestSecurityHubFiltersExcludeGuardDuty(t *testing.T) {
	fl := securityHubFilters(time.Now().Add(-time.Hour), time.Now())
	pn := fl["ProductName"].([]map[string]string)
	if pn[0]["Comparison"] != "NOT_EQUALS" || pn[0]["Value"] != "GuardDuty" {
		t.Fatal("GuardDuty must be excluded to avoid double ingestion")
	}
}
