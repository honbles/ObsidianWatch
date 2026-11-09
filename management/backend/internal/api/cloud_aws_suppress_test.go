package api

import (
	"testing"
	"time"
)

func TestAWSSuppressMatching(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	s := &AWSSuppressor{rules: []AWSSuppressRule{
		{ID: 1, Resource: "legacy-", Category: "storage", Reason: "x"},
		{ID: 2, FindingTitle: "mfa", AccountID: "111", Reason: "x"},
		{ID: 3, Severity: "low", ExpiresAt: &past, Reason: "expired"},
	}}
	if !s.ShouldSuppress(CSPMFinding{Resource: "legacy-bucket", Category: "storage"}, "1") {
		t.Fatal("prefix+category rule should match")
	}
	if s.ShouldSuppress(CSPMFinding{Resource: "legacy-bucket", Category: "iam"}, "1") {
		t.Fatal("category mismatch must not match")
	}
	if !s.ShouldSuppress(CSPMFinding{Title: "Root MFA missing"}, "111") || s.ShouldSuppress(CSPMFinding{Title: "Root MFA missing"}, "222") {
		t.Fatal("account scoping broken")
	}
	if s.ShouldSuppress(CSPMFinding{Severity: "low"}, "1") {
		t.Fatal("expired rule must not apply")
	}
}
