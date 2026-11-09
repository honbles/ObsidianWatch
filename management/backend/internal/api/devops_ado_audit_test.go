package api

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestADOAuditSeverityAndEvents(t *testing.T) {
	if adoAuditSeverity("Security.ModifyPermission") != 4 || adoAuditSeverity("Library.ServiceConnectionModified") != 4 || adoAuditSeverity("Token.PatCreateEvent") != 4 {
		t.Fatal("sensitive actions should be high")
	}
	if adoAuditSeverity("Git.RefUpdatePoliciesBypassed") != 4 {
		t.Fatal("policy bypass should be high")
	}
	if adoAuditSeverity("Release.ReleaseCreated") != 2 || adoAuditSeverity("Something.Viewed") != 0 {
		t.Fatal("routine/read actions")
	}
	conn := &store.DevOpsConnector{ID: 5, Org: "acme"}
	ev := adoAuditToEvents([]map[string]interface{}{
		{"id": "a1", "actionId": "Security.ModifyPermission", "timestamp": "2026-11-01T10:00:00Z", "actorDisplayName": "bob", "ipAddress": "8.8.8.8"},
		{"id": "a2", "actionId": "Something.Viewed"}, {"id": "a3"},
	}, conn)
	if len(ev) != 1 || ev[0].Username != "bob" || ev[0].SrcIP != "8.8.8.8" || ev[0].EventType != "devops.audit" {
		t.Fatalf("%+v", ev)
	}
}

func TestADOBuildsToEvents(t *testing.T) {
	conn := &store.DevOpsConnector{ID: 5, Org: "acme"}
	b := adoBuild{ID: 9, Result: "failed", FinishTime: "2026-11-01T10:00:00Z", SourceBranch: "refs/heads/main"}
	b.Definition.Name = "ci"
	b.Repository.Name = "app"
	ev := adoBuildsToEvents([]adoBuild{b, {ID: 10, Result: "succeeded"}}, "proj", conn)
	if len(ev) != 2 || ev[0].Severity != 2 || ev[1].Severity != 1 || ev[0].ID == ev[1].ID {
		t.Fatalf("%+v", ev)
	}
}
