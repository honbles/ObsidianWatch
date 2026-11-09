package api

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestGitLabExtraEvents(t *testing.T) {
	conn := &store.DevOpsConnector{ID: 3, Org: "grp"}
	ev := gitlabPipelinesToEvents([]glPipeline{{ID: 1, Status: "failed", UpdatedAt: "2026-11-01T10:00:00Z"}, {ID: 2, Status: "success"}}, "grp/app", conn)
	if len(ev) != 2 || ev[0].Severity != 2 || ev[1].Severity != 1 {
		t.Fatalf("%+v", ev)
	}
	pe := gitlabProjectEventsToEvents([]map[string]interface{}{
		{"id": 1.0, "action_name": "joined", "created_at": "2026-11-01T10:00:00Z", "author": map[string]interface{}{"username": "eve"}},
		{"id": 2.0, "action_name": "pushed to", "target_type": ""},
		{"id": 3.0, "action_name": "created", "target_type": "Issue"},
		{"id": 4.0, "action_name": "destroyed", "target_type": "Project"},
	}, "grp/app", conn)
	if len(pe) != 2 || pe[0].EventType != "devops.member_change" || pe[0].Username != "eve" || pe[1].EventType != "devops.project_destroyed" {
		t.Fatalf("%+v", pe)
	}
}
