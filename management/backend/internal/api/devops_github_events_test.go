package api

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestGitHubUserEventsAreKept(t *testing.T) {
	conn := &store.DevOpsConnector{ID: 1, Org: "me"}
	evs := githubUserEventsToEvents([]map[string]interface{}{
		{"id": "1", "type": "PublicEvent", "actor": map[string]interface{}{"login": "me"}, "repo": map[string]interface{}{"name": "me/x"}, "created_at": "2026-01-01T00:00:00Z"},
		{"id": "2", "type": "DeleteEvent", "actor": map[string]interface{}{"login": "me"}, "repo": map[string]interface{}{"name": "me/x"}, "payload": map[string]interface{}{"ref_type": "branch", "ref": "main"}},
		{"id": "3", "type": "WatchEvent"},
	}, conn)
	if len(evs) != 2 || evs[0].Severity != 5 || evs[1].Severity != 4 || evs[1].EventType != "devops.delete_branch" {
		t.Fatalf("unexpected: %+v", evs)
	}
}

func TestGitHubAuditUnratedKept(t *testing.T) {
	conn := &store.DevOpsConnector{ID: 1, Org: "o"}
	evs, _ := githubAuditToEvents([]map[string]interface{}{
		{"action": "repo.destroy", "actor": "a", "repo": "o/r", "created_at": float64(1700000000000)},
		{"action": "project.create", "actor": "a", "created_at": float64(1700000000001)},
		{"action": "git.clone", "actor": "a", "created_at": float64(1700000000002)},
	}, conn)
	if len(evs) != 2 || evs[0].Severity != 5 || evs[1].Severity != 1 {
		t.Fatalf("unexpected: %+v", evs)
	}
}

func TestGitHubWebhookFallback(t *testing.T) {
	ev := processGitHubWebhookEvent("deploy_key", map[string]interface{}{"action": "created"}, nil)
	if len(ev) != 1 || ev[0].Severity != 4 {
		t.Fatalf("deploy_key: %+v", ev)
	}
	if len(processGitHubWebhookEvent("star", map[string]interface{}{}, nil)) != 0 {
		t.Fatal("star should be skipped")
	}
	if len(processGitHubWebhookEvent("some_new_event", map[string]interface{}{}, nil)) != 1 {
		t.Fatal("unknown events must be kept")
	}
}
