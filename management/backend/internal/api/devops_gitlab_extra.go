package api

// devops_gitlab_extra.go — DO-11: GitLab pipeline runs and project events that
// work on every tier. Group audit events need Premium; project events do not,
// so membership changes and project create/destroy are still seen without it.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type glPipeline struct {
	ID        int    `json:"id"`
	Status    string `json:"status"`
	Source    string `json:"source"`
	Ref       string `json:"ref"`
	SHA       string `json:"sha"`
	UpdatedAt string `json:"updated_at"`
	WebURL    string `json:"web_url"`
}

func gitlabPipelinesToEvents(ps []glPipeline, project string, conn *store.DevOpsConnector) []CloudEvent {
	var out []CloudEvent
	for _, p := range ps {
		t, _ := time.Parse(time.RFC3339Nano, p.UpdatedAt)
		if t.IsZero() {
			t = time.Now()
		}
		sev := 1
		if p.Status == "failed" {
			sev = 2
		}
		raw, _ := json.Marshal(map[string]interface{}{
			"pipeline_id": p.ID, "repo": project, "ref": p.Ref, "sha": p.SHA,
			"status": p.Status, "source": p.Source, "url": p.WebURL,
		})
		out = append(out, CloudEvent{
			ID: fmt.Sprintf("gl-pipeline:%d:%d:%s", conn.ID, p.ID, p.Status), Time: t,
			AgentID: fmt.Sprintf("devops:%d", conn.ID), Host: conn.Org, OS: "devops",
			EventType: "devops.pipeline_run", Severity: sev, Source: "gitlab_pipeline", Raw: raw,
		})
	}
	return out
}

// gitlabProjectEventsToEvents keeps membership and lifecycle events; routine
// pushes are already covered by the commit sync.
func gitlabProjectEventsToEvents(es []map[string]interface{}, project string, conn *store.DevOpsConnector) []CloudEvent {
	var out []CloudEvent
	for _, e := range es {
		action, _ := e["action_name"].(string)
		a := strings.ToLower(action)
		typ, sev := "", 0
		switch {
		case a == "joined" || a == "left" || a == "expired" || a == "removed":
			typ, sev = "devops.member_change", 3
		case a == "created" || a == "destroyed":
			if tt, _ := e["target_type"].(string); tt == "" || strings.EqualFold(tt, "project") {
				typ, sev = "devops.project_"+a, 3
			}
		}
		if typ == "" {
			continue
		}
		ts, _ := e["created_at"].(string)
		t, _ := time.Parse(time.RFC3339Nano, ts)
		if t.IsZero() {
			t = time.Now()
		}
		author := ""
		if au, ok := e["author"].(map[string]interface{}); ok {
			author, _ = au["username"].(string)
		}
		id := fmt.Sprint(e["id"])
		e["repo"] = project
		raw, _ := json.Marshal(e)
		out = append(out, CloudEvent{
			ID: fmt.Sprintf("gl-event:%d:%s", conn.ID, id), Time: t,
			AgentID: fmt.Sprintf("devops:%d", conn.ID), Host: conn.Org, OS: "devops",
			EventType: typ, Severity: sev, Source: "gitlab_events", Username: author, Raw: raw,
		})
	}
	return out
}
