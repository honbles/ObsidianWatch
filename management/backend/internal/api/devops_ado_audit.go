package api

// devops_ado_audit.go — DO-11: Azure DevOps audit log and pipeline runs.
// The audit stream needs auditing enabled on the organisation and a PAT with
// the Auditing (read) scope; if it is not available the sync continues with
// the other sources.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// adoAuditSeverity rates an Azure DevOps audit actionId; 0 = not interesting.
func adoAuditSeverity(actionID string) int {
	a := strings.ToLower(actionID)
	switch {
	case containsAny(a, "modifypermission", "removepermission", "projectcollectionadmin", "addmember", "removemember", "grouprenamed"),
		containsAny(a, "serviceconnection"), containsAny(a, "token.pat", "token.ssh", "token.delete"),
		containsAny(a, "policy.policyconfigremoved", "policy.policyconfigmodified", "bypassed", "repositorydeleted", "project.delete",
			"organization.", "extension.", "agentpool", "securefile", "library.variablegroup"):
		return 4
	case containsAny(a, "create", "modif", "delete", "remove", "add", "update", "change"):
		return 2
	}
	return 0
}

func adoAuditToEvents(entries []map[string]interface{}, conn *store.DevOpsConnector) []CloudEvent {
	var out []CloudEvent
	for _, e := range entries {
		action, _ := e["actionId"].(string)
		if action == "" {
			continue
		}
		sev := adoAuditSeverity(action)
		if sev == 0 {
			continue
		}
		ts, _ := e["timestamp"].(string)
		t, _ := time.Parse(time.RFC3339Nano, ts)
		if t.IsZero() {
			t = time.Now()
		}
		actor, _ := e["actorDisplayName"].(string)
		ip, _ := e["ipAddress"].(string)
		id, _ := e["id"].(string)
		if id == "" {
			id = action + "@" + ts
		}
		raw, _ := json.Marshal(e)
		out = append(out, CloudEvent{
			ID: fmt.Sprintf("ado-audit:%d:%s", conn.ID, id), Time: t,
			AgentID: fmt.Sprintf("devops:%d", conn.ID), Host: conn.Org, OS: "devops",
			EventType: "devops.audit", Severity: sev, Source: "azuredevops_audit",
			Username: actor, SrcIP: ip, Raw: raw,
		})
	}
	return out
}

// fetchADOAudit pages the organisation audit log since a time (bounded).
func fetchADOAudit(ctx context.Context, c *azureClient, org string, since time.Time) ([]map[string]interface{}, error) {
	var all []map[string]interface{}
	token := ""
	for page := 0; page < 10; page++ {
		u := fmt.Sprintf("https://auditservice.dev.azure.com/%s/_apis/audit/auditlog?startTime=%s&batchSize=200&api-version=7.1-preview.1",
			url.PathEscape(org), url.QueryEscape(since.UTC().Format(time.RFC3339)))
		if token != "" {
			u += "&continuationToken=" + url.QueryEscape(token)
		}
		var resp struct {
			Entries  []map[string]interface{} `json:"decoratedAuditLogEntries"`
			HasMore  bool                     `json:"hasMore"`
			Continue string                   `json:"continuationToken"`
		}
		if err := c.getJSON(ctx, u, &resp); err != nil {
			return all, err
		}
		all = append(all, resp.Entries...)
		if !resp.HasMore || resp.Continue == "" {
			break
		}
		token = resp.Continue
	}
	return all, nil
}

type adoBuild struct {
	ID           int    `json:"id"`
	BuildNumber  string `json:"buildNumber"`
	Status       string `json:"status"`
	Result       string `json:"result"`
	Reason       string `json:"reason"`
	SourceBranch string `json:"sourceBranch"`
	FinishTime   string `json:"finishTime"`
	QueueTime    string `json:"queueTime"`
	Definition   struct {
		Name string `json:"name"`
	} `json:"definition"`
	Repository struct {
		Name string `json:"name"`
	} `json:"repository"`
	RequestedFor struct {
		DisplayName string `json:"displayName"`
	} `json:"requestedFor"`
}

// adoBuildsToEvents turns pipeline runs into events. Failed runs are rated
// low-medium; runs triggered manually on a non-default pattern stay informational.
func adoBuildsToEvents(builds []adoBuild, project string, conn *store.DevOpsConnector) []CloudEvent {
	var out []CloudEvent
	for _, b := range builds {
		ts := b.FinishTime
		if ts == "" {
			ts = b.QueueTime
		}
		t, _ := time.Parse(time.RFC3339Nano, ts)
		if t.IsZero() {
			t = time.Now()
		}
		sev := 1
		if b.Result == "failed" {
			sev = 2
		}
		raw, _ := json.Marshal(map[string]interface{}{
			"build_id": b.ID, "build_number": b.BuildNumber, "pipeline": b.Definition.Name, "project": project,
			"repo": fmt.Sprintf("%s/%s/%s", conn.Org, project, b.Repository.Name), "branch": strings.TrimPrefix(b.SourceBranch, "refs/heads/"),
			"status": b.Status, "result": b.Result, "reason": b.Reason, "requested_for": b.RequestedFor.DisplayName,
		})
		out = append(out, CloudEvent{
			ID: fmt.Sprintf("ado-build:%d:%s:%d", conn.ID, project, b.ID), Time: t,
			AgentID: fmt.Sprintf("devops:%d", conn.ID), Host: conn.Org, OS: "devops",
			EventType: "devops.pipeline_run", Severity: sev, Source: "azuredevops_build",
			Username: b.RequestedFor.DisplayName, Raw: raw,
		})
	}
	return out
}

func fetchADOBuilds(ctx context.Context, c *azureClient, project string, since time.Time) ([]adoBuild, error) {
	u := fmt.Sprintf("%s/%s/_apis/build/builds?minTime=%s&$top=50&queryOrder=finishTimeDescending&api-version=7.0",
		c.baseURL, url.PathEscape(project), url.QueryEscape(since.UTC().Format(time.RFC3339)))
	var resp struct {
		Value []adoBuild `json:"value"`
	}
	if err := c.getJSON(ctx, u, &resp); err != nil {
		return nil, err
	}
	return resp.Value, nil
}
