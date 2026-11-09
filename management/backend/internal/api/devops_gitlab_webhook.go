package api

// DO-11: GitLab webhook route. GitLab authenticates deliveries with a shared
// token header (X-Gitlab-Token) rather than an HMAC, so it is compared in
// constant time and the route fails closed when no secret is configured.

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

const gitlabZeroSHA = "0000000000000000000000000000000000000000"

func processGitLabWebhookEvent(payload map[string]interface{}, conn *store.DevOpsConnector, now time.Time) []CloudEvent {
	str := func(m map[string]interface{}, k string) string {
		if m == nil {
			return ""
		}
		s, _ := m[k].(string)
		return s
	}
	kind := str(payload, "object_kind")
	if kind == "" {
		kind = str(payload, "event_name")
	}
	org, connID := "", int64(0)
	if conn != nil {
		org, connID = conn.Org, conn.ID
	}
	project, _ := payload["project"].(map[string]interface{})
	repo := str(project, "path_with_namespace")
	if repo == "" {
		repo = str(payload, "project_path_with_namespace")
	}
	if repo == "" {
		repo = str(payload, "path_with_namespace")
	}
	actor := str(payload, "user_username")
	if actor == "" {
		actor = str(payload, "user_login")
	}
	if actor == "" {
		if u, ok := payload["user"].(map[string]interface{}); ok {
			actor = str(u, "username")
		}
	}

	mk := func(eventType string, sev int, raw map[string]interface{}) CloudEvent {
		b, _ := json.Marshal(raw)
		return CloudEvent{
			ID:   fmt.Sprintf("gl-wh:%s:%s:%d", eventType, actor, now.UnixNano()),
			Time: now, AgentID: fmt.Sprintf("devops:%d", connID), Host: org, OS: "devops",
			EventType: eventType, Severity: sev, Source: "gitlab_webhook", Username: actor, Raw: b,
		}
	}

	switch kind {
	case "push", "tag_push":
		ref := str(payload, "ref")
		branch := strings.TrimPrefix(strings.TrimPrefix(ref, "refs/heads/"), "refs/tags/")
		commits, _ := payload["commits"].([]interface{})
		deleted := str(payload, "after") == gitlabZeroSHA
		created := str(payload, "before") == gitlabZeroSHA
		sev := 1
		if deleted && isProtectedBranch(branch) {
			sev = 4
		} else if deleted {
			sev = 2
		}
		return []CloudEvent{mk("devops.push", sev, map[string]interface{}{
			"event": "push", "ref": ref, "branch": branch, "pusher": actor, "repo": repo,
			"commits": len(commits), "deleted": deleted, "created": created,
		})}
	case "project_create", "project_destroy", "project_transfer", "project_rename", "project_update":
		action := strings.TrimPrefix(kind, "project_")
		sev := 2
		if action == "destroy" || action == "transfer" {
			sev = 4
		}
		name := action
		if action == "destroy" {
			name = "deleted" // match the GitHub-derived rule names (repo_deleted)
		}
		return []CloudEvent{mk("devops.repo_"+name, sev, map[string]interface{}{
			"event": "repository." + name, "repo": repo, "actor": actor, "owner": str(payload, "owner_name")})}
	case "user_add_to_team", "user_remove_from_team", "user_update_for_team",
		"user_add_to_group", "user_remove_from_group", "user_update_for_group":
		action := "added"
		sev := 4
		switch {
		case strings.Contains(kind, "remove"):
			action, sev = "removed", 3
		case strings.Contains(kind, "update"):
			action, sev = "updated", 3
		}
		member := str(payload, "user_username")
		raw := map[string]interface{}{
			"event": "member." + action, "actor": actor, "member": member, "repo": repo,
			"role": strings.ToLower(str(payload, "project_access")) + strings.ToLower(str(payload, "group_access")),
		}
		return []CloudEvent{mk("devops.member_"+action, sev, raw)}
	case "merge_request":
		attrs, _ := payload["object_attributes"].(map[string]interface{})
		action := str(attrs, "action")
		if action != "merge" {
			return nil
		}
		return []CloudEvent{mk("devops.merge", 1, map[string]interface{}{
			"event": "merge", "repo": repo, "actor": actor,
			"branch": str(attrs, "target_branch"), "source_branch": str(attrs, "source_branch"),
		})}
	case "pipeline":
		attrs, _ := payload["object_attributes"].(map[string]interface{})
		return []CloudEvent{mk("devops.workflow_run", 1, map[string]interface{}{
			"event": "workflow_run", "repo": repo, "actor": actor,
			"conclusion": str(attrs, "status"), "branch": str(attrs, "ref"),
		})}
	}
	return nil
}

func handleGitLabWebhook(db *store.DB, eventDB *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if !webhookLimiter.Allow(idStr) {
			http.Error(w, "rate limited", 429)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read error", 400)
			return
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "unknown connector", 404)
			return
		}
		conn, err := db.GetDevOpsConnectorRaw(r.Context(), id)
		if err != nil || conn == nil || conn.Provider != "gitlab" {
			http.Error(w, "unknown connector", 404)
			return
		}
		if conn.WebhookSecret == "" {
			logger.Warn("gitlab webhook: no secret configured", "connector", idStr)
			http.Error(w, "webhook secret not configured", 401)
			return
		}
		tok := r.Header.Get("X-Gitlab-Token")
		if tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(conn.WebhookSecret)) != 1 {
			logger.Warn("gitlab webhook: invalid token", "connector", idStr)
			http.Error(w, "invalid token", 401)
			return
		}
		var payload map[string]interface{}
		if json.Unmarshal(body, &payload) != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		// Replay protection: GitLab sends a unique Idempotency-Key / X-Gitlab-Event-UUID.
		delivery := r.Header.Get("X-Gitlab-Event-UUID")
		if delivery == "" {
			delivery = r.Header.Get("Idempotency-Key")
		}
		if delivery != "" && webhookDeliverySeen(idStr+":"+delivery) {
			w.WriteHeader(204)
			return
		}
		events := processGitLabWebhookEvent(payload, conn, time.Now())
		if delivery != "" {
			for i := range events {
				events[i].ID = fmt.Sprintf("gl-wh:%s:%d", delivery, i)
			}
		}
		if len(events) > 0 {
			ingestCloudEvents(r.Context(), eventDB, events)
		}
		w.WriteHeader(204)
	}
}
