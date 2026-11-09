package api

// DO-11: Azure DevOps service-hook route. Service hooks can send HTTP Basic
// credentials or a custom header; this route accepts either the Basic
// password or an X-Webhook-Token header, compared in constant time, and fails
// closed when no secret is configured. Handled events: git.push,
// git.pullrequest.merged, build.complete and pipeline run-state changes.

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

const adoZeroSHA = "0000000000000000000000000000000000000000"

func processADOWebhookEvent(payload map[string]interface{}, conn *store.DevOpsConnector, now time.Time) []CloudEvent {
	obj := func(m map[string]interface{}, k string) map[string]interface{} {
		if m == nil {
			return nil
		}
		o, _ := m[k].(map[string]interface{})
		return o
	}
	str := func(m map[string]interface{}, k string) string {
		if m == nil {
			return ""
		}
		s, _ := m[k].(string)
		return s
	}
	kind := str(payload, "eventType")
	res := obj(payload, "resource")
	org, connID := "", int64(0)
	if conn != nil {
		org, connID = conn.Org, conn.ID
	}
	repo := str(obj(res, "repository"), "name")
	actor := str(obj(res, "pushedBy"), "uniqueName")
	if actor == "" {
		actor = str(obj(res, "requestedFor"), "uniqueName")
	}
	if actor == "" {
		actor = str(obj(res, "closedBy"), "uniqueName")
	}
	mk := func(eventType string, sev int, raw map[string]interface{}) CloudEvent {
		b, _ := json.Marshal(raw)
		return CloudEvent{
			ID:   fmt.Sprintf("ado-wh:%s:%s:%d", eventType, actor, now.UnixNano()),
			Time: now, AgentID: fmt.Sprintf("devops:%d", connID), Host: org, OS: "devops",
			EventType: eventType, Severity: sev, Source: "azuredevops_webhook", Username: actor, Raw: b,
		}
	}
	switch kind {
	case "git.push":
		var out []CloudEvent
		updates, _ := res["refUpdates"].([]interface{})
		for _, u := range updates {
			ru, _ := u.(map[string]interface{})
			ref := str(ru, "name")
			branch := strings.TrimPrefix(strings.TrimPrefix(ref, "refs/heads/"), "refs/tags/")
			deleted := str(ru, "newObjectId") == adoZeroSHA
			created := str(ru, "oldObjectId") == adoZeroSHA
			sev := 1
			if deleted && isProtectedBranch(branch) {
				sev = 4
			} else if deleted {
				sev = 2
			}
			commits, _ := res["commits"].([]interface{})
			out = append(out, mk("devops.push", sev, map[string]interface{}{
				"event": "push", "ref": ref, "branch": branch, "pusher": actor, "repo": repo,
				"commits": len(commits), "deleted": deleted, "created": created,
			}))
		}
		return out
	case "git.pullrequest.merged":
		return []CloudEvent{mk("devops.merge", 1, map[string]interface{}{
			"event": "merge", "repo": repo, "actor": actor,
			"branch":        strings.TrimPrefix(str(res, "targetRefName"), "refs/heads/"),
			"source_branch": strings.TrimPrefix(str(res, "sourceRefName"), "refs/heads/"),
		})}
	case "build.complete", "ms.vss-pipelines.run-state-changed-event":
		concl := str(res, "result")
		if concl == "" {
			concl = str(res, "state")
		}
		def := str(obj(res, "definition"), "name")
		if def == "" {
			def = str(obj(res, "pipeline"), "name")
		}
		return []CloudEvent{mk("devops.workflow_run", 1, map[string]interface{}{
			"event": "workflow_run", "repo": repo, "actor": actor, "conclusion": concl, "workflow": def,
		})}
	}
	return nil
}

func adoWebhookToken(r *http.Request) string {
	if t := r.Header.Get("X-Webhook-Token"); t != "" {
		return t
	}
	if _, pw, ok := r.BasicAuth(); ok {
		return pw
	}
	return ""
}

func handleADOWebhook(db *store.DB, eventDB *store.DB, logger *slog.Logger) http.HandlerFunc {
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
		if err != nil || conn == nil || conn.Provider != "azuredevops" {
			http.Error(w, "unknown connector", 404)
			return
		}
		if conn.WebhookSecret == "" {
			logger.Warn("ado webhook: no secret configured", "connector", idStr)
			http.Error(w, "webhook secret not configured", 401)
			return
		}
		tok := adoWebhookToken(r)
		if tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(conn.WebhookSecret)) != 1 {
			logger.Warn("ado webhook: invalid token", "connector", idStr)
			http.Error(w, "invalid token", 401)
			return
		}
		var payload map[string]interface{}
		if json.Unmarshal(body, &payload) != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		delivery, _ := payload["id"].(string) // service hooks carry a notification id
		if delivery != "" && webhookDeliverySeen(idStr+":"+delivery) {
			w.WriteHeader(204)
			return
		}
		events := processADOWebhookEvent(payload, conn, time.Now())
		if delivery != "" {
			for i := range events {
				events[i].ID = fmt.Sprintf("ado-wh:%s:%d", delivery, i)
			}
		}
		if len(events) > 0 {
			ingestCloudEvents(r.Context(), eventDB, events)
		}
		w.WriteHeader(204)
	}
}
