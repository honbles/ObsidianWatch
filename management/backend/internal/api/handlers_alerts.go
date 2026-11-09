package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/notify"
	"obsidianwatch/management/internal/store"
)

func handleListAlerts(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")
		host := r.URL.Query().Get("host")
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

		// If host filter provided, use the host-specific query
		if host != "" {
			since := time.Now().AddDate(0, 0, -30) // last 30 days
			alerts, err := db.ListAlertsForHost(r.Context(), host, since)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": "query failed"})
				return
			}
			writeJSON(w, 200, map[string]interface{}{"alerts": alerts, "counts": nil})
			return
		}

		alerts, err := db.ListAlerts(r.Context(), status, limit)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		counts, _ := db.CountAlertsByStatus(r.Context())
		writeJSON(w, 200, map[string]interface{}{"alerts": alerts, "counts": counts})
	}
}

func handleCreateAlert(db *store.DB, mailer *notify.Mailer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		var body struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Severity    int    `json:"severity"`
			AgentID     string `json:"agent_id"`
			Host        string `json:"host"`
			EventType   string `json:"event_type"`
			EventID     string `json:"event_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if body.Title == "" {
			writeJSON(w, 400, map[string]string{"error": "title required"})
			return
		}
		if body.Severity < 1 || body.Severity > 5 {
			body.Severity = 3
		}
		id, err := db.CreateAlert(r.Context(), store.Alert{
			Title: body.Title, Description: body.Description, Severity: body.Severity,
			AgentID: body.AgentID, Host: body.Host, EventType: body.EventType, EventID: body.EventID,
		})
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to create alert"})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "create_alert", fmt.Sprintf("alert:%d", id), body.Title, clientIP(r))
		if mailer.Enabled() {
			mailer.QueueAlert(store.Alert{
				ID: id, Title: body.Title, Description: body.Description,
				Severity: body.Severity, Host: body.Host, EventType: body.EventType,
				Status: "open",
			})
		}
		writeJSON(w, 201, map[string]interface{}{"id": id, "status": "created"})
	}
}

func handleAcknowledgeAlert(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		claims := auth.GetClaims(r)
		if err := db.AcknowledgeAlert(r.Context(), id, claims.Username); err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "ack_alert", fmt.Sprintf("alert:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "acknowledged"})
	}
}

func handleCloseAlert(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		claims := auth.GetClaims(r)
		if err := db.CloseAlert(r.Context(), id, claims.Username); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "close_alert", fmt.Sprintf("alert:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "closed"})
	}
}

// ── Alert Rules ───────────────────────────────────────────────────────────────

func handleListAlertRules(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := db.ListAlertRules(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"rules": rules})
	}
}

func handleCreateAlertRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		var rule store.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if rule.Name == "" {
			writeJSON(w, 400, map[string]string{"error": "name required"})
			return
		}
		if err := validateRule(&rule); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		rule.CreatedBy = claims.Username
		id, err := db.CreateAlertRule(r.Context(), rule)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to create rule"})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "create_alert_rule", fmt.Sprintf("rule:%d", id), rule.Name, clientIP(r))
		writeJSON(w, 201, map[string]interface{}{"id": id})
	}
}

func handleUpdateAlertRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		var rule store.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		rule.ID = id
		if err := validateRule(&rule); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := db.UpdateAlertRule(r.Context(), rule); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to update rule"})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "update_alert_rule", fmt.Sprintf("rule:%d", id), rule.Name, clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "updated"})
	}
}

func handleDeleteAlertRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		if err := db.DeleteAlertRule(r.Context(), id); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to delete rule"})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "delete_alert_rule", fmt.Sprintf("rule:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}

// ── Users ─────────────────────────────────────────────────────────────────────

func handleGetAlert(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		alert, err := db.GetAlert(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "alert not found"})
			return
		}
		// Fetch related event using source_event_id (the actual event UUID)
		// Fall back to event_id for backwards compatibility with old alerts
		var relatedEvent *store.Event
		lookupID := alert.SourceEventID
		if lookupID == "" {
			// Legacy: try event_id only if it doesn't look like a dedup key
			if alert.EventID != "" &&
				!strings.HasPrefix(alert.EventID, "sig:") &&
				!strings.HasPrefix(alert.EventID, "ioc:") &&
				!strings.HasPrefix(alert.EventID, "rule:") {
				lookupID = alert.EventID
			}
		}
		if lookupID != "" {
			if ev, err := db.GetEventByID(r.Context(), lookupID); err == nil {
				relatedEvent = ev
			}
		}
		// Fallback for old alerts: find the closest matching event by host + event_type near alert creation time
		if relatedEvent == nil && alert.Host != "" {
			since := alert.CreatedAt.Add(-2 * time.Minute)
			until := alert.CreatedAt.Add(2 * time.Minute)
			events, _, _ := db.QueryEvents(r.Context(), store.EventFilter{
				Host:      alert.Host,
				EventType: alert.EventType,
				Since:     since,
				Until:     until,
				Limit:     1,
			})
			if len(events) > 0 {
				relatedEvent = &events[0]
			}
		}
		writeJSON(w, 200, map[string]interface{}{
			"alert":         alert,
			"related_event": relatedEvent,
		})
	}
}

// ── SMTP Settings ─────────────────────────────────────────────────────────────

func handleAssignAlert(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		var body struct {
			AssignedTo string `json:"assigned_to"`
			Notes      string `json:"notes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		claims := auth.GetClaims(r)
		if err := db.AssignAlert(r.Context(), id, body.AssignedTo, claims.Username, body.Notes); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "assign_alert", strconv.FormatInt(id, 10), "assigned to "+body.AssignedTo, clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "acknowledged"})
	}
}

func handleUpdateCaseNotes(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		var body struct {
			Notes string `json:"notes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if err := db.UpdateCaseNotes(r.Context(), id, body.Notes); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func handleCloseWithReview(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		var body struct {
			Comment string `json:"comment"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		claims := auth.GetClaims(r)
		if err := db.CloseAlertWithReview(r.Context(), id, claims.Username, body.Comment); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "close_alert", strconv.FormatInt(id, 10), body.Comment, clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "closed"})
	}
}
