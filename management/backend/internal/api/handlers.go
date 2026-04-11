package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/notify"
	"obsidianwatch/management/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return r.RemoteAddr
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func handleLogin(db *store.DB, jwt *auth.JWTService, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		user, hash, err := db.GetUserByUsername(r.Context(), body.Username)
		if err != nil || !store.CheckPassword(hash, body.Password) {
			writeJSON(w, 401, map[string]string{"error": "invalid credentials"})
			return
		}
		token, err := jwt.Sign(user.ID, user.Username, user.Role)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "token generation failed"})
			return
		}
		db.UpdateLastLogin(r.Context(), user.ID)
		db.WriteAudit(r.Context(), user.Username, "login", "", "", clientIP(r))
		logger.Info("auth: login", "user", user.Username)
		writeJSON(w, 200, map[string]interface{}{
			"token":                   token,
			"user":                    user,
			"require_password_change": !user.PasswordChanged,
		})
	}
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	writeJSON(w, 200, map[string]interface{}{
		"user_id":  claims.UserID,
		"username": claims.Username,
		"role":     claims.Role,
	})
}

func handleChangePassword(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		var body struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if len(body.NewPassword) < 8 {
			writeJSON(w, 400, map[string]string{"error": "new password must be at least 8 characters"})
			return
		}
		_, hash, err := db.GetUserByUsername(r.Context(), claims.Username)
		if err != nil || !store.CheckPassword(hash, body.CurrentPassword) {
			writeJSON(w, 401, map[string]string{"error": "current password is incorrect"})
			return
		}
		if err := db.ChangePassword(r.Context(), claims.UserID, body.NewPassword); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to update password"})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "change_password", "", "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

// ── Events ────────────────────────────────────────────────────────────────────

func handleListEvents(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f := parseEventFilter(r)
		events, total, err := db.QueryEvents(r.Context(), f)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"events": events,
			"total":  total,
			"limit":  f.Limit,
			"offset": f.Offset,
		})
	}
}

func handleGetEvent(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			writeJSON(w, 400, map[string]string{"error": "missing id"})
			return
		}
		event, err := db.GetEventByID(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "event not found"})
			return
		}
		related, _ := db.RelatedEvents(r.Context(), event.Host, event.Time, id)
		writeJSON(w, 200, map[string]interface{}{
			"event":   event,
			"related": related,
		})
	}
}

func handleExportEvents(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f := parseEventFilter(r)
		f.Limit = 10000
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "csv"
		}
		events, err := db.ExportEvents(r.Context(), f)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "export failed"})
			return
		}
		if format == "json" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="obsidianwatch-events-%s.json"`, time.Now().Format("20060102-150405")))
			json.NewEncoder(w).Encode(events)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="obsidianwatch-events-%s.csv"`, time.Now().Format("20060102-150405")))
		cw := csv.NewWriter(w)
		cw.Write([]string{"time", "severity", "host", "os", "event_type", "source", "user_name", "process_name", "command_line", "src_ip", "src_port", "dst_ip", "dst_port", "proto"})
		for _, e := range events {
			cw.Write([]string{
				e.Time.Format(time.RFC3339), strconv.Itoa(e.Severity),
				e.Host, e.OS, e.EventType, e.Source,
				strPtr(e.UserName), strPtr(e.ProcessName), strPtr(e.CommandLine),
				strPtr(e.SrcIP), intPtr(e.SrcPort), strPtr(e.DstIP), intPtr(e.DstPort), strPtr(e.Proto),
			})
		}
		cw.Flush()
	}
}

func strPtr(s *string) string {
	if s == nil { return "" }
	return *s
}
func intPtr(i *int) string {
	if i == nil { return "" }
	return strconv.Itoa(*i)
}

func parseEventFilter(r *http.Request) store.EventFilter {
	q := r.URL.Query()
	f := store.EventFilter{
		AgentID:     q.Get("agent_id"),
		Host:        q.Get("host"),
		OS:          q.Get("os"),
		EventType:   q.Get("event_type"),
		SrcIP:       q.Get("src_ip"),
		DstIP:       q.Get("dst_ip"),
		SrcOrDstIP:  q.Get("src_or_dst_ip"),
		Proto:       q.Get("proto"),
		UserName:    q.Get("user_name"),
		ProcessName: q.Get("process_name"),
		CommandLine: q.Get("command_line"),
		ImagePath:   q.Get("image_path"),
		FilePath:    q.Get("file_path"),
		RegKey:      q.Get("reg_key"),
		Channel:     q.Get("channel"),
		Source:      q.Get("source"),
		Search:      q.Get("search"),
	}
	if s := q.Get("severity");  s != "" { f.Severity, _  = strconv.Atoi(s) }
	if s := q.Get("dst_port");  s != "" { f.DstPort, _   = strconv.Atoi(s) }
	if s := q.Get("src_port");  s != "" { f.SrcPort, _   = strconv.Atoi(s) }
	if s := q.Get("event_id");  s != "" { v, _ := strconv.ParseUint(s, 10, 32); f.EventID = uint32(v) }
	if s := q.Get("since");     s != "" { f.Since, _     = time.Parse(time.RFC3339, s) }
	if s := q.Get("until");     s != "" { f.Until, _     = time.Parse(time.RFC3339, s) }
	if s := q.Get("limit");     s != "" { f.Limit, _     = strconv.Atoi(s) }
	if s := q.Get("offset");    s != "" { f.Offset, _    = strconv.Atoi(s) }
	// all_time=1 searches full history; otherwise default to last 24h
	if q.Get("all_time") != "1" && f.Since.IsZero() && f.Until.IsZero() {
		f.Since = time.Now().Add(-24 * time.Hour)
	}
	return f
}

// ── Agents ────────────────────────────────────────────────────────────────────

func handleListAgents(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agents, err := db.ListAgents(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"agents": agents, "count": len(agents)})
	}
}

func handleGetAgent(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		agents, err := db.ListAgents(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		for _, a := range agents {
			if a.ID == id {
				f := store.EventFilter{AgentID: id, Since: time.Now().Add(-24 * time.Hour), Limit: 100}
				events, total, _ := db.QueryEvents(r.Context(), f)
				writeJSON(w, 200, map[string]interface{}{"agent": a, "recent_events": events, "event_total": total})
				return
			}
		}
		writeJSON(w, 404, map[string]string{"error": "agent not found"})
	}
}

// ── Alerts ────────────────────────────────────────────────────────────────────

func handleListAlerts(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")
		host   := r.URL.Query().Get("host")
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
		if body.Severity < 1 || body.Severity > 5 { body.Severity = 3 }
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
			go mailer.SendAlert(store.Alert{
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
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		claims := auth.GetClaims(r)
		if err := db.AcknowledgeAlert(r.Context(), id, claims.Username); err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()}); return
		}
		db.WriteAudit(r.Context(), claims.Username, "ack_alert", fmt.Sprintf("alert:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "acknowledged"})
	}
}

func handleCloseAlert(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		claims := auth.GetClaims(r)
		if err := db.CloseAlert(r.Context(), id, claims.Username); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()}); return
		}
		db.WriteAudit(r.Context(), claims.Username, "close_alert", fmt.Sprintf("alert:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "closed"})
	}
}

// ── Alert Rules ───────────────────────────────────────────────────────────────

func handleListAlertRules(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := db.ListAlertRules(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": "query failed"}); return }
		writeJSON(w, 200, map[string]interface{}{"rules": rules})
	}
}

func handleCreateAlertRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		var rule store.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"}); return
		}
		if rule.Name == "" { writeJSON(w, 400, map[string]string{"error": "name required"}); return }
		rule.CreatedBy = claims.Username
		id, err := db.CreateAlertRule(r.Context(), rule)
		if err != nil { writeJSON(w, 500, map[string]string{"error": "failed to create rule"}); return }
		db.WriteAudit(r.Context(), claims.Username, "create_alert_rule", fmt.Sprintf("rule:%d", id), rule.Name, clientIP(r))
		writeJSON(w, 201, map[string]interface{}{"id": id})
	}
}

func handleUpdateAlertRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		var rule store.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"}); return
		}
		rule.ID = id
		if err := db.UpdateAlertRule(r.Context(), rule); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to update rule"}); return
		}
		db.WriteAudit(r.Context(), claims.Username, "update_alert_rule", fmt.Sprintf("rule:%d", id), rule.Name, clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "updated"})
	}
}

func handleDeleteAlertRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		if err := db.DeleteAlertRule(r.Context(), id); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to delete rule"}); return
		}
		db.WriteAudit(r.Context(), claims.Username, "delete_alert_rule", fmt.Sprintf("rule:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}

// ── Users ─────────────────────────────────────────────────────────────────────

func handleListUsers(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := db.ListUsers(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": "query failed"}); return }
		writeJSON(w, 200, map[string]interface{}{"users": users})
	}
}

func handleCreateUser(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		if claims.Role != "admin" { writeJSON(w, 403, map[string]string{"error": "admin only"}); return }
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"}); return
		}
		if body.Username == "" || body.Password == "" {
			writeJSON(w, 400, map[string]string{"error": "username and password required"}); return
		}
		if body.Role != "admin" && body.Role != "analyst" { body.Role = "analyst" }
		if len(body.Password) < 8 {
			writeJSON(w, 400, map[string]string{"error": "password must be at least 8 characters"}); return
		}
		user, err := db.CreateUser(r.Context(), body.Username, body.Password, body.Role)
		if err != nil { writeJSON(w, 409, map[string]string{"error": "username already exists"}); return }
		db.WriteAudit(r.Context(), claims.Username, "create_user", body.Username, body.Role, clientIP(r))
		writeJSON(w, 201, user)
	}
}

func handleDeleteUser(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		if claims.Role != "admin" { writeJSON(w, 403, map[string]string{"error": "admin only"}); return }
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		if err := db.DeleteUser(r.Context(), id); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to delete user"}); return
		}
		db.WriteAudit(r.Context(), claims.Username, "delete_user", fmt.Sprintf("user:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

func handleListAuditLog(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		entries, total, err := db.ListAuditLog(r.Context(), limit, offset)
		if err != nil { writeJSON(w, 500, map[string]string{"error": "query failed"}); return }
		writeJSON(w, 200, map[string]interface{}{"entries": entries, "total": total})
	}
}

// ── Stats ─────────────────────────────────────────────────────────────────────

func handleStats(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if s := r.URL.Query().Get("hours"); s != "" {
			if v, err := strconv.Atoi(s); err == nil { hours = v }
		}
		summary, _ := db.Summary(r.Context())
		timeline, _ := db.EventsOverTime(r.Context(), hours)
		bySeverity, _ := db.EventsBySeverity(r.Context())
		byType, _ := db.EventsByType(r.Context())
		agentStats, _ := db.AgentStats(r.Context())
		dashData, _ := db.DashboardStats(r.Context())

		// Endpoint dashboard data — use ListAgents which has correct columns
		var agents []map[string]interface{}
		if agentList, err := db.ListAgents(r.Context()); err == nil {
			for _, a := range agentList {
				agents = append(agents, map[string]interface{}{
					"agent_id": a.ID, "hostname": a.Hostname, "os": a.OS,
					"ip_address": a.LastIP, "last_seen": a.LastSeen, "online": a.Online,
					"version": a.Version,
				})
			}
		}

		// OS counts
		var winCount, linCount, macCount int64
		db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM agents WHERE LOWER(os) LIKE '%win%'`).Scan(&winCount)
		db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM agents WHERE LOWER(os) LIKE '%linux%' OR LOWER(os) LIKE '%ubuntu%'`).Scan(&linCount)
		db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM agents WHERE LOWER(os) LIKE '%mac%' OR LOWER(os) LIKE '%darwin%'`).Scan(&macCount)

		// Cloud connector count
		var cloudConns int64
		db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM cloud_connectors`).Scan(&cloudConns)

		// DevOps connector + SAST data
		var devopsConns int64
		db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM devops_connectors`).Scan(&devopsConns)

		var sastRepos, sastFindings, sastCritical, sastHigh, sastMedium int64
		db.QueryRowContext(r.Context(), `SELECT COUNT(DISTINCT repo) FROM sast_results`).Scan(&sastRepos)
		db.QueryRowContext(r.Context(), `SELECT COALESCE(SUM(finding_count),0) FROM sast_results WHERE id IN (SELECT MAX(id) FROM sast_results GROUP BY connector_id, repo)`).Scan(&sastFindings)
		db.QueryRowContext(r.Context(), `SELECT COALESCE(SUM(critical_count),0) FROM sast_results WHERE id IN (SELECT MAX(id) FROM sast_results GROUP BY connector_id, repo)`).Scan(&sastCritical)
		db.QueryRowContext(r.Context(), `SELECT COALESCE(SUM(high_count),0) FROM sast_results WHERE id IN (SELECT MAX(id) FROM sast_results GROUP BY connector_id, repo)`).Scan(&sastHigh)
		db.QueryRowContext(r.Context(), `SELECT COALESCE(SUM(medium_count),0) FROM sast_results WHERE id IN (SELECT MAX(id) FROM sast_results GROUP BY connector_id, repo)`).Scan(&sastMedium)

		// SAST results list
		var sastResults []map[string]interface{}
		if rows, err := db.QueryContext(r.Context(), `
			SELECT repo, engine, finding_count, critical_count, high_count, scanned_at
			FROM sast_results ORDER BY scanned_at DESC LIMIT 10`); err == nil {
			defer rows.Close()
			for rows.Next() {
				var repo, engine string
				var findings, critical, high int64
				var scannedAt interface{}
				rows.Scan(&repo, &engine, &findings, &critical, &high, &scannedAt)
				sastResults = append(sastResults, map[string]interface{}{
					"repo": repo, "engine": engine,
					"finding_count": findings, "critical_count": critical,
					"high_count": high, "scanned_at": scannedAt,
				})
			}
		}

		writeJSON(w, 200, map[string]interface{}{
			"summary": summary, "timeline": timeline,
			"by_severity": bySeverity, "by_type": byType, "agents": agentStats,
			"dashboard": dashData,
			// Endpoint
			"endpoint_agents": agents,
			"windows_agents": winCount, "linux_agents": linCount, "macos_agents": macCount,
			// Cloud
			"cloud_connectors": cloudConns,
			// DevOps
			"devops_connectors": devopsConns,
			"sast_repos_scanned": sastRepos,
			"sast_total_findings": sastFindings,
			"sast_critical_count": sastCritical,
			"sast_high_count": sastHigh,
			"sast_medium_count": sastMedium,
			"sast_results": sastResults,
		})
	}
}

func handleHealth(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dbStatus := "ok"
		if err := db.HealthCheck(r.Context()); err != nil { dbStatus = "error: " + err.Error() }
		writeJSON(w, 200, map[string]interface{}{"status": "ok", "database": dbStatus, "time": time.Now().UTC()})
	}
}

func handleThreatIntel(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := db.ThreatIntel(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": "query failed"}); return }
		writeJSON(w, 200, data)
	}
}

// ── Alert detail ──────────────────────────────────────────────────────────────

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

func smtpConfigFromDB(ctx context.Context, db *store.DB) config.SMTPConfig {
	m, _ := db.GetSettingsPrefix(ctx, "smtp")
	port, _ := strconv.Atoi(m["port"])
	if port == 0 { port = 587 }
	minSev, _ := strconv.Atoi(m["min_severity"])
	if minSev == 0 { minSev = 4 }
	var to []string
	if m["to"] != "" {
		for _, r := range strings.Split(m["to"], ",") {
			if r = strings.TrimSpace(r); r != "" {
				to = append(to, r)
			}
		}
	}
	return config.SMTPConfig{
		Enabled:     m["enabled"] == "true",
		Host:        m["host"],
		Port:        port,
		Username:    m["username"],
		Password:    m["password"],
		From:        m["from"],
		To:          to,
		MinSeverity: minSev,
		UseTLS:      m["use_tls"] != "false",
	}
}

func handleGetSMTPSettings(cfg *config.Config, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dbCfg := smtpConfigFromDB(r.Context(), db)
		smtpCfg := dbCfg
		if smtpCfg.Host == "" {
			smtpCfg = cfg.SMTP
		}
		writeJSON(w, 200, map[string]interface{}{
			"enabled":      smtpCfg.Enabled,
			"host":         smtpCfg.Host,
			"port":         smtpCfg.Port,
			"username":     smtpCfg.Username,
			"from":         smtpCfg.From,
			"to":           smtpCfg.To,
			"min_severity": smtpCfg.MinSeverity,
			"use_tls":      smtpCfg.UseTLS,
			"has_password": smtpCfg.Password != "",
		})
	}
}

func handleSaveSMTPSettings(db *store.DB, mailer *notify.Mailer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled     bool     `json:"enabled"`
			Host        string   `json:"host"`
			Port        int      `json:"port"`
			Username    string   `json:"username"`
			Password    string   `json:"password"`
			From        string   `json:"from"`
			To          []string `json:"to"`
			MinSeverity int      `json:"min_severity"`
			UseTLS      bool     `json:"use_tls"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if body.Port == 0 { body.Port = 587 }
		if body.MinSeverity == 0 { body.MinSeverity = 4 }
		ctx := r.Context()
		if body.Password == "" {
			body.Password, _ = db.GetSetting(ctx, "smtp.password")
		}
		values := map[string]string{
			"enabled":      fmt.Sprintf("%v", body.Enabled),
			"host":         body.Host,
			"port":         strconv.Itoa(body.Port),
			"username":     body.Username,
			"password":     body.Password,
			"from":         body.From,
			"to":           strings.Join(body.To, ","),
			"min_severity": strconv.Itoa(body.MinSeverity),
			"use_tls":      fmt.Sprintf("%v", body.UseTLS),
		}
		if err := db.SetSettingsPrefix(ctx, "smtp", values); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to save"})
			return
		}
		mailer.UpdateConfig(config.SMTPConfig{
			Enabled: body.Enabled, Host: body.Host, Port: body.Port,
			Username: body.Username, Password: body.Password,
			From: body.From, To: body.To,
			MinSeverity: body.MinSeverity, UseTLS: body.UseTLS,
		})
		writeJSON(w, 200, map[string]string{"status": "saved"})
	}
}

func handleTestSMTP(mailer *notify.Mailer, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := smtpConfigFromDB(r.Context(), db)
		if cfg.Host == "" {
			writeJSON(w, 400, map[string]string{"error": "SMTP not configured — save settings first"})
			return
		}
		testMailer := notify.NewMailer(cfg)
		if err := testMailer.TestConnection(); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "test email sent"})
	}
}

// ── Detection Signatures ───────────────────────────────────────────────────────

func handleListDetections(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type SigInfo struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Severity    int    `json:"severity"`
			MITRE       string `json:"mitre"`
			Category    string `json:"category"`
			Enabled     bool   `json:"enabled"`
		}
		states, _ := db.GetSignatureStates(r.Context())

		// Combine all per-OS signature sets plus DNS blocklist for the UI listing
		allSigs := append(append(append(append(append(append(append(append(append(append(append(
			linuxSignatures,
			windowsSignatures...),
			macosSignatures...),
			dnsCatSignatures...),
			cloudSignaturesExtended...),
			dcSignatures...),
			cloudReconSignatures...),
			cloudNetworkSignatures...),
			cloudLateralSignatures...),
			cloudComputeAbuseSignatures...),
			devopsSignatures...),
			networkSignatures...)

		out := make([]SigInfo, len(allSigs))
		for i, s := range allSigs {
			enabled := true
			sev := s.Severity
			if state, ok := states[s.ID]; ok {
				enabled = state.Enabled
				if state.Severity != nil {
					sev = *state.Severity
				}
			}
			out[i] = SigInfo{s.ID, s.Name, s.Description, sev, s.MITRE, s.Category, enabled}
		}
		// Sigma rules — just return enabled/disabled state (single toggle for all)
		sigmaEnabled := true
		if v, _ := db.GetSetting(r.Context(), "detection.sigma_enabled"); v == "false" {
			sigmaEnabled = false
		}
		sigmaCount, _ := db.GetSigmaRuleCount(r.Context())
		writeJSON(w, 200, map[string]interface{}{
			"signatures":    out,
			"count":         len(out),
			"sigma_enabled": sigmaEnabled,
			"sigma_count":   sigmaCount,
		})
	}
}

// handleListSASTRules returns all SAST rules for the detections page
func handleListSASTRules(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type RuleInfo struct {
			ID       string `json:"id"`
			Lang     string `json:"lang"`
			Severity string `json:"severity"`
			CWE      string `json:"cwe"`
			OWASP    string `json:"owasp"`
			Title    string `json:"title"`
			Detail   string `json:"detail"`
			Fix      string `json:"fix"`
		}
		out := make([]RuleInfo, len(SASTRules))
		for i, r := range SASTRules {
			out[i] = RuleInfo{r.ID, r.Lang, r.Severity, r.CWE, r.OWASP, r.Title, r.Detail, r.Fix}
		}
		writeJSON(w, 200, map[string]interface{}{"rules": out, "count": len(out)})
	}
}

func handleToggleDetection(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var body struct {
			Enabled  *bool `json:"enabled"`
			Severity *int  `json:"severity"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if body.Enabled != nil {
			if err := db.SetSignatureEnabled(r.Context(), id, *body.Enabled); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
		}
		if body.Severity != nil {
			if err := db.SetSignatureSeverity(r.Context(), id, *body.Severity); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

// ── Threat Intel Sources ──────────────────────────────────────────────────────

func handleListThreatIntelSources(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		sources, err := db.ListThreatIntelSources(ctx)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		liveCounts := make(map[string]int)
		if rows, err2 := db.QueryContext(ctx,
			`SELECT source, COUNT(*) FROM ioc_indicators
			 WHERE expires_at IS NULL OR expires_at > NOW() GROUP BY source`); err2 == nil {
			defer rows.Close()
			for rows.Next() {
				var src string; var cnt int
				if rows.Scan(&src, &cnt) == nil { liveCounts[src] = cnt }
			}
		}
		type SourceOut struct {
			ID        int        `json:"id"`
			Name      string     `json:"name"`
			Enabled   bool       `json:"enabled"`
			HasAPIKey bool       `json:"has_api_key"`
			LastSync  *time.Time `json:"last_sync"`
			LastError *string    `json:"last_error"`
			IOCCount  int        `json:"ioc_count"`
		}
		out := make([]SourceOut, len(sources))
		for i, s := range sources {
			cnt := liveCounts[s.Name]
			if cnt == 0 { cnt = s.IOCCount }
			out[i] = SourceOut{
				ID:        s.ID,
				Name:      s.Name,
				Enabled:   s.Enabled,
				HasAPIKey: s.APIKey != nil && *s.APIKey != "",
				LastSync:  s.LastSync,
				LastError: s.LastError,
				IOCCount:  cnt,
			}
		}
		writeJSON(w, 200, map[string]interface{}{"sources": out})
	}
}

func handleUpdateThreatIntelSource(db *store.DB, engine *ThreatIntelEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		var body struct {
			Enabled *bool   `json:"enabled"`
			APIKey  *string `json:"api_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}

		sources, _ := db.ListThreatIntelSources(r.Context())
		var current *store.ThreatIntelSource
		for _, s := range sources {
			if s.Name == name {
				c := s
				current = &c
				break
			}
		}
		if current == nil {
			writeJSON(w, 404, map[string]string{"error": "source not found"})
			return
		}

		enabled := current.Enabled
		if body.Enabled != nil {
			enabled = *body.Enabled
		}
		apiKey := current.APIKey
		if body.APIKey != nil {
			apiKey = body.APIKey
		}

		if err := db.UpdateThreatIntelSource(r.Context(), name, enabled, apiKey); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}

		// If just enabled, trigger an immediate sync in background
		if body.Enabled != nil && *body.Enabled && !current.Enabled {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				engine.SyncSource(ctx, name, apiKey)
			}()
		}

		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

func handleTriggerSync(engine *ThreatIntelEngine, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		sources, _ := db.ListThreatIntelSources(r.Context())
		var apiKey *string
		for _, s := range sources {
			if s.Name == name {
				apiKey = s.APIKey
				break
			}
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			engine.SyncSource(ctx, name, apiKey)
		}()
		writeJSON(w, 200, map[string]string{"status": "sync started"})
	}
}

func handleSetTamperLock(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		var body struct { Locked bool `json:"locked"` }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if err := db.SetTamperLock(r.Context(), agentID, body.Locked); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"locked": body.Locked})
	}
}

func handleRegenerateKey(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		key, err := db.RegenerateInstallKey(r.Context(), agentID)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"install_key": key})
	}
}

// ── Case Management ───────────────────────────────────────────────────────────

func handleAssignAlert(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
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
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		var body struct { Notes string `json:"notes"` }
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
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		var body struct { Comment string `json:"comment"` }
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


// handleAgentRegisterKey allows an agent to register/update its own install key.
// Called at install time with the password the operator chose interactively.
// Auth: X-API-Key header matching any backend api_key.
func handleAgentRegisterKey(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			InstallKey string `json:"install_key"`
			AgentID    string `json:"agent_id"`
			OS         string `json:"os"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if body.InstallKey == "" {
			writeJSON(w, 400, map[string]string{"error": "install_key required"})
			return
		}
		// agentID optional — if not provided we try to find by API key header
		agentID := body.AgentID
		if agentID == "" {
			writeJSON(w, 400, map[string]string{"error": "agent_id required"})
			return
		}
		if err := db.SetInstallKey(r.Context(), agentID, body.InstallKey, body.OS); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

// handleVerifyInstallKey allows agents to verify their install key on service install
func handleVerifyInstallKey(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		if key == "" {
			writeJSON(w, 400, map[string]string{"error": "key required"})
			return
		}
		agent, err := db.GetAgentByInstallKey(r.Context(), key)
		if err != nil || agent == nil {
			writeJSON(w, 403, map[string]string{"error": "invalid key"})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok", "hostname": agent.Hostname})
	}
}

// handleThreatIntelHost returns threat intel scoped to a single host
func handleThreatIntelHost(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		hours := 24
		if s := r.URL.Query().Get("hours"); s != "" {
			if v, err := strconv.Atoi(s); err == nil { hours = v }
		}
		data, err := db.ThreatIntelHost(r.Context(), host, hours)
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, data)
	}
}

// ── Threat Graph ──────────────────────────────────────────────────────────────

// handleThreatGraphHost returns all process events for a host, grouped by
// application, with parent/child relationships for tree rendering.
func handleThreatGraphHost(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		since := time.Now().Add(-24 * time.Hour)
		if s := r.URL.Query().Get("since_hours"); s != "" {
			if h, err := strconv.Atoi(s); err == nil {
				since = time.Now().Add(-time.Duration(h) * time.Hour)
			}
		}

		// Fetch ALL events for this host — enrichFromRaw populates process_name even on
		// raw/file/network events, so we use all_events for both tree and enrichment.
		fAll := store.EventFilter{Host: host, Since: since, Limit: 5000}
		allEvents, _, err := db.QueryEvents(r.Context(), fAll)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}

		// Build deduplicated process list from all events.
		// For each unique process_name:pid combo, keep the event with the richest data
		// (prefer event_type=process, then highest severity, then most fields populated).
		type procKey struct{ name string; pid int }
		procMap := map[procKey]store.Event{}
		for _, e := range allEvents {
			if e.ProcessName == nil { continue }
			pid := 0; if e.PID != nil { pid = *e.PID }
			k := procKey{*e.ProcessName, pid}
			existing, exists := procMap[k]
			if !exists {
				procMap[k] = e
				continue
			}
			// Prefer event_type=process over other types
			if e.EventType == "process" && existing.EventType != "process" {
				procMap[k] = e
				continue
			}
			// Prefer events with command_line populated
			if e.CommandLine != nil && existing.CommandLine == nil {
				procMap[k] = e
			}
		}
		processEvents := make([]store.Event, 0, len(procMap))
		for _, e := range procMap { processEvents = append(processEvents, e) }

		writeJSON(w, 200, map[string]interface{}{
			"host":       host,
			"processes":  processEvents,
			"all_events": allEvents,
			"since":      since,
		})
	}
}

// handleThreatGraphProcess returns full process tree for a specific process name on a host.
func handleThreatGraphProcess(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host        := r.URL.Query().Get("host")
		processName := r.URL.Query().Get("process")
		since       := time.Now().Add(-24 * time.Hour)

		// Get all events related to this process
		f := store.EventFilter{
			Host:        host,
			ProcessName: processName,
			Since:       since,
			Limit:       500,
		}
		events, _, err := db.QueryEvents(r.Context(), f)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}

		writeJSON(w, 200, map[string]interface{}{
			"host":    host,
			"process": processName,
			"events":  events,
		})
	}
}

// handleGetAgentLocations returns all agents with known locations for the map.
func handleGetAgentLocations(db *store.DB, backendDB *store.DB) http.HandlerFunc {
	type locationRow struct {
		ID               string     `json:"id"`
		Hostname         string     `json:"hostname"`
		OS               string     `json:"os"`
		LastIP           string     `json:"last_ip"`
		LastSeen         time.Time  `json:"last_seen"`
		Lat              float64    `json:"lat"`
		Lng              float64    `json:"lng"`
		LocationAccuracy float64    `json:"location_accuracy,omitempty"`
		LocationSource   string     `json:"location_source,omitempty"`
		LocationCity     string     `json:"location_city,omitempty"`
		LocationCountry  string     `json:"location_country,omitempty"`
		LocationUpdated  *time.Time `json:"location_updated,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Use backend DB if available — it has live location data from agents
		// Query only the columns that exist in both management and backend agents tables
		queryDB := db
		if backendDB != nil {
			queryDB = backendDB
		}

		rows, err := queryDB.QueryContext(r.Context(), `
			SELECT id, hostname, os, COALESCE(last_ip,''), last_seen,
			       lat, lng, COALESCE(location_accuracy, 0),
			       COALESCE(location_source,''), COALESCE(location_city,''),
			       COALESCE(location_country,''), location_updated
			FROM agents
			WHERE lat IS NOT NULL AND lng IS NOT NULL
			ORDER BY last_seen DESC
		`)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		defer rows.Close()

		var locs []locationRow
		for rows.Next() {
			var l locationRow
			if err := rows.Scan(
				&l.ID, &l.Hostname, &l.OS, &l.LastIP, &l.LastSeen,
				&l.Lat, &l.Lng, &l.LocationAccuracy,
				&l.LocationSource, &l.LocationCity, &l.LocationCountry,
				&l.LocationUpdated,
			); err != nil {
				continue
			}
			locs = append(locs, l)
		}
		if locs == nil {
			locs = []locationRow{}
		}
		writeJSON(w, 200, locs)
	}
}

func handleUpdateAgentLocation(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AgentID  string  `json:"agent_id"`
			Lat      float64 `json:"lat"`
			Lng      float64 `json:"lng"`
			Accuracy float64 `json:"accuracy"`
			Source   string  `json:"source"`
			City     string  `json:"city"`
			Country  string  `json:"country"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AgentID == "" {
			http.Error(w, `{"error":"bad request"}`, 400)
			return
		}
		if body.Lat == 0 && body.Lng == 0 {
			http.Error(w, `{"error":"invalid coordinates"}`, 400)
			return
		}
		if err := db.UpdateAgentLocation(r.Context(), body.AgentID,
			body.Lat, body.Lng, body.Accuracy, body.Source, body.City, body.Country,
		); err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

// ── AI Alert Analysis ─────────────────────────────────────────────────────────

// ── AI Alert Analysis (local rule-based engine) ───────────────────────────────

type AlertAnalysisRequest struct {
	AlertID     int64  `json:"alert_id,omitempty"`
	Title       string `json:"title"`
	Severity    int    `json:"severity"`
	Description string `json:"description"`
	Host        string `json:"host"`
	EventType   string `json:"event_type"`
	ProcessName string `json:"process_name"`
	CommandLine string `json:"command_line"`
	UserName    string `json:"user_name"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	DstPort     int    `json:"dst_port"`
	FilePath    string `json:"file_path"`
	FileHash    string `json:"file_hash"`
	RegKey      string `json:"reg_key"`
	RegValue    string `json:"reg_value"`
	MITRE       string `json:"mitre"`
	Category    string `json:"category"`
	RawEvent    string `json:"raw_event"` // full raw event JSON for deep analysis
}

type AlertAnalysis struct {
	Summary                 string   `json:"summary"`
	WhatHappened            string   `json:"what_happened"`
	ThreatAssessment        string   `json:"threat_assessment"`
	AffectedSystem          string   `json:"affected_system"`
	MITREContext            string   `json:"mitre_context"`
	RiskLevel               string   `json:"risk_level"`
	RecommendedActions      []string `json:"recommended_actions"`
	FalsePositiveIndicators string   `json:"false_positive_indicators"`
	InvestigationQuestions  []string `json:"investigation_questions"`
}

func handleAIAnalysis(cfg *config.Config, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AlertAnalysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}

		// Resolve API keys: settings DB takes precedence over server.yaml
		// (Agent Builder saves keys to DB; server.yaml is the static fallback)
		groqKey := cfg.Groq.APIKey
		anthropicKey := cfg.Anthropic.APIKey
		if aiSettings, err := db.GetSettingsPrefix(r.Context(), "ai"); err == nil {
			if v := aiSettings["groq_api_key"]; v != "" {
				groqKey = v
			}
			if v := aiSettings["anthropic_api_key"]; v != "" {
				anthropicKey = v
			}
		}

		// Use Groq if key configured, else Anthropic, else local rule-based engine
		if groqKey != "" {
			result, err := callGroq(r.Context(), groqKey, req)
			if err == nil {
				saveAlertAnalysis(r.Context(), db, req, result)
				writeJSON(w, 200, result)
				return
			}
			writeJSON(w, 500, map[string]string{"error": "Groq API error: " + err.Error()})
			return
		} else if anthropicKey != "" {
			result, err := callAnthropic(r.Context(), anthropicKey, req)
			if err == nil {
				saveAlertAnalysis(r.Context(), db, req, result)
				writeJSON(w, 200, result)
				return
			}
			writeJSON(w, 500, map[string]string{"error": "Anthropic API error: " + err.Error()})
			return
		}

		// Local rule-based fallback
		analysis := analyseAlert(req)
		text, _ := json.Marshal(analysis)
		writeJSON(w, 200, map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": string(text)},
			},
		})
	}
}

func buildAnalysisPrompt(req AlertAnalysisRequest) string {
	sevLabel := map[int]string{1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}[req.Severity]
	if sevLabel == "" {
		sevLabel = "Medium"
	}

	rawSection := ""
	if req.RawEvent != "" {
		rawSection = fmt.Sprintf("\nRaw Event Data (JSON):\n%s", req.RawEvent)
	}

	extraFields := ""
	if req.SrcIP != "" { extraFields += fmt.Sprintf("\nSrc IP: %s", req.SrcIP) }
	if req.DstPort > 0 { extraFields += fmt.Sprintf("\nDst Port: %d", req.DstPort) }
	if req.RegKey != "" { extraFields += fmt.Sprintf("\nRegistry Key: %s", req.RegKey) }
	if req.RegValue != "" { extraFields += fmt.Sprintf("\nRegistry Value: %s", req.RegValue) }
	if req.FileHash != "" { extraFields += fmt.Sprintf("\nFile Hash: %s", req.FileHash) }

	return fmt.Sprintf(`You are an expert cybersecurity analyst. Analyse this SIEM alert and return ONLY a valid JSON object — no markdown, no code blocks, no extra text.

=== ALERT ===
Title: %s
Severity: %s
Host: %s
Event Type: %s
Process: %s
Command Line: %s
User: %s
Dst IP/Domain: %s
File Path: %s
MITRE Technique: %s
Category: %s
Description: %s%s%s

=== INSTRUCTIONS ===
Analyse every field above carefully. If raw event data is provided, use it to give a more precise analysis.
Determine if this is a real threat or likely false positive based on all available context.

Return this exact JSON structure:
{
  "risk_score": <integer 0-100, where 100 is most critical — be precise, not all critical alerts are 100>,
  "fp_probability": <integer 0-100, likelihood this is a false positive — 0=definitely real threat, 100=definitely benign>,
  "verdict": "THREAT|SUSPICIOUS|LIKELY_FP|FALSE_POSITIVE",
  "summary": "one sentence — what happened in plain English",
  "what_happened": "2-4 sentences — precise technical explanation of the activity",
  "threat_assessment": "detailed analysis of whether this is a real threat, suspicious activity, or false positive and exactly why",
  "affected_system": "what we know about the host, user, and potential blast radius",
  "mitre_context": "explanation of the MITRE ATT&CK technique and how it applies here",
  "hash_analysis": "if a file hash is provided, describe what this hash is known for — malware family, tool name, etc. If no hash, return null",
  "recommended_actions": ["immediate action 1", "containment step 2", "investigation step 3", "remediation step 4"],
  "false_positive_indicators": "specific signs in this event data that suggest it could be benign",
  "investigation_questions": ["question 1 to answer before escalating", "question 2", "question 3"],
  "timeline": [
    {"time": "T+0", "event": "what triggered this alert"},
    {"time": "T+?", "event": "likely next attacker step if threat is real"}
  ]
}`,
		req.Title, sevLabel, req.Host, req.EventType,
		req.ProcessName, req.CommandLine, req.UserName,
		req.DstIP, req.FilePath, req.MITRE, req.Category,
		req.Description, extraFields, rawSection,
	)
}

func callGroq(ctx context.Context, apiKey string, req AlertAnalysisRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{
		"model":       "llama-3.3-70b-versatile",
		"max_tokens":  1024,
		"temperature": 0.2,
		"response_format": map[string]string{"type": "json_object"},
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a cybersecurity analyst. Always respond with valid JSON only. No explanations, no markdown, no code blocks — just the raw JSON object.",
			},
			{"role": "user", "content": buildAnalysisPrompt(req)},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.groq.com/openai/v1/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var groqResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&groqResp); err != nil {
		return nil, err
	}
	if groqResp.Error != nil {
		return nil, fmt.Errorf("groq: %s", groqResp.Error.Message)
	}
	if len(groqResp.Choices) == 0 {
		return nil, fmt.Errorf("groq: no choices returned")
	}

	text := groqResp.Choices[0].Message.Content
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": text},
		},
	}, nil
}

func callAnthropic(ctx context.Context, apiKey string, req AlertAnalysisRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{
		"model":      "claude-sonnet-4-20250514",
		"max_tokens": 1024,
		"messages": []map[string]string{
			{"role": "user", "content": buildAnalysisPrompt(req)},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.anthropic.com/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("anthropic: status %d", resp.StatusCode)
	}
	return result, nil
}

func analyseAlert(req AlertAnalysisRequest) AlertAnalysis {
	title := req.Title
	cat := req.Category
	mitre := req.MITRE
	host := req.Host
	if host == "" { host = "Unknown" }
	proc := req.ProcessName
	cmd := req.CommandLine
	user := req.UserName
	if user == "" { user = "Unknown" }
	dstIP := req.DstIP
	filePath := req.FilePath

	sevLabel := map[int]string{1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}[req.Severity]
	if sevLabel == "" { sevLabel = "Unknown" }

	// ── Build contextual description ──────────────────────────────────────
	var whatHappened, threat, falsePos string
	var actions, questions []string

	switch {
	// ── Execution ──────────────────────────────────────────────────────────
	case strings.Contains(strings.ToLower(title), "powershell encoded"):
		whatHappened = fmt.Sprintf("PowerShell was launched on %s with an encoded command (-EncodedCommand flag). The command was base64-encoded to hide its content from casual inspection. Process: %s.", host, strOrDash2(&proc))
		threat = "Attackers commonly encode PowerShell to evade signature-based detection. This is a hallmark of malware delivery, post-exploitation frameworks (Cobalt Strike, Metasploit), and living-off-the-land attacks."
		falsePos = "Some legitimate software and system management tools use encoded PowerShell. Check if the parent process is a known admin tool (SCCM, PDQ Deploy, etc.)."
		actions = []string{
			"Decode the base64 command: [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<encoded>'))",
			"Check the parent process that launched PowerShell",
			"Review network connections made by this PowerShell process",
			"Isolate the host if the decoded command contains download cradles or suspicious URLs",
		}
		questions = []string{
			"What was the parent process that launched PowerShell?",
			"What does the decoded command do?",
			"Was there outbound network activity immediately after?",
		}

	case strings.Contains(strings.ToLower(title), "download cradle"):
		whatHappened = fmt.Sprintf("PowerShell on %s attempted to download and execute code from a remote source using WebClient or Invoke-Expression. Command: %s.", host, strOrDash2(&cmd))
		threat = "This is a classic 'fileless malware' technique — code is downloaded directly into memory without touching disk, bypassing antivirus file scanning. Commonly used in phishing attacks and exploitation chains."
		falsePos = "Software updates and IT scripts occasionally use WebClient. Verify if this aligns with scheduled maintenance windows."
		actions = []string{
			"Capture and analyse the URL being contacted",
			"Block the destination IP/domain at the firewall immediately",
			"Run a memory dump on the affected process",
			"Check for persistence mechanisms (scheduled tasks, registry Run keys) created after this event",
			"Isolate the host from the network",
		}
		questions = []string{
			"What URL was being contacted?",
			"Was the download successful?",
			"Are there signs of persistence being established?",
		}

	case strings.Contains(strings.ToLower(title), "lsass"):
		whatHappened = fmt.Sprintf("An attempt to access or dump the LSASS (Local Security Authority Subsystem Service) process memory was detected on %s by user %s.", host, user)
		threat = "LSASS holds password hashes, Kerberos tickets, and plaintext credentials in memory. Dumping it allows attackers to extract all credentials on the machine and move laterally across the network with Pass-the-Hash or Pass-the-Ticket attacks."
		falsePos = "Legitimate tools like Windows Defender, EDR agents, and crash dump utilities can access LSASS. Verify the process origin."
		actions = []string{
			"Immediately isolate the host to prevent credential reuse",
			"Reset passwords for all accounts that logged into this host",
			"Invalidate all Kerberos tickets (reset KRBTGT account if domain controller is affected)",
			"Check for lateral movement from this host in the 30 minutes following this event",
			"Enable Credential Guard if not already enabled",
		}
		questions = []string{
			"Which process accessed LSASS?",
			"Has this user account been used on other hosts since this event?",
			"Is there evidence of lateral movement (new SMB/RDP connections)?",
		}

	case strings.Contains(strings.ToLower(title), "shadow copy"):
		whatHappened = fmt.Sprintf("Volume Shadow Copies (system backups) were deleted on %s using vssadmin or wmic. This is commonly the final step before ransomware begins encrypting files.", host)
		threat = "This is a near-certain ransomware precursor. Deleting shadow copies prevents victims from recovering files without paying ransom. This should be treated as an active ransomware incident."
		falsePos = "Very rarely, system administrators delete shadow copies for storage management. This should still be investigated urgently."
		actions = []string{
			"IMMEDIATELY isolate the host from the network — cut the network cable if necessary",
			"Check if file encryption has begun (look for new file extensions, ransom notes)",
			"Identify patient zero — how did the attacker get in?",
			"Activate your incident response plan",
			"Do not pay ransom without consulting legal and security teams",
			"Check offsite/cloud backups for clean restore points",
		}
		questions = []string{
			"Has file encryption already started?",
			"What was the initial infection vector?",
			"Are other hosts on the network showing similar activity?",
		}

	case strings.Contains(strings.ToLower(title), "lateral movement") || strings.Contains(strings.ToLower(title), "psexec"):
		whatHappened = fmt.Sprintf("Lateral movement activity detected from %s. A remote execution tool or protocol (RDP/SMB/PsExec) was used to connect to or from this host.", host)
		threat = "The attacker has already compromised one machine and is now spreading through the network. This indicates an active, hands-on attacker who has moved beyond initial access."
		falsePos = "System administrators use PsExec and RDP legitimately. Verify if this aligns with known admin activity."
		actions = []string{
			"Map all hosts this machine has connected to in the past 24 hours",
			"Identify the source of compromise on the originating host",
			"Check for new accounts or privilege escalation on destination hosts",
			"Review firewall logs for unusual internal traffic patterns",
			"Consider network segmentation to limit further spread",
		}
		questions = []string{
			"What was the source host that initiated the connection?",
			"What credentials were used for the connection?",
			"Which other hosts has the source host connected to?",
		}

	case strings.Contains(strings.ToLower(title), "keychain"):
		whatHappened = fmt.Sprintf("The macOS Keychain was accessed on %s by process %s. The Keychain stores passwords, certificates, and cryptographic keys.", host, strOrDash2(&proc))
		threat = "Keychain dumping allows attackers to extract all stored passwords including Wi-Fi passwords, website credentials, and application secrets without the user noticing."
		falsePos = "Many legitimate macOS applications access the Keychain for their own stored credentials. Check if the accessing process is trusted."
		actions = []string{
			"Identify what specific keychain items were accessed",
			"Change all passwords that may have been stored in the Keychain",
			"Check for new applications recently installed on the host",
			"Review Login Items and LaunchAgents for persistence",
		}
		questions = []string{
			"Which keychain items were accessed?",
			"Was this process authorised to access the Keychain?",
			"Is this a known application?",
		}

	case strings.Contains(strings.ToLower(title), "brute force") || strings.Contains(strings.ToLower(title), "failed logon"):
		src := strOrDash2(&dstIP)
		if req.SrcIP != "" { src = req.SrcIP }
		whatHappened = fmt.Sprintf("Multiple failed authentication attempts detected on %s from source %s. This pattern matches automated credential stuffing or brute force attacks.", host, src)
		threat = "Brute force attacks attempt to guess passwords by trying many combinations. If successful, the attacker gains full access to the account. Credential stuffing uses previously leaked username/password pairs."
		falsePos = "A user who forgot their password or a misconfigured application can generate false positives. Check if the attempts come from a known IP."
		actions = []string{
			"Check if any login eventually succeeded after the failures",
			"Temporarily lock the targeted account",
			"Block the source IP at the firewall",
			"Enable account lockout policy if not already enabled",
			"Consider enabling MFA for affected accounts",
		}
		questions = []string{
			"Did any authentication attempt succeed?",
			"Is the source IP associated with known threat infrastructure?",
			"Is this a service account or user account?",
		}

	case strings.Contains(strings.ToLower(title), "ioc match") || strings.Contains(strings.ToLower(title), "threatfox") || strings.Contains(strings.ToLower(title), "otx"):
		whatHappened = fmt.Sprintf("A network connection or file on %s matched a known malicious indicator from threat intelligence feeds. The matched indicator: %s.", host, strOrDash2(&dstIP))
		threat = "This host communicated with infrastructure known to be associated with malware, command-and-control servers, or threat actors. This is a high-confidence indicator of compromise."
		falsePos = "Rarely, legitimate CDN or cloud IP addresses get incorrectly flagged. Verify the indicator in multiple threat intel sources."
		actions = []string{
			"Block the flagged IP/domain at the perimeter firewall immediately",
			"Check what process initiated the connection",
			"Review all network connections from this host in the past 24 hours",
			"Run a full malware scan on the host",
			"Check for persistence mechanisms",
			"Isolate if the connection was sustained or data was transferred",
		}
		questions = []string{
			"What process initiated the connection to the malicious indicator?",
			"How long has this communication been happening?",
			"Was any data transferred to the external destination?",
		}

	case strings.Contains(strings.ToLower(title), "dlp") || strings.Contains(strings.ToLower(cat), "data loss"):
		whatHappened = fmt.Sprintf("A potential data loss event was detected on %s. Process %s performed an action that may result in sensitive data leaving the organisation.", host, strOrDash2(&proc))
		threat = "Data exfiltration or accidental data loss can result in regulatory violations (GDPR, HIPAA), intellectual property theft, or competitive harm. This may be intentional insider threat activity or accidental data spillage."
		falsePos = "Legitimate business activities such as approved file sharing, cloud backups, and authorised email attachments can trigger these rules."
		actions = []string{
			"Identify what data was involved and classify its sensitivity",
			"Determine the destination — was it internal or external?",
			"Review the user's recent activity for context",
			"Check if this aligns with a legitimate business process",
			"If sensitive data left the organisation, initiate data breach assessment",
		}
		questions = []string{
			"What specific data was involved?",
			"Where was the data sent?",
			"Is this user authorised to handle and transfer this type of data?",
		}

	default:
		// Generic analysis based on category and event type
		whatHappened = fmt.Sprintf("A security event was detected on host %s. The alert '%s' was triggered based on activity matching known threat patterns.", host, title)
		if proc != "" { whatHappened += fmt.Sprintf(" Involved process: %s.", proc) }
		if cmd != "" { whatHappened += fmt.Sprintf(" Command executed: %s.", cmd) }
		if filePath != "" { whatHappened += fmt.Sprintf(" File involved: %s.", filePath) }

		threat = fmt.Sprintf("This alert falls under the '%s' category (MITRE ATT&CK: %s). %s",
			cat, mitre, categoryThreatContext(cat))

		falsePos = categoryFalsePositive(cat)
		actions = categoryActions(cat, host)
		questions = categoryQuestions(cat)
	}

	// ── Build affected system description ─────────────────────────────────
	affectedSystem := fmt.Sprintf("Host: %s", host)
	if user != "Unknown" && user != "" {
		affectedSystem += fmt.Sprintf(" | User: %s", user)
	}
	if req.EventType != "" {
		affectedSystem += fmt.Sprintf(" | Event type: %s", req.EventType)
	}

	// ── MITRE context ─────────────────────────────────────────────────────
	mitreContext := mitreDescription(mitre, cat)

	// ── Risk level explanation ─────────────────────────────────────────────
	riskLevel := fmt.Sprintf("This alert is rated %s. %s", sevLabel, severityRationale(req.Severity, cat))

	// ── Summary ───────────────────────────────────────────────────────────
	summary := fmt.Sprintf("%s detected on %s", title, host)
	if user != "Unknown" && user != "" {
		summary += fmt.Sprintf(" by user %s", user)
	}
	summary += fmt.Sprintf(" — %s severity.", strings.ToLower(sevLabel))

	return AlertAnalysis{
		Summary:                 summary,
		WhatHappened:            whatHappened,
		ThreatAssessment:        threat,
		AffectedSystem:          affectedSystem,
		MITREContext:            mitreContext,
		RiskLevel:               riskLevel,
		RecommendedActions:      actions,
		FalsePositiveIndicators: falsePos,
		InvestigationQuestions:  questions,
	}
}

func strOrDash2(s *string) string {
	if s == nil || *s == "" { return "—" }
	return *s
}

func categoryThreatContext(cat string) string {
	m := map[string]string{
		"Execution":            "The attacker is attempting to run malicious code on the system.",
		"Persistence":          "The attacker is attempting to maintain access across reboots and credential changes.",
		"Privilege Escalation": "The attacker is attempting to gain higher-level permissions on the system.",
		"Defence Evasion":      "The attacker is attempting to avoid detection and hide their activity.",
		"Credential Access":    "The attacker is attempting to steal account credentials.",
		"Discovery":            "The attacker is gathering information about the environment to plan next steps.",
		"Lateral Movement":     "The attacker is moving through the network, compromising additional systems.",
		"Command & Control":    "The attacker is communicating with external infrastructure to control the compromised system.",
		"Exfiltration":         "The attacker is attempting to steal data from the organisation.",
		"Impact":               "The attacker is attempting to disrupt, destroy, or hold data for ransom.",
		"Initial Access":       "The attacker is attempting to gain a foothold in the environment.",
		"Data Loss Prevention": "Sensitive data may be leaving the organisation through an unauthorised channel.",
		"Insider Threat":       "Activity suggests a potential insider threat or policy violation.",
		"Reconnaissance":       "The attacker is gathering information to plan an attack.",
	}
	if v, ok := m[cat]; ok { return v }
	return "Review the alert details for more context on the threat."
}

func categoryFalsePositive(cat string) string {
	m := map[string]string{
		"Execution":            "Legitimate administration scripts, software deployment tools, and developer activity can trigger these rules.",
		"Persistence":          "Software installers and system management tools often create scheduled tasks and registry entries.",
		"Privilege Escalation": "Legitimate administrative tasks require elevated privileges. Verify the user's role.",
		"Defence Evasion":      "Some security tools and IT management software use similar techniques.",
		"Credential Access":    "Password managers and legitimate security tools may access credential stores.",
		"Discovery":            "IT administrators regularly enumerate systems. Check if this aligns with known admin activity.",
		"Lateral Movement":     "Authorised remote administration (RDP, SSH) is common. Verify against change management records.",
		"Command & Control":    "Legitimate update servers and cloud services can sometimes match C2 patterns.",
		"Exfiltration":         "Authorised file sharing and backup tools can trigger DLP rules.",
		"Data Loss Prevention": "Approved business processes such as cloud backups and authorised sharing may trigger these rules.",
	}
	if v, ok := m[cat]; ok { return v }
	return "Verify whether this activity aligns with known legitimate business operations."
}

func categoryActions(cat, host string) []string {
	m := map[string][]string{
		"Execution":            {"Review the full process tree for this event", "Check network connections made by the process", "Scan the host for malware", "Review recently installed software"},
		"Persistence":          {"Review all startup items, scheduled tasks, and services on " + host, "Compare against a known-good baseline", "Remove any unauthorised persistence mechanisms"},
		"Privilege Escalation": {"Review what the escalated process did after gaining privileges", "Check for new accounts or group membership changes", "Review sudo/admin logs"},
		"Credential Access":    {"Reset credentials for any accounts on " + host, "Enable MFA if not already active", "Check for lateral movement using harvested credentials"},
		"Discovery":            {"Monitor for follow-up activity (lateral movement, exploitation)", "Review who the user is and whether this is expected behaviour"},
		"Lateral Movement":     {"Map all affected hosts", "Identify the initial point of compromise", "Isolate affected systems", "Reset credentials on all touched systems"},
		"Command & Control":    {"Block the destination IP/domain at the firewall", "Isolate " + host + " from the network", "Analyse the process making the connection"},
		"Exfiltration":         {"Identify what data was exfiltrated", "Notify legal/compliance teams if sensitive data is involved", "Block the destination"},
		"Impact":               {"Isolate " + host + " immediately", "Activate incident response plan", "Preserve forensic evidence before remediation"},
		"Initial Access":       {"Identify the attack vector", "Patch the exploited vulnerability", "Review other hosts for similar activity"},
	}
	if v, ok := m[cat]; ok { return v }
	return []string{"Investigate the alert details", "Determine if this is malicious or benign", "Document findings in case notes"}
}

func categoryQuestions(cat string) []string {
	m := map[string][]string{
		"Execution":            {"What was the parent process?", "Was any network connection made during or after execution?", "Is this process expected on this host?"},
		"Persistence":          {"Is this persistence mechanism expected or authorised?", "When was it created and by which user?"},
		"Privilege Escalation": {"What did the process do after gaining elevated privileges?", "Is this user authorised to perform this escalation?"},
		"Credential Access":    {"Were the credentials successfully extracted?", "Has the affected account been used from other locations since this event?"},
		"Discovery":            {"Is this a known administrator performing routine tasks?", "What activity followed this discovery phase?"},
		"Lateral Movement":     {"What credentials were used?", "How many systems were touched?", "What is the original point of compromise?"},
		"Command & Control":    {"How long has this communication been occurring?", "What data was sent or received?"},
		"Exfiltration":         {"What specific data was taken?", "Was it encrypted in transit?", "Is this a targeted or opportunistic attack?"},
		"Impact":               {"How many systems are affected?", "Are backups intact and recoverable?"},
	}
	if v, ok := m[cat]; ok { return v }
	return []string{"Is this activity authorised?", "What happened before and after this event?", "Are other hosts showing similar activity?"}
}

func mitreDescription(mitre, cat string) string {
	descriptions := map[string]string{
		"T1059.001": "PowerShell (T1059.001) — Adversaries abuse PowerShell to execute commands, scripts, and download payloads. It's a trusted Windows component that can bypass application controls.",
		"T1003.001": "OS Credential Dumping: LSASS Memory (T1003.001) — Adversaries attempt to access LSASS to obtain credential material such as account login and credential hashes.",
		"T1490":     "Inhibit System Recovery (T1490) — Adversaries delete or disable backups to prevent recovery after ransomware deployment.",
		"T1486":     "Data Encrypted for Impact (T1486) — Adversaries encrypt data to interrupt availability and hold it hostage for ransom.",
		"T1021.001": "Remote Services: RDP (T1021.001) — Adversaries use RDP to move laterally between systems using valid credentials.",
		"T1547.001": "Boot or Logon Autostart: Registry Run Keys (T1547.001) — Adversaries add programs to run keys to establish persistence.",
		"T1110":     "Brute Force (T1110) — Adversaries use brute force to gain access to accounts when passwords are unknown.",
		"T1055":     "Process Injection (T1055) — Adversaries inject code into processes to evade defences and execute under the context of a legitimate process.",
		"T1562.001": "Impair Defences: Disable or Modify Tools (T1562.001) — Adversaries disable security tools to avoid detection.",
		"T1070.001": "Indicator Removal: Clear Windows Event Logs (T1070.001) — Adversaries clear event logs to remove evidence of their activity.",
	}
	if v, ok := descriptions[mitre]; ok { return v }
	if cat != "" {
		return fmt.Sprintf("MITRE ATT&CK technique %s falls under the '%s' tactic. Visit https://attack.mitre.org/techniques/%s for full details.", mitre, cat, strings.Replace(mitre, ".", "/", 1))
	}
	return fmt.Sprintf("MITRE ATT&CK technique %s. Visit https://attack.mitre.org for detailed information.", mitre)
}

func severityRationale(sev int, cat string) string {
	switch sev {
	case 5:
		return "Critical alerts indicate activity that poses an immediate threat to systems, data, or operations and requires urgent response."
	case 4:
		return "High severity alerts indicate likely malicious activity that poses significant risk and requires prompt investigation."
	case 3:
		return "Medium severity alerts indicate suspicious activity that warrants investigation but may have legitimate explanations."
	case 2:
		return "Low severity alerts indicate potentially suspicious activity, often reconnaissance or policy violations, that should be reviewed."
	default:
		return "Informational alerts provide context about activity on the system."
	}
}

// ── Cloud Connectors (stub — full implementation coming) ──────────────────────

func handleListCloudConnectors(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connectors, err := db.ListCloudConnectors(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if connectors == nil {
			connectors = []store.CloudConnector{}
		}
		writeJSON(w, 200, map[string]interface{}{"connectors": connectors})
	}
}

func handleSaveCloudConnector(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider    string            `json:"provider"`
			Credentials map[string]string `json:"credentials"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Provider == "" {
			writeJSON(w, 400, map[string]string{"error": "provider and credentials required"})
			return
		}
		id, err := db.UpsertCloudConnector(r.Context(), req.Provider, req.Credentials)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"id": id, "status": "saved"})
	}
}

func handleTestCloudConnector(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider    string            `json:"provider"`
			Credentials map[string]string `json:"credentials"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		switch req.Provider {
		case "aws":
			creds := awsCreds{
				AccessKeyID:     req.Credentials["access_key_id"],
				SecretAccessKey: req.Credentials["secret_access_key"],
				Region:          req.Credentials["region"],
			}
			if creds.Region == "" {
				creds.Region = "us-east-1"
			}
			accountID, err := testAWSConnection(r.Context(), creds)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": "ok", "account_id": accountID})

		case "azure":
			err := testAzureConnection(r.Context(),
				req.Credentials["tenant_id"],
				req.Credentials["client_id"],
				req.Credentials["client_secret"],
				req.Credentials["subscription_id"])
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": "ok", "subscription_id": req.Credentials["subscription_id"]})

		case "gcp":
			projectID, err := testGCPConnection(r.Context(), req.Credentials["service_account"])
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": "ok", "project_id": projectID})

		default:
			writeJSON(w, 400, map[string]string{"error": "unsupported provider: " + req.Provider})
		}
	}
}

func handleDeleteCloudConnector(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		var id int64
		fmt.Sscanf(idStr, "%d", &id)
		if err := db.DeleteCloudConnector(r.Context(), id); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}

func handleSyncCloudConnector(db *store.DB, engine *CloudConnectorEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		var id int64
		fmt.Sscanf(idStr, "%d", &id)
		go engine.SyncOne(context.Background(), id)
		writeJSON(w, 200, map[string]string{"status": "sync started"})
	}
}

// ── AI Chat ───────────────────────────────────────────────────────────────────
// handleAIChat handles follow-up analyst questions about an alert.
// Receives the original alert context + conversation history + new question.

type ChatMessage struct {
	Role    string `json:"role"`    // "user" | "assistant"
	Content string `json:"content"`
}

type AIChatRequest struct {
	// Alert context (same fields as AlertAnalysisRequest)
	Title       string `json:"title"`
	Severity    int    `json:"severity"`
	Host        string `json:"host"`
	EventType   string `json:"event_type"`
	ProcessName string `json:"process_name"`
	CommandLine string `json:"command_line"`
	UserName    string `json:"user_name"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	DstPort     int    `json:"dst_port"`
	FilePath    string `json:"file_path"`
	RegKey      string `json:"reg_key"`
	MITRE       string `json:"mitre"`
	RawEvent    string `json:"raw_event"`
	// Conversation
	History  []ChatMessage `json:"history"`
	Question string        `json:"question"`
}

func buildChatSystemPrompt(req AIChatRequest) string {
	sevLabel := map[int]string{1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}[req.Severity]
	if sevLabel == "" { sevLabel = "Medium" }

	rawSection := ""
	if req.RawEvent != "" {
		rawSection = fmt.Sprintf("\nRaw Event JSON:\n%s", req.RawEvent)
	}
	return fmt.Sprintf(`You are an expert cybersecurity analyst assistant helping investigate a SIEM alert.
Answer questions concisely and precisely. Be direct — this is a live investigation.
If you are unsure, say so. Never invent indicators or IOCs.

=== ALERT CONTEXT ===
Title: %s | Severity: %s | Host: %s
Event Type: %s | Process: %s | Command: %s
User: %s | Src IP: %s | Dst IP: %s | Port: %d
File: %s | Registry: %s | MITRE: %s%s`,
		req.Title, sevLabel, req.Host,
		req.EventType, req.ProcessName, req.CommandLine,
		req.UserName, req.SrcIP, req.DstIP, req.DstPort,
		req.FilePath, req.RegKey, req.MITRE, rawSection,
	)
}

func handleAIChat(cfg *config.Config, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AIChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if req.Question == "" {
			writeJSON(w, 400, map[string]string{"error": "question is required"})
			return
		}

		// Resolve API keys
		groqKey := cfg.Groq.APIKey
		anthropicKey := cfg.Anthropic.APIKey
		if aiSettings, err := db.GetSettingsPrefix(r.Context(), "ai"); err == nil {
			if v := aiSettings["groq_api_key"]; v != "" { groqKey = v }
			if v := aiSettings["anthropic_api_key"]; v != "" { anthropicKey = v }
		}

		systemPrompt := buildChatSystemPrompt(req)

		// Build messages: system + history + new question
		if groqKey != "" {
			messages := []map[string]string{
				{"role": "system", "content": systemPrompt},
			}
			for _, msg := range req.History {
				messages = append(messages, map[string]string{"role": msg.Role, "content": msg.Content})
			}
			messages = append(messages, map[string]string{"role": "user", "content": req.Question})

			body := map[string]interface{}{
				"model": "llama-3.3-70b-versatile", "max_tokens": 1024, "temperature": 0.3,
				"messages": messages,
			}
			bodyBytes, _ := json.Marshal(body)
			httpReq, _ := http.NewRequestWithContext(r.Context(), "POST",
				"https://api.groq.com/openai/v1/chat/completions", bytes.NewReader(bodyBytes))
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("Authorization", "Bearer "+groqKey)

			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.Do(httpReq)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": "Groq request failed: " + err.Error()})
				return
			}
			defer resp.Body.Close()
			var groqResp struct {
				Choices []struct { Message struct { Content string `json:"content"` } `json:"message"` } `json:"choices"`
				Error   *struct { Message string `json:"message"` } `json:"error"`
			}
			json.NewDecoder(resp.Body).Decode(&groqResp)
			if groqResp.Error != nil {
				writeJSON(w, 500, map[string]string{"error": "Groq: " + groqResp.Error.Message})
				return
			}
			if len(groqResp.Choices) == 0 {
				writeJSON(w, 500, map[string]string{"error": "no response from Groq"})
				return
			}
			writeJSON(w, 200, map[string]string{"answer": groqResp.Choices[0].Message.Content})
			return

		} else if anthropicKey != "" {
			// Build Anthropic messages (no system in messages array — use system param)
			msgs := []map[string]string{}
			for _, msg := range req.History {
				msgs = append(msgs, map[string]string{"role": msg.Role, "content": msg.Content})
			}
			msgs = append(msgs, map[string]string{"role": "user", "content": req.Question})

			body := map[string]interface{}{
				"model": "claude-sonnet-4-20250514", "max_tokens": 1024,
				"system": systemPrompt, "messages": msgs,
			}
			bodyBytes, _ := json.Marshal(body)
			httpReq, _ := http.NewRequestWithContext(r.Context(), "POST",
				"https://api.anthropic.com/v1/messages", bytes.NewReader(bodyBytes))
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("x-api-key", anthropicKey)
			httpReq.Header.Set("anthropic-version", "2023-06-01")

			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.Do(httpReq)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": "Anthropic request failed: " + err.Error()})
				return
			}
			defer resp.Body.Close()
			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			if resp.StatusCode != 200 {
				writeJSON(w, 500, map[string]string{"error": fmt.Sprintf("Anthropic status %d", resp.StatusCode)})
				return
			}
			// Extract text from content array
			answer := ""
			if content, ok := result["content"].([]interface{}); ok {
				for _, block := range content {
					if b, ok := block.(map[string]interface{}); ok {
						if b["type"] == "text" {
							answer, _ = b["text"].(string)
							break
						}
					}
				}
			}
			writeJSON(w, 200, map[string]string{"answer": answer})
			return
		}

		// No AI key configured
		writeJSON(w, 503, map[string]string{"error": "No AI provider configured. Add a Groq or Anthropic API key in Settings → AI."})
	}
}

// handleGetVulnScan returns the latest vulnerability.scan event for a host
func handleGetVulnScan(db *store.DB, backendDB *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		if host == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
			return
		}
		ctx := r.Context()
		// Try management DB first, then backend DB
		events, _, err := db.QueryEvents(ctx, store.EventFilter{
			Host:      host,
			EventType: "vulnerability.scan",
			Limit:     1,
		})
		if (err != nil || len(events) == 0) && backendDB != nil {
			// Events are stored in the backend DB — try there too
			events, _, err = backendDB.QueryEvents(ctx, store.EventFilter{
				Host:      host,
				EventType: "vulnerability.scan",
				Limit:     1,
			})
		}
		if err != nil || len(events) == 0 {
			writeJSON(w, http.StatusOK, map[string]interface{}{"scan": nil})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"scan": events[0]})
	}
}

// handleVulnAIAnalysis — runs AI analysis on a vulnerability scan result
func handleVulnAIAnalysis(cfg *config.Config, db *store.DB, backendDB *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ScanJSON string `json:"scan_json"`
			Host     string `json:"host"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}

		// Resolve AI keys
		groqKey := cfg.Groq.APIKey
		anthropicKey := cfg.Anthropic.APIKey
		if aiSettings, err := db.GetSettingsPrefix(r.Context(), "ai"); err == nil {
			if v := aiSettings["groq_api_key"]; v != "" { groqKey = v }
			if v := aiSettings["anthropic_api_key"]; v != "" { anthropicKey = v }
		}
		if groqKey == "" && anthropicKey == "" {
			writeJSON(w, 503, map[string]string{"error": "No AI provider configured. Add a Groq or Anthropic API key in Settings → AI."})
			return
		}

		apiKey, model := groqKey, "llama-3.3-70b-versatile"
		if apiKey == "" {
			apiKey, model = anthropicKey, "claude-sonnet-4-20250514"
		}

		ctx := r.Context()

		// Parse the scan
		var scan map[string]interface{}
		if err := json.Unmarshal([]byte(req.ScanJSON), &scan); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid scan JSON"})
			return
		}

		// ── NVD-powered CVE lookup + AI analysis ─────────────────────────────
		//
		// Phase 1: Query NVD (National Vulnerability Database) for real CVEs.
		//   - No AI guessing — real CVE IDs with real CVSS scores
		//   - Results cached 24h to avoid re-querying on every analysis
		//   - Rate limited to stay within NVD free tier (5 req/30s)
		//
		// Phase 2: Single AI call with confirmed CVEs + ports + findings.
		//   - AI produces narrative, attack surface, remediation plan
		//   - No package list sent to AI — just confirmed vulnerabilities

		pkgCount := 0
		var nvdFindings []CVEFinding

		if pkgs, ok := scan["packages"].([]interface{}); ok && len(pkgs) > 0 {
			pkgCount = len(pkgs)

			// Check host-level NVD cache first (24h TTL, avoids re-querying on every analysis)
			hostCacheKey := "nvd_findings:" + req.Host
			if cached, err := db.GetSetting(r.Context(), hostCacheKey); err == nil && cached != "" {
				if err2 := json.Unmarshal([]byte(cached), &nvdFindings); err2 == nil {
					logger.Info("nvd: using cached findings", "host", req.Host, "count", len(nvdFindings))
				} else {
					nvdFindings = nil
				}
			}

			// If no cache, query NVD
			if nvdFindings == nil {
				pkgMaps := make([]map[string]interface{}, 0, len(pkgs))
				for _, p := range pkgs {
					if pm, ok := p.(map[string]interface{}); ok {
						pkgMaps = append(pkgMaps, pm)
					}
				}

				nvdKey := cfg.NVD.APIKey
				if s, err := db.GetSetting(r.Context(), "nvd_api_key"); err == nil && s != "" {
					nvdKey = s
				}
				nvdClient := NewNVDClient(nvdKey, logger)

				// Cap at 20s — stays within server write timeout
				nvdCtx, nvdCancel := context.WithTimeout(ctx, 20*time.Second)
				var nvdErr error
				nvdFindings, nvdErr = nvdClient.LookupPackages(nvdCtx, pkgMaps, 4.0)
				nvdCancel()

				if nvdErr != nil {
					logger.Warn("nvd: lookup timed out, proceeding with AI analysis only", "err", nvdErr)
				} else if len(nvdFindings) > 0 {
					// Cache findings per host for 24h
					if b, err := json.Marshal(nvdFindings); err == nil {
						_ = db.SetSetting(r.Context(), hostCacheKey, string(b))
					}
				}
			}
		}

		// Build the AI prompt with confirmed CVEs (no raw package list)
		analysisScan := map[string]interface{}{
			"host":               scan["host"],
			"os":                 scan["os"],
			"system":             scan["system"],
			"scanned_at":         scan["scanned_at"],
			"open_ports":         scan["open_ports"],
			"udp_ports":          scan["udp_ports"],
			"services":           scan["services"],
			"findings":           scan["findings"],
			"total_open":         scan["total_open"],
			"critical_count":     scan["critical_count"],
			"high_count":         scan["high_count"],
			"medium_count":       scan["medium_count"],
			"scan_duration_secs": scan["scan_duration_secs"],
			"total_packages":     pkgCount,
			"confirmed_cves":     nvdFindings, // real CVEs from NVD, not AI guesses
		}
		analysisScanJSON, _ := json.Marshal(analysisScan)

		aiCtx, cancel2 := context.WithTimeout(ctx, 60*time.Second)
		defer cancel2()

		finalPrompt := buildVulnAnalysisPrompt(string(analysisScanJSON), req.Host)
		finalText, err := callVulnAI(aiCtx, apiKey, model, finalPrompt)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "AI analysis failed: " + err.Error()})
			return
		}

		// Cache the result so re-opens are instant
		_ = db.SetSetting(r.Context(), "vuln_analysis:"+req.Host, finalText)

		writeJSON(w, 200, map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": finalText},
			},
		})
	}
}

// callVulnAI sends a prompt to the configured AI provider and returns the text response.
func callVulnAI(ctx context.Context, apiKey, model, prompt string) (string, error) {
	isGroq := model == "llama-3.3-70b-versatile"

	var apiURL string
	body := map[string]interface{}{
		"model":       model,
		"max_tokens":  4096,
		"temperature": 0.1,
		"messages": []map[string]interface{}{
			{
				"role":    "system",
				"content": "You are a cybersecurity vulnerability analyst. Always respond with valid JSON only. No markdown, no code blocks, no explanations — just the raw JSON.",
			},
			{"role": "user", "content": prompt},
		},
	}

	if isGroq {
		apiURL = "https://api.groq.com/openai/v1/chat/completions"
	} else {
		apiURL = "https://api.anthropic.com/v1/messages"
	}

	bodyBytes, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if isGroq {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	} else {
		httpReq.Header.Set("x-api-key", apiKey)
		httpReq.Header.Set("anthropic-version", "2023-06-01")
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	var text string
	if isGroq {
		if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if msg, ok := choice["message"].(map[string]interface{}); ok {
					text, _ = msg["content"].(string)
				}
			}
		}
	} else {
		if content, ok := result["content"].([]interface{}); ok {
			for _, block := range content {
				if b, ok := block.(map[string]interface{}); ok && b["type"] == "text" {
					text, _ = b["text"].(string)
				}
			}
		}
	}

	if text == "" {
		return "", fmt.Errorf("empty AI response")
	}

	// Strip markdown fences if present
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	return strings.TrimSpace(text), nil
}


func buildVulnAnalysisPrompt(scanJSON, host string) string {
	return fmt.Sprintf(`You are an enterprise security engineer performing a vulnerability assessment review.

You have been given a full vulnerability scan result from host "%s" in JSON format.
The scan includes: open TCP/UDP ports with service versions, ALL installed packages (analyse every package for known CVEs and outdated versions — golang, php, python, openssl, nginx, ssh, mysql, etc.), running services, and security findings.

Analyse the scan data and return ONLY a valid JSON object — no markdown, no code blocks, no extra text.

Return this exact JSON structure:
{
  "executive_summary": "2-3 sentence plain English summary for a CISO — overall risk posture and top concerns",
  "risk_score": <integer 0-100 representing overall risk, 100=most critical>,
  "risk_label": "Critical|High|Medium|Low|Minimal",
  "critical_findings": [
    {"title": "...", "detail": "...", "cve_references": ["CVE-XXXX-XXXXX"], "affected": "service or component", "remediation": "specific fix command or action"}
  ],
  "high_findings": [
    {"title": "...", "detail": "...", "cve_references": [], "affected": "...", "remediation": "..."}
  ],
  "medium_findings": [
    {"title": "...", "detail": "...", "cve_references": [], "affected": "...", "remediation": "..."}
  ],
  "outdated_software": [
    {"name": "...", "installed_version": "...", "recommended_version": "...", "cves": ["..."], "upgrade_command": "..."}
  ],
  "attack_surface_summary": "paragraph describing what an attacker could do with the exposed services",
  "immediate_actions": ["highest priority action 1", "action 2", "action 3"],
  "remediation_plan": [
    {"priority": 1, "action": "...", "effort": "minutes|hours|days", "impact": "..."},
    {"priority": 2, "action": "...", "effort": "...", "impact": "..."}
  ],
  "compliance_notes": "brief note on any obvious compliance implications (PCI-DSS, SOC2, ISO27001, HIPAA)",
  "positive_findings": ["things that are configured correctly and should be maintained"]
}

Scan data:
%s`, host, scanJSON)
}

// filterInterestingPackages removes low-value system/lib packages that rarely
// have exploitable CVEs, reducing the number of AI calls needed.
func filterInterestingPackages(pkgs []interface{}) []interface{} {
	skipPrefixes := []string{
		"lib", "font", "fonts-", "python3-", "python-", "perl-", "ruby-",
		"php-", "gir1.2-", "golang-", "nodejs-", "gnome-", "kde-",
		"locale-", "language-", "xfonts-", "ttf-", "texlive-",
		"linux-image-", "linux-headers-", "linux-modules-",
		"grub-", "initramfs-", "plymouth-",
	}
	var out []interface{}
	for _, p := range pkgs {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := pm["name"].(string)
		if name == "" {
			continue
		}
		skip := false
		for _, prefix := range skipPrefixes {
			if strings.HasPrefix(strings.ToLower(name), prefix) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, p)
		}
	}
	return out
}

// saveAlertAnalysis extracts the AI text from the response and persists it
// against the alert so subsequent opens don't need to re-call the AI.
func saveAlertAnalysis(ctx context.Context, db *store.DB, req AlertAnalysisRequest, result map[string]interface{}) {
	if req.AlertID == 0 {
		return // no alert ID — can't save
	}
	// Extract text content from AI response
	text := ""
	if content, ok := result["content"].([]interface{}); ok {
		for _, block := range content {
			if b, ok := block.(map[string]interface{}); ok && b["type"] == "text" {
				text, _ = b["text"].(string)
			}
		}
	}
	if text == "" {
		return
	}
	_ = db.SaveAlertAIAnalysis(ctx, req.AlertID, text)
}

// handleGetVulnAnalysisCache returns the cached AI analysis for a host's vuln scan.
func handleGetVulnAnalysisCache(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		val, err := db.GetSetting(r.Context(), "vuln_analysis:"+host)
		if err != nil || val == "" {
			writeJSON(w, http.StatusOK, map[string]interface{}{"analysis": nil})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"analysis": val})
	}
}

// ── Root Cause Analysis ───────────────────────────────────────────────────────

type RCARequest struct {
	Host        string `json:"host"`
	Description string `json:"description"` // what the user thinks happened
	IncidentAt  string `json:"incident_at"` // ISO time user believes incident started
	Question    string `json:"question,omitempty"` // follow-up question
	History     []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"history,omitempty"`
}

// handleGetRCAContext returns the pre-sampled data the frontend shows before running RCA.
// This lets the user see what will be sent to the AI.
func handleGetRCAContext(db *store.DB, backendDB *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		incidentAt := r.URL.Query().Get("incident_at")
		if incidentAt == "" {
			incidentAt = time.Now().UTC().Format(time.RFC3339)
		}
		t, err := time.Parse(time.RFC3339, incidentAt)
		if err != nil {
			t = time.Now().UTC()
		}
		ctx := r.Context()

		alerts, events, vulnSummary := gatherRCAData(ctx, db, backendDB, host, t)

		writeJSON(w, 200, map[string]interface{}{
			"alert_count":  len(alerts),
			"event_count":  len(events),
			"has_vuln":     vulnSummary != "",
			"window_start": t.Add(-48 * time.Hour).Format(time.RFC3339),
			"window_end":   t.Add(48 * time.Hour).Format(time.RFC3339),
		})
	}
}

// gatherRCAData collects the context for RCA: alerts, sampled events, vuln summary.
func gatherRCAData(ctx context.Context, db *store.DB, backendDB *store.DB, host string, t time.Time) ([]store.Alert, []store.Event, string) {
	since := t.Add(-48 * time.Hour)
	until := t.Add(48 * time.Hour)

	// Alerts for host in window
	alerts, _ := db.ListAlertsForHost(ctx, host, since)
	// Cap at 50 most severe
	if len(alerts) > 50 {
		alerts = alerts[:50]
	}

	// Events: sample top 60 by severity, deduplicated by event_type+process
	// Use backendDB first, fall back to db
	evDB := backendDB
	if evDB == nil {
		evDB = db
	}
	events, _, _ := evDB.QueryEvents(ctx, store.EventFilter{
		Host:     host,
		Since:    since,
		Until:    until,
		Severity: 2, // skip info-only
		Limit:    200,
	})
	events = sampleEvents(events, 60)

	// Vuln scan summary
	vulnSummary := ""
	vulnEvents, _, _ := evDB.QueryEvents(ctx, store.EventFilter{
		Host:      host,
		EventType: "vulnerability.scan",
		Limit:     1,
	})
	if len(vulnEvents) > 0 {
		if raw := vulnEvents[0].Raw; raw != nil {
			var scan map[string]interface{}
			if json.Unmarshal(raw, &scan) == nil {
				// Only send summary — ports + findings, no packages
				summary := map[string]interface{}{
					"total_open":     scan["total_open"],
					"critical_count": scan["critical_count"],
					"high_count":     scan["high_count"],
					"medium_count":   scan["medium_count"],
					"open_ports":     scan["open_ports"],
					"findings":       scan["findings"],
					"system":         scan["system"],
					"scanned_at":     scan["scanned_at"],
				}
				if b, err := json.Marshal(summary); err == nil {
					vulnSummary = string(b)
				}
			}
		}
	}

	return alerts, events, vulnSummary
}

// sampleEvents deduplicates and caps events for RCA context.
// Keeps the most interesting: high severity first, then deduplicated by event_type+process.
func sampleEvents(events []store.Event, max int) []store.Event {
	if len(events) <= max {
		return events
	}
	deref := func(s *string) string {
		if s == nil { return "" }
		return *s
	}
	// Deduplicate by event_type + process_name — keep first occurrence
	seen := map[string]bool{}
	var out []store.Event
	for _, ev := range events {
		key := ev.EventType + "|" + deref(ev.ProcessName) + "|" + deref(ev.CommandLine)
		if !seen[key] {
			seen[key] = true
			out = append(out, ev)
		}
		if len(out) >= max {
			break
		}
	}
	return out
}

// handleRCAAnalysis runs the AI-powered root cause analysis.
func handleRCAAnalysis(cfg *config.Config, db *store.DB, backendDB *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		var req RCARequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		req.Host = host

		// Resolve AI keys
		groqKey := cfg.Groq.APIKey
		anthropicKey := cfg.Anthropic.APIKey
		if aiSettings, err := db.GetSettingsPrefix(r.Context(), "ai"); err == nil {
			if v := aiSettings["groq_api_key"]; v != "" { groqKey = v }
			if v := aiSettings["anthropic_api_key"]; v != "" { anthropicKey = v }
		}
		if groqKey == "" && anthropicKey == "" {
			writeJSON(w, 503, map[string]string{"error": "No AI provider configured."})
			return
		}
		apiKey, model := groqKey, "llama-3.3-70b-versatile"
		if apiKey == "" {
			apiKey, model = anthropicKey, "claude-sonnet-4-20250514"
		}

		// Parse incident time
		t, err := time.Parse(time.RFC3339, req.IncidentAt)
		if err != nil {
			t = time.Now().UTC()
		}

		ctx := r.Context()
		alerts, events, vulnSummary := gatherRCAData(ctx, db, backendDB, host, t)

		// Build compact event summaries — not full raw payloads
		type evSummary struct {
			Time        string `json:"time"`
			Type        string `json:"type"`
			Severity    int    `json:"severity"`
			Process     string `json:"process,omitempty"`
			CommandLine string `json:"cmd,omitempty"`
			User        string `json:"user,omitempty"`
			SrcIP       string `json:"src_ip,omitempty"`
			DstIP       string `json:"dst_ip,omitempty"`
			DstPort     int    `json:"dst_port,omitempty"`
			FilePath    string `json:"file,omitempty"`
			RegKey      string `json:"reg_key,omitempty"`
		}
		evSummaries := make([]evSummary, 0, len(events))
		pStr := func(s *string) string { if s == nil { return "" }; return *s }
		pInt := func(i *int) int { if i == nil { return 0 }; return *i }
		for _, ev := range events {
			evSummaries = append(evSummaries, evSummary{
				Time: ev.Time.Format("2006-01-02 15:04:05"),
				Type: ev.EventType, Severity: int(ev.Severity),
				Process: pStr(ev.ProcessName), CommandLine: pStr(ev.CommandLine),
				User: pStr(ev.UserName), SrcIP: pStr(ev.SrcIP), DstIP: pStr(ev.DstIP),
				DstPort: pInt(ev.DstPort), FilePath: pStr(ev.FilePath), RegKey: pStr(ev.RegKey),
			})
		}

		type alertSummary struct {
			Time     string `json:"time"`
			Title    string `json:"title"`
			Severity int    `json:"severity"`
			Status   string `json:"status"`
			Type     string `json:"type"`
		}
		alertSummaries := make([]alertSummary, 0, len(alerts))
		for _, a := range alerts {
			alertSummaries = append(alertSummaries, alertSummary{
				Time:     a.CreatedAt.Format("2006-01-02 15:04:05"),
				Title:    a.Title,
				Severity: a.Severity,
				Status:   a.Status,
				Type:     a.EventType,
			})
		}

		evJSON, _    := json.Marshal(evSummaries)
		alertJSON, _ := json.Marshal(alertSummaries)

		// Handle follow-up question vs initial analysis
		var prompt string
		if req.Question != "" && len(req.History) > 0 {
			// Follow-up — build conversation history prompt
			prompt = buildRCAChatPrompt(req, string(evJSON), string(alertJSON), vulnSummary)
		} else {
			// Initial analysis
			prompt = buildRCAPrompt(req, string(evJSON), string(alertJSON), vulnSummary)
		}

		rcaCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		text, err := callVulnAI(rcaCtx, apiKey, model, prompt)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "RCA analysis failed: " + err.Error()})
			return
		}

		// Cache if initial analysis
		if req.Question == "" {
			_ = db.SetSetting(ctx, "rca:"+host, text)
		}

		writeJSON(w, 200, map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": text},
			},
			"event_count": len(evSummaries),
			"alert_count": len(alertSummaries),
		})
	}
}

func buildRCAPrompt(req RCARequest, eventsJSON, alertsJSON, vulnSummary string) string {
	vulnSection := ""
	if vulnSummary != "" {
		vulnSection = fmt.Sprintf("\n\n=== VULNERABILITY SCAN (latest) ===\n%s", vulnSummary)
	}
	return fmt.Sprintf(`You are a senior incident response analyst at a cybersecurity firm performing a thorough Root Cause Analysis (RCA) report. You have deep expertise in threat hunting, MITRE ATT&CK, digital forensics, and incident response.

=== INCIDENT DESCRIPTION ===
Host: %s
Reported time: %s
What happened (user description): %s

=== SECURITY ALERTS (±48h window, max 50, sorted by severity) ===
%s

=== SECURITY EVENTS (±48h window, sampled 60 most significant) ===
%s%s

=== YOUR TASK ===
Perform a comprehensive, professional Root Cause Analysis. Be thorough and specific — reference actual event timestamps, process names, IPs, file paths, and alert titles from the data above. Do not be vague.

Return ONLY this exact JSON — no markdown, no code blocks, no preamble:
{
  "incident_title": "descriptive title for this incident (e.g. 'LSASS Credential Dumping via Mimikatz on CORP-VAPT')",
  "executive_summary": "3-5 sentence non-technical summary of what happened, the impact, and current status. Written for a CISO or board member.",
  "root_cause": "Precise 2-4 sentence technical root cause. Name the specific vulnerability, misconfiguration, or user action that enabled the attack. Be specific about what failed.",
  "confidence": "High|Medium|Low",
  "confidence_reason": "Explain specifically why confidence is High/Medium/Low based on evidence quality and gaps in the data.",
  "attack_chain": [
    {
      "phase": "Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Exfiltration|Command and Control|Impact",
      "technique": "specific technique name (e.g. 'Spearphishing Attachment')",
      "description": "2-3 sentences explaining exactly what happened in this phase, referencing specific events/processes/IPs from the data",
      "evidence": "specific alert title, event ID, timestamp, process name, or command line from the data that proves this phase occurred",
      "mitre": "T1xxx.xxx"
    }
  ],
  "timeline": [
    {"time": "timestamp from data or relative (e.g. T+5min)", "event": "precise description of what happened", "significance": "why this event matters to the attack chain"}
  ],
  "key_indicators": [
    {"type": "process|network|file|registry|user|dns|hash", "indicator": "exact value from the data", "significance": "what this indicator tells us about attacker intent or capability"}
  ],
  "impact_assessment": {
    "systems_affected": ["list specific systems, accounts, or services impacted"],
    "data_at_risk": "specific data types or systems that may have been accessed, exfiltrated, or damaged",
    "business_impact": "operational, financial, and reputational impact — be specific about what services or data were affected",
    "severity": "Critical|High|Medium|Low",
    "severity_rationale": "why this severity rating"
  },
  "contributing_factors": [
    "specific security control failure or misconfiguration that enabled the attack (e.g. 'LSA protection not enabled allowing LSASS memory access')",
    "additional factor..."
  ],
  "remediation": {
    "immediate": ["specific action to take RIGHT NOW — contain, isolate, or block (e.g. 'Isolate CORP-VAPT from network', 'Reset credentials for affected accounts')", "..."],
    "short_term": ["action within 24-72 hours to fully remediate (e.g. 'Enable Credential Guard', 'Patch CVE-XXXX-XXXX')", "..."],
    "long_term": ["systemic improvement to prevent recurrence (e.g. 'Deploy PAM solution', 'Implement network segmentation')", "..."]
  },
  "detection_gaps": [
    "specific detection that was missing or slow that would have caught this earlier (e.g. 'No alert on LSASS handle access by non-system processes')"
  ],
  "lessons_learned": [
    "actionable lesson from this incident for both detection engineering and security operations"
  ],
  "questions_for_analyst": [
    "specific question whose answer would significantly change or confirm this analysis"
  ]
}`,
		req.Host, req.IncidentAt, req.Description,
		alertsJSON, eventsJSON, vulnSection,
	)
}

func buildRCAChatPrompt(req RCARequest, eventsJSON, alertsJSON, vulnSummary string) string {
	historyText := ""
	for _, h := range req.History {
		historyText += fmt.Sprintf("\n[%s]: %s", strings.ToUpper(h.Role), h.Content)
	}
	return fmt.Sprintf(`You are a senior incident response analyst helping investigate a security incident. You are in a conversation with a security analyst who has questions about the incident.

Host: %s | Incident time: %s
Incident description: %s

=== SECURITY ALERTS ===
%s

=== SECURITY EVENTS ===
%s

=== CONVERSATION SO FAR ===%s

=== ANALYST QUESTION ===
%s

=== INSTRUCTIONS ===
- Answer in clear, natural prose — NO JSON, NO code blocks, NO bullet point lists unless specifically asked
- Be direct and specific — reference actual timestamps, process names, IPs, commands from the data above
- If something is uncertain, say so and explain what additional evidence would help
- Keep responses focused and concise — 2-5 paragraphs maximum
- Write as if explaining to a fellow senior security analyst
- NEVER return JSON format`,
		req.Host, req.IncidentAt, req.Description,
		alertsJSON, eventsJSON, historyText, req.Question,
	)
}

// handleGetRCACache returns the cached RCA for a host.
func handleGetRCACache(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		val, err := db.GetSetting(r.Context(), "rca:"+host)
		if err != nil || val == "" {
			writeJSON(w, 200, map[string]interface{}{"rca": nil})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"rca": val})
	}
}

// handleGetAPIKeys returns all configured API keys (masked)
// Keys are stored with dot-prefix: ai.groq_api_key, ai.anthropic_api_key,
// nvd_api_key (bare), ti.threatfox_api_key etc.
// handleGetAPIKeys returns all configured API keys (masked).
// Storage locations:
//   AI keys  → settings table as "ai.groq_api_key", "ai.anthropic_api_key"
//   NVD      → settings table as "nvd_api_key"
//   TI feeds → threat_intel_sources table (threatfox, otx)
//   Other TI → settings table as "ti.virustotal_api_key" etc.
func handleGetAPIKeys(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		result := map[string]interface{}{}

		maskVal := func(uiKey, val string) {
			if val == "" { result[uiKey] = ""; return }
			if len(val) > 8 {
				result[uiKey] = val[:4] + strings.Repeat("•", 8)
			} else {
				result[uiKey] = strings.Repeat("•", len(val))
			}
			result[uiKey+"_set"] = true
		}

		// AI + NVD + other TI keys from settings table
		settingsKeys := map[string]string{
			"groq_api_key":       "ai.groq_api_key",
			"anthropic_api_key":  "ai.anthropic_api_key",
			"nvd_api_key":        "nvd_api_key",
			"virustotal_api_key":       "ti.virustotal_api_key",
			"hybrid_analysis_api_key": "ti.hybrid_analysis_api_key",
			"abuseipdb_api_key":        "ti.abuseipdb_api_key",
			"shodan_api_key":           "ti.shodan_api_key",
		}
		for uiKey, storeKey := range settingsKeys {
			val, _ := db.GetSetting(ctx, storeKey)
			maskVal(uiKey, val)
		}

		// ThreatFox + OTX from threat_intel_sources table
		if sources, err := db.ListThreatIntelSources(ctx); err == nil {
			for _, src := range sources {
				switch src.Name {
				case "threatfox":
					if src.APIKey != nil { maskVal("threatfox_api_key", *src.APIKey) } else { result["threatfox_api_key"] = "" }
				case "otx":
					if src.APIKey != nil { maskVal("otx_api_key", *src.APIKey) } else { result["otx_api_key"] = "" }
				}
			}
		}

		writeJSON(w, 200, result)
	}
}

// handleSaveAPIKeys saves API keys to their correct storage locations.
func handleSaveAPIKeys(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		ctx := r.Context()
		saved := []string{}

		save := func(uiKey, storeKey string) {
			v, ok := body[uiKey]
			if !ok || strings.Contains(v, "•") { return } // skip if absent or masked
			_ = db.SetSetting(ctx, storeKey, v)
			saved = append(saved, uiKey)
		}

		// Settings table keys
		save("groq_api_key",       "ai.groq_api_key")
		save("anthropic_api_key",  "ai.anthropic_api_key")
		save("nvd_api_key",        "nvd_api_key")
		save("virustotal_api_key",       "ti.virustotal_api_key")
		save("hybrid_analysis_api_key", "ti.hybrid_analysis_api_key")
		save("abuseipdb_api_key",  "ti.abuseipdb_api_key")
		save("shodan_api_key",     "ti.shodan_api_key")

		// ThreatFox → threat_intel_sources table
		if v, ok := body["threatfox_api_key"]; ok && !strings.Contains(v, "•") {
			_ = db.UpdateThreatIntelSource(ctx, "threatfox", v != "", func() *string { if v == "" { return nil }; return &v }())
			saved = append(saved, "threatfox_api_key")
		}
		// OTX → threat_intel_sources table
		if v, ok := body["otx_api_key"]; ok && !strings.Contains(v, "•") {
			_ = db.UpdateThreatIntelSource(ctx, "otx", v != "", func() *string { if v == "" { return nil }; return &v }())
			saved = append(saved, "otx_api_key")
		}

		writeJSON(w, 200, map[string]interface{}{"saved": saved})
	}
}

// handleToggleSigma enables or disables ALL Sigma rules at once.
func handleToggleSigma(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		val := "true"
		if !body.Enabled { val = "false" }
		if err := db.SetSetting(r.Context(), "detection.sigma_enabled", val); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true, "enabled": body.Enabled})
	}
}

// ── IP ISP/ASN Lookup ─────────────────────────────────────────────────────────

var ispCache = struct {
	sync.RWMutex
	data map[string]map[string]string
}{data: make(map[string]map[string]string)}

func lookupISP(ip string) map[string]string {
	ispCache.RLock()
	if v, ok := ispCache.data[ip]; ok {
		ispCache.RUnlock()
		return v
	}
	ispCache.RUnlock()

	result := map[string]string{"isp": "", "org": "", "country": "", "asn": ""}
	// ip-api.com free tier — no key needed, 45 req/min
	resp, err := http.Get("http://ip-api.com/json/" + ip + "?fields=status,isp,org,country,as")
	if err != nil { return result }
	defer resp.Body.Close()
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil { return result }
	if s, _ := data["status"].(string); s != "success" { return result }
	if v, ok := data["isp"].(string); ok { result["isp"] = v }
	if v, ok := data["org"].(string); ok { result["org"] = v }
	if v, ok := data["country"].(string); ok { result["country"] = v }
	if v, ok := data["as"].(string); ok { result["asn"] = v }

	ispCache.Lock()
	ispCache.data[ip] = result
	ispCache.Unlock()
	return result
}

// handleISPLookup enriches a list of IPs with ISP/ASN data.
func handleISPLookup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IPs []string `json:"ips"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		result := make(map[string]map[string]string)
		isPrivate := func(ip string) bool {
			return strings.HasPrefix(ip, "10.") ||
				strings.HasPrefix(ip, "192.168.") ||
				strings.HasPrefix(ip, "127.") ||
				strings.HasPrefix(ip, "172.16.") ||
				strings.HasPrefix(ip, "172.17.") ||
				strings.HasPrefix(ip, "::1") ||
				ip == ""
		}
		// Lookup up to 20 IPs, skip private
		var wg sync.WaitGroup
		var mu sync.Mutex
		count := 0
		for _, ip := range body.IPs {
			if isPrivate(ip) || count >= 20 { continue }
			count++
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				info := lookupISP(ip)
				mu.Lock()
				result[ip] = info
				mu.Unlock()
			}(ip)
		}
		wg.Wait()
		writeJSON(w, 200, map[string]interface{}{"enriched": result})
	}
}

// handleRunCSPM runs a CSPM scan for a cloud connector
func handleRunCSPM(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }

		conn, err := db.GetCloudConnectorRaw(r.Context(), id)
		if err != nil { writeJSON(w, 404, map[string]string{"error": "connector not found"}); return }
		if conn.Provider != "gcp" {
			writeJSON(w, 400, map[string]string{"error": "CSPM currently supported for GCP only"})
			return
		}

		saJSON := conn.Credentials["service_account"]
		projectID := conn.Credentials["project_id"]
		if projectID == "" { projectID = conn.AccountID }

		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()

		result, err := RunGCPCSPM(ctx, saJSON, projectID)
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }

		// Store result in settings
		resultJSON, _ := json.Marshal(result)
		db.SetSetting(r.Context(), fmt.Sprintf("cspm:gcp:%d", id), string(resultJSON))

		writeJSON(w, 200, result)
	}
}

// handleGetCSPM returns the latest CSPM scan result
func handleGetCSPM(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }

		val, err := db.GetSetting(r.Context(), fmt.Sprintf("cspm:gcp:%d", id))
		if err != nil || val == "" {
			writeJSON(w, 200, map[string]interface{}{"findings": []interface{}{}, "total_findings": 0})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(val))
	}
}

// handleCSPMAIExplain — AI explanation for a CSPM finding or AI summary of full scan
func handleCSPMAIExplain(cfg *config.Config, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Prompt  string      `json:"prompt"`
			Finding interface{} `json:"finding,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}

		// Resolve AI keys
		groqKey := cfg.Groq.APIKey
		anthropicKey := cfg.Anthropic.APIKey
		if aiSettings, err := db.GetSettingsPrefix(r.Context(), "ai"); err == nil {
			if v := aiSettings["groq_api_key"]; v != "" { groqKey = v }
			if v := aiSettings["anthropic_api_key"]; v != "" { anthropicKey = v }
		}
		if groqKey == "" && anthropicKey == "" {
			writeJSON(w, 503, map[string]string{"error": "No AI provider configured. Add a Groq or Anthropic API key in Settings → AI."})
			return
		}

		apiKey, model := groqKey, "llama-3.3-70b-versatile"
		if apiKey == "" { apiKey, model = anthropicKey, "claude-sonnet-4-20250514" }

		aiCtx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()

		text, err := callVulnAI(aiCtx, apiKey, model, req.Prompt)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "AI analysis failed: " + err.Error()})
			return
		}

		writeJSON(w, 200, map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": text},
			},
		})
	}
}
