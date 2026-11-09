package api

import (
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// clientIP returns the caller's address. X-Forwarded-For is honoured only when
// the direct peer is itself a private/loopback address (i.e. our own reverse
// proxy); the entry used is the right-most one that is not private, because a
// client can freely prepend fake entries on the left. Without this, anyone could
// rotate X-Forwarded-For to dodge the per-IP login limiter and forge audit IPs.
// RemoteAddr's port is also stripped so rate limiting keys on the host, not the connection.
func clientIP(r *http.Request) string {
	peer := r.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	pa, err := netip.ParseAddr(peer)
	if err != nil {
		return peer
	}
	pa = pa.Unmap()
	if !(pa.IsPrivate() || pa.IsLoopback()) {
		return pa.String()
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return pa.String()
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue
		}
		a = a.Unmap()
		if a.IsPrivate() || a.IsLoopback() {
			continue
		}
		return a.String()
	}
	// Every hop was private (internal client behind our proxy): use the left-most valid entry.
	for _, p := range parts {
		if a, err := netip.ParseAddr(strings.TrimSpace(p)); err == nil {
			return a.Unmap().String()
		}
	}
	return pa.String()
}

// validAgentAPIKey checks the X-API-Key header against the configured agent
// key using a constant-time comparison. M-02/M-03: several agent-facing
// endpoints (tunnel, register-key) previously trusted whatever agent_id the
// caller supplied with no key check at all, letting anyone impersonate any
// agent.
func validAgentAPIKey(expected string, r *http.Request) bool {
	if expected == "" {
		return false
	}
	got := r.Header.Get("X-API-Key")
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

// ── Auth ──────────────────────────────────────────────────────────────────────

// loginLimiter and loginIPLimiter are M-07 brute-force guards: without them
// an attacker can try unlimited password combinations against any username.
var (
	loginLimiter   = NewRateLimiter(1*time.Minute, 5)  // per-username
	loginIPLimiter = NewRateLimiter(1*time.Minute, 20) // per-IP (covers username spraying)
)

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
		ip := clientIP(r)
		if !loginIPLimiter.Allow(ip) || !loginLimiter.Allow(strings.ToLower(body.Username)) {
			writeJSON(w, 429, map[string]string{"error": "too many login attempts, try again later"})
			return
		}
		user, hash, err := db.GetUserByUsername(r.Context(), body.Username)
		if err != nil {
			// Same bcrypt cost for unknown users so response time does not reveal which usernames exist.
			store.CheckPassword(dummyPasswordHash, body.Password)
		}
		if err != nil || !store.CheckPassword(hash, body.Password) {
			db.WriteAudit(r.Context(), strings.ToLower(trimTo(body.Username, 64)), "login_failed", "", "", ip)
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

// handleWSTicket issues a short-lived single-use ticket for opening a WebSocket
// (browsers cannot send an Authorization header on one).
func handleWSTicket(w http.ResponseWriter, r *http.Request) {
	t, ok := auth.IssueWSTicket(auth.GetClaims(r))
	if !ok {
		writeJSON(w, 503, map[string]string{"error": "try again shortly"})
		return
	}
	writeJSON(w, 200, map[string]any{"ticket": t, "expires_in": 30})
}

// handleLogout (M-07): JWTs are stateless, so without this a stolen/leaked
// token stays valid until it naturally expires even after the user "logs
// out" in the UI. Revokes the presented token's JTI immediately.
func handleLogout(db *store.DB, jwt *auth.JWTService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		jwt.Revoke(claims)
		db.WriteAudit(r.Context(), claims.Username, "logout", "", "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func handleChangePassword(db *store.DB, jwt *auth.JWTService) http.HandlerFunc {
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
		if err := validatePassword(body.NewPassword, claims.Username, body.CurrentPassword); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
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
		// A password change must end every other session (a stolen token should
		// not survive it); hand back a fresh token so this session continues.
		jwt.RevokeUser(claims.UserID)
		resp := map[string]string{"status": "ok"}
		if tok, err := jwt.Sign(claims.UserID, claims.Username, claims.Role); err == nil {
			resp["token"] = tok
		}
		writeJSON(w, 200, resp)
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

const exportEventsLimit = 10000

// csvSafe (F-08): neutralizes CSV/spreadsheet formula injection. Fields
// here come from raw endpoint telemetry (process name, command line, etc)
// which an attacker fully controls — a command line starting with "=", "+",
// "-", or "@" is interpreted as a formula by Excel/Sheets/LibreOffice on
// open, which can exfiltrate data or run further commands on the analyst's
// machine. Prefixing with a tab neutralizes the formula while keeping the
// value human-readable.
func csvSafe(s string) string {
	if s != "" && strings.ContainsAny(s[:1], "=+-@") {
		return "\t" + s
	}
	return s
}

func handleExportEvents(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		f := parseEventFilter(r)
		f.Limit = exportEventsLimit + 1 // +1 so we can detect truncation
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "csv"
		}
		events, err := db.ExportEvents(r.Context(), f)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "export failed"})
			return
		}
		truncated := len(events) > exportEventsLimit
		if truncated {
			events = events[:exportEventsLimit]
		}
		db.WriteAudit(r.Context(), claims.Username, "export_events", "", fmt.Sprintf("count=%d format=%s truncated=%t", len(events), format, truncated), clientIP(r))

		if format == "json" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="obsidianwatch-events-%s.json"`, time.Now().Format("20060102-150405")))
			if truncated {
				w.Header().Set("X-Export-Truncated", "true")
			}
			json.NewEncoder(w).Encode(events)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="obsidianwatch-events-%s.csv"`, time.Now().Format("20060102-150405")))
		if truncated {
			w.Header().Set("X-Export-Truncated", "true")
		}
		cw := csv.NewWriter(w)
		cw.Write([]string{"time", "severity", "host", "os", "event_type", "source", "user_name", "process_name", "command_line", "src_ip", "src_port", "dst_ip", "dst_port", "proto"})
		for _, e := range events {
			cw.Write([]string{
				e.Time.Format(time.RFC3339), strconv.Itoa(e.Severity),
				csvSafe(e.Host), csvSafe(e.OS), csvSafe(e.EventType), csvSafe(e.Source),
				csvSafe(strPtr(e.UserName)), csvSafe(strPtr(e.ProcessName)), csvSafe(strPtr(e.CommandLine)),
				csvSafe(strPtr(e.SrcIP)), intPtr(e.SrcPort), csvSafe(strPtr(e.DstIP)), intPtr(e.DstPort), csvSafe(strPtr(e.Proto)),
			})
		}
		cw.Flush()
		if truncated {
			cw.Write([]string{"# NOTE: export truncated at " + strconv.Itoa(exportEventsLimit) + " rows; narrow your filters for a complete export"})
			cw.Flush()
		}
	}
}

func strPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func intPtr(i *int) string {
	if i == nil {
		return ""
	}
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
	if s := q.Get("severity"); s != "" {
		f.Severity, _ = strconv.Atoi(s)
	}
	if s := q.Get("dst_port"); s != "" {
		f.DstPort, _ = strconv.Atoi(s)
	}
	if s := q.Get("src_port"); s != "" {
		f.SrcPort, _ = strconv.Atoi(s)
	}
	if s := q.Get("event_id"); s != "" {
		v, _ := strconv.ParseUint(s, 10, 32)
		f.EventID = uint32(v)
	}
	if s := q.Get("since"); s != "" {
		f.Since, _ = time.Parse(time.RFC3339, s)
	}
	if s := q.Get("until"); s != "" {
		f.Until, _ = time.Parse(time.RFC3339, s)
	}
	if s := q.Get("limit"); s != "" {
		f.Limit, _ = strconv.Atoi(s)
	}
	if s := q.Get("offset"); s != "" {
		f.Offset, _ = strconv.Atoi(s)
	}
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

func handleStats(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if s := r.URL.Query().Get("hours"); s != "" {
			if v, err := strconv.Atoi(s); err == nil {
				hours = v
			}
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
			"windows_agents":  winCount, "linux_agents": linCount, "macos_agents": macCount,
			// Cloud
			"cloud_connectors": cloudConns,
			// DevOps
			"devops_connectors":   devopsConns,
			"sast_repos_scanned":  sastRepos,
			"sast_total_findings": sastFindings,
			"sast_critical_count": sastCritical,
			"sast_high_count":     sastHigh,
			"sast_medium_count":   sastMedium,
			"sast_results":        sastResults,
		})
	}
}

func handleHealth(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dbStatus := "ok"
		if err := db.HealthCheck(r.Context()); err != nil {
			dbStatus = "error: " + err.Error()
		}
		writeJSON(w, 200, map[string]interface{}{"status": "ok", "database": dbStatus, "time": time.Now().UTC()})
	}
}

func handleThreatIntel(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := db.ThreatIntel(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, data)
	}
}

// ── Alert detail ──────────────────────────────────────────────────────────────

// dummyPasswordHash is a valid bcrypt hash used to equalise login timing for
// unknown usernames.
var dummyPasswordHash = func() string {
	hh, _ := store.HashPassword("obsidianwatch-dummy-" + strconv.FormatInt(time.Now().UnixNano(), 36))
	return hh
}()

func trimTo(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
