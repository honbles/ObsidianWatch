package api

// endpoint_suppress.go — suppression / allowlist rules for endpoint
// detections (D-10; only cloud had one before). A rule needs a reason, at
// least one matcher, and should normally carry an expiry.
//
//   GET    /api/v1/suppressions
//   POST   /api/v1/suppressions
//   DELETE /api/v1/suppressions/{id}

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

type EndpointSuppression struct {
	ID          int64      `json:"id"`
	RuleID      string     `json:"rule_id"`
	Host        string     `json:"host"`
	ProcessName string     `json:"process_name"`
	Reason      string     `json:"reason"`
	CreatedBy   string     `json:"created_by"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type endpointSuppressor struct {
	mu    sync.RWMutex
	rules []EndpointSuppression
}

var endpointSupp = &endpointSuppressor{}

func loadEndpointSuppressions(ctx context.Context, db *store.DB) ([]EndpointSuppression, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, rule_id, host, process_name, reason, created_by, expires_at, created_at
		FROM endpoint_suppressions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EndpointSuppression
	for rows.Next() {
		var r EndpointSuppression
		var exp sql.NullTime
		if err := rows.Scan(&r.ID, &r.RuleID, &r.Host, &r.ProcessName, &r.Reason, &r.CreatedBy, &exp, &r.CreatedAt); err != nil {
			continue
		}
		if exp.Valid {
			t := exp.Time
			r.ExpiresAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// refreshEndpointSuppressions reloads the rules (called once per evaluation cycle).
func refreshEndpointSuppressions(ctx context.Context, db *store.DB) {
	if rules, err := loadEndpointSuppressions(ctx, db); err == nil {
		endpointSupp.mu.Lock()
		endpointSupp.rules = rules
		endpointSupp.mu.Unlock()
	}
}

// endpointSuppressed reports whether a (rule, event) pair is suppressed.
func endpointSuppressed(sigID string, ev store.Event) bool {
	now := time.Now()
	proc := ""
	if ev.ProcessName != nil {
		proc = strings.ToLower(*ev.ProcessName)
	}
	endpointSupp.mu.RLock()
	defer endpointSupp.mu.RUnlock()
	for _, r := range endpointSupp.rules {
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			continue
		}
		if r.RuleID != "" && sigID != r.RuleID && !strings.HasPrefix(sigID, r.RuleID) {
			continue
		}
		if r.Host != "" && !strings.EqualFold(r.Host, ev.Host) {
			continue
		}
		if r.ProcessName != "" && strings.ToLower(r.ProcessName) != proc {
			continue
		}
		return true
	}
	return false
}

func handleListSuppressions(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := loadEndpointSuppressions(r.Context(), db)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		if rules == nil {
			rules = []EndpointSuppression{}
		}
		writeJSON(w, 200, map[string]interface{}{"rules": rules, "total": len(rules)})
	}
}

func handleCreateSuppression(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var req EndpointSuppression
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		req.Reason = strings.TrimSpace(req.Reason)
		if req.Reason == "" || len(req.Reason) > 500 {
			writeJSON(w, 400, map[string]string{"error": "reason is required (max 500 chars)"})
			return
		}
		if req.RuleID == "" && req.Host == "" && req.ProcessName == "" {
			writeJSON(w, 400, map[string]string{"error": "at least one of rule_id, host, process_name is required"})
			return
		}
		// A rule-less, host-wide or process-wide mute would silence every
		// detection for that scope; require a rule_id for those.
		if req.RuleID == "" {
			writeJSON(w, 400, map[string]string{"error": "rule_id is required: suppressing all rules for a host/process is not allowed"})
			return
		}
		if len(req.RuleID) > 64 || len(req.Host) > 255 || len(req.ProcessName) > 255 {
			writeJSON(w, 400, map[string]string{"error": "field too long"})
			return
		}
		actor := ""
		if c := auth.GetClaims(r); c != nil {
			actor = c.Username
		}
		var id int64
		err := db.QueryRowContext(r.Context(), `
			INSERT INTO endpoint_suppressions (rule_id, host, process_name, reason, created_by, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
			req.RuleID, req.Host, req.ProcessName, req.Reason, actor, req.ExpiresAt).Scan(&id)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not save rule"})
			return
		}
		db.WriteAudit(r.Context(), actor, "create_suppression", "suppression:"+strconv.FormatInt(id, 10), req.Reason, clientIP(r))
		refreshEndpointSuppressions(r.Context(), db)
		req.ID, req.CreatedBy, req.CreatedAt = id, actor, time.Now()
		writeJSON(w, 201, req)
	}
}

func handleDeleteSuppression(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		res, err := db.ExecContext(r.Context(), `DELETE FROM endpoint_suppressions WHERE id=$1`, id)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "delete failed"})
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			writeJSON(w, 404, map[string]string{"error": "rule not found"})
			return
		}
		actor := ""
		if c := auth.GetClaims(r); c != nil {
			actor = c.Username
		}
		db.WriteAudit(r.Context(), actor, "delete_suppression", "suppression:"+strconv.FormatInt(id, 10), "", clientIP(r))
		refreshEndpointSuppressions(r.Context(), db)
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}
