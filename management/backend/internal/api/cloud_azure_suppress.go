package api

// cloud_azure_suppress.go — Alert suppression engine for Azure CSPM findings.
// Mirrors cloud_gcp_suppress.go in structure.
//
// Routes (registered in server.go):
//   GET    /api/v1/cloud-connectors/suppress/azure     — list Azure rules
//   POST   /api/v1/cloud-connectors/suppress/azure     — create Azure rule
//   DELETE /api/v1/cloud-connectors/suppress/azure/{id} — delete Azure rule

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// AzureSuppressRule defines a suppression or allowlist rule for Azure findings.
type AzureSuppressRule struct {
	ID          int64     `json:"id"`
	SubscriptionID string `json:"subscription_id,omitempty"` // empty = all subscriptions
	FindingTitle string  `json:"finding_title,omitempty"` // substring match
	Resource     string  `json:"resource,omitempty"`      // exact or prefix
	Category     string  `json:"category,omitempty"`
	Severity     string  `json:"severity,omitempty"`
	Reason       string  `json:"reason"`
	CreatedBy    string  `json:"created_by,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// AzureSuppressor manages suppression rules for Azure CSPM findings.
//
// AZ-06: rules are persisted in azure_suppress_rules (they used to live in a
// slice that was lost on restart, with IDs resetting to 1), guarded by a
// mutex, and actually applied: see applyAzureSuppression, called wherever a
// CSPM scan result is produced.
type AzureSuppressor struct {
	db    *store.DB
	mu    sync.RWMutex
	rules []AzureSuppressRule
}

// activeAzureSuppressor is the process-wide suppressor, set by
// NewCloudConnectorEngine so scan paths outside the engine (the manual
// "run CSPM" handler) honour the same rules.
var activeAzureSuppressor *AzureSuppressor

func NewAzureSuppressor(db *store.DB) *AzureSuppressor {
	s := &AzureSuppressor{db: db}
	s.reload(context.Background())
	return s
}

func (s *AzureSuppressor) reload(ctx context.Context) {
	if s.db == nil {
		return
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, subscription_id, finding_title, resource, category, severity,
		       reason, created_by, expires_at, created_at
		FROM azure_suppress_rules ORDER BY id`)
	if err != nil {
		return
	}
	defer rows.Close()
	var out []AzureSuppressRule
	for rows.Next() {
		var r AzureSuppressRule
		var exp sql.NullTime
		if rows.Scan(&r.ID, &r.SubscriptionID, &r.FindingTitle, &r.Resource, &r.Category,
			&r.Severity, &r.Reason, &r.CreatedBy, &exp, &r.CreatedAt) != nil {
			continue
		}
		if exp.Valid {
			t := exp.Time
			r.ExpiresAt = &t
		}
		out = append(out, r)
	}
	s.mu.Lock()
	s.rules = out
	s.mu.Unlock()
}

// ShouldSuppress returns true if the given finding matches a suppression rule.
func (s *AzureSuppressor) ShouldSuppress(f CSPMFinding, subscriptionID string) bool {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.rules {
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			continue
		}
		if r.SubscriptionID != "" && r.SubscriptionID != subscriptionID {
			continue
		}
		if r.FindingTitle != "" && !strings.Contains(strings.ToLower(f.Title), strings.ToLower(r.FindingTitle)) {
			continue
		}
		if r.Resource != "" && !strings.HasPrefix(f.Resource, r.Resource) {
			continue
		}
		if r.Category != "" && r.Category != f.Category {
			continue
		}
		if r.Severity != "" && r.Severity != f.Severity {
			continue
		}
		return true
	}
	return false
}

// ApplySuppression marks findings as suppressed in place.
func (s *AzureSuppressor) ApplySuppression(result *AzureCSPMResult) {
	for i := range result.Findings {
		if s.ShouldSuppress(result.Findings[i], result.SubscriptionID) {
			result.Findings[i].Status = "suppressed"
		}
	}
}

// applyAzureSuppression is the nil-safe package entry point.
func applyAzureSuppression(result *AzureCSPMResult) {
	if activeAzureSuppressor != nil && result != nil {
		activeAzureSuppressor.ApplySuppression(result)
	}
}

func (s *AzureSuppressor) ListRules() []AzureSuppressRule {
	s.reload(context.Background())
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AzureSuppressRule, len(s.rules))
	copy(out, s.rules)
	return out
}

func (s *AzureSuppressor) AddRule(r AzureSuppressRule) (AzureSuppressRule, error) {
	if s.db == nil {
		return r, fmt.Errorf("no database")
	}
	err := s.db.QueryRowContext(context.Background(), `
		INSERT INTO azure_suppress_rules
		  (subscription_id, finding_title, resource, category, severity, reason, created_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, created_at`,
		r.SubscriptionID, r.FindingTitle, r.Resource, r.Category, r.Severity,
		r.Reason, r.CreatedBy, r.ExpiresAt).Scan(&r.ID, &r.CreatedAt)
	if err != nil {
		return r, err
	}
	s.reload(context.Background())
	return r, nil
}

func (s *AzureSuppressor) DeleteRule(id int64) bool {
	if s.db == nil {
		return false
	}
	res, err := s.db.ExecContext(context.Background(), `DELETE FROM azure_suppress_rules WHERE id=$1`, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	s.reload(context.Background())
	return n > 0
}

// HTTP handlers

func handleListAzureSuppressRules(sup *AzureSuppressor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{
			"rules": sup.ListRules(),
			"total": len(sup.ListRules()),
		})
	}
}

func handleCreateAzureSuppressRule(sup *AzureSuppressor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AzureSuppressRule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request: " + err.Error()})
			return
		}
		if req.Reason == "" {
			writeJSON(w, 400, map[string]string{"error": "reason is required"})
			return
		}
		// A suppression rule with no matcher would silence every finding.
		if req.SubscriptionID == "" && req.FindingTitle == "" && req.Resource == "" && req.Category == "" && req.Severity == "" {
			writeJSON(w, 400, map[string]string{"error": "at least one matcher (subscription_id, finding_title, resource, category, severity) is required"})
			return
		}
		if c := auth.GetClaims(r); c != nil {
			req.CreatedBy = c.Username
		}
		rule, err := sup.AddRule(req)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not save rule"})
			return
		}
		writeJSON(w, 201, rule)
	}
}

func handleDeleteAzureSuppressRule(sup *AzureSuppressor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		if sup.DeleteRule(id) {
			writeJSON(w, 200, map[string]string{"status": "deleted", "id": fmt.Sprintf("%d", id)})
		} else {
			writeJSON(w, 404, map[string]string{"error": "rule not found"})
		}
	}
}
