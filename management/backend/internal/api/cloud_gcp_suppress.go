package api

// cloud_gcp_suppress.go — Alert suppression and allowlist engine for GCP.
//
// Prevents alert fatigue from high-volume but legitimate activity.
// Suppression rules are stored in the settings table under "suppress:gcp:*"
// and evaluated before any GCP signature match fires an alert.
//
// A suppression rule can match on:
//   - Signature ID (exact or prefix)
//   - Principal email (exact or suffix, e.g. "@mycompany.gserviceaccount.com")
//   - Source IP CIDR (simple prefix match)
//   - Method name (contains)
//   - Time window (UTC hour range, e.g. 08-18 for business hours only)
//   - Expiry (suppress until a specific time)
//
// API endpoints (registered in server.go):
//   GET    /api/v1/cloud-connectors/suppress        — list rules
//   POST   /api/v1/cloud-connectors/suppress        — create rule
//   DELETE /api/v1/cloud-connectors/suppress/{id}   — delete rule

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// GCPSuppressRule defines a single suppression entry.
type GCPSuppressRule struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	SigID       string    `json:"sig_id"`        // e.g. "C-GCP-025" or "C-GCP-" (prefix)
	Principal   string    `json:"principal"`     // e.g. "ci-cd@proj.iam.gserviceaccount.com" or "@gserviceaccount.com"
	SrcIPPrefix string    `json:"src_ip_prefix"` // e.g. "10.128." or "34.90."
	MethodContains string `json:"method_contains"`
	HourFrom    int       `json:"hour_from"`    // 0-23 UTC, suppress OUTSIDE this range
	HourTo      int       `json:"hour_to"`      // 0-23 UTC
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// GCPSuppressor holds the loaded rules and evaluates events against them.
type GCPSuppressor struct {
	db    *store.DB
	mu    sync.RWMutex // G-33: rules are refreshed by one goroutine and read by many
	rules []GCPSuppressRule // refreshed periodically
}

func NewGCPSuppressor(db *store.DB) *GCPSuppressor {
	return &GCPSuppressor{db: db}
}

// Refresh reloads suppression rules from the DB. Call before each detection cycle.
func (s *GCPSuppressor) Refresh(ctx context.Context) {
	rules, err := s.loadRules(ctx)
	if err == nil {
		s.mu.Lock()
		s.rules = rules
		s.mu.Unlock()
	}
}

// IsSuppressed returns true if the given event+sigID should be suppressed.
func (s *GCPSuppressor) IsSuppressed(sigID string, ev store.Event) bool {
	now := time.Now().UTC()
	principal := ""
	if ev.UserName != nil {
		principal = *ev.UserName
	}
	srcIP := ""
	if ev.SrcIP != nil {
		srcIP = *ev.SrcIP
	}
	method := extractMethod(ev)
	hour := ev.Time.UTC().Hour()

	s.mu.RLock()
	rulesSnap := s.rules
	s.mu.RUnlock()
	for _, rule := range rulesSnap {
		// Skip expired rules
		if !rule.ExpiresAt.IsZero() && rule.ExpiresAt.Before(now) {
			continue
		}

		// Match sig ID (exact or prefix)
		if rule.SigID != "" {
			if !strings.HasPrefix(sigID, rule.SigID) && sigID != rule.SigID {
				continue
			}
		}

		// Match principal (exact or suffix)
		if rule.Principal != "" {
			if !strings.EqualFold(principal, rule.Principal) &&
				!strings.HasSuffix(strings.ToLower(principal), strings.ToLower(rule.Principal)) {
				continue
			}
		}

		// Match source IP prefix
		if rule.SrcIPPrefix != "" {
			if !strings.HasPrefix(srcIP, rule.SrcIPPrefix) {
				continue
			}
		}

		// Match method contains
		if rule.MethodContains != "" {
			if !strings.Contains(strings.ToLower(method), strings.ToLower(rule.MethodContains)) {
				continue
			}
		}

		// Match time window (if both set, suppress WITHIN window)
		if rule.HourFrom > 0 || rule.HourTo > 0 {
			inWindow := false
			if rule.HourFrom <= rule.HourTo {
				inWindow = hour >= rule.HourFrom && hour <= rule.HourTo
			} else {
				// Wraps midnight
				inWindow = hour >= rule.HourFrom || hour <= rule.HourTo
			}
			if !inWindow {
				continue // Outside suppression window — don't suppress
			}
		}

		// All specified criteria matched — suppress
		return true
	}
	return false
}

// ── Persistence ───────────────────────────────────────────────────────────────

func (s *GCPSuppressor) loadRules(ctx context.Context) ([]GCPSuppressRule, error) {
	vals, err := s.db.GetSettingsPrefix(ctx, "suppress:gcp")
	if err != nil {
		return nil, err
	}
	var rules []GCPSuppressRule
	for _, v := range vals {
		var r GCPSuppressRule
		if err := json.Unmarshal([]byte(v), &r); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func (s *GCPSuppressor) SaveRule(ctx context.Context, r GCPSuppressRule) error {
	if r.ID == "" {
		r.ID = fmt.Sprintf("sr-%d", time.Now().UnixNano())
	}
	r.CreatedAt = time.Now()
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.db.SetSetting(ctx, "suppress:gcp:"+r.ID, string(data))
}

func (s *GCPSuppressor) DeleteRule(ctx context.Context, id string) error {
	_, err := s.db.GetSetting(ctx, "suppress:gcp:"+id)
	if err != nil {
		return fmt.Errorf("rule not found")
	}
	return s.db.SetSetting(ctx, "suppress:gcp:"+id, "")
}

func (s *GCPSuppressor) ListRules(ctx context.Context) ([]GCPSuppressRule, error) {
	return s.loadRules(ctx)
}

// ── HTTP Handlers ─────────────────────────────────────────────────────────────

func handleListGCPSuppressRules(suppressor *GCPSuppressor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := suppressor.ListRules(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if rules == nil {
			rules = []GCPSuppressRule{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rules)
	}
}

func handleCreateGCPSuppressRule(suppressor *GCPSuppressor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rule GCPSuppressRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		if rule.Description == "" {
			http.Error(w, "description required", 400)
			return
		}
		// At least one criterion must be set
		if rule.SigID == "" && rule.Principal == "" && rule.SrcIPPrefix == "" && rule.MethodContains == "" {
			http.Error(w, "at least one of sig_id, principal, src_ip_prefix, method_contains must be set", 400)
			return
		}
		// Extract caller from JWT context if available
		if u := r.Context().Value("username"); u != nil {
			rule.CreatedBy = fmt.Sprintf("%v", u)
		}
		if err := suppressor.SaveRule(r.Context(), rule); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(rule)
	}
}

func handleDeleteGCPSuppressRule(suppressor *GCPSuppressor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "id required", 400)
			return
		}
		if err := suppressor.DeleteRule(r.Context(), id); err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
