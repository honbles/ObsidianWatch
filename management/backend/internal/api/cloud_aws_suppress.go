package api

// cloud_aws_suppress.go — suppression rules for AWS CSPM findings.
// Rules are kept as one JSON document in the settings table (no migration);
// applied inside RunAWSCSPM so manual, scheduled and CIS paths all honour them.
//
//	GET    /api/v1/cloud-connectors/suppress/aws
//	POST   /api/v1/cloud-connectors/suppress/aws
//	DELETE /api/v1/cloud-connectors/suppress/aws/{id}

import (
	"context"
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

const awsSuppressKey = "suppress:aws:rules"

type AWSSuppressRule struct {
	ID           int64      `json:"id"`
	AccountID    string     `json:"account_id,omitempty"`
	FindingTitle string     `json:"finding_title,omitempty"`
	Resource     string     `json:"resource,omitempty"`
	Category     string     `json:"category,omitempty"`
	Severity     string     `json:"severity,omitempty"`
	Reason       string     `json:"reason"`
	CreatedBy    string     `json:"created_by,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type AWSSuppressor struct {
	db    *store.DB
	mu    sync.RWMutex
	rules []AWSSuppressRule
}

var activeAWSSuppressor *AWSSuppressor

func NewAWSSuppressor(db *store.DB) *AWSSuppressor {
	s := &AWSSuppressor{db: db}
	s.reload(context.Background())
	return s
}

func (s *AWSSuppressor) reload(ctx context.Context) {
	if s.db == nil {
		return
	}
	val, err := s.db.GetSetting(ctx, awsSuppressKey)
	if err != nil || val == "" {
		return
	}
	var rules []AWSSuppressRule
	if json.Unmarshal([]byte(val), &rules) != nil {
		return
	}
	s.mu.Lock()
	s.rules = rules
	s.mu.Unlock()
}

func (s *AWSSuppressor) save(ctx context.Context) error {
	b, _ := json.Marshal(s.rules)
	return s.db.SetSetting(ctx, awsSuppressKey, string(b))
}

func (s *AWSSuppressor) ShouldSuppress(f CSPMFinding, accountID string) bool {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.rules {
		if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
			continue
		}
		if r.AccountID != "" && r.AccountID != accountID {
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

func (s *AWSSuppressor) ListRules() []AWSSuppressRule {
	s.reload(context.Background())
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]AWSSuppressRule{}, s.rules...)
}

func (s *AWSSuppressor) AddRule(r AWSSuppressRule) (AWSSuppressRule, error) {
	if s.db == nil {
		return r, fmt.Errorf("no database")
	}
	s.reload(context.Background())
	s.mu.Lock()
	defer s.mu.Unlock()
	var next int64 = 1
	for _, x := range s.rules {
		if x.ID >= next {
			next = x.ID + 1
		}
	}
	r.ID, r.CreatedAt = next, time.Now().UTC()
	s.rules = append(s.rules, r)
	if err := s.save(context.Background()); err != nil {
		s.rules = s.rules[:len(s.rules)-1]
		return r, err
	}
	return r, nil
}

func (s *AWSSuppressor) DeleteRule(id int64) bool {
	if s.db == nil {
		return false
	}
	s.reload(context.Background())
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.rules {
		if x.ID == id {
			old := s.rules
			s.rules = append(append([]AWSSuppressRule{}, old[:i]...), old[i+1:]...)
			if s.save(context.Background()) != nil {
				s.rules = old
				return false
			}
			return true
		}
	}
	return false
}

func handleListAWSSuppressRules(s *AWSSuppressor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules := s.ListRules()
		writeJSON(w, 200, map[string]interface{}{"rules": rules, "total": len(rules)})
	}
}

func handleCreateAWSSuppressRule(s *AWSSuppressor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AWSSuppressRule
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if req.Reason == "" {
			writeJSON(w, 400, map[string]string{"error": "reason is required"})
			return
		}
		if req.AccountID == "" && req.FindingTitle == "" && req.Resource == "" && req.Category == "" && req.Severity == "" {
			writeJSON(w, 400, map[string]string{"error": "at least one matcher (account_id, finding_title, resource, category, severity) is required"})
			return
		}
		if c := auth.GetClaims(r); c != nil {
			req.CreatedBy = c.Username
		}
		rule, err := s.AddRule(req)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not save rule"})
			return
		}
		writeJSON(w, 201, rule)
	}
}

func handleDeleteAWSSuppressRule(s *AWSSuppressor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		if s.DeleteRule(id) {
			writeJSON(w, 200, map[string]string{"status": "deleted"})
		} else {
			writeJSON(w, 404, map[string]string{"error": "rule not found"})
		}
	}
}
