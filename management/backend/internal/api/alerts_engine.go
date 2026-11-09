package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/notify"
	"obsidianwatch/management/internal/store"
)

type AlertEngine struct {
	db     *store.DB
	mailer *notify.Mailer
	logger *slog.Logger
}

func NewAlertEngine(db *store.DB, mailer *notify.Mailer, logger *slog.Logger) *AlertEngine {
	return &AlertEngine{db: db, mailer: mailer, logger: logger}
}

func (e *AlertEngine) Run(ctx context.Context) {
	// D-01/D-02: cursor-based paging over events.ingested_at — see
	// pageEventCursor. First run falls back to a 2h lookback; every run
	// after that resumes exactly where the last one left off, so a burst
	// or a backlogged agent can't fall outside a fixed wall-clock window.
	e.runCursor(ctx)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.runCursor(ctx)
		}
	}
}

func (e *AlertEngine) runCursor(ctx context.Context) {
	rules, err := e.db.GetEnabledRules(ctx)
	if err != nil {
		e.logger.Warn("alert engine: failed to load rules", "err", err)
		return
	}
	if len(rules) == 0 {
		return
	}

	events, err := pageEventCursor(ctx, e.db, "alerts", store.EventFilter{}, 2*time.Hour, 2000)
	if err != nil {
		e.logger.Warn("alert engine: cursor query failed", "err", err)
		return
	}

	created := 0
	for _, ev := range events {
		eventIDStr := fmt.Sprintf("%v", ev.EventID)
		for _, rule := range rules {
			if !matchesRule(ev, rule) {
				continue
			}
			if !thresholdReached(rule, ev.Host, ev.Time) {
				continue
			}

			// Dedup key: one alert per rule+host+hour
			// Prevents spam when many events match the same rule in a short window
			hour := ev.Time.UTC().Format("2006010215")
			dedupKey := fmt.Sprintf("rule:%d:host:%s:h:%s:e:%s", rule.ID, ev.Host, hour, alertEntityKey(ev)) // D-06: entity fingerprint folded in

			title := fmt.Sprintf("[%s] %s on %s", rule.Name, ev.EventType, ev.Host)
			desc := fmt.Sprintf("Rule '%s' triggered by %s event (severity %d) on host %s at %s",
				rule.Name, ev.EventType, ev.Severity, ev.Host, ev.Time.Format(time.RFC3339))
			if ev.ProcessName != nil && *ev.ProcessName != "" {
				desc += fmt.Sprintf(" | Process: %s", *ev.ProcessName)
			}
			if ev.UserName != nil && *ev.UserName != "" {
				desc += fmt.Sprintf(" | User: %s", *ev.UserName)
			}
			if eventIDStr != "<nil>" && eventIDStr != "0" {
				desc += fmt.Sprintf(" | EventID: %s", eventIDStr)
			}

			alert := store.Alert{
				Title:         title,
				Description:   desc,
				Severity:      ev.Severity,
				AgentID:       ev.AgentID,
				Host:          ev.Host,
				EventType:     ev.EventType,
				EventID:       dedupKey,
				SourceEventID: ev.ID,
			}

			// Atomic insert — ON CONFLICT DO NOTHING prevents race-condition dupes.
			id, inserted, err := e.db.CreateAlertDeduped(ctx, alert)
			if err != nil {
				e.logger.Warn("alert engine: create alert failed", "err", err)
				continue
			}
			if !inserted {
				continue // duplicate — already alerted
			}

			alert.CreatedAt = time.Now()
			created++

			// Send email if severity meets threshold
			if e.mailer.Enabled() && ev.Severity >= e.mailer.MinSeverity() {
				alert.ID = id
				e.mailer.QueueAlert(alert)
			}
		}
	}
	if created > 0 {
		e.logger.Info("alert engine: created alerts", "count", created)
	}
}

// D-09: field matching supports "substring" (default, case-insensitive) and
// "regex" modes. Regexes are compiled once and cached; an invalid regex never
// matches (and is rejected at save time by validateRule).
var (
	ruleRegexMu    sync.Mutex
	ruleRegexCache = map[string]*regexp.Regexp{}
)

func ruleRegex(pat string) *regexp.Regexp {
	ruleRegexMu.Lock()
	defer ruleRegexMu.Unlock()
	if re, ok := ruleRegexCache[pat]; ok {
		return re
	}
	re, err := regexp.Compile("(?i)" + pat)
	if err != nil {
		re = nil
	}
	if len(ruleRegexCache) > 2000 {
		ruleRegexCache = map[string]*regexp.Regexp{}
	}
	ruleRegexCache[pat] = re
	return re
}

func fieldMatches(mode, pattern, value string) bool {
	if mode == "regex" {
		re := ruleRegex(pattern)
		return re != nil && re.MatchString(value)
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
}

func strVal(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// validateRule checks a rule before saving (regexes compile, sane threshold).
func validateRule(r *store.AlertRule) error {
	if r.MatchMode == "" {
		r.MatchMode = "substring"
	}
	if r.MatchMode != "substring" && r.MatchMode != "regex" {
		return fmt.Errorf("match_mode must be substring or regex")
	}
	if r.MatchMode == "regex" {
		for _, p := range []string{r.HostMatch, r.UserMatch, r.ProcessMatch, r.CommandLineMatch,
			r.SrcIPMatch, r.DstIPMatch, r.DNSMatch, r.SourceMatch, r.ExcludeHost, r.ExcludeUser, r.ExcludeProcess} {
			if p == "" {
				continue
			}
			if len(p) > 500 {
				return fmt.Errorf("pattern too long")
			}
			if _, err := regexp.Compile("(?i)" + p); err != nil {
				return fmt.Errorf("invalid regex %q: %v", p, err)
			}
		}
	}
	if r.ThresholdCount < 0 || r.ThresholdCount > 100000 {
		return fmt.Errorf("threshold_count out of range")
	}
	if r.ThresholdCount > 1 && (r.ThresholdWindowSec < 1 || r.ThresholdWindowSec > 86400) {
		return fmt.Errorf("threshold_window_sec must be 1..86400 when threshold_count > 1")
	}
	return nil
}

// ruleThreshold tracks match timestamps per rule+host for threshold rules.
var (
	ruleThreshMu sync.Mutex
	ruleThresh   = map[string][]time.Time{}
)

// thresholdReached records a match and reports whether the rule's threshold
// (N matches on the same host within the window) is now met. The window is
// cleared on firing so the next alert needs a fresh N matches.
func thresholdReached(rule store.AlertRule, host string, at time.Time) bool {
	if rule.ThresholdCount <= 1 {
		return true
	}
	key := fmt.Sprintf("%d|%s", rule.ID, host)
	win := time.Duration(rule.ThresholdWindowSec) * time.Second
	ruleThreshMu.Lock()
	defer ruleThreshMu.Unlock()
	if len(ruleThresh) > 50000 {
		ruleThresh = map[string][]time.Time{}
	}
	cut := at.Add(-win)
	kept := ruleThresh[key][:0]
	for _, t := range ruleThresh[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, at)
	if len(kept) >= rule.ThresholdCount {
		delete(ruleThresh, key)
		return true
	}
	ruleThresh[key] = kept
	return false
}

func matchesRule(ev store.Event, rule store.AlertRule) bool {
	if ev.Severity < rule.Severity {
		return false
	}
	if rule.EventType != "" && ev.EventType != rule.EventType {
		return false
	}
	if rule.OSMatch != "" && !strings.EqualFold(ev.OS, rule.OSMatch) {
		return false
	}
	m := rule.MatchMode
	if rule.HostMatch != "" && !fieldMatches(m, rule.HostMatch, ev.Host) {
		return false
	}
	if rule.UserMatch != "" && (ev.UserName == nil || !fieldMatches(m, rule.UserMatch, *ev.UserName)) {
		return false
	}
	if rule.ProcessMatch != "" && (ev.ProcessName == nil || !fieldMatches(m, rule.ProcessMatch, *ev.ProcessName)) {
		return false
	}
	if rule.CommandLineMatch != "" && (ev.CommandLine == nil || !fieldMatches(m, rule.CommandLineMatch, *ev.CommandLine)) {
		return false
	}
	if rule.SrcIPMatch != "" && (ev.SrcIP == nil || !fieldMatches(m, rule.SrcIPMatch, *ev.SrcIP)) {
		return false
	}
	if rule.DstIPMatch != "" && (ev.DstIP == nil || !fieldMatches(m, rule.DstIPMatch, *ev.DstIP)) {
		return false
	}
	if rule.DNSMatch != "" && (ev.EventType != "dns" || ev.DstIP == nil || !fieldMatches(m, rule.DNSMatch, *ev.DstIP)) {
		return false
	}
	if rule.SourceMatch != "" && !fieldMatches(m, rule.SourceMatch, ev.Source) {
		return false
	}
	// Exclusions (D-09)
	if rule.ExcludeHost != "" && fieldMatches(m, rule.ExcludeHost, ev.Host) {
		return false
	}
	if rule.ExcludeUser != "" && fieldMatches(m, rule.ExcludeUser, strVal(ev.UserName)) {
		return false
	}
	if rule.ExcludeProcess != "" && fieldMatches(m, rule.ExcludeProcess, strVal(ev.ProcessName)) {
		return false
	}
	return true
}

// handleTestAlertRule is a dry run: it evaluates a draft rule against the last
// N hours of events and returns the match count and a sample, without creating
// alerts. Thresholds are ignored in the dry run (it reports raw matches).
func handleTestAlertRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var req struct {
			Rule  store.AlertRule `json:"rule"`
			Hours int             `json:"hours"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if err := validateRule(&req.Rule); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if req.Hours <= 0 || req.Hours > 168 {
			req.Hours = 24
		}
		events, _, err := db.QueryEvents(r.Context(), store.EventFilter{
			Since: time.Now().Add(-time.Duration(req.Hours) * time.Hour),
			Limit: 20000,
		})
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		matches := 0
		hosts := map[string]int{}
		type sample struct {
			Time    time.Time `json:"time"`
			Host    string    `json:"host"`
			Type    string    `json:"event_type"`
			Process string    `json:"process,omitempty"`
			Cmd     string    `json:"command_line,omitempty"`
		}
		var samples []sample
		for _, ev := range events {
			if !matchesRule(ev, req.Rule) {
				continue
			}
			matches++
			hosts[ev.Host]++
			if len(samples) < 20 {
				cmd := strVal(ev.CommandLine)
				if len(cmd) > 200 {
					cmd = cmd[:200]
				}
				samples = append(samples, sample{ev.Time, ev.Host, ev.EventType, strVal(ev.ProcessName), cmd})
			}
		}
		writeJSON(w, 200, map[string]interface{}{
			"hours_evaluated":  req.Hours,
			"events_evaluated": len(events),
			"matches":          matches,
			"hosts_affected":   len(hosts),
			"sample":           samples,
			"truncated":        len(events) >= 20000,
		})
	}
}
