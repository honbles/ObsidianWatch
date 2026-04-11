package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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
	// Catch-up: scan last 1h on first start so recent events get evaluated.
	// Deliberately short (not 24h) to avoid alert spam on every restart.
	e.evaluateSince(ctx, time.Now().Add(-2*time.Hour))

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.evaluate(ctx)
		}
	}
}

func (e *AlertEngine) evaluate(ctx context.Context) {
	// 45s window: slightly more than the 30s tick to handle late-arriving events,
	// but narrow enough to minimise re-evaluation overlap between cycles.
	e.evaluateSince(ctx, time.Now().Add(-45*time.Second))
}

func (e *AlertEngine) evaluateSince(ctx context.Context, since time.Time) {
	rules, err := e.db.GetEnabledRules(ctx)
	if err != nil {
		e.logger.Warn("alert engine: failed to load rules", "err", err)
		return
	}
	if len(rules) == 0 {
		return
	}

	f := store.EventFilter{Since: since, Limit: 2000}
	events, _, err := e.db.QueryEvents(ctx, f)
	if err != nil {
		e.logger.Warn("alert engine: failed to query events", "err", err)
		return
	}

	created := 0
	for _, ev := range events {
		eventIDStr := fmt.Sprintf("%v", ev.EventID)
		for _, rule := range rules {
			if !matchesRule(ev, rule) {
				continue
			}

			// Dedup key: one alert per rule+host+hour
			// Prevents spam when many events match the same rule in a short window
			hour := ev.Time.UTC().Format("2006010215")
			dedupKey := fmt.Sprintf("rule:%d:host:%s:h:%s", rule.ID, ev.Host, hour)

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
				go func(a store.Alert, alertID int64) {
					a.ID = alertID
					if err := e.mailer.SendAlert(a); err != nil {
						e.logger.Warn("alert engine: email failed", "alert_id", alertID, "err", err)
					} else {
						e.logger.Info("alert engine: email sent", "alert_id", alertID)
					}
				}(alert, id)
			}
		}
	}
	if created > 0 {
		e.logger.Info("alert engine: created alerts", "count", created)
	}
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
	if rule.HostMatch != "" && !strings.Contains(strings.ToLower(ev.Host), strings.ToLower(rule.HostMatch)) {
		return false
	}
	if rule.UserMatch != "" {
		if ev.UserName == nil || !strings.Contains(strings.ToLower(*ev.UserName), strings.ToLower(rule.UserMatch)) {
			return false
		}
	}
	if rule.ProcessMatch != "" {
		if ev.ProcessName == nil || !strings.Contains(strings.ToLower(*ev.ProcessName), strings.ToLower(rule.ProcessMatch)) {
			return false
		}
	}
	if rule.CommandLineMatch != "" {
		if ev.CommandLine == nil || !strings.Contains(strings.ToLower(*ev.CommandLine), strings.ToLower(rule.CommandLineMatch)) {
			return false
		}
	}
	if rule.SrcIPMatch != "" {
		if ev.SrcIP == nil || !strings.Contains(strings.ToLower(*ev.SrcIP), strings.ToLower(rule.SrcIPMatch)) {
			return false
		}
	}
	if rule.DstIPMatch != "" {
		if ev.DstIP == nil || !strings.Contains(strings.ToLower(*ev.DstIP), strings.ToLower(rule.DstIPMatch)) {
			return false
		}
	}
	if rule.DNSMatch != "" {
		if ev.EventType != "dns" || ev.DstIP == nil || !strings.Contains(strings.ToLower(*ev.DstIP), strings.ToLower(rule.DNSMatch)) {
			return false
		}
	}
	if rule.SourceMatch != "" && !strings.Contains(strings.ToLower(ev.Source), strings.ToLower(rule.SourceMatch)) {
		return false
	}
	return true
}
