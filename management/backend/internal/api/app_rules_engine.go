package api

// app_rules_engine.go - runs the Application rules inside the management backend.
//
// Events: the foundation calls every registered sig provider once per event it evaluates
// (after its own-agent-activity filter). The provider registered below returns no signatures; it is
// only a tap that hands the event to the rule worker through a bounded, non-blocking queue.
// Aggregates: a one-minute ticker runs the data-driven rules (Scan).
// Alerts never go through the engine's signature path (its severity is static and its dedup is per
// host); they are created by appPGEmitter after ruleGate and appWeigh.

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"obsidianwatch/management/internal/store"
)

const (
	appRuleQueueSize = 20000
	appScanInterval  = time.Minute
)

// appEngine is the running instance (one per process).
type appEngine struct {
	rules   *appRules
	queue   chan store.Event
	dropped atomic.Int64
	logger  *slog.Logger
}

var (
	appEngineMu  sync.Mutex
	appEngineCur *appEngine
)

// appTap is the sig provider: it never produces signatures.
func appTap(ev store.Event) []ThreatSig {
	appEngineMu.Lock()
	e := appEngineCur
	appEngineMu.Unlock()
	if e == nil {
		return nil
	}
	switch ev.EventType {
	case "process", "network", "file":
		select {
		case e.queue <- ev:
		default:
			e.dropped.Add(1) // never block the foundation's engine loop
		}
	}
	return nil
}

func init() { RegisterSigProvider(appTap) }

// appStartRules starts the rule worker and scanner once. It returns a stop function (tests call it).
func appStartRules(db, backendDB *store.DB, logger *slog.Logger) func() {
	if db == nil {
		return func() {}
	}
	appEngineMu.Lock()
	if appEngineCur != nil {
		appEngineMu.Unlock()
		return func() {}
	}
	if logger == nil {
		logger = slog.Default()
	}
	idb := appIngestDB(db, backendDB)
	rules := appNewRules(appPGData{db: db, idb: idb}, appPGEmitter{db: db},
		func(ctx context.Context, rule string, svc appSvc) RuleGate {
			if svc.ID != 0 {
				return ruleGate(ctx, db, rule, "service", svc.Key())
			}
			return ruleGate(ctx, db, rule, "", "")
		})
	e := &appEngine{rules: rules, queue: make(chan store.Event, appRuleQueueSize), logger: logger}
	appEngineCur = e
	appEngineMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case ev := <-e.queue:
				e.safely(func() { rules.OnEvent(ctx, ev) })
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		t := time.NewTicker(appScanInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				e.safely(func() { rules.Scan(ctx) })
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() {
		cancel()
		appEngineMu.Lock()
		if appEngineCur == e {
			appEngineCur = nil
		}
		appEngineMu.Unlock()
	}
}

// safely keeps one bad event or scan from killing the worker.
func (e *appEngine) safely(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("application rule panic recovered", "panic", r)
		}
	}()
	fn()
}

// appHandleRulesStatus reports each Application rule with what it has done since the backend
// started: fired, fired in observe mode, ran degraded, and why it was skipped (spec 11.3 Coverage).
func appHandleRulesStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := appStatusSnapshot()
		type row struct {
			ID             string           `json:"id"`
			Family         string           `json:"family"`
			Layer          string           `json:"layer"`
			Tier           int              `json:"tier"`
			Operational    bool             `json:"operational"`
			DefaultObserve bool             `json:"default_observe"`
			WhatToCheck    string           `json:"what_to_check"`
			Fired          int64            `json:"fired"`
			Observed       int64            `json:"observed"`
			Degraded       int64            `json:"degraded"`
			Skipped        map[string]int64 `json:"skipped"`
			LastFired      *time.Time       `json:"last_fired,omitempty"`
		}
		rows := []row{}
		for _, m := range AllRuleMeta() {
			if !strings.HasPrefix(m.ID, "APP-") && !strings.HasPrefix(m.ID, "APM-") {
				continue
			}
			c := snap[m.ID]
			x := row{ID: m.ID, Family: m.Family, Layer: m.Layer, Tier: m.Tier, Operational: m.Operational, DefaultObserve: m.DefaultObserve,
				WhatToCheck: m.WhatToCheck, Fired: c.Fired, Observed: c.Observed, Degraded: c.Degraded, Skipped: c.Skipped}
			if x.Skipped == nil {
				x.Skipped = map[string]int64{}
			}
			if !c.LastFire.IsZero() {
				t := c.LastFire
				x.LastFired = &t
			}
			rows = append(rows, x)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
		var dropped int64
		appEngineMu.Lock()
		running := appEngineCur != nil
		if appEngineCur != nil {
			dropped = appEngineCur.dropped.Load()
		}
		appEngineMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"rules": rows, "engine": map[string]any{"running": running, "events_dropped": dropped}})
	}
}
