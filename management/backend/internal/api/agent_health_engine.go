package api

// agent_health_engine.go — D-11.
//
// Previously nothing alerted when an agent went silent, a collector
// stopped reporting, the event queue backed up, or drops started rising —
// "online" was just a passive `last_seen < 2 minutes` computed field with
// no alerting behind it, and the agents' own periodic "health" events
// (queue_depth, events_dropped, collectors reporting) were collected but
// never evaluated server-side. This engine turns those existing signals,
// plus the D-01/D-02 engine cursors, into real alerts:
//
//   - an agent that was seen before but has gone quiet for a while
//   - a detection/correlation/etc engine whose cursor hasn't moved —
//     i.e. it has stopped running entirely
//   - an agent's own queue_depth / events_dropped climbing, from its
//     self-reported health events
//   - a collector that was previously reporting and has disappeared from
//     an agent's collector list

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

const (
	agentSilentThreshold    = 10 * time.Minute
	engineStalledThreshold  = 10 * time.Minute
	healthQueueDepthAlert   = 2000
	healthDropIncreaseAlert = 50
)

type agentHealthPayload struct {
	Status          string   `json:"status"`
	Collectors      []string `json:"collectors"`
	EventsCollected int64    `json:"events_collected"`
	EventsDropped   int64    `json:"events_dropped"`
	EventsForwarded int64    `json:"events_forwarded"`
	QueueDepth      int64    `json:"queue_depth"`
	// SysmonStatus (W-01, Windows agents only) is "" on non-Windows
	// agents and on Windows agents older than this fix. "running" is the
	// only healthy value — ETW alone (what the Windows process collector
	// falls back to without Sysmon) only exposes PID/TID/opcode, so
	// process detections on that host are effectively blind.
	SysmonStatus  string `json:"sysmon_status"`
	ForwardErrors int64  `json:"forward_errors"`
}

type AgentHealthEngine struct {
	db     *store.DB
	logger *slog.Logger

	mu          sync.Mutex
	graceUntil  time.Time // no stall/drop alerts until then (startup, or after the process was paused)
	lastCheck   time.Time
	lastDropped map[string]int64           // agentID -> events_dropped as of last health event seen
	knownColls  map[string]map[string]bool // agentID -> set of collector names ever reported
}

func NewAgentHealthEngine(db *store.DB, logger *slog.Logger) *AgentHealthEngine {
	return &AgentHealthEngine{
		db:          db,
		logger:      logger,
		lastDropped: make(map[string]int64),
		knownColls:  make(map[string]map[string]bool),
		graceUntil:  time.Now().Add(healthStartupGrace),
	}
}

// healthStartupGrace: after the management server (re)starts, the other
// engines' cursors are stale until their first poll, and agents have been
// dropping events because the server was unreachable. Both are expected, so
// stall and drop alerts wait this long.
const healthStartupGrace = 10 * time.Minute

func (e *AgentHealthEngine) inGrace() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return time.Now().Before(e.graceUntil)
}

func (e *AgentHealthEngine) Run(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	e.check(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.check(ctx)
		}
	}
}

func (e *AgentHealthEngine) check(ctx context.Context) {
	// If this loop itself was paused (VM suspended, host asleep, long GC or DB
	// stall), every engine looks stalled the moment it resumes — wait for them.
	e.mu.Lock()
	now := time.Now()
	if !e.lastCheck.IsZero() && now.Sub(e.lastCheck) > 3*time.Minute {
		e.graceUntil = now.Add(5 * time.Minute)
	}
	e.lastCheck = now
	e.mu.Unlock()
	e.checkSilentAgents(ctx)
	e.checkStalledEngines(ctx)
	e.checkHealthEvents(ctx)
	e.checkLocationTravel(ctx)
}

// hourBucket re-arms a dedup key roughly once an hour while a condition
// persists, instead of firing once ever (CreateAlertDeduped would merge
// every subsequent occurrence into the first row forever) or on every poll.
func hourBucket() string {
	return time.Now().UTC().Format("2006010215")
}

func (e *AgentHealthEngine) fire(ctx context.Context, dedupKey, title, desc, agentID, host string, severity int) {
	alert := store.Alert{
		Title:       title,
		Description: desc,
		Severity:    severity,
		AgentID:     agentID,
		Host:        host,
		EventType:   "agent_health",
		EventID:     dedupKey,
	}
	if _, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err != nil {
		e.logger.Warn("agent health: create alert failed", "err", err)
	} else if inserted {
		e.logger.Info("agent health: alert fired", "title", title, "host", host)
	}
}

// checkSilentAgents alerts when an agent that has previously reported in
// goes quiet for longer than agentSilentThreshold.
func (e *AgentHealthEngine) checkSilentAgents(ctx context.Context) {
	agents, err := e.db.ListAgents(ctx)
	if err != nil {
		e.logger.Warn("agent health: list agents failed", "err", err)
		return
	}
	now := time.Now()
	for _, a := range agents {
		if a.FirstSeen.IsZero() || a.LastSeen.IsZero() {
			continue
		}
		silentFor := now.Sub(a.LastSeen)
		if silentFor < agentSilentThreshold {
			continue
		}
		sev := 3 // Medium
		if silentFor > time.Hour {
			sev = 4 // High
		}
		dedupKey := fmt.Sprintf("health:silent:%s:h:%s", a.ID, hourBucket())
		e.fire(ctx, dedupKey,
			fmt.Sprintf("Agent offline: %s", a.Hostname),
			fmt.Sprintf("Agent %s (%s) has not reported in for %s (last seen %s).",
				a.Hostname, a.ID, silentFor.Round(time.Minute), a.LastSeen.UTC().Format(time.RFC3339)),
			a.ID, a.Hostname, sev)
	}
}

// checkStalledEngines alerts when a detection/correlation/etc engine's
// ingested_at cursor (see cursor_paging.go) hasn't advanced recently —
// pageEventCursor advances the cursor even on an empty poll, so a cursor
// that stops moving means the engine's goroutine itself has stopped, not
// just that there's no new data.
func (e *AgentHealthEngine) checkStalledEngines(ctx context.Context) {
	if e.inGrace() {
		return
	}
	cursors, err := e.db.ListEngineCursors(ctx)
	if err != nil {
		e.logger.Warn("agent health: list engine cursors failed", "err", err)
		return
	}
	now := time.Now()
	for _, c := range cursors {
		if c.UpdatedAt.IsZero() {
			continue
		}
		stalledFor := now.Sub(c.UpdatedAt)
		if stalledFor < engineStalledThreshold {
			continue
		}
		dedupKey := fmt.Sprintf("health:engine-stalled:%s:h:%s", c.EngineName, hourBucket())
		e.fire(ctx, dedupKey,
			fmt.Sprintf("Detection engine stalled: %s", c.EngineName),
			fmt.Sprintf("Engine '%s' has not advanced its event cursor in %s (last update %s). It may have crashed or deadlocked.",
				c.EngineName, stalledFor.Round(time.Minute), c.UpdatedAt.UTC().Format(time.RFC3339)),
			"", "", 4)
	}
}

// checkHealthEvents pages newly-ingested "health" events (the self-reported
// heartbeat each agent already sends) and alerts on rising drops or a
// backed-up queue, and on a collector that was previously reporting and
// has now disappeared from an agent's collector list.
func (e *AgentHealthEngine) checkHealthEvents(ctx context.Context) {
	events, err := pageEventCursor(ctx, e.db, "agent-health-monitor", store.EventFilter{
		EventType: "health",
	}, 10*time.Minute, 2000)
	if err != nil {
		e.logger.Warn("agent health: cursor query failed", "err", err)
		return
	}
	for _, ev := range events {
		if ev.Raw == nil {
			continue
		}
		var p agentHealthPayload
		if err := json.Unmarshal(ev.Raw, &p); err != nil {
			continue
		}

		e.mu.Lock()
		prevDropped, hadPrev := e.lastDropped[ev.AgentID]
		e.lastDropped[ev.AgentID] = p.EventsDropped
		known := e.knownColls[ev.AgentID]
		if known == nil {
			known = make(map[string]bool)
			e.knownColls[ev.AgentID] = known
		}
		var missing []string
		seenNow := make(map[string]bool, len(p.Collectors))
		for _, c := range p.Collectors {
			seenNow[c] = true
			known[c] = true
		}
		// Only complain about a collector that was previously seen and is
		// absent from this report — never about one we've simply never
		// observed yet (e.g. a platform that doesn't have it).
		if len(known) > 0 && len(p.Collectors) > 0 {
			for c := range known {
				if !seenNow[c] {
					missing = append(missing, c)
				}
			}
		}
		e.mu.Unlock()

		// W-01: Sysmon not running means the Windows process collector is
		// operating on ETW alone — PID/TID/opcode only, no image path,
		// command line, parent, or user — so most process-based detection
		// content (including nearly all Sigma process_creation rules) is
		// silently blind on this host even though it looks "online".
		if p.SysmonStatus != "" && p.SysmonStatus != "running" {
			sev := 3
			if p.SysmonStatus == "not_installed" {
				sev = 4
			}
			dedupKey := fmt.Sprintf("health:sysmon:%s:h:%s", ev.AgentID, hourBucket())
			e.fire(ctx, dedupKey,
				fmt.Sprintf("Sysmon not running on %s", ev.Host),
				fmt.Sprintf("Agent %s reports Sysmon status '%s'. Without Sysmon, the Windows process collector falls back to raw ETW, which only exposes PID/TID/opcode — no image path, command line, parent process, or user. Process-based detection content is effectively disabled on this host until Sysmon is installed and running.", ev.Host, p.SysmonStatus),
				ev.AgentID, ev.Host, sev)
		}

		grace := e.inGrace()
		if !grace && p.QueueDepth >= healthQueueDepthAlert {
			dedupKey := fmt.Sprintf("health:queue:%s:h:%s", ev.AgentID, hourBucket())
			e.fire(ctx, dedupKey,
				fmt.Sprintf("Event queue backing up on %s", ev.Host),
				fmt.Sprintf("Agent %s reports a forwarder queue depth of %d — events are being collected faster than they can be sent to the backend.", ev.Host, p.QueueDepth),
				ev.AgentID, ev.Host, 3)
		}

		if !grace && hadPrev && p.EventsDropped > prevDropped && p.EventsDropped-prevDropped >= healthDropIncreaseAlert {
			// once per 6 hours per agent: drops come in bursts when the
			// backend is briefly unreachable
			dedupKey := fmt.Sprintf("health:drops:%s:h:%s", ev.AgentID, time.Now().UTC().Format("2006010215")[:8]+fmt.Sprintf("%02d", time.Now().UTC().Hour()/6))
			e.fire(ctx, dedupKey,
				fmt.Sprintf("Agent dropping events on %s", ev.Host),
				fmt.Sprintf("Agent %s dropped %d more events since its last health report (total dropped: %d). The forwarder can't keep up or the backend is unreachable.",
					ev.Host, p.EventsDropped-prevDropped, p.EventsDropped),
				ev.AgentID, ev.Host, 3)
		}

		for _, c := range missing {
			dedupKey := fmt.Sprintf("health:collector-stopped:%s:%s:h:%s", ev.AgentID, c, hourBucket())
			e.fire(ctx, dedupKey,
				fmt.Sprintf("Collector stopped: %s on %s", c, ev.Host),
				fmt.Sprintf("Agent %s was previously reporting data from the '%s' collector, which is now missing from its health report. It may have crashed or lost permissions.", ev.Host, c),
				ev.AgentID, ev.Host, 3)
		}
	}
}
