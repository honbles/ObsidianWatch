package collector

// analysis.go — Analysis engine
// Runs scheduled SQL queries on the local SQLite database,
// computes summaries and detects anomalies,
// then sends only the results upstream (never raw data).
//
// Runs every 5 minutes. Each analysis produces one or more ProbeEvents
// that get forwarded to the management backend.

import (
	"context"
	"log/slog"
	"time"

	"obsidianwatch/network-probe/internal/forwarder"
	"obsidianwatch/network-probe/internal/store"
	"obsidianwatch/network-probe/pkg/schema"
)

type AnalysisEngine struct {
	db      *store.DB
	fwd     *forwarder.Forwarder
	probeID string
	host    string
	logger  *slog.Logger
}

func NewAnalysisEngine(db *store.DB, fwd *forwarder.Forwarder,
	probeID, host string, logger *slog.Logger) *AnalysisEngine {
	return &AnalysisEngine{
		db: db, fwd: fwd,
		probeID: probeID, host: host,
		logger: logger,
	}
}

func (e *AnalysisEngine) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Run once on startup after a short delay (let collectors warm up)
	time.Sleep(30 * time.Second)
	e.runAll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.runAll(ctx)
		}
	}
}

func (e *AnalysisEngine) runAll(ctx context.Context) {
	e.analyzeBandwidth(ctx)
	e.analyzeTopDestinations(ctx)
	e.analyzeAuthFailures(ctx)
	e.analyzeDeviceActivity(ctx)
	e.analyzeFirewallDenies(ctx)
}

// ── Bandwidth summary — top talkers in last hour ──────────────────────────────
func (e *AnalysisEngine) analyzeBandwidth(ctx context.Context) {
	talkers, err := e.db.GetTopTalkers(ctx, 1, 20)
	if err != nil || len(talkers) == 0 {
		return
	}

	e.fwd.Enqueue(schema.ProbeEvent{
		ID:        eventID("analysis-bw", e.host),
		Time:      time.Now().UTC(),
		AgentID:   e.probeID, Host: e.host, OS: "network-probe",
		EventType: schema.EventTopTalker,
		Severity:  schema.SevInfo,
		Source:    "analysis",
		Raw: toRaw(map[string]interface{}{
			"type":        "bandwidth_summary",
			"period":      "1h",
			"top_talkers": talkers,
		}),
	})
	e.logger.Debug("analysis: bandwidth summary sent", "talkers", len(talkers))
}

// ── Top destinations — what are devices connecting to most ───────────────────
func (e *AnalysisEngine) analyzeTopDestinations(ctx context.Context) {
	destinations, err := e.db.GetTopDestinations(ctx, 1, 20)
	if err != nil || len(destinations) == 0 {
		return
	}

	e.fwd.Enqueue(schema.ProbeEvent{
		ID:        eventID("analysis-dst", e.host),
		Time:      time.Now().UTC(),
		AgentID:   e.probeID, Host: e.host, OS: "network-probe",
		EventType: schema.EventNetFlow,
		Severity:  schema.SevInfo,
		Source:    "analysis",
		Raw: toRaw(map[string]interface{}{
			"type":             "top_destinations",
			"period":           "1h",
			"top_destinations": destinations,
		}),
	})
}

// ── Auth failure summary — devices with brute force attempts ─────────────────
func (e *AnalysisEngine) analyzeAuthFailures(ctx context.Context) {
	failures, err := e.db.GetAuthFailureSummary(ctx, 60) // last 60 min
	if err != nil || len(failures) == 0 {
		return
	}

	// Alert on any source with > 20 failures in the window
	for _, f := range failures {
		count, _ := f["fail_count"].(int64)
		if count < 20 {
			continue
		}
		srcIP, _ := f["src_ip"].(string)
		dstDevice, _ := f["dst_device"].(string)
		proto, _ := f["proto"].(string)

		e.fwd.Enqueue(schema.ProbeEvent{
			ID:        eventID("alert-bf", srcIP, dstDevice),
			Time:      time.Now().UTC(),
			AgentID:   e.probeID, Host: e.host, OS: "network-probe",
			EventType: "net.brute_force",
			Severity:  schema.SevHigh,
			Source:    "analysis",
			SrcIP:     srcIP,
			DstIP:     dstDevice,
			Proto:     proto,
			Raw: toRaw(map[string]interface{}{
				"type":       "brute_force_alert",
				"src_ip":     srcIP,
				"dst_device": dstDevice,
				"fail_count": count,
				"window_min": 60,
				"proto":      proto,
			}),
		})
		e.logger.Warn("analysis: brute force detected",
			"src", srcIP, "dst", dstDevice, "failures", count)
	}
}

// ── Device activity — devices not seen in a while (went offline) ─────────────
func (e *AnalysisEngine) analyzeDeviceActivity(ctx context.Context) {
	// Devices seen in last 24h but not in last 10 min (went offline)
	offline, err := e.db.GetRecentlyOfflineDevices(ctx, 10, 1440) // 10 min, 24h
	if err != nil {
		return
	}
	if len(offline) == 0 {
		return
	}

	e.fwd.Enqueue(schema.ProbeEvent{
		ID:        eventID("analysis-offline", e.host),
		Time:      time.Now().UTC(),
		AgentID:   e.probeID, Host: e.host, OS: "network-probe",
		EventType: schema.EventDeviceSeen,
		Severity:  schema.SevInfo,
		Source:    "analysis",
		Raw: toRaw(map[string]interface{}{
			"type":            "device_offline_summary",
			"offline_devices": offline,
		}),
	})
}

// ── Firewall deny summary — top blocked sources ───────────────────────────────
func (e *AnalysisEngine) analyzeFirewallDenies(ctx context.Context) {
	denies, err := e.db.GetTopFirewallDenies(ctx, 60, 15) // last 60 min, top 15
	if err != nil || len(denies) == 0 {
		return
	}

	e.fwd.Enqueue(schema.ProbeEvent{
		ID:        eventID("analysis-fw", e.host),
		Time:      time.Now().UTC(),
		AgentID:   e.probeID, Host: e.host, OS: "network-probe",
		EventType: schema.EventFirewallDeny,
		Severity:  schema.SevInfo,
		Source:    "analysis",
		Raw: toRaw(map[string]interface{}{
			"type":           "firewall_deny_summary",
			"period_min":     60,
			"top_blocked":    denies,
		}),
	})
}
