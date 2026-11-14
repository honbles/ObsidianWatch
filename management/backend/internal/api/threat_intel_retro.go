package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// P-01 retro-hunt: when a sync brings in new IOCs, search the retained event
// history for past hits and raise alerts tagged "Retro-hunt". Bounded so a
// large first sync cannot flood the alert queue or the database.
const (
	retroWindow       = 90 * 24 * time.Hour
	retroBatch        = 500  // IOC values per query
	retroHitsPerBatch = 2000 // events returned per query
	retroMaxAlerts    = 500  // alerts per sync
)

func (e *ThreatIntelEngine) retroHunt(ctx context.Context, source string, since time.Time) {
	if v, _ := e.db.GetSetting(ctx, "threat_intel.retro_hunt"); v == "false" {
		return
	}
	iocs, err := e.db.ListIOCsCreatedSince(ctx, source, since)
	if err != nil || len(iocs) == 0 {
		return
	}
	// IOCs under 25% confidence are ignored, matching the live path (D-14).
	byType := map[string]map[string]store.IOCIndicator{}
	for _, i := range iocs {
		if i.Confidence > 0 && i.Confidence < 25 {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(i.Value))
		if v == "" {
			continue
		}
		if byType[i.IOCType] == nil {
			byType[i.IOCType] = map[string]store.IOCIndicator{}
		}
		byType[i.IOCType][v] = i
	}
	horizon := time.Now().Add(-retroWindow)
	created := 0
	for typ, m := range byType {
		vals := make([]string, 0, len(m))
		for v := range m {
			vals = append(vals, v)
		}
		for start := 0; start < len(vals) && created < retroMaxAlerts; start += retroBatch {
			end := start + retroBatch
			if end > len(vals) {
				end = len(vals)
			}
			hits, err := e.db.RetroHuntEvents(ctx, typ, vals[start:end], horizon, retroHitsPerBatch)
			if err != nil {
				e.logger.Warn("threat-intel: retro-hunt query failed", "type", typ, "err", err)
				continue
			}
			// One alert per (host, indicator) with a count, not one per event:
			// a single domain looked up 40 times is one finding.
			type grp struct {
				ioc         store.IOCIndicator
				latest      store.RetroHuntHit
				first, last time.Time
				n           int
				procs       map[string]bool
			}
			groups := map[string]*grp{}
			var order []string
			for _, h := range hits {
				ioc, ok := m[strings.ToLower(h.Matched)]
				if !ok {
					continue
				}
				k := h.AgentID + "|" + ioc.Source + "|" + strings.ToLower(ioc.Value)
				g := groups[k]
				if g == nil {
					g = &grp{ioc: ioc, latest: h, first: h.Time, last: h.Time, procs: map[string]bool{}}
					groups[k] = g
					order = append(order, k)
				}
				g.n++
				if h.Time.Before(g.first) {
					g.first = h.Time
				}
				if h.Time.After(g.last) {
					g.last, g.latest = h.Time, h
				}
				if h.Process != "" && len(g.procs) < 5 {
					g.procs[h.Process] = true
				}
			}
			sort.Strings(order)
			for _, k := range order {
				if created >= retroMaxAlerts {
					break
				}
				g := groups[k]
				ioc, h := g.ioc, g.latest
				sev := ioc.Severity
				if ioc.Confidence > 0 && ioc.Confidence < 50 && sev > 2 {
					sev--
				}
				procs := make([]string, 0, len(g.procs))
				for p := range g.procs {
					procs = append(procs, p)
				}
				sort.Strings(procs)
				src := strings.ToUpper(ioc.Source)
				a := store.Alert{
					Title: fmt.Sprintf("[%s] Retro-hunt %s IOC Match — %s", src, titleCase(ioc.IOCType), ioc.Value),
					Description: fmt.Sprintf(
						"[%s] Retro-hunt: indicator added after these events occurred.\nMatched known malicious %s: %s\nOccurrences: %d (first %s, last %s)\n\nMalware: %s | Threat: %s | Confidence: %d%%\nHost: %s | OS: %s | Process: %s",
						src, ioc.IOCType, ioc.Value, g.n, g.first.UTC().Format(time.RFC3339), g.last.UTC().Format(time.RFC3339),
						ioc.Malware, ioc.ThreatType, ioc.Confidence, h.Host, h.OS, strings.Join(procs, ", ")),
					Severity:      sev,
					AgentID:       h.AgentID,
					Host:          h.Host,
					EventType:     h.EventType,
					EventID:       fmt.Sprintf("retro:%s:%s:%s", ioc.Source, ioc.Value, h.AgentID),
					SourceEventID: h.EventID,
				}
				if _, inserted, err := e.db.CreateAlertDeduped(ctx, a); err == nil && inserted {
					created++
				}
			}
		}
	}
	if created > 0 {
		e.logger.Info("threat-intel: retro-hunt alerts raised", "source", source, "alerts", created)
	}
}
