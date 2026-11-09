package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// P-02 alerting: a binary (by hash) that has only ever run on ONE host in the
// fleet AND runs from a user-writable location is worth a low-severity alert.
// Suppressed until the prevalence table has at least a week of history so a
// fresh deployment does not alert on every binary.
const prevalenceWarmup = 7 * 24 * time.Hour

var writableDirMarkers = []string{
	`\appdata\local\temp\`, `\appdata\roaming\`, `\appdata\local\`, `\windows\temp\`, `\users\public\`,
	`\downloads\`, `\programdata\`, `\$recycle.bin\`,
	"/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/", "/private/var/tmp/", "/downloads/",
}

func inWritableDir(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, "/", "/"))
	for _, m := range writableDirMarkers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}

func hashKey(ev store.Event) string {
	for _, k := range prevalenceKeys(ev) {
		if strings.HasPrefix(k, "hash:") {
			return k
		}
	}
	return ""
}

// rarityCandidates picks process events with a hash running from writable dirs.
func rarityCandidates(events []store.Event, max int) map[string]store.Event {
	out := map[string]store.Event{}
	for _, ev := range events {
		if ev.EventType != "process" || ev.ImagePath == nil || !inWritableDir(*ev.ImagePath) {
			continue
		}
		k := hashKey(ev)
		if k == "" {
			continue
		}
		if _, dup := out[k]; !dup && len(out) < max {
			out[k] = ev
		}
	}
	return out
}

// alertRareBinaries must run after recordPrevalence for the same batch.
func (e *DetectionEngine) alertRareBinaries(ctx context.Context, events []store.Event) {
	cands := rarityCandidates(events, 50)
	if len(cands) == 0 {
		return
	}
	start, err := e.db.PrevalenceHistoryStartForPrefix(ctx, "hash:") // warm-up per key type: newly reported hashes do not inherit old history
	if err != nil || start.IsZero() || time.Since(start) < prevalenceWarmup {
		return
	}
	keys := make([]string, 0, len(cands))
	for k := range cands {
		keys = append(keys, k)
	}
	counts, err := e.db.PrevalenceHostCounts(ctx, keys)
	if err != nil {
		return
	}
	for k, ev := range cands {
		if counts[k] != 1 {
			continue
		}
		a := store.Alert{
			Title: "Rare binary executed from a user-writable location",
			Description: fmt.Sprintf("%s ran from %s on %s. This file hash has been seen on no other host in the fleet.\nHash key: %s",
				derefStr(ev.ProcessName), derefStr(ev.ImagePath), ev.Host, k),
			Severity: 2, AgentID: ev.AgentID, Host: ev.Host, EventType: ev.EventType,
			EventID: "prev:rare:" + sha12(k+"|"+ev.Host), SourceEventID: ev.ID,
		}
		if _, _, err := e.db.CreateAlertDeduped(ctx, a); err != nil {
			e.logger.Warn("prevalence: rare-binary alert failed", "err", err)
		}
	}
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
