package api

// rule_backtest.go — P-06: replay a built-in signature against recent events
// and report how many alerts it would have produced, before it is enabled.
//
//	POST /api/v1/detections/{id}/backtest?hours=24
//
// It evaluates only the rule's Match function. Engine-side gates (per-rule
// suppression, dedup, correlation windows) are not applied, so the count is an
// upper bound on alert volume. At most backtestMaxEvents events are scanned.

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"obsidianwatch/management/internal/store"
)

const (
	backtestMaxEvents = 50000
	backtestPage      = 5000
)

type backtestHit struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Host      string    `json:"host"`
	EventType string    `json:"event_type"`
}

type backtestResult struct {
	RuleID    string          `json:"rule_id"`
	Name      string          `json:"name"`
	Hours     int             `json:"hours"`
	Scanned   int             `json:"events_scanned"`
	Truncated bool            `json:"truncated"`
	Matches   int             `json:"matches"`
	PerDay    float64         `json:"estimated_per_day"`
	TopHosts  []backtestCount `json:"top_hosts"`
	Samples   []backtestHit   `json:"samples"`
	Note      string          `json:"note"`
}

type backtestCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

func findSignature(id string) (ThreatSig, bool) {
	for _, set := range allSignatureSets() {
		for _, s := range set {
			if s.ID == id {
				return s, true
			}
		}
	}
	return ThreatSig{}, false
}

// backtestEvents is pure: it counts matches over a slice of events.
func backtestEvents(sig ThreatSig, events []store.Event) (matches int, hosts map[string]int, samples []backtestHit) {
	hosts = map[string]int{}
	for _, ev := range events {
		if !safeMatch(sig, ev) {
			continue
		}
		matches++
		hosts[ev.Host]++
		if len(samples) < 5 {
			samples = append(samples, backtestHit{ID: ev.ID, Time: ev.Time, Host: ev.Host, EventType: ev.EventType})
		}
	}
	return
}

// safeMatch shields the handler from a panicking matcher.
func safeMatch(sig ThreatSig, ev store.Event) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return sig.Match(ev)
}

func handleBacktestRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sig, found := findSignature(r.PathValue("id"))
		if !found {
			writeJSON(w, 404, map[string]string{"error": "rule not found (only built-in signatures can be backtested)"})
			return
		}
		hours := 24
		if v, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && v > 0 {
			hours = v
		}
		if hours > 24*14 {
			hours = 24 * 14
		}
		since := time.Now().Add(-time.Duration(hours) * time.Hour)
		res := backtestResult{RuleID: sig.ID, Name: sig.Name, Hours: hours,
			Note: "Upper bound: only the rule's match logic is replayed; suppression, dedup and correlation windows are not applied."}
		hosts := map[string]int{}
		for off := 0; res.Scanned < backtestMaxEvents; off += backtestPage {
			events, _, err := db.QueryEvents(r.Context(), store.EventFilter{Since: since, Limit: backtestPage, Offset: off})
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": "event query failed"})
				return
			}
			m, h, s := backtestEvents(sig, events)
			res.Matches += m
			for k, v := range h {
				hosts[k] += v
			}
			for _, x := range s {
				if len(res.Samples) < 5 {
					res.Samples = append(res.Samples, x)
				}
			}
			res.Scanned += len(events)
			if len(events) < backtestPage {
				break
			}
		}
		res.Truncated = res.Scanned >= backtestMaxEvents
		for k, v := range hosts {
			res.TopHosts = append(res.TopHosts, backtestCount{k, v})
		}
		sort.Slice(res.TopHosts, func(i, j int) bool { return res.TopHosts[i].Count > res.TopHosts[j].Count })
		if len(res.TopHosts) > 10 {
			res.TopHosts = res.TopHosts[:10]
		}
		res.PerDay = float64(res.Matches) / float64(hours) * 24
		writeJSON(w, 200, res)
	}
}
