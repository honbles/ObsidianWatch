package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// P-13: one user's activity across hosts. Exact (case-insensitive) match on
// the account name, with any DOMAIN\ or @domain part ignored.
func normUser(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndex(s, `\`); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, "@"); i > 0 {
		s = s[:i]
	}
	return s
}

type identityHost struct {
	Host       string         `json:"host"`
	OS         string         `json:"os"`
	Events     int            `json:"events"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	EventTypes map[string]int `json:"event_types"`
	MaxSev     int            `json:"max_severity"`
}

type identityEntry struct {
	Time      time.Time `json:"time"`
	Host      string    `json:"host"`
	EventType string    `json:"event_type"`
	Severity  int       `json:"severity"`
	Summary   string    `json:"summary"`
	SrcIP     string    `json:"src_ip,omitempty"`
	EventID   string    `json:"id"`
	Surface   string    `json:"surface"` // endpoint | cloud | devops (DR-05)
}

// identitySurface classifies where an event came from so one person's
// activity can be followed across endpoint, cloud and source control.
func identitySurface(ev store.Event) string {
	switch {
	case strings.HasPrefix(ev.EventType, "cloud."):
		return "cloud"
	case strings.HasPrefix(ev.EventType, "devops."):
		return "devops"
	}
	return "endpoint"
}

// identitySummary picks a readable one-liner for events without a command line.
func identitySummary(ev store.Event) string {
	if ev.CommandLine != nil && *ev.CommandLine != "" {
		return *ev.CommandLine
	}
	if ev.ProcessName != nil && *ev.ProcessName != "" {
		return *ev.ProcessName
	}
	var m struct {
		Method string `json:"method_name"`
		Action string `json:"action"`
		Event  string `json:"event"`
		Name   string `json:"event_name"`
		Repo   string `json:"repo"`
	}
	if json.Unmarshal(ev.Raw, &m) == nil {
		for _, v := range []string{m.Method, m.Name, m.Action, m.Event} {
			if v != "" {
				if m.Repo != "" {
					return v + " (" + m.Repo + ")"
				}
				return v
			}
		}
	}
	return ev.EventType
}

func handleIdentityTimeline(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := normUser(r.URL.Query().Get("user"))
		if user == "" {
			writeJSONError(w, http.StatusBadRequest, "user required")
			return
		}
		hours := 72
		if v, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && v >= 1 && v <= 24*30 {
			hours = v
		}
		// DR-05: a person often has different account names per surface
		// (laptop login, Entra UPN, GitHub handle). Aliases link them.
		names := identityNames(user, loadIdentityAliases(r.Context(), db))
		var events []store.Event
		seen := map[string]bool{}
		for n := range names {
			evs, _, err := db.QueryEvents(r.Context(), store.EventFilter{
				UserName: n, Since: time.Now().Add(-time.Duration(hours) * time.Hour),
				Limit: 5000, SkipCount: true,
			})
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "query failed")
				return
			}
			for _, ev := range evs {
				if !seen[ev.ID] {
					seen[ev.ID] = true
					events = append(events, ev)
				}
			}
		}
		hosts := map[string]*identityHost{}
		var tl []identityEntry
		for _, ev := range events {
			if ev.UserName == nil || !names[normUser(*ev.UserName)] {
				continue
			}
			h := hosts[ev.Host]
			if h == nil {
				h = &identityHost{Host: ev.Host, OS: ev.OS, FirstSeen: ev.Time, LastSeen: ev.Time, EventTypes: map[string]int{}}
				hosts[ev.Host] = h
			}
			h.Events++
			h.EventTypes[ev.EventType]++
			if ev.Time.Before(h.FirstSeen) {
				h.FirstSeen = ev.Time
			}
			if ev.Time.After(h.LastSeen) {
				h.LastSeen = ev.Time
			}
			if ev.Severity > h.MaxSev {
				h.MaxSev = ev.Severity
			}
			// Timeline keeps authentication and anything notable, not every process.
			if ev.EventType == "logon" || ev.EventType == "auth" || ev.EventType == "kerberos" || ev.Severity >= 3 ||
				identitySurface(ev) != "endpoint" {
				e := identityEntry{Time: ev.Time, Host: ev.Host, EventType: ev.EventType, Severity: ev.Severity, EventID: ev.ID, Surface: identitySurface(ev)}
				e.Summary = identitySummary(ev)
				if len(e.Summary) > 200 {
					e.Summary = e.Summary[:200]
				}
				if ev.SrcIP != nil {
					e.SrcIP = *ev.SrcIP
				}
				tl = append(tl, e)
			}
		}
		sort.Slice(tl, func(i, j int) bool { return tl[i].Time.After(tl[j].Time) })
		if len(tl) > 500 {
			tl = tl[:500]
		}
		hl := make([]identityHost, 0, len(hosts))
		for _, h := range hosts {
			hl = append(hl, *h)
		}
		sort.Slice(hl, func(i, j int) bool { return hl[i].LastSeen.After(hl[j].LastSeen) })
		writeJSON(w, 200, map[string]interface{}{"user": user, "hours": hours, "hosts": hl, "timeline": tl, "surfaces": surfaceCounts(events, names), "linked_accounts": sortedKeys(names)})
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func surfaceCounts(events []store.Event, names map[string]bool) map[string]int {
	out := map[string]int{}
	for _, ev := range events {
		if ev.UserName != nil && names[normUser(*ev.UserName)] {
			out[identitySurface(ev)]++
		}
	}
	return out
}
