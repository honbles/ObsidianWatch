package api

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"obsidianwatch/management/internal/store"
)

// P-04: incidents. Open alerts are grouped per host into time-contiguous
// clusters (a gap of more than incidentGap between consecutive alerts starts
// a new incident). Each incident carries a risk score so analysts can triage
// a handful of incidents instead of a flat alert list.
const incidentGap = 2 * time.Hour

type Incident struct {
	ID         string         `json:"id"`
	Host       string         `json:"host"`
	AgentID    string         `json:"agent_id"`
	Start      time.Time      `json:"start"`
	End        time.Time      `json:"end"`
	AlertCount int            `json:"alert_count"`
	MaxSev     int            `json:"max_severity"`
	Risk       int            `json:"risk_score"`
	Titles     []string       `json:"top_titles"`
	AlertIDs   []int64        `json:"alert_ids"`
	EventTypes map[string]int `json:"event_types"`
	State      *IncidentState `json:"state,omitempty"`
}

func sevWeight(s int) int {
	switch {
	case s >= 5:
		return 25
	case s == 4:
		return 12
	case s == 3:
		return 5
	case s == 2:
		return 2
	}
	return 1
}

// buildIncidents is pure so it can be unit tested.
func buildIncidents(alerts []store.Alert) []Incident {
	byHost := map[string][]store.Alert{}
	for _, a := range alerts {
		k := a.Host
		if k == "" {
			k = a.AgentID
		}
		byHost[k] = append(byHost[k], a)
	}
	var out []Incident
	for host, as := range byHost {
		sort.Slice(as, func(i, j int) bool { return as[i].CreatedAt.Before(as[j].CreatedAt) })
		var cur *Incident
		titles := map[string]int{}
		flush := func() {
			if cur == nil {
				return
			}
			type tc struct {
				t string
				n int
			}
			var l []tc
			for t, n := range titles {
				l = append(l, tc{t, n})
			}
			sort.Slice(l, func(i, j int) bool {
				if l[i].n != l[j].n {
					return l[i].n > l[j].n
				}
				return l[i].t < l[j].t
			})
			for i := 0; i < len(l) && i < 3; i++ {
				cur.Titles = append(cur.Titles, l[i].t)
			}
			// distinct event types widen the chain: bonus per extra type
			cur.Risk += 3 * (len(cur.EventTypes) - 1)
			if cur.Risk > 100 {
				cur.Risk = 100
			}
			out = append(out, *cur)
			cur, titles = nil, map[string]int{}
		}
		for _, a := range as {
			if cur != nil && a.CreatedAt.Sub(cur.End) > incidentGap {
				flush()
			}
			if cur == nil {
				cur = &Incident{ID: "inc-" + sha12(host+a.CreatedAt.UTC().Format(time.RFC3339)), Host: host, AgentID: a.AgentID,
					Start: a.CreatedAt, EventTypes: map[string]int{}}
			}
			cur.End = a.CreatedAt
			cur.AlertCount++
			cur.AlertIDs = append(cur.AlertIDs, a.ID)
			if a.Severity > cur.MaxSev {
				cur.MaxSev = a.Severity
			}
			cur.Risk += sevWeight(a.Severity)
			cur.EventTypes[a.EventType]++
			titles[a.Title]++
		}
		flush()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].End.After(out[j].End)
	})
	return out
}

func handleIncidents(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := "open" // alert status; incident status filter is separate
		incStatus := r.URL.Query().Get("incident_status")
		limit := 2000
		if v, _ := strconv.Atoi(r.URL.Query().Get("limit")); v > 0 && v <= 5000 {
			limit = v
		}
		alerts, err := db.ListAlerts(r.Context(), status, limit)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to load alerts")
			return
		}
		inc := applyIncidentState(buildIncidents(alerts), loadIncidentStates(r, db), incStatus)
		if len(inc) > 200 {
			inc = inc[:200]
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"incidents": inc, "count": len(inc), "alerts_considered": len(alerts)})
	}
}
