package api

import (
	"net/http"
	"sort"
	"time"

	"obsidianwatch/management/internal/store"
)

// F-28: alert response SLAs. An open alert is "breached" once it has sat
// unacknowledged longer than the target for its severity.
func slaTarget(sev int) time.Duration {
	switch {
	case sev >= 5:
		return time.Hour
	case sev == 4:
		return 4 * time.Hour
	case sev == 3:
		return 24 * time.Hour
	case sev == 2:
		return 72 * time.Hour
	}
	return 7 * 24 * time.Hour
}

type slaAlert struct {
	ID        int64     `json:"id"`
	Title     string    `json:"title"`
	Host      string    `json:"host"`
	Severity  int       `json:"severity"`
	CreatedAt time.Time `json:"created_at"`
	Target    string    `json:"target"`
	Overdue   string    `json:"overdue_by"`
	OverdueS  int64     `json:"overdue_seconds"`
	Assigned  string    `json:"assigned_to,omitempty"`
}

// breachedAlerts returns open, unacknowledged alerts past their SLA, worst first.
func breachedAlerts(alerts []store.Alert, now time.Time) []slaAlert {
	var out []slaAlert
	for _, a := range alerts {
		if a.Status != "open" || a.AcknowledgedAt != nil {
			continue
		}
		t := slaTarget(a.Severity)
		over := now.Sub(a.CreatedAt) - t
		if over <= 0 {
			continue
		}
		s := slaAlert{ID: a.ID, Title: a.Title, Host: a.Host, Severity: a.Severity, CreatedAt: a.CreatedAt,
			Target: t.String(), Overdue: over.Round(time.Minute).String(), OverdueS: int64(over.Seconds())}
		if a.AssignedTo != nil {
			s.Assigned = *a.AssignedTo
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].OverdueS > out[j].OverdueS
	})
	return out
}

func handleAlertSLA(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		alerts, err := db.ListAlerts(r.Context(), "open", 2000)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to load alerts")
			return
		}
		b := breachedAlerts(alerts, time.Now())
		bySev := map[int]int{}
		for _, a := range b {
			bySev[a.Severity]++
		}
		if len(b) > 200 {
			b = b[:200]
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"breached": b, "by_severity": bySev, "open_considered": len(alerts)})
	}
}
