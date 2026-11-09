package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"obsidianwatch/management/internal/store"
)

// handleThreatIntelHost returns threat intel scoped to a single host
func handleThreatIntelHost(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		hours := 24
		if s := r.URL.Query().Get("hours"); s != "" {
			if v, err := strconv.Atoi(s); err == nil {
				hours = v
			}
		}
		data, err := db.ThreatIntelHost(r.Context(), host, hours)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, data)
	}
}

// ── Threat Graph ──────────────────────────────────────────────────────────────

// handleThreatGraphHost returns all process events for a host, grouped by
// application, with parent/child relationships for tree rendering.
func handleThreatGraphHost(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		since := time.Now().Add(-24 * time.Hour)
		if s := r.URL.Query().Get("since_hours"); s != "" {
			if h, err := strconv.Atoi(s); err == nil {
				since = time.Now().Add(-time.Duration(h) * time.Hour)
			}
		}

		// Fetch ALL events for this host — enrichFromRaw populates process_name even on
		// raw/file/network events, so we use all_events for both tree and enrichment.
		fAll := store.EventFilter{HostExact: host, Since: since, Limit: 5000} // F-10: exact match
		allEvents, _, err := db.QueryEvents(r.Context(), fAll)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}

		// Build deduplicated process list from all events.
		// For each unique process_name:pid combo, keep the event with the richest data
		// (prefer event_type=process, then highest severity, then most fields populated).
		type procKey struct {
			name string
			pid  int
		}
		procMap := map[procKey]store.Event{}
		for _, e := range allEvents {
			if e.ProcessName == nil {
				continue
			}
			pid := 0
			if e.PID != nil {
				pid = *e.PID
			}
			k := procKey{*e.ProcessName, pid}
			existing, exists := procMap[k]
			if !exists {
				procMap[k] = e
				continue
			}
			// Prefer event_type=process over other types
			if e.EventType == "process" && existing.EventType != "process" {
				procMap[k] = e
				continue
			}
			// Prefer events with command_line populated
			if e.CommandLine != nil && existing.CommandLine == nil {
				procMap[k] = e
			}
		}
		processEvents := make([]store.Event, 0, len(procMap))
		for _, e := range procMap {
			processEvents = append(processEvents, e)
		}

		writeJSON(w, 200, map[string]interface{}{
			"host":       host,
			"processes":  processEvents,
			"all_events": allEvents,
			"since":      since,
		})
	}
}

// handleThreatGraphProcess returns full process tree for a specific process name on a host.
func handleThreatGraphProcess(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		processName := r.URL.Query().Get("process")
		since := time.Now().Add(-24 * time.Hour)

		// Get all events related to this process (F-10: exact host match)
		f := store.EventFilter{
			HostExact:   host,
			ProcessName: processName,
			Since:       since,
			Limit:       500,
		}
		events, _, err := db.QueryEvents(r.Context(), f)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}

		writeJSON(w, 200, map[string]interface{}{
			"host":    host,
			"process": processName,
			"events":  events,
		})
	}
}

// handleGetAgentLocations returns all agents with known locations for the map.
func handleGetAgentLocations(db *store.DB, backendDB *store.DB) http.HandlerFunc {
	type locationRow struct {
		ID               string     `json:"id"`
		Hostname         string     `json:"hostname"`
		OS               string     `json:"os"`
		LastIP           string     `json:"last_ip"`
		LastSeen         time.Time  `json:"last_seen"`
		Lat              float64    `json:"lat"`
		Lng              float64    `json:"lng"`
		LocationAccuracy float64    `json:"location_accuracy,omitempty"`
		LocationSource   string     `json:"location_source,omitempty"`
		LocationCity     string     `json:"location_city,omitempty"`
		LocationCountry  string     `json:"location_country,omitempty"`
		LocationUpdated  *time.Time `json:"location_updated,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Use backend DB if available — it has live location data from agents
		// Query only the columns that exist in both management and backend agents tables
		queryDB := db
		if backendDB != nil {
			queryDB = backendDB
		}

		rows, err := queryDB.QueryContext(r.Context(), `
			SELECT id, hostname, os, COALESCE(last_ip,''), last_seen,
			       lat, lng, COALESCE(location_accuracy, 0),
			       COALESCE(location_source,''), COALESCE(location_city,''),
			       COALESCE(location_country,''), location_updated
			FROM agents
			WHERE lat IS NOT NULL AND lng IS NOT NULL
			ORDER BY last_seen DESC
		`)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		defer rows.Close()

		var locs []locationRow
		for rows.Next() {
			var l locationRow
			if err := rows.Scan(
				&l.ID, &l.Hostname, &l.OS, &l.LastIP, &l.LastSeen,
				&l.Lat, &l.Lng, &l.LocationAccuracy,
				&l.LocationSource, &l.LocationCity, &l.LocationCountry,
				&l.LocationUpdated,
			); err != nil {
				continue
			}
			locs = append(locs, l)
		}
		if locs == nil {
			locs = []locationRow{}
		}
		writeJSON(w, 200, locs)
	}
}

func handleUpdateAgentLocation(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AgentID  string  `json:"agent_id"`
			Lat      float64 `json:"lat"`
			Lng      float64 `json:"lng"`
			Accuracy float64 `json:"accuracy"`
			Source   string  `json:"source"`
			City     string  `json:"city"`
			Country  string  `json:"country"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AgentID == "" {
			http.Error(w, `{"error":"bad request"}`, 400)
			return
		}
		if body.Lat == 0 && body.Lng == 0 {
			http.Error(w, `{"error":"invalid coordinates"}`, 400)
			return
		}
		// I-04: range/length validation — agent-supplied, never trusted as-is.
		if body.Lat < -90 || body.Lat > 90 || body.Lng < -180 || body.Lng > 180 ||
			body.Accuracy < 0 || body.Accuracy > 1e7 ||
			len(body.AgentID) > 128 || len(body.Source) > 32 || len(body.City) > 128 || len(body.Country) > 64 {
			http.Error(w, `{"error":"invalid location values"}`, 400)
			return
		}
		if err := db.UpdateAgentLocation(r.Context(), body.AgentID,
			body.Lat, body.Lng, body.Accuracy, body.Source, body.City, body.Country,
		); err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

// ── AI Alert Analysis ─────────────────────────────────────────────────────────

// ── AI Alert Analysis (local rule-based engine) ───────────────────────────────
