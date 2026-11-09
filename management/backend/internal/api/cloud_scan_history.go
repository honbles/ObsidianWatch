package api

import (
	"net/http"
	"strconv"

	"obsidianwatch/management/internal/store"
)

// handleCSPMHistory returns severity counts per CSPM scan for a connector.
//
//	GET /api/v1/cloud-connectors/{id}/cspm/history?days=90
func handleCSPMHistory(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		conn, cerr := db.GetCloudConnectorRaw(r.Context(), id)
		if err != nil || cerr != nil {
			writeJSON(w, 404, map[string]string{"error": "connector not found"})
			return
		}
		days := 90
		if v, e := strconv.Atoi(r.URL.Query().Get("days")); e == nil && v > 0 && v <= 180 {
			days = v
		}
		pts, herr := db.ListScanHistory(r.Context(), conn.Provider, id, days)
		if herr != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"points": pts, "days": days})
	}
}
