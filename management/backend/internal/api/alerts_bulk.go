package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// F-28: bulk alert actions (acknowledge, close, assign) so analysts can work
// a queue instead of clicking each alert.
const bulkAlertMax = 500

func handleBulkAlerts(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IDs        []int64 `json:"ids"`
			Action     string  `json:"action"` // acknowledge | close | assign
			Comment    string  `json:"comment,omitempty"`
			AssignedTo string  `json:"assigned_to,omitempty"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req) != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if len(req.IDs) == 0 || len(req.IDs) > bulkAlertMax {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("ids must contain 1-%d alert ids", bulkAlertMax))
			return
		}
		req.Action = strings.ToLower(req.Action)
		if req.Action == "assign" && strings.TrimSpace(req.AssignedTo) == "" {
			writeJSONError(w, http.StatusBadRequest, "assigned_to required for assign")
			return
		}
		if req.Action != "acknowledge" && req.Action != "close" && req.Action != "assign" {
			writeJSONError(w, http.StatusBadRequest, "action must be acknowledge, close or assign")
			return
		}
		user := "unknown"
		if c := auth.GetClaims(r); c != nil {
			user = c.Username
		}
		okIDs := []int64{}
		failed := map[string]string{}
		for _, id := range req.IDs {
			var err error
			switch req.Action {
			case "acknowledge":
				err = db.AcknowledgeAlert(r.Context(), id, user)
			case "close":
				if req.Comment != "" {
					err = db.CloseAlertWithReview(r.Context(), id, user, req.Comment)
				} else {
					err = db.CloseAlert(r.Context(), id, user)
				}
			case "assign":
				err = db.AssignAlert(r.Context(), id, req.AssignedTo, user, req.Comment)
			}
			if err != nil {
				failed[fmt.Sprint(id)] = err.Error()
			} else {
				okIDs = append(okIDs, id)
			}
		}
		db.WriteAudit(r.Context(), user, "bulk_"+req.Action+"_alerts", fmt.Sprintf("alerts:%d", len(okIDs)),
			fmt.Sprintf("ok=%d failed=%d", len(okIDs), len(failed)), clientIP(r))
		writeJSON(w, http.StatusOK, map[string]interface{}{"action": req.Action, "succeeded": okIDs, "failed": failed})
	}
}
