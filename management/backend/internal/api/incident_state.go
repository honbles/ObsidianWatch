package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// P-04: analyst state for incidents (status, owner, notes). Incident IDs are
// derived deterministically from host + first alert time, so state is keyed by
// ID in the settings table and re-attached on every listing.
const incidentStatePrefix = "incident.state."

type IncidentState struct {
	Status    string    `json:"status"` // open | investigating | resolved | false_positive
	Owner     string    `json:"owner,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

var validIncidentStatus = map[string]bool{"open": true, "investigating": true, "resolved": true, "false_positive": true}

func loadIncidentStates(r *http.Request, db *store.DB) map[string]IncidentState {
	out := map[string]IncidentState{}
	m, err := db.GetSettingsPrefix(r.Context(), incidentStatePrefix)
	if err != nil {
		return out
	}
	for k, v := range m {
		var st IncidentState
		if json.Unmarshal([]byte(v), &st) == nil {
			out[strings.TrimPrefix(k, incidentStatePrefix)] = st
		}
	}
	return out
}

// applyIncidentState attaches state and filters by status ("" or "all" = no filter;
// default view hides resolved / false-positive incidents).
func applyIncidentState(inc []Incident, states map[string]IncidentState, want string) []Incident {
	out := make([]Incident, 0, len(inc))
	for _, i := range inc {
		st, ok := states[i.ID]
		if !ok {
			st = IncidentState{Status: "open"}
		}
		i.State = &st
		switch want {
		case "all":
		case "":
			if st.Status == "resolved" || st.Status == "false_positive" {
				continue
			}
		default:
			if st.Status != want {
				continue
			}
		}
		out = append(out, i)
	}
	return out
}

func handleIncidentUpdate(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !strings.HasPrefix(id, "inc-") || len(id) > 40 {
			writeJSONError(w, http.StatusBadRequest, "invalid incident id")
			return
		}
		var req struct {
			Status *string `json:"status"`
			Owner  *string `json:"owner"`
			Notes  *string `json:"notes"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid body")
			return
		}
		cur := IncidentState{Status: "open"}
		if v, err := db.GetSetting(r.Context(), incidentStatePrefix+id); err == nil && v != "" {
			_ = json.Unmarshal([]byte(v), &cur)
		}
		if req.Status != nil {
			if !validIncidentStatus[*req.Status] {
				writeJSONError(w, http.StatusBadRequest, "status must be open, investigating, resolved or false_positive")
				return
			}
			cur.Status = *req.Status
		}
		if req.Owner != nil {
			cur.Owner = strings.TrimSpace(*req.Owner)
		}
		if req.Notes != nil {
			if len(*req.Notes) > 8000 {
				writeJSONError(w, http.StatusBadRequest, "notes too long")
				return
			}
			cur.Notes = *req.Notes
		}
		user := "unknown"
		if c := auth.GetClaims(r); c != nil {
			user = c.Username
		}
		cur.UpdatedBy, cur.UpdatedAt = user, time.Now().UTC()
		b, _ := json.Marshal(cur)
		if err := db.SetSetting(r.Context(), incidentStatePrefix+id, string(b)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to save")
			return
		}
		db.WriteAudit(r.Context(), user, "update_incident", id, cur.Status+" owner="+cur.Owner, clientIP(r))
		writeJSON(w, http.StatusOK, cur)
	}
}
