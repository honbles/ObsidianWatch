package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"obsidianwatch/backend/internal/store"
)

type agentStore interface {
	ListAgents(ctx context.Context) ([]store.Agent, error)
	GetAgent(ctx context.Context, id string) (*store.Agent, error)
}

// GET /api/v1/agents  — list all known agents
func handleListAgents(db agentStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		agents, err := db.ListAgents(r.Context())
		if err != nil {
			http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"agents": agents,
			"count":  len(agents),
		})
	}
}

// GET /api/v1/agents/{id}  — get a single agent
func handleGetAgent(db agentStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		// Extract ID from path: /api/v1/agents/{id}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, `{"error":"missing agent id"}`, http.StatusBadRequest)
			return
		}

		agent, err := db.GetAgent(r.Context(), id)
		if err != nil {
			http.Error(w, `{"error":"agent not found"}`, http.StatusNotFound)
			return
		}

		writeJSON(w, http.StatusOK, agent)
	}
}

// Ensure agentStore is satisfied by *store.DB at compile time.
var _ agentStore = (*store.DB)(nil)

// handleUpdateAgentLocation receives a location update from an agent.
func handleUpdateAgentLocation(db *store.DB, logger *slog.Logger) http.HandlerFunc {
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
		if err := db.UpdateAgentLocation(r.Context(), body.AgentID,
			body.Lat, body.Lng, body.Accuracy, body.Source, body.City, body.Country,
		); err != nil {
			logger.Warn("location update failed", "agent", body.AgentID, "err", err)
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		logger.Info("location updated", "agent", body.AgentID, "source", body.Source,
			"city", body.City, "lat", body.Lat, "lng", body.Lng)
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}
