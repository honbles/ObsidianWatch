package api

// app_agentconfig.go - GET /api/v1/app/agent-config. Agents poll this over their existing
// outbound HTTPS connection to learn per-service privacy and sampling settings, so a change in
// the UI (client-address mode, cleartext user ids, latency target) takes effect without an
// agent rebuild. Nothing is pushed to the agent and no inbound port is opened.

import (
	"context"
	"log/slog"
	"net/http"

	"obsidianwatch/backend/internal/store"
)

type appConfigStore interface {
	AppAgentInfo(ctx context.Context, id string) (host, osName string, ok bool, err error)
	AppRemoteConfig(ctx context.Context) ([]store.AppRemoteService, error)
}

func appHandleAgentConfig(db appConfigStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("agent_id")
		if id == "" || len(id) > 128 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing or invalid agent_id"})
			return
		}
		_, _, ok, err := db.AppAgentInfo(r.Context(), id)
		if err != nil {
			logger.Error("app agent-config: agent lookup failed", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "unknown agent"})
			return
		}
		svcs, err := db.AppRemoteConfig(r.Context())
		if err != nil {
			logger.Error("app agent-config: read failed", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"services": svcs})
	}
}
