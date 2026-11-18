package api

// app_routes.go - OWNED BY THE APPLICATION BUILD. Registers POST /api/v1/app/batch and other agent-facing /api/v1/app/* routes
// on the ingest backend (API-key authenticated mux).

import (
	"log/slog"
	"net/http"

	"obsidianwatch/backend/internal/store"
)

func registerApplicationIngestRoutes(protected *http.ServeMux, db *store.DB, logger *slog.Logger) {
	protected.HandleFunc("POST /api/v1/app/batch", appHandleBatch(db, logger))
	protected.HandleFunc("GET /api/v1/app/agent-config", appHandleAgentConfig(db, logger))
}
