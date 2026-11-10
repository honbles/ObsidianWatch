package api

// app_routes.go — OWNED BY THE APPLICATION BUILD. Registers POST /api/v1/app/batch and other agent-facing /api/v1/app/* routes
// on the ingest backend (API-key authenticated mux). Foundation stub.

import (
	"log/slog"
	"net/http"

	"obsidianwatch/backend/internal/store"
)

func registerApplicationIngestRoutes(protected *http.ServeMux, db *store.DB, logger *slog.Logger) {
	_ = protected
	_ = db
	_ = logger
}
