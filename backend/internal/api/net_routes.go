package api

// net_routes.go — OWNED BY THE NETWORK BUILD. Registers /api/v1/probe/* and /api/v1/network/* ingest routes
// on the ingest backend (API-key authenticated mux). Foundation stub.

import (
	"log/slog"
	"net/http"

	"obsidianwatch/backend/internal/store"
)

func registerNetworkIngestRoutes(protected *http.ServeMux, db *store.DB, logger *slog.Logger) {
	_ = protected
	_ = db
	_ = logger
}
