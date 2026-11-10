package api

// app_routes.go — OWNED BY THE APPLICATION BUILD. All /api/v1/app/* routes are
// registered here. Foundation stub.

import (
	"net/http"

	"obsidianwatch/management/internal/store"
)

func registerAppRoutes(protected *http.ServeMux, db *store.DB, backendDB *store.DB) {
	_ = protected
	_ = db
	_ = backendDB
}
