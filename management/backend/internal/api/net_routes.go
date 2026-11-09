package api

// net_routes.go — OWNED BY THE NETWORK BUILD. All /api/v1/network/* and
// /api/v1/probe/* routes are registered here. Foundation stub.

import (
	"net/http"

	"obsidianwatch/management/internal/store"
)

func registerNetRoutes(protected *http.ServeMux, db *store.DB, backendDB *store.DB) {
	_ = protected
	_ = db
	_ = backendDB
}
