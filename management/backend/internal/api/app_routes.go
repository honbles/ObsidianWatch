package api

// app_routes.go - OWNED BY THE APPLICATION BUILD. All /api/v1/app/* routes are
// registered here.

import (
	"net/http"

	"obsidianwatch/management/internal/store"
)

func registerAppRoutes(protected *http.ServeMux, db *store.DB, backendDB *store.DB) {
	appStartRules(db, backendDB, nil) // the rule worker and scanner start with the routes
	protected.HandleFunc("GET /api/v1/app/services", appHandleListServices(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}", appHandleGetService(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/rules/status", appHandleRulesStatus())
	protected.HandleFunc("GET /api/v1/app/map", appHandleMap(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/overview", appHandleOverview(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/instances/{id}", appHandleGetInstance(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/runtime", appHandleServiceRuntime(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/alerts", appHandleServiceAlerts(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/events", appHandleServiceEvents(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/timeline", appHandleServiceTimeline(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/red", appHandleREDSeries(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/routes", appHandleRoutes(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/edges", appHandleServiceEdges(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/traces", appHandleListTraces(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/errors", appHandleErrors(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/errors/{id}", appHandleGetError(db, backendDB))
	protected.HandleFunc("PATCH /api/v1/app/errors/{id}", appHandlePatchError(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/queries", appHandleQueries(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/metrics", appHandleMetrics(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/slo", appHandleSLO(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/operations", appHandleOperations(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/sampling", appHandleSampling(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/services/{id}/compare", appHandleCompare(db, backendDB))
	protected.HandleFunc("GET /api/v1/app/traces/{trace_id}", appHandleGetTrace(db, backendDB))
	protected.HandleFunc("PUT /api/v1/app/services/{id}/payload-policy", adminOnly(appHandlePutPayloadPolicy(db, backendDB)))
	protected.HandleFunc("POST /api/v1/app/services/{id}/payload-policy/bulk", adminOnly(appHandleBulkPayloadPolicy(db, backendDB)))
	protected.HandleFunc("DELETE /api/v1/app/services/{id}/payload-policy", adminOnly(appHandleDeletePayloadPolicy(db, backendDB)))
	protected.HandleFunc("GET /api/v1/app/services/{id}/openapi", adminOnly(appHandleGetOpenAPI(db, backendDB)))
	protected.HandleFunc("POST /api/v1/app/services/{id}/openapi", adminOnly(appHandleLoadOpenAPI(db, backendDB)))
	protected.HandleFunc("DELETE /api/v1/app/services/{id}/openapi", adminOnly(appHandleDeleteOpenAPI(db, backendDB)))
	protected.HandleFunc("GET /api/v1/app/services/{id}/payloads", adminOnly(appHandleListPayloads(db, backendDB)))
	protected.HandleFunc("PUT /api/v1/app/services/{id}/settings", adminOnly(appHandlePutServiceSettings(db, backendDB)))
}
