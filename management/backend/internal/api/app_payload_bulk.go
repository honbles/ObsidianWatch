package api

// app_payload_bulk.go - approve the fields of many routes at once.
//
//	POST /api/v1/app/services/{id}/payload-policy/bulk
//	{"scope":"needs_review" | "needs_review_and_new_fields", "mode":"capture" | "names_only"}
//	{"routes":[{"method":"GET","route":"/x"}], "mode":"capture" | "names_only"}
//
// The server reads each route's field names itself; the client never sends names. A route that has fields and
// no review is approved with every current name listed as reviewed. Mode "capture" leaves every field unmasked
// except the always-masked names, so values are forwarded; mode "names_only" masks every field, so the route is
// reviewed but no value leaves the host. A route that already has a review keeps what was masked before; only
// its new fields are approved. Admin only. Every route approved is audit-logged like a single review.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

const appBulkMaxRoutes = 1000

func appHandleBulkPayloadPolicy(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		var name, env string
		if err := idb.QueryRowContext(r.Context(), `SELECT name, environment FROM services WHERE id = $1`, id).Scan(&name, &env); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "service not found"})
			return
		}
		var body struct {
			Scope  string `json:"scope"`
			Mode   string `json:"mode"`
			Routes []struct {
				Method string `json:"method"`
				Route  string `json:"route"`
			} `json:"routes"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		if body.Mode != "capture" && body.Mode != "names_only" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": `mode must be "capture" or "names_only"`})
			return
		}
		if body.Scope != "" && body.Scope != "needs_review" && body.Scope != "needs_review_and_new_fields" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown scope"})
			return
		}
		if (body.Scope == "") == (len(body.Routes) == 0) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "send either a scope or a list of routes"})
			return
		}
		if len(body.Routes) > appBulkMaxRoutes {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "too many routes in one request"})
			return
		}

		// Field names per route, as the service has reported or declared them.
		names := map[string][]string{} // "METHOD route" -> names
		rows, err := idb.QueryContext(r.Context(), `SELECT route, method, name FROM service_route_params WHERE service_id = $1 ORDER BY name`, id)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		for rows.Next() {
			var route, method, n string
			if rows.Scan(&route, &method, &n) == nil && appPayloadNameOK(n) {
				k := method + " " + route
				names[k] = append(names[k], n)
			}
		}
		rows.Close()
		policies := appLoadPayloadPolicies(r, db, id)

		// Which routes to approve.
		var targets []string
		if body.Scope != "" {
			for k, ns := range names {
				pol, has := policies[k]
				switch {
				case len(ns) == 0:
				case !has:
					targets = append(targets, k)
				case body.Scope == "needs_review_and_new_fields" && appHasNewNames(ns, pol):
					targets = append(targets, k)
				}
			}
			sort.Strings(targets)
			if len(targets) > appBulkMaxRoutes {
				targets = targets[:appBulkMaxRoutes] // the rest is approved by repeating the request
			}
		} else {
			seen := map[string]bool{}
			for _, x := range body.Routes {
				k := strings.ToUpper(strings.TrimSpace(x.Method)) + " " + strings.TrimSpace(x.Route)
				if !seen[k] {
					seen[k] = true
					targets = append(targets, k)
				}
			}
		}

		by := ""
		if c := auth.GetClaims(r); c != nil {
			by = c.Username
		}
		tx, err := db.BeginTx(r.Context(), nil)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		defer tx.Rollback()
		approved, skipped := 0, 0
		for _, k := range targets {
			method, route, _ := strings.Cut(k, " ")
			ns := names[k]
			if len(ns) == 0 || route == "" || len(route) > 256 {
				skipped++
				continue
			}
			if len(ns) > appMaxPolicyNames {
				ns = ns[:appMaxPolicyNames]
			}
			masked := map[string]bool{}
			if pol, has := policies[k]; has { // keep earlier choices
				for _, m := range pol.Masked {
					masked[m] = true
				}
			}
			for _, n := range ns { // names_only masks the fields this review adds; capture adds them unmasked
				if body.Mode == "names_only" && !appInList(n, policies[k].Reviewed) {
					masked[n] = true
				}
			}
			ml := make([]string, 0, len(masked))
			for n := range masked {
				if appInList(n, ns) {
					ml = append(ml, n)
				}
			}
			sort.Strings(ml)
			rj, _ := json.Marshal(ns)
			mj, _ := json.Marshal(ml)
			if _, err := tx.ExecContext(r.Context(), `
				INSERT INTO app_route_payload_policy (service_id, route, method, reviewed_names, masked, reviewed_by, reviewed_at)
				VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6,NOW())
				ON CONFLICT (service_id, route, method) DO UPDATE SET reviewed_names=EXCLUDED.reviewed_names, masked=EXCLUDED.masked,
				  reviewed_by=EXCLUDED.reviewed_by, reviewed_at=NOW()`, id, route, method, string(rj), string(mj), by); err != nil {
				appQueryFailed(w, r.URL.Path, id, err)
				return
			}
			if _, err := tx.ExecContext(r.Context(), `INSERT INTO app_route_payload_policy_log (service_id, route, method, reviewed_names, masked, changed_by)
				VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6)`, id, route, method, string(rj), string(mj), by); err != nil {
				appQueryFailed(w, r.URL.Path, id, err)
				return
			}
			approved++
		}
		if err := tx.Commit(); err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		slogPolicy("bulk approved "+body.Mode, name, env, "*", strconv.Itoa(approved)+" routes", by, approved, 0)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "approved": approved, "skipped": skipped, "mode": body.Mode})
	}
}

func appInList(n string, list []string) bool {
	for _, x := range list {
		if x == n {
			return true
		}
	}
	return false
}

// appHasNewNames reports whether a route has a field the saved review has not listed.
func appHasNewNames(names []string, pol appPayloadPolicy) bool {
	for _, n := range names {
		if !PayloadNameDenied(n) && !appInList(n, pol.Reviewed) {
			return true
		}
	}
	return false
}
