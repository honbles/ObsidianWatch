package api

// app_payload_policy.go - per-route payload review and masking (payload capture design, step 2).
//
//	PUT    /api/v1/app/services/{id}/payload-policy         admin: save a route's review (names seen, names masked)
//	DELETE /api/v1/app/services/{id}/payload-policy         admin: revoke a route's review (?route=&method=)
//	GET    /api/v1/app/services/{id}/payloads                admin: sampled requests from reviewed routes
//
// A route with no saved policy has not been reviewed: the agent forwards no parameter values for it and the
// ingest backend stores none. The policy is delivered to agents through the ingest backend's agent-config.

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

const appMaxPolicyNames = 200

// appPayloadNameOK accepts names that look like a parameter name (the agent and ingest apply the same rule).
func appPayloadNameOK(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '[' || c == ']') {
			return false
		}
	}
	return true
}

type appPayloadPolicy struct {
	Reviewed   []string  `json:"reviewed_names"`
	Masked     []string  `json:"masked"`
	ReviewedBy string    `json:"reviewed_by"`
	ReviewedAt time.Time `json:"reviewed_at"`
}

// appLoadPayloadPolicies reads the saved policies of a service, keyed "METHOD route". A missing table means
// nothing has been reviewed yet.
func appLoadPayloadPolicies(r *http.Request, db *store.DB, serviceID int64) map[string]appPayloadPolicy {
	out := map[string]appPayloadPolicy{}
	rows, err := db.QueryContext(r.Context(), `SELECT route, method, reviewed_names, masked, reviewed_by, reviewed_at
		FROM app_route_payload_policy WHERE service_id = $1`, serviceID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var route, method string
		var rv, mk []byte
		var p appPayloadPolicy
		if rows.Scan(&route, &method, &rv, &mk, &p.ReviewedBy, &p.ReviewedAt) != nil {
			continue
		}
		_ = json.Unmarshal(rv, &p.Reviewed)
		_ = json.Unmarshal(mk, &p.Masked)
		out[method+" "+route] = p
	}
	return out
}

// appParamState classifies one parameter name against a route's saved policy.
//
//	always_masked  on the fixed deny list; never forwarded
//	pending        the route has no saved policy
//	new            the route was reviewed but this name was not among the names the admin saw
//	masked         the admin masked it
//	captured       reviewed and left unmasked
func appParamState(name string, pol *appPayloadPolicy) string {
	switch {
	case PayloadNameDenied(name):
		return "always_masked"
	case pol == nil:
		return "pending"
	}
	for _, m := range pol.Masked {
		if m == name {
			return "masked"
		}
	}
	for _, n := range pol.Reviewed {
		if n == name {
			return "captured"
		}
	}
	return "new"
}

func appHandlePutPayloadPolicy(db, backendDB *store.DB) http.HandlerFunc {
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
			Route    string   `json:"route"`
			Method   string   `json:"method"`
			Reviewed []string `json:"reviewed_names"`
			Masked   []string `json:"masked"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		body.Method = strings.ToUpper(strings.TrimSpace(body.Method))
		body.Route = strings.TrimSpace(body.Route)
		switch {
		case body.Route == "" || len(body.Route) > 256 || body.Method == "" || len(body.Method) > 8:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "route and method are required"})
			return
		case len(body.Reviewed) > appMaxPolicyNames || len(body.Masked) > appMaxPolicyNames:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "too many parameter names"})
			return
		}
		clean := func(in []string) ([]string, bool) {
			seen, out := map[string]bool{}, []string{}
			for _, n := range in {
				if !appPayloadNameOK(n) {
					return nil, false
				}
				if !seen[n] {
					seen[n] = true
					out = append(out, n)
				}
			}
			sort.Strings(out)
			return out, true
		}
		reviewed, ok1 := clean(body.Reviewed)
		masked, ok2 := clean(body.Masked)
		if !ok1 || !ok2 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parameter names may only contain letters, digits and _ - . [ ]"})
			return
		}
		// The route must exist: a policy for a route the service never reported is a mistake.
		var one int
		if err := idb.QueryRowContext(r.Context(), `SELECT 1 FROM service_routes WHERE service_id=$1 AND route=$2 AND method=$3`, id, body.Route, body.Method).Scan(&one); err != nil {
			// not seen in traffic: a route declared by an API spec can be reviewed before it is
			if err2 := idb.QueryRowContext(r.Context(), `SELECT 1 FROM service_declared_routes WHERE service_id=$1 AND route=$2 AND method=$3`, id, body.Route, body.Method).Scan(&one); err2 != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "route not found for this service"})
				return
			}
		}
		by := ""
		if c := auth.GetClaims(r); c != nil {
			by = c.Username
		}
		rj, _ := json.Marshal(reviewed)
		mj, _ := json.Marshal(masked)
		tx, err := db.BeginTx(r.Context(), nil)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(r.Context(), `
			INSERT INTO app_route_payload_policy (service_id, route, method, reviewed_names, masked, reviewed_by, reviewed_at)
			VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6,NOW())
			ON CONFLICT (service_id, route, method) DO UPDATE SET reviewed_names=EXCLUDED.reviewed_names, masked=EXCLUDED.masked,
			  reviewed_by=EXCLUDED.reviewed_by, reviewed_at=NOW()`, id, body.Route, body.Method, string(rj), string(mj), by); err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO app_route_payload_policy_log (service_id, route, method, reviewed_names, masked, changed_by)
			VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6)`, id, body.Route, body.Method, string(rj), string(mj), by); err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		if err := tx.Commit(); err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		slogPolicy("saved", name, env, body.Method, body.Route, by, len(reviewed), len(masked))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "route": body.Route, "method": body.Method, "reviewed_names": reviewed, "masked": masked})
	}
}

func appHandleDeletePayloadPolicy(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		route, method := r.URL.Query().Get("route"), strings.ToUpper(r.URL.Query().Get("method"))
		if route == "" || method == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "route and method are required"})
			return
		}
		var name, env string
		if err := idb.QueryRowContext(r.Context(), `SELECT name, environment FROM services WHERE id = $1`, id).Scan(&name, &env); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "service not found"})
			return
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
		if _, err := tx.ExecContext(r.Context(), `DELETE FROM app_route_payload_policy WHERE service_id=$1 AND route=$2 AND method=$3`, id, route, method); err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO app_route_payload_policy_log (service_id, route, method, reviewed_names, masked, changed_by)
			VALUES ($1,$2,$3,'[]','[]',$4)`, id, route, method, by+" (revoked)"); err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		if err := tx.Commit(); err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		slogPolicy("revoked", name, env, method, route, by, 0, 0)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

func appHandleListPayloads(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		from, to, msg := appParseRange(r)
		if msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
			return
		}
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 || limit > 200 {
			limit = 50
		}
		offset, _ := strconv.Atoi(q.Get("offset"))
		if offset < 0 || offset > 100000 {
			offset = 0
		}
		route, method := q.Get("route"), strings.ToUpper(q.Get("method"))
		// status filter: an exact code ("500") or a class ("2xx", "4xx", "5xx"); "" means all
		lo, hi := 0, 1000
		if st := strings.ToLower(strings.TrimSpace(q.Get("status"))); st != "" {
			if len(st) == 3 && st[1:] == "xx" && st[0] >= '1' && st[0] <= '5' {
				lo = int(st[0]-'0') * 100
				hi = lo + 100
			} else if n, err := strconv.Atoi(st); err == nil && n >= 0 && n < 1000 {
				lo, hi = n, n+1
			} else {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status filter"})
				return
			}
		}
		where := `service_id = $1 AND time >= $2 AND time < $3 AND ($4 = '' OR route = $4) AND ($5 = '' OR method = $5) AND status >= $6 AND status < $7`
		var total int
		if err := idb.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM app_payloads WHERE `+where, id, from, to, route, method, lo, hi).Scan(&total); err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		rows, err := idb.QueryContext(r.Context(), `
			SELECT time, route, method, status, duration_ms, trace_id, params, withheld FROM app_payloads
			WHERE `+where+` ORDER BY time DESC, id DESC LIMIT $8 OFFSET $9`, id, from, to, route, method, lo, hi, limit, offset)
		if err != nil {
			appQueryFailed(w, r.URL.Path, id, err)
			return
		}
		defer rows.Close()
		type item struct {
			Time       time.Time         `json:"time"`
			Route      string            `json:"route"`
			Method     string            `json:"method"`
			Status     int               `json:"status"`
			DurationMs float64           `json:"duration_ms"`
			TraceID    string            `json:"trace_id,omitempty"`
			Params     map[string]string `json:"params"`
			Withheld   []string          `json:"withheld"`
		}
		list := []item{}
		for rows.Next() {
			var it item
			var pj, wj []byte
			var tr sql.NullString
			if rows.Scan(&it.Time, &it.Route, &it.Method, &it.Status, &it.DurationMs, &tr, &pj, &wj) == nil {
				it.TraceID = tr.String
				_ = json.Unmarshal(pj, &it.Params)
				_ = json.Unmarshal(wj, &it.Withheld)
				if it.Params == nil {
					it.Params = map[string]string{}
				}
				if it.Withheld == nil {
					it.Withheld = []string{}
				}
				list = append(list, it)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"payloads": list, "total": total, "offset": offset, "limit": limit,
			"has_more": offset+len(list) < total, "from": from, "to": to})
	}
}

func slogPolicy(action, service, env, method, route, by string, reviewed, masked int) {
	slog.Info("application payload policy "+action, "service", service, "environment", env, "route", method+" "+route,
		"by", by, "reviewed_names", reviewed, "masked", masked)
}
