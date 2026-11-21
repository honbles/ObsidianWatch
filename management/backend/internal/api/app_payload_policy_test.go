package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestAppPayloadPolicyIntegration(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE IF EXISTS app_traces, app_route_stats, app_baselines, service_versions, service_routes,
		service_edges, service_instances, services, service_settings, app_edge_stats, app_client_stats, app_service_merges,
		service_route_params, app_payloads, app_route_payload_policy, app_route_payload_policy_log CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"030_app_services.sql", "031_app_edge_client_stats.sql", "032_app_route_params.sql", "033_app_payloads.sql"} {
		b, _ := os.ReadFile("../../../../backend/internal/store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	for _, f := range []string{"060_app_service_settings.sql", "063_app_route_payload_policy.sql"} {
		b, _ := os.ReadFile("../store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC()
	var sid int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('juice-shop','test','otel',$1,$1) RETURNING id`, now.Add(-time.Hour)).Scan(&sid)
	raw.Exec(`INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,'/rest/products/search','GET',$2,$2)`, sid, now)
	for _, n := range []string{"q", "sort", "api_key"} {
		raw.Exec(`INSERT INTO service_route_params (service_id, route, method, name, requests, first_seen, last_seen) VALUES ($1,'/rest/products/search','GET',$2,5,$3,$3)`, sid, n, now)
	}
	db := &store.DB{DB: raw}
	pv := map[string]string{"id": strconv.FormatInt(sid, 10)}
	rng := "?from=" + now.Add(-time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Minute).Format(time.RFC3339)

	call := func(h http.HandlerFunc, method, url, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		for k, v := range pv {
			req.SetPathValue(k, v)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	routes := func() appRouteRow {
		t.Helper()
		rec := appGet(appHandleRoutes(db, nil), "/x"+rng, pv)
		var out struct {
			Routes []appRouteRow `json:"routes"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != 200 || len(out.Routes) != 1 {
			t.Fatalf("routes: %d %s", rec.Code, rec.Body.String())
		}
		return out.Routes[0]
	}
	states := func(r appRouteRow) string {
		var s []string
		for _, p := range r.Params {
			s = append(s, p.Name+"="+p.State)
		}
		return strings.Join(s, ",")
	}

	// 1. Unreviewed: needs review, nothing is captured, and the always-masked name is shown as such.
	if r := routes(); r.PayloadReview != "needs_review" || r.Policy != nil || states(r) != "q=pending,sort=pending,api_key=always_masked" {
		t.Fatalf("unreviewed: %s %+v", r.PayloadReview, states(r))
	}
	// 2. Only an admin can save: the wrapper rejects a request without admin claims.
	if rec := call(adminOnly(appHandlePutPayloadPolicy(db, nil)), "PUT", "/x", `{}`); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: %d", rec.Code)
	}
	put := func(body string) *httptest.ResponseRecorder {
		return call(appHandlePutPayloadPolicy(db, nil), "PUT", "/x", body)
	}
	for _, bad := range []string{`{"route":"/rest/products/search","method":"GET","reviewed_names":["a b"],"masked":[]}`,
		`{"route":"/rest/products/search","method":"GET","reviewed_names":["q"],"masked":["x=y"]}`,
		`{"route":"/nope","method":"GET","reviewed_names":["q"],"masked":[]}`, `{"route":"","method":"GET"}`, `not json`} {
		if rec := put(bad); rec.Code < 400 {
			t.Fatalf("bad policy accepted: %s -> %d", bad, rec.Code)
		}
	}
	// 3. The admin saw q, sort and api_key, and masked sort.
	if rec := put(`{"route":"/rest/products/search","method":"get","reviewed_names":["sort","q","api_key","q"],"masked":["sort"]}`); rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	if r := routes(); r.PayloadReview != "reviewed" || r.Policy == nil || states(r) != "q=captured,sort=masked,api_key=always_masked" {
		t.Fatalf("reviewed: %s %s", r.PayloadReview, states(r))
	}
	// 4. A parameter that appears later is a new field: withheld until reviewed.
	raw.Exec(`INSERT INTO service_route_params (service_id, route, method, name, requests, first_seen, last_seen) VALUES ($1,'/rest/products/search','GET','newfield',1,$2,$2)`, sid, now)
	if r := routes(); r.PayloadReview != "new_fields" || !strings.Contains(states(r), "newfield=new") {
		t.Fatalf("new field: %s %s", r.PayloadReview, states(r))
	}
	// 5. The audit log records who saved what.
	var logs int
	_ = raw.QueryRow(`SELECT COUNT(*) FROM app_route_payload_policy_log WHERE service_id=$1`, sid).Scan(&logs)
	if logs != 1 {
		t.Fatalf("audit rows: %d", logs)
	}
	// 6. Revoking returns the route to needs_review (and is logged).
	if rec := call(appHandleDeletePayloadPolicy(db, nil), "DELETE", "/x?route=/rest/products/search&method=GET", ""); rec.Code != 200 {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if r := routes(); r.PayloadReview != "needs_review" || r.Policy != nil {
		t.Fatalf("revoked: %s", r.PayloadReview)
	}
	_ = raw.QueryRow(`SELECT COUNT(*) FROM app_route_payload_policy_log WHERE service_id=$1`, sid).Scan(&logs)
	if logs != 2 {
		t.Fatalf("revocation is logged: %d", logs)
	}
	// 7. Sampled requests are listed from the ingest table.
	raw.Exec(`INSERT INTO app_payloads (service_id, time, route, method, status, params, withheld) VALUES ($1,$2,'/rest/products/search','GET',200,'{"q":"apple"}','["sort"]')`, sid, now.Add(-time.Minute))
	rec := call(appHandleListPayloads(db, nil), "GET", "/x"+rng, "")
	var pl struct {
		Payloads []struct {
			Params   map[string]string `json:"params"`
			Withheld []string          `json:"withheld"`
		} `json:"payloads"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &pl)
	if rec.Code != 200 || len(pl.Payloads) != 1 || pl.Payloads[0].Params["q"] != "apple" || len(pl.Payloads[0].Withheld) != 1 {
		t.Fatalf("payloads: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(adminOnly(appHandleListPayloads(db, nil)), "GET", "/x"+rng, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("payloads are admin only: %d", rec.Code)
	}
}
