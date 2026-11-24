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

func TestAppBulkPayloadPolicy(t *testing.T) {
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
		service_route_params, service_declared_routes, service_openapi, app_payloads, app_route_payload_policy, app_route_payload_policy_log CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"030_app_services.sql", "031_app_edge_client_stats.sql", "032_app_route_params.sql", "033_app_payloads.sql", "034_app_payloads_latency.sql", "035_app_declared_api.sql"} {
		b, _ := os.ReadFile("../../../../backend/internal/store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	for _, f := range []string{"060_app_service_settings.sql", "063_app_route_payload_policy.sql", "066_app_db_statement_mode.sql", "067_app_error_message_mode.sql", "068_app_sampling.sql", "069_app_slo.sql"} {
		b, _ := os.ReadFile("../store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC()
	var sid int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('shop','test','otel',$1,$1) RETURNING id`, now.Add(-time.Hour)).Scan(&sid)
	add := func(method, route string, names ...string) {
		raw.Exec(`INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,$2,$3,$4,$4)`, sid, route, method, now)
		for _, n := range names {
			raw.Exec(`INSERT INTO service_route_params (service_id, route, method, name, requests, first_seen, last_seen) VALUES ($1,$2,$3,$4,3,$5,$5)`, sid, route, method, n, now)
		}
	}
	add("GET", "/a", "q", "api_key")
	add("GET", "/b", "page", "sort")
	add("POST", "/c", "email")
	add("GET", "/none") // no fields: never approved
	db := &store.DB{DB: raw}
	pv := map[string]string{"id": strconv.FormatInt(sid, 10)}
	call := func(h http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/x", strings.NewReader(body))
		for k, v := range pv {
			req.SetPathValue(k, v)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	bulk := func(body string) (int, map[string]any) {
		rec := call(appHandleBulkPayloadPolicy(db, nil), "POST", body)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	pol := func(method, route string) (rev, masked string) {
		_ = raw.QueryRow(`SELECT reviewed_names::text, masked::text FROM app_route_payload_policy WHERE service_id=$1 AND route=$2 AND method=$3`, sid, route, method).Scan(&rev, &masked)
		return
	}

	// Admin only, and bad requests are refused.
	if rec := call(adminOnly(appHandleBulkPayloadPolicy(db, nil)), "POST", `{"scope":"needs_review","mode":"capture"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: %d", rec.Code)
	}
	for _, bad := range []string{`{"scope":"needs_review","mode":"yes"}`, `{"scope":"all","mode":"capture"}`, `{"mode":"capture"}`,
		`{"scope":"needs_review","routes":[{"method":"GET","route":"/a"}],"mode":"capture"}`, `nope`} {
		if code, _ := bulk(bad); code != 400 {
			t.Fatalf("accepted %s -> %d", bad, code)
		}
	}
	// Scope needs_review, capture: three routes approved, the empty route is not.
	code, out := bulk(`{"scope":"needs_review","mode":"capture"}`)
	if code != 200 || out["approved"] != float64(3) {
		t.Fatalf("scope: %d %v", code, out)
	}
	if rev, m := pol("GET", "/a"); rev != `["api_key", "q"]` || m != `[]` {
		t.Fatalf("/a: %s %s", rev, m) // the deny list is enforced at read time, so it is not stored as a choice
	}
	if _, m := pol("POST", "/c"); m != `[]` {
		t.Fatalf("/c masked: %s", m)
	}
	var n int
	_ = raw.QueryRow(`SELECT COUNT(*) FROM app_route_payload_policy WHERE route='/none'`).Scan(&n)
	if n != 0 {
		t.Fatal("a route without fields was approved")
	}
	_ = raw.QueryRow(`SELECT COUNT(*) FROM app_route_payload_policy_log WHERE service_id=$1`, sid).Scan(&n)
	if n != 3 {
		t.Fatalf("audit rows: %d", n)
	}
	// Run again: nothing is left to approve.
	if _, out := bulk(`{"scope":"needs_review","mode":"capture"}`); out["approved"] != float64(0) {
		t.Fatalf("repeat: %v", out)
	}
	// The admin masked "q" on /a earlier; a new field arrives; approving new fields keeps that choice.
	raw.Exec(`UPDATE app_route_payload_policy SET masked='["q"]' WHERE route='/a'`)
	raw.Exec(`INSERT INTO service_route_params (service_id, route, method, name, requests, first_seen, last_seen) VALUES ($1,'/a','GET','extra',1,$2,$2)`, sid, now)
	if _, out := bulk(`{"scope":"needs_review","mode":"capture"}`); out["approved"] != float64(0) {
		t.Fatalf("needs_review must not touch reviewed routes: %v", out)
	}
	if _, out := bulk(`{"scope":"needs_review_and_new_fields","mode":"names_only"}`); out["approved"] != float64(1) {
		t.Fatalf("new fields: %v", out)
	}
	if rev, m := pol("GET", "/a"); !strings.Contains(rev, "extra") || m != `["extra", "q"]` {
		t.Fatalf("/a after: %s %s", rev, m) // q stays masked, extra is masked by names_only, api_key untouched
	}
	// An explicit list, names only: every field of the route is masked.
	raw.Exec(`DELETE FROM app_route_payload_policy WHERE route='/b'`)
	if code, out := bulk(`{"routes":[{"method":"get","route":"/b"},{"method":"GET","route":"/b"},{"method":"GET","route":"/none"}],"mode":"names_only"}`); code != 200 || out["approved"] != float64(1) || out["skipped"] != float64(1) {
		t.Fatalf("list: %d %v", code, out)
	}
	if _, m := pol("GET", "/b"); m != `["page", "sort"]` {
		t.Fatalf("/b masked: %s", m)
	}
}
