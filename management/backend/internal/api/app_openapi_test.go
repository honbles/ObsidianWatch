package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestAppBlockedIPAndFetchGuard(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "fe80::1"} {
		if !appBlockedIP(net.ParseIP(ip)) {
			t.Errorf("%s must be blocked", ip)
		}
	}
	for _, ip := range []string{"10.1.2.3", "192.168.0.5", "93.184.216.34"} {
		if appBlockedIP(net.ParseIP(ip)) {
			t.Errorf("%s must be allowed", ip)
		}
	}
	for _, u := range []string{"ftp://x/y", "file:///etc/passwd", "http://127.0.0.1:3000/api-docs", "http://169.254.169.254/latest", "http://user:pw@example.com/", "not a url", "http://[::1]/x"} {
		if _, err := appFetchSpec(context.Background(), u); err == nil {
			t.Errorf("%s must be refused", u)
		}
	}
	// a hostname that resolves to loopback is refused when dialling, not only when parsing
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) }))
	defer ts.Close()
	if _, err := appFetchSpec(context.Background(), strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)); err == nil {
		t.Error("localhost must be refused at dial time")
	}
}

func TestAppOpenAPIDeclaredRoutesIntegration(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	appMustExec(t, raw, `DROP TABLE IF EXISTS app_traces, app_route_stats, app_baselines, service_versions, service_routes,
		service_edges, service_instances, services, service_settings, app_edge_stats, app_client_stats, app_service_merges,
		service_route_params, service_declared_routes, service_openapi, app_payloads, app_route_payload_policy, app_route_payload_policy_log CASCADE`)
	for _, f := range []string{"030_app_services.sql", "031_app_edge_client_stats.sql", "032_app_route_params.sql", "033_app_payloads.sql", "034_app_payloads_latency.sql", "035_app_declared_api.sql"} {
		b, _ := os.ReadFile("../../../../backend/internal/store/migrations/" + f)
		appMustExec(t, raw, string(b))
	}
	for _, f := range []string{"060_app_service_settings.sql", "063_app_route_payload_policy.sql"} {
		b, _ := os.ReadFile("../store/migrations/" + f)
		appMustExec(t, raw, string(b))
	}
	now := time.Now().UTC()
	var sid int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('juice-shop','test','otel',$1,$1) RETURNING id`, now.Add(-time.Hour)).Scan(&sid)
	// an observed route written in the framework's style, with one observed field the spec will not list
	appMustExec(t, raw, `INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,'/api/Products/:id','GET',$2,$2)`, sid, now)
	appMustExec(t, raw, `INSERT INTO service_route_params (service_id, route, method, name, requests, first_seen, last_seen) VALUES ($1,'/api/Products/:id','GET','debug',4,$2,$2)`, sid, now)
	appMustExec(t, raw, `INSERT INTO service_route_params (service_id, route, method, name, requests, first_seen, last_seen) VALUES ($1,'/api/Products/:id','GET','q',9,$2,$2)`, sid, now)
	// an observed route the spec does not list
	appMustExec(t, raw, `INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,'/hidden','GET',$2,$2)`, sid, now)

	db := &store.DB{DB: raw}
	pv := map[string]string{"id": strconv.FormatInt(sid, 10)}
	rng := "?from=" + now.Add(-time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Minute).Format(time.RFC3339)
	call := func(h http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/x"+rng, strings.NewReader(body))
		for k, v := range pv {
			req.SetPathValue(k, v)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	routes := func() map[string]appRouteRow {
		t.Helper()
		rec := appGet(appHandleRoutes(db, nil), "/x"+rng, pv)
		var out struct {
			Routes []appRouteRow `json:"routes"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		m := map[string]appRouteRow{}
		for _, r := range out.Routes {
			m[r.Method+" "+r.Route] = r
		}
		if rec.Code != 200 {
			t.Fatalf("routes: %d %s", rec.Code, rec.Body.String())
		}
		return m
	}
	before := routes()
	if before["GET /hidden"].NotInSpec || before["GET /hidden"].Declared {
		t.Fatal("no spec loaded: nothing is 'not in spec'")
	}

	withFeedbacks := strings.Replace(appTestOAS3, "components:\n  parameters", "  /Feedbacks:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema: {type: object, properties: {comment: {type: string}, rating: {type: integer}}}\ncomponents:\n  parameters", 1)
	spec, _ := json.Marshal(map[string]string{"spec": withFeedbacks})
	rec := call(appHandleLoadOpenAPI(db, nil), "POST", string(spec))
	if rec.Code != 200 {
		t.Fatalf("load: %d %s", rec.Code, rec.Body.String())
	}
	var info appOpenAPIInfo
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if !info.Loaded || info.Routes != 3 || info.Matched != 1 || info.Title != "Shop" {
		t.Fatalf("info: %+v", info)
	}
	if rec := call(appHandleLoadOpenAPI(db, nil), "POST", `{"spec":"x","url":"http://example.com"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("both spec and url: %d", rec.Code)
	}
	if rec := call(appHandleLoadOpenAPI(db, nil), "POST", `{"spec":"hello: world"}`); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("not a spec: %d", rec.Code)
	}

	got := routes()
	// the declared "/api/Products/{id}" joined the observed "/api/Products/:id"
	p := got["GET /api/Products/:id"]
	if !p.Declared || !p.Observed || len(got) != 4 {
		t.Fatalf("merged route: %+v (%d routes)", p, len(got))
	}
	states := map[string]appRouteParam{}
	for _, f := range p.Params {
		states[f.Name] = f
	}
	if states["q"].Source != "both" || states["debug"].Source != "observed" || !states["debug"].Undocumented || states["q"].Undocumented {
		t.Fatalf("param merge: %+v", states)
	}
	if states["lang"].Source != "declared" || states["lang"].Requests != 0 || states["lang"].Location != "query" {
		t.Fatalf("declared field: %+v", states["lang"])
	}
	// declared only: listed with no traffic, reviewable before any request
	u := got["POST /api/Users"]
	if !u.Declared || u.Observed || u.Active || u.PayloadReview != "needs_review" || len(u.Params) < 5 {
		t.Fatalf("declared-only route: %+v", u)
	}
	if !got["GET /hidden"].NotInSpec {
		t.Fatal("an observed route missing from the spec is flagged")
	}
	// review before traffic: the policy is accepted for a declared-only route
	body := `{"route":"/api/Users","method":"POST","reviewed_names":["email","password","securityQuestion.id","id","items[].sku"],"masked":["email"]}`
	if rec := call(appHandlePutPayloadPolicy(db, nil), "PUT", body); rec.Code != 200 {
		t.Fatalf("review a declared route: %d %s", rec.Code, rec.Body.String())
	}
	if routes()["POST /api/Users"].PayloadReview != "reviewed" {
		t.Fatal("reviewed")
	}
	// traffic arrives later: an undeclared field is flagged, a declared one is merged
	appMustExec(t, raw, `INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,'/api/Users','POST',$2,$2)`, sid, now)
	appMustExec(t, raw, `INSERT INTO service_route_params (service_id, route, method, name, requests, first_seen, last_seen, source) VALUES ($1,'/api/Users','POST','role',3,$2,$2,'observed')`, sid, now)
	appMustExec(t, raw, `UPDATE service_route_params SET source='both', requests=3 WHERE service_id=$1 AND route='/api/Users' AND name='email'`, sid)
	u = routes()["POST /api/Users"]
	if !u.Observed || !u.Declared || u.PayloadReview != "new_fields" {
		t.Fatalf("after traffic: %+v", u)
	}
	for _, f := range u.Params {
		if f.Name == "role" && (!f.Undocumented || f.State != "new") {
			t.Fatalf("role: %+v", f)
		}
	}
	// removing the spec forgets declared-only fields and keeps observed ones
	if rec := call(appHandleDeleteOpenAPI(db, nil), "DELETE", ""); rec.Code != 200 {
		t.Fatalf("delete: %d", rec.Code)
	}
	after := routes()
	if _, ok := after["GET /hidden"]; !ok || after["GET /hidden"].NotInSpec || after["GET /api/Products/:id"].Declared {
		t.Fatalf("after delete: %+v", after["GET /api/Products/:id"])
	}
	for _, f := range after["GET /api/Products/:id"].Params {
		if f.Source != "observed" {
			t.Fatalf("source after delete: %+v", f)
		}
	}
	if rec := call(appHandleGetOpenAPI(db, nil), "GET", ""); !strings.Contains(rec.Body.String(), `"loaded":false`) {
		t.Fatalf("status after delete: %s", rec.Body.String())
	}
}
