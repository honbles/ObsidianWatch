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

func TestAppO08NewErrorGroup(t *testing.T) {
	fx := appNewFx(t)
	fx.d.errGroups = []appErrGroupRef{
		{ID: 1, Fingerprint: "aaaaaaaaaaaaaaaa", Type: "TypeError", Route: "/orders/:id", Method: "GET", Frame: "getOrder src/orders.js:42", Count: 5, FirstSeen: appNow.Add(-5 * time.Minute), Status: "open"},
		{ID: 2, Fingerprint: "bbbbbbbbbbbbbbbb", Type: "Error", Count: 1, FirstSeen: appNow.Add(-5 * time.Minute), Status: "open"},                    // one stray exception
		{ID: 3, Fingerprint: "cccccccccccccccc", Type: "Error", Count: 9, FirstSeen: appNow.Add(-5 * time.Minute), Status: "ignored"},                 // triaged as ignored
		{ID: 4, Fingerprint: "dddddddddddddddd", Type: "Error", Count: 9, FirstSeen: appNow.Add(-5 * time.Hour), Status: "open", RegressedAt: appNow}, // old group
	}
	fx.scan()
	got := fx.pos("APM-O08", 1)
	if !strings.Contains(got[0].F.Detail, "TypeError on GET /orders/:id at getOrder") {
		t.Fatalf("detail: %s", got[0].F.Detail)
	}
	// A service in its first day of learning is quiet: everything is new then.
	l := appNewFx(t)
	l.setSvc(func(s *appSvc) { s.FirstSeen = appNow.Add(-2 * time.Hour) })
	l.d.errGroups = fx.d.errGroups[:1]
	l.scan()
	l.neg("APM-O08")
}

func TestAppO09Regression(t *testing.T) {
	fx := appNewFx(t)
	fx.d.errGroups = []appErrGroupRef{
		{ID: 1, Fingerprint: "aaaaaaaaaaaaaaaa", Type: "Error", Route: "/x", Method: "GET", Count: 9, FirstSeen: appNow.Add(-48 * time.Hour), RegressedAt: appNow.Add(-5 * time.Minute), Version: "1.1.0", Status: "open"},
		{ID: 2, Fingerprint: "bbbbbbbbbbbbbbbb", Type: "Error", Count: 9, FirstSeen: appNow.Add(-48 * time.Hour), RegressedAt: appNow.Add(-5 * time.Minute), Status: "resolved"},
	}
	fx.scan()
	got := fx.pos("APM-O09", 1)
	if !strings.Contains(got[0].F.Detail, "1.1.0") {
		t.Fatalf("detail: %s", got[0].F.Detail)
	}
	q := appNewFx(t)
	q.d.errGroups = []appErrGroupRef{{ID: 3, Fingerprint: "cccccccccccccccc", Count: 9, FirstSeen: appNow.Add(-48 * time.Hour), Status: "open"}} // never regressed
	q.scan()
	q.neg("APM-O09")
}

func TestAppErrorsAPI(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DROP TABLE IF EXISTS error_group_hours, error_groups, app_traces, app_route_stats, app_baselines, service_versions, service_routes,
		service_edges, service_instances, services, service_settings, app_edge_stats, app_client_stats, app_service_merges,
		service_route_params, service_declared_routes, service_openapi, app_payloads, app_route_payload_policy, app_route_payload_policy_log,
		app_route_children, app_db_stats, app_route_n1 CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"030_app_services.sql", "031_app_edge_client_stats.sql", "037_app_errors.sql"} {
		b, _ := os.ReadFile("../../../../backend/internal/store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC()
	var sid int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('orders','prod','otel',$1,$1) RETURNING id`, now.Add(-time.Hour)).Scan(&sid)
	var g1, g2 int64
	raw.QueryRow(`INSERT INTO error_groups (service_id, fingerprint, type, route, method, frame, frames, first_seen, last_seen, count, first_version, last_version, sample_traces)
		VALUES ($1,'aaaaaaaaaaaaaaaa','TypeError','/orders/:id','GET','getOrder src/orders.js:42','["getOrder src/orders.js:42","handler src/routes.js:10"]',$2,$2,7,'1.0.0','1.0.0','["0102030405060708090a0b0c0d0e0f10"]') RETURNING id`, sid, now.Add(-10*time.Minute)).Scan(&g1)
	raw.QueryRow(`INSERT INTO error_groups (service_id, fingerprint, type, first_seen, last_seen, count, status) VALUES ($1,'bbbbbbbbbbbbbbbb','Error',$2,$2,2,'ignored') RETURNING id`, sid, now.Add(-20*time.Minute)).Scan(&g2)
	raw.Exec(`INSERT INTO error_group_hours (group_id, hour, count) VALUES ($1,$2,7),($3,$2,2)`, g1, now.Truncate(time.Hour), g2)

	db := &store.DB{DB: raw}
	call := func(h http.HandlerFunc, method, url, body string, pv map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		for k, v := range pv {
			req.SetPathValue(k, v)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	rng := "?from=" + now.Add(-time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Minute).Format(time.RFC3339)
	sp := map[string]string{"id": strconv.FormatInt(sid, 10)}
	var list struct {
		Errors []appErrorGroup `json:"errors"`
	}
	rec := call(appHandleErrors(db, nil), "GET", "/x"+rng, "", sp)
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != 200 || len(list.Errors) != 2 || list.Errors[0].ID != g1 || list.Errors[0].RangeCount != 7 || len(list.Errors[0].Frames) != 0 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	rec = call(appHandleErrors(db, nil), "GET", "/x"+rng+"&status=ignored", "", sp)
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Errors) != 1 || list.Errors[0].ID != g2 {
		t.Fatalf("status filter: %s", rec.Body.String())
	}
	if rec := call(appHandleErrors(db, nil), "GET", "/x"+rng+"&status=bogus", "", sp); rec.Code != 400 {
		t.Fatalf("bad status: %d", rec.Code)
	}
	gp := map[string]string{"id": strconv.FormatInt(g1, 10)}
	var one appErrorGroup
	rec = call(appHandleGetError(db, nil), "GET", "/x", "", gp)
	_ = json.Unmarshal(rec.Body.Bytes(), &one)
	if rec.Code != 200 || len(one.Frames) != 2 || len(one.SampleTraces) != 1 || one.ServiceName != "orders" {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body.String())
	}
	// Resolving records the running version; an unknown status or an empty body is refused.
	rec = call(appHandlePatchError(db, nil), "PATCH", "/x", `{"status":"resolved","assignee":"dana"}`, gp)
	_ = json.Unmarshal(rec.Body.Bytes(), &one)
	if rec.Code != 200 || one.Status != "resolved" || one.ResolvedIn != "1.0.0" || one.Assignee != "dana" {
		t.Fatalf("resolve: %d %s", rec.Code, rec.Body.String())
	}
	for _, bad := range []string{`{}`, `{"status":"done"}`, `nope`, `{"assignee":"` + strings.Repeat("x", 200) + `"}`} {
		if rec := call(appHandlePatchError(db, nil), "PATCH", "/x", bad, gp); rec.Code != 400 {
			t.Fatalf("accepted %s -> %d", bad, rec.Code)
		}
	}
	if rec := call(appHandlePatchError(db, nil), "PATCH", "/x", `{"status":"open"}`, map[string]string{"id": "999999"}); rec.Code != 404 {
		t.Fatalf("missing group: %d", rec.Code)
	}
	// Reopening by hand clears the resolved version and the regression flag.
	rec = call(appHandlePatchError(db, nil), "PATCH", "/x", `{"status":"open"}`, gp)
	one = appErrorGroup{}
	_ = json.Unmarshal(rec.Body.Bytes(), &one)
	if one.Status != "open" || one.ResolvedIn != "" || one.Regressed {
		t.Fatalf("reopen: %s", rec.Body.String())
	}
}
