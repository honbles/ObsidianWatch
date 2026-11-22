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

func TestAppValidateSettings(t *testing.T) {
	ok := appDefaultSettings()
	ok.Exposure, ok.Criticality = "internet", "high"
	ok.TrustedProxies = []string{"10.0.0.0/8", "192.168.1.5"}
	if msg := appValidateSettings(ok); msg != "" {
		t.Fatal(msg)
	}
	mut := func(f func(*appServiceSettings)) appServiceSettings {
		s := appDefaultSettings()
		f(&s)
		return s
	}
	neg, big := -1, 700000
	pct := 101.0
	for name, bad := range map[string]appServiceSettings{
		"exposure":    mut(func(s *appServiceSettings) { s.Exposure = "public" }),
		"criticality": mut(func(s *appServiceSettings) { s.Criticality = "urgent" }),
		"sensitivity": mut(func(s *appServiceSettings) { s.DataSensitivity = "secret" }),
		"clientip":    mut(func(s *appServiceSettings) { s.StoreClientIP = "hash" }),
		"owner":       mut(func(s *appServiceSettings) { s.Owner = strings.Repeat("o", 129) }),
		"cidr":        mut(func(s *appServiceSettings) { s.TrustedProxies = []string{"not-a-cidr"} }),
		"emptyroute":  mut(func(s *appServiceSettings) { s.LoginRoutes = []string{""} }),
		"latneg":      mut(func(s *appServiceSettings) { s.LatencyTargetMs = &neg }),
		"latbig":      mut(func(s *appServiceSettings) { s.LatencyTargetMs = &big }),
		"budget":      mut(func(s *appServiceSettings) { s.ErrorBudgetPct = &pct }),
		"window": mut(func(s *appServiceSettings) {
			s.Maintenance = []appMaintenance{{Start: time.Now(), End: time.Now().Add(-time.Hour)}}
		}),
	} {
		if appValidateSettings(bad) == "" {
			t.Fatalf("should reject %s", name)
		}
	}
}

func TestAppServiceKeyAndTier(t *testing.T) {
	if appServiceKey("api", "prod") != "api|prod" {
		t.Fatal("key format must be name|environment")
	}
	if appTier("otel") != 1 || appTier("discovered") != 0 {
		t.Fatal("tier mapping")
	}
}

// Integration: runs only when OW_TEST_PG_DSN points at a scratch Postgres.
func TestAppServicesAPIIntegration(t *testing.T) {
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
		service_edges, service_instances, services, service_settings, app_edge_stats, app_client_stats, app_service_merges CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		"../../../../backend/internal/store/migrations/002_agents.sql",
		"../../../../backend/internal/store/migrations/030_app_services.sql", "../../../../backend/internal/store/migrations/031_app_edge_client_stats.sql",
		"../store/migrations/060_app_service_settings.sql", "../store/migrations/064_app_db_statement_mode.sql",
		"../store/migrations/060_app_service_settings.sql", "../store/migrations/064_app_db_statement_mode.sql", // twice: idempotent
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC()
	var id int64
	if err := raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen, attrs) VALUES ('api','prod','otel',$1,$1,'{"language":"java"}') RETURNING id`, now).Scan(&id); err != nil {
		t.Fatal(err)
	}
	raw.Exec(`INSERT INTO service_instances (service_id, agent_id, host, pid, instance_ref, version, identity, attrs, first_seen, last_seen)
		VALUES ($1,'a1','web-01',100,'i1','1.0','verified','{"container_name":"api-1","image":"registry/acme/api:1.0","unit":""}',$2,$2)`, id, now)
	raw.Exec(`INSERT INTO service_edges (src_service, dst_kind, dst_name, source, calls, first_seen, last_seen) VALUES ($1,'database','pg:5432','otel',9,$2,$2)`, id, now)
	db := &store.DB{DB: raw}

	rec := httptest.NewRecorder()
	appHandleListServices(db, nil)(rec, httptest.NewRequest("GET", "/api/v1/app/services", nil))
	var list struct {
		Services []appServiceRow `json:"services"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != 200 || len(list.Services) != 1 || list.Services[0].Instances != 1 || list.Services[0].Tier != 1 ||
		list.Services[0].Settings.Exposure != "unknown" || list.Services[0].Edges != 1 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}

	if l := list.Services[0]; len(l.Containers) != 1 || l.Containers[0] != "api-1" || len(l.Images) != 1 || len(l.Units) != 0 || len(l.Hosts) != 1 || l.Hosts[0] != "web-01" {
		t.Fatalf("where the service runs: %+v %+v %+v %+v", l.Containers, l.Images, l.Units, l.Hosts)
	}

	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "/x", strings.NewReader(body))
		req.SetPathValue("id", strconv.FormatInt(id, 10))
		r := httptest.NewRecorder()
		appHandlePutServiceSettings(db, nil)(r, req)
		return r
	}
	if r := put(`{"exposure":"nope"}`); r.Code != http.StatusBadRequest {
		t.Fatalf("bad settings accepted: %d", r.Code)
	}
	if r := put(`{"exposure":"internet","criticality":"critical","owner":"payments","trusted_proxies":["10.0.0.0/8"],
	   "login_routes":["/login"],"latency_target_ms":300,"error_budget_pct":1.5,"reset_learning":true}`); r.Code != 200 {
		t.Fatalf("put: %d %s", r.Code, r.Body.String())
	}
	// A second PUT without reset must keep learning_started.
	if r := put(`{"exposure":"internet","criticality":"high"}`); r.Code != 200 {
		t.Fatalf("put2: %d %s", r.Code, r.Body.String())
	}

	req := httptest.NewRequest("GET", "/x", nil)
	req.SetPathValue("id", strconv.FormatInt(id, 10))
	rec = httptest.NewRecorder()
	appHandleGetService(db, nil)(rec, req)
	var det struct {
		Service   appServiceRow `json:"service"`
		Instances []struct {
			Identity string `json:"identity"`
		} `json:"instances"`
		Edges []any `json:"edges"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &det)
	s := det.Service.Settings
	if rec.Code != 200 || s.Exposure != "internet" || s.Criticality != "high" || s.LearningStarted == nil ||
		len(det.Instances) != 1 || det.Instances[0].Identity != "verified" || len(det.Edges) != 1 {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body.String())
	}
}
