package api

import (
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestAppMapIntegration(t *testing.T) {
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
	for _, f := range []string{"../../../../backend/internal/store/migrations/030_app_services.sql", "../../../../backend/internal/store/migrations/031_app_edge_client_stats.sql", "../store/migrations/060_app_service_settings.sql", "../store/migrations/066_app_db_statement_mode.sql", "../store/migrations/067_app_error_message_mode.sql", "../store/migrations/068_app_sampling.sql", "../store/migrations/069_app_slo.sql"} {
		b, _ := os.ReadFile(f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC()
	old := now.Add(-30 * 24 * time.Hour)
	mk := func(name, env string) int64 {
		var id int64
		raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ($1,$2,'otel',$3,$4) RETURNING id`, name, env, old, now).Scan(&id)
		return id
	}
	web, orders, billing, stale := mk("web", "prod"), mk("orders", "prod"), mk("billing", "prod"), mk("web", "staging")
	_ = stale
	raw.Exec(`INSERT INTO service_settings (service_id, exposure, criticality) VALUES ($1,'internet','normal'), ($2,'internal','critical')`, web, billing)
	edge := func(src int64, kind, dst string, first time.Time, calls int64) {
		raw.Exec(`INSERT INTO service_edges (src_service, dst_kind, dst_name, source, calls, first_seen, last_seen) VALUES ($1,$2,$3,'otel',$4,$5,$6)`, src, kind, dst, calls, first, now)
		raw.Exec(`INSERT INTO app_edge_stats (hour, src_service, dst_kind, dst_name, source, calls, errors) VALUES ($1,$2,$3,$4,'otel',$5,1)`, now.Truncate(time.Hour), src, kind, dst, calls)
	}
	edge(web, "service", "orders", old, 100)    // resolves to the orders service
	edge(orders, "service", "billing", old, 50) // web -> orders -> billing: billing reachable from the internet
	edge(orders, "database", "postgresql@db1", old, 400)
	edge(web, "external", "evil.example.com", now.Add(-2*time.Hour), 3) // new, beyond the service's first day
	edge(billing, "service", "ghost", old, 1)                           // unresolved service stays a pseudo node
	db := &store.DB{DB: raw}
	rng := "?from=" + now.Add(-24*time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Minute).Format(time.RFC3339)
	rec := appGet(appHandleMap(db, nil), "/x"+rng, nil)
	var m struct {
		Nodes []appMapNode `json:"nodes"`
		Edges []appMapEdge `json:"edges"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	nodes := map[string]appMapNode{}
	for _, n := range m.Nodes {
		nodes[n.ID] = n
	}
	if len(m.Edges) != 5 {
		t.Fatalf("edges: %s", rec.Body.String())
	}
	var sawResolved, sawNew bool
	for _, e := range m.Edges {
		if e.Source == "service:web|prod" && e.Target == "service:orders|prod" && e.Calls == 100 {
			sawResolved = true
		}
		if e.Target == "external:evil.example.com" && e.New {
			sawNew = true
		}
		if e.Target == "service:orders|prod" && e.New {
			t.Fatal("an old dependency must not be flagged new")
		}
	}
	if !sawResolved || !sawNew {
		t.Fatalf("resolved=%v new=%v: %s", sawResolved, sawNew, rec.Body.String())
	}
	if _, ok := nodes["service:ghost"]; !ok || nodes["service:ghost"].ServiceID != 0 {
		t.Fatalf("unresolved peer.service must be a pseudo node: %+v", nodes["service:ghost"])
	}
	if !nodes["service:web|prod"].ReachableFromInternet || !nodes["service:orders|prod"].ReachableFromInternet || !nodes["service:billing|prod"].ReachableFromInternet {
		t.Fatalf("reachability: %+v", nodes)
	}
	if nodes["service:web|staging"].ReachableFromInternet || nodes["database:postgresql@db1"].ReachableFromInternet {
		t.Fatal("unrelated services and non-service nodes must not be marked reachable")
	}
	if nodes["service:billing|prod"].Criticality != "critical" || nodes["service:web|prod"].Exposure != "internet" {
		t.Fatalf("settings on nodes: %+v", nodes["service:billing|prod"])
	}
	if rec := appGet(appHandleMap(db, nil), "/x?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z", nil); rec.Code != 400 {
		t.Fatalf("bad range: %d", rec.Code)
	}
}
