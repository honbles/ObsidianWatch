package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

func TestAppPurgeIntegration(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, f := range []string{"migrations/011_settings.sql", "../../../../backend/internal/store/migrations/030_app_services.sql"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if _, err := raw.Exec(`DROP TABLE IF EXISTS app_traces, app_route_stats, app_baselines, service_versions, service_routes,
		service_edges, service_instances, services, service_settings, app_edge_stats, app_client_stats CASCADE`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"030_app_services.sql", "031_app_edge_client_stats.sql"} {
		b, _ := os.ReadFile("../../../../backend/internal/store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatal(err)
		}
	}
	raw.Exec(`DELETE FROM settings WHERE key LIKE 'app.retention_%'`)
	now := time.Now().UTC()
	for _, d := range []int{1, 100} {
		if _, err := raw.Exec(`INSERT INTO app_route_stats (minute, service_id, route, method) VALUES ($1,1,'/','GET')`, now.AddDate(0, 0, -d)); err != nil {
			t.Fatal(err)
		}
	}
	for i, d := range []int{1, 10} {
		if _, err := raw.Exec(`INSERT INTO app_traces (trace_id, service_id, agent_id, started) VALUES ($1,1,'a',$2)`, string(rune('a'+i)), now.AddDate(0, 0, -d)); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []int{1, 100} {
		raw.Exec(`INSERT INTO app_edge_stats (hour, src_service, dst_kind, dst_name, source) VALUES ($1,1,'database','pg','otel')`, now.AddDate(0, 0, -d))
	}
	for _, d := range []int{1, 10} {
		raw.Exec(`INSERT INTO app_client_stats (minute, service_id, route, method, client_ip) VALUES ($1,1,'/login','POST','203.0.113.9')`, now.AddDate(0, 0, -d))
	}
	db := &DB{DB: raw}
	res, err := db.AppPurge(context.Background(), now)
	if err != nil || res.Stats != 1 || res.Traces != 1 || res.EdgeStats != 1 || res.ClientStats != 1 {
		t.Fatalf("defaults: %+v err=%v", res, err)
	}
	raw.Exec(`INSERT INTO settings (key, value) VALUES ('app.retention_trace_days','0'),('app.retention_stats_days','abc') ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`)
	if sd, td := db.AppRetentionDays(context.Background()); sd != AppDefaultStatsDays || td != AppDefaultTraceDays {
		t.Fatalf("invalid values must fall back: %d %d", sd, td)
	}
}
