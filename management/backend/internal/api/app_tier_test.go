package api

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestAppTierTwoFromHelperEvents(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	appMustExec(t, raw, `DROP TABLE IF EXISTS events CASCADE`)
	appMustExec(t, raw, `CREATE TABLE events (id TEXT, time TIMESTAMPTZ NOT NULL, event_type TEXT, raw JSONB)`)
	now := time.Now()
	appMustExec(t, raw, `INSERT INTO events VALUES ('1',$1,'app.security','{"app":{"service":"juice-shop","environment":"test"}}')`, now.Add(-time.Hour))
	appMustExec(t, raw, `INSERT INTO events VALUES ('2',$1,'app.security','{"app":{"service":"old","environment":"test"}}')`, now.Add(-30*24*time.Hour))
	appHelperCache.mu.Lock()
	appHelperCache.set = nil
	appHelperCache.mu.Unlock()
	set := appHelperServices(context.Background(), &store.DB{DB: raw})
	if !set["juice-shop|test"] || set["old|test"] {
		t.Fatalf("helper set: %v", set)
	}
	if appTierWithHelper("otel", "juice-shop|test", set) != 2 || appTierWithHelper("otel", "other|test", set) != 1 || appTierWithHelper("discovered", "juice-shop|test", set) != 0 {
		t.Fatal("tier lifting")
	}
}
