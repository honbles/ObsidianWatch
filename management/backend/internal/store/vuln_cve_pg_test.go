package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Runs against a real Postgres when OW_TEST_PG is set (applies migration 043).
func TestVulnCVEStorePG(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG")
	if dsn == "" {
		t.Skip("OW_TEST_PG not set")
	}
	sdb, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	mig, err := os.ReadFile("migrations/043_vuln_cve.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sdb.Exec(string(mig)); err != nil {
		t.Fatalf("migration: %v", err)
	}
	sdb.Exec(`DELETE FROM vuln_cpe_cache; DELETE FROM vuln_host_cve`)
	db := &DB{DB: sdb}
	ctx := context.Background()

	if _, _, ok := db.CPECacheGet(ctx, "cpe:x", time.Hour); ok {
		t.Fatal("empty cache must miss")
	}
	if err := db.CPECachePut(ctx, "cpe:x", 7, json.RawMessage(`[{"id":"CVE-1"}]`)); err != nil {
		t.Fatal(err)
	}
	b, total, ok := db.CPECacheGet(ctx, "cpe:x", time.Hour)
	if !ok || total != 7 || len(b) == 0 {
		t.Fatalf("cache hit: %v %d %s", ok, total, b)
	}
	if _, _, ok := db.CPECacheGet(ctx, "cpe:x", -time.Second); ok {
		t.Fatal("expired entry must miss")
	}
	// upsert
	db.CPECachePut(ctx, "cpe:x", 9, json.RawMessage(`[]`))
	if _, total, _ := db.CPECacheGet(ctx, "cpe:x", time.Hour); total != 9 {
		t.Fatalf("upsert total %d", total)
	}

	scanAt := time.Date(2026, 11, 14, 10, 0, 0, 123456000, time.UTC)
	if err := db.HostCVEPut(ctx, "h1", scanAt, json.RawMessage(`{"status":"done"}`)); err != nil {
		t.Fatal(err)
	}
	res, sa, at, ok := db.HostCVEGet(ctx, "h1")
	if !ok || !sa.Equal(scanAt) || time.Since(at) > time.Minute || string(res) != `{"status": "done"}` && string(res) != `{"status":"done"}` {
		t.Fatalf("host cve: %v %v %v %s", ok, sa, at, res)
	}
}
