package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
)

// Needs a database with every migration applied (OW_TEST_PG_DSN).
func TestAlertWindowDedupePG(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.Exec(`DELETE FROM alerts`)
	db := &DB{DB: raw}
	ctx := context.Background()
	mk := func(title, host string, sev int, src string) Alert {
		return Alert{Title: title, Host: host, AgentID: "ag-" + host, Severity: sev, EventType: "process", EventID: "k-" + src, SourceEventID: src}
	}
	id1, ins, err := db.CreateAlertDeduped(ctx, mk("Rare binary", "H1", 2, "e1"))
	if err != nil || !ins {
		t.Fatalf("first alert: %v %v", err, ins)
	}
	// same title, same host, different rule key: folded in
	id2, ins, err := db.CreateAlertDeduped(ctx, mk("Rare binary", "H1", 2, "e2"))
	if err != nil || ins || id2 != id1 {
		t.Fatalf("repeat must fold into the first: id=%d first=%d inserted=%v err=%v", id2, id1, ins, err)
	}
	// a more severe repeat raises the severity
	if _, ins, _ = db.CreateAlertDeduped(ctx, mk("Rare binary", "H1", 4, "e3")); ins {
		t.Fatal("severe repeat must still fold")
	}
	var count, sev, related int
	raw.QueryRow(`SELECT occurrence_count, severity FROM alerts WHERE id=$1`, id1).Scan(&count, &sev)
	raw.QueryRow(`SELECT count(*) FROM alert_related_events WHERE alert_id=$1`, id1).Scan(&related)
	if count != 3 || sev != 4 || related != 2 {
		t.Fatalf("count=%d severity=%d related=%d, want 3, 4, 2", count, sev, related)
	}
	// other host and other title are separate alerts
	if _, ins, _ = db.CreateAlertDeduped(ctx, mk("Rare binary", "H2", 2, "e4")); !ins {
		t.Fatal("another host must get its own alert")
	}
	if _, ins, _ = db.CreateAlertDeduped(ctx, mk("Other rule", "H1", 2, "e5")); !ins {
		t.Fatal("another title must get its own alert")
	}
	// outside the window: a new alert
	raw.Exec(`UPDATE alerts SET last_seen = NOW() - interval '31 minutes' WHERE id=$1`, id1)
	id3, ins, _ := db.CreateAlertDeduped(ctx, mk("Rare binary", "H1", 2, "e6"))
	if !ins || id3 == id1 {
		t.Fatal("a repeat after the window must be a new alert")
	}
	// a closed alert is not reopened by a repeat
	raw.Exec(`UPDATE alerts SET status='closed' WHERE id=$1`, id3)
	id4, ins, _ := db.CreateAlertDeduped(ctx, mk("Rare binary", "H1", 2, "e7"))
	if !ins || id4 == id3 {
		t.Fatal("a closed alert must not absorb a repeat")
	}
	// an alert older than the max age stops absorbing repeats even if it keeps being seen
	raw.Exec(`UPDATE alerts SET created_at = NOW() - interval '25 hours', last_seen = NOW() WHERE id=$1`, id4)
	id5, ins, _ := db.CreateAlertDeduped(ctx, mk("Rare binary", "H1", 2, "e8"))
	if !ins || id5 == id4 {
		t.Fatal("an alert past the max age must not absorb repeats")
	}
	// concurrent identical alerts produce exactly one row
	raw.Exec(`DELETE FROM alerts`)
	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func(i int) {
			_, ins, err := db.CreateAlertDeduped(ctx, mk("Burst", "H9", 2, "b"+string(rune('a'+i))))
			done <- err == nil && ins
		}(i)
	}
	inserted := 0
	for i := 0; i < 20; i++ {
		if <-done {
			inserted++
		}
	}
	if inserted != 1 {
		t.Fatalf("20 concurrent identical alerts inserted %d rows, want 1", inserted)
	}
	raw.Exec(`DELETE FROM alerts`)
}
