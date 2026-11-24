package api

import (
	"database/sql"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestAppSamplingValidation(t *testing.T) {
	ok := appDefaultSettings()
	if m := appValidateSettings(ok); m != "" {
		t.Fatal(m)
	}
	zero, big := 0.0, 101.0
	s := ok
	s.Sampling = appSampling{BaselinePct: &zero, ErrorMaxPerMin: 20, MaxPerFlush: 100}
	if m := appValidateSettings(s); m != "" {
		t.Fatalf("baseline 0 is valid (it turns baseline off): %s", m)
	}
	for _, bad := range []appSampling{{BaselinePct: &big}, {ErrorMaxPerMin: -1}, {MaxPerFlush: 6000}} {
		s.Sampling = bad
		if appValidateSettings(s) == "" {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestAppSamplingAPI(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_, _ = raw.Exec(`DROP TABLE IF EXISTS app_sampling_stats, services CASCADE`)
	for _, f := range []string{"030_app_services.sql", "040_app_sampling.sql"} {
		b, _ := os.ReadFile("../../../../backend/internal/store/migrations/" + f)
		if _, err := raw.Exec(string(b)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	now := time.Now().UTC()
	var sid int64
	raw.QueryRow(`INSERT INTO services (name, environment, source, first_seen, last_seen) VALUES ('api','prod','otel',$1,$1) RETURNING id`, now).Scan(&sid)
	raw.Exec(`INSERT INTO app_sampling_stats VALUES ($1,$2,'baseline',100,1),($1,$2,'error',7,7)`, now.Truncate(time.Hour), sid)
	db := &store.DB{DB: raw}
	pv := map[string]string{"id": strconv.FormatInt(sid, 10)}
	rng := "?from=" + now.Add(-2*time.Hour).Format(time.RFC3339) + "&to=" + now.Add(time.Hour).Format(time.RFC3339)
	rec := appGet(appHandleSampling(db, nil), "/x"+rng, pv)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, `{"reason":"error","seen":7,"kept":7},{"reason":"baseline","seen":100,"kept":1}`) {
		t.Fatalf("%d %s", rec.Code, body)
	}
}
