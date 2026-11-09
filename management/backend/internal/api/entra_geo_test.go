package api

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func geoEv(user, country string, code int, at time.Time) store.Event {
	raw, _ := json.Marshal(map[string]interface{}{
		"user_principal_name": user, "location": map[string]string{"countryOrRegion": country},
		"status": map[string]int{"errorCode": code},
	})
	return store.Event{EventType: "cloud.entra_signin", Raw: raw, Time: at}
}

func TestEntraGeoNewCountryAndTravel(t *testing.T) {
	tr := newEntraGeoTracker()
	base := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 3; i++ { // baseline in NG
		if h := tr.observe(geoEv("a@x.io", "NG", 0, base.Add(time.Duration(i)*time.Hour)), nil); len(h) != 0 {
			t.Fatalf("baseline should not alert: %+v", h)
		}
	}
	// New country a day later: new-country but not impossible travel.
	h := tr.observe(geoEv("a@x.io", "RU", 0, base.Add(24*time.Hour)), nil)
	if len(h) != 1 || h[0].Rule != "CORR-GEO-001" {
		t.Fatalf("want new-country only, got %+v", h)
	}
	// Back to NG 30 minutes later: impossible travel, not a new country.
	h = tr.observe(geoEv("a@x.io", "NG", 0, base.Add(24*time.Hour+30*time.Minute)), nil)
	if len(h) != 1 || h[0].Rule != "CORR-GEO-002" {
		t.Fatalf("want impossible travel, got %+v", h)
	}
	// Failed sign-ins and users with too little history are ignored.
	if h := tr.observe(geoEv("a@x.io", "CN", 50126, time.Now()), nil); len(h) != 0 {
		t.Fatal("failed sign-in must be ignored")
	}
	tr2 := newEntraGeoTracker()
	if h := tr2.observe(geoEv("new@x.io", "US", 0, base), nil); len(h) != 0 {
		t.Fatal("first sign-in must not alert")
	}
	if h := tr2.observe(geoEv("new@x.io", "DE", 0, base.Add(72*time.Hour)), nil); len(h) != 0 {
		t.Fatalf("no baseline yet, got %+v", h)
	}
}

func TestEntraGeoSeed(t *testing.T) {
	tr := newEntraGeoTracker()
	now := time.Now()
	seed := func(user string, before time.Time) (map[string]bool, int, string, time.Time) {
		return map[string]bool{"NG": true}, 10, "NG", before.Add(-24 * time.Hour)
	}
	h := tr.observe(geoEv("b@x.io", "BR", 0, now), seed)
	if len(h) != 1 || h[0].Rule != "CORR-GEO-001" {
		t.Fatalf("seeded baseline should flag new country: %+v", h)
	}
	_ = fmt.Sprint(h)
}
