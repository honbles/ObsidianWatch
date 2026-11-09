package api

// P-13: new-country and country-level impossible-travel detection on Entra
// sign-ins. Entra supplies the sign-in country, so no GeoIP database is needed.
// Per user we remember the countries of earlier successful sign-ins (seeded
// lazily from stored events) and the most recent one.
//
// Limits: country granularity only (same-country travel is not detected), VPN
// egress countries count as real locations, and a user needs minGeoBaseline
// earlier successful sign-ins before a new country is flagged.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

const (
	minGeoBaseline      = 3
	impossibleTravelGap = 2 * time.Hour
)

type geoUser struct {
	countries map[string]bool
	signins   int
	lastCtry  string
	lastTime  time.Time
}

type entraGeoTracker struct {
	mu    sync.Mutex
	users map[string]*geoUser
}

func newEntraGeoTracker() *entraGeoTracker { return &entraGeoTracker{users: map[string]*geoUser{}} }

type entraGeo struct {
	User    string
	Country string
	OK      bool
}

func parseEntraGeo(ev store.Event) entraGeo {
	if ev.EventType != "cloud.entra_signin" {
		return entraGeo{}
	}
	var r struct {
		UPN      string `json:"user_principal_name"`
		Location struct {
			Country string `json:"countryOrRegion"`
		} `json:"location"`
		Status struct {
			ErrorCode int `json:"errorCode"`
		} `json:"status"`
		Kind string `json:"sign_in_kind"`
	}
	if json.Unmarshal(ev.Raw, &r) != nil || r.UPN == "" || r.Location.Country == "" || r.Status.ErrorCode != 0 || r.Kind != "" {
		return entraGeo{}
	}
	return entraGeo{User: strings.ToLower(r.UPN), Country: strings.ToUpper(r.Location.Country), OK: true}
}

// observe updates state and returns correlation hits. seed is called at most
// once per user to load earlier countries (nil in tests that pre-fill state).
func (t *entraGeoTracker) observe(ev store.Event, seed func(user string, before time.Time) (map[string]bool, int, string, time.Time)) []authHit {
	g := parseEntraGeo(ev)
	if !g.OK {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.users) > 20000 {
		t.users = map[string]*geoUser{}
	}
	u := t.users[g.User]
	if u == nil {
		u = &geoUser{countries: map[string]bool{}}
		if seed != nil {
			u.countries, u.signins, u.lastCtry, u.lastTime = seed(g.User, ev.Time)
			if u.countries == nil {
				u.countries = map[string]bool{}
			}
		}
		t.users[g.User] = u
	}
	var hits []authHit
	day := ev.Time.UTC().Unix() / 86400
	if u.signins >= minGeoBaseline && !u.countries[g.Country] {
		hits = append(hits, authHit{
			Rule: "CORR-GEO-001", Title: "Entra sign-in from a new country",
			Desc:     fmt.Sprintf("%s signed in from %s, a country not seen in their earlier successful sign-ins (%d on record).", g.User, g.Country, u.signins),
			Severity: 3, MITRE: "T1078.004", Entity: g.User + "|" + g.Country, Bucket: day,
		})
	}
	if u.lastCtry != "" && u.lastCtry != g.Country && ev.Time.After(u.lastTime) && ev.Time.Sub(u.lastTime) < impossibleTravelGap {
		hits = append(hits, authHit{
			Rule: "CORR-GEO-002", Title: "Entra impossible travel (country level)",
			Desc: fmt.Sprintf("%s signed in from %s %s after a sign-in from %s. Countries differ too quickly for normal travel (VPN or proxy use is possible).",
				g.User, g.Country, ev.Time.Sub(u.lastTime).Round(time.Minute), u.lastCtry),
			Severity: 4, MITRE: "T1078.004", Entity: g.User + "|" + u.lastCtry + ">" + g.Country, Bucket: day,
		})
	}
	u.countries[g.Country] = true
	u.signins++
	if ev.Time.After(u.lastTime) {
		u.lastCtry, u.lastTime = g.Country, ev.Time
	}
	return hits
}

// dbGeoSeed loads up to 300 earlier successful sign-in countries for a user.
func dbGeoSeed(ctx context.Context, db *store.DB) func(string, time.Time) (map[string]bool, int, string, time.Time) {
	return func(user string, before time.Time) (map[string]bool, int, string, time.Time) {
		evs, _, err := db.QueryEvents(ctx, store.EventFilter{
			HostExact: user, EventType: "cloud.entra_signin", Since: before.Add(-30 * 24 * time.Hour),
			Until: before.Add(-time.Second), Limit: 300, SkipCount: true, SkipEnrich: true,
		})
		if err != nil {
			return nil, 0, "", time.Time{}
		}
		set := map[string]bool{}
		n := 0
		last, lastT := "", time.Time{}
		for _, e := range evs {
			g := parseEntraGeo(e)
			if !g.OK {
				continue
			}
			set[g.Country] = true
			n++
			if e.Time.After(lastT) {
				last, lastT = g.Country, e.Time
			}
		}
		return set, n, last, lastT
	}
}
