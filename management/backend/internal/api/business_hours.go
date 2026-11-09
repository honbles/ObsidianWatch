package api

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// Configurable business hours (DS-06). DEV-017/018 used a hard-coded UTC
// window (22:00-06:00). Settings (Settings table):
//
//	detection.business_hours = "07-19"   (start-end hour, 24h, local to the TZ below)
//	detection.business_tz    = "Africa/Lagos"   (IANA zone; default UTC)
//
// Defaults reproduce the previous behaviour (06-22 UTC).
var businessHours = struct {
	sync.RWMutex
	start, end int
	loc        *time.Location
}{start: 6, end: 22, loc: time.UTC}

// refreshBusinessHours reloads the settings; invalid values keep the last good ones.
func refreshBusinessHours(ctx context.Context, db *store.DB) {
	if db == nil {
		return
	}
	start, end, loc := -1, -1, (*time.Location)(nil)
	if v, err := db.GetSetting(ctx, "detection.business_hours"); err == nil && v != "" {
		var s, e int
		if n, _ := fmt.Sscanf(strings.TrimSpace(v), "%d-%d", &s, &e); n == 2 && s >= 0 && s <= 23 && e >= 1 && e <= 24 && s != e {
			start, end = s, e
		}
	}
	if v, err := db.GetSetting(ctx, "detection.business_tz"); err == nil && v != "" {
		if l, err := time.LoadLocation(strings.TrimSpace(v)); err == nil {
			loc = l
		}
	}
	businessHours.Lock()
	if start >= 0 {
		businessHours.start, businessHours.end = start, end
	}
	if loc != nil {
		businessHours.loc = loc
	}
	businessHours.Unlock()
}

// outsideBusinessHours reports whether t falls outside the configured window
// (handles windows that wrap midnight, e.g. 22-06 is "business" overnight).
func outsideBusinessHours(t time.Time) bool {
	businessHours.RLock()
	s, e, loc := businessHours.start, businessHours.end, businessHours.loc
	businessHours.RUnlock()
	h := t.In(loc).Hour()
	if s < e {
		return h < s || h >= e
	}
	return h >= e && h < s
}
