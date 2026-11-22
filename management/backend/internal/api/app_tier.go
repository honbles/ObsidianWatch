package api

// app_tier.go - Tier 2: a service that has sent security-helper events (event_type app.security) in the last
// 14 days. Tier 1 is OpenTelemetry, Tier 0 is host discovery only. The set of helper services is read from the
// events table and cached for a minute so list pages do not each scan it.

import (
	"context"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

const appHelperWindow = 14 * 24 * time.Hour

var appHelperCache struct {
	mu  sync.Mutex
	at  time.Time
	set map[string]bool
}

// appHelperServices returns the "name|environment" keys of services that sent helper events recently.
func appHelperServices(ctx context.Context, db *store.DB) map[string]bool {
	c := &appHelperCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.set != nil && time.Since(c.at) < time.Minute {
		return c.set
	}
	set := map[string]bool{}
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT COALESCE(raw->'app'->>'service',''), COALESCE(raw->'app'->>'environment','')
		FROM events WHERE event_type = 'app.security' AND time >= $1`, time.Now().Add(-appHelperWindow))
	if err == nil {
		for rows.Next() {
			var n, e string
			if rows.Scan(&n, &e) == nil && n != "" {
				set[appServiceKey(n, e)] = true
			}
		}
		rows.Close()
	}
	c.set, c.at = set, time.Now()
	return set
}

// appTierWithHelper lifts an OpenTelemetry service to Tier 2 when it has sent helper events.
func appTierWithHelper(source, key string, helpers map[string]bool) int {
	t := appTier(source)
	if t >= 1 && helpers[key] {
		return 2
	}
	return t
}
