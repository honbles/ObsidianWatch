package api

// Detection cycle helpers: how often the engine polls, and a short-lived
// cache for the indicator sets. The engine used to reload every IOC (tens of
// thousands of rows) from the database on every cycle even when there was
// nothing to evaluate, which is what made a short poll interval too costly.

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

const (
	defaultDetectionSeconds = 10
	iocCacheTTL             = 2 * time.Minute
)

// detectionInterval is the poll interval; OW_DETECTION_INTERVAL_SECONDS
// overrides the default and is bounded to 2..300 seconds.
func detectionInterval() time.Duration {
	sec := defaultDetectionSeconds
	if v := strings.TrimSpace(os.Getenv("OW_DETECTION_INTERVAL_SECONDS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			sec = n
		}
	}
	if sec < 2 {
		sec = 2
	}
	if sec > 300 {
		sec = 300
	}
	return time.Duration(sec) * time.Second
}

type iocCache struct {
	mu     sync.Mutex
	at     time.Time
	ip     map[string]store.IOCIndicator
	domain map[string]store.IOCIndicator
	hash   map[string]store.IOCIndicator
}

var detectionIOCCache iocCache

// loadIOCs returns the IP, domain (including URL-derived entries) and hash
// indicator sets, refreshed at most every iocCacheTTL. It also refreshes the
// DNS category cache on the same schedule.
func (e *DetectionEngine) loadIOCs(ctx context.Context) (ip, domain, hash map[string]store.IOCIndicator) {
	c := &detectionIOCCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ip != nil && time.Since(c.at) < iocCacheTTL {
		return c.ip, c.domain, c.hash
	}
	c.ip, _ = e.db.GetAllIOCsOfType(ctx, "ip")
	c.domain, _ = e.db.GetAllIOCsOfType(ctx, "domain")
	c.hash, _ = e.db.GetAllIOCsOfType(ctx, "hash")
	if c.ip == nil {
		c.ip = map[string]store.IOCIndicator{}
	}
	if c.domain == nil {
		c.domain = map[string]store.IOCIndicator{}
	}
	if c.hash == nil {
		c.hash = map[string]store.IOCIndicator{}
	}
	if urlIOCs, err := e.db.GetAllIOCsOfType(ctx, "url"); err == nil && len(urlIOCs) > 0 {
		addURLIOCs(c.domain, urlIOCs)
	}
	domainCats, _ := e.db.GetAllIOCsOfType(ctx, "domain_category")
	for d, ioc := range domainCats {
		if ioc.Tags != "" && ioc.Tags != "clean" {
			dnsCatCache[d] = strings.Split(ioc.Tags, ",")
		}
	}
	c.at = time.Now()
	return c.ip, c.domain, c.hash
}
