package api

import (
	"sync"
	"time"
)

// RateLimiter is a simple fixed-window counter keyed by an arbitrary string
// (IP, username, etc). Used to slow down brute-force attempts against
// login, install-key verification, and webhook endpoints.
type RateLimiter struct {
	mu     sync.Mutex
	window time.Duration
	limit  int
	counts map[string]*windowCount
}

type windowCount struct {
	count     int
	windowEnd time.Time
}

func NewRateLimiter(window time.Duration, limit int) *RateLimiter {
	rl := &RateLimiter{
		window: window,
		limit:  limit,
		counts: make(map[string]*windowCount),
	}
	go rl.sweepLoop()
	return rl
}

// Allow returns true if the call for this key is within the limit for the
// current window, incrementing the count as a side effect.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	wc, ok := rl.counts[key]
	if !ok || now.After(wc.windowEnd) {
		rl.counts[key] = &windowCount{count: 1, windowEnd: now.Add(rl.window)}
		return true
	}
	if wc.count >= rl.limit {
		return false
	}
	wc.count++
	return true
}

func (rl *RateLimiter) sweepLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for k, wc := range rl.counts {
			if now.After(wc.windowEnd) {
				delete(rl.counts, k)
			}
		}
		rl.mu.Unlock()
	}
}
