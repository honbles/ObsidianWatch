package collector

// ratelimit.go — identical to Windows agent ratelimit.go, cross-platform pure Go.

import (
	"sync"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
)

type RateLimitConfig struct {
	MaxPerSecond int
	DedupeWindow time.Duration
}

var DefaultRateLimitConfig = RateLimitConfig{
	MaxPerSecond: 500,
	DedupeWindow: 5 * time.Second,
}

type sourceState struct {
	windowStart time.Time
	windowCount int
	recentIDs   map[string]time.Time
}

type RateLimiter struct {
	cfg    RateLimitConfig
	mu     sync.Mutex
	states map[string]*sourceState
}

func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	return &RateLimiter{cfg: cfg, states: make(map[string]*sourceState)}
}

func (r *RateLimiter) Allow(ev *schema.Event) bool {
	if r.cfg.MaxPerSecond == 0 && r.cfg.DedupeWindow == 0 {
		return true
	}
	key := string(ev.EventType) + ":" + ev.Source
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.states[key]
	if !ok {
		s = &sourceState{windowStart: now, recentIDs: make(map[string]time.Time)}
		r.states[key] = s
	}

	if r.cfg.DedupeWindow > 0 && ev.ID != "" {
		if expiry, seen := s.recentIDs[ev.ID]; seen && now.Before(expiry) {
			GlobalHealth.EventsDropped.Add(1)
			return false
		}
		if len(s.recentIDs) > 1000 {
			for id, expiry := range s.recentIDs {
				if now.After(expiry) {
					delete(s.recentIDs, id)
				}
			}
		}
		s.recentIDs[ev.ID] = now.Add(r.cfg.DedupeWindow)
	}

	if r.cfg.MaxPerSecond > 0 {
		if now.Sub(s.windowStart) > time.Second {
			s.windowStart = now
			s.windowCount = 0
		}
		if s.windowCount >= r.cfg.MaxPerSecond {
			GlobalHealth.EventsDropped.Add(1)
			return false
		}
		s.windowCount++
	}

	GlobalHealth.EventsCollected.Add(1)
	return true
}

func FilteredChannel(in <-chan schema.Event, out chan<- schema.Event, limiter *RateLimiter) {
	for ev := range in {
		if limiter.Allow(&ev) {
			select {
			case out <- ev:
			default:
				GlobalHealth.EventsDropped.Add(1)
			}
		}
	}
}
