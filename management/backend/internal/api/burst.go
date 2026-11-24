package api

// burst.go - small in-memory sliding-window counter of DISTINCT values, used
// by rules that must see several events before alerting (ransomware renames,
// Kerberoasting). Counting distinct values keeps it idempotent when the same
// event is evaluated more than once.

import (
	"sync"
	"time"
)

type burstTracker struct {
	mu sync.Mutex
	m  map[string]map[string]time.Time
}

var bursts = &burstTracker{m: map[string]map[string]time.Time{}}

const burstMaxKeys = 20000

// count records val under key at time at (zero = now) and returns how many
// distinct values were seen under key within the last win.
func (b *burstTracker) count(key, val string, at time.Time, win time.Duration) int {
	if at.IsZero() {
		at = time.Now()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.m) > burstMaxKeys {
		b.m = map[string]map[string]time.Time{}
	}
	s := b.m[key]
	if s == nil {
		s = map[string]time.Time{}
		b.m[key] = s
	}
	s[val] = at
	n := 0
	for v, t := range s {
		if at.Sub(t) > win {
			delete(s, v)
		} else {
			n++
		}
	}
	return n
}
