package api

import (
	"encoding/json"
	"sync"
	"time"
	"unicode/utf8"

	"obsidianwatch/backend/pkg/schema"
)

// I-03: field length caps and a per-agent throttle so one misbehaving or
// hostile agent cannot bloat the events table or starve other agents.

const (
	maxIngestBodyBytes = 16 << 20 // 16 MiB per request
	maxRawBytes        = 64 << 10 // events.raw
	maxCmdLineRunes    = 8192
	maxPathRunes       = 2048
	maxShortRunes      = 512
	// Per-agent sustained rate; burst allows a queue flush after an outage.
	agentEventsPerSec = 500.0
	agentBurstEvents  = 20000.0
)

func capStr(s string, n int) string {
	if len(s) <= n { // bytes >= runes, so this is a cheap fast-path
		return s
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// sanitizeEvent truncates oversized fields in place and returns true if
// anything was changed.
func sanitizeEvent(e *schema.Event) bool {
	changed := false
	cap := func(p *string, n int) {
		if v := capStr(*p, n); v != *p {
			*p = v
			changed = true
		}
	}
	cap(&e.CommandLine, maxCmdLineRunes)
	cap(&e.ImagePath, maxPathRunes)
	cap(&e.FilePath, maxPathRunes)
	cap(&e.RegKey, maxPathRunes)
	cap(&e.RegValue, maxPathRunes)
	cap(&e.RegData, maxPathRunes)
	cap(&e.ProcessName, maxShortRunes)
	cap(&e.UserName, maxShortRunes)
	cap(&e.Domain, maxShortRunes)
	cap(&e.Host, maxShortRunes)
	cap(&e.OS, 64)
	cap(&e.Source, maxShortRunes)
	cap(&e.Channel, maxShortRunes)
	cap(&e.SrcIP, 64)
	cap(&e.DstIP, 64)
	cap(&e.Proto, 32)
	cap(&e.FileHash, 128)
	cap(&e.LogonID, 64)
	cap(&e.ID, 128)
	if len(e.Raw) > maxRawBytes {
		stub, _ := json.Marshal(map[string]any{"truncated": true, "original_bytes": len(e.Raw)})
		e.Raw = stub
		changed = true
	}
	return changed
}

type agentBucket struct {
	tokens float64
	last   time.Time
}

type agentThrottle struct {
	mu sync.Mutex
	m  map[string]*agentBucket
}

var ingestThrottle = &agentThrottle{m: map[string]*agentBucket{}}

// allow consumes n tokens for the agent; returns false if over budget.
func (t *agentThrottle) allow(agent string, n int) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.m[agent]
	if b == nil {
		if len(t.m) > 50000 { // bound memory against agent-id spraying
			t.m = map[string]*agentBucket{}
		}
		b = &agentBucket{tokens: agentBurstEvents, last: now}
		t.m[agent] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * agentEventsPerSec
	if b.tokens > agentBurstEvents {
		b.tokens = agentBurstEvents
	}
	b.last = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}
