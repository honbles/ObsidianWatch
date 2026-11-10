// Package ownproc recognises processes the ObsidianWatch agent itself spawned
// (vulnerability scans, installers, ACL changes, service checks) so their
// telemetry is not turned into alerts. A process counts as "own" when its
// parent is the agent, or another own process, and it is not the live-response
// shell (analyst-driven commands must stay visible and alertable).
package ownproc

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const ttl = 10 * time.Minute

var (
	mu       sync.Mutex
	self     = os.Getpid()
	own      = map[int]time.Time{} // pid -> expiry
	excluded = map[int]time.Time{} // live-response shells (pid -> expiry)
)

// Exclude marks a pid (and so its subtree) as NOT agent activity. Call it for
// the live-response shell right after Start.
func Exclude(pid int) {
	if pid <= 0 {
		return
	}
	mu.Lock()
	excluded[pid] = time.Now().Add(24 * time.Hour)
	mu.Unlock()
}

func live(m map[int]time.Time, pid int, now time.Time) bool {
	exp, ok := m[pid]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(m, pid)
		return false
	}
	return true
}

// IsOwn reports whether an event for (pid, ppid) is agent self-activity, and
// remembers the pid so later events from the same process and its children
// are recognised too.
func IsOwn(pid, ppid int) bool {
	if pid <= 0 {
		return false
	}
	now := time.Now()
	mu.Lock()
	defer mu.Unlock()
	if len(own) > 4096 { // bound memory
		for k, exp := range own {
			if now.After(exp) {
				delete(own, k)
			}
		}
	}
	if live(excluded, pid, now) || (ppid > 0 && live(excluded, ppid, now)) {
		return false
	}
	if pid == self {
		return true
	}
	if live(own, pid, now) {
		return true
	}
	if ppid > 0 && (ppid == self || live(own, ppid, now)) {
		own[pid] = now.Add(ttl)
		return true
	}
	return false
}

// TagRaw returns raw with "self_activity":true added (raw may be empty or not
// a JSON object, in which case it is wrapped under "original").
func TagRaw(raw json.RawMessage) json.RawMessage {
	m := map[string]json.RawMessage{}
	if len(raw) > 0 && json.Unmarshal(raw, &m) != nil {
		m = map[string]json.RawMessage{"original": raw}
	}
	m["self_activity"] = json.RawMessage("true")
	b, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return b
}
