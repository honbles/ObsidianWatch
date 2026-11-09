package api

import "sync"

// syncInflight (G-05/DO-12) tracks which connectors currently have a sync
// running. syncAll fires one goroutine per connector every 5 minutes; a slow
// sync (3 attempts x 3 min plus backoff) used to overlap the next tick, and a
// manual "sync now" could overlap both, so the same connector was pulled by
// several goroutines at once. tryAcquireSync returns false if one is already
// running for key.
var syncInflight sync.Map

func tryAcquireSync(key string) bool {
	_, loaded := syncInflight.LoadOrStore(key, struct{}{})
	return !loaded
}

func releaseSync(key string) { syncInflight.Delete(key) }
