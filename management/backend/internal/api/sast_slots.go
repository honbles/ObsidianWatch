package api

import (
	"context"
	"os"
	"strconv"
	"sync"
)

// A repository scan clones up to OW_SAST_MAX_REPO_MB and runs several engines (CodeQL alone takes gigabytes of
// memory), and manual scans, "scan all", pushes, schedules and pull requests could all run at once. Every scan of a
// repository now takes a slot first; at most OW_SAST_MAX_CONCURRENT (default 2) run at a time and the rest wait in
// order of arrival.

var (
	scanSlotsOnce sync.Once
	scanSlots     chan struct{}
)

func sastMaxConcurrent() int {
	if n, err := strconv.Atoi(os.Getenv("OW_SAST_MAX_CONCURRENT")); err == nil && n > 0 && n <= 16 {
		return n
	}
	return 2
}

// acquireScanSlot waits for a scan slot. It returns the release function, or the context's error if the wait was
// cancelled.
func acquireScanSlot(ctx context.Context) (func(), error) {
	scanSlotsOnce.Do(func() { scanSlots = make(chan struct{}, sastMaxConcurrent()) })
	select {
	case scanSlots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-scanSlots }) }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}
