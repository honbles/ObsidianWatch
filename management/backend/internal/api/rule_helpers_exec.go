package api

// Helpers that decide what a process is EXECUTING, as opposed to what its
// command line merely mentions. "ls /tmp/" and "rm -rf /tmp/build" are not
// executions from /tmp.

import (
	"path/filepath"
	"strings"

	"obsidianwatch/management/internal/store"
)

var scriptInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true,
	"python": true, "python2": true, "python3": true, "perl": true, "ruby": true,
	"node": true, "php": true, "osascript": true,
}

// execPaths returns the paths a process runs: its image, the first token of
// the command line, and, for interpreters, the first non-flag argument.
func execPaths(ev store.Event) []string {
	var out []string
	if i := img(ev); i != "" {
		out = append(out, i)
	}
	f := strings.Fields(cl(ev))
	if len(f) == 0 {
		return out
	}
	out = append(out, f[0])
	base := filepath.Base(f[0])
	base = strings.TrimRight(base, "0123456789.") // python3.11 -> python
	if scriptInterpreters[base] || scriptInterpreters[filepath.Base(f[0])] {
		for _, a := range f[1:] {
			if strings.HasPrefix(a, "-") {
				continue
			}
			out = append(out, a)
			break
		}
	}
	return out
}

// execFromDir reports whether the process runs something located under one of dirs.
func execFromDir(ev store.Event, dirs ...string) bool {
	for _, p := range execPaths(ev) {
		for _, d := range dirs {
			if strings.HasPrefix(p, d) {
				return true
			}
		}
	}
	return false
}

// benignPreloadLibs are libraries commonly injected with LD_PRELOAD for
// allocation, test and debugging purposes.
var benignPreloadLibs = []string{"libjemalloc", "libtcmalloc", "libfaketime", "libeatmydata", "libasan", "libtsan", "libSegFault", "libhugetlbfs"}
