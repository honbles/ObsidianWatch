//go:build darwin

package collector

import (
	"fmt"
	"strconv"
	"sync"
)

// Latest pid -> start-time snapshot shared by collectors, so network, DNS and
// FIM events can carry the same process_guid the process collector emits
// ("<pid>-<start>"). Used by the Alert Graph to join events to a process
// instance.
var (
	procStartMu sync.RWMutex
	procStartBy map[int32]uint64
)

func setProcStarts(m map[int32]uint64) {
	procStartMu.Lock()
	procStartBy = m
	procStartMu.Unlock()
}

// macProcGUID returns the process_guid for a live pid, or "" if unknown.
func macProcGUID(pid int32) string {
	if pid <= 0 {
		return ""
	}
	procStartMu.RLock()
	s := procStartBy[pid]
	procStartMu.RUnlock()
	if s == 0 {
		return ""
	}
	return fmt.Sprintf("%d-%d", pid, s)
}

// macProcGUIDStr is macProcGUID for collectors that hold the pid as text.
func macProcGUIDStr(pid string) string {
	n, err := strconv.Atoi(pid)
	if err != nil {
		return ""
	}
	return macProcGUID(int32(n))
}
