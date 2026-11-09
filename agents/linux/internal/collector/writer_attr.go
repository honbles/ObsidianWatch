//go:build linux

package collector

// L-02: writer attribution for file events. fanotify already supplies the PID;
// this resolves the rest of "who wrote it": executable path, parent PID and the
// owning user, read from /proc at event time. A short-lived writer may already
// be gone, in which case the fields stay empty rather than guessed.

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

type writerInfo struct {
	Exe  string
	PPID int
	User string
}

var (
	uidNameMu    sync.Mutex
	uidNameCache = map[int]string{}
)

// parsePasswdName finds the user name for uid in passwd-format text.
func parsePasswdName(passwd string, uid int) string {
	sc := bufio.NewScanner(strings.NewReader(passwd))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 3 {
			continue
		}
		if id, err := strconv.Atoi(f[2]); err == nil && id == uid {
			return f[0]
		}
	}
	return ""
}

func uidToName(uid int) string {
	uidNameMu.Lock()
	if n, ok := uidNameCache[uid]; ok {
		uidNameMu.Unlock()
		return n
	}
	uidNameMu.Unlock()
	name := fmt.Sprintf("uid:%d", uid)
	if b, err := os.ReadFile("/etc/passwd"); err == nil {
		if n := parsePasswdName(string(b), uid); n != "" {
			name = n
		}
	}
	uidNameMu.Lock()
	if len(uidNameCache) > 1024 {
		uidNameCache = map[int]string{}
	}
	uidNameCache[uid] = name
	uidNameMu.Unlock()
	return name
}

// parseProcStatus extracts PPid and the real UID from /proc/<pid>/status text.
func parseProcStatus(status string) (ppid, uid int, ok bool) {
	uid = -1
	for _, line := range strings.Split(status, "\n") {
		switch {
		case strings.HasPrefix(line, "PPid:"):
			ppid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
		case strings.HasPrefix(line, "Uid:"):
			if f := strings.Fields(strings.TrimPrefix(line, "Uid:")); len(f) > 0 {
				uid, _ = strconv.Atoi(f[0])
			}
		}
	}
	return ppid, uid, uid >= 0
}

func lookupWriter(pid int) writerInfo {
	var w writerInfo
	if pid <= 0 {
		return w
	}
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		w.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		if ppid, uid, ok := parseProcStatus(string(b)); ok {
			w.PPID, w.User = ppid, uidToName(uid)
		}
	}
	return w
}
