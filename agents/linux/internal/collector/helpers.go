//go:build linux

package collector

import (
	"crypto/rand"
	"encoding/hex"
	"os/user"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// newID generates a random 16-byte hex string for use as an event ID.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b)
}

// resolveUID looks up the username for a numeric UID.
// Returns the UID as a string if the lookup fails.
func resolveUID(uid int) string {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return strconv.Itoa(uid)
	}
	return u.Username
}

// isInterpreter returns true if the process name is a known script interpreter.
// These are flagged at SeverityLow since they commonly run malicious scripts.
func isInterpreter(name string) bool {
	interpreters := []string{
		"python", "python2", "python3",
		"perl", "ruby", "php",
		"bash", "sh", "zsh", "ksh", "dash",
		"node", "nodejs", "deno",
		"lua", "tclsh", "wish",
		"powershell", "pwsh",
	}
	base := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		base = name[idx+1:]
	}
	// Strip version suffix e.g. python3.11 → python3
	for _, interp := range interpreters {
		if base == interp || strings.HasPrefix(base, interp) {
			return true
		}
	}
	return false
}

// inotifyEventAt casts the byte buffer at offset to an inotify event.
// Replaces unix.Pointer which was removed in newer versions of golang.org/x/sys.
func inotifyEventAt(buf []byte, offset int) *unix.InotifyEvent {
	return (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
}


