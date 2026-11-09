//go:build linux

package collector

// L-01: exec-time SHA-256 of the running binary. Opens /proc/<pid>/exe (so
// binaries deleted after launch are still hashed) and caches by
// path+size+mtime so each distinct binary is hashed once. Files above
// exeHashMaxSize are skipped to keep the poll loop fast.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
)

const (
	exeHashMaxSize  = 16 << 20
	exeHashMaxCache = 4096
)

var (
	exeHashMu    sync.Mutex
	exeHashCache = map[string]string{}
)

// exeSHA256 returns the hex SHA-256 of the process image, or "" when it cannot
// be read or is too large.
func exeSHA256(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > exeHashMaxSize {
		return ""
	}
	key := fmt.Sprintf("%d|%d|%d", inodeOf(st), st.Size(), st.ModTime().UnixNano())
	exeHashMu.Lock()
	if h, ok := exeHashCache[key]; ok {
		exeHashMu.Unlock()
		return h
	}
	exeHashMu.Unlock()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	exeHashMu.Lock()
	if len(exeHashCache) >= exeHashMaxCache {
		exeHashCache = map[string]string{}
	}
	exeHashCache[key] = sum
	exeHashMu.Unlock()
	return sum
}

func inodeOf(st os.FileInfo) uint64 {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return s.Ino
	}
	return 0
}
