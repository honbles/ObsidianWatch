package collector

// L-01 (macOS): image path and SHA-256 of a started process. The executable
// path is the first string of the kern.procargs2 buffer. Hashes are cached by
// path+size+mtime so each binary is read once; files over execHashMaxSize are
// skipped.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
)

const (
	execHashMaxSize  = 16 << 20
	execHashMaxCache = 4096
)

var (
	execHashMu    sync.Mutex
	execHashCache = map[string]string{}
)

// execPathFromProcArgs extracts the executable path from a KERN_PROCARGS2
// buffer (4-byte argc followed by the NUL-terminated exec path).
func execPathFromProcArgs(buf []byte) string {
	if len(buf) <= 4 {
		return ""
	}
	end := 4
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	return string(buf[4:end])
}

func hashFileCached(path string) string {
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > execHashMaxSize {
		return ""
	}
	key := fmt.Sprintf("%s|%d|%d", path, st.Size(), st.ModTime().UnixNano())
	execHashMu.Lock()
	if h, ok := execHashCache[key]; ok {
		execHashMu.Unlock()
		return h
	}
	execHashMu.Unlock()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	execHashMu.Lock()
	if len(execHashCache) >= execHashMaxCache {
		execHashCache = map[string]string{}
	}
	execHashCache[key] = sum
	execHashMu.Unlock()
	return sum
}
