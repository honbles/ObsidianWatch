package collector

// filehash.go - adds a SHA-256 to file events.
//
// Sysmon's file-create event (11) carries no hash, and its stream-hash event (15) uses whatever
// algorithms the Sysmon config lists (often MD5 first), so most file events reached the server with
// no SHA-256 and could never match a SHA-256 indicator. The hasher computes MD5+SHA-256 itself for
// files that were just written, in a small bounded worker pool so it never slows collection.

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"obsidianwatch/agent/pkg/schema"
)

const (
	hashMaxBytes = 100 << 20 // files larger than this are not hashed
	hashWorkers  = 4
)

type FileHasher struct {
	out  chan<- schema.Event
	sem  chan struct{}
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewFileHasher: hashed events are delivered on out.
func NewFileHasher(out chan<- schema.Event) *FileHasher {
	return &FileHasher{out: out, sem: make(chan struct{}, hashWorkers), seen: map[string]time.Time{}}
}

// Handle returns true when the caller should process ev immediately. When it returns false the
// event has been taken over and will arrive on out once hashed.
func (h *FileHasher) Handle(ev schema.Event) bool {
	if ev.EventType != schema.EventTypeFile || ev.FilePath == "" || strings.Contains(strings.ToUpper(ev.FileHash), "SHA256=") {
		return true
	}
	if a := strings.ToLower(rawAction(ev)); a == "deleted" || a == "renamed_from" {
		return true
	}
	h.mu.Lock()
	key := strings.ToLower(ev.FilePath)
	if t, ok := h.seen[key]; ok && time.Since(t) < 20*time.Second {
		h.mu.Unlock()
		return true // hashed (or attempted) moments ago; later events for the same file pass through
	}
	h.seen[key] = time.Now()
	if len(h.seen) > 5000 {
		for k, t := range h.seen {
			if time.Since(t) > time.Minute {
				delete(h.seen, k)
			}
		}
	}
	h.mu.Unlock()
	select {
	case h.sem <- struct{}{}:
	default:
		return true // workers busy: send unhashed rather than block
	}
	go func() {
		defer func() { <-h.sem }()
		time.Sleep(1500 * time.Millisecond) // let the writer finish
		ev := ev
		if md5s, sha, ok := hashFile(ev.FilePath); ok {
			parts := []string{}
			if ev.FileHash != "" && !strings.Contains(strings.ToUpper(ev.FileHash), "SHA256=") {
				parts = append(parts, ev.FileHash)
			} else {
				parts = append(parts, "MD5="+md5s)
			}
			parts = append(parts, "SHA256="+sha)
			ev.FileHash = strings.Join(parts, ",")
		}
		h.out <- ev
	}()
	return false
}

func hashFile(path string) (md5hex, sha256hex string, ok bool) {
	for try := 0; try < 3; try++ {
		f, err := os.Open(path)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		st, err := f.Stat()
		if err != nil || st.IsDir() || st.Size() > hashMaxBytes {
			f.Close()
			return "", "", false
		}
		m, s := md5.New(), sha256.New()
		_, err = io.Copy(io.MultiWriter(m, s), f)
		f.Close()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(s.Sum(nil)), true
	}
	return "", "", false
}

func rawAction(ev schema.Event) string {
	b := string(ev.Raw)
	i := strings.Index(b, `"action":"`)
	if i < 0 {
		return ""
	}
	b = b[i+10:]
	if j := strings.IndexByte(b, '"'); j > 0 {
		return b[:j]
	}
	return ""
}
