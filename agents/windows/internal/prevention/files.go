package prevention

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/agent/internal/response"
)

const (
	fileScanEvery   = 10 * time.Second
	fileMaxBytes    = 200 << 20 // larger files are not hashed (reported as unchecked in health)
	fileScanDepth   = 4
	fileScanBudget  = 20000 // entries per pass
	fileStableAfter = 3 * time.Second
)

func osGetpid() int { return os.Getpid() }

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// defaultWatchDirs are where new files arrive: downloads, desktops, temp
// directories and removable media.
func defaultWatchDirs() []string {
	var dirs []string
	add := func(globs ...string) {
		for _, g := range globs {
			m, _ := filepath.Glob(g)
			dirs = append(dirs, m...)
		}
	}
	switch runtime.GOOS {
	case "windows":
		root := os.Getenv("SystemDrive")
		if root == "" {
			root = "C:"
		}
		add(root+`\Users\*\Downloads`, root+`\Users\*\Desktop`, root+`\Users\*\AppData\Local\Temp`, os.Getenv("SystemRoot")+`\Temp`)
	case "darwin":
		add("/Users/*/Downloads", "/Users/*/Desktop", "/tmp", "/private/var/tmp", "/Volumes/*")
	default:
		add("/home/*/Downloads", "/home/*/Desktop", "/root/Downloads", "/tmp", "/var/tmp", "/dev/shm", "/media/*/*", "/run/media/*/*")
	}
	return dirs
}

type fileSeen struct {
	size  int64
	mtime time.Time
	first time.Time // when this size/mtime was first seen (stability check)
	done  bool
}

// watchFiles checks new and changed files in the watched folders against
// the hash set. A file is hashed once it has stopped changing.
func (e *Engine) watchFiles(ctx context.Context) {
	seen := map[string]*fileSeen{}
	baseline := true // the first pass records what exists
	t := time.NewTicker(fileScanEvery)
	defer t.Stop()
	for {
		if e.Mode("hash") != Off {
			e.mu.RLock()
			extra := append([]string(nil), e.watchDirs...)
			n := len(e.hashes)
			e.mu.RUnlock()
			if n > 0 || e.hasTests() {
				e.scanOnce(ctx, append(defaultWatchDirs(), extra...), seen, baseline)
				baseline = false
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (e *Engine) scanOnce(ctx context.Context, roots []string, seen map[string]*fileSeen, baseline bool) {
	now := time.Now()
	budget := fileScanBudget
	alive := map[string]bool{}
	for _, root := range roots {
		root = filepath.Clean(root)
		depth0 := strings.Count(root, string(filepath.Separator))
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if budget--; budget <= 0 {
				return fs.SkipAll
			}
			if d.IsDir() {
				if strings.Count(path, string(filepath.Separator))-depth0 >= fileScanDepth {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() == 0 || info.Size() > fileMaxBytes {
				return nil
			}
			alive[path] = true
			s := seen[path]
			if s == nil || s.size != info.Size() || !s.mtime.Equal(info.ModTime()) {
				seen[path] = &fileSeen{size: info.Size(), mtime: info.ModTime(), first: now, done: baseline}
				return nil
			}
			if s.done || now.Sub(s.first) < fileStableAfter {
				return nil
			}
			s.done = true
			e.checkFile(path)
			return nil
		})
	}
	for p := range seen {
		if !alive[p] {
			delete(seen, p)
		}
	}
}

func hashPath(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, fileMaxBytes+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (e *Engine) checkFile(path string) {
	sum, err := hashPath(path)
	if err != nil {
		return
	}
	e.count(cFiles)
	if _, ok := e.lookupHash(sum); !ok {
		return
	}
	e.fileMatch(path, sum, "new_file")
}

// cachedHash hashes a file once per path, size and modification time.
func (e *Engine) cachedHash(path string) string {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > fileMaxBytes {
		return ""
	}
	key := path + "|" + st.ModTime().String() + "|" + strconv.FormatInt(st.Size(), 10)
	if v, ok := e.hashCache.Load(key); ok {
		return v.(string)
	}
	sum, err := hashPath(path)
	if err != nil {
		return ""
	}
	e.hashCache.Store(key, sum)
	if e.hashCacheN.Add(1) > 20000 { // keep the cache bounded
		e.hashCache.Range(func(k, _ any) bool { e.hashCache.Delete(k); return true })
		e.hashCacheN.Store(0)
	}
	return sum
}

// fileMatch reports a listed file and quarantines it in enforce mode.
func (e *Engine) fileMatch(path, sum, trigger string) {
	x, ok := e.lookupHash(sum)
	if !ok || e.seen("file|"+sum+"|"+path) {
		return
	}
	mode := e.Mode("hash")
	r := e.report("hash", sum, x, mode)
	r.Fields["path"] = path
	r.Fields["trigger"] = trigger
	if mode != Enforce {
		e.emit(r, "audit", "")
		return
	}
	e.do(func() {
		if e.resp == nil {
			e.emit(r, "failed", "response actions are not available in this build")
			return
		}
		res := e.resp.Handle(context.Background(), "quarantine_file", response.Params{Path: path})
		if res.OK {
			e.emit(r, "quarantined", res.Message)
		} else {
			e.emit(r, "failed", res.Message)
		}
	})
}
