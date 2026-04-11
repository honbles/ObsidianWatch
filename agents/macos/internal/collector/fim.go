//go:build darwin

package collector

// fim.go — macOS File Integrity Monitoring via kqueue.
//
// macOS does not expose FSEvents to Go without CGo.
// We use kqueue EVFILT_VNODE to watch files and directories for changes.
// For recursive watching, we walk the directory tree and add watches per entry.
//
// Monitors: create, write, delete, rename, attribute changes.
//
// Events emitted: event_type="file", source="kqueue"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
	"golang.org/x/sys/unix"
)

type FIMCollectorConfig struct {
	Enabled bool
	Dirs    []FIMDirConfig
}

type FIMDirConfig struct {
	Path      string
	Recursive bool
	Exclude   []string
}

type FIMCollector struct {
	cfg     FIMCollectorConfig
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
}

func NewFIMCollector(cfg FIMCollectorConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *FIMCollector {
	return &FIMCollector{cfg: cfg, out: out, agentID: agentID, host: host, logger: logger}
}

func (c *FIMCollector) Run(ctx context.Context) {
	if !c.cfg.Enabled {
		return
	}

	kq, err := unix.Kqueue()
	if err != nil {
		c.logger.Error("fim: kqueue create failed", "err", err)
		return
	}
	defer unix.Close(kq)

	// Map fd → path for event attribution
	fdToPath := make(map[int]string)

	addWatch := func(path string) {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_EVTONLY, 0)
		if err != nil {
			return
		}
		fdToPath[fd] = path
		ev := unix.Kevent_t{
			Ident:  uint64(fd),
			Filter: unix.EVFILT_VNODE,
			Flags:  unix.EV_ADD | unix.EV_CLEAR,
			Fflags: unix.NOTE_WRITE | unix.NOTE_ATTRIB | unix.NOTE_RENAME | unix.NOTE_DELETE | unix.NOTE_EXTEND | unix.NOTE_LINK,
		}
		unix.Kevent(kq, []unix.Kevent_t{ev}, nil, nil)
	}

	for _, dir := range c.cfg.Dirs {
		if dir.Recursive {
			filepath.Walk(dir.Path, func(p string, info os.FileInfo, err error) error {
				if err != nil || c.excluded(p, dir.Exclude) {
					return nil
				}
				addWatch(p)
				return nil
			})
		} else {
			addWatch(dir.Path)
			// Also watch immediate children
			entries, _ := os.ReadDir(dir.Path)
			for _, e := range entries {
				full := filepath.Join(dir.Path, e.Name())
				if !c.excluded(full, dir.Exclude) {
					addWatch(full)
				}
			}
		}
	}

	c.logger.Info("fim: kqueue watching", "watches", len(fdToPath))

	events := make([]unix.Kevent_t, 32)
	timeout := unix.Timespec{Nsec: 200_000_000} // 200ms

	for {
		select {
		case <-ctx.Done():
			for fd := range fdToPath {
				unix.Close(fd)
			}
			return
		default:
		}

		n, err := unix.Kevent(kq, nil, events, &timeout)
		if err != nil {
			continue
		}
		for i := 0; i < n; i++ {
			ev := events[i]
			fd := int(ev.Ident)
			path, ok := fdToPath[fd]
			if !ok {
				continue
			}
			action := fflags2action(ev.Fflags)
			hash := ""
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				hash = hashFile(path)
			}
			detail := map[string]interface{}{
				"path":   path,
				"action": action,
				"hash":   hash,
			}
			raw, _ := json.Marshal(detail)
			c.out <- schema.Event{
				AgentID:   c.agentID,
				Host:      c.host,
				OS:        "darwin",
				EventType: "file",
				Source:    "kqueue",
				Severity:  2,
				Time:      time.Now().UTC(),
				FilePath:  path,
				FileHash:  hash,
				Raw:       raw,
			}
		}
	}
}

func fflags2action(fflags uint32) string {
	switch {
	case fflags&unix.NOTE_DELETE != 0:
		return "delete"
	case fflags&unix.NOTE_RENAME != 0:
		return "rename"
	case fflags&unix.NOTE_WRITE != 0:
		return "modify"
	case fflags&unix.NOTE_ATTRIB != 0:
		return "attrib"
	case fflags&unix.NOTE_EXTEND != 0:
		return "extend"
	case fflags&unix.NOTE_LINK != 0:
		return "link"
	default:
		return "change"
	}
}

func (c *FIMCollector) excluded(path string, patterns []string) bool {
	base := filepath.Base(path)
	for _, pat := range patterns {
		if matched, _ := filepath.Match(pat, base); matched {
			return true
		}
		if strings.HasPrefix(path, pat) {
			return true
		}
	}
	return false
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
