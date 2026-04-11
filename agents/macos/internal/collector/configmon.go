//go:build darwin

package collector

// configmon.go — macOS sensitive config file monitoring.
//
// Watches macOS-specific sensitive paths using kqueue EVFILT_VNODE.
// Equivalent to Windows registry monitoring / Linux configmon.
//
// Monitored by default:
//   /etc/passwd, /etc/sudoers, /etc/ssh/sshd_config, /etc/hosts,
//   /Library/LaunchDaemons, /Library/LaunchAgents (persistence locations),
//   /System/Library/LaunchDaemons, /root/.ssh
//
// Events emitted: event_type="config_change", source="kqueue-configmon"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
	"golang.org/x/sys/unix"
)

type ConfigMonConfig struct {
	Enabled bool
	Paths   []string
}

type ConfigMonCollector struct {
	cfg     ConfigMonConfig
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
}

func NewConfigMonCollector(cfg ConfigMonConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *ConfigMonCollector {
	return &ConfigMonCollector{cfg: cfg, out: out, agentID: agentID, host: host, logger: logger}
}

func (c *ConfigMonCollector) Run(ctx context.Context) {
	if !c.cfg.Enabled {
		return
	}

	kq, err := unix.Kqueue()
	if err != nil {
		c.logger.Error("configmon: kqueue create failed", "err", err)
		return
	}
	defer unix.Close(kq)

	fdToPath := make(map[int]string)
	hashCache := make(map[string]string)

	addWatch := func(path string) {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_EVTONLY, 0)
		if err != nil {
			return
		}
		fdToPath[fd] = path
		hashCache[path] = fileHash(path)
		ev := unix.Kevent_t{
			Ident:  uint64(fd),
			Filter: unix.EVFILT_VNODE,
			Flags:  unix.EV_ADD | unix.EV_CLEAR,
			Fflags: unix.NOTE_WRITE | unix.NOTE_ATTRIB | unix.NOTE_RENAME | unix.NOTE_DELETE | unix.NOTE_LINK,
		}
		unix.Kevent(kq, []unix.Kevent_t{ev}, nil, nil)
	}

	// Watch each configured path; for directories also watch children
	for _, p := range c.cfg.Paths {
		addWatch(p)
		info, err := os.Stat(p)
		if err == nil && info.IsDir() {
			entries, _ := os.ReadDir(p)
			for _, e := range entries {
				addWatch(filepath.Join(p, e.Name()))
			}
		}
	}

	c.logger.Info("configmon: watching paths", "count", len(fdToPath))

	events := make([]unix.Kevent_t, 16)
	timeout := unix.Timespec{Nsec: 200_000_000}

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
			newHash := fileHash(path)
			oldHash := hashCache[path]
			hashCache[path] = newHash

			detail := map[string]interface{}{
				"path":     path,
				"action":   action,
				"old_hash": oldHash,
				"new_hash": newHash,
			}
			raw, _ := json.Marshal(detail)
			c.out <- schema.Event{
				AgentID:   c.agentID,
				Host:      c.host,
				EventType: "config_change",
				Source:    "kqueue-configmon",
				Severity:  3,
				Raw:       raw,
				Time:      time.Now().UTC(),
			}
		}
	}
}

func fileHash(path string) string {
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
