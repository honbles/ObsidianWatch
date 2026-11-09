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
	"strings"
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

	watched := make(map[string]bool)       // path -> already watched
	dirChildren := make(map[string]map[string]bool) // dir -> known child names

	addWatch := func(path string) {
		if watched[path] {
			return
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_EVTONLY, 0)
		if err != nil {
			return
		}
		watched[path] = true
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

	// scan (re)registers watches. A-08: it also expands per-user LaunchAgents
	// (/Users/*/Library/LaunchAgents) and re-runs periodically so newly
	// created users/paths/children are picked up without an agent restart.
	scan := func() {
		paths := append([]string{}, c.cfg.Paths...)
		if homes, err := filepath.Glob("/Users/*/Library/LaunchAgents"); err == nil {
			paths = append(paths, homes...)
		}
		if homes, err := filepath.Glob("/Users/*/.ssh"); err == nil {
			paths = append(paths, homes...)
		}
		for _, p := range paths {
			addWatch(p)
			info, err := os.Stat(p)
			if err == nil && info.IsDir() {
				entries, _ := os.ReadDir(p)
				known := dirChildren[p]
				if known == nil {
					known = make(map[string]bool)
					dirChildren[p] = known
				}
				for _, e := range entries {
					known[e.Name()] = true
					addWatch(filepath.Join(p, e.Name()))
				}
			}
		}
	}
	scan()
	lastScan := time.Now()

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

		if time.Since(lastScan) > time.Minute {
			scan()
			lastScan = time.Now()
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

			sev := 3
			persistence := isMacPersistencePath(path)
			if persistence {
				sev = 4
			}
			emit := func(p, act, oh, nh string, extra map[string]interface{}) {
				detail := map[string]interface{}{
					"path": p, "action": act, "old_hash": oh, "new_hash": nh,
					"persistence": persistence,
				}
				for k, v := range extra {
					detail[k] = v
				}
				raw, _ := json.Marshal(detail)
				c.out <- schema.Event{
					AgentID:   c.agentID,
					Host:      c.host,
					EventType: "config_change",
					Source:    "kqueue-configmon",
					Severity:  schema.Severity(sev),
					Raw:       raw,
					Time:      time.Now().UTC(),
					FilePath:  p,
				}
			}

			// Directory write: report each NEW child (a dropped LaunchAgent/Daemon
			// plist, cron tab, etc.) individually and start watching it.
			if known := dirChildren[path]; known != nil {
				if entries, derr := os.ReadDir(path); derr == nil {
					for _, e := range entries {
						if known[e.Name()] {
							continue
						}
						known[e.Name()] = true
						child := filepath.Join(path, e.Name())
						addWatch(child)
						emit(child, "created", "", fileHash(child), map[string]interface{}{"parent": path})
					}
				}
				continue
			}
			emit(path, action, oldHash, newHash, nil)
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

// isMacPersistencePath reports whether path is an autostart/persistence location
// (launchd, cron, login items, shell profiles, emond, periodic, login hooks, BTM).
func isMacPersistencePath(p string) bool {
	for _, frag := range []string{
		"/LaunchAgents", "/LaunchDaemons", "/StartupItems", "/etc/periodic", "/usr/lib/cron", "/var/at/tabs",
		"/etc/emond.d", "com.apple.loginwindow.plist", "/etc/zshrc", "/etc/zprofile", "/etc/profile",
		"/etc/rc.common", "/etc/rc.local", "backgroundtaskmanagement", "com.apple.loginitems", "/Library/Scripts",
		"/etc/authorization", "/Library/ScriptingAdditions",
	} {
		if strings.Contains(p, frag) {
			return true
		}
	}
	return false
}
