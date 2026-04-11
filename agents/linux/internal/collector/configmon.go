//go:build linux

package collector

// configmon.go — Linux sensitive config file monitoring.
//
// Equivalent to Windows registry monitoring (Run keys, Services, LSA, etc.).
// Watches critical Linux config paths for modification:
//   /etc/passwd, /etc/shadow, /etc/sudoers, /etc/sudoers.d/*
//   /etc/ssh/sshd_config, /etc/cron*, /etc/hosts, /etc/ld.so.preload
//   /etc/systemd/system/*, /root/.ssh/authorized_keys
//
// Uses inotify (reuses the unix package already imported for FIM).
// Emits events as event_type="registry" (mapped to reg_key field) so the
// management platform can display them in the Registry tab per process.
//
// Events emitted: event_type="registry", source="configmon"

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"obsidianwatch/linux-agent/pkg/schema"
)

type ConfigMonCollector struct {
	cfg     ConfigMonConfig
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
}

type ConfigMonConfig struct {
	Enabled bool
	Paths   []string
}

func NewConfigMonCollector(cfg ConfigMonConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *ConfigMonCollector {
	return &ConfigMonCollector{
		cfg:     cfg,
		out:     out,
		agentID: agentID,
		host:    host,
		logger:  logger,
	}
}

func (c *ConfigMonCollector) Run(ctx context.Context) error {
	if !c.cfg.Enabled {
		return nil
	}

	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	wdToPath := make(map[int]string)
	mask := uint32(unix.IN_CREATE | unix.IN_MODIFY | unix.IN_DELETE |
		unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_CLOSE_WRITE |
		unix.IN_ATTRIB) // also catch chmod/chown

	for _, path := range c.cfg.Paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		watchPath := path
		if !info.IsDir() {
			watchPath = filepath.Dir(path)
		}
		wd, err := unix.InotifyAddWatch(fd, watchPath, mask)
		if err != nil {
			c.logger.Debug("configmon: watch failed", "path", watchPath, "err", err)
			continue
		}
		wdToPath[wd] = watchPath
	}

	c.logger.Info("configmon: watching sensitive config paths", "count", len(wdToPath))

	return c.readLoop(ctx, fd, wdToPath)
}

func (c *ConfigMonCollector) readLoop(ctx context.Context, fd int, wdToPath map[int]string) error {
	epfd, _ := unix.EpollCreate1(0)
	defer unix.Close(epfd)
	event := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}
	unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, &event)

	buf := make([]byte, 4096)
	events := make([]unix.EpollEvent, 8)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := unix.EpollWait(epfd, events, 500)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}

		for {
			n, err := unix.Read(fd, buf)
			if err != nil || n == 0 {
				break
			}
			c.parseEvents(buf[:n], wdToPath)
		}
	}
}

func (c *ConfigMonCollector) parseEvents(buf []byte, wdToPath map[int]string) {
	offset := 0
	for offset < len(buf) {
		if offset+unix.SizeofInotifyEvent > len(buf) {
			break
		}
		ev := inotifyEventAt(buf, offset)
		offset += unix.SizeofInotifyEvent

		var name string
		if ev.Len > 0 && offset+int(ev.Len) <= len(buf) {
			nameBytes := buf[offset : offset+int(ev.Len)]
			name = strings.TrimRight(string(nameBytes), "\x00")
			offset += int(ev.Len)
		}

		dir, ok := wdToPath[int(ev.Wd)]
		if !ok {
			continue
		}

		fullPath := filepath.Join(dir, name)
		action := c.maskToAction(ev.Mask)
		if action == "" {
			continue
		}

		// Only emit for paths we were actually asked to watch
		if !c.isWatchedPath(fullPath, dir) {
			continue
		}

		c.emit(fullPath, action)
	}
}

func (c *ConfigMonCollector) isWatchedPath(path, dir string) bool {
	for _, watched := range c.cfg.Paths {
		info, err := os.Stat(watched)
		if err != nil {
			continue
		}
		if info.IsDir() {
			if strings.HasPrefix(path, watched) {
				return true
			}
		} else {
			if path == watched || filepath.Dir(watched) == dir {
				return true
			}
		}
	}
	return false
}

func (c *ConfigMonCollector) maskToAction(mask uint32) string {
	switch {
	case mask&unix.IN_CREATE != 0:
		return "created"
	case mask&unix.IN_CLOSE_WRITE != 0:
		return "modified"
	case mask&unix.IN_DELETE != 0:
		return "deleted"
	case mask&unix.IN_MOVED_FROM != 0:
		return "moved_from"
	case mask&unix.IN_MOVED_TO != 0:
		return "moved_to"
	case mask&unix.IN_ATTRIB != 0:
		return "attributes_changed"
	case mask&unix.IN_MODIFY != 0:
		return "modified"
	default:
		return ""
	}
}

func (c *ConfigMonCollector) emit(path, action string) {
	sev := c.severityFor(path, action)

	// Hash the file content on modification for integrity verification
	hash := ""
	if action == "modified" || action == "created" {
		hash = hashFile(path)
	}

	rawData := map[string]interface{}{
		"path":   path,
		"action": action,
		"hash":   hash,
	}
	rawJSON, _ := json.Marshal(rawData)

	ev := schema.Event{
		Time:      time.Now().UTC(),
		AgentID:   c.agentID,
		Host:      c.host,
		OS:        "linux",
		EventType: schema.EventTypeRegistry, // reuse registry slot for config files
		Severity:  sev,
		Source:    "configmon",
		Raw:       rawJSON,
		RegKey:    path,   // path as "registry key"
		RegValue:  action, // action as "value name"
		RegData:   hash,   // file hash as "data"
		FilePath:  path,
		FileHash:  hash,
	}

	select {
	case c.out <- ev:
	default:
		GlobalHealth.EventsDropped.Add(1)
	}
}

func (c *ConfigMonCollector) severityFor(path, action string) schema.Severity {
	critical := []string{
		"/etc/shadow", "/etc/sudoers", "/etc/ld.so.preload",
		"/root/.ssh", "/etc/ssh/sshd_config",
	}
	for _, p := range critical {
		if strings.HasPrefix(path, p) {
			return schema.SeverityCritical
		}
	}
	high := []string{
		"/etc/passwd", "/etc/hosts", "/etc/cron",
		"/etc/systemd/system",
	}
	for _, p := range high {
		if strings.HasPrefix(path, p) {
			return schema.SeverityHigh
		}
	}
	return schema.SeverityMedium
}
