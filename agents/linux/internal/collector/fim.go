//go:build linux

package collector

// fim.go — Linux File Integrity Monitoring.
//
// Primary: fanotify() — provides PID with every file event.
//   Requires CAP_SYS_ADMIN (agent runs as root).
//   Gives: path, action, PID, process name — exactly what we need for graph.
//
// Fallback: inotify() — no PID, but works without elevated privileges.
//   Used when fanotify init fails.
//
// Events emitted: event_type="file", source="fanotify" or "inotify"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"obsidianwatch/linux-agent/pkg/schema"
)

type FIMCollector struct {
	cfg     FIMCollectorConfig
	out     chan<- schema.Event
	agentID string
	host    string
	logger  *slog.Logger
}

type FIMCollectorConfig struct {
	Enabled bool
	Dirs    []FIMDirConfig
}

type FIMDirConfig struct {
	Path      string
	Recursive bool
	Exclude   []string
}

func NewFIMCollector(cfg FIMCollectorConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *FIMCollector {
	return &FIMCollector{
		cfg:     cfg,
		out:     out,
		agentID: agentID,
		host:    host,
		logger:  logger,
	}
}

func (f *FIMCollector) Run(ctx context.Context) error {
	if !f.cfg.Enabled {
		return nil
	}

	// Try fanotify first (gives PID)
	if err := f.runFanotify(ctx); err != nil {
		f.logger.Warn("fim: fanotify unavailable, falling back to inotify (no PID)", "err", err)
		return f.runInotify(ctx)
	}
	return nil
}

// ── fanotify implementation ──────────────────────────────────────────────────

// fanotify syscall numbers and constants
// fanotify constants — use unix package values where available
// These match linux/fanotify.h
const (
	fanClassNotifContent = 0x00000004
	fanUnlimitedQueue    = 0x00000010
	fanUnlimitedMarks    = 0x00000020
	fanMarkAdd           = 0x00000001
	fanMarkMount         = 0x00000010

	fanModify     = 0x00000002
	fanCloseWrite = 0x00000008
	fanCreate     = 0x00000100
	fanDelete     = 0x00000200
	fanMovedFrom  = 0x00000040
	fanMovedTo    = 0x00000080
	fanDeleteSelf = 0x00000400
	fanOpenExec   = 0x00001000
)

// fanotify_event_metadata layout
type fanotifyEventMetadata struct {
	EventLen    uint32
	Vers        uint8
	Reserved    uint8
	MetadataLen uint16
	Mask        uint64
	Fd          int32
	Pid         int32
}

func (f *FIMCollector) runFanotify(ctx context.Context) error {
	// FAN_CLASS_NOTIF | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS
	// Use unix.SYS_FANOTIFY_INIT for arch portability (x86_64=300, arm64=262)
	fd, _, errno := unix.Syscall(unix.SYS_FANOTIFY_INIT,
		fanClassNotifContent|fanUnlimitedQueue|fanUnlimitedMarks,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC,
		0)
	if errno != 0 {
		return fmt.Errorf("fanotify_init: %v", errno)
	}
	defer unix.Close(int(fd))

	watchMask := uint64(fanModify | fanCloseWrite | fanCreate | fanDelete |
		fanMovedFrom | fanMovedTo | fanDeleteSelf | fanOpenExec)

	successfulMarks := 0
	for _, dir := range f.cfg.Dirs {
		// Resolve symlinks — Ubuntu 22+ has /bin → /usr/bin etc.
		// fanotify cannot mark symlinks, only real directories
		realPath, err := filepath.EvalSymlinks(dir.Path)
		if err != nil {
			realPath = dir.Path // use original if resolution fails
		}
		// Mark the mount point containing this path for comprehensive coverage
		pathPtr, pErr := unix.BytePtrFromString(realPath)
		if pErr != nil {
			continue
		}
		// AT_FDCWD is an untyped int constant (-100). Assigning to a typed int
		// variable first forces the compiler to treat it as a runtime value,
		// avoiding the "overflows uintptr" compile error on 64-bit targets.
		atFdCwdInt := int(unix.AT_FDCWD)
		atFdCwd := uintptr(atFdCwdInt)

		_, _, errno = unix.Syscall6(unix.SYS_FANOTIFY_MARK,
			fd,
			fanMarkAdd|fanMarkMount,
			uintptr(watchMask),
			atFdCwd,
			uintptr(unsafe.Pointer(pathPtr)),
			0)
		if errno != 0 {
			// Fall back to marking just the directory (no mount-level)
			pathPtr2, _ := unix.BytePtrFromString(realPath)
			_, _, errno = unix.Syscall6(unix.SYS_FANOTIFY_MARK,
				fd,
				fanMarkAdd,
				uintptr(watchMask),
				atFdCwd,
				uintptr(unsafe.Pointer(pathPtr2)),
				0)
			if errno != 0 {
				f.logger.Warn("fim: fanotify mark failed", "path", dir.Path, "err", errno)
			} else {
				successfulMarks++
			}
		} else {
			successfulMarks++
		}
	}

	// If no paths could be marked (e.g. overlayfs), fall back to inotify
	if successfulMarks == 0 {
		f.logger.Warn("fim: fanotify marks all failed, falling back to inotify")
		unix.Close(int(fd))
		return f.runInotify(ctx)
	}

	f.logger.Info("fim: fanotify active (PID attribution enabled)", "dirs", successfulMarks)

	buf := make([]byte, 4096*8)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Set read timeout via poll
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 500)
		if err != nil || n == 0 {
			continue
		}

		n2, err := unix.Read(int(fd), buf)
		if err != nil || n2 <= 0 {
			continue
		}

		f.parseFanotifyEvents(buf[:n2])
	}
}

func (f *FIMCollector) parseFanotifyEvents(buf []byte) {
	offset := 0
	metaSize := int(unsafe.Sizeof(fanotifyEventMetadata{}))

	for offset+metaSize <= len(buf) {
		meta := (*fanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
		if meta.EventLen < uint32(metaSize) {
			break
		}

		offset += int(meta.EventLen)

		if meta.Fd < 0 {
			continue
		}

		// Read path from /proc/self/fd/<fd>
		path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", meta.Fd))
		unix.Close(int(meta.Fd))
		if err != nil {
			continue
		}

		if f.isExcluded(path) {
			continue
		}

		pid := int(meta.Pid)
		procName := readProcName(pid)
		action := f.fanotifyMaskToAction(meta.Mask)
		if action == "" {
			continue
		}

		f.emit(path, action, pid, procName)
	}
}

func (f *FIMCollector) fanotifyMaskToAction(mask uint64) string {
	switch {
	case mask&fanCreate != 0:
		return "create"
	case mask&fanDelete != 0, mask&fanDeleteSelf != 0:
		return "delete"
	case mask&fanCloseWrite != 0, mask&fanModify != 0:
		return "modify"
	case mask&fanMovedFrom != 0:
		return "rename_from"
	case mask&fanMovedTo != 0:
		return "rename_to"
	case mask&fanOpenExec != 0:
		return "exec"
	default:
		return ""
	}
}

// ── inotify fallback ─────────────────────────────────────────────────────────

func (f *FIMCollector) runInotify(ctx context.Context) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	wdToPath := make(map[int]string)
	mask := uint32(unix.IN_CREATE | unix.IN_MODIFY | unix.IN_DELETE |
		unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_CLOSE_WRITE)

	for _, dirCfg := range f.cfg.Dirs {
		if err := f.addInotifyWatch(fd, dirCfg.Path, dirCfg.Recursive, mask, wdToPath); err != nil {
			f.logger.Warn("fim: inotify add watch failed", "path", dirCfg.Path, "err", err)
		}
	}
	f.logger.Info("fim: inotify fallback active (no PID)", "watches", len(wdToPath))

	epfd, err := unix.EpollCreate1(0)
	if err != nil {
		return err
	}
	defer unix.Close(epfd)

	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}
	unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, &ev)

	buf := make([]byte, 4096)
	events := make([]unix.EpollEvent, 8)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := unix.EpollWait(epfd, events, 500)
		if err != nil || n == 0 {
			continue
		}

		for {
			n2, err := unix.Read(fd, buf)
			if err != nil || n2 == 0 {
				break
			}
			f.parseInotifyEvents(buf[:n2], wdToPath)
		}
	}
}

func (f *FIMCollector) addInotifyWatch(fd int, path string, recursive bool, mask uint32, wdToPath map[int]string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		path = filepath.Dir(path)
	}
	wd, err := unix.InotifyAddWatch(fd, path, mask)
	if err != nil {
		return err
	}
	wdToPath[wd] = path

	if recursive && info.IsDir() {
		return filepath.Walk(path, func(sub string, si os.FileInfo, err error) error {
			if err != nil || !si.IsDir() || sub == path {
				return nil
			}
			wd2, err2 := unix.InotifyAddWatch(fd, sub, mask)
			if err2 != nil {
				return nil
			}
			wdToPath[wd2] = sub
			return nil
		})
	}
	return nil
}

func (f *FIMCollector) parseInotifyEvents(buf []byte, wdToPath map[int]string) {
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
		if f.isExcluded(fullPath) {
			continue
		}
		action := f.inotifyMaskToAction(ev.Mask)
		if action == "" {
			continue
		}
		// No PID in inotify — emit with 0
		f.emit(fullPath, action, 0, "")
	}
}

func (f *FIMCollector) inotifyMaskToAction(mask uint32) string {
	switch {
	case mask&unix.IN_CREATE != 0:
		return "create"
	case mask&unix.IN_CLOSE_WRITE != 0, mask&unix.IN_MODIFY != 0:
		return "modify"
	case mask&unix.IN_DELETE != 0:
		return "delete"
	case mask&unix.IN_MOVED_FROM != 0:
		return "rename_from"
	case mask&unix.IN_MOVED_TO != 0:
		return "rename_to"
	default:
		return ""
	}
}

// ── shared emit ──────────────────────────────────────────────────────────────

func (f *FIMCollector) emit(path, action string, pid int, procName string) {
	sev := f.severityForPath(path, action)

	hash := ""
	if action != "delete" && action != "rename_from" {
		hash = hashFile(path)
	}

	source := "fanotify"
	if pid == 0 {
		source = "inotify"
	}

	rawData := map[string]interface{}{
		"action":       action,
		"path":         path,
		"pid":          pid,
		"process_name": procName,
		"file_hash":    hash,
		"source":       source,
	}
	rawJSON, _ := json.Marshal(rawData)

	ev := schema.Event{
		Time:        time.Now().UTC(),
		AgentID:     f.agentID,
		Host:        f.host,
		OS:          "linux",
		EventType:   schema.EventTypeFile,
		Severity:    sev,
		Source:      source,
		Raw:         rawJSON,
		PID:         pid,
		ProcessName: procName,
		FilePath:    path,
		FileHash:    hash,
	}

	select {
	case f.out <- ev:
	default:
		GlobalHealth.EventsDropped.Add(1)
	}
}

func (f *FIMCollector) isExcluded(path string) bool {
	base := filepath.Base(path)
	for _, dirCfg := range f.cfg.Dirs {
		for _, pattern := range dirCfg.Exclude {
			if matched, _ := filepath.Match(pattern, base); matched {
				return true
			}
		}
	}
	return false
}

func (f *FIMCollector) severityForPath(path, action string) schema.Severity {
	critical := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/etc/ssh/sshd_config", "/etc/ld.so.preload",
		"/root/.ssh",
	}
	for _, c := range critical {
		if strings.HasPrefix(path, c) {
			return schema.SeverityHigh
		}
	}
	if action == "create" || action == "modify" {
		for _, d := range []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/"} {
			if strings.HasPrefix(path, d) {
				return schema.SeverityMedium
			}
		}
	}
	if strings.HasPrefix(path, "/tmp/") && action == "create" {
		return schema.SeverityMedium
	}
	return schema.SeverityInfo
}

// ── file hash ─────────────────────────────────────────────────────────────────

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 10*1024*1024)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
