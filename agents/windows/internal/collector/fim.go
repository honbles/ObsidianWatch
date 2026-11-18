//go:build windows

package collector

// fim.go - File Integrity Monitoring using ReadDirectoryChangesW.
// Watches configured directories recursively for file create, modify,
// delete, and rename events. Emits schema.Events for each change.
//
// High-value default targets: System32, Program Files, startup dirs.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"obsidianwatch/agent/pkg/schema"
)

// FIM change notification flags
const (
	fileNotifyChangeFileName   = 0x00000001
	fileNotifyChangeDirName    = 0x00000002
	fileNotifyChangeAttributes = 0x00000004
	fileNotifyChangeSize       = 0x00000008
	fileNotifyChangeLastWrite  = 0x00000010
	fileNotifyChangeSecurity   = 0x00000100

	// We watch for: file/dir name changes + write + size changes
	fimNotifyFilter = fileNotifyChangeFileName |
		fileNotifyChangeDirName |
		fileNotifyChangeSize |
		fileNotifyChangeLastWrite

	fileListDirectory = 0x0001
	fileFlagBackupSemantics = 0x02000000
	fileFlagOverlapped      = 0x40000000
)

// FILE_NOTIFY_INFORMATION layout
type fileNotifyInformation struct {
	NextEntryOffset uint32
	Action          uint32
	FileNameLength  uint32
	FileName        [1]uint16 // variable length
}

const (
	fimActionAdded          = 1
	fimActionRemoved        = 2
	fimActionModified       = 3
	fimActionRenamedOldName = 4
	fimActionRenamedNewName = 5
)

var fimActionNames = map[uint32]string{
	fimActionAdded:          "created",
	fimActionRemoved:        "deleted",
	fimActionModified:       "modified",
	fimActionRenamedOldName: "renamed_from",
	fimActionRenamedNewName: "renamed_to",
}

// FIMConfig is the per-directory watcher configuration.
type FIMConfig struct {
	Path      string   `yaml:"path"`
	Recursive bool     `yaml:"recursive"`
	Exclude   []string `yaml:"exclude"` // glob patterns to skip
}

// FIMCollector watches a set of directories for file changes.
type FIMCollector struct {
	dirs    []FIMConfig
	agentID string
	host    string
	out     chan<- schema.Event
	logger  *slog.Logger
}

func NewFIMCollector(dirs []FIMConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *FIMCollector {
	return &FIMCollector{dirs: dirs, agentID: agentID, host: host, out: out, logger: logger}
}

func (f *FIMCollector) Run(ctx context.Context) error {
	// Every configured directory is watched, plus the interactive folders of each
	// local user profile (Downloads, Desktop, Documents, Temp, Startup). Those are where
	// malware and dropped files land, and they are not in the system-directory defaults.
	// Profiles created after start are picked up by the periodic rescan.
	watched := map[string]bool{}
	start := func(d FIMConfig) {
		key := strings.ToLower(d.Path)
		if watched[key] {
			return
		}
		watched[key] = true
		go func() {
			w := &dirWatcher{cfg: d, collector: f}
			if err := w.watch(ctx); err != nil && err != context.Canceled {
				f.logger.Error("fim: watcher error", "dir", d.Path, "err", err)
			}
		}()
		f.logger.Info("fim: watching", "dir", d.Path, "recursive", d.Recursive)
	}
	for _, dir := range f.dirs {
		start(dir)
	}
	scan := func() {
		for _, d := range userProfileDirs() {
			start(d)
		}
	}
	scan()
	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			scan()
		}
	}
}

// userProfileDirs lists the per-user folders to watch for every profile under C:\Users.
func userProfileDirs() []FIMConfig {
	noise := []string{".tmp", ".crdownload", ".part", "desktop.ini", "~$"}
	rel := []struct {
		path string
		rec  bool
	}{
		{`Downloads`, true},
		{`Desktop`, true},
		{`Documents`, false},
		{`AppData\Local\Temp`, false},
		{`AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`, true},
	}
	root := os.Getenv("SystemDrive")
	if root == "" {
		root = "C:"
	}
	users, _ := filepath.Glob(root + `\Users\*`)
	var out []FIMConfig
	for _, u := range users {
		switch strings.ToLower(filepath.Base(u)) {
		case "default", "default user", "all users", "defaultuser0":
			continue
		}
		for _, r := range rel {
			p := filepath.Join(u, r.path)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				out = append(out, FIMConfig{Path: p, Recursive: r.rec, Exclude: noise})
			}
		}
	}
	return out
}

type dirWatcher struct {
	cfg       FIMConfig
	collector *FIMCollector
}

func (w *dirWatcher) watch(ctx context.Context) error {
	pathPtr, err := windows.UTF16PtrFromString(w.cfg.Path)
	if err != nil {
		return fmt.Errorf("fim: UTF16 path: %w", err)
	}

	handle, err := windows.CreateFile(
		pathPtr,
		fileListDirectory,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		fileFlagBackupSemantics|fileFlagOverlapped,
		0,
	)
	if err != nil {
		return fmt.Errorf("fim: open dir %q: %w", w.cfg.Path, err)
	}
	defer windows.CloseHandle(handle)

	const bufSize = 64 * 1024 // 64 KB buffer
	buf := make([]byte, bufSize)

	recursive := uint32(0)
	if w.cfg.Recursive {
		recursive = 1
	}

	var bytesReturned uint32
	overlapped := &windows.Overlapped{}
	completionEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("fim: CreateEvent: %w", err)
	}
	defer windows.CloseHandle(completionEvent)
	overlapped.HEvent = completionEvent

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Queue a ReadDirectoryChangesW call
		err := windows.ReadDirectoryChanges(
			handle,
			&buf[0],
			uint32(len(buf)),
			recursive != 0,
			fimNotifyFilter,
			&bytesReturned,
			overlapped,
			0,
		)
		if err != nil && err != windows.ERROR_IO_PENDING {
			return fmt.Errorf("fim: ReadDirectoryChanges: %w", err)
		}

		// Wait for the overlapped operation or context cancellation
		waitHandles := []windows.Handle{completionEvent}
		idx, err := windows.WaitForMultipleObjects(waitHandles, false, 500)
		_ = idx
		if err != nil {
			// timeout - loop and check ctx
			windows.ResetEvent(completionEvent)
			continue
		}

		// Get the result
		if err := windows.GetOverlappedResult(handle, overlapped, &bytesReturned, false); err != nil {
			windows.ResetEvent(completionEvent)
			continue
		}

		if bytesReturned == 0 {
			windows.ResetEvent(completionEvent)
			continue
		}

		w.parseNotifications(buf[:bytesReturned])
		windows.ResetEvent(completionEvent)
	}
}

func (w *dirWatcher) parseNotifications(buf []byte) {
	offset := uint32(0)
	for {
		if int(offset)+int(unsafe.Sizeof(fileNotifyInformation{})) > len(buf) {
			break
		}

		fni := (*fileNotifyInformation)(unsafe.Pointer(&buf[offset]))
		nameLen := fni.FileNameLength / 2 // FileNameLength is in bytes, each UTF-16 char is 2 bytes
		if nameLen == 0 {
			break
		}

		// Extract filename from the variable-length array
		nameSlice := (*[32768]uint16)(unsafe.Pointer(&fni.FileName[0]))[:nameLen:nameLen]
		relPath := windows.UTF16ToString(nameSlice)
		fullPath := filepath.Join(w.cfg.Path, relPath)

		// Apply exclusion patterns
		if !w.shouldEmit(fullPath) {
			if fni.NextEntryOffset == 0 {
				break
			}
			offset += fni.NextEntryOffset
			continue
		}

		action := fni.Action
		actionName := fimActionNames[action]
		if actionName == "" {
			actionName = "unknown"
		}

		sev := fimSeverity(fullPath, action)
		rawData, _ := json.Marshal(map[string]interface{}{
			"action":   actionName,
			"path":     fullPath,
			"rel_path": relPath,
			"dir":      w.cfg.Path,
		})

		ev := schema.Event{
			Time:      time.Now().UTC(),
			AgentID:   w.collector.agentID,
			Host:      w.collector.host,
			OS:        "windows",
			EventType: schema.EventTypeFile,
			Severity:  sev,
			Source:    "FIM",
			FilePath:  fullPath,
			Raw:       rawData,
		}

		select {
		case w.collector.out <- ev:
		default:
			w.collector.logger.Warn("fim: out channel full, dropping event")
		}

		if fni.NextEntryOffset == 0 {
			break
		}
		offset += fni.NextEntryOffset
	}
}

func (w *dirWatcher) shouldEmit(path string) bool {
	lPath := strings.ToLower(path)
	base := filepath.Base(lPath)
	for _, pattern := range w.cfg.Exclude {
		lp := strings.ToLower(pattern)
		// Glob patterns are matched against the file name: a "*" never crosses a path
		// separator, so matching the full path made "*.log" style excludes inert.
		if matched, _ := filepath.Match(lp, base); matched {
			return false
		}
		// Also match if the pattern appears anywhere in the path
		if strings.Contains(lPath, strings.ToLower(pattern)) {
			return false
		}
	}
	return true
}

// fimSeverity determines severity based on path sensitivity and action.
func fimSeverity(path string, action uint32) schema.Severity {
	lPath := strings.ToLower(path)

	// High-sensitivity paths
	sensitive := []string{
		`\windows\system32`,
		`\windows\syswow64`,
		`\program files`,
		`\windows\system`,
	}

	isSensitive := false
	for _, s := range sensitive {
		if strings.Contains(lPath, s) {
			isSensitive = true
			break
		}
	}

	switch action {
	case fimActionRemoved:
		if isSensitive {
			return schema.SeverityHigh
		}
		return schema.SeverityMedium
	case fimActionAdded, fimActionRenamedNewName:
		if isSensitive {
			return schema.SeverityHigh
		}
		return schema.SeverityLow
	default:
		if isSensitive {
			return schema.SeverityMedium
		}
		return schema.SeverityInfo
	}
}
