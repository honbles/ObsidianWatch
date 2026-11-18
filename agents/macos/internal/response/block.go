package response

// block.go - stop a program from running, not just kill the current instance.
//
// A block has two layers. (1) The file is made non-executable (Windows: an ACL that denies Execute
// to Everyone; Linux/macOS: the execute bits are removed), so the OS refuses to start it at all.
// (2) The agent scans running processes every second and kills any whose image is on the block list,
// which covers copies launched through a path the permission change does not reach and files that
// were replaced after the block. The list is persisted and survives restarts. System files and the
// agent itself can never be blocked.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type blockEntry struct {
	Path   string    `json:"path"`
	Mode   uint32    `json:"mode,omitempty"` // original permission bits (Linux/macOS)
	Since  time.Time `json:"since"`
	Reason string    `json:"reason,omitempty"`
	Denied bool      `json:"denied"` // the file-level deny was applied
}

func (h *Handler) blockedFile() string { return filepath.Join(h.dir, "blocked.json") }

func (h *Handler) loadBlocked() []blockEntry {
	var l []blockEntry
	if b, err := os.ReadFile(h.blockedFile()); err == nil {
		_ = json.Unmarshal(b, &l)
	}
	return l
}

func (h *Handler) saveBlocked(l []blockEntry) error {
	if err := os.MkdirAll(h.dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(l, "", "  ")
	return os.WriteFile(h.blockedFile(), b, 0o600)
}

func samePath(a, b string) bool {
	n := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, `\`, "/")) }
	return n(a) == n(b)
}

func (h *Handler) block(ctx context.Context, p Params) Result {
	path := p.Path
	if path == "" || !filepath.IsAbs(path) {
		return Result{Message: "the full path of the program to block is required"}
	}
	path = filepath.Clean(path)
	if protectedPath(path) {
		return Result{Message: "refusing to block an operating-system file (" + path + "); that would damage the host"}
	}
	if strings.Contains(strings.ToLower(filepath.Base(path)), "obsidianwatch") || strings.HasPrefix(strings.ToLower(path), strings.ToLower(h.dir)+string(filepath.Separator)) {
		return Result{Message: "refusing to block the ObsidianWatch agent"}
	}
	if exe, err := os.Executable(); err == nil && samePath(exe, path) {
		return Result{Message: "refusing to block the ObsidianWatch agent binary"}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	l := h.loadBlocked()
	for _, e := range l {
		if samePath(e.Path, path) {
			return Result{OK: true, Message: "already blocked: " + path}
		}
	}
	e := blockEntry{Path: path, Since: time.Now().UTC(), Reason: p.Match}
	note := ""
	if _, err := os.Stat(path); err == nil {
		mode, err := denyExec(path)
		if err != nil {
			note = " (file permission change failed: " + err.Error() + "; running copies are still killed on sight)"
		} else {
			e.Mode, e.Denied = mode, true
		}
	} else {
		note = " (file not found; running copies will be killed on sight)"
	}
	l = append(l, e)
	if err := h.saveBlocked(l); err != nil {
		return Result{Message: "could not save the block list: " + err.Error()}
	}
	killed := 0
	for _, pid := range pidsByPath(ctx, path) {
		if _, err := killProcess(pid, path, true); err == nil {
			killed++
		}
	}
	h.logger.Warn("response: program blocked", "path", path, "killed", killed)
	return Result{OK: true, Message: "blocked " + path + "; ended " + strconv.Itoa(killed) + " running instance(s)" + note}
}

func (h *Handler) unblock(p Params) Result {
	h.mu.Lock()
	defer h.mu.Unlock()
	l := h.loadBlocked()
	var keep []blockEntry
	found := false
	for _, e := range l {
		if samePath(e.Path, p.Path) {
			found = true
			if e.Denied {
				_ = allowExec(e.Path, e.Mode)
			}
			continue
		}
		keep = append(keep, e)
	}
	if !found {
		return Result{Message: "that program is not on the block list"}
	}
	if err := h.saveBlocked(keep); err != nil {
		return Result{Message: err.Error()}
	}
	h.logger.Warn("response: program unblocked", "path", p.Path)
	return Result{OK: true, Message: "unblocked " + p.Path}
}

func (h *Handler) listBlocked() Result {
	h.mu.Lock()
	defer h.mu.Unlock()
	l := h.loadBlocked()
	t := Table{Columns: []string{"path", "since", "reason", "file_denied"}, Rows: [][]string{}}
	for _, e := range l {
		d := "no"
		if e.Denied {
			d = "yes"
		}
		t.Rows = append(t.Rows, []string{e.Path, e.Since.Format(time.RFC3339), e.Reason, d})
	}
	return Result{OK: true, Message: strconv.Itoa(len(l)) + " blocked", Data: t}
}

// enforceLoop kills blocked programs the moment they appear, and re-applies the file-level deny
// every few minutes in case the file was replaced.
func (h *Handler) enforceLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		h.mu.Lock()
		l := h.loadBlocked()
		h.mu.Unlock()
		if len(l) == 0 {
			continue
		}
		n++
		for _, e := range l {
			for _, pid := range pidsByPath(ctx, e.Path) {
				if _, err := killProcess(pid, e.Path, true); err == nil {
					h.logger.Warn("response: blocked program was started and ended", "path", e.Path, "pid", pid)
				}
			}
			if e.Denied && n%300 == 0 {
				_, _ = denyExec(e.Path)
			}
		}
	}
}
