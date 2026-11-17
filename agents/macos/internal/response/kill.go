package response

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// protectedNames are never killed: doing so crashes or bricks the host.
var protectedNames = map[string]bool{
	"systemd": true, "init": true, "launchd": true, "kernel_task": true,
	"system": true, "registry": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true,
	"winlogon.exe": true, "services.exe": true, "lsass.exe": true, "obsidianwatch-agent": true,
}

func guardKill(pid int, name string) error {
	if pid <= 1 {
		return fmt.Errorf("refusing to kill pid %d", pid)
	}
	if pid == os.Getpid() || pid == os.Getppid() {
		return fmt.Errorf("refusing to kill the ObsidianWatch agent")
	}
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(name, `\`, "/")))
	if protectedNames[base] {
		return fmt.Errorf("refusing to kill protected system process %q", base)
	}
	if strings.Contains(base, "obsidianwatch") {
		return fmt.Errorf("refusing to kill the ObsidianWatch agent")
	}
	return nil
}

// imageMatches reports whether the live process's image is the one the analyst
// saw (guards against PID reuse). want may be a full path or a bare name.
func imageMatches(want, got string) bool {
	if want == "" {
		return true
	}
	norm := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, `\`, "/")) }
	w, g := norm(want), norm(got)
	if w == g {
		return true
	}
	return filepath.Base(w) == filepath.Base(g)
}

func (h *Handler) kill(p Params) Result {
	if p.PID <= 0 {
		return Result{Message: "pid required"}
	}
	msg, err := killProcess(p.PID, p.Image, p.Tree)
	if err != nil {
		return Result{Message: err.Error()}
	}
	h.logger.Warn("response: process killed", "pid", p.PID, "tree", p.Tree)
	return Result{OK: true, Message: msg}
}
