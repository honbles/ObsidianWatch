//go:build darwin

package response

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func psField(pid int, field string) string {
	out, err := run(context.Background(), "ps", "-p", strconv.Itoa(pid), "-o", field+"=")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func descendants(root int) []int {
	var out []int
	var walk func(int, int)
	walk = func(p, depth int) {
		if depth > 32 {
			return
		}
		o, _ := run(context.Background(), "pgrep", "-P", strconv.Itoa(p))
		for _, f := range strings.Fields(o) {
			if c, err := strconv.Atoi(f); err == nil {
				walk(c, depth+1)
				out = append(out, c)
			}
		}
	}
	walk(root, 0)
	return out
}

func killProcess(pid int, image string, tree bool) (string, error) {
	exe := psField(pid, "comm")
	if exe == "" {
		return "", fmt.Errorf("process %d does not exist", pid)
	}
	if err := guardKill(pid, exe); err != nil {
		return "", err
	}
	if !imageMatches(image, exe) {
		return "", fmt.Errorf("pid %d is now %q, not %q (PID reused); not killed", pid, filepath.Base(exe), image)
	}
	killed := 0
	if tree {
		for _, c := range descendants(pid) {
			if c != os.Getpid() && syscall.Kill(c, syscall.SIGKILL) == nil {
				killed++
			}
		}
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return "", fmt.Errorf("kill %d: %v", pid, err)
	}
	if tree {
		return fmt.Sprintf("killed %s (pid %d) and %d child process(es)", filepath.Base(exe), pid, killed), nil
	}
	return fmt.Sprintf("killed %s (pid %d)", filepath.Base(exe), pid), nil
}
