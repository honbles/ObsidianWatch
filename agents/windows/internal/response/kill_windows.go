//go:build windows

package response

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func imagePath(h windows.Handle) string {
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func killProcess(pid int, image string, tree bool) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", fmt.Errorf("cannot open process %d: %v", pid, err)
	}
	defer windows.CloseHandle(h)
	img := imagePath(h)
	if err := guardKill(pid, img); err != nil {
		return "", err
	}
	if !imageMatches(image, img) {
		return "", fmt.Errorf("pid %d is now %q, not %q (PID reused); not killed", pid, filepath.Base(img), image)
	}
	if tree {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "taskkill", "/PID", fmt.Sprint(pid), "/T", "/F")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("taskkill: %v: %s", err, out)
		}
		return fmt.Sprintf("killed %s (pid %d) and its child processes", filepath.Base(img), pid), nil
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		return "", fmt.Errorf("terminate %d: %v", pid, err)
	}
	return fmt.Sprintf("killed %s (pid %d)", filepath.Base(img), pid), nil
}
