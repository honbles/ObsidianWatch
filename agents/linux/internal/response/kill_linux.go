//go:build linux

package response

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func procPPID(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return -1
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return -1
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 {
		return -1
	}
	n, _ := strconv.Atoi(f[1])
	return n
}

func descendants(root int) []int {
	ents, _ := os.ReadDir("/proc")
	children := map[int][]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if pp := procPPID(pid); pp > 0 {
			children[pp] = append(children[pp], pid)
		}
	}
	var out []int
	var walk func(int, int)
	walk = func(p, depth int) {
		if depth > 32 {
			return
		}
		for _, c := range children[p] {
			walk(c, depth+1)
			out = append(out, c) // deepest first
		}
	}
	walk(root, 0)
	return out
}

func killProcess(pid int, image string, tree bool) (string, error) {
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	exe = strings.TrimSuffix(exe, " (deleted)")
	comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	name := exe
	if name == "" {
		name = strings.TrimSpace(string(comm))
	}
	if exe == "" && len(comm) == 0 {
		return "", fmt.Errorf("process %d does not exist", pid)
	}
	if err := guardKill(pid, name); err != nil {
		return "", err
	}
	if !imageMatches(image, exe) && !imageMatches(image, strings.TrimSpace(string(comm))) {
		return "", fmt.Errorf("pid %d is now %q, not %q (PID reused); not killed", pid, filepath.Base(name), image)
	}
	killed := 0
	if tree {
		for _, c := range descendants(pid) {
			if c == os.Getpid() {
				continue
			}
			if syscall.Kill(c, syscall.SIGKILL) == nil {
				killed++
			}
		}
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return "", fmt.Errorf("kill %d: %v", pid, err)
	}
	if tree {
		return fmt.Sprintf("killed %s (pid %d) and %d child process(es)", filepath.Base(name), pid, killed), nil
	}
	return fmt.Sprintf("killed %s (pid %d)", filepath.Base(name), pid), nil
}
