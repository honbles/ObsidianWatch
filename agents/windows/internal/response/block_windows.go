//go:build windows

package response

import (
	"fmt"
	"os/exec"
	"strings"
)

// denyExec adds an ACL entry that denies Execute to Everyone (which includes SYSTEM), so Windows
// refuses to start the file. It does not touch the file's contents.
func denyExec(path string) (uint32, error) {
	out, err := exec.Command("icacls", path, "/deny", "*S-1-1-0:(X)").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("icacls: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return 0, nil
}

func allowExec(path string, _ uint32) error {
	out, err := exec.Command("icacls", path, "/remove:d", "*S-1-1-0").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
