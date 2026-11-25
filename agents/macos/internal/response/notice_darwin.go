//go:build darwin

package response

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// showNotice shows a dialog to the user at the console (launchctl asuser
// runs osascript in their session). It closes on its own after 5 minutes.
func showNotice(title, msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "stat", "-f", "%u", "/dev/console").Output()
	uid := strings.TrimSpace(string(out))
	if err != nil || uid == "" || uid == "0" {
		return // nobody logged in at the console
	}
	q := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) }
	script := `display dialog "` + q(msg) + `" with title "` + q(title) + `" buttons {"OK"} default button "OK" with icon caution giving up after 300`
	_ = exec.CommandContext(ctx, "launchctl", "asuser", uid, "osascript", "-e", script).Run()
}
