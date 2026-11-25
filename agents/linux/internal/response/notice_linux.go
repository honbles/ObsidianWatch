//go:build linux

package response

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// showNotice puts a critical desktop notification in every graphical
// session (through each user's session bus) and writes the message to every
// terminal (wall). Both are best effort: a server without a desktop just
// gets the wall message.
func showNotice(title, msg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "loginctl", "list-sessions", "--no-legend").Output(); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) < 3 {
				continue
			}
			id, uid, user := f[0], f[1], f[2]
			typ, _ := exec.CommandContext(ctx, "loginctl", "show-session", id, "-p", "Type", "--value").Output()
			t := strings.TrimSpace(string(typ))
			if t != "x11" && t != "wayland" {
				continue
			}
			bus := "/run/user/" + uid + "/bus"
			if _, err := os.Stat(bus); err != nil {
				continue
			}
			_ = exec.CommandContext(ctx, "runuser", "-u", user, "--", "env", "DBUS_SESSION_BUS_ADDRESS=unix:path="+bus,
				"notify-send", "-u", "critical", "-a", "ObsidianWatch", title, msg).Run()
		}
	}
	_ = exec.CommandContext(ctx, "wall", title+"\n"+msg).Run()
}
