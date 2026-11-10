package api

import (
	"strings"

	"obsidianwatch/management/internal/store"
)

// isSelfActivity reports whether the agent tagged the event as activity of its
// own making: a process the agent spawned (vulnerability scan, installer,
// service check) or a descendant of one. The agent sets raw.self_activity;
// the live-response shell is deliberately never tagged, so analyst commands
// stay visible and alertable.
func isSelfActivity(ev store.Event) bool {
	return strings.Contains(rawStr(ev), `"self_activity":true`)
}

// isOwnSysmon matches the Sysmon service the Windows agent installs. A path is
// required, so a binary merely named sysmon64.exe elsewhere is still analysed.
func isOwnSysmon(ev store.Event) bool {
	if ev.ProcessName == nil || ev.ImagePath == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(*ev.ProcessName)) {
	case "sysmon.exe", "sysmon64.exe":
	default:
		return false
	}
	p := strings.ToLower(strings.ReplaceAll(*ev.ImagePath, "\\", "/"))
	return strings.HasPrefix(p, "c:/windows/sysmon")
}
