package api

import (
	"strings"

	"obsidianwatch/management/internal/store"
)

// isObsidianWatchActivity is every way an event can be ObsidianWatch's own
// doing, so it never becomes an alert:
//   - the agent itself, or a process the agent tagged as its own (scans,
//     response actions, hunt queries, installers);
//   - a process descended from the agent that the tag missed (the lineage
//     says so), unless it runs under the live-response shell: analyst
//     commands stay visible and alertable;
//   - the ObsidianWatch server stack on a monitored host: the backend and
//     management binaries in their containers, what they start (scanners,
//     git), and the compose healthchecks;
//   - Sysmon as the Windows agent installs it.
//
// The events are still stored and searchable; only alerting skips them.
func isObsidianWatchActivity(ev store.Event) bool {
	return isOwnAgentProcess(ev) || isSelfActivity(ev) || isOwnSysmon(ev) ||
		descendsFromAgent(ev) || isOwnServerStack(ev)
}

// liveShell reports whether a, a direct child of the agent, is the
// live-response shell: /bin/bash --login (Linux), <shell> -l (macOS), or a
// bare cmd.exe (Windows). The agent's own commands never look like this.
func liveShell(a store.ProcAncestor) bool {
	c := strings.ToLower(strings.TrimSpace(a.CommandLine))
	n := strings.ToLower(winBase(firstNonEmpty(a.Image, a.Name)))
	switch n {
	case "bash", "sh", "zsh":
		return strings.HasSuffix(c, " --login") || strings.HasSuffix(c, " -l")
	case "cmd.exe":
		return c == "" || c == "cmd.exe" || strings.HasSuffix(c, `\cmd.exe`) || strings.HasSuffix(c, `\cmd.exe"`)
	}
	return false
}

func isAgentAncestor(a store.ProcAncestor) bool {
	return ownAgentBinaries[strings.ToLower(winBase(firstNonEmpty(a.Image, a.Name)))]
}

// descendsFromAgent walks the lineage (parent first): the event is the
// agent's own when an ancestor is the agent and the process just below the
// agent is not the live-response shell.
func descendsFromAgent(ev store.Event) bool {
	for i, a := range ev.Ancestors {
		if !isAgentAncestor(a) {
			continue
		}
		var below store.ProcAncestor
		if i > 0 {
			below = ev.Ancestors[i-1]
		} else {
			below = store.ProcAncestor{Name: deref(ev.ProcessName), Image: deref(ev.ImagePath), CommandLine: deref(ev.CommandLine)}
		}
		return !liveShell(below)
	}
	return false
}

// ownServerImages are the server binaries inside the ObsidianWatch images
// (backend/docker/Dockerfile and management/docker/Dockerfile: WORKDIR /app).
var ownServerImages = map[string]bool{"/app/server": true, "/app/management-server": true}

// ownHealthchecks are the compose healthchecks of the ObsidianWatch stack
// (docker-compose.yml). They run every 10 to 15 s in the containers.
var ownHealthchecks = []string{
	"pg_isready -u obsidianwatch -d obsidianwatch",
	"wget -qo- --no-check-certificate https://localhost:8443/health",
	"cat /proc/net/tcp6 2>/dev/null | grep -q 20fb",
}

func ownHealthcheck(cmd string) bool {
	c := strings.ToLower(cmd)
	for _, h := range ownHealthchecks {
		if strings.Contains(c, h) {
			return true
		}
	}
	return false
}

func isOwnServerStack(ev store.Event) bool {
	if ownServerImages[strings.ToLower(deref(ev.ImagePath))] || ownHealthcheck(deref(ev.CommandLine)) {
		return true
	}
	for _, a := range ev.Ancestors {
		if ownServerImages[strings.ToLower(a.Image)] || ownHealthcheck(a.CommandLine) {
			return true
		}
	}
	return false
}

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
