package ebpf

// darwinparse.go - parsing of the ps and lsof output the macOS provider reads. No OS calls, so it
// is tested on any platform.

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// parsePS parses `ps -axww -o pid=,ppid=,user=,lstart=,command=`: five lstart words
// ("Wed Nov 18 07:00:00 2026") sit between the user and the command.
func parsePS(out string, loc *time.Location) map[int]procRec {
	res := map[int]procRec{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 9 {
			continue
		}
		pid, e1 := strconv.Atoi(f[0])
		ppid, e2 := strconv.Atoi(f[1])
		if e1 != nil || e2 != nil {
			continue
		}
		start, _ := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.Join(f[3:8], " "), loc)
		cmd := strings.Join(f[8:], " ")
		// the command's first word is the program; arguments follow (paths with spaces are not split correctly)
		res[pid] = procRec{PID: pid, PPID: ppid, User: f[2], Start: start.UTC(), Cmd: cmd, Exe: f[8], Name: baseOf(f[8]), Args: f[9:]}
	}
	return res
}

// parseLsofTCP parses `lsof -nP -iTCP -F pfnT`.
func parseLsofTCP(out string) []connRec {
	var res []connRec
	pid := 0
	var name, state string
	flush := func() {
		if name == "" || pid == 0 {
			name, state = "", ""
			return
		}
		local, remote := name, ""
		if i := strings.Index(name, "->"); i >= 0 {
			local, remote = name[:i], name[i+2:]
		}
		lip, lp := splitHostPort(local)
		rip, rp := splitHostPort(remote)
		if state == "" {
			state = "OTHER"
		}
		res = append(res, connRec{State: state, LocalIP: lip, LocalPort: lp, RemoteIP: rip, RemotePort: rp, PID: pid})
		name, state = "", ""
	}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		switch {
		case ln[0] == 'p':
			flush()
			pid, _ = strconv.Atoi(ln[1:])
		case ln[0] == 'f':
			flush()
		case ln[0] == 'n':
			name = ln[1:]
		case strings.HasPrefix(ln, "TST="):
			state = ln[4:]
		}
	}
	flush()
	return res
}

func splitHostPort(s string) (string, int) {
	if s == "" {
		return "", 0
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0
	}
	if h == "*" {
		h = "0.0.0.0"
	}
	n, _ := strconv.Atoi(p)
	return h, n
}
