package otel

// lsofparse.go - parsing of `lsof -F pn` output, used on macOS to find the process that owns
// the client end of a loopback connection. Pure string handling, so it is tested on any OS.

import (
	"strconv"
	"strings"
)

// lsofOwner returns the PID whose connection name is "<client>-><server>" (for example
// "127.0.0.1:55000->127.0.0.1:4318"). Field output is lines starting with p<pid> then n<name>.
func lsofOwner(out, client, server string) int {
	want := client + "->" + server
	pid := 0
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		switch ln[0] {
		case 'p':
			pid, _ = strconv.Atoi(ln[1:])
		case 'n':
			if pid > 0 && strings.TrimSuffix(ln[1:], " (ESTABLISHED)") == want {
				return pid
			}
		}
	}
	return 0
}
