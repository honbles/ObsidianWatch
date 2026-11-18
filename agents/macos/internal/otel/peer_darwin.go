//go:build darwin

package otel

// peer_darwin.go - peer identification on macOS. lsof (part of the OS) lists the owner of the
// client socket of a loopback connection; ps supplies parent, start time and image path. This is
// done once per connection. A native libproc implementation would avoid the subprocess but needs cgo.

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type darwinResolver struct{}

// NewPeerResolver returns the macOS resolver.
func NewPeerResolver() PeerResolver { return darwinResolver{} }

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).Output()
	return string(b), err
}

func (darwinResolver) Resolve(c net.Conn) Peer {
	conn, ok := c.(*net.TCPConn)
	if !ok {
		return Peer{Reason: "unsupported connection type"}
	}
	ra, ok1 := conn.RemoteAddr().(*net.TCPAddr)
	la, ok2 := conn.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return Peer{Reason: "not a TCP address"}
	}
	out, err := run("lsof", "-nP", "-a", "-iTCP:"+strconv.Itoa(ra.Port), "-sTCP:ESTABLISHED", "-Fpn")
	if err != nil && out == "" {
		return Peer{Reason: "lsof failed: " + err.Error()}
	}
	pid := lsofOwner(out, ra.String(), la.String())
	if pid == 0 {
		return Peer{Reason: "no process owns the client socket"}
	}
	p := Peer{Resolved: true, PID: pid}
	if s, err := run("ps", "-o", "ppid=,lstart=", "-p", strconv.Itoa(pid)); err == nil {
		f := strings.Fields(s)
		if len(f) >= 6 {
			p.PPID, _ = strconv.Atoi(f[0])
			if t, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.Join(f[1:], " "), time.Local); err == nil {
				p.ProcStart = t.UTC().Truncate(time.Second)
			}
		}
	} else {
		return Peer{Reason: "process exited before it could be identified"}
	}
	if s, err := run("ps", "-o", "comm=", "-p", strconv.Itoa(pid)); err == nil {
		p.Exe = strings.TrimSpace(s)
	}
	return p
}
