//go:build linux

package otel

// peer_linux.go - peer identification on Linux. A Unix socket yields the peer's
// credentials from the kernel (SO_PEERCRED). A loopback TCP connection is mapped to a
// process through /proc: find the client socket's inode in /proc/net/tcp{,6}, then the
// process holding that inode in /proc/<pid>/fd. Process start time comes from
// /proc/<pid>/stat and the container id from /proc/<pid>/cgroup (spec sections 4, 13 #14).

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ProcFS is the /proc root; tests point it at a fixture tree.
type linuxResolver struct {
	proc string
}

// NewPeerResolver returns the Linux resolver reading the real /proc.
func NewPeerResolver() PeerResolver { return &linuxResolver{proc: "/proc"} }

func (r *linuxResolver) Resolve(c net.Conn) Peer {
	switch conn := c.(type) {
	case *net.UnixConn:
		raw, err := conn.SyscallConn()
		if err != nil {
			return Peer{Reason: "no syscall conn"}
		}
		var cred *unix.Ucred
		var cerr error
		if err := raw.Control(func(fd uintptr) {
			cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		}); err != nil || cerr != nil || cred == nil {
			return Peer{Reason: "SO_PEERCRED failed"}
		}
		return r.describe(int(cred.Pid))
	case *net.TCPConn:
		ra, ok1 := conn.RemoteAddr().(*net.TCPAddr)
		la, ok2 := conn.LocalAddr().(*net.TCPAddr)
		if !ok1 || !ok2 {
			return Peer{Reason: "not a TCP address"}
		}
		inode, err := r.socketInode(ra, la)
		if err != nil {
			return Peer{Reason: err.Error()}
		}
		pid := r.pidForInode(inode)
		if pid == 0 {
			return Peer{Reason: "no process holds the socket (other network namespace?)"}
		}
		return r.describe(pid)
	}
	return Peer{Reason: "unsupported connection type"}
}

// socketInode finds the inode of the CLIENT end of the connection: the table entry
// whose local address is our peer's address and whose remote address is ours.
func (r *linuxResolver) socketInode(client, server *net.TCPAddr) (string, error) {
	file := "net/tcp"
	if client.IP.To4() == nil {
		file = "net/tcp6"
	}
	f, err := os.Open(r.proc + "/" + file)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", file, err)
	}
	defer f.Close()
	want := hexAddr(client) + " " + hexAddr(server)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		if strings.ToUpper(fs[1]+" "+fs[2]) == want {
			return fs[9], nil
		}
	}
	return "", fmt.Errorf("connection not found in %s", file)
}

// hexAddr renders an address the way /proc/net/tcp does (little-endian words, upper hex).
func hexAddr(a *net.TCPAddr) string {
	ip := a.IP.To4()
	var hexIP string
	if ip != nil {
		hexIP = fmt.Sprintf("%02X%02X%02X%02X", ip[3], ip[2], ip[1], ip[0])
	} else {
		ip = a.IP.To16()
		for w := 0; w < 4; w++ {
			hexIP += fmt.Sprintf("%02X%02X%02X%02X", ip[w*4+3], ip[w*4+2], ip[w*4+1], ip[w*4])
		}
	}
	return fmt.Sprintf("%s:%04X", hexIP, a.Port)
}

// pidForInode scans /proc/<pid>/fd for socket:[inode]. Bounded work per connection.
func (r *linuxResolver) pidForInode(inode string) int {
	target := "socket:[" + inode + "]"
	ents, err := os.ReadDir(r.proc)
	if err != nil {
		return 0
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(fmt.Sprintf("%s/%d/fd", r.proc, pid))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if l, err := os.Readlink(fmt.Sprintf("%s/%d/fd/%s", r.proc, pid, fd.Name())); err == nil && l == target {
				return pid
			}
		}
	}
	return 0
}

var containerRe = regexp.MustCompile(`[0-9a-f]{64}`)

func (r *linuxResolver) describe(pid int) Peer {
	p := Peer{Resolved: true, PID: pid}
	stat, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", r.proc, pid))
	if err != nil {
		return Peer{Reason: "process exited before it could be identified"}
	}
	p.PPID, p.ProcStart = parseStat(string(stat), r.bootTime())
	p.Exe, _ = os.Readlink(fmt.Sprintf("%s/%d/exe", r.proc, pid))
	if cg, err := os.ReadFile(fmt.Sprintf("%s/%d/cgroup", r.proc, pid)); err == nil {
		p.ContainerID = containerRe.FindString(string(cg))
	}
	return p
}

// parseStat extracts ppid (field 4) and start time (field 22, clock ticks since boot).
// comm (field 2) may contain spaces and parentheses, so parsing starts after the LAST ')'.
func parseStat(s string, boot time.Time) (ppid int, start time.Time) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 > len(s) {
		return 0, time.Time{}
	}
	fs := strings.Fields(s[i+2:]) // fs[0] is field 3 (state)
	if len(fs) < 20 {
		return 0, time.Time{}
	}
	ppid, _ = strconv.Atoi(fs[1])
	ticks, err := strconv.ParseUint(fs[19], 10, 64)
	if err != nil || boot.IsZero() {
		return ppid, time.Time{}
	}
	const clkTck = 100 // USER_HZ is 100 on every mainstream Linux configuration
	return ppid, boot.Add(time.Duration(ticks) * time.Second / clkTck).UTC().Truncate(time.Millisecond)
}

func (r *linuxResolver) bootTime() time.Time {
	b, err := os.ReadFile(r.proc + "/stat")
	if err != nil {
		return time.Time{}
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "btime ") {
			if n, err := strconv.ParseInt(strings.TrimSpace(ln[6:]), 10, 64); err == nil {
				return time.Unix(n, 0).UTC()
			}
		}
	}
	return time.Time{}
}
