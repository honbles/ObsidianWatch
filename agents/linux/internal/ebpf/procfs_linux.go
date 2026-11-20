//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// procFS reads process and socket facts from /proc (a different root in tests).
type procFS struct {
	root string
	boot time.Time
	mu   sync.Mutex
	usr  map[int]string
}

func newProcFS(root string) *procFS {
	f := &procFS{root: root, usr: map[int]string{}}
	if b, err := os.ReadFile(root + "/stat"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(ln, "btime ") {
				if n, err := strconv.ParseInt(strings.TrimSpace(ln[6:]), 10, 64); err == nil {
					f.boot = time.Unix(n, 0).UTC()
				}
			}
		}
	}
	return f
}

// procDetail is ProcInfo plus the argument vector (used for service naming, never sent as is).
type procDetail struct {
	ProcInfo
	Args []string
	Unit string // systemd service the process runs under, if any
}

var containerRe = regexp.MustCompile(`[0-9a-f]{64}`)

func (f *procFS) pids() []int {
	ents, err := os.ReadDir(f.root)
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// statFields returns comm and the fields after the closing parenthesis of /proc/<pid>/stat:
// [0]=state [1]=ppid [2]=pgrp [3]=session [4]=tty_nr ... [19]=starttime.
func (f *procFS) statFields(pid int) (comm string, fs []string, err error) {
	b, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", f.root, pid))
	if err != nil {
		return "", nil, err
	}
	s := string(b)
	open, closeIdx := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || closeIdx < open || closeIdx+2 > len(s) {
		return "", nil, fmt.Errorf("malformed stat for %d", pid)
	}
	fs = strings.Fields(s[closeIdx+2:])
	if len(fs) < 20 {
		return "", nil, fmt.Errorf("short stat for %d", pid)
	}
	return s[open+1 : closeIdx], fs, nil
}

func (f *procFS) uidOf(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("%s/%d/status", f.root, pid))
	if err != nil {
		return -1
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "Uid:") {
			if fs := strings.Fields(ln[4:]); len(fs) >= 2 {
				n, _ := strconv.Atoi(fs[1]) // effective uid
				return n
			}
		}
	}
	return -1
}

func (f *procFS) userName(uid int) string {
	if uid < 0 {
		return ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if n, ok := f.usr[uid]; ok {
		return n
	}
	name := strconv.Itoa(uid)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	f.usr[uid] = name
	return name
}

// info reads what the sensor reports about one process.
func (f *procFS) info(pid int) (procDetail, error) {
	comm, fs, err := f.statFields(pid)
	if err != nil {
		return procDetail{}, err
	}
	d := procDetail{}
	d.PID, d.Name = pid, comm
	d.PPID, _ = strconv.Atoi(fs[1])
	tty, _ := strconv.Atoi(fs[4])
	d.TTY = tty != 0
	if ticks, err := strconv.ParseUint(fs[19], 10, 64); err == nil && !f.boot.IsZero() {
		d.Start = f.boot.Add(time.Duration(ticks) * time.Second / 100).UTC() // USER_HZ is 100
	}
	d.Exe, _ = os.Readlink(fmt.Sprintf("%s/%d/exe", f.root, pid))
	// Right after an exec the kernel can briefly report an empty cmdline; a kernel thread reports one
	// permanently (it has no exe either), so retry only for processes that do have an executable.
	for try := 0; try < 4; try++ {
		cl, err := os.ReadFile(fmt.Sprintf("%s/%d/cmdline", f.root, pid))
		if err == nil && len(cl) > 0 {
			d.Args = strings.Split(strings.TrimRight(string(cl), "\x00"), "\x00")
			d.Cmd = strings.Join(d.Args, " ")
			if len(d.Args) > 0 {
				d.Args = d.Args[1:] // argv[0] is the program
			}
			break
		}
		if d.Exe == "" || err != nil {
			break
		}
		time.Sleep(3 * time.Millisecond)
	}
	d.UID = f.uidOf(pid)
	d.User = f.userName(d.UID)
	if cg, err := os.ReadFile(fmt.Sprintf("%s/%d/cgroup", f.root, pid)); err == nil {
		d.Container = containerRe.FindString(string(cg))
		d.Unit = UnitFromCgroup(string(cg))
	}
	return d, nil
}

// ancestors walks the parent chain, nearest first, up to max levels.
func (f *procFS) ancestors(pid, max int) []Anc {
	var out []Anc
	cur := pid
	for i := 0; i < max; i++ {
		_, fs, err := f.statFields(cur)
		if err != nil {
			break
		}
		ppid, _ := strconv.Atoi(fs[1])
		if ppid <= 0 {
			break
		}
		comm, _, err := f.statFields(ppid)
		if err != nil {
			break
		}
		exe, _ := os.Readlink(fmt.Sprintf("%s/%d/exe", f.root, ppid))
		out = append(out, Anc{PID: ppid, Name: comm, Exe: exe})
		if ppid == 1 {
			break
		}
		cur = ppid
	}
	return out
}

// full is info plus the ancestry.
func (f *procFS) full(pid int) (procDetail, error) {
	d, err := f.info(pid)
	if err != nil {
		return d, err
	}
	d.Ancestors = f.ancestors(pid, 16)
	return d, nil
}

// ── sockets ────────────────────────────────────────────────────────────────

const (
	tcpEstablished = 0x01
	tcpSynSent     = 0x02
	tcpListen      = 0x0A
)

type tcpSock struct {
	localIP, remoteIP     string
	localPort, remotePort int
	state                 int
	inode                 string
}

// parseTCPAddr decodes an address as /proc/net/tcp{,6} prints it (little-endian 32-bit words).
func parseTCPAddr(s string) (string, int, error) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, fmt.Errorf("bad address %q", s)
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return "", 0, err
	}
	switch len(host) {
	case 8:
		v, err := strconv.ParseUint(host, 16, 32)
		if err != nil {
			return "", 0, err
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(v))
		return net.IP(b).String(), int(p), nil
	case 32:
		b := make([]byte, 16)
		for w := 0; w < 4; w++ {
			v, err := strconv.ParseUint(host[w*8:w*8+8], 16, 32)
			if err != nil {
				return "", 0, err
			}
			binary.LittleEndian.PutUint32(b[w*4:], uint32(v))
		}
		return net.IP(b).String(), int(p), nil
	}
	return "", 0, fmt.Errorf("bad address length %q", s)
}

func (f *procFS) tcp() []tcpSock {
	var out []tcpSock
	for _, file := range []string{"/net/tcp", "/net/tcp6"} {
		b, err := os.ReadFile(f.root + file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(b), "\n")
		for _, ln := range lines[1:] {
			fs := strings.Fields(ln)
			if len(fs) < 10 {
				continue
			}
			lip, lport, err1 := parseTCPAddr(fs[1])
			rip, rport, err2 := parseTCPAddr(fs[2])
			st, err3 := strconv.ParseUint(fs[3], 16, 8)
			if err1 != nil || err2 != nil || err3 != nil {
				continue
			}
			out = append(out, tcpSock{lip, rip, lport, rport, int(st), fs[9]})
		}
	}
	return out
}

// inodePIDs maps socket inodes to an owning pid by scanning /proc/<pid>/fd. It is the expensive step,
// so callers use it only when a new socket needs an owner.
func (f *procFS) inodePIDs(want map[string]bool) map[string]int {
	out := map[string]int{}
	for _, pid := range f.pids() {
		fds, err := os.ReadDir(fmt.Sprintf("%s/%d/fd", f.root, pid))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			l, err := os.Readlink(fmt.Sprintf("%s/%d/fd/%s", f.root, pid, fd.Name()))
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			ino := l[8 : len(l)-1]
			if want == nil || want[ino] {
				if _, seen := out[ino]; !seen {
					out[ino] = pid
				}
			}
		}
		if want != nil && len(out) == len(want) {
			break
		}
	}
	return out
}
