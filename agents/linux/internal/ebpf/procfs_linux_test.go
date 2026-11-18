//go:build linux

package ebpf

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestParseTCPAddr(t *testing.T) {
	for in, want := range map[string]struct {
		ip   string
		port int
	}{
		"0100007F:1F90":                         {"127.0.0.1", 8080},
		"0A00020F:01BB":                         {"15.2.0.10", 443},
		"00000000000000000000000001000000:0050": {"::1", 80},
		"00000000:0000":                         {"0.0.0.0", 0},
	} {
		ip, port, err := parseTCPAddr(in)
		if err != nil || ip != want.ip || port != want.port {
			t.Fatalf("%s: %s %d %v", in, ip, port, err)
		}
	}
	for _, bad := range []string{"", "nocolon", "ZZ:1", "0100007F:ZZZZ", "123:50"} {
		if _, _, err := parseTCPAddr(bad); err == nil {
			t.Fatalf("%q must fail", bad)
		}
	}
}

func TestProcInfoOfSelfAndChild(t *testing.T) {
	f := newProcFS("/proc")
	d, err := f.full(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if d.PID != os.Getpid() || d.PPID != os.Getppid() || d.Exe == "" || d.Cmd == "" || d.Start.IsZero() || d.UID != os.Geteuid() || d.User == "" {
		t.Fatalf("%+v", d)
	}
	if time.Since(d.Start) < 0 || time.Since(d.Start) > 24*time.Hour {
		t.Fatalf("start time implausible: %v", d.Start)
	}
	// A child: its ancestry must include this test process, nearest first.
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skip("cannot start a child process")
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	c, err := f.full(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "sleep" || c.PPID != os.Getpid() || len(c.Ancestors) == 0 || c.Ancestors[0].PID != os.Getpid() || c.TTY {
		t.Fatalf("child: %+v", c)
	}
	if len(c.Args) != 1 || c.Args[0] != "5" {
		t.Fatalf("args exclude argv[0]: %v", c.Args)
	}
	if f.ancestors(999999999, 5) != nil {
		t.Fatal("a missing pid has no ancestors")
	}
	if _, err := f.info(999999999); err == nil {
		t.Fatal("a missing pid is an error")
	}
}

func TestTCPSocketsAndOwners(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	srv, _ := ln.Accept()
	defer srv.Close()
	f := newProcFS("/proc")
	var listen, est *tcpSock
	for _, s := range f.tcp() {
		s := s
		if s.localPort == port && s.state == tcpListen {
			listen = &s
		}
		if s.remotePort == port && s.state == tcpEstablished {
			est = &s
		}
	}
	if listen == nil || est == nil {
		t.Skipf("could not see the sockets in /proc/net/tcp (restricted /proc?): listen=%v est=%v", listen, est)
	}
	owners := f.inodePIDs(map[string]bool{listen.inode: true, est.inode: true})
	if owners[listen.inode] != os.Getpid() || owners[est.inode] != os.Getpid() {
		t.Fatalf("owners: %v want pid %s", owners, strconv.Itoa(os.Getpid()))
	}
}
