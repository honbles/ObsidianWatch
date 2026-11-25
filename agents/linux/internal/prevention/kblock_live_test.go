//go:build linux && bpflive

package prevention

// Live test: go test -tags bpflive -run KernelBlock ./internal/prevention (root)

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

func TestKernelBlockLive(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.77:0")
	if err != nil {
		t.Skip("cannot bind 127.0.0.77:", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	addr := ln.Addr().String()
	out := make(chan schema.Event, 10)
	e := New(Options{Dir: t.TempDir(), Out: out, Logger: quiet()})
	k, err := StartKernelBlocker(e)
	if err != nil {
		t.Fatalf("kernel blocker: %v", err)
	}
	defer k.Close()
	e.SetKernelBlocker(k)
	go e.Run(context.Background())

	if c, err := net.DialTimeout("tcp4", addr, time.Second); err != nil {
		t.Fatalf("before the block: %v", err)
	} else {
		c.Close()
	}
	e.Update(&Set{Version: "k1", IPs: []Entry{{V: "127.0.0.77", Until: time.Now().Add(time.Hour).Unix(), Src: "test"}}},
		map[string]string{"ip": Enforce}, nil)

	_, err = net.DialTimeout("tcp4", addr, time.Second)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("connect not refused: %v", err)
	}
	// Connected UDP goes through the connect hook, unconnected UDP through sendmsg.
	if _, uerr := net.Dial("udp4", "127.0.0.77:53"); !errors.Is(uerr, syscall.EPERM) {
		t.Fatalf("udp connect not refused: %v", uerr)
	}
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer pc.Close()
	if _, uerr := pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 77), Port: 53}); !errors.Is(uerr, syscall.EPERM) {
		t.Fatalf("udp sendto not refused: %v", uerr)
	}
	select {
	case ev := <-out:
		var m map[string]any
		json.Unmarshal(ev.Raw, &m)
		if m["action"] != "blocked" || m["indicator"] != "127.0.0.77" || ev.PID == 0 {
			t.Fatalf("report %v pid %d", m, ev.PID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no report for the refused connect")
	}
	// Other addresses are untouched.
	if c, err := net.DialTimeout("tcp4", "127.0.0.1:1", 200*time.Millisecond); err == nil {
		c.Close()
	} else if errors.Is(err, syscall.EPERM) {
		t.Fatal("unlisted address refused")
	}
	// Audit mode empties the kernel list.
	e.Update(nil, map[string]string{"ip": Audit}, nil)
	if c, err := net.DialTimeout("tcp4", addr, time.Second); err != nil {
		t.Fatalf("after switching to audit: %v", err)
	} else {
		c.Close()
	}
	_ = netip.Addr{}
}
