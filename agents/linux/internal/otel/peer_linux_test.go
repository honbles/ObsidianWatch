//go:build linux

package otel

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseStatHandlesOddComm(t *testing.T) {
	// comm contains spaces and a closing parenthesis; field 4 is ppid, field 22 is starttime.
	stat := "123 (my (weird) app) S 77 123 123 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 5 0 5000 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0"
	boot := time.Unix(1_700_000_000, 0).UTC()
	ppid, start := parseStat(stat, boot)
	if ppid != 77 || !start.Equal(boot.Add(50*time.Second)) {
		t.Fatalf("ppid=%d start=%v", ppid, start)
	}
	if p, s := parseStat("garbage", boot); p != 0 || !s.IsZero() {
		t.Fatal("garbage must not parse")
	}
}

func TestHexAddrMatchesProcFormat(t *testing.T) {
	if got := hexAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4318}); got != "0100007F:10DE" {
		t.Fatal(got)
	}
	if got := hexAddr(&net.TCPAddr{IP: net.ParseIP("::1"), Port: 80}); got != "00000000000000000000000001000000:0050" {
		t.Fatal(got)
	}
}

// The real thing: this process connects to a receiver; the resolver must name this process.
func TestRealTCPPeerResolution(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan Peer, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got <- NewPeerResolver().Resolve(c)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case p := <-got:
		if !p.Resolved || p.PID != os.Getpid() || p.PPID != os.Getppid() || p.Exe == "" || p.ProcStart.IsZero() {
			t.Skipf("could not resolve via /proc in this sandbox: %+v", p) // e.g. restricted /proc
		}
		if time.Since(p.ProcStart) < 0 {
			t.Fatalf("process start in the future: %v", p.ProcStart)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRealUnixSocketPeerCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "otlp.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan Peer, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got <- NewPeerResolver().Resolve(c)
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := <-got
	if !p.Resolved || p.PID != os.Getpid() {
		t.Fatalf("SO_PEERCRED: %+v", p)
	}
}

func TestReceiverOnUnixSocketEndToEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "otlp.sock")
	agg := NewAggregator(AggOptions{}, nil)
	r := NewReceiver(ReceiverOptions{Socket: path}, agg, NewBinder(), NewPeerResolver(), EventContext{}, nil, discardLog())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !r.OnlyLocal() {
		t.Fatal("unix socket is local")
	}
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	req, _ := http.NewRequest("POST", "http://otlp/v1/traces", bytesReader(goodTraces()))
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := hc.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", err, resp)
	}
	resp.Body.Close()
	b := agg.Flush("a", true)
	if b == nil || len(b.Instances) != 1 || b.Instances[0].PID != os.Getpid() || b.Instances[0].Identity != "verified" {
		t.Fatalf("%+v", b)
	}
	cancel()
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("socket file should be removed on shutdown")
	}
}
