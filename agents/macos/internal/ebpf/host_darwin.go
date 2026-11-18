//go:build darwin

package ebpf

// host_darwin.go - process and TCP snapshots on macOS from ps and lsof, both part of the OS.
// lsof is heavier than the Linux /proc reads, so the TCP snapshot is cached for a few seconds.

import (
	"context"
	"os/exec"
	"sync"
	"time"
)

type darwinHost struct {
	mu     sync.Mutex
	conns  []connRec
	connAt time.Time
}

func newHost() hostProvider { return &darwinHost{} }

func runCmd(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).Output()
	return string(b), err
}

func (h *darwinHost) Procs() (map[int]procRec, error) {
	out, err := runCmd("ps", "-axww", "-o", "pid=,ppid=,user=,lstart=,command=")
	if err != nil && out == "" {
		return nil, err
	}
	return parsePS(out, time.Local), nil
}

func (h *darwinHost) TCP() ([]connRec, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if time.Since(h.connAt) < 4*time.Second {
		return h.conns, nil
	}
	out, err := runCmd("lsof", "-nP", "-iTCP", "-F", "pfnT")
	if err != nil && out == "" {
		return nil, err
	}
	h.conns, h.connAt = parseLsofTCP(out), time.Now()
	return h.conns, nil
}
