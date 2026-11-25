package prevention

import (
	"bufio"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"obsidianwatch/agent/pkg/schema"
)

// protector answers whether an address must never be blocked: loopback,
// private, link-local, multicast, the manager's addresses and the host's
// DNS resolvers. Manager names are re-resolved every 10 minutes.
type protector struct {
	mu    sync.RWMutex
	hosts []string
	set   map[netip.Addr]bool
	at    time.Time
}

func newProtector(urls []string) *protector {
	p := &protector{set: map[netip.Addr]bool{}}
	for _, u := range urls {
		if pu, err := url.Parse(u); err == nil && pu.Hostname() != "" {
			p.hosts = append(p.hosts, pu.Hostname())
		}
	}
	p.refresh()
	return p
}

func (p *protector) refresh() {
	set := map[netip.Addr]bool{}
	for _, h := range p.hosts {
		if a, err := netip.ParseAddr(h); err == nil {
			set[a.Unmap()] = true
			continue
		}
		addrs, _ := net.LookupHost(h)
		for _, s := range addrs {
			if a, err := netip.ParseAddr(s); err == nil {
				set[a.Unmap()] = true
			}
		}
	}
	if runtime.GOOS != "windows" {
		if f, err := os.Open("/etc/resolv.conf"); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if fl := strings.Fields(sc.Text()); len(fl) >= 2 && fl[0] == "nameserver" {
					if a, err := netip.ParseAddr(fl[1]); err == nil {
						set[a.Unmap()] = true
					}
				}
			}
			f.Close()
		}
	}
	p.mu.Lock()
	// Keep previously known addresses if a lookup failed this time.
	for a := range p.set {
		if len(set) == 0 {
			set[a] = true
		}
	}
	p.set, p.at = set, time.Now()
	p.mu.Unlock()
}

func (p *protector) protected(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	p.mu.RLock()
	hit, stale := p.set[a], time.Since(p.at) > 10*time.Minute
	p.mu.RUnlock()
	if stale {
		go p.refresh()
	}
	return hit
}

// StartOptions wire the engine into an agent.
type StartOptions struct {
	Dir        string
	Out        chan<- schema.Event
	Responder  Responder
	AgentID    string
	Host       string
	OS         string
	Logger     *slog.Logger
	BackendURL string
	// ProtectURLs are the manager URLs; their addresses are never blocked.
	ProtectURLs []string
	TLS         *tls.Config
	// Kernel enables the Linux eBPF connect block (ignored elsewhere).
	Kernel bool
}

// Start builds the engine, restores the last set, starts the kernel tier
// when asked and available, the poller and the engine loop.
func Start(ctx context.Context, o StartOptions) *Engine {
	prot := newProtector(append([]string{o.BackendURL}, o.ProtectURLs...))
	e := New(Options{Dir: o.Dir, Out: o.Out, Responder: o.Responder, Protected: prot.protected,
		AgentID: o.AgentID, Host: o.Host, OS: o.OS, Logger: o.Logger})
	if o.Kernel {
		if k, err := StartKernelBlocker(e); err == nil {
			e.SetKernelBlocker(k)
			e.logger.Info("prevention: kernel connect blocking available (eBPF)")
		} else if runtime.GOOS == "linux" {
			e.logger.Info("prevention: kernel connect blocking unavailable; IP matches use block_ip", "reason", err)
		}
	}
	go e.Run(ctx)
	go (&Poller{Engine: e, BackendURL: o.BackendURL, AgentID: o.AgentID, TLS: o.TLS}).Run(ctx)
	return e
}
