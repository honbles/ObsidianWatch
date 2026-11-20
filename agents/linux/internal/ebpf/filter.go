package ebpf

import (
	"strings"
	"sync"
)

// ignoredListeners are well-known system daemons that listen on ports but are not application
// services; they are not reported as discovered services.
var ignoredListeners = map[string]bool{
	"sshd": true, "systemd": true, "systemd-resolve": true, "systemd-resolved": true, "rpcbind": true, "chronyd": true, "ntpd": true,
	"cupsd": true, "avahi-daemon": true, "dnsmasq": true, "master": true, "named": true, "unbound": true, "containerd": true,
	"dockerd": true, "kubelet": true, "node_exporter": true, "dhclient": true, "rsyslogd": true, "crond": true, "cron": true,
	// Docker publishes each port through a docker-proxy on the host, and the shims supervise containers; none is an application.
	"docker-proxy": true, "containerd-shim": true, "containerd-shim-runc-v2": true, "containerd-shim-runc-v1": true,
	"agent": true, "obsidianwatch-agent": true, "obsidian-agent": true, "snapd": true, "polkitd": true, "exim4": true, "smbd": true, "nmbd": true,
}

// IgnoreListener reports whether a process listening on a port is a system daemon.
func IgnoreListener(exeBase string) bool {
	return ignoredListeners[strings.ToLower(exeBase)]
}

// Registry is the set of service process ids the sensor reports on.
type Registry struct {
	mu   sync.RWMutex
	pids map[int]string // pid -> service name
}

func NewRegistry() *Registry { return &Registry{pids: map[int]string{}} }

// Set replaces the discovered services' pids.
func (r *Registry) Set(m map[int]string) {
	r.mu.Lock()
	r.pids = m
	r.mu.Unlock()
}

func (r *Registry) Has(pid int) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.pids[pid]
	return ok
}

// InLineage reports whether any pid of the lineage is a registered service process.
func (r *Registry) InLineage(pids []int) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range pids {
		if _, ok := r.pids[p]; ok {
			return true
		}
	}
	return false
}

// PIDs returns the registered service pids (used to seed the kernel tier's watch map).
func (r *Registry) PIDs() []int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]int, 0, len(r.pids))
	for p := range r.pids {
		out = append(out, p)
	}
	return out
}

func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.pids)
}
