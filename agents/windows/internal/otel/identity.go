package otel

// identity.go - who is sending? The app never says which host, process or container
// it runs in. The agent resolves the sending process from the connection itself and
// binds a service name to that process; telemetry from a process that does not match
// the service's known instances is marked "asserted" and cannot raise high-severity
// alerts on its own (spec sections 4 and 7).

import (
	"net"
	"path/filepath"
	"sync"
	"time"
)

// Peer is what the agent learned about the sending process.
type Peer struct {
	Resolved    bool
	PID         int
	PPID        int
	ProcStart   time.Time
	ContainerID string
	Exe         string
	Reason      string // why it was not resolved
}

// PeerResolver maps an accepted connection to a process.
type PeerResolver interface {
	Resolve(c net.Conn) Peer
}

// Identity values stored on an instance.
const (
	IdentityVerified = "verified"
	IdentityAsserted = "asserted"
)

type boundInstance struct {
	pid       int
	procStart time.Time
	exe       string
}

// Binder decides verified vs asserted per (service, environment).
type Binder struct {
	mu   sync.Mutex
	svcs map[string][]boundInstance
}

func NewBinder() *Binder { return &Binder{svcs: map[string][]boundInstance{}} }

const maxBoundPerService = 64

// Bind returns the identity for telemetry claiming (service, env) from peer.
//
//   - Unresolved peer: asserted.
//   - First resolved process to claim a service: it becomes the binding (verified).
//   - Later processes: verified only when they are a known instance (same pid and
//     start time) or run the same executable as a known instance (a worker, a
//     restart, a second copy). Anything else is asserted and is NOT recorded, so a
//     local process cannot enlarge the set of processes allowed to speak for a service.
func (b *Binder) Bind(service, env string, p Peer) string {
	if !p.Resolved || p.PID <= 0 {
		return IdentityAsserted
	}
	k := service + "|" + env
	b.mu.Lock()
	defer b.mu.Unlock()
	known := b.svcs[k]
	if len(known) == 0 {
		b.svcs[k] = []boundInstance{{p.PID, p.ProcStart, p.Exe}}
		return IdentityVerified
	}
	for _, ki := range known {
		if ki.pid == p.PID && ki.procStart.Equal(p.ProcStart) {
			return IdentityVerified
		}
	}
	if p.Exe != "" {
		for _, ki := range known {
			if ki.exe == p.Exe {
				if len(known) < maxBoundPerService {
					b.svcs[k] = append(known, boundInstance{p.PID, p.ProcStart, p.Exe})
				}
				return IdentityVerified
			}
		}
	}
	return IdentityAsserted
}

// ExeBase is the executable's file name for event fields.
func ExeBase(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

// IsLoopbackAddr reports whether addr is a loopback IP literal (or a unix path).
func IsLoopbackAddr(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
