// Package ebpf is the host runtime sensor of Application Monitoring (spec section 8).
//
// It observes the processes, network connections and file accesses of the services on a host and
// emits them as ordinary process / network / file events into the agent's NORMAL event channel
// (enrichment, normaliser, own-activity filter, rate limiter), each carrying pid and ppid and the
// raw.proc block that the Application rules read (docs/app/platform-guide.md).
//
// Three tiers, best first; "auto" takes the best one that works on the host:
//
//	ebpf      kernel programs (build tag `ebpf`, needs github.com/cilium/ebpf and a compiled object)
//	procevent netlink proc connector for exec / uid changes, /proc polling for connections,
//	          fanotify marks for watched files. Needs root; no library, no kernel objects.
//	poll      /proc polling only. Works unprivileged inside containers; short-lived processes
//	          (shorter than the poll interval) can be missed.
//
// The sensor only reports what concerns a service: a process whose lineage contains a known service
// process. Everything else is dropped at the source, which keeps volume and privacy exposure small.
package ebpf

import (
	"errors"
	"log/slog"
	"time"

	"obsidianwatch/macos-agent/internal/otel"
	"obsidianwatch/macos-agent/pkg/schema"
)

// Sensor modes.
const (
	ModeAuto      = "auto"
	ModeEBPF      = "ebpf"
	ModeProcEvent = "procevent"
	ModePoll      = "poll"
)

// ErrUnsupported is returned where the sensor cannot run at all (non-Linux).
var ErrUnsupported = errors.New("host runtime sensor is not supported on this platform")

// Options configures the sensor. Emit is required and must be the agent's normal event channel.
type Options struct {
	AgentID  string
	Hostname string
	OS       string

	Mode         string        // auto | ebpf | procevent | poll
	PollInterval time.Duration // default 2s
	Environment  string        // deployment environment given to discovered services (default "default")
	WatchDirs    []string      // extra web/upload directories to watch for file creation
	SecretFiles  []string      // extra credential files to watch for reads

	// Emit hands an event to the agent's normal event channel; it must not block.
	Emit func(schema.Event) bool
	// ServicePIDs returns the pids of services known from OpenTelemetry (identity-bound).
	ServicePIDs func() []int
	// Discovered reports host-discovered service instances (Tier 0).
	Discovered func([]otel.BatchInstance)
	Logger     *slog.Logger

	procRoot      string // tests point this at a fixture; empty means /proc
	allowLoopback bool   // tests connect over loopback
}

func (o *Options) defaults() {
	if o.Mode == "" {
		o.Mode = ModeAuto
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 2 * time.Second
	}
	if o.Environment == "" {
		o.Environment = "default"
	}
	if o.OS == "" {
		o.OS = "linux"
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// Stats are counters for health output.
type Stats struct {
	Process, Network, File, Priv, Dropped int64
	Services                              int
	Mode                                  string
}
