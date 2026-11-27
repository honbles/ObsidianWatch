// Package prevention matches the host's own activity against the indicator
// set the server publishes (IPs, SHA-256 hashes, domains) and, per type,
// reports matches (audit) or acts on them (enforce):
//
//	IP      Linux: an eBPF program on connect() and UDP sendmsg refuses the
//	        connection before a packet leaves (fails open: it goes away with
//	        the agent). Elsewhere, and when that cannot load: the matching
//	        connection's IP is blocked with the block_ip response action.
//	hash    a new file in a watched folder is quarantined; a running process
//	        whose image matches is killed and its file quarantined.
//	domain  a DNS answer for a listed domain gets its IPs blocked, so later
//	        connections fail; the lookup itself is not prevented.
//
// The agent writes no policy to the host: the set lives in the agent's data
// directory, each entry has its own expiry (removal works offline), and the
// only host changes are the ones the existing response actions make.
package prevention

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"obsidianwatch/agent/internal/response"
	"obsidianwatch/agent/pkg/schema"
)

// Modes per indicator type.
const (
	Off     = "off"
	Audit   = "audit"
	Enforce = "enforce"
)

// Entry is one indicator with its expiry.
type Entry struct {
	V     string `json:"v"`
	Until int64  `json:"until"`
	Src   string `json:"src"`
	Conf  int    `json:"conf,omitempty"`
	Name  string `json:"name,omitempty"`
}

// Set is what the server publishes.
type Set struct {
	Version string  `json:"version"`
	IPs     []Entry `json:"ips"`
	Hashes  []Entry `json:"hashes"`
	Domains []Entry `json:"domains"`
}

// Responder runs response actions (response.Handler satisfies it).
type Responder interface {
	Handle(ctx context.Context, action string, p response.Params) response.Result
}

// KernelBlocker refuses connections in the kernel (Linux eBPF); nil elsewhere.
type KernelBlocker interface {
	Replace(ips []netip.Addr) error
	Close()
}

// Engine holds the set and does the matching. Inspect is called for every
// event on the agent's pipeline and only does map lookups; actions run on
// their own goroutine.
type Engine struct {
	mu        sync.RWMutex
	ips       map[netip.Addr]Entry
	hashes    map[string]Entry
	domains   map[string]Entry
	version   string
	modes     map[string]string
	watchDirs []string

	dir        string // state directory
	out        chan<- schema.Event
	resp       Responder
	kernel     KernelBlocker
	protected  func(netip.Addr) bool
	agentID    string
	host       string
	osName     string
	logger     *slog.Logger
	acts       chan func()
	recent     sync.Map                 // dedup key -> time (one report per indicator, host and process per 10 min)
	owned      map[netip.Addr]time.Time // IPs this engine blocked with block_ip, and until when
	hashCache  sync.Map                 // path|mtime|size -> sha256
	hashCacheN atomic.Int64
}

// Options configure an Engine.
type Options struct {
	Dir       string
	Out       chan<- schema.Event
	Responder Responder
	Protected func(netip.Addr) bool // the manager, resolvers, gateway: never blocked
	AgentID   string
	Host      string
	OS        string
	Logger    *slog.Logger
}

func New(o Options) *Engine {
	e := &Engine{
		ips: map[netip.Addr]Entry{}, hashes: map[string]Entry{}, domains: map[string]Entry{},
		modes: map[string]string{"ip": Off, "hash": Off, "domain": Off},
		dir:   o.Dir, out: o.Out, resp: o.Responder, protected: o.Protected,
		agentID: o.AgentID, host: o.Host, osName: o.OS, logger: o.Logger,
		acts: make(chan func(), 256), owned: map[netip.Addr]time.Time{},
	}
	if e.logger == nil {
		e.logger = slog.Default()
	}
	if e.protected == nil {
		e.protected = func(netip.Addr) bool { return false }
	}
	e.load()
	return e
}

func (e *Engine) statePath() string { return filepath.Join(e.dir, "prevention.json") }

type state struct {
	Set   Set                  `json:"set"`
	Modes map[string]string    `json:"modes"`
	Dirs  []string             `json:"dirs"`
	Owned map[string]time.Time `json:"owned_blocks"`
}

// load restores the last set, so enforcement works with the server down.
func (e *Engine) load() {
	b, err := os.ReadFile(e.statePath())
	if err != nil {
		return
	}
	var st state
	if json.Unmarshal(b, &st) != nil {
		return
	}
	e.apply(st.Set, st.Modes, st.Dirs)
	for k, v := range st.Owned {
		if a, err := netip.ParseAddr(k); err == nil {
			e.owned[a] = v
		}
	}
}

func (e *Engine) save() {
	e.mu.RLock()
	st := state{Set: e.snapshotLocked(), Modes: e.modes, Dirs: e.watchDirs, Owned: map[string]time.Time{}}
	for a, t := range e.owned {
		st.Owned[a.String()] = t
	}
	e.mu.RUnlock()
	b, _ := json.Marshal(st)
	_ = os.MkdirAll(e.dir, 0o700)
	tmp := e.statePath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, e.statePath())
	}
}

func (e *Engine) snapshotLocked() Set {
	s := Set{Version: e.version}
	for a, x := range e.ips {
		x.V = a.String()
		s.IPs = append(s.IPs, x)
	}
	for _, x := range e.hashes {
		s.Hashes = append(s.Hashes, x)
	}
	for _, x := range e.domains {
		s.Domains = append(s.Domains, x)
	}
	return s
}

// apply installs a set and modes. Entries already expired are skipped.
func (e *Engine) apply(set Set, modes map[string]string, dirs []string) {
	now := time.Now().Unix()
	ips := map[netip.Addr]Entry{}
	for _, x := range set.IPs {
		if a, err := netip.ParseAddr(x.V); err == nil && x.Until > now && !e.protected(a.Unmap()) {
			ips[a.Unmap()] = x
		}
	}
	hashes := map[string]Entry{}
	for _, x := range set.Hashes {
		if len(x.V) == 64 && x.Until > now {
			hashes[strings.ToLower(x.V)] = x
		}
	}
	domains := map[string]Entry{}
	for _, x := range set.Domains {
		if x.V != "" && x.Until > now {
			domains[strings.TrimSuffix(strings.ToLower(x.V), ".")] = x
		}
	}
	m := map[string]string{"ip": Off, "hash": Off, "domain": Off}
	for k := range m {
		switch modes[k] {
		case Audit, Enforce:
			m[k] = modes[k]
		}
	}
	e.mu.Lock()
	e.ips, e.hashes, e.domains, e.version, e.modes, e.watchDirs = ips, hashes, domains, set.Version, m, dirs
	e.mu.Unlock()
	e.noteList()
	e.syncKernel()
}

// syncKernel loads the IP set into the kernel blocker when IP mode is enforce
// (and empties it otherwise).
func (e *Engine) syncKernel() {
	if e.kernel == nil {
		return
	}
	e.mu.RLock()
	var list []netip.Addr
	if e.modes["ip"] == Enforce {
		list = make([]netip.Addr, 0, len(e.ips))
		for a := range e.ips {
			list = append(list, a)
		}
	}
	e.mu.RUnlock()
	if err := e.kernel.Replace(list); err != nil {
		e.logger.Warn("prevention: kernel block list update failed", "err", err)
	}
}

// SetKernelBlocker installs the kernel tier (Linux).
func (e *Engine) SetKernelBlocker(k KernelBlocker) {
	e.kernel = k
	e.syncKernel()
}

// Mode returns the current mode for an indicator type.
func (e *Engine) Mode(kind string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.modes[kind]
}

// Counts reports how many indicators of each type are loaded.
func (e *Engine) Counts() (ips, hashes, domains int, version string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.ips), len(e.hashes), len(e.domains), e.version
}

func (e *Engine) lookupIP(s string) (Entry, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return Entry{}, false
	}
	a = a.Unmap()
	e.mu.RLock()
	x, ok := e.ips[a]
	e.mu.RUnlock()
	if !ok || x.Until <= time.Now().Unix() || e.protected(a) {
		return Entry{}, false
	}
	return x, true
}

func (e *Engine) lookupHash(h string) (Entry, bool) {
	e.mu.RLock()
	x, ok := e.hashes[strings.ToLower(h)]
	e.mu.RUnlock()
	if !ok || x.Until <= time.Now().Unix() {
		return e.lookupTest(h) // a protection test (protect.go)
	}
	return x, true
}

// lookupDomain matches the name or any parent domain (a listed
// evil.example also covers a.b.evil.example).
func (e *Engine) lookupDomain(name string) (Entry, string, bool) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	e.mu.RLock()
	defer e.mu.RUnlock()
	for n != "" && strings.Contains(n, ".") {
		if x, ok := e.domains[n]; ok && x.Until > time.Now().Unix() {
			return x, n, true
		}
		i := strings.IndexByte(n, '.')
		n = n[i+1:]
	}
	return Entry{}, "", false
}

// Run polls nothing itself (see Poller); it runs actions, expires entries
// and owned blocks, and scans watched folders for new files.
func (e *Engine) Run(ctx context.Context) {
	go e.watchFiles(ctx)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			if e.kernel != nil {
				e.kernel.Close()
			}
			return
		case f := <-e.acts:
			f()
		case <-tick.C:
			e.expire(ctx)
		}
	}
}

// expire drops entries past their date and lifts block_ip blocks this
// engine made once they lapse.
func (e *Engine) expire(ctx context.Context) {
	now := time.Now()
	changed := false
	e.mu.Lock()
	for a, x := range e.ips {
		if x.Until <= now.Unix() {
			delete(e.ips, a)
			changed = true
		}
	}
	for h, x := range e.hashes {
		if x.Until <= now.Unix() {
			delete(e.hashes, h)
		}
	}
	for d, x := range e.domains {
		if x.Until <= now.Unix() {
			delete(e.domains, d)
		}
	}
	var lift []netip.Addr
	for a, until := range e.owned {
		if now.After(until) {
			lift = append(lift, a)
			delete(e.owned, a)
		}
	}
	e.mu.Unlock()
	for _, a := range lift {
		if e.resp != nil {
			e.resp.Handle(ctx, "unblock_ip", response.Params{IP: a.String()})
		}
	}
	if changed {
		e.syncKernel()
	}
	if changed || len(lift) > 0 {
		e.save()
	}
}

func (e *Engine) do(f func()) {
	select {
	case e.acts <- f:
	default:
		e.logger.Warn("prevention: action queue full, action skipped")
	}
}

// seen reports whether this report was made in the last 10 minutes.
func (e *Engine) seen(key string) bool {
	now := time.Now()
	if t, ok := e.recent.Load(key); ok && now.Sub(t.(time.Time)) < 10*time.Minute {
		return true
	}
	e.recent.Store(key, now)
	return false
}
