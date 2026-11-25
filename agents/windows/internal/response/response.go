// Package response executes one-click response actions sent by the management
// server over the agent tunnel: network isolation, process kill, file
// quarantine and fleet hunt queries.
//
// Isolation keeps ONLY the ObsidianWatch backend and management addresses
// reachable (plus loopback and DHCP so the host keeps its lease); every other
// host and the internet are blocked in both directions. The state is persisted
// and re-applied on agent start, so a reboot does not release a host.
package response

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

// Params is the union of all action parameters (unused fields are ignored).
type Params struct {
	PID        int    `json:"pid,omitempty"`
	Image      string `json:"image,omitempty"` // expected exe path/name: guards against PID reuse
	Tree       bool   `json:"tree,omitempty"`  // kill: include child processes
	Path       string `json:"path,omitempty"`
	ID         string `json:"id,omitempty"`   // quarantine id (restore)
	Kind       string `json:"kind,omitempty"` // fleet query kind
	Match      string `json:"match,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Hours      int    `json:"hours,omitempty"`       // recent_files window
	TTLMinutes int    `json:"ttl_minutes,omitempty"` // isolate: auto-release after N minutes (0 = until released)
	// NoBlockPage (isolate): do not redirect browsing to the "contact your
	// administrator" page.
	NoBlockPage bool   `json:"no_block_page,omitempty"`
	SHA256      string `json:"sha256,omitempty"` // delete_file: only delete if the content still matches
	IP          string `json:"ip,omitempty"`     // block_ip / unblock_ip
	User        string `json:"user,omitempty"`   // disable_user / enable_user
}

// Table is a tabular answer to a fleet query.
type Table struct {
	Columns   []string   `json:"columns"`
	Rows      [][]string `json:"rows"`
	Truncated bool       `json:"truncated,omitempty"`
}

// Result is what goes back to the server.
type Result struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

// State is reported to the server on tunnel connect and after every action.
type State struct {
	Isolated    bool      `json:"isolated"`
	Since       time.Time `json:"since,omitempty"`
	Expires     time.Time `json:"expires,omitempty"`
	Quarantined int       `json:"quarantined"`
}

type isoState struct {
	Isolated bool      `json:"isolated"`
	Since    time.Time `json:"since"`
	Expires  time.Time `json:"expires,omitempty"`
	Allow    []string  `json:"allow"`           // union of every address ever resolved for the backend/management hosts
	Saved    string    `json:"saved,omitempty"` // platform-specific data needed to undo (e.g. firewall profile states)
	// Block page (blockpage.go): server names' addresses for the DNS sink,
	// whether the page is on, and platform data to undo the DNS change.
	HostIPs    map[string][]string `json:"host_ips,omitempty"`
	BlockPage  bool                `json:"block_page,omitempty"`
	BlockSaved string              `json:"block_saved,omitempty"`
}

// Handler runs response actions.
type Handler struct {
	dir    string
	hosts  []string // hostnames/IPs of the backend + management URLs
	logger *slog.Logger
	mu     sync.Mutex

	cbMu     sync.Mutex
	onChange func() // told when isolation ends on its own (ttl expiry)

	bp blockPage
}

// SetOnChange registers a callback fired when the state changes without a
// command (an isolation window elapsing), so the server can be told.
func (h *Handler) SetOnChange(f func()) {
	h.cbMu.Lock()
	h.onChange = f
	h.cbMu.Unlock()
}

func (h *Handler) notify() {
	h.cbMu.Lock()
	f := h.onChange
	h.cbMu.Unlock()
	if f != nil {
		go f()
	}
}

// DefaultDir is where state and the quarantine vault live.
func DefaultDir() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\ObsidianWatch`
	}
	return "/var/lib/obsidianwatch"
}

// New builds a handler. urls are the backend and management URLs the agent
// talks to; their hosts are the isolation allow-list.
func New(dir string, urls []string, logger *slog.Logger) *Handler {
	if dir == "" {
		dir = DefaultDir()
	}
	var hosts []string
	seen := map[string]bool{}
	for _, u := range urls {
		pu, err := url.Parse(u)
		if err != nil || pu.Hostname() == "" {
			continue
		}
		if h := pu.Hostname(); !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return &Handler{dir: dir, hosts: hosts, logger: logger}
}

func (h *Handler) statePath() string { return filepath.Join(h.dir, "response.json") }
func (h *Handler) vaultDir() string  { return filepath.Join(h.dir, "quarantine") }

func (h *Handler) loadIso() isoState {
	var s isoState
	if b, err := os.ReadFile(h.statePath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func (h *Handler) saveIso(s isoState) error {
	if err := os.MkdirAll(h.dir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(s)
	tmp := h.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.statePath())
}

// State returns the current response state.
func (h *Handler) State() State {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.loadIso()
	return State{Isolated: s.Isolated, Since: s.Since, Expires: s.Expires, Quarantined: len(h.listQuarantine())}
}

// resolveAllow returns the IPs of the backend/management hosts, unioned with
// those remembered from earlier (DNS is blocked while isolated, so the cache
// is what keeps a name-based deployment reachable).
func (h *Handler) resolveAllow(cached []string) ([]netip.Addr, error) {
	set := map[netip.Addr]bool{}
	for _, c := range cached {
		if a, err := netip.ParseAddr(c); err == nil {
			set[a.Unmap()] = true
		}
	}
	for _, host := range h.hosts {
		if a, err := netip.ParseAddr(host); err == nil {
			set[a.Unmap()] = true
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		cancel()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip.IP); ok {
				set[a.Unmap()] = true
			}
		}
	}
	out := make([]netip.Addr, 0, len(set))
	for a := range set {
		if a.IsLoopback() || a.IsUnspecified() {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	if len(out) == 0 {
		return nil, fmt.Errorf("cannot resolve the ObsidianWatch backend/management address; refusing to isolate (the host would lose contact with the server)")
	}
	return out, nil
}

func addrStrings(a []netip.Addr) []string {
	s := make([]string, len(a))
	for i, x := range a {
		s[i] = x.String()
	}
	return s
}

// Handle runs one action.
func (h *Handler) Handle(ctx context.Context, action string, p Params) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			res = Result{Message: fmt.Sprintf("action %q panicked: %v", action, r)}
		}
	}()
	switch action {
	case "isolate":
		return h.isolate(p)
	case "release":
		return h.release()
	case "kill_process":
		return h.kill(p)
	case "quarantine_file":
		return h.quarantine(p.Path)
	case "restore_file":
		return h.restore(p.ID)
	case "block_process":
		return h.block(ctx, p)
	case "unblock_process":
		return h.unblock(p)
	case "list_blocked":
		return h.listBlocked()
	case "list_quarantine":
		h.mu.Lock()
		defer h.mu.Unlock()
		return Result{OK: true, Data: h.listQuarantine()}
	case "query":
		return h.query(ctx, p)
	case "delete_file":
		return h.deleteFile(p)
	case "delete_quarantined":
		return h.deleteQuarantined(p.ID)
	case "file_info":
		return h.fileInfo(p.Path, false)
	case "collect_file":
		return h.fileInfo(p.Path, true)
	case "block_ip":
		return h.blockIP(p.IP)
	case "unblock_ip":
		return h.unblockIP(p.IP)
	case "list_blocked_ips":
		h.mu.Lock()
		defer h.mu.Unlock()
		return Result{OK: true, Data: h.loadIPBlocks()}
	case "disable_user":
		return h.disableUserAction(p.User)
	case "enable_user":
		return h.enableUserAction(p.User)
	}
	return Result{Message: "unknown action " + action}
}

func (h *Handler) isolate(p Params) Result {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.loadIso()
	allow, err := h.resolveAllow(st.Allow)
	if err != nil {
		return Result{Message: err.Error()}
	}
	// Resolve the server names now, while DNS still works: the block page's
	// DNS sink answers them with these addresses.
	exempt, keep := exemptFor(h.hosts, st.HostIPs, lookupHost)
	st.HostIPs = keep
	saved, err := applyIsolation(allow, st.Saved)
	if err != nil {
		return Result{Message: "isolation failed: " + err.Error()}
	}
	if !st.Isolated {
		st.Since = time.Now().UTC()
	}
	st.Isolated, st.Allow, st.Saved = true, addrStrings(allow), saved
	note := ""
	if !p.NoBlockPage {
		st.BlockPage = true
		note = blockPageErr(h.startBlockPage(exempt, &st))
	} else if st.BlockPage {
		h.stopBlockPage(&st)
		st.BlockPage = false
	}
	st.Expires = time.Time{}
	if p.TTLMinutes > 0 {
		st.Expires = time.Now().UTC().Add(time.Duration(p.TTLMinutes) * time.Minute)
	}
	if err := h.saveIso(st); err != nil {
		h.logger.Warn("response: cannot persist isolation state", "err", err)
	}
	h.logger.Warn("response: host ISOLATED", "allow", st.Allow, "block_page", st.BlockPage)
	msg := fmt.Sprintf("host isolated; only %v is reachable", st.Allow)
	if st.BlockPage {
		msg += "; browsing shows the \"contact your administrator\" page" + note
	}
	return Result{OK: true, Message: msg, Data: h.stateLocked()}
}

func (h *Handler) release() Result {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.loadIso()
	h.stopBlockPage(&st)
	if err := removeIsolation(st.Saved); err != nil {
		return Result{Message: "release failed: " + err.Error()}
	}
	st.Isolated, st.Expires, st.Saved, st.BlockPage = false, time.Time{}, "", false
	_ = h.saveIso(st)
	h.logger.Warn("response: host RELEASED from isolation")
	return Result{OK: true, Message: "isolation removed; normal network access restored", Data: h.stateLocked()}
}

// startBlockPage brings up the block page and, where the platform needs it,
// points DNS at its sink. Caller holds h.mu and saves st.
func (h *Handler) startBlockPage(exempt map[string][]netip.Addr, st *isoState) error {
	httpAddr, dnsAddr := blockPageAddrs()
	host, _ := os.Hostname()
	dnsOK, err := h.bp.start(httpAddr, dnsAddr, exempt, host)
	if dnsOK {
		saved, perr := pointToBlockPage(st.BlockSaved)
		if perr != nil {
			h.logger.Warn("response: cannot point DNS at the block page", "err", perr)
			if err == nil {
				err = perr
			}
		} else {
			st.BlockSaved = saved
		}
	}
	return err
}

func (h *Handler) stopBlockPage(st *isoState) {
	if st.BlockSaved != "" {
		if err := unpointBlockPage(st.BlockSaved); err != nil {
			h.logger.Warn("response: cannot restore DNS settings", "err", err)
		}
		st.BlockSaved = ""
	}
	h.bp.stop()
}

func lookupHost(name string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
}

func (h *Handler) stateLocked() State {
	s := h.loadIso()
	return State{Isolated: s.Isolated, Since: s.Since, Expires: s.Expires, Quarantined: len(h.listQuarantine())}
}

// Restore re-applies isolation after an agent/host restart.
func (h *Handler) Restore() {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.loadIso()
	if !st.Isolated {
		return
	}
	if !st.Expires.IsZero() && time.Now().After(st.Expires) {
		h.stopBlockPage(&st)
		_ = removeIsolation(st.Saved)
		st.Isolated, st.Saved, st.BlockPage = false, "", false
		_ = h.saveIso(st)
		h.logger.Warn("response: isolation window elapsed; host released")
		h.notify()
		return
	}
	allow, err := h.resolveAllow(st.Allow)
	if err != nil {
		h.logger.Error("response: cannot re-apply isolation", "err", err)
		return
	}
	if saved, err := applyIsolation(allow, st.Saved); err != nil {
		h.logger.Error("response: re-apply isolation failed", "err", err)
	} else {
		st.Allow, st.Saved = addrStrings(allow), saved
		if st.BlockPage {
			exempt, keep := exemptFor(h.hosts, st.HostIPs, lookupHost)
			st.HostIPs = keep
			if err := h.startBlockPage(exempt, &st); err != nil {
				h.logger.Warn("response: block page", "err", err)
			}
		}
		_ = h.saveIso(st)
	}
}

// Run keeps isolation correct while the agent lives: it re-applies the rules
// periodically (so a flushed firewall or a changed backend IP self-heals) and
// honours an expiry set with ttl_minutes.
func (h *Handler) Run(ctx context.Context) {
	go h.enforceLoop(ctx)
	h.Restore()
	h.reapplyIPBlocks()
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.Restore()
		}
	}
}
