package prevention

// protect.go - what the console needs to show that protection works:
//
//	Status        reported in every health heartbeat: the modes in force, the list the agent holds and how
//	              old it is, whether the kernel block is loaded, and 24-hour counters of what was checked,
//	              matched and stopped.
//	scan          a response action: hash every file under a folder (or the whole disk, without system
//	              folders) and check it against the list. Matches go through the normal path (quarantine in
//	              enforce, report in audit); a prevention_scan event summarises the run, with the
//	              executables found so the server can look up their reputation.
//	test_protection  a response action: put a one-off harmless test hash on the list for ten minutes, then
//	              write a file with that content into a watched folder. The file watcher has to find it,
//	              like any download; the resulting prevention event (ioc_source obsidianwatch-test) is the
//	              proof, and the server shows Pass or Fail.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"obsidianwatch/linux-agent/internal/response"
	"obsidianwatch/linux-agent/pkg/schema"
)

// testWriteDelay: one file-watcher pass, so the watcher has the test hash before the file appears.
var testWriteDelay = fileScanEvery + 2*time.Second

// ScanEventType is the summary event of a scan.
const ScanEventType schema.EventType = "prevention_scan"

// TestSource marks the indicator of a protection test (the server raises no alert for it).
const TestSource = "obsidianwatch-test"

// Counter names in Status.
const (
	cFiles = iota
	cProcesses
	cConnections
	cDNS
	cMatched
	cStopped
	nCounters
)

var counterNames = [nCounters]string{"files_checked", "programs_checked", "connections_checked", "dns_checked", "threats_matched", "threats_stopped"}

// hourly keeps 24 one-hour buckets per counter.
type hourly struct {
	mu    sync.Mutex
	hour  int64
	slots [24][nCounters]int64
}

func (h *hourly) add(c int, n int64) {
	now := time.Now().Unix() / 3600
	h.mu.Lock()
	h.roll(now)
	h.slots[now%24][c] += n
	h.mu.Unlock()
}

func (h *hourly) roll(now int64) {
	if h.hour == 0 {
		h.hour = now
	}
	for h.hour < now {
		h.hour++
		h.slots[h.hour%24] = [nCounters]int64{}
		if now-h.hour > 24 {
			h.slots = [24][nCounters]int64{}
			h.hour = now
		}
	}
}

func (h *hourly) totals() map[string]int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.roll(time.Now().Unix() / 3600)
	out := map[string]int64{}
	for _, s := range h.slots {
		for i, v := range s {
			out[counterNames[i]] += v
		}
	}
	return out
}

// protectState is the engine's protection bookkeeping (kept off the Engine struct literal so the three
// agents' copies of engine.go stay unchanged).
type protectState struct {
	stats      hourly
	listAt     atomic.Int64 // unix time the current list arrived
	lastThreat atomic.Int64
	scanning   atomic.Bool
	lastScan   atomic.Value // map[string]any
	mu         sync.Mutex
	tests      map[string]Entry // test hashes (sha256 -> entry)
	lastTest   map[string]any
}

var protectOf sync.Map // *Engine -> *protectState

func (e *Engine) ps() *protectState {
	if v, ok := protectOf.Load(e); ok {
		return v.(*protectState)
	}
	v, _ := protectOf.LoadOrStore(e, &protectState{tests: map[string]Entry{}})
	return v.(*protectState)
}

func (e *Engine) count(c int) { e.ps().stats.add(c, 1) }

// noteList records that a new list was applied.
func (e *Engine) noteList() { e.ps().listAt.Store(time.Now().Unix()) }

// noteOutcome counts a match and, when the threat was stopped, a stop.
func (e *Engine) noteOutcome(action string, testHit bool) {
	if testHit {
		return
	}
	p := e.ps()
	p.stats.add(cMatched, 1)
	p.lastThreat.Store(time.Now().Unix())
	switch action {
	case "blocked", "ip_blocked", "killed", "quarantined", "killed+quarantined":
		p.stats.add(cStopped, 1)
	}
}

// lookupTest finds a protection-test hash.
func (e *Engine) lookupTest(sum string) (Entry, bool) {
	p := e.ps()
	p.mu.Lock()
	defer p.mu.Unlock()
	x, ok := p.tests[strings.ToLower(sum)]
	return x, ok && x.Until > time.Now().Unix()
}

func (e *Engine) hasTests() bool {
	p := e.ps()
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.tests) > 0
}

// Status is the protection block of the health heartbeat.
func (e *Engine) Status() map[string]any {
	ips, hashes, domains, version := e.Counts()
	p := e.ps()
	e.mu.RLock()
	modes := map[string]string{"ip": e.modes["ip"], "hash": e.modes["hash"], "domain": e.modes["domain"]}
	extra := len(e.watchDirs)
	e.mu.RUnlock()
	st := map[string]any{
		"modes": modes, "list_version": version,
		"list_counts":     map[string]int{"ips": ips, "hashes": hashes, "domains": domains},
		"kernel_block":    e.kernel != nil,
		"watched_folders": len(defaultWatchDirs()) + extra,
		"counters_24h":    p.stats.totals(),
		"scanning":        p.scanning.Load(),
	}
	if t := p.listAt.Load(); t > 0 {
		st["list_received"] = time.Unix(t, 0).UTC()
	}
	if t := p.lastThreat.Load(); t > 0 {
		st["last_threat"] = time.Unix(t, 0).UTC()
	}
	if v, ok := p.lastScan.Load().(map[string]any); ok {
		st["last_scan"] = v
	}
	p.mu.Lock()
	if p.lastTest != nil {
		st["last_test"] = p.lastTest
	}
	p.mu.Unlock()
	return st
}

// RegisterActions adds scan and test_protection to the response handler.
func (e *Engine) RegisterActions(h interface {
	Register(name string, f func(context.Context, response.Params) response.Result)
}) {
	h.Register("scan", e.scanAction)
	h.Register("test_protection", e.testAction)
}

// ---- scan -----------------------------------------------------------------------------------------------

const (
	scanMaxFiles   = 500000
	scanMaxTime    = 2 * time.Hour
	scanMaxExecs   = 2000
	scanThrottleN  = 200
	scanThrottleMs = 10
)

// skipWhole: folders a whole-disk scan leaves out (virtual file systems and the operating system).
func skipWhole(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	for _, pre := range []string{"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/var/lib/containerd",
		"/system", "/private/var/vm", "/library/apple", "c:/windows", "c:/$recycle.bin", "c:/system volume information"} {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return systemPath(path)
}

func wholeRoots() []string {
	if runtime.GOOS != "windows" {
		return []string{"/"}
	}
	var out []string
	for c := 'C'; c <= 'Z'; c++ {
		r := string(c) + `:\`
		if st, err := os.Stat(r); err == nil && st.IsDir() {
			out = append(out, r)
		}
	}
	return out
}

func (e *Engine) scanAction(_ context.Context, p response.Params) response.Result {
	whole := p.Kind == "whole"
	var roots []string
	if whole {
		roots = wholeRoots()
	} else {
		root := filepath.Clean(strings.TrimSpace(p.Path))
		if root == "" || root == "." || !filepath.IsAbs(root) {
			return response.Result{Message: "give an absolute folder path, or choose the whole disk"}
		}
		st, err := os.Stat(root)
		if err != nil || !st.IsDir() {
			return response.Result{Message: "folder not found: " + root}
		}
		roots = []string{root}
	}
	ps := e.ps()
	if !ps.scanning.CompareAndSwap(false, true) {
		return response.Result{Message: "a scan is already running on this host"}
	}
	id := newID()
	go func() {
		defer ps.scanning.Store(false)
		e.runScan(id, roots, whole)
	}()
	return response.Result{OK: true, Message: "scan started", Data: map[string]any{"scan_id": id, "roots": roots}}
}

func looksExecutable(path string, mode fs.FileMode) bool {
	if mode&0o111 != 0 && runtime.GOOS != "windows" {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jar", ".dylib", ".so", ".app", ".pkg", ".dmg", ".elf", ".bin", ".sh":
		return true
	}
	return false
}

func (e *Engine) runScan(id string, roots []string, whole bool) {
	start := time.Now()
	deadline := start.Add(scanMaxTime)
	var files, matched, skipped, tooLarge int
	execs := []map[string]string{}
	stopped := ""
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				skipped++
				return nil
			}
			if files >= scanMaxFiles || time.Now().After(deadline) {
				if stopped == "" {
					stopped = "limit reached"
				}
				return fs.SkipAll
			}
			if d.IsDir() {
				if whole && path != root && skipWhole(path) {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				skipped++
				return nil
			}
			if info.Size() == 0 {
				return nil
			}
			if info.Size() > fileMaxBytes {
				tooLarge++
				return nil
			}
			sum := e.cachedHash(path)
			if sum == "" {
				skipped++
				return nil
			}
			files++
			e.count(cFiles)
			if _, ok := e.lookupHash(sum); ok {
				matched++
				e.fileMatch(path, sum, "scan")
			} else if len(execs) < scanMaxExecs && looksExecutable(path, info.Mode()) {
				execs = append(execs, map[string]string{"sha256": sum, "path": path})
			}
			if files%scanThrottleN == 0 {
				time.Sleep(scanThrottleMs * time.Millisecond) // stay in the background
			}
			return nil
		})
	}
	sum := map[string]any{"scan_id": id, "roots": roots, "whole_disk": whole, "files_scanned": files,
		"threats_found": matched, "unreadable": skipped, "too_large": tooLarge,
		"duration_s": int(time.Since(start).Seconds()), "finished": time.Now().UTC(), "mode": e.Mode("hash")}
	if stopped != "" {
		sum["stopped"] = stopped
	}
	e.ps().lastScan.Store(sum)
	raw := map[string]any{}
	for k, v := range sum {
		raw[k] = v
	}
	raw["executables"] = execs
	b, _ := json.Marshal(raw)
	sev := schema.SeverityInfo
	if matched > 0 {
		sev = schema.SeverityHigh
	}
	ev := schema.Event{ID: newID(), Time: time.Now().UTC(), AgentID: e.agentID, Host: e.host, OS: e.osName,
		EventType: ScanEventType, Severity: sev, Source: "prevention", Raw: b}
	if e.out != nil {
		select {
		case e.out <- ev:
		case <-time.After(30 * time.Second):
			e.logger.Warn("prevention: scan summary dropped (pipeline full)", "scan", id)
		}
	}
	e.logger.Info("prevention: scan finished", "scan", id, "files", files, "threats", matched, "seconds", int(time.Since(start).Seconds()))
}

// ---- protection test ------------------------------------------------------------------------------------

// testDir picks a watched folder the agent can write to, preferring temporary folders.
func (e *Engine) testDir() string {
	e.mu.RLock()
	dirs := append(defaultWatchDirs(), e.watchDirs...)
	e.mu.RUnlock()
	try := func(d string) bool {
		st, err := os.Stat(d)
		if err != nil || !st.IsDir() {
			return false
		}
		f, err := os.CreateTemp(d, ".ow-probe-*")
		if err != nil {
			return false
		}
		n := f.Name()
		f.Close()
		os.Remove(n)
		return true
	}
	for _, d := range dirs {
		l := strings.ToLower(d)
		if (strings.Contains(l, "tmp") || strings.Contains(l, "temp")) && !strings.Contains(d, "*") && try(d) {
			return d
		}
	}
	for _, d := range dirs {
		if !strings.Contains(d, "*") && try(d) {
			return d
		}
	}
	return ""
}

func (e *Engine) testAction(_ context.Context, p response.Params) response.Result {
	token := strings.TrimSpace(p.Match)
	if len(token) < 16 || len(token) > 128 {
		return response.Result{Message: "missing test token"}
	}
	if e.Mode("hash") == Off {
		return response.Result{Message: "file protection is off on this host, so the test cannot pass: set files to audit or enforce under Endpoint → Prevention"}
	}
	dir := e.testDir()
	if dir == "" {
		return response.Result{Message: "no watched folder is writable on this host"}
	}
	content := "ObsidianWatch protection test. This file is harmless; the agent should quarantine or report it. " + token + "\n"
	h := sha256.Sum256([]byte(content))
	sum := hex.EncodeToString(h[:])
	ps := e.ps()
	ps.mu.Lock()
	for k, x := range ps.tests { // forget old tests
		if x.Until <= time.Now().Unix() {
			delete(ps.tests, k)
		}
	}
	ps.tests[sum] = Entry{V: sum, Until: time.Now().Add(10 * time.Minute).Unix(), Src: TestSource, Conf: 100, Name: "ObsidianWatch protection test"}
	ps.lastTest = map[string]any{"sha256": sum, "started": time.Now().UTC(), "folder": dir}
	ps.mu.Unlock()
	path := filepath.Join(dir, "obsidianwatch-protection-test-"+sum[:12]+".txt")
	go func() {
		// Let the watcher make at least one pass with the test hash on the list first: its first pass only
		// records what already exists.
		time.Sleep(testWriteDelay)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			e.logger.Warn("prevention: protection test file not written", "path", path, "err", err)
			return
		}
		// Remove the file if nothing acted on it (audit mode) once the test is over.
		time.Sleep(3 * time.Minute)
		if f, err := os.Open(path); err == nil {
			b, _ := io.ReadAll(io.LimitReader(f, 1024))
			f.Close()
			if string(b) == content {
				os.Remove(path)
			}
		}
	}()
	return response.Result{OK: true, Message: "test file will be written to " + path,
		Data: map[string]any{"sha256": sum, "path": path, "folder": dir}}
}
