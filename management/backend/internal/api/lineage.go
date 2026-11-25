package api

// lineage.go - process lineage for detection.
//
// Rules used to see one event at a time: a shell was a shell whether nginx
// or a logged-in admin started it. The engine now keeps a cache of the
// processes it has seen start (by process GUID, with a pid fallback for
// sources without GUIDs such as Security 4688), fills parents it has not
// seen from stored events, and attaches each event's ancestors
// (store.Event.Ancestors, parent first) before rules run. Alerts carry the
// chain so an analyst sees "nginx → php-fpm → sh → curl" without opening
// the graph.

import (
	"context"
	"encoding/json"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

const (
	lineageMaxNodes   = 200000
	lineageMaxDepth   = 8
	lineageNodeTTL    = 7 * 24 * time.Hour
	lineageFetchLimit = 300 // missing parents looked up per pass
	lineageFetchDepth = 3   // rounds of parent lookups per pass
)

type linNode struct {
	pid, ppid    int
	name, image  string
	cmd          string
	guid, parent string
	agent        string
	seen         time.Time
	synthetic    bool // built from a child's parent fields, not its own start event
	// prior is the image this process ran before an exec replaced it (Linux
	// keeps pid and start time, so the GUID is the same): bash -c execs its
	// command in place, and the earlier image is an ancestor of the later.
	prior *linNode
}

type lineage struct {
	mu     sync.Mutex
	byGUID map[string]*linNode  // agent|guid
	byPID  map[string]*linNode  // agent|pid, latest start
	misses map[string]time.Time // agent|guid looked up and not found (do not ask again for an hour)
}

func newLineage() *lineage {
	return &lineage{byGUID: map[string]*linNode{}, byPID: map[string]*linNode{}, misses: map[string]time.Time{}}
}

func lkey(agent, guid string) string { return agent + "|" + guid }

func pkey(agent string, pid int) string { return agent + "|#" + strconv.Itoa(pid) }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// isProcessStart reports whether ev is the start of a process: agent exec
// and start events, Sysmon 1 and Security 4688.
func isProcessStart(ev store.Event) bool {
	if ev.EventType != "process" {
		return false
	}
	if ev.EventID != nil && (*ev.EventID == 4688 || (*ev.EventID == 1 && strings.Contains(strings.ToLower(deref(ev.Channel)), "sysmon"))) {
		return true
	}
	var r struct {
		Action string `json:"action"`
	}
	if len(ev.Raw) > 0 && json.Unmarshal(ev.Raw, &r) == nil {
		switch r.Action {
		case "exec", "start", "process_create":
			return true
		}
	}
	return false
}

// parentHints are the parent fields a start event carries about its parent:
// the Linux agent's parent_exe/parent_name and Sysmon's ParentImage and
// ParentCommandLine.
type parentHints struct {
	ParentExe  string `json:"parent_exe"`
	ParentName string `json:"parent_name"`
	EventData  struct {
		ParentImage       string `json:"ParentImage"`
		ParentCommandLine string `json:"ParentCommandLine"`
		ParentProcessName string `json:"ParentProcessName"`
	} `json:"event_data"`
}

func nodeFromEvent(ev store.Event) *linNode {
	n := &linNode{
		pid: derefInt(ev.PID), ppid: derefInt(ev.PPID),
		name: deref(ev.ProcessName), image: deref(ev.ImagePath), cmd: deref(ev.CommandLine),
		guid: ev.ProcessGUID, parent: ev.ParentProcessGUID, agent: ev.AgentID, seen: ev.Time,
	}
	if n.name == "" && n.image != "" {
		n.name = winBase(n.image)
	}
	return n
}

func parentFromHints(ev store.Event) *linNode {
	var h parentHints
	if len(ev.Raw) == 0 || json.Unmarshal(ev.Raw, &h) != nil {
		return nil
	}
	img := firstNonEmpty(h.ParentExe, h.EventData.ParentImage, h.EventData.ParentProcessName)
	name := firstNonEmpty(h.ParentName, winBase(img))
	if img == "" && name == "" {
		return nil
	}
	return &linNode{
		pid: derefInt(ev.PPID), name: name, image: img, cmd: h.EventData.ParentCommandLine,
		guid: ev.ParentProcessGUID, agent: ev.AgentID, seen: ev.Time, synthetic: true,
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// winBase is the file name of a Windows or Unix path.
func winBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (l *lineage) add(n *linNode) {
	if n.guid != "" {
		if old, ok := l.byGUID[lkey(n.agent, n.guid)]; ok {
			if !old.synthetic && n.synthetic {
				return // a real start event beats a child's description of its parent
			}
			if old.image == n.image && old.cmd == n.cmd {
				return // the same start seen twice
			}
			if !old.synthetic && !n.synthetic && !old.seen.After(n.seen) {
				n.prior = old // exec in place: keep what ran before
				if n.parent == "" {
					n.parent = old.parent
				}
			}
		}
		l.byGUID[lkey(n.agent, n.guid)] = n
		delete(l.misses, lkey(n.agent, n.guid))
	}
	if n.pid > 0 && !n.synthetic {
		l.byPID[pkey(n.agent, n.pid)] = n
	}
}

// parentOf finds n's parent: by GUID when both sides have one, otherwise the
// latest process with the parent pid that started before n.
func (l *lineage) parentOf(n *linNode) *linNode {
	if n.parent != "" {
		if p, ok := l.byGUID[lkey(n.agent, n.parent)]; ok {
			return p
		}
		return nil
	}
	if n.ppid > 0 {
		if p, ok := l.byPID[pkey(n.agent, n.ppid)]; ok && !p.seen.After(n.seen) && p != n {
			return p
		}
	}
	return nil
}

// chain lists n's ancestors, nearest first: the images the same process ran
// before its last exec, then its parent (and the parent's earlier images),
// and so on.
func (l *lineage) chain(n *linNode) []store.ProcAncestor {
	var out []store.ProcAncestor
	seen := map[*linNode]bool{n: true}
	push := func(x *linNode) bool {
		if x == nil || seen[x] || len(out) >= lineageMaxDepth {
			return false
		}
		seen[x] = true
		out = append(out, store.ProcAncestor{PID: x.pid, Name: x.name, Image: x.image, CommandLine: x.cmd, GUID: x.guid})
		return true
	}
	for cur := n; cur != nil && len(out) < lineageMaxDepth; {
		for p := cur.prior; p != nil; p = p.prior {
			if !push(p) {
				break
			}
		}
		next := l.parentOf(cur)
		if !push(next) {
			break
		}
		cur = next
	}
	return out
}

func (l *lineage) evict(now time.Time) {
	if len(l.byGUID)+len(l.byPID) < lineageMaxNodes {
		return
	}
	for k, n := range l.byGUID {
		if now.Sub(n.seen) > 24*time.Hour {
			delete(l.byGUID, k)
		}
	}
	for k, n := range l.byPID {
		if now.Sub(n.seen) > 24*time.Hour {
			delete(l.byPID, k)
		}
	}
	if len(l.byGUID)+len(l.byPID) >= lineageMaxNodes { // still full: start over
		l.byGUID, l.byPID = map[string]*linNode{}, map[string]*linNode{}
	}
	for k, t := range l.misses {
		if now.Sub(t) > time.Hour {
			delete(l.misses, k)
		}
	}
}

// guidFetcher looks up stored events by process GUID (store.DB satisfies it).
type guidFetcher interface {
	EventsByProcessGUIDs(ctx context.Context, agentID string, guids []string, from, to time.Time, limit int) ([]store.Event, error)
}

// observe records the batch's process starts, fetches parents it has not
// seen, and fills Ancestors on every event that names a process.
func (l *lineage) observe(ctx context.Context, db guidFetcher, events []store.Event) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.evict(now)
	for _, ev := range events {
		if !isProcessStart(ev) {
			continue
		}
		l.add(nodeFromEvent(ev))
		if p := parentFromHints(ev); p != nil {
			l.add(p)
		}
	}
	if db != nil {
		l.fetchMissing(ctx, db, events, now)
	}
	for i := range events {
		ev := &events[i]
		if ev.ProcessGUID == "" && derefInt(ev.PID) == 0 {
			continue
		}
		self := nodeFromEvent(*ev)
		if isProcessStart(*ev) && ev.ProcessGUID != "" {
			// Use the cached node for this exec, which knows the images the
			// process ran before it.
			for n := l.byGUID[lkey(ev.AgentID, ev.ProcessGUID)]; n != nil; n = n.prior {
				if n.image == self.image && n.cmd == self.cmd {
					self = n
					break
				}
			}
		} else if !isProcessStart(*ev) {
			// For network, file and other events the process is the actor:
			// its lineage starts with its own parent.
			if ev.ProcessGUID != "" {
				if n, ok := l.byGUID[lkey(ev.AgentID, ev.ProcessGUID)]; ok {
					self = n
				}
			} else if n, ok := l.byPID[pkey(ev.AgentID, derefInt(ev.PID))]; ok {
				self = n
			}
		}
		ev.Ancestors = l.chain(self)
	}
}

func (l *lineage) fetchMissing(ctx context.Context, db guidFetcher, events []store.Event, now time.Time) {
	want := map[string]map[string]bool{} // agent -> guids
	budget := lineageFetchLimit
	need := func(agent, guid string) {
		if guid == "" || budget <= 0 {
			return
		}
		k := lkey(agent, guid)
		if _, ok := l.byGUID[k]; ok {
			return
		}
		if t, ok := l.misses[k]; ok && now.Sub(t) < time.Hour {
			return
		}
		if want[agent] == nil {
			want[agent] = map[string]bool{}
		}
		if !want[agent][guid] {
			want[agent][guid] = true
			budget--
		}
	}
	for _, ev := range events {
		need(ev.AgentID, ev.ParentProcessGUID)
		if !isProcessStart(ev) {
			need(ev.AgentID, ev.ProcessGUID)
		}
	}
	for round := 0; round < lineageFetchDepth && len(want) > 0; round++ {
		next := map[string]map[string]bool{}
		for agent, set := range want {
			guids := make([]string, 0, len(set))
			for g := range set {
				guids = append(guids, g)
			}
			found, err := db.EventsByProcessGUIDs(ctx, agent, guids, now.Add(-lineageNodeTTL), now.Add(time.Minute), 2000)
			if err != nil {
				return
			}
			got := map[string]bool{}
			for _, ev := range found {
				if !isProcessStart(ev) {
					continue
				}
				n := nodeFromEvent(ev)
				l.add(n)
				got[ev.ProcessGUID] = true
				if p := parentFromHints(ev); p != nil {
					l.add(p)
				}
				if ev.ParentProcessGUID != "" {
					if _, ok := l.byGUID[lkey(agent, ev.ParentProcessGUID)]; !ok {
						if next[agent] == nil {
							next[agent] = map[string]bool{}
						}
						next[agent][ev.ParentProcessGUID] = true
					}
				}
			}
			for _, g := range guids {
				if !got[g] {
					l.misses[lkey(agent, g)] = now
				}
			}
		}
		want = next
	}
}

// ── helpers for rules ─────────────────────────────────────────────────────────

// ancestorNames are the lowercase file names of ev's ancestors, parent first.
func ancestorNames(ev store.Event) []string {
	out := make([]string, 0, len(ev.Ancestors))
	for _, a := range ev.Ancestors {
		n := a.Name
		if a.Image != "" {
			n = winBase(a.Image)
		}
		out = append(out, strings.ToLower(n))
	}
	return out
}

// nameMatches compares a process file name with a rule's name: exact, or
// the rule name followed by a version or ".exe" (python3.11, java.exe).
func nameMatches(name, want string) bool {
	if name == want {
		return true
	}
	if strings.HasPrefix(name, want) {
		rest := name[len(want):]
		return rest == ".exe" || strings.Trim(rest, "0123456789.-") == ""
	}
	return false
}

// ancestorIn reports whether any of ev's first depth ancestors is one of names.
func ancestorIn(ev store.Event, depth int, names ...string) bool {
	for i, a := range ancestorNames(ev) {
		if i >= depth {
			break
		}
		for _, n := range names {
			if nameMatches(a, n) {
				return true
			}
		}
	}
	return false
}

// parentIn reports whether ev's direct parent is one of names.
func parentIn(ev store.Event, names ...string) bool { return ancestorIn(ev, 1, names...) }

// processChain renders ev's lineage oldest first, ending with ev's process:
// "systemd → nginx → sh → curl". Empty when no ancestor is known.
func processChain(ev store.Event) string {
	if len(ev.Ancestors) == 0 {
		return ""
	}
	names := ancestorNames(ev)
	parts := make([]string, 0, len(names)+1)
	for i := len(names) - 1; i >= 0; i-- {
		parts = append(parts, names[i])
	}
	self := strings.ToLower(deref(ev.ProcessName))
	if img := deref(ev.ImagePath); img != "" {
		self = strings.ToLower(path.Base(strings.ReplaceAll(img, `\`, "/")))
	}
	if self != "" {
		parts = append(parts, self)
	}
	return strings.Join(parts, " → ")
}

// chainLine is the alert-description line for ev's lineage, or "".
func chainLine(ev store.Event) string {
	if c := processChain(ev); c != "" {
		return "\nProcess chain: " + c
	}
	return ""
}
