package api

// graph_alert.go — Alert Graph phase 3 (spec §5). The builder is pure apart
// from the graphSource it queries: events and anchors in, a bounded graph
// out. Process alerts are anchored on the exact process instance (GUID) and
// follow ancestors, descendants and per-process artifacts. Every edge says
// what evidence joined it; nothing is joined on time proximity.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// graphSource is what the builder needs from storage. *store.DB satisfies it;
// tests use an in-memory fake that also counts queries.
type graphSource interface {
	EventsByProcessGUIDs(ctx context.Context, agentID string, guids []string, from, to time.Time, limit int) ([]store.Event, error)
	EventsByParentGUIDs(ctx context.Context, agentID string, guids []string, from, to time.Time, limit int) ([]store.Event, error)
	EventsByPID(ctx context.Context, agentID string, pid int, from, to time.Time, limit int) ([]store.Event, error)
	AlertEntityMap(ctx context.Context, kind string, keys []string, perKey int) (map[string][]int64, error)
}

type AGNode struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"` // process|ip|domain|file|reg|burst|gap|entity
	Role       string            `json:"role"` // anchor|ancestor|descendant|artifact|burst|gap|entity
	Label      string            `json:"label"`
	Detail     string            `json:"detail,omitempty"`
	Cmd        string            `json:"cmd,omitempty"`
	User       string            `json:"user,omitempty"`
	PID        int               `json:"pid,omitempty"`
	First      time.Time         `json:"first"`
	Last       time.Time         `json:"last"`
	Ended      *time.Time        `json:"ended,omitempty"`
	Severity   int               `json:"severity,omitempty"`
	Score      int               `json:"score"`
	Confidence string            `json:"confidence,omitempty"` // high|low
	Alerts     []int64           `json:"alerts,omitempty"`
	Collapsed  int               `json:"collapsed,omitempty"`
	EventIDs   []string          `json:"event_ids,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
}

type AGEdge struct {
	Source     string    `json:"source"`
	Target     string    `json:"target"`
	Type       string    `json:"type"`     // spawned|connected|resolved|wrote|modified|unseen|about
	Evidence   string    `json:"evidence"` // guid|pid|logon|hash|path|inferred
	Confidence int       `json:"confidence"`
	First      time.Time `json:"first"`
	Last       time.Time `json:"last"`
	Count      int       `json:"count"`
	Label      string    `json:"label,omitempty"`
	EventIDs   []string  `json:"event_ids,omitempty"`
}

type AGTimelineItem struct {
	T    time.Time `json:"t"`
	Node string    `json:"node"`
	What string    `json:"what"`
}

type AGGap struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Note string `json:"note"`
}

type AGCoverage struct {
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Truncated bool      `json:"truncated"`
	Gaps      []AGGap   `json:"gaps"`
	Queries   int       `json:"queries"`
	Mode      string    `json:"mode"` // process|process_pid|fallback
}

type AlertGraph struct {
	Alert    map[string]interface{} `json:"alert"`
	Anchors  []Anchor               `json:"anchors"`
	Nodes    []AGNode               `json:"nodes"`
	Edges    []AGEdge               `json:"edges"`
	Timeline []AGTimelineItem       `json:"timeline"`
	Coverage AGCoverage             `json:"coverage"`
}

type graphInput struct {
	Alert       store.Alert
	Anchors     []Anchor
	AnchorEvent *store.Event
	Days        int
	MaxNodes    int
	// RelatedAlerts are extra alerts to show on the fallback view (for
	// anchors that are not processes). Optional.
}

const (
	graphMaxUpHops    = 12
	graphMaxDownDepth = 6
	graphMaxProcs     = 300
	graphEventLimit   = 5000
	graphMaxEdges     = 150
	graphPerKindCap   = 6
	graphEvtIDsCap    = 20
)

// Stable roots: the walk up stops here instead of chasing the whole OS tree.
var graphStableRoots = map[string]bool{
	"services.exe": true, "wininit.exe": true, "smss.exe": true, "system": true,
	"init": true, "systemd": true, "launchd": true, "explorer.exe": true,
	"winlogon.exe": true, "csrss.exe": true, "kthreadd": true,
}

type gProc struct {
	key      string // GUID, or "pid:N" in pid mode
	nodeID   string
	name     string
	image    string
	cmd      string
	user     string
	pid      int
	ppid     int
	parent   string // parent key (GUID)
	first    time.Time
	last     time.Time
	ended    *time.Time
	sev      int
	started  bool
	events   []string
	arts     []store.Event
	seed     bool
	low      bool
	parentOK bool // parent process was found (or is a stable root)
}

type gBuilder struct {
	ctx     context.Context
	src     graphSource
	in      graphInput
	agent   string
	alertT  time.Time
	from    time.Time
	to      time.Time
	procs   map[string]*gProc
	seenEv  map[string]bool
	queries int
	trunc   bool
	gaps    []AGGap
}

func procBase(ev store.Event) string {
	if n := gs(ev.ProcessName); n != "" {
		return n
	}
	if p := gs(ev.ImagePath); p != "" {
		return lastPathElem(p)
	}
	return ""
}

func lastPathElem(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	return path.Base(p)
}

func evID(ev store.Event) int {
	if ev.EventID != nil {
		return int(*ev.EventID)
	}
	return 0
}

func isProcStartEvent(ev store.Event) bool {
	if ev.EventType != "process" {
		return false
	}
	switch evID(ev) {
	case 0, 1, 4688:
		return !rawActionIs(ev, "exit")
	}
	return false
}

func isProcEndEvent(ev store.Event) bool {
	if ev.EventType != "process" {
		return false
	}
	id := evID(ev)
	return id == 5 || id == 4689 || rawActionIs(ev, "exit")
}

func rawActionIs(ev store.Event, want string) bool {
	if len(ev.Raw) == 0 {
		return false
	}
	// avoid a full unmarshal: the action key is tiny and unique enough
	s := string(ev.Raw)
	i := strings.Index(s, `"action"`)
	if i < 0 {
		return false
	}
	rest := s[i+8:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return false
	}
	rest = rest[j+1:]
	k := strings.Index(rest, `"`)
	if k < 0 {
		return false
	}
	return rest[:k] == want
}

func isPublicIPStr(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast())
}

func parseProcessAnchor(a Anchor) (agent, guid string, pid int, name string, ok bool) {
	if a.Kind != EntityProcess {
		return
	}
	i := strings.Index(a.Key, "|")
	if i <= 0 {
		return
	}
	agent, rest := a.Key[:i], a.Key[i+1:]
	if strings.HasPrefix(rest, "pid:") {
		parts := strings.SplitN(rest[4:], "|", 2)
		n, err := strconv.Atoi(parts[0])
		if err != nil {
			return
		}
		if len(parts) == 2 {
			name = parts[1]
		}
		return agent, "", n, name, true
	}
	return agent, rest, 0, "", rest != ""
}

// BuildAlertGraph is the builder entry point.
func BuildAlertGraph(ctx context.Context, src graphSource, in graphInput) (*AlertGraph, error) {
	if in.Days <= 0 || in.Days > 14 {
		in.Days = 3
	}
	if in.MaxNodes <= 0 || in.MaxNodes > 200 {
		in.MaxNodes = 60
	}
	b := &gBuilder{ctx: ctx, src: src, in: in, procs: map[string]*gProc{}, seenEv: map[string]bool{}}
	b.alertT = in.Alert.CreatedAt
	if in.AnchorEvent != nil && !in.AnchorEvent.Time.IsZero() {
		b.alertT = in.AnchorEvent.Time
	}
	if b.alertT.IsZero() {
		b.alertT = time.Now()
	}
	b.from = b.alertT.Add(-time.Duration(in.Days) * 24 * time.Hour)
	b.to = b.alertT.Add(2 * time.Hour)

	g := &AlertGraph{Anchors: in.Anchors}
	g.Alert = map[string]interface{}{"id": in.Alert.ID, "title": in.Alert.Title, "time": b.alertT,
		"severity": in.Alert.Severity, "host": in.Alert.Host}

	var guidSeeds, pidSeeds []Anchor
	for _, a := range in.Anchors {
		ag, guid, _, _, ok := parseProcessAnchor(a)
		if !ok {
			continue
		}
		if b.agent == "" {
			b.agent = ag
		}
		if ag != b.agent {
			continue
		}
		if guid != "" {
			guidSeeds = append(guidSeeds, a)
		} else {
			pidSeeds = append(pidSeeds, a)
		}
	}
	if len(guidSeeds) > 5 {
		guidSeeds = guidSeeds[:5]
	}
	var err error
	switch {
	case len(guidSeeds) > 0:
		g.Coverage.Mode = "process"
		err = b.buildGUID(guidSeeds)
	case len(pidSeeds) > 0:
		g.Coverage.Mode = "process_pid"
		err = b.buildPID(pidSeeds[0])
	}
	if err != nil {
		return nil, err
	}
	if len(b.procs) == 0 {
		g.Coverage.Mode = "fallback"
		b.fallback(g)
	} else {
		b.assemble(g)
	}
	g.Coverage.From, g.Coverage.To = b.from, b.to
	g.Coverage.Truncated = b.trunc
	g.Coverage.Gaps = b.gaps
	if g.Coverage.Gaps == nil {
		g.Coverage.Gaps = []AGGap{}
	}
	g.Coverage.Queries = b.queries
	b.finish(g)
	return g, nil
}

// ingest folds events into process records. Artifact events attach to their
// process; process events create or refine it.
func (b *gBuilder) ingest(events []store.Event) {
	for _, ev := range events {
		if ev.ProcessGUID == "" || b.seenEv[ev.ID] {
			continue
		}
		b.seenEv[ev.ID] = true
		p := b.procs[ev.ProcessGUID]
		if p == nil {
			p = &gProc{key: ev.ProcessGUID, nodeID: "proc:" + b.agent + ":" + ev.ProcessGUID}
			b.procs[ev.ProcessGUID] = p
		}
		b.apply(p, ev)
		if ev.ParentProcessGUID != "" && p.parent == "" {
			p.parent = ev.ParentProcessGUID
		}
	}
}

func (b *gBuilder) apply(p *gProc, ev store.Event) {
	if p.first.IsZero() || ev.Time.Before(p.first) {
		p.first = ev.Time
	}
	if ev.Time.After(p.last) {
		p.last = ev.Time
	}
	if ev.Severity > p.sev {
		p.sev = ev.Severity
	}
	if len(p.events) < graphEvtIDsCap {
		p.events = append(p.events, ev.ID)
	}
	switch {
	case isProcStartEvent(ev):
		p.started = true
		p.first = ev.Time
		if p.name == "" {
			p.name = procBase(ev)
		}
		if p.image == "" {
			p.image = gs(ev.ImagePath)
		}
		if p.cmd == "" {
			p.cmd = gs(ev.CommandLine)
		}
		if p.user == "" {
			p.user = gs(ev.UserName)
		}
		if ev.PID != nil {
			p.pid = *ev.PID
		}
		if ev.PPID != nil {
			p.ppid = *ev.PPID
		}
	case isProcEndEvent(ev):
		t := ev.Time
		p.ended = &t
	default:
		if p.name == "" {
			p.name = procBase(ev)
		}
		if p.image == "" {
			p.image = gs(ev.ImagePath)
		}
		switch ev.EventType {
		case "network", "dns", "file", "fim", "registry":
			p.arts = append(p.arts, ev)
		}
	}
}

func (b *gBuilder) query(fn func() ([]store.Event, error), limit int) ([]store.Event, error) {
	b.queries++
	evs, err := fn()
	if err != nil {
		return nil, err
	}
	if len(evs) >= limit {
		b.trunc = true
	}
	return evs, nil
}

func (b *gBuilder) buildGUID(seeds []Anchor) error {
	var guids []string
	for _, a := range seeds {
		_, g, _, _, _ := parseProcessAnchor(a)
		guids = append(guids, g)
	}
	evs, err := b.query(func() ([]store.Event, error) {
		return b.src.EventsByProcessGUIDs(b.ctx, b.agent, guids, b.from, b.to, graphEventLimit)
	}, graphEventLimit)
	if err != nil {
		return err
	}
	b.ingest(evs)
	for _, g := range guids {
		if p := b.procs[g]; p != nil {
			p.seed = true
		}
	}
	if len(b.procs) == 0 {
		return nil
	}

	// Up: parents, one query per hop. Ancestors can predate the window by
	// weeks (a long-lived shell), so the lower bound is wider.
	upFrom := b.alertT.AddDate(0, 0, -30)
	frontier := b.seedKeys()
	for hop := 0; hop < graphMaxUpHops && len(frontier) > 0; hop++ {
		var want []string
		for _, k := range frontier {
			p := b.procs[k]
			if p.parent != "" && b.procs[p.parent] == nil {
				want = append(want, p.parent)
			}
		}
		if len(want) == 0 {
			break
		}
		evs, err := b.query(func() ([]store.Event, error) {
			return b.src.EventsByProcessGUIDs(b.ctx, b.agent, uniq(want), upFrom, b.to, graphEventLimit)
		}, graphEventLimit)
		if err != nil {
			return err
		}
		b.ingest(evs)
		var next []string
		for _, w := range uniq(want) {
			if q := b.procs[w]; q != nil {
				next = append(next, w)
			}
		}
		frontier = next
	}

	// Down: children by parent GUID, breadth-first.
	level := b.seedKeys()
	for depth := 0; depth < graphMaxDownDepth && len(level) > 0 && len(b.procs) < graphMaxProcs; depth++ {
		evs, err := b.query(func() ([]store.Event, error) {
			return b.src.EventsByParentGUIDs(b.ctx, b.agent, level, b.from, b.to, graphEventLimit)
		}, graphEventLimit)
		if err != nil {
			return err
		}
		before := map[string]bool{}
		for k := range b.procs {
			before[k] = true
		}
		b.ingest(evs)
		var next []string
		for k := range b.procs {
			if !before[k] && b.procs[k].parent != "" {
				next = append(next, k)
			}
		}
		sort.Strings(next)
		level = next
	}

	// Artifacts for the whole lineage in one query (chunked only if huge).
	all := make([]string, 0, len(b.procs))
	for k := range b.procs {
		all = append(all, k)
	}
	sort.Strings(all)
	for i := 0; i < len(all); i += 400 {
		j := i + 400
		if j > len(all) {
			j = len(all)
		}
		chunk := all[i:j]
		evs, err := b.query(func() ([]store.Event, error) {
			return b.src.EventsByProcessGUIDs(b.ctx, b.agent, chunk, b.from, b.to, graphEventLimit)
		}, graphEventLimit)
		if err != nil {
			return err
		}
		b.ingest(evs)
	}
	return nil
}

func (b *gBuilder) seedKeys() []string {
	var out []string
	for k, p := range b.procs {
		if p.seed {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// buildPID is the no-GUID fallback (Windows without Sysmon, old rows). Exact
// identity is unavailable, so the node is flagged low confidence and only the
// anchor, its parent chain via ppid and its own artifacts are shown.
func (b *gBuilder) buildPID(seed Anchor) error {
	_, _, pid, name, _ := parseProcessAnchor(seed)
	b.from = b.alertT.Add(-24 * time.Hour)
	evs, err := b.query(func() ([]store.Event, error) {
		return b.src.EventsByPID(b.ctx, b.agent, pid, b.from, b.to, graphEventLimit)
	}, graphEventLimit)
	if err != nil {
		return err
	}
	var mine []store.Event
	for _, ev := range evs {
		if name != "" && strings.ToLower(procBase(ev)) != name {
			continue
		}
		mine = append(mine, ev)
	}
	if len(mine) == 0 {
		return nil
	}
	mk := func(pid int, name string) *gProc {
		key := "pid:" + strconv.Itoa(pid)
		p := &gProc{key: key, nodeID: "proc:" + b.agent + ":pid:" + strconv.Itoa(pid) + ":" + strings.ToLower(name), low: true}
		b.procs[key] = p
		return p
	}
	p := mk(pid, name)
	p.seed = true
	for _, ev := range mine {
		if b.seenEv[ev.ID] {
			continue
		}
		b.seenEv[ev.ID] = true
		b.apply(p, ev)
	}
	b.gaps = append(b.gaps, AGGap{ID: "gap:no_guid", Kind: "no_guid",
		Note: "No process GUID on these events (Windows without Sysmon, or older rows). Identity is pid + image + time, so descendants are not shown and PID reuse is possible."})
	// Parent chain (max 4 hops) by ppid.
	cur := p
	for hop := 0; hop < 4 && cur.ppid > 0; hop++ {
		ppid := cur.ppid
		evs, err := b.query(func() ([]store.Event, error) {
			return b.src.EventsByPID(b.ctx, b.agent, ppid, b.from.Add(-24*time.Hour), cur.first.Add(time.Minute), 500)
		}, 500)
		if err != nil {
			return err
		}
		var pp *gProc
		for _, ev := range evs {
			if !isProcStartEvent(ev) {
				continue
			}
			if pp == nil {
				pp = mk(ppid, procBase(ev))
			}
			b.seenEv[ev.ID] = true
			b.apply(pp, ev) // later start events win: closest to the child
		}
		if pp == nil {
			break
		}
		cur.parent = pp.key
		cur = pp
	}
	return nil
}

func (b *gBuilder) fallback(g *AlertGraph) {
	g.Nodes = nil
	g.Edges = nil
	id := fmt.Sprintf("alert:%d", b.in.Alert.ID)
	g.Nodes = append(g.Nodes, AGNode{ID: id, Type: "entity", Role: "anchor", Label: graphTrunc(b.in.Alert.Title, 80),
		First: b.alertT, Last: b.alertT, Severity: b.in.Alert.Severity, Score: 1000, Alerts: []int64{b.in.Alert.ID}})
	for _, a := range b.in.Anchors {
		nid := a.Kind + ":" + a.Key
		g.Nodes = append(g.Nodes, AGNode{ID: nid, Type: "entity", Role: "entity", Label: a.Key, Detail: a.Kind, First: b.alertT, Last: b.alertT})
		g.Edges = append(g.Edges, AGEdge{Source: id, Target: nid, Type: "about", Evidence: "guid", Confidence: 100, First: b.alertT, Last: b.alertT, Count: 1})
	}
	note := "No process-level evidence for this alert's anchor (non-process alert, or the source events are outside retention)."
	b.gaps = append(b.gaps, AGGap{ID: "gap:no_process_anchor", Kind: "no_process_anchor", Note: note})
}

func graphTrunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// ---------------------------------------------------------------------------
// Assembly: roles, edges, artifacts, collapse, prune
// ---------------------------------------------------------------------------

type gArt struct {
	kind, id, label, detail string
	first, last             time.Time
	n                       int
	ids                     []string
	ports                   map[string]int
	sev                     int
	score                   int
	owner                   string // process nodeID
}

func suspiciousDir(p string) bool {
	l := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	for _, s := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/appdata/", "/downloads/", "/users/public/", "/windows/temp/", "/programdata/"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func persistenceKey(k string) bool {
	l := strings.ToLower(k)
	for _, s := range []string{`\currentversion\run`, `\services\`, `\winlogon`, `image file execution options`, `\appinit_dlls`} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func (b *gBuilder) artifactsFor(p *gProc) []*gArt {
	agg := map[string]*gArt{}
	for _, ev := range p.arts {
		var kind, key, label string
		switch ev.EventType {
		case "network":
			d := strings.ToLower(gs(ev.DstIP))
			if d == "" {
				continue
			}
			kind, key, label = "ip", d, d
		case "dns":
			d := strings.ToLower(gs(ev.DstIP))
			if d == "" {
				continue
			}
			kind, key, label = "domain", d, d
		case "file", "fim":
			f := gs(ev.FilePath)
			if f == "" {
				continue
			}
			kind, key, label = "file", ev.Host+":"+f, lastPathElem(f)
		case "registry":
			k := gs(ev.RegKey)
			if k == "" {
				continue
			}
			kind, key, label = "reg", ev.Host+":"+k, lastPathElem(k)
		default:
			continue
		}
		id := kind + ":" + key
		a := agg[id]
		if a == nil {
			a = &gArt{kind: kind, id: id, label: label, first: ev.Time, last: ev.Time, ports: map[string]int{}, owner: p.nodeID}
			switch kind {
			case "file":
				a.detail = gs(ev.FilePath)
			case "reg":
				a.detail = gs(ev.RegKey)
			}
			agg[id] = a
		}
		a.n++
		if ev.Time.Before(a.first) {
			a.first = ev.Time
		}
		if ev.Time.After(a.last) {
			a.last = ev.Time
		}
		if ev.Severity > a.sev {
			a.sev = ev.Severity
		}
		if len(a.ids) < graphEvtIDsCap {
			a.ids = append(a.ids, ev.ID)
		}
		if kind == "ip" && ev.DstPort != nil && *ev.DstPort > 0 {
			a.ports[strconv.Itoa(*ev.DstPort)]++
		}
	}
	out := make([]*gArt, 0, len(agg))
	for _, a := range agg {
		sc := 10 + minInt(a.n, 20)
		switch a.kind {
		case "ip":
			if isPublicIPStr(strings.TrimPrefix(a.id, "ip:")) {
				sc += 30
			}
		case "file":
			if suspiciousDir(a.detail) {
				sc += 25
			}
		case "reg":
			if persistenceKey(a.detail) {
				sc += 20
			}
		}
		if a.sev >= 4 {
			sc += 15
		}
		a.score = sc
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].id < out[j].id
	})
	return out
}

func (a *gArt) edgeType() string {
	switch a.kind {
	case "ip":
		return "connected"
	case "domain":
		return "resolved"
	case "file":
		return "wrote"
	}
	return "modified"
}

func (a *gArt) edgeLabel() string {
	if len(a.ports) == 0 {
		if a.n > 1 {
			return "×" + strconv.Itoa(a.n)
		}
		return ""
	}
	type pc struct {
		p string
		c int
	}
	var l []pc
	for p, c := range a.ports {
		l = append(l, pc{p, c})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].c != l[j].c {
			return l[i].c > l[j].c
		}
		return l[i].p < l[j].p
	})
	var parts []string
	for i, x := range l {
		if i == 3 {
			break
		}
		parts = append(parts, ":"+x.p)
	}
	s := strings.Join(parts, " ")
	if a.n > 1 {
		s += " ×" + strconv.Itoa(a.n)
	}
	return s
}

func (b *gBuilder) assemble(g *AlertGraph) {
	// Roles and distances.
	dist := map[string]int{}
	role := map[string]string{}
	for k, p := range b.procs {
		if p.seed {
			dist[k] = 0
			role[k] = "anchor"
		}
	}
	// ancestors: follow parent pointers from each seed
	for _, k := range b.seedKeys() {
		d := 0
		cur := b.procs[k]
		for cur != nil && cur.parent != "" && d < graphMaxUpHops+1 {
			par := b.procs[cur.parent]
			if par == nil {
				break
			}
			d++
			if _, ok := role[par.key]; !ok {
				role[par.key] = "ancestor"
				dist[par.key] = d
			}
			cur = par
		}
	}
	// descendants: distance by climbing to the nearest classified ancestor
	var keys []string
	for k := range b.procs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := role[k]; ok {
			continue
		}
		d := 0
		cur := b.procs[k]
		seen := map[string]bool{}
		for cur != nil && !seen[cur.key] {
			seen[cur.key] = true
			if _, ok := role[cur.key]; ok && cur.key != k {
				break
			}
			d++
			cur = b.procs[cur.parent]
		}
		role[k] = "descendant"
		dist[k] = d
	}

	// Gap: parent not seen for anchor/ancestor chain nodes.
	gapCount := 0
	var gapNodes []AGNode
	var gapEdges []AGEdge
	for _, k := range keys {
		p := b.procs[k]
		if role[k] == "descendant" || gapCount >= 3 {
			continue
		}
		if graphStableRoots[strings.ToLower(p.name)] {
			continue
		}
		missing := (p.parent != "" && b.procs[p.parent] == nil) || (p.parent == "" && !p.low)
		if p.low && p.parent == "" && p.ppid == 0 {
			missing = false
		}
		if !missing {
			continue
		}
		gid := "gap:parent_unseen:" + p.nodeID
		note := "Parent process not seen in the retained events (it may have exited before the agent recorded it, or predates the window)."
		if p.parent == "" && !p.started {
			note = "No process-start event for this process was seen, so its parent is unknown."
		}
		gapNodes = append(gapNodes, AGNode{ID: gid, Type: "gap", Role: "gap", Label: "parent not seen", Detail: note, First: p.first, Last: p.first, Score: 500})
		gapEdges = append(gapEdges, AGEdge{Source: gid, Target: p.nodeID, Type: "unseen", Evidence: "inferred", Confidence: 0, First: p.first, Last: p.first, Count: 1})
		b.gaps = append(b.gaps, AGGap{ID: gid, Kind: "parent_unseen", Note: note})
		gapCount++
	}
	if b.trunc {
		b.gaps = append(b.gaps, AGGap{ID: "gap:truncated", Kind: "truncated",
			Note: fmt.Sprintf("A query hit its %d-event limit; older or lower-volume activity may be missing.", graphEventLimit)})
	}
	if b.in.AnchorEvent != nil && strings.EqualFold(b.in.AnchorEvent.OS, "windows") {
		b.gaps = append(b.gaps, AGGap{ID: "gap:filtered_source", Kind: "filtered_source",
			Note: "Sysmon file, registry and image-load events are include-filtered, so a missing file or registry node does not mean the activity did not happen."})
	}

	// Select process nodes: anchor + ancestors always; descendants by score,
	// kept only when their parent is kept so the tree stays connected.
	budget := b.in.MaxNodes - len(gapNodes)
	kept := map[string]bool{}
	for _, k := range keys {
		if role[k] != "descendant" {
			kept[k] = true
		}
	}
	var desc []string
	for _, k := range keys {
		if role[k] == "descendant" {
			desc = append(desc, k)
		}
	}
	procScore := func(k string) int {
		p := b.procs[k]
		switch role[k] {
		case "anchor":
			return 1000
		case "ancestor":
			return 900 - dist[k]
		}
		return 800 - 10*dist[k] + 5*p.sev
	}
	sort.Slice(desc, func(i, j int) bool {
		si, sj := procScore(desc[i]), procScore(desc[j])
		if si != sj {
			return si > sj
		}
		return desc[i] < desc[j]
	})
	procBudget := budget * 2 / 3 // leave room for artifacts
	if procBudget < len(kept)+1 {
		procBudget = len(kept) + 1
	}
	collapsedProc := map[string]int{}
	for _, k := range desc {
		if len(kept) < procBudget && kept[b.procs[k].parent] {
			kept[k] = true
			continue
		}
		// dropped: credit the nearest kept ancestor
		cur := b.procs[k]
		for cur != nil {
			if kept[cur.key] {
				collapsedProc[cur.key]++
				break
			}
			cur = b.procs[cur.parent]
		}
	}

	// Process nodes and spawn edges.
	nodes := map[string]*AGNode{}
	var edges []AGEdge
	conf := "high"
	for _, k := range keys {
		if !kept[k] {
			continue
		}
		p := b.procs[k]
		conf = "high"
		if p.low {
			conf = "low"
		}
		label := p.name
		if label == "" {
			label = "(unknown process)"
		}
		n := &AGNode{ID: p.nodeID, Type: "process", Role: role[k], Label: label, Detail: p.image, Cmd: graphTrunc(p.cmd, 300),
			User: p.user, PID: p.pid, First: p.first, Last: p.last, Ended: p.ended, Severity: p.sev, Score: procScore(k),
			Confidence: conf, Collapsed: collapsedProc[k], EventIDs: p.events}
		if !p.started {
			n.Meta = map[string]string{"start_seen": "false"}
		}
		nodes[n.ID] = n
		if par := b.procs[p.parent]; par != nil && kept[par.key] {
			ev := "guid"
			ec := 100
			if p.low {
				ev, ec = "pid", 60
			}
			edges = append(edges, AGEdge{Source: par.nodeID, Target: p.nodeID, Type: "spawned", Evidence: ev, Confidence: ec,
				First: p.first, Last: p.first, Count: 1})
		}
	}
	for i := range gapNodes {
		n := gapNodes[i]
		nodes[n.ID] = &n
	}
	edges = append(edges, gapEdges...)

	// Artifacts: top N per (process, kind), the rest collapsed into a burst.
	artBudget := b.in.MaxNodes - len(nodes)
	var cand []*gArt
	burstOf := map[string]*AGNode{}
	var burstEdges []AGEdge
	for _, k := range keys {
		if !kept[k] {
			continue
		}
		p := b.procs[k]
		perKind := map[string]int{}
		type rest struct {
			n     int
			items []string
			ext   map[string]int
			first time.Time
			last  time.Time
			ids   []string
		}
		rests := map[string]*rest{}
		for _, a := range b.artifactsFor(p) {
			if perKind[a.kind] < graphPerKindCap {
				perKind[a.kind]++
				cand = append(cand, a)
				continue
			}
			r := rests[a.kind]
			if r == nil {
				r = &rest{ext: map[string]int{}, first: a.first, last: a.last}
				rests[a.kind] = r
			}
			r.n++
			if len(r.items) < 5 {
				r.items = append(r.items, a.label)
			}
			if a.kind == "file" {
				e := strings.ToLower(path.Ext(a.label))
				if e == "" {
					e = "(none)"
				}
				r.ext[e]++
			}
			if a.first.Before(r.first) {
				r.first = a.first
			}
			if a.last.After(r.last) {
				r.last = a.last
			}
			for _, id := range a.ids {
				if len(r.ids) < graphEvtIDsCap {
					r.ids = append(r.ids, id)
				}
			}
		}
		var rk []string
		for kind := range rests {
			rk = append(rk, kind)
		}
		sort.Strings(rk)
		for _, kind := range rk {
			r := rests[kind]
			bid := "burst:" + kind + ":" + p.nodeID
			meta := map[string]string{"items": strings.Join(r.items, ", ")}
			if len(r.ext) > 0 {
				meta["extensions"] = histString(r.ext)
			}
			bn := &AGNode{ID: bid, Type: "burst", Role: "burst", Label: fmt.Sprintf("+%d more %s", r.n, kindPlural(kind)),
				Detail: "candidate: collapsed " + kind + " activity", First: r.first, Last: r.last, Score: 5, Collapsed: r.n, EventIDs: r.ids, Meta: meta}
			burstOf[bid] = bn
			burstEdges = append(burstEdges, AGEdge{Source: p.nodeID, Target: bid, Type: burstEdgeType(kind), Evidence: "guid",
				Confidence: 100, First: r.first, Last: r.last, Count: r.n, EventIDs: r.ids})
		}
	}
	sort.SliceStable(cand, func(i, j int) bool {
		if cand[i].score != cand[j].score {
			return cand[i].score > cand[j].score
		}
		return cand[i].id < cand[j].id
	})
	keptArt := map[string]*gArt{}
	for _, a := range cand {
		if _, dup := keptArt[a.id]; dup {
			continue
		}
		if artBudget-len(burstOf) > 0 && len(keptArt) < artBudget-len(burstOf) {
			keptArt[a.id] = a
		}
	}
	artEdges := map[string]AGEdge{}
	for _, a := range cand {
		owner := a.owner
		if keptArt[a.id] == nil {
			nodes[owner].Collapsed++
			continue
		}
		if _, ok := nodes[a.id]; !ok {
			t := a.kind
			nodes[a.id] = &AGNode{ID: a.id, Type: t, Role: "artifact", Label: a.label, Detail: a.detail,
				First: a.first, Last: a.last, Severity: a.sev, Score: a.score}
		} else {
			n := nodes[a.id]
			if a.first.Before(n.First) {
				n.First = a.first
			}
			if a.last.After(n.Last) {
				n.Last = a.last
			}
		}
		artEdges[owner+"|"+a.id] = AGEdge{Source: owner, Target: a.id, Type: a.edgeType(), Evidence: "guid", Confidence: 100,
			First: a.first, Last: a.last, Count: a.n, Label: a.edgeLabel(), EventIDs: a.ids}
	}
	for id, bn := range burstOf {
		nodes[id] = bn
	}
	var ak []string
	for k := range artEdges {
		ak = append(ak, k)
	}
	sort.Strings(ak)
	for _, k := range ak {
		edges = append(edges, artEdges[k])
	}
	edges = append(edges, burstEdges...)

	// Edge budget: structure first, then artifact edges by target score.
	if len(edges) > graphMaxEdges {
		sort.SliceStable(edges, func(i, j int) bool {
			ri := edgeRank(edges[i], nodes)
			rj := edgeRank(edges[j], nodes)
			return ri > rj
		})
		for _, e := range edges[graphMaxEdges:] {
			if o := nodes[e.Source]; o != nil {
				o.Collapsed++
			}
		}
		edges = edges[:graphMaxEdges]
	}

	// Related alerts: one query for every kept process.
	var pk []string
	for _, k := range keys {
		if kept[k] && !b.procs[k].low {
			pk = append(pk, b.agent+"|"+k)
		}
	}
	b.queries++
	if m, err := b.src.AlertEntityMap(b.ctx, EntityProcess, pk, 5); err == nil {
		for _, k := range keys {
			if n := nodes[b.procs[k].nodeID]; n != nil {
				n.Alerts = m[b.agent+"|"+k]
			}
		}
	}
	for _, k := range keys {
		if role[k] == "anchor" {
			if n := nodes[b.procs[k].nodeID]; n != nil && b.in.Alert.ID != 0 {
				has := false
				for _, id := range n.Alerts {
					if id == b.in.Alert.ID {
						has = true
					}
				}
				if !has {
					n.Alerts = append([]int64{b.in.Alert.ID}, n.Alerts...)
				}
			}
		}
	}
	for _, n := range nodes {
		g.Nodes = append(g.Nodes, *n)
	}
	g.Edges = edges
}

func edgeRank(e AGEdge, nodes map[string]*AGNode) int {
	if e.Type == "spawned" || e.Type == "unseen" {
		return 100000
	}
	if n := nodes[e.Target]; n != nil {
		return n.Score
	}
	return 0
}

func kindPlural(k string) string {
	switch k {
	case "ip":
		return "network destinations"
	case "domain":
		return "DNS names"
	case "file":
		return "files"
	}
	return "registry keys"
}

func burstEdgeType(k string) string {
	switch k {
	case "ip":
		return "connected"
	case "domain":
		return "resolved"
	case "file":
		return "wrote"
	}
	return "modified"
}

func histString(m map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	var parts []string
	for i, x := range l {
		if i == 5 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s ×%d", x.k, x.v))
	}
	return strings.Join(parts, ", ")
}

// finish sorts everything deterministically and derives the timeline.
func (b *gBuilder) finish(g *AlertGraph) {
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	sort.SliceStable(g.Edges, func(i, j int) bool {
		a, c := g.Edges[i], g.Edges[j]
		if a.Source != c.Source {
			return a.Source < c.Source
		}
		if a.Target != c.Target {
			return a.Target < c.Target
		}
		return a.Type < c.Type
	})
	sort.Slice(g.Coverage.Gaps, func(i, j int) bool { return g.Coverage.Gaps[i].ID < g.Coverage.Gaps[j].ID })
	byID := map[string]AGNode{}
	for _, n := range g.Nodes {
		byID[n.ID] = n
	}
	var tl []AGTimelineItem
	for _, n := range g.Nodes {
		if n.Type == "process" {
			what := "started " + n.Label
			if n.Cmd != "" {
				what += " — " + graphTrunc(n.Cmd, 120)
			}
			if n.Meta["start_seen"] == "false" {
				what = "activity from " + n.Label + " (start not seen)"
			}
			tl = append(tl, AGTimelineItem{T: n.First, Node: n.ID, What: what})
		}
	}
	for _, e := range g.Edges {
		if e.Type == "spawned" || e.Type == "unseen" {
			continue
		}
		t := byID[e.Target]
		what := e.Type + " " + t.Label
		if e.Label != "" {
			what += " " + e.Label
		}
		tl = append(tl, AGTimelineItem{T: e.First, Node: e.Target, What: what})
	}
	sort.SliceStable(tl, func(i, j int) bool {
		if !tl[i].T.Equal(tl[j].T) {
			return tl[i].T.Before(tl[j].T)
		}
		if tl[i].Node != tl[j].Node {
			return tl[i].Node < tl[j].Node
		}
		return tl[i].What < tl[j].What
	})
	if len(tl) > 300 {
		tl = tl[:300]
	}
	g.Timeline = tl
	if g.Nodes == nil {
		g.Nodes = []AGNode{}
	}
	if g.Edges == nil {
		g.Edges = []AGEdge{}
	}
	if g.Timeline == nil {
		g.Timeline = []AGTimelineItem{}
	}
	if g.Anchors == nil {
		g.Anchors = []Anchor{}
	}
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

// handleAlertGraph serves GET /api/v1/alerts/{id}/graph?days=3&max_nodes=60.
// Anchors are resolved on read from the alert's source event, then merged with
// anchors persisted by the AlertCreatedHook (extra processes recorded when a
// duplicate alert fired), so the view works for alerts created before this
// feature existed.
func handleAlertGraph(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		alert, err := db.GetAlert(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "alert not found"})
			return
		}
		days, _ := strconv.Atoi(r.URL.Query().Get("days"))
		maxNodes, _ := strconv.Atoi(r.URL.Query().Get("max_nodes"))

		lookupID := alert.SourceEventID
		if lookupID == "" && alert.EventID != "" &&
			!strings.HasPrefix(alert.EventID, "sig:") && !strings.HasPrefix(alert.EventID, "ioc:") &&
			!strings.HasPrefix(alert.EventID, "rule:") && !strings.HasPrefix(alert.EventID, "corr:") {
			lookupID = alert.EventID
		}
		var ev *store.Event
		if lookupID != "" {
			if e, err := db.GetEventByID(r.Context(), lookupID); err == nil {
				ev = e
			}
		}
		var anchors []Anchor
		seen := map[string]bool{}
		add := func(a Anchor) {
			if !seen[a.Kind+"\x00"+a.Key] {
				seen[a.Kind+"\x00"+a.Key] = true
				anchors = append(anchors, a)
			}
		}
		if ev != nil {
			for _, a := range deriveAnchors(*ev) {
				add(a)
			}
		}
		if links, err := db.AlertEntities(r.Context(), id); err == nil {
			for _, l := range links {
				switch l[0] {
				case EntityProcess, EntityLogon, EntityUser, EntityIP, EntityFile, EntityRegistry, EntityDomain:
					add(Anchor{l[0], l[1]})
				}
			}
		}
		g, err := BuildAlertGraph(r.Context(), db, graphInput{Alert: *alert, Anchors: anchors, AnchorEvent: ev, Days: days, MaxNodes: maxNodes})
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "graph build failed"})
			return
		}
		writeJSON(w, 200, g)
	}
}
