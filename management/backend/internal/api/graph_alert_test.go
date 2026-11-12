package api

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

type fakeGraphSrc struct {
	evs    []store.Event
	calls  int
	alerts map[string][]int64
}

func (f *fakeGraphSrc) in(from, to, t time.Time) bool { return !t.Before(from) && !t.After(to) }

func (f *fakeGraphSrc) EventsByProcessGUIDs(_ context.Context, agent string, guids []string, from, to time.Time, limit int) ([]store.Event, error) {
	f.calls++
	set := map[string]bool{}
	for _, g := range guids {
		set[g] = true
	}
	var out []store.Event
	for _, e := range f.evs {
		if e.AgentID == agent && set[e.ProcessGUID] && f.in(from, to, e.Time) {
			out = append(out, e)
		}
	}
	return out, nil
}
func (f *fakeGraphSrc) EventsByParentGUIDs(_ context.Context, agent string, guids []string, from, to time.Time, limit int) ([]store.Event, error) {
	f.calls++
	set := map[string]bool{}
	for _, g := range guids {
		set[g] = true
	}
	var out []store.Event
	for _, e := range f.evs {
		if e.AgentID == agent && set[e.ParentProcessGUID] && f.in(from, to, e.Time) {
			out = append(out, e)
		}
	}
	return out, nil
}
func (f *fakeGraphSrc) EventsByPID(_ context.Context, agent string, pid int, from, to time.Time, limit int) ([]store.Event, error) {
	f.calls++
	var out []store.Event
	for _, e := range f.evs {
		if e.AgentID == agent && e.PID != nil && *e.PID == pid && f.in(from, to, e.Time) {
			out = append(out, e)
		}
	}
	return out, nil
}
func (f *fakeGraphSrc) AlertEntityMap(_ context.Context, kind string, keys []string, perKey int) (map[string][]int64, error) {
	f.calls++
	out := map[string][]int64{}
	for _, k := range keys {
		if v := f.alerts[k]; v != nil {
			out[k] = v
		}
	}
	return out, nil
}

var t0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
var evSeq int

func mkEv(typ, guid, parent, name string, at time.Duration) store.Event {
	evSeq++
	e := store.Event{ID: fmt.Sprintf("e%d", evSeq), Time: t0.Add(at), AgentID: "a1", Host: "h1", OS: "windows",
		EventType: typ, Severity: 1, ProcessGUID: guid, ParentProcessGUID: parent}
	e.ProcessName = sp(name)
	return e
}
func startEv(guid, parent, name string, at time.Duration) store.Event {
	e := mkEv("process", guid, parent, name, at)
	e.ImagePath = sp(`C:\Windows\` + name)
	e.CommandLine = sp(name + " --run")
	id := uint32(1)
	e.EventID = &id
	return e
}
func netEv(guid, ip string, port int, at time.Duration) store.Event {
	e := mkEv("network", guid, "", "", at)
	e.DstIP = sp(ip)
	e.DstPort = ip2(port)
	return e
}
func ip2(i int) *int { return &i }
func fileEv(guid, p string, at time.Duration) store.Event {
	e := mkEv("file", guid, "", "", at)
	e.FilePath = sp(p)
	return e
}

func chainFixture() *fakeGraphSrc {
	evSeq = 0
	f := &fakeGraphSrc{alerts: map[string][]int64{}}
	f.evs = []store.Event{
		startEv("{EXP}", "{WININIT}", "explorer.exe", -48*time.Hour),
		startEv("{CMD}", "{EXP}", "cmd.exe", -10*time.Minute),
		startEv("{PS}", "{CMD}", "powershell.exe", -9*time.Minute),
		startEv("{CURL}", "{PS}", "curl.exe", -8*time.Minute),
		netEv("{PS}", "203.0.113.7", 443, -7*time.Minute),
		netEv("{PS}", "203.0.113.7", 443, -6*time.Minute),
		netEv("{PS}", "10.0.0.5", 445, -5*time.Minute),
		fileEv("{CURL}", `C:\Users\bob\AppData\Local\Temp\payload.exe`, -4*time.Minute),
		// same pid-style noise belonging to a different instance must not attach
		startEv("{PS2}", "{CMD}", "powershell.exe", -3*time.Hour),
		netEv("{PS2}", "198.51.100.9", 80, -3*time.Hour),
	}
	f.alerts["a1|{CMD}"] = []int64{77}
	return f
}

func chainInput() graphInput {
	return graphInput{Alert: store.Alert{ID: 5, Title: "t", CreatedAt: t0, AgentID: "a1", Host: "h1"},
		Anchors: []Anchor{{EntityProcess, "a1|{PS}"}}, AnchorEvent: &store.Event{Time: t0, OS: "windows"}}
}

func nodeByLabel(g *AlertGraph, label string) *AGNode {
	for i := range g.Nodes {
		if g.Nodes[i].Label == label {
			return &g.Nodes[i]
		}
	}
	return nil
}

func hasEdge(g *AlertGraph, src, dst, typ string) bool {
	for _, e := range g.Edges {
		if e.Source == src && e.Target == dst && e.Type == typ {
			return true
		}
	}
	return false
}

func TestAlertGraphChain(t *testing.T) {
	f := chainFixture()
	g, err := BuildAlertGraph(context.Background(), f, chainInput())
	if err != nil {
		t.Fatal(err)
	}
	ps := nodeByLabel(g, "powershell.exe")
	if ps == nil || ps.Role != "anchor" || ps.ID != "proc:a1:{PS}" {
		t.Fatalf("anchor: %+v", ps)
	}
	if n := nodeByLabel(g, "cmd.exe"); n == nil || n.Role != "ancestor" || len(n.Alerts) != 1 || n.Alerts[0] != 77 {
		t.Fatalf("ancestor / related alert: %+v", n)
	}
	if n := nodeByLabel(g, "curl.exe"); n == nil || n.Role != "descendant" {
		t.Fatalf("descendant: %+v", n)
	}
	if !hasEdge(g, "proc:a1:{CMD}", "proc:a1:{PS}", "spawned") || !hasEdge(g, "proc:a1:{PS}", "proc:a1:{CURL}", "spawned") {
		t.Fatalf("spawn edges missing: %+v", g.Edges)
	}
	// artifacts: both IPs, the dropped file; edge aggregates the two connections
	if !hasEdge(g, "proc:a1:{PS}", "ip:203.0.113.7", "connected") || !hasEdge(g, "proc:a1:{PS}", "ip:10.0.0.5", "connected") {
		t.Fatalf("network edges: %+v", g.Edges)
	}
	for _, e := range g.Edges {
		if e.Target == "ip:203.0.113.7" && (e.Count != 2 || e.Label != ":443 ×2") {
			t.Errorf("aggregated edge: %+v", e)
		}
	}
	if !hasEdge(g, "proc:a1:{CURL}", `file:h1:C:\Users\bob\AppData\Local\Temp\payload.exe`, "wrote") {
		t.Errorf("file edge missing")
	}
	// the other powershell instance must not leak in
	for _, n := range g.Nodes {
		if n.ID == "proc:a1:{PS2}" || n.ID == "ip:198.51.100.9" {
			t.Errorf("unrelated instance leaked: %s", n.ID)
		}
	}
	// explorer is a stable root: no parent_unseen gap for it, and it is not shown as a gap
	for _, gp := range g.Coverage.Gaps {
		if gp.Kind == "parent_unseen" {
			t.Errorf("unexpected gap %+v", gp)
		}
	}
	if g.Coverage.Mode != "process" {
		t.Errorf("mode %q", g.Coverage.Mode)
	}
	// 1 seed + up: CMD, EXP (+1 miss none) + down: 2 levels + artifacts, plus alerts map
	if f.calls > 9 {
		t.Errorf("too many queries: %d", f.calls)
	}
	if len(g.Timeline) == 0 || g.Timeline[0].T.After(g.Timeline[len(g.Timeline)-1].T) {
		t.Errorf("timeline not ordered")
	}
}

func TestAlertGraphDeterministic(t *testing.T) {
	var prev []byte
	for i := 0; i < 5; i++ {
		g, err := BuildAlertGraph(context.Background(), chainFixture(), chainInput())
		if err != nil {
			t.Fatal(err)
		}
		g.Coverage.Queries = 0
		b, _ := json.Marshal(g)
		if prev != nil && string(prev) != string(b) {
			t.Fatalf("run %d differs", i)
		}
		prev = b
	}
}

func TestAlertGraphParentUnseen(t *testing.T) {
	f := &fakeGraphSrc{evs: []store.Event{
		startEv("{X}", "{GONE}", "evil.exe", -time.Minute),
	}}
	g, err := BuildAlertGraph(context.Background(), f, graphInput{Alert: store.Alert{ID: 1, CreatedAt: t0},
		Anchors: []Anchor{{EntityProcess, "a1|{X}"}}, AnchorEvent: &store.Event{Time: t0}})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, n := range g.Nodes {
		if n.Type == "gap" && n.ID == "gap:parent_unseen:proc:a1:{X}" {
			found = true
		}
	}
	if !found || !hasEdge(g, "gap:parent_unseen:proc:a1:{X}", "proc:a1:{X}", "unseen") {
		t.Fatalf("gap node missing: %+v", g.Nodes)
	}
}

func TestAlertGraphPrunesToBudget(t *testing.T) {
	f := &fakeGraphSrc{}
	f.evs = append(f.evs, startEv("{ROOT}", "{P}", "root.exe", -time.Hour))
	for i := 0; i < 120; i++ {
		f.evs = append(f.evs, startEv(fmt.Sprintf("{C%03d}", i), "{ROOT}", fmt.Sprintf("child%03d.exe", i), -time.Duration(i)*time.Second))
	}
	// 40 files by the root in one dir: collapsed into a burst with an extension histogram
	for i := 0; i < 40; i++ {
		f.evs = append(f.evs, fileEv("{ROOT}", fmt.Sprintf(`C:\Users\x\Documents\f%d.locked`, i), -time.Minute))
	}
	in := graphInput{Alert: store.Alert{ID: 1, CreatedAt: t0}, Anchors: []Anchor{{EntityProcess, "a1|{ROOT}"}},
		AnchorEvent: &store.Event{Time: t0}, MaxNodes: 40}
	g, err := BuildAlertGraph(context.Background(), f, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) > 40 {
		t.Fatalf("budget exceeded: %d nodes", len(g.Nodes))
	}
	root := nodeByLabel(g, "root.exe")
	if root == nil || root.Collapsed == 0 {
		t.Fatalf("root should record collapsed children: %+v", root)
	}
	ids := map[string]bool{}
	for _, n := range g.Nodes {
		ids[n.ID] = true
	}
	for _, e := range g.Edges {
		if !ids[e.Source] || !ids[e.Target] {
			t.Fatalf("dangling edge %+v", e)
		}
	}
	var burst *AGNode
	for i := range g.Nodes {
		if g.Nodes[i].Type == "burst" && g.Nodes[i].Meta["extensions"] != "" {
			burst = &g.Nodes[i]
		}
	}
	if burst == nil || burst.Meta["extensions"] != ".locked ×34" || burst.Collapsed != 34 {
		t.Fatalf("file burst: %+v", burst)
	}
}

func TestAlertGraphPIDFallback(t *testing.T) {
	f := &fakeGraphSrc{}
	mk := func(pid, ppid int, name string, at time.Duration) store.Event {
		e := mkEv("process", "", "", name, at)
		e.PID, e.PPID = ip2(pid), ip2(ppid)
		return e
	}
	f.evs = []store.Event{mk(10, 5, "cmd.exe", -time.Hour), mk(42, 10, "evil.exe", -time.Minute)}
	n := mkEv("network", "", "", "evil.exe", -30*time.Second)
	n.PID = ip2(42)
	n.DstIP = sp("203.0.113.1")
	f.evs = append(f.evs, n)
	g, err := BuildAlertGraph(context.Background(), f, graphInput{Alert: store.Alert{ID: 2, CreatedAt: t0},
		Anchors: []Anchor{{EntityProcess, "a1|pid:42|evil.exe"}}, AnchorEvent: &store.Event{Time: t0}})
	if err != nil {
		t.Fatal(err)
	}
	if g.Coverage.Mode != "process_pid" {
		t.Fatalf("mode %q", g.Coverage.Mode)
	}
	ev := nodeByLabel(g, "evil.exe")
	if ev == nil || ev.Confidence != "low" {
		t.Fatalf("low confidence node: %+v", ev)
	}
	if nodeByLabel(g, "cmd.exe") == nil {
		t.Errorf("parent via ppid missing")
	}
	var noGUID bool
	for _, gp := range g.Coverage.Gaps {
		if gp.Kind == "no_guid" {
			noGUID = true
		}
	}
	if !noGUID {
		t.Errorf("no_guid gap missing")
	}
}

func TestAlertGraphFallbackNeverEmpty(t *testing.T) {
	g, err := BuildAlertGraph(context.Background(), &fakeGraphSrc{}, graphInput{Alert: store.Alert{ID: 3, Title: "brute force", CreatedAt: t0},
		Anchors: []Anchor{{EntityUser, "admin"}, {EntityIP, "203.0.113.9"}}})
	if err != nil {
		t.Fatal(err)
	}
	if g.Coverage.Mode != "fallback" || len(g.Nodes) != 3 || len(g.Edges) != 2 {
		t.Fatalf("fallback shape: mode=%s nodes=%d edges=%d", g.Coverage.Mode, len(g.Nodes), len(g.Edges))
	}
}
