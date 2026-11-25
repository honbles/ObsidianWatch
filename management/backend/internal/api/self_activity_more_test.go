package api

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func TestObsidianWatchActivity(t *testing.T) {
	agent := store.ProcAncestor{Name: "obsidianwatch-agent", Image: "/usr/local/bin/obsidianwatch-agent"}
	liveBash := store.ProcAncestor{Name: "bash", Image: "/bin/bash", CommandLine: "/bin/bash --login"}
	winAgent := store.ProcAncestor{Name: "obsidianwatch-agent.exe", Image: `C:\Program Files\ObsidianWatch\obsidianwatch-agent.exe`}
	cases := []struct {
		name string
		ev   store.Event
		want bool
	}{
		{"hunt command under the agent", withParents(mk(linEv{name: "systemctl", exe: "/usr/bin/systemctl", cmd: "systemctl list-units"}), agent), true},
		{"grandchild of the agent", withParents(mk(linEv{name: "cat", exe: "/usr/bin/cat"}), store.ProcAncestor{Name: "sh", Image: "/bin/sh", CommandLine: "sh -c x"}, agent), true},
		{"analyst command in the live shell", withParents(mk(linEv{name: "curl", exe: "/usr/bin/curl", cmd: "curl http://x | sh"}), liveBash, agent), false},
		{"the live shell itself", withParents(mk(linEv{name: "bash", exe: "/bin/bash", cmd: "/bin/bash --login"}), agent), false},
		{"windows live cmd.exe child", withParents(mk(linEv{name: "whoami.exe", exe: `C:\Windows\System32\whoami.exe`}), store.ProcAncestor{Name: "cmd.exe", Image: `C:\Windows\System32\cmd.exe`, CommandLine: `C:\Windows\System32\cmd.exe`}, winAgent), false},
		{"windows response powershell", withParents(mk(linEv{name: "netsh.exe", exe: `C:\Windows\System32\netsh.exe`}), store.ProcAncestor{Name: "powershell.exe", Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, CommandLine: "powershell.exe -NoProfile -Command x"}, winAgent), true},
		{"management server in its container", mk(linEv{name: "management-server", exe: "/app/management-server"}), true},
		{"scanner started by management", withParents(mk(linEv{name: "semgrep", exe: "/usr/local/bin/semgrep"}), store.ProcAncestor{Name: "management-server", Image: "/app/management-server"}), true},
		{"compose healthcheck", mk(linEv{name: "sh", exe: "/bin/sh", cmd: "/bin/sh -c cat /proc/net/tcp6 2>/dev/null | grep -q 20FB || exit 1"}), true},
		{"healthcheck child", withParents(mk(linEv{name: "pg_isready", exe: "/usr/bin/pg_isready"}), store.ProcAncestor{Name: "sh", CommandLine: "/bin/sh -c pg_isready -U obsidianwatch -d obsidianwatch"}), true},
		{"ordinary process", withParents(mk(linEv{name: "curl", exe: "/usr/bin/curl"}), store.ProcAncestor{Name: "sshd"}), false},
	}
	for _, c := range cases {
		if got := isObsidianWatchActivity(c.ev); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestRuncReexecIsNotMemfdMalware(t *testing.T) {
	runc := mk(linEv{pid: 4148589, ppid: 4148579, name: "6", exe: "/proc/self/fd/6", cmd: "runc init",
		raw: map[string]any{"argv": []string{"runc", "init"}, "parent_exe": "/usr/bin/runc", "sensor": "ebpf"}})
	if sigByID("L-T1620").Match(runc) {
		t.Fatal("runc init re-exec flagged as memfd execution")
	}
	crun := mk(linEv{name: "crun", exe: "/memfd:crun (deleted)", raw: map[string]any{"argv": []string{"crun"}}})
	if sigByID("L-T1620").Match(crun) {
		t.Fatal("crun flagged")
	}
	evil := mk(linEv{name: "3", exe: "/proc/self/fd/3", raw: map[string]any{"argv": []string{"./x"}}})
	if !sigByID("L-T1620").Match(evil) {
		t.Fatal("real fd exec missed")
	}
}

func TestOTXConfidenceGate(t *testing.T) {
	if otxConfidentEnough(store.IOCIndicator{Source: "otx", Confidence: 69}, 70) {
		t.Fatal("OTX 69 alerted")
	}
	if !otxConfidentEnough(store.IOCIndicator{Source: "otx", Confidence: 70}, 70) {
		t.Fatal("OTX 70 dropped")
	}
	if !otxConfidentEnough(store.IOCIndicator{Source: "threatfox", Confidence: 30}, 70) {
		t.Fatal("gate must apply to OTX only")
	}
}

func TestIMDSOnGCP(t *testing.T) {
	net := func(name, exe string, parents ...store.ProcAncestor) store.Event {
		ev := mk(linEv{name: name, exe: exe, typ: "network", dst: "169.254.169.254", raw: map[string]any{"action": "connect"}})
		ev.Ancestors = parents
		return ev
	}
	osconfig := store.ProcAncestor{Name: "google_osconfig_agent", Image: "/usr/bin/google_osconfig_agent"}
	expect := func(label string, ev store.Event, s1, s2 bool) {
		t.Helper()
		if got := imdsSignatures[0].Match(ev); got != s1 {
			t.Errorf("%s: IMDS-001 %v", label, got)
		}
		if got := imdsSignatures[1].Match(ev); got != s2 {
			t.Errorf("%s: IMDS-002 %v", label, got)
		}
	}
	expect("osconfig script (sh)", net("sh", "/usr/bin/dash", osconfig), false, false)
	expect("OS Login via sshd", net("sshd", "/usr/sbin/sshd"), false, false)
	expect("sudo via NSS", net("sudo", "/usr/bin/sudo"), false, false)
	expect("curl from a shell", net("curl", "/usr/bin/curl", store.ProcAncestor{Name: "bash"}), true, false)
	expect("python from ssh session", net("python3", "/usr/bin/python3", store.ProcAncestor{Name: "bash"}, store.ProcAncestor{Name: "sshd"}), false, true)
	expect("dropped binary", net("x", "/tmp/x"), false, true)
	expect("unknown service binary", net("myapp", "/opt/myapp/bin/myapp"), true, false)
}
