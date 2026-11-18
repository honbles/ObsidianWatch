package api

import (
	"strings"
	"testing"
	"time"
)

func TestAppH01ShellFromServiceProcess(t *testing.T) {
	// positive: a shell, no terminal, descended from the service's own process
	fx := appNewFx(t)
	fx.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`,"tty":false}`))
	a := fx.pos("APP-H01", 1)[0]
	if a.Sev != appSevHigh || a.F.Svc.Name != "checkout" || a.F.InstanceID != 11 || a.F.Identity != "verified" || a.F.Degraded {
		t.Fatalf("%+v", a)
	}
	for _, want := range []string{"java(100)", "bash(500)"} {
		if !appContains(a.F.Lineage, want) {
			t.Fatalf("lineage %q lacks %q", a.F.Lineage, want)
		}
	}
}

func appContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (func() bool { return appIndexOf(s, sub) >= 0 })())
}
func appIndexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestAppH01Negatives(t *testing.T) {
	cases := map[string]func(fx *appFx){
		"terminal attached (an operator)": func(fx *appFx) { fx.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`,"tty":true}`)) },
		"not a shell":                     func(fx *appFx) { fx.event(appEv("process", 500, 100, "ls", `{`+appAncJava+`}`)) },
		"not descended from the service": func(fx *appFx) {
			fx.event(appEv("process", 500, 1, "bash", `{"ancestors":[{"pid":1,"name":"systemd"}]}`))
		},
		"the service process itself": func(fx *appFx) { fx.event(appEv("process", 100, 1, "bash", `{"tty":false}`)) },
		"allowlisted parent>child pair": func(fx *appFx) {
			fx.gate("APP-H01", RuleGate{Enabled: true, Allowlist: []string{"java>bash"}})
			fx.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`}`))
		},
		"rule disabled": func(fx *appFx) {
			fx.gate("APP-H01", RuleGate{Enabled: false})
			fx.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`}`))
		},
	}
	for name, run := range cases {
		fx := appNewFx(t)
		run(fx)
		fx.neg("APP-H01")
		_ = name
	}
}

func TestAppH01DegradedWithoutAncestry(t *testing.T) {
	fx := appNewFx(t) // existing collectors: only ppid is known, and it IS the service process
	fx.event(appEv("process", 500, 100, "bash", ""))
	a := fx.pos("APP-H01", 1)[0]
	if !a.F.Degraded || a.Sev != appSevMed || !appContains(a.F.DegradeNote, "ancestry") {
		t.Fatalf("a direct child must be recognised but reduced one level: %+v", a)
	}
	// a grandchild cannot be seen without ancestry
	fx2 := appNewFx(t)
	fx2.event(appEv("process", 500, 400, "bash", ""))
	fx2.neg("APP-H01")
}

func TestAppH01FollowOnEscalatesToCritical(t *testing.T) {
	fx := appNewFx(t)
	fx.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`}`))
	net := appEv("network", 500, 100, "bash", `{`+appAncJava+`}`)
	net.Time = appNow.Add(20 * time.Second)
	net.DstIP, net.DstPort = appSP("203.0.113.9"), appIP(4444)
	fx.event(net)
	got := fx.pos("APP-H01", 2)
	if got[0].Sev != appSevHigh || got[1].Sev != appSevCrit || !appContains(got[1].F.Detail, "203.0.113.9:4444") {
		t.Fatalf("%+v", got)
	}
	// a file write by the shell also escalates
	fx = appNewFx(t)
	fx.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`}`))
	file := appEv("file", 500, 100, "bash", `{`+appAncJava+`,"op":"write"}`)
	file.Time, file.FilePath = appNow.Add(5*time.Second), appSP("/tmp/x")
	fx.event(file)
	if got := fx.pos("APP-H01", 2); got[1].Sev != appSevCrit {
		t.Fatalf("%+v", got)
	}
}

func TestAppH01FollowOnNegatives(t *testing.T) {
	fx := appNewFx(t) // outside the follow-on window
	fx.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`}`))
	net := appEv("network", 500, 100, "bash", `{`+appAncJava+`}`)
	net.Time, net.DstIP = appNow.Add(10*time.Minute), appSP("203.0.113.9")
	fx.event(net)
	fx.pos("APP-H01", 1) // only the original
	fx2 := appNewFx(t)   // a file READ is not a write
	fx2.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`}`))
	rd := appEv("file", 500, 100, "bash", `{`+appAncJava+`,"op":"read"}`)
	rd.FilePath = appSP("/etc/hosts")
	fx2.event(rd)
	fx2.pos("APP-H01", 1)
}

func TestAppH02Downloader(t *testing.T) {
	fx := appNewFx(t)
	fx.event(appEv("process", 600, 100, "curl", `{`+appAncJava+`}`))
	if a := fx.pos("APP-H02", 1)[0]; a.Sev != appSevHigh {
		t.Fatalf("%+v", a)
	}
	for _, run := range []func(*appFx){
		func(f *appFx) { f.event(appEv("process", 600, 1, "curl", `{"ancestors":[{"pid":1,"name":"cron"}]}`)) },
		func(f *appFx) { f.event(appEv("process", 600, 100, "grep", `{`+appAncJava+`}`)) },
		func(f *appFx) {
			f.gate("APP-H02", RuleGate{Enabled: true, Allowlist: []string{"curl"}})
			f.event(appEv("process", 600, 100, "curl", `{`+appAncJava+`}`))
		},
	} {
		f := appNewFx(t)
		run(f)
		f.neg("APP-H02")
	}
}

func TestAppH03ExecutableInWebDirectory(t *testing.T) {
	mk := func(path, op, mode string) (fx *appFx) {
		fx = appNewFx(t)
		raw := `{"op":"` + op + `","mode":"` + mode + `"}`
		ev := appEv("file", 100, 1, "java", raw)
		ev.FilePath = appSP(path)
		fx.event(ev)
		return fx
	}
	mk("/var/www/html/uploads/shell.php", "create", "0644").pos("APP-H03", 1)
	mk("/srv/app/public/tool", "create", "0755").pos("APP-H03", 1) // no extension, but executable
	mk("/var/www/html/a.txt", "create", "0644").neg("APP-H03")     // not a script
	mk("/tmp/shell.php", "create", "0644").neg("APP-H03")          // not a web directory
	mk("/var/www/html/shell.php", "read", "0644").neg("APP-H03")   // reading is not writing
	fx := appNewFx(t)
	fx.d.deploy = true
	ev := appEv("file", 100, 1, "java", `{"op":"create","mode":"0644"}`)
	ev.FilePath = appSP("/var/www/html/index.php")
	fx.event(ev)
	fx.neg("APP-H03") // a deploy writes scripts too
	if appStatusSnapshot()["APP-H03"].Skipped["deploy window"] != 1 {
		t.Fatalf("a suppressed deploy-window finding must be counted: %+v", appStatusSnapshot()["APP-H03"])
	}
}

func appNetFx(t *testing.T, dst, raw string, prep func(*appFx)) *appFx {
	fx := appNewFx(t)
	if prep != nil {
		prep(fx)
	}
	ev := appEv("network", 100, 1, "java", raw)
	ev.DstIP, ev.DstPort = appSP(dst), appIP(443)
	fx.event(ev)
	return fx
}

func appLearnedDest(fx *appFx) { // 7+ days old (30) and 300 outbound connections learned
	fx.d.baselines[fx.d.bkey(1, "destination", "dns:db.internal")] = 300
}

func TestAppH04NewDestination(t *testing.T) {
	// positive: a destination not seen while learning
	fx := appNetFx(t, "203.0.113.50", `{"dns":"evil.example.net"}`, appLearnedDest)
	if a := fx.pos("APP-H04", 1)[0]; a.Sev != appSevMed || !appContains(a.F.Detail, "evil.example.net") {
		t.Fatalf("%+v", a)
	}
	// the same destination again is not an alert twice (it was recorded)
	// negatives: known destination; still learning (too young); not enough samples; deploy window; loopback
	appNetFx(t, "10.0.0.9", `{"dns":"db.internal"}`, appLearnedDest).neg("APP-H04")
	young := appNetFx(t, "203.0.113.50", `{"dns":"evil.example.net"}`, func(fx *appFx) {
		appLearnedDest(fx)
		fx.setSvc(func(s *appSvc) { s.FirstSeen = appNow.Add(-24 * time.Hour) })
	})
	young.neg("APP-H04")
	if n := young.d.baselines[young.d.bkey(1, "destination", "dns:evil.example.net")]; n != 1 {
		t.Fatalf("learning must record the destination into the baseline: %d", n)
	}
	appNetFx(t, "203.0.113.50", `{"dns":"evil.example.net"}`, nil).neg("APP-H04") // 0 samples: not learned
	appNetFx(t, "203.0.113.50", `{"dns":"evil.example.net"}`, func(fx *appFx) { appLearnedDest(fx); fx.d.deploy = true }).neg("APP-H04")
	appNetFx(t, "127.0.0.1", `{}`, appLearnedDest).neg("APP-H04")
	// a known registrable domain under a new name is reduced to Low
	fx = appNetFx(t, "203.0.113.50", `{"dns":"api2.stripe.com"}`, func(fx *appFx) {
		appLearnedDest(fx)
		fx.d.baselines[fx.d.bkey(1, "destination", "dnsdom:stripe.com")] = 5
	})
	if a := fx.pos("APP-H04", 1)[0]; a.Sev != appSevLow {
		t.Fatalf("known domain: %+v", a)
	}
}

func TestAppH05PublicIPLiteral(t *testing.T) {
	appNetFx(t, "198.51.100.7", `{"prior_dns":false}`, nil).pos("APP-H05", 1)
	appNetFx(t, "198.51.100.7", `{"prior_dns":true,"dns":"x.example.com"}`, nil).neg("APP-H05") // resolved by name first
	appNetFx(t, "10.1.2.3", `{"prior_dns":false}`, nil).neg("APP-H05")                          // private address
	skip := appNetFx(t, "198.51.100.7", `{}`, nil)                                              // sensor gave no DNS information
	skip.neg("APP-H05")
	if appStatusSnapshot()["APP-H05"].Skipped["no DNS lookup information from the sensor"] != 1 {
		t.Fatal("a missing input must be counted, not silently ignored")
	}
	fx := appNetFx(t, "198.51.100.7", `{"prior_dns":true,"dns":"x.example.com"}`, func(fx *appFx) { fx.d.intel = map[string]string{"198.51.100.7": "abuse.ch"} })
	if a := fx.pos("APP-H05", 1)[0]; a.Sev != appSevHigh || !appContains(a.F.Detail, "abuse.ch") {
		t.Fatalf("a threat-intel hit is High even with DNS: %+v", a)
	}
	allow := appNetFx(t, "198.51.100.7", `{"prior_dns":false}`, func(fx *appFx) { fx.gate("APP-H05", RuleGate{Enabled: true, Allowlist: []string{"198.51.100.0/24"}}) })
	allow.neg("APP-H05") // CIDR allowlist
}

func TestAppH06MetadataEndpoint(t *testing.T) {
	prep := func(fx *appFx) { appLearnedDest(fx) }
	appNetFx(t, "169.254.169.254", `{}`, prep).pos("APP-H06", 1)
	appNetFx(t, "198.51.100.1", `{"dns":"metadata.google.internal"}`, prep).pos("APP-H06", 1)
	appNetFx(t, "169.254.169.254", `{}`, func(fx *appFx) { // the service used it while learning
		appLearnedDest(fx)
		fx.d.baselines[fx.d.bkey(1, "metadata", "meta:169.254.169.254")] = 40
	}).neg("APP-H06")
	appNetFx(t, "169.254.169.254", `{}`, func(fx *appFx) { // still learning: recorded, not alerted
		appLearnedDest(fx)
		fx.setSvc(func(s *appSvc) { s.FirstSeen = appNow.Add(-2 * 24 * time.Hour) })
	}).neg("APP-H06")
	appNetFx(t, "203.0.113.5", `{}`, prep).neg("APP-H06")
}

func appFileFx(t *testing.T, name string, pid int, path, op string, prep func(*appFx)) *appFx {
	fx := appNewFx(t)
	if prep != nil {
		prep(fx)
	}
	ev := appEv("file", pid, 1, name, `{"op":"`+op+`"}`)
	ev.FilePath = appSP(path)
	fx.event(ev)
	return fx
}

func TestAppH07SecretFileRead(t *testing.T) {
	appFileFx(t, "java", 100, "/etc/shadow", "read", nil).pos("APP-H07", 1)
	appFileFx(t, "java", 100, "/home/app/.aws/credentials", "open", nil).pos("APP-H07", 1)
	appFileFx(t, "java", 100, "/home/app/.ssh/id_ed25519", "read", nil).pos("APP-H07", 1)
	appFileFx(t, "java", 100, "/proc/4242/environ", "read", nil).pos("APP-H07", 1) // another process's environment
	appFileFx(t, "sshd", 100, "/etc/shadow", "read", nil).neg("APP-H07")           // legitimate reader
	appFileFx(t, "java", 100, "/etc/hosts", "read", nil).neg("APP-H07")
	appFileFx(t, "java", 100, "/home/app/.ssh/id_ed25519.pub", "read", nil).neg("APP-H07") // public key
	appFileFx(t, "java", 100, "/proc/self/environ", "read", nil).neg("APP-H07")
	appFileFx(t, "java", 100, "/proc/100/environ", "read", nil).neg("APP-H07") // its own environment
	appFileFx(t, "java", 100, "/etc/shadow", "write", nil).neg("APP-H07")
	appFileFx(t, "java", 999, "/etc/shadow", "read", nil).neg("APP-H07") // not a service process
	appFileFx(t, "java", 100, "/etc/shadow", "read", func(fx *appFx) {
		fx.gate("APP-H07", RuleGate{Enabled: true, Allowlist: []string{"java"}})
	}).neg("APP-H07")
}

func appPrivFx(t *testing.T, kind, detail string, prep func(*appFx)) *appFx {
	fx := appNewFx(t)
	if prep != nil {
		prep(fx)
	}
	fx.event(appEv("process", 100, 1, "java", `{"priv_change":{"kind":"`+kind+`","detail":"`+detail+`"}}`))
	return fx
}

func TestAppH08PrivilegeChange(t *testing.T) {
	// learned: 30 days old; the baseline records priv changes (no sample minimum)
	appPrivFx(t, "setuid", "0", nil).pos("APP-H08", 1)
	appPrivFx(t, "cap", "CAP_SYS_ADMIN", nil).pos("APP-H08", 1)
	appPrivFx(t, "setuid", "0", func(fx *appFx) { fx.d.baselines[fx.d.bkey(1, "priv", "priv:setuid:0")] = 3 }).neg("APP-H08") // part of its normal start
	young := appPrivFx(t, "setuid", "0", func(fx *appFx) { fx.setSvc(func(s *appSvc) { s.FirstSeen = appNow.Add(-24 * time.Hour) }) })
	young.neg("APP-H08")
	if young.d.baselines[young.d.bkey(1, "priv", "priv:setuid:0")] != 1 {
		t.Fatal("learning must record the change")
	}
	// no priv_change: nothing to evaluate
	fx := appNewFx(t)
	fx.event(appEv("process", 100, 1, "java", `{}`))
	fx.neg("APP-H08")
}

func TestAppH11ContainerEscape(t *testing.T) {
	ctr := strings.Repeat("c", 64)
	mk := func(name, raw, path string, container string) *appFx {
		fx := appNewFx(t)
		ev := appEv("process", 777, 1, name, raw)
		if path != "" {
			ev.EventType = "file"
			ev.FilePath = appSP(path)
		}
		_ = container
		fx.event(ev)
		return fx
	}
	a := mk("nsenter", `{"escape":"setns","container_id":"`+ctr+`"}`, "", ctr).pos("APP-H11", 1)[0]
	if a.Sev != appSevCrit || a.F.Svc.ID != 0 {
		t.Fatalf("a container process with no service is host-scoped and Critical: %+v", a)
	}
	mk("python3", `{"op":"open","container_id":"`+ctr+`"}`, "/var/run/docker.sock", ctr).pos("APP-H11", 1) // runtime socket by a non-runtime
	mk("runc", `{"escape":"mount","container_id":"`+ctr+`"}`, "", ctr).neg("APP-H11")                      // the runtime itself
	mk("dockerd", `{"op":"open","container_id":"`+ctr+`"}`, "/var/run/docker.sock", ctr).neg("APP-H11")
	mk("mount", `{"escape":"mount"}`, "", "").neg("APP-H11") // not in a container and not a service process
	// a service process is also attributed to its service
	fx := appNewFx(t)
	ev := appEv("process", 100, 1, "java", `{"escape":"mount"}`)
	fx.event(ev)
	if a := fx.pos("APP-H11", 1)[0]; a.F.Svc.Name != "checkout" {
		t.Fatalf("%+v", a)
	}
}
