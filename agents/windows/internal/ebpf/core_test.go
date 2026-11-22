package ebpf

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactCmd(t *testing.T) {
	for in, want := range map[string]string{
		"mysql --user=app --password=hunter2 db":           "mysql --user=app --password=[REDACTED] db",
		"app --token abc123 --verbose":                     "app --token [REDACTED] --verbose",
		"API_KEY=abcd1234 curl https://x":                  "API_KEY=[REDACTED] curl https://x",
		"curl https://bob:s3cret@host.example/path":        "curl https://bob:[REDACTED]@host.example/path",
		`curl -H Authorization: Bearer eyJhbGciOi.xyz url`: `curl -H Authorization: Bearer [REDACTED] url`,
		"bash -c ls -la /var/www":                          "bash -c ls -la /var/www",
		"java -jar app.jar --server.port=8080":             "java -jar app.jar --server.port=8080",
		"psql --passphrase=x --dbname=y":                   "psql --passphrase=[REDACTED] --dbname=y",
		"tool --client-secret topsecret":                   "tool --client-secret [REDACTED]",
	} {
		if got := RedactCmd(in); got != want {
			t.Fatalf("RedactCmd(%q)\n got  %q\n want %q", in, got, want)
		}
	}
	if long := RedactCmd(strings.Repeat("a ", 3000)); len(long) > maxCmdLen {
		t.Fatalf("command lines are capped: %d", len(long))
	}
	if got := RedactCmd("--password"); got != "--password" { // a flag with no value left alone, no panic
		t.Fatal(got)
	}
}

func TestDiscoverName(t *testing.T) {
	for _, c := range []struct {
		exe  string
		args []string
		want string
	}{
		{"/usr/bin/java", []string{"-Xmx1g", "-jar", "/opt/shop/checkout-1.4.2.jar", "--port=8080"}, "checkout"},
		{"/usr/bin/java", []string{"-cp", "/lib/*", "com.example.orders.Main"}, "Main"},
		{"/usr/bin/java", []string{"org.apache.catalina.startup.Bootstrap", "start"}, "tomcat"},
		{"/usr/bin/node", []string{"--max-old-space-size=512", "/srv/billing/server.js"}, "billing"}, // generic file name: use the directory
		{"/usr/bin/node", []string{"/srv/api/payments.js"}, "payments"},
		{"/usr/bin/python3", []string{"-m", "uvicorn.main"}, "uvicorn"},
		{"/usr/bin/python3", []string{"/srv/reports/manage.py", "runserver"}, "reports"},
		{"/usr/local/bin/gunicorn", []string{"shop.wsgi:application", "-b", "0.0.0.0:8000"}, "shop"},
		{"/usr/bin/dotnet", []string{"/app/Orders.Api.dll"}, "Orders.Api"},
		{"/usr/sbin/nginx", nil, "nginx"},
		{"/opt/bin/mygoservice", []string{"--listen", ":9000"}, "mygoservice"},
		{"/usr/bin/java", nil, "java"},
	} {
		if got := DiscoverName(c.exe, c.args, "/"); got != c.want {
			t.Fatalf("%s %v: got %q want %q", c.exe, c.args, got, c.want)
		}
	}
	if n := DiscoverName("/usr/bin/node", []string{"/x/../etc/pass wd;rm -rf.js"}, ""); strings.ContainsAny(n, " /;") {
		t.Fatalf("names are sanitised: %q", n)
	}
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	r.Set(map[int]string{100: "checkout", 200: "billing"})
	if !r.Has(100) || r.Has(300) || r.Len() != 2 {
		t.Fatal("membership")
	}
	if !r.InLineage([]int{500, 400, 100}) || r.InLineage([]int{500, 400, 1}) {
		t.Fatal("lineage match")
	}
	r.Set(map[int]string{})
	if r.InLineage([]int{100}) {
		t.Fatal("set replaces")
	}
	for _, d := range []string{"sshd", "SSHD", "systemd-resolved"} {
		if !IgnoreListener(d) {
			t.Fatal(d)
		}
	}
	if IgnoreListener("java") || IgnoreListener("nginx") {
		t.Fatal("application servers are not ignored")
	}
}

// The raw.proc JSON is a contract with the backend rules (docs/app/platform-guide.md): the key names must not drift.
func TestRawProcContract(t *testing.T) {
	o := &Options{AgentID: "a1", Hostname: "web-01"}
	o.defaults()
	p := ProcInfo{PID: 500, PPID: 100, Name: "bash", Exe: "/bin/bash", Cmd: "bash -c id --password=x", User: "www-data", TTY: false,
		Container: strings.Repeat("c", 64), Ancestors: []Anc{{PID: 100, Name: "java", Exe: "/usr/bin/java"}}}
	prior := false
	check := func(raw []byte, want ...string) map[string]any {
		var m map[string]map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		proc := m["proc"]
		for _, k := range want {
			if _, ok := proc[k]; !ok {
				t.Fatalf("raw.proc lacks %q: %s", k, raw)
			}
		}
		return proc
	}
	ev := ProcessEvent(o, "procevent", p, &Priv{Kind: "setuid", Detail: "0"})
	proc := check(ev.Raw, "ancestors", "tty", "container_id", "priv_change", "sensor")
	anc := proc["ancestors"].([]any)[0].(map[string]any)
	if anc["pid"].(float64) != 100 || anc["name"] != "java" || anc["exe"] != "/usr/bin/java" {
		t.Fatalf("ancestor shape: %v", anc)
	}
	if pc := proc["priv_change"].(map[string]any); pc["kind"] != "setuid" || pc["detail"] != "0" {
		t.Fatalf("priv_change shape: %v", pc)
	}
	if ev.PID != 500 || ev.PPID != 100 || ev.ProcessName != "bash" || ev.EventType != "process" || ev.Source != "procevent" || ev.OS != "linux" {
		t.Fatalf("every event carries pid and ppid for the own-activity filter: %+v", ev)
	}
	if strings.Contains(ev.CommandLine, "x") && !strings.Contains(ev.CommandLine, "[REDACTED]") || strings.Contains(ev.CommandLine, "password=x") {
		t.Fatalf("command lines are redacted before leaving the sensor: %q", ev.CommandLine)
	}
	n := NetworkEvent(o, "procfs", p, "203.0.113.9", 443, "10.0.0.5", 51000, "api.example.com", &prior)
	proc = check(n.Raw, "dns", "prior_dns")
	if proc["prior_dns"] != false || n.DstIP != "203.0.113.9" || n.DstPort != 443 || n.EventType != "network" || n.PID != 500 {
		t.Fatalf("%+v %v", n, proc)
	}
	f := FileEvent(o, "fanotify", p, "/var/www/html/up.php", "create", "0644")
	proc = check(f.Raw, "op", "mode")
	if proc["op"] != "create" || f.FilePath != "/var/www/html/up.php" || f.EventType != "file" {
		t.Fatalf("%+v", f)
	}
	// Optional keys are omitted, not sent empty.
	bare := ProcessEvent(o, "procfs", ProcInfo{PID: 9, PPID: 1}, nil)
	var m map[string]map[string]any
	_ = json.Unmarshal(bare.Raw, &m)
	for _, k := range []string{"priv_change", "dns", "prior_dns", "op", "mode", "escape", "container_id", "ancestors"} {
		if _, ok := m["proc"][k]; ok {
			t.Fatalf("%s should be omitted when empty: %v", k, m["proc"])
		}
	}
	if got := p.Lineage(); len(got) != 2 || got[0] != 500 || got[1] != 100 {
		t.Fatalf("lineage: %v", got)
	}
	if got := (ProcInfo{PID: 7, PPID: 3}).Lineage(); len(got) != 2 || got[1] != 3 {
		t.Fatalf("without ancestry the parent is the lineage: %v", got)
	}
}

func TestDiscoverNameWindowsPaths(t *testing.T) {
	cases := []struct {
		exe  string
		args []string
		want string
	}{
		{`C:\Program Files\Java\bin\java.exe`, []string{"-jar", `D:\apps\orders\orders-1.2.3.jar`}, "orders"},
		{`C:\Program Files\nodejs\node.exe`, []string{`C:\srv\shop\server.js`}, "server"},
		{`C:\Python312\python.exe`, []string{"-m", "uvicorn"}, "uvicorn"},
		{`C:\Program Files\dotnet\dotnet.exe`, []string{`C:\inetpub\billing\Billing.Api.dll`}, "BillingApi"},
	}
	for _, c := range cases {
		got := DiscoverName(c.exe, c.args, "")
		if got == "" || got == "java" || got == "node" {
			t.Errorf("%s %v -> %q (want a name like %q)", c.exe, c.args, got, c.want)
		}
	}
	if baseOf(`C:\x\y\Evil.exe`) != "Evil.exe" {
		t.Error("baseOf must split on backslashes")
	}
}
