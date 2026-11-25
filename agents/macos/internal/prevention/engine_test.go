package prevention

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"obsidianwatch/macos-agent/internal/response"
	"obsidianwatch/macos-agent/pkg/schema"
)

type fakeResp struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeResp) Handle(_ context.Context, action string, p response.Params) response.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	arg := p.IP + p.Path
	if p.PID > 0 {
		arg = p.Image
	}
	f.calls = append(f.calls, action+" "+arg)
	return response.Result{OK: true, Message: "done"}
}

func (f *fakeResp) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const evilHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testEngine(t *testing.T, modes map[string]string) (*Engine, *fakeResp, chan schema.Event) {
	out := make(chan schema.Event, 100)
	fr := &fakeResp{}
	e := New(Options{Dir: t.TempDir(), Out: out, Responder: fr, AgentID: "ag", Host: "h", OS: "linux", Logger: quiet(),
		Protected: func(a netip.Addr) bool { return a.String() == "198.51.100.1" }})
	until := time.Now().Add(time.Hour).Unix()
	e.Update(&Set{Version: "v1",
		IPs:     []Entry{{V: "45.9.148.10", Until: until, Src: "threatfox"}, {V: "198.51.100.1", Until: until}, {V: "45.9.148.11", Until: time.Now().Add(-time.Hour).Unix()}},
		Hashes:  []Entry{{V: evilHash, Until: until, Src: "manual"}},
		Domains: []Entry{{V: "evil.example", Until: until, Src: "threatfox"}},
	}, modes, nil)
	go e.Run(context.Background())
	return e, fr, out
}

func next(t *testing.T, out chan schema.Event) map[string]any {
	select {
	case ev := <-out:
		var m map[string]any
		json.Unmarshal(ev.Raw, &m)
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("no prevention event")
		return nil
	}
}

func TestAuditChangesNothing(t *testing.T) {
	e, fr, out := testEngine(t, map[string]string{"ip": Audit, "hash": Audit, "domain": Audit})
	e.Inspect(&schema.Event{EventType: schema.EventTypeNetwork, DstIP: "45.9.148.10", PID: 5})
	if m := next(t, out); m["action"] != "audit" || m["indicator"] != "45.9.148.10" {
		t.Fatalf("%v", m)
	}
	raw, _ := json.Marshal(map[string]any{"action": "exec"})
	e.Inspect(&schema.Event{EventType: schema.EventTypeProcess, FileHash: evilHash, PID: 7, ImagePath: "/tmp/x", Raw: raw})
	if m := next(t, out); m["action"] != "audit" || m["kind"] != "hash" {
		t.Fatalf("%v", m)
	}
	time.Sleep(100 * time.Millisecond)
	if c := fr.list(); len(c) != 0 {
		t.Fatalf("audit made changes: %v", c)
	}
}

func TestEnforceActions(t *testing.T) {
	e, fr, out := testEngine(t, map[string]string{"ip": Enforce, "hash": Enforce, "domain": Enforce})
	// Expired, protected and unknown addresses never match.
	for _, ip := range []string{"45.9.148.11", "198.51.100.1", "8.8.8.8"} {
		e.Inspect(&schema.Event{EventType: schema.EventTypeNetwork, DstIP: ip, PID: 5})
	}
	e.Inspect(&schema.Event{EventType: schema.EventTypeNetwork, DstIP: "45.9.148.10", PID: 5})
	if m := next(t, out); m["action"] != "ip_blocked" {
		t.Fatalf("ip: %v", m)
	}
	raw, _ := json.Marshal(map[string]any{"action": "exec"})
	e.Inspect(&schema.Event{EventType: schema.EventTypeProcess, FileHash: evilHash, PID: 7, ImagePath: "/tmp/x", Raw: raw})
	if m := next(t, out); m["action"] != "killed+quarantined" {
		t.Fatalf("hash: %v", m)
	}
	dns, _ := json.Marshal(map[string]any{"query_name": "cdn.evil.example", "query_results": "type: 5 x;::ffff:45.33.2.1;10.0.0.9;"})
	e.Inspect(&schema.Event{EventType: "dns", Raw: dns})
	m := next(t, out)
	if m["action"] != "ip_blocked" || m["matched_domain"] != "evil.example" {
		t.Fatalf("dns: %v", m)
	}
	want := []string{"block_ip 45.9.148.10", "kill_process /tmp/x", "quarantine_file /tmp/x", "block_ip 45.33.2.1"}
	got := fr.list()
	if len(got) != len(want) {
		t.Fatalf("calls %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("calls %v", got)
		}
	}
	// Blocks made for a domain answer are lifted when they lapse.
	e.mu.Lock()
	for a := range e.owned {
		e.owned[a] = time.Now().Add(-time.Second)
	}
	e.mu.Unlock()
	e.expire(context.Background())
	if c := fr.list(); c[len(c)-1] != "unblock_ip 45.33.2.1" && c[len(c)-2] != "unblock_ip 45.33.2.1" {
		t.Fatalf("owned block not lifted: %v", c)
	}
}

func TestSetSurvivesRestartAndNewFilesAreChecked(t *testing.T) {
	e, _, _ := testEngine(t, map[string]string{"ip": Audit, "hash": Enforce, "domain": Off})
	e2 := New(Options{Dir: e.dir, Logger: quiet()})
	if ips, hashes, domains, v := e2.Counts(); ips != 1 || hashes != 1 || domains != 1 || v != "v1" || e2.Mode("hash") != Enforce {
		t.Fatalf("restored %d %d %d %s %s", ips, hashes, domains, v, e2.Mode("hash"))
	}
	// A dropped file with a listed hash is quarantined once it stops changing.
	dir := t.TempDir()
	payload := []byte("not really malware")
	f := filepath.Join(dir, "invoice.exe")
	os.WriteFile(f, payload, 0o644)
	sum, _ := hashPath(f)
	out := make(chan schema.Event, 10)
	fr := &fakeResp{}
	e3 := New(Options{Dir: t.TempDir(), Out: out, Responder: fr, Logger: quiet()})
	e3.Update(&Set{Version: "v2", Hashes: []Entry{{V: sum, Until: time.Now().Add(time.Hour).Unix()}}}, map[string]string{"hash": Enforce}, nil)
	go e3.Run(context.Background())
	seen := map[string]*fileSeen{}
	os.WriteFile(filepath.Join(dir, "old.txt"), []byte("x"), 0o644)
	e3.scanOnce(context.Background(), []string{dir}, seen, false) // first sight
	for _, s := range seen {
		s.first = time.Now().Add(-time.Minute) // stable for long enough
	}
	e3.scanOnce(context.Background(), []string{dir}, seen, false)
	m := next(t, out)
	if m["action"] != "quarantined" || m["path"] != f {
		t.Fatalf("%v", m)
	}
}

func TestSha256OfFormats(t *testing.T) {
	if sha256Of("SHA1=abc,MD5=x,SHA256="+evilHash+",IMPHASH=y") != evilHash || sha256Of(evilHash) != evilHash || sha256Of("MD5=x") != "" {
		t.Fatal("sha256Of")
	}
}

func TestProcessWithoutHashIsHashedFromImage(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "dropper")
	os.WriteFile(img, []byte("payload-bytes"), 0o755)
	sum, _ := hashPath(img)
	out := make(chan schema.Event, 10)
	fr := &fakeResp{}
	e := New(Options{Dir: t.TempDir(), Out: out, Responder: fr, Logger: quiet()})
	e.Update(&Set{Version: "v", Hashes: []Entry{{V: sum, Until: time.Now().Add(time.Hour).Unix()}}}, map[string]string{"hash": Enforce}, nil)
	go e.Run(context.Background())
	e.Inspect(&schema.Event{EventType: schema.EventTypeProcess, EventID: 4688, PID: 99, ImagePath: img})
	if m := next(t, out); m["action"] != "killed+quarantined" || m["indicator"] != sum {
		t.Fatalf("%v", m)
	}
}

func TestSystemBinaryNeverKilled(t *testing.T) {
	e, fr, out := testEngine(t, map[string]string{"hash": Enforce})
	raw, _ := json.Marshal(map[string]any{"action": "exec"})
	e.Inspect(&schema.Event{EventType: schema.EventTypeProcess, FileHash: evilHash, PID: 8, ImagePath: "/usr/bin/sleep", Raw: raw})
	if m := next(t, out); m["action"] != "failed" {
		t.Fatalf("%v", m)
	}
	time.Sleep(50 * time.Millisecond)
	if c := fr.list(); len(c) != 0 {
		t.Fatalf("acted on a system binary: %v", c)
	}
}
