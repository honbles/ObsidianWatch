package response

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testHandler(t *testing.T, urls ...string) *Handler {
	return New(t.TempDir(), urls, slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

func TestFilterTable(t *testing.T) {
	cols := []string{"pid", "name", "cmdline"}
	rows := [][]string{{"1", "bash", "bash -l"}, {"2", "curl", "curl http://evil.test"}, {"3", "Curl", "x"}}
	if got := filterTable(cols, rows, "curl", 10); len(got.Rows) != 2 {
		t.Fatalf("any-column match: %v", got.Rows)
	}
	if got := filterTable(cols, rows, "name:curl name:evil", 10); len(got.Rows) != 0 {
		t.Fatalf("AND across columns should fail: %v", got.Rows)
	}
	if got := filterTable(cols, rows, "name:curl cmdline:evil", 10); len(got.Rows) != 1 {
		t.Fatalf("column terms: %v", got.Rows)
	}
	if got := filterTable(cols, rows, "", 2); len(got.Rows) != 2 || !got.Truncated {
		t.Fatalf("limit/truncate: %+v", got)
	}
}

func TestGuardKill(t *testing.T) {
	for _, c := range []struct {
		pid  int
		name string
		bad  bool
	}{{1, "init", true}, {os.Getpid(), "x", true}, {4242, "/usr/lib/systemd/systemd", true}, {4242, `C:\Windows\System32\lsass.exe`, true},
		{4242, "/opt/obsidianwatch-agent", true}, {4242, "/usr/bin/curl", false}} {
		if err := guardKill(c.pid, c.name); (err != nil) != c.bad {
			t.Errorf("guardKill(%d,%q)=%v want bad=%v", c.pid, c.name, err, c.bad)
		}
	}
}

func TestImageMatches(t *testing.T) {
	if !imageMatches("", "/x/y") || !imageMatches("curl", "/usr/bin/curl") || !imageMatches(`C:\a\B.EXE`, "c:/a/b.exe") {
		t.Fatal("should match")
	}
	if imageMatches("curl", "/usr/bin/wget") {
		t.Fatal("should not match")
	}
}

func TestQuarantineRoundTrip(t *testing.T) {
	h := testHandler(t)
	f := filepath.Join(t.TempDir(), "mal.bin")
	os.WriteFile(f, []byte("payload"), 0o755)
	r := h.quarantine(f)
	if !r.OK {
		t.Fatal(r.Message)
	}
	if _, err := os.Stat(f); err == nil {
		t.Fatal("original still present")
	}
	list := h.listQuarantine()
	if len(list) != 1 || list[0].SHA256 == "" || list[0].Orig != f {
		t.Fatalf("list: %+v", list)
	}
	if r := h.restore(list[0].ID); !r.OK {
		t.Fatal(r.Message)
	}
	if b, _ := os.ReadFile(f); string(b) != "payload" {
		t.Fatal("content not restored")
	}
	if r := h.quarantine("relative/path"); r.OK {
		t.Fatal("relative path accepted")
	}
	if r := h.quarantine(h.dir + "/response.json"); r.OK {
		t.Fatal("agent data accepted")
	}
	if r := h.restore("../etc"); r.OK {
		t.Fatal("traversal id accepted")
	}
}

func TestResolveAllow(t *testing.T) {
	h := testHandler(t, "https://10.1.2.3:8443", "https://10.1.2.3:8080", "https://[2001:db8::5]:443")
	a, err := h.resolveAllow([]string{"192.0.2.9", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(addrStrings(a), ",")
	if got != "10.1.2.3,192.0.2.9,2001:db8::5" {
		t.Fatalf("got %s", got)
	}
	if _, err := testHandler(t).resolveAllow(nil); err == nil {
		t.Fatal("empty allowlist must refuse to isolate")
	}
}

func TestFileFind(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "Evil.exe"), []byte("abc"), 0o644)
	os.WriteFile(filepath.Join(d, "ok.txt"), []byte("x"), 0o644)
	h := testHandler(t)
	r := h.fileFind(context.Background(), Params{Path: d, Match: "evil"}, 10)
	if tb, _ := r.Data.(Table); !r.OK || len(tb.Rows) != 1 {
		t.Fatalf("%+v", r)
	}
	// sha256("abc")
	r = h.fileFind(context.Background(), Params{Path: d, Match: "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}, 10)
	if tb, _ := r.Data.(Table); len(tb.Rows) != 1 {
		t.Fatalf("hash search: %+v", r)
	}
	if r := h.fileFind(context.Background(), Params{Path: d, Match: "sha256:zz"}, 10); r.OK {
		t.Fatal("bad hash accepted")
	}
}

func inRanges(t *testing.T, ranges []string, ip string) bool {
	a := netip.MustParseAddr(ip)
	for _, r := range ranges {
		lo, hi, ok := strings.Cut(r, "-")
		if !ok {
			hi = lo
		}
		l, h := netip.MustParseAddr(lo), netip.MustParseAddr(hi)
		if a.Is4() == l.Is4() && a.Compare(l) >= 0 && a.Compare(h) <= 0 {
			return true
		}
	}
	return false
}

func TestBlockRangesCoverage(t *testing.T) {
	allow := []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.6"), netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8::5")}
	r := blockRanges(allow, true)
	for _, ip := range []string{"10.0.0.5", "10.0.0.6", "203.0.113.9", "127.0.0.1", "127.9.9.9", "0.0.0.0", "255.255.255.255", "2001:db8::5", "::1", "fe80::1", "ff02::1"} {
		if inRanges(t, r, ip) {
			t.Errorf("%s must NOT be blocked", ip)
		}
	}
	for _, ip := range []string{"10.0.0.4", "10.0.0.7", "8.8.8.8", "192.168.1.1", "1.1.1.1", "203.0.113.8", "203.0.113.10", "2001:db8::4", "2001:db8::6", "2606:4700::1111", "128.0.0.1", "224.0.0.251"} {
		if !inRanges(t, r, ip) {
			t.Errorf("%s must be blocked", ip)
		}
	}
	if r2 := blockRanges(allow, false); inRanges(t, r2, "fe80::1") == false {
		t.Error("link-local v6 must be blocked when not exempted")
	}
}

func TestProtectedPath(t *testing.T) {
	for _, p := range []string{"/bin/bash", "/usr/bin/curl", "/etc/passwd", "/usr/lib/x86_64/libc.so", `C:\Windows\System32\cmd.exe`} {
		if !protectedPath(p) {
			t.Errorf("%s must be protected", p)
		}
	}
	for _, p := range []string{"/tmp/payload", "/home/u/.cache/x", "/var/tmp/a", `C:\Users\u\AppData\Local\Temp\a.exe`, "/opt/app/bin"} {
		if protectedPath(p) {
			t.Errorf("%s must not be protected", p)
		}
	}
}
