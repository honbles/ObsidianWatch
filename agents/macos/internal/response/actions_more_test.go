package response

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	p := filepath.Join(t.TempDir(), "evil.bin")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestDeleteFile(t *testing.T) {
	h := testHandler(t)
	ctx := context.Background()
	p := writeTemp(t, "payload")
	if r := h.Handle(ctx, "delete_file", Params{Path: p, SHA256: sum("other")}); r.OK {
		t.Fatal("deleted although the hash did not match")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("file gone after a refused delete")
	}
	r := h.Handle(ctx, "delete_file", Params{Path: p, SHA256: strings.ToUpper(sum("payload"))})
	if !r.OK || r.Data.(FileFacts).SHA256 != sum("payload") {
		t.Fatalf("delete: %+v", r)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file still there")
	}
	for _, bad := range []string{"", "relative/x", "/etc/passwd", "/usr/bin/ls", filepath.Join(h.dir, "response.json")} {
		if r := h.Handle(ctx, "delete_file", Params{Path: bad}); r.OK {
			t.Errorf("deleted %q", bad)
		}
	}
	if r := h.Handle(ctx, "delete_file", Params{Path: t.TempDir()}); r.OK {
		t.Error("deleted a directory")
	}
}

func TestDeleteQuarantined(t *testing.T) {
	h := testHandler(t)
	ctx := context.Background()
	p := writeTemp(t, "malware")
	q := h.Handle(ctx, "quarantine_file", Params{Path: p})
	if !q.OK {
		t.Fatalf("quarantine: %+v", q)
	}
	id := q.Data.(QItem).ID
	if r := h.Handle(ctx, "delete_quarantined", Params{ID: id}); !r.OK {
		t.Fatalf("delete quarantined: %+v", r)
	}
	if len(h.listQuarantine()) != 0 {
		t.Fatal("vault still lists it")
	}
	if r := h.Handle(ctx, "restore_file", Params{ID: id}); r.OK {
		t.Fatal("restored a deleted item")
	}
	if r := h.Handle(ctx, "delete_quarantined", Params{ID: "../x"}); r.OK {
		t.Fatal("path in id accepted")
	}
}

func TestFileInfoAndCollect(t *testing.T) {
	h := testHandler(t)
	ctx := context.Background()
	p := writeTemp(t, "hello")
	r := h.Handle(ctx, "file_info", Params{Path: p})
	if f := r.Data.(FileFacts); !r.OK || f.SHA256 != sum("hello") || f.Size != 5 || f.Content != "" {
		t.Fatalf("info: %+v", r)
	}
	r = h.Handle(ctx, "collect_file", Params{Path: p})
	f := r.Data.(FileFacts)
	if b, _ := base64.StdEncoding.DecodeString(f.Content); !r.OK || string(b) != "hello" || f.SHA256 != sum("hello") {
		t.Fatalf("collect: %+v", r)
	}
	big := writeTemp(t, strings.Repeat("x", maxCollectBytes+1))
	if r := h.Handle(ctx, "collect_file", Params{Path: big}); r.OK {
		t.Fatal("collected past the limit")
	}
	if r := h.Handle(ctx, "collect_file", Params{Path: filepath.Join(h.dir, "response.json")}); r.OK {
		t.Fatal("collected the agent's own data")
	}
}

func TestIPBlockGuards(t *testing.T) {
	h := testHandler(t, "https://10.0.0.5:8443")
	if err := h.saveIso(isoState{Allow: []string{"10.0.0.6"}, HostIPs: map[string][]string{"siem.corp": {"10.0.0.7"}}}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"10.0.0.5", "10.0.0.6", "10.0.0.7", "127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "fe80::1", "10.0.0.0/8", "evil.com", ""} {
		if _, why := h.blockableIP(bad); why == "" {
			t.Errorf("%q accepted", bad)
		}
	}
	if a, why := h.blockableIP("::ffff:203.0.113.9"); why != "" || a.String() != "203.0.113.9" {
		t.Errorf("mapped address: %v %s", a, why)
	}
	if r := h.Handle(context.Background(), "unblock_ip", Params{IP: "203.0.113.9"}); r.OK {
		t.Error("unblocked an address that was never blocked")
	}
}

func TestAccountGuards(t *testing.T) {
	for _, bad := range []string{"root", "SYSTEM", "", "-rf", "a'b", "a;b", "..\\x", strings.Repeat("a", 70)} {
		if _, why := checkUser(bad); why == "" {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, ok := range []string{"alice", "j.doe", "svc_backup", "John Smith"} {
		if _, why := checkUser(ok); why != "" {
			t.Errorf("%q refused: %s", ok, why)
		}
	}
}
