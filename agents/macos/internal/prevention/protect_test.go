package prevention

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"obsidianwatch/macos-agent/internal/response"
	"obsidianwatch/macos-agent/pkg/schema"
)

func drain(out chan schema.Event, want schema.EventType, d time.Duration) (schema.Event, bool) {
	deadline := time.After(d)
	for {
		select {
		case ev := <-out:
			if ev.EventType == want {
				return ev, true
			}
		case <-deadline:
			return schema.Event{}, false
		}
	}
}

func TestScanFindsListedFile(t *testing.T) {
	out := make(chan schema.Event, 64)
	fr := &fakeResp{}
	e := New(Options{Dir: t.TempDir(), Out: out, Responder: fr, AgentID: "ag", Host: "h", OS: "linux", Logger: quiet()})
	go e.Run(context.Background())
	dir := t.TempDir()
	bad := []byte("pretend malware body")
	h := sha256.Sum256(bad)
	sum := hex.EncodeToString(h[:])
	os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(dir, "tool.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "invoice.pdf.exe"), bad, 0o644)
	e.apply(Set{Version: "v1", Hashes: []Entry{{V: sum, Until: time.Now().Add(time.Hour).Unix(), Src: "threatfox"}}},
		map[string]string{"hash": Enforce}, nil)

	if r := e.scanAction(context.Background(), response.Params{Path: "relative/dir"}); r.OK {
		t.Fatal("relative folder accepted")
	}
	r := e.scanAction(context.Background(), response.Params{Path: dir})
	if !r.OK {
		t.Fatalf("scan: %s", r.Message)
	}
	if r2 := e.scanAction(context.Background(), response.Params{Path: dir}); r2.OK && e.ps().scanning.Load() {
		t.Error("second scan started while one runs")
	}
	sev, ok := drain(out, ScanEventType, 10*time.Second)
	if !ok {
		t.Fatal("no scan summary")
	}
	var raw map[string]any
	json.Unmarshal(sev.Raw, &raw)
	if raw["files_scanned"].(float64) != 3 || raw["threats_found"].(float64) != 1 {
		t.Errorf("summary: %s", sev.Raw)
	}
	if ex, _ := raw["executables"].([]any); len(ex) != 1 { // tool.sh; the listed .exe is a match, not an unknown
		t.Errorf("executables: %v", raw["executables"])
	}
	time.Sleep(200 * time.Millisecond)
	if calls := strings.Join(fr.list(), ";"); !strings.Contains(calls, "quarantine_file") || !strings.Contains(calls, "invoice.pdf.exe") {
		t.Errorf("listed file not quarantined: %s", calls)
	}
	st := e.Status()
	c := st["counters_24h"].(map[string]int64)
	if c["files_checked"] < 3 || c["threats_matched"] != 1 || c["threats_stopped"] != 1 {
		t.Errorf("counters: %v", c)
	}
	if st["list_version"] != "v1" || st["list_received"] == nil || st["last_scan"] == nil {
		t.Errorf("status: %v", st)
	}
}

func TestProtectionTest(t *testing.T) {
	old := testWriteDelay
	testWriteDelay = 0
	defer func() { testWriteDelay = old }()
	out := make(chan schema.Event, 64)
	fr := &fakeResp{}
	e := New(Options{Dir: t.TempDir(), Out: out, Responder: fr, Logger: quiet()})
	go e.Run(context.Background())
	extra := t.TempDir()
	e.apply(Set{Version: "v1"}, map[string]string{"hash": Off}, []string{extra})
	if r := e.testAction(context.Background(), response.Params{Match: "0123456789abcdef0123"}); r.OK || !strings.Contains(r.Message, "off") {
		t.Fatalf("hash off: %+v", r)
	}
	e.apply(Set{Version: "v1"}, map[string]string{"hash": Enforce}, []string{extra})
	r := e.testAction(context.Background(), response.Params{Match: "0123456789abcdef0123"})
	if !r.OK {
		t.Fatalf("test: %s", r.Message)
	}
	path := r.Data.(map[string]any)["path"].(string)
	defer os.Remove(path)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.checkFile(path) // what the watcher does on its next pass
	ev, ok := drain(out, EventType, 5*time.Second)
	if !ok {
		t.Fatal("no prevention event for the test file")
	}
	var raw map[string]any
	json.Unmarshal(ev.Raw, &raw)
	if raw["ioc_source"] != TestSource || raw["action"] != "quarantined" {
		t.Errorf("test event: %s", ev.Raw)
	}
	// a test is not a threat
	if c := e.Status()["counters_24h"].(map[string]int64); c["threats_matched"] != 0 {
		t.Errorf("test counted as a threat: %v", c)
	}
	if e.Status()["last_test"] == nil {
		t.Error("last_test missing")
	}
}
