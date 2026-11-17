package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestHuntLibraryQueriesCompile(t *testing.T) {
	seen := map[string]bool{}
	for _, h := range huntLibrary {
		if seen[h.ID] {
			t.Errorf("duplicate id %s", h.ID)
		}
		seen[h.ID] = true
		switch h.Mode {
		case "history":
			e, err := store.ParseEventQuery(h.Query)
			if err != nil || e == nil {
				t.Errorf("%s: %v", h.ID, err)
				continue
			}
			if _, _, err := e.SQL(1); err != nil {
				t.Errorf("%s: compile: %v", h.ID, err)
			}
		case "live":
			if !liveHuntKinds[h.Kind] {
				t.Errorf("%s: unknown live kind %q", h.ID, h.Kind)
			}
		default:
			t.Errorf("%s: bad mode %q", h.ID, h.Mode)
		}
		if h.Title == "" || h.Desc == "" {
			t.Errorf("%s: missing text", h.ID)
		}
	}
}

func TestValidateAction(t *testing.T) {
	bad := []struct {
		a string
		p actionParams
	}{
		{"isolate", actionParams{TTLMinutes: -1}}, {"isolate", actionParams{TTLMinutes: 999999}},
		{"kill_process", actionParams{}}, {"kill_process", actionParams{PID: 1}}, {"kill_process", actionParams{PID: -5}},
		{"quarantine_file", actionParams{Path: "relative.exe"}}, {"quarantine_file", actionParams{Path: "../etc/passwd"}},
		{"quarantine_file", actionParams{Path: "/tmp/a\x00b"}},
		{"restore_file", actionParams{ID: "../../x"}}, {"restore_file", actionParams{ID: "ABCDEF0123456789"}},
		{"format_disk", actionParams{}}, {"", actionParams{}},
	}
	for _, c := range bad {
		if validateAction(c.a, c.p) == "" {
			t.Errorf("%q %+v should be rejected", c.a, c.p)
		}
	}
	good := []struct {
		a string
		p actionParams
	}{
		{"isolate", actionParams{}}, {"isolate", actionParams{TTLMinutes: 60}}, {"release", actionParams{}},
		{"kill_process", actionParams{PID: 4242, Tree: true}}, {"quarantine_file", actionParams{Path: `C:\Users\a\evil.exe`}},
		{"quarantine_file", actionParams{Path: "/tmp/evil"}}, {"restore_file", actionParams{ID: "0123456789abcdef"}}, {"list_quarantine", actionParams{}},
	}
	for _, c := range good {
		if m := validateAction(c.a, c.p); m != "" {
			t.Errorf("%q %+v rejected: %s", c.a, c.p, m)
		}
	}
}

func TestActionBroker(t *testing.T) {
	b := newActionBroker()
	got := make(chan actionResult, 1)
	b.expect("t1", time.Minute, func(r actionResult) { got <- r })
	b.deliver("t1", json.RawMessage(`{"ok":true,"message":"done","data":{"x":1}}`))
	select {
	case r := <-got:
		if !r.OK || r.Message != "done" {
			t.Fatalf("%+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("no delivery")
	}
	b.deliver("t1", json.RawMessage(`{"ok":true}`)) // second delivery is ignored
	select {
	case <-got:
		t.Fatal("delivered twice")
	case <-time.After(50 * time.Millisecond):
	}
	// timeout path
	b.expect("t2", 30*time.Millisecond, func(r actionResult) { got <- r })
	select {
	case r := <-got:
		if r.OK || !strings.HasPrefix(r.Message, "timeout") {
			t.Fatalf("timeout result: %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("no timeout")
	}
	// malformed agent payload must not panic
	b.expect("t3", time.Minute, func(r actionResult) { got <- r })
	b.deliver("t3", json.RawMessage(`not json`))
	if r := <-got; r.OK {
		t.Fatal("malformed payload treated as success")
	}
}

func TestAbsPath(t *testing.T) {
	for p, want := range map[string]bool{"/etc/x": true, `C:\a\b`: true, `c:/a`: true, `\\srv\share\f`: true, "rel/x": false, "": false, "~/x": false} {
		if absPath(p) != want {
			t.Errorf("absPath(%q)=%v", p, !want)
		}
	}
}
