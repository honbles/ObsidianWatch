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
	b.expect("ag", "t1", time.Minute, func(r actionResult) { got <- r })
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
	b.expect("ag", "t2", 30*time.Millisecond, func(r actionResult) { got <- r })
	select {
	case r := <-got:
		if r.OK || !strings.HasPrefix(r.Message, "timeout") {
			t.Fatalf("timeout result: %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("no timeout")
	}
	// malformed agent payload must not panic
	b.expect("ag", "t3", time.Minute, func(r actionResult) { got <- r })
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

func TestHuntWaitWindows(t *testing.T) {
	cases := []struct {
		offline, wait string
		hours         int
		mode          string
		window        time.Duration
		bad           bool
	}{
		{"", "", 0, "", 0, false},
		{"skip", "7d", 0, "", 0, false},
		{"wait", "1h", 0, "1h", time.Hour, false},
		{"wait", "24h", 0, "24h", 24 * time.Hour, false},
		{"wait", "7d", 0, "7d", 7 * 24 * time.Hour, false},
		{"wait", "until_done", 0, "until_done", huntHardExpiry, false},
		{"wait", "", 0, "24h", 24 * time.Hour, false},     // older clients
		{"wait", "", 999, "168h", 168 * time.Hour, false}, // capped
		{"wait", "forever", 0, "", 0, true},
		{"later", "", 0, "", 0, true},
	}
	for _, c := range cases {
		mode, win, err := huntWait(c.offline, c.wait, c.hours)
		if (err != nil) != c.bad || mode != c.mode || win != c.window {
			t.Errorf("huntWait(%q,%q,%d) = %q %s %v", c.offline, c.wait, c.hours, mode, win, err)
		}
	}
	if huntHardExpiry > 31*24*time.Hour || huntHardExpiry <= 7*24*time.Hour {
		t.Errorf("until_done hard expiry %s out of range", huntHardExpiry)
	}
}

func TestQueuedHuntsAreReadOnlyQueries(t *testing.T) {
	for kind := range liveHuntKinds {
		action, params, ok := queuedHuntFrame(store.QueuedHunt{ID: "h", Kind: kind})
		if !ok || action != "query" || !strings.Contains(string(params), `"kind":"`+kind+`"`) {
			t.Errorf("%s: %q %s %v", kind, action, params, ok)
		}
	}
	for _, kind := range []string{"isolate", "kill_process", "quarantine_file", "shell", ""} {
		if _, _, ok := queuedHuntFrame(store.QueuedHunt{ID: "h", Kind: kind}); ok {
			t.Errorf("%q must never be sent from the offline queue", kind)
		}
	}
}

func TestHuntResultStates(t *testing.T) {
	for status, want := range map[string]string{"pending": "running", "ok": "answered", "failed": "answered", "timeout": "answered",
		"queued": "queued", "expired": "expired", "skipped": "skipped", "offline": "skipped"} {
		if got := store.HuntResultState(status); got != want {
			t.Errorf("%s -> %s, want %s", status, got, want)
		}
	}
}

func TestValidateMoreActions(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	good := []struct {
		a string
		p actionParams
	}{
		{"delete_file", actionParams{Path: "/tmp/x"}}, {"delete_file", actionParams{Path: `C:\x.exe`, SHA256: sha}},
		{"delete_quarantined", actionParams{ID: "0123456789abcdef"}}, {"file_info", actionParams{Path: "/etc/hosts"}},
		{"collect_file", actionParams{Path: "/tmp/x"}}, {"block_ip", actionParams{IP: "203.0.113.9"}}, {"unblock_ip", actionParams{IP: "2001:db8::1"}},
		{"list_blocked_ips", actionParams{}}, {"disable_user", actionParams{User: "j.doe"}}, {"enable_user", actionParams{User: "John Smith"}},
		{"isolate", actionParams{NoBlockPage: true}},
	}
	for _, c := range good {
		if m := validateAction(c.a, c.p); m != "" {
			t.Errorf("%s %+v refused: %s", c.a, c.p, m)
		}
	}
	bad := []struct {
		a string
		p actionParams
	}{
		{"delete_file", actionParams{Path: "rel"}}, {"delete_file", actionParams{Path: "/x", SHA256: "abc"}},
		{"delete_quarantined", actionParams{ID: "../x"}}, {"collect_file", actionParams{}},
		{"block_ip", actionParams{IP: "10.0.0.0/8"}}, {"block_ip", actionParams{IP: "127.0.0.1"}}, {"block_ip", actionParams{IP: "evil.com"}},
		{"disable_user", actionParams{User: "a'b"}}, {"disable_user", actionParams{User: "-r"}}, {"enable_user", actionParams{}},
	}
	for _, c := range bad {
		if validateAction(c.a, c.p) == "" {
			t.Errorf("%s %+v accepted", c.a, c.p)
		}
	}
	if safeFileName(`web-01_..\evil "x".exe`) != "web-01_.._evil__x_.exe" {
		t.Error(safeFileName(`web-01_..\evil "x".exe`))
	}
}
