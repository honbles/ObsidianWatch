package collector

import "testing"

func TestParseESExec(t *testing.T) {
	line := `{"event":{"exec":{"args":["/bin/ls","-l","/tmp"],"target":{"audit_token":{"pid":4321,"euid":501},"ppid":100,"executable":{"path":"/bin/ls"}}}},"event_type":9,"time":"2026-11-04T10:11:12.123456789Z"}`
	ev, err := parseESExec([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if ev.PID != 4321 || ev.PPID != 100 || ev.UID != 501 || ev.Exe != "/bin/ls" || len(ev.Args) != 3 || ev.Args[1] != "-l" {
		t.Fatalf("unexpected: %+v", ev)
	}
	if ev.Time.Year() != 2026 || ev.Time.Nanosecond() != 123456789 {
		t.Fatalf("time not parsed: %v", ev.Time)
	}
}

func TestParseESExecRejects(t *testing.T) {
	for name, line := range map[string]string{
		"not json": `garbage`,
		"not exec": `{"event":{"open":{"file":{"path":"/x"}}}}`,
		"no pid":   `{"event":{"exec":{"target":{"executable":{"path":"/bin/ls"}}}}}`,
		"no path":  `{"event":{"exec":{"target":{"audit_token":{"pid":5}}}}}`,
	} {
		if _, err := parseESExec([]byte(line)); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
	// A bad timestamp must not discard an otherwise good event.
	ev, err := parseESExec([]byte(`{"time":"nope","event":{"exec":{"target":{"audit_token":{"pid":9},"executable":{"path":"/bin/x"}}}}}`))
	if err != nil || ev.PID != 9 || ev.Time.IsZero() {
		t.Fatalf("bad time should fall back to now: %v %+v", err, ev)
	}
}
