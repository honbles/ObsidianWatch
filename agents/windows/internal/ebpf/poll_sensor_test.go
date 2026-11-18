package ebpf

import (
	"context"
	"testing"
	"time"

	"obsidianwatch/agent/pkg/schema"
)

type fakeHost struct {
	procs map[int]procRec
	conns []connRec
}

func (f *fakeHost) Procs() (map[int]procRec, error) {
	m := map[int]procRec{}
	for k, v := range f.procs {
		m[k] = v
	}
	return m, nil
}
func (f *fakeHost) TCP() ([]connRec, error) { return append([]connRec(nil), f.conns...), nil }

func TestPollSensorDiscoversAndReportsUnderService(t *testing.T) {
	t0 := time.Now().Add(-time.Hour)
	h := &fakeHost{
		procs: map[int]procRec{
			10: {PID: 10, PPID: 1, Name: "java.exe", Exe: `C:\Java\bin\java.exe`, Args: []string{"-jar", `C:\apps\orders\orders.jar`}, Start: t0},
			99: {PID: 99, PPID: 1, Name: "notepad.exe", Exe: `C:\Windows\notepad.exe`, Start: t0},
		},
		conns: []connRec{{State: "LISTEN", LocalIP: "0.0.0.0", LocalPort: 8080, PID: 10}},
	}
	var got []schema.Event
	s := newPollSensor(Options{AgentID: "a", Hostname: "h", OS: "windows", Emit: func(e schema.Event) bool { got = append(got, e); return true }}, h)
	s.tick() // prime: the existing service is discovered, nothing is reported
	if s.reg.Len() != 1 || !s.reg.Has(10) || len(got) != 0 {
		t.Fatalf("after prime: services=%d events=%d", s.reg.Len(), len(got))
	}
	now := time.Now()
	h.procs[11] = procRec{PID: 11, PPID: 10, Name: "cmd.exe", Exe: `C:\Windows\System32\cmd.exe`, Cmd: "cmd.exe /c whoami", Start: now}
	h.procs[100] = procRec{PID: 100, PPID: 99, Name: "calc.exe", Exe: `C:\Windows\calc.exe`, Start: now} // not under a service
	h.conns = append(h.conns,
		connRec{State: "ESTABLISHED", LocalIP: "10.0.0.5", LocalPort: 50000, RemoteIP: "203.0.113.9", RemotePort: 443, PID: 11},
		connRec{State: "ESTABLISHED", LocalIP: "10.0.0.5", LocalPort: 8080, RemoteIP: "198.51.100.2", RemotePort: 40000, PID: 10}, // inbound to the service
		connRec{State: "ESTABLISHED", LocalIP: "10.0.0.5", LocalPort: 50001, RemoteIP: "203.0.113.10", RemotePort: 443, PID: 99})  // not a service
	s.tick()
	var proc, net int
	for _, e := range got {
		switch e.EventType {
		case schema.EventTypeProcess:
			proc++
			if e.PID != 11 || e.PPID != 10 || e.ProcessName != "cmd.exe" {
				t.Errorf("process event: %+v", e)
			}
		case schema.EventTypeNetwork:
			net++
			if e.DstIP != "203.0.113.9" || e.PID != 11 {
				t.Errorf("network event: %+v", e)
			}
		}
	}
	if proc != 1 || net != 1 {
		t.Fatalf("want 1 process and 1 network event, got %d and %d (%d total)", proc, net, len(got))
	}
}

func TestPollSensorPidReuseEndsLineage(t *testing.T) {
	now := time.Now()
	procs := map[int]procRec{
		5: {PID: 5, PPID: 4, Start: now},                  // child
		4: {PID: 4, PPID: 1, Start: now.Add(time.Minute)}, // "parent" started after the child: reused pid
	}
	p, ok := info(procs, 5)
	if !ok || len(p.Ancestors) != 0 {
		t.Fatalf("reused parent pid must not appear as an ancestor: %+v", p.Ancestors)
	}
}

func TestPollSensorRunStops(t *testing.T) {
	s := newPollSensor(Options{Emit: func(schema.Event) bool { return true }, PollInterval: 10 * time.Millisecond}, &fakeHost{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
}
