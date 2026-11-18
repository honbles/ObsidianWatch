//go:build windows

package collector

// components_windows.go - per-component health reported in every health event, so the console
// can show at a glance which parts of the agent (and the services it depends on) are working.

import (
	"sync"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Component is one row of the health board. State is "ok", "warn" or "error".
type Component struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

var (
	compMu     sync.Mutex
	compFailed = map[string]string{} // collector name -> error text
)

// ReportCollectorFailure marks a collector as failed (it exited with an error or panicked).
func ReportCollectorFailure(name, detail string) {
	compMu.Lock()
	compFailed[name] = detail
	compMu.Unlock()
}

// ReportCollectorOK clears a failure (a collector that restarted).
func ReportCollectorOK(name string) {
	compMu.Lock()
	delete(compFailed, name)
	compMu.Unlock()
}

func svcState(m *mgr.Mgr, name string) (string, bool) {
	s, err := m.OpenService(name)
	if err != nil {
		return "not installed", false
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "unknown", false
	}
	switch st.State {
	case svc.Running:
		return "running", true
	case svc.Stopped:
		return "stopped", true
	}
	return "starting/stopping", true
}

// buildComponents assembles the board. collectors is the list the agent started.
func buildComponents(collectors []string) []Component {
	var out []Component
	compMu.Lock()
	failed := map[string]string{}
	for k, v := range compFailed {
		failed[k] = v
	}
	compMu.Unlock()
	for _, c := range collectors {
		if why, bad := failed[c]; bad {
			out = append(out, Component{c + " collector", "error", why})
		} else {
			out = append(out, Component{c + " collector", "ok", "running"})
		}
	}
	for c, why := range failed {
		found := false
		for _, n := range collectors {
			found = found || n == c
		}
		if !found {
			out = append(out, Component{c + " collector", "error", why})
		}
	}
	// Services the telemetry depends on.
	if m, err := mgr.Connect(); err == nil {
		defer m.Disconnect()
		sysmon := Component{Name: "Sysmon", State: "error", Detail: "not installed"}
		for _, n := range []string{"Sysmon64", "Sysmon"} {
			if st, found := svcState(m, n); found {
				sysmon.Detail = st
				if st == "running" {
					sysmon.State = "ok"
				}
				break
			}
		}
		out = append(out, sysmon)
		for _, s := range []struct{ svc, label string }{{"EventLog", "Windows Event Log service"}, {"WinDefend", "Microsoft Defender service"}} {
			st, _ := svcState(m, s.svc)
			state := "ok"
			if st != "running" {
				state = "warn"
				if s.svc == "EventLog" {
					state = "error"
				}
			}
			out = append(out, Component{s.label, state, st})
		}
	}
	q := GlobalHealth.QueueDepth.Load()
	qs := Component{"Event queue", "ok", ""}
	if q > 5000 {
		qs.State, qs.Detail = "warn", "backlog building up"
	}
	out = append(out, qs)
	return out
}

