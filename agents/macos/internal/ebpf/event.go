package ebpf

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
)

// Anc is one ancestor in a process's lineage (nearest parent first).
type Anc struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Exe  string `json:"exe"`
}

// ProcInfo is what the sensor knows about a process.
type ProcInfo struct {
	PID, PPID int
	Start     time.Time
	Name, Exe string
	Cmd, User string
	UID       int
	TTY       bool
	Container string
	Ancestors []Anc
}

// Priv describes a privilege change (setuid, capability gain).
type Priv struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// RawProc is the raw.proc block the Application rules read (docs/app/rules.md).
type RawProc struct {
	Ancestors  []Anc  `json:"ancestors,omitempty"`
	TTY        bool   `json:"tty"`
	Container  string `json:"container_id,omitempty"`
	PrivChange *Priv  `json:"priv_change,omitempty"`
	Escape     string `json:"escape,omitempty"`
	DNS        string `json:"dns,omitempty"`
	PriorDNS   *bool  `json:"prior_dns,omitempty"`
	Op         string `json:"op,omitempty"`
	Mode       string `json:"mode,omitempty"`
	Sensor     string `json:"sensor,omitempty"`
}

func newEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Lineage returns the pids to test against the registry: the process, then its ancestors.
func (p ProcInfo) Lineage() []int {
	out := []int{p.PID}
	for _, a := range p.Ancestors {
		out = append(out, a.PID)
	}
	if len(p.Ancestors) == 0 && p.PPID > 0 {
		out = append(out, p.PPID)
	}
	return out
}

// build creates an agent event for a process. source names the mechanism ("ebpf", "procevent",
// "procfs", "fanotify"); the rules ignore it, health output and analysts use it.
func build(o *Options, typ schema.EventType, source string, p ProcInfo, rp RawProc) schema.Event {
	rp.Ancestors, rp.TTY, rp.Container = p.Ancestors, p.TTY, p.Container
	rp.Sensor = source
	raw, _ := json.Marshal(map[string]any{"proc": rp})
	name := p.Name
	if name == "" {
		name = baseOf(p.Exe)
	}
	return schema.Event{
		ID: newEventID(), Time: time.Now().UTC(), AgentID: o.AgentID, Host: o.Hostname, OS: o.OS,
		EventType: typ, Severity: schema.SeverityInfo, Source: source, Raw: raw,
		PID: p.PID, PPID: p.PPID, ProcessName: name, ImagePath: p.Exe, CommandLine: RedactCmd(p.Cmd), UserName: p.User,
	}
}

func baseOf(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 { // either separator: Windows paths use a backslash
		return p[i+1:]
	}
	return p
}

// ProcessEvent builds a process (exec) event.
func ProcessEvent(o *Options, source string, p ProcInfo, priv *Priv) schema.Event {
	return build(o, schema.EventTypeProcess, source, p, RawProc{PrivChange: priv})
}

// NetworkEvent builds an outbound-connection event.
func NetworkEvent(o *Options, source string, p ProcInfo, dstIP string, dstPort int, srcIP string, srcPort int, dns string, priorDNS *bool) schema.Event {
	ev := build(o, schema.EventTypeNetwork, source, p, RawProc{DNS: dns, PriorDNS: priorDNS})
	ev.DstIP, ev.DstPort, ev.SrcIP, ev.SrcPort, ev.Proto = dstIP, dstPort, srcIP, srcPort, "tcp"
	return ev
}

// FileEvent builds a file event (op: create | write | read | open | rename).
func FileEvent(o *Options, source string, p ProcInfo, path, op, mode string) schema.Event {
	ev := build(o, schema.EventTypeFile, source, p, RawProc{Op: op, Mode: mode})
	ev.FilePath = path
	return ev
}

// EscapeEvent builds a process event carrying a container-escape signal (rule APP-H11):
// mount | setns | unshare | runtime_socket.
func EscapeEvent(o *Options, source string, p ProcInfo, kind string) schema.Event {
	return build(o, schema.EventTypeProcess, source, p, RawProc{Escape: kind})
}
