package prevention

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"obsidianwatch/agent/internal/response"
	"obsidianwatch/agent/pkg/schema"
)

// EventType is the type of the events the engine reports.
const EventType schema.EventType = "prevention"

// How long an IP blocked because of a domain answer stays blocked.
const domainBlockTTL = 24 * time.Hour

// Inspect checks one pipeline event against the set. It never blocks the
// pipeline: matches are reported and acted on from the engine's goroutine.
func (e *Engine) Inspect(ev *schema.Event) {
	if ev == nil || ev.EventType == EventType {
		return
	}
	switch ev.EventType {
	case schema.EventTypeNetwork:
		e.inspectNetwork(ev)
	case schema.EventTypeProcess:
		e.inspectProcess(ev)
	case schema.EventTypeFile:
		e.inspectFile(ev)
	}
	if strings.HasPrefix(string(ev.EventType), "dns") {
		e.inspectDNS(ev)
	}
}

func (e *Engine) inspectNetwork(ev *schema.Event) {
	mode := e.Mode("ip")
	if mode == Off || ev.DstIP == "" {
		return
	}
	x, ok := e.lookupIP(ev.DstIP)
	if !ok {
		return
	}
	if e.seen(fmt.Sprintf("ip|%s|%d", ev.DstIP, ev.PID)) {
		return
	}
	r := e.report("ip", ev.DstIP, x, mode)
	r.addProcess(ev)
	r.Fields["dst_ip"], r.Fields["dst_port"] = ev.DstIP, ev.DstPort
	if mode != Enforce {
		e.emit(r, "audit", "")
		return
	}
	// The kernel tier refuses connects before they happen and reports them
	// itself; a connection seen here got through (no kernel tier, or it was
	// open before the set arrived), so block the address now.
	ip := ev.DstIP
	e.do(func() {
		action, detail := e.blockIP(ip, time.Unix(x.Until, 0))
		e.emit(r, action, detail)
	})
}

// sha256Of returns the SHA-256 in a hash field: a bare 64-hex value or the
// SHA256= part of Sysmon's "SHA256=...,MD5=..." list.
func sha256Of(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		return strings.ToLower(s)
	}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if k, v, ok := strings.Cut(part, "="); ok && strings.EqualFold(k, "sha256") && len(v) == 64 {
			return strings.ToLower(v)
		}
	}
	return ""
}

func (e *Engine) inspectProcess(ev *schema.Event) {
	mode := e.Mode("hash")
	if mode == Off || !isStart(ev) {
		return
	}
	e.mu.RLock()
	n := len(e.hashes)
	e.mu.RUnlock()
	if n == 0 {
		return
	}
	sum := sha256Of(ev.FileHash)
	if sum == "" {
		// No hash on the event (ETW, 4688, macOS): hash the image off the
		// pipeline, cached by path, size and modification time.
		if ev.ImagePath == "" {
			return
		}
		cp := *ev
		e.do(func() {
			if s := e.cachedHash(cp.ImagePath); s != "" {
				if _, ok := e.lookupHash(s); ok {
					cp.FileHash = s
					e.processMatchEvent(&cp, "process_start")
				}
			}
		})
		return
	}
	if _, ok := e.lookupHash(sum); !ok {
		return
	}
	ev2 := *ev
	ev2.FileHash = sum
	e.processMatchEvent(&ev2, "process_start")
}

// inspectFile checks file events that already carry a hash (Windows file
// hasher, Sysmon, FIM).
func (e *Engine) inspectFile(ev *schema.Event) {
	if e.Mode("hash") == Off || ev.FilePath == "" {
		return
	}
	sum := sha256Of(ev.FileHash)
	if sum == "" {
		return
	}
	if _, ok := e.lookupHash(sum); !ok {
		return
	}
	e.fileMatch(ev.FilePath, sum, "file_event")
}

func (e *Engine) processMatchEvent(ev *schema.Event, trigger string) {
	r := e.processReport(ev.PID, ev.ProcessName, ev.ImagePath, strings.ToLower(ev.FileHash), trigger)
	if r == nil {
		return
	}
	r.cmd, r.user = ev.CommandLine, ev.UserName
	e.actOnProcess(r)
}

// processMatch handles a running process whose image matched (sweep).
func (e *Engine) processMatch(pid int, name, image, sum, trigger string) {
	if r := e.processReport(pid, name, image, sum, trigger); r != nil {
		e.actOnProcess(r)
	}
}

func (e *Engine) processReport(pid int, name, image, sum, trigger string) *report {
	x, ok := e.lookupHash(sum)
	if !ok || e.seen(fmt.Sprintf("hash|%s|%d", sum, pid)) {
		return nil
	}
	r := e.report("hash", sum, x, e.Mode("hash"))
	r.pid, r.proc, r.image = pid, name, image
	if pid > 0 {
		r.Fields["pid"] = pid
	}
	r.Fields["trigger"] = trigger
	if image != "" {
		r.Fields["path"] = image
	}
	return r
}

func (e *Engine) actOnProcess(r *report) {
	if r.Mode != Enforce {
		e.emit(r, "audit", "")
		return
	}
	if systemPath(r.image) {
		// A listed hash on an operating-system binary is far more likely a
		// bad feed entry than malware: never kill or move system files.
		e.emit(r, "failed", "operating-system binary; not killed or quarantined (check the indicator)")
		return
	}
	pid, image := r.pid, r.image
	e.do(func() {
		var done, errs []string
		if e.resp != nil && pid > 1 && !e.isSelf(pid) {
			res := e.resp.Handle(context.Background(), "kill_process", response.Params{PID: pid, Image: image, Tree: true})
			if res.OK {
				done = append(done, "killed")
			} else {
				errs = append(errs, "kill: "+res.Message)
			}
		}
		if e.resp != nil && image != "" {
			res := e.resp.Handle(context.Background(), "quarantine_file", response.Params{Path: image})
			if res.OK {
				done = append(done, "quarantined")
			} else {
				errs = append(errs, "quarantine: "+res.Message)
			}
		}
		if e.resp == nil {
			errs = append(errs, "response actions are not available in this build")
		}
		action := strings.Join(done, "+")
		if action == "" {
			action = "failed"
		}
		e.emit(r, action, strings.Join(errs, "; "))
	})
}

// addrsInText finds IP addresses in free text such as Windows QueryResults
// ("type: 5 x;::ffff:1.2.3.4;"): every run of address characters that parses.
func addrsInText(s string) []netip.Addr {
	var out []netip.Addr
	tokens := strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == ':' || r == '.')
	})
	for _, t := range tokens {
		if a, err := netip.ParseAddr(t); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func (e *Engine) inspectDNS(ev *schema.Event) {
	mode := e.Mode("domain")
	if mode == Off || len(ev.Raw) == 0 {
		return
	}
	var raw map[string]any
	if json.Unmarshal(ev.Raw, &raw) != nil {
		return
	}
	name := ""
	for _, k := range []string{"query_name", "query", "domain", "name"} {
		if s, ok := raw[k].(string); ok && s != "" {
			name = s
			break
		}
	}
	if name == "" {
		return
	}
	x, matched, ok := e.lookupDomain(name)
	if !ok {
		return
	}
	if e.seen(fmt.Sprintf("domain|%s|%d", name, ev.PID)) {
		return
	}
	// Answers, where the collector has them (Windows QueryResults, or an
	// answers list).
	var answers []netip.Addr
	collect := func(s string) { answers = append(answers, addrsInText(s)...) }
	for _, k := range []string{"query_results", "answers", "answer", "resolved"} {
		switch v := raw[k].(type) {
		case string:
			collect(v)
		case []any:
			for _, s := range v {
				if str, ok := s.(string); ok {
					collect(str)
				}
			}
		}
	}
	r := e.report("domain", name, x, mode)
	r.Fields["matched_domain"] = matched
	r.addProcess(ev)
	if len(answers) > 0 {
		var s []string
		for _, a := range answers {
			s = append(s, a.String())
		}
		r.Fields["answers"] = s
	}
	if mode != Enforce || len(answers) == 0 {
		detail := ""
		if mode == Enforce {
			detail = "no resolved addresses in the DNS event; nothing to block"
		}
		e.emit(r, "audit", detail)
		return
	}
	until := time.Now().Add(domainBlockTTL)
	e.do(func() {
		var blocked, errs []string
		for _, a := range answers {
			if e.protected(a) || !a.IsGlobalUnicast() || a.IsPrivate() {
				continue
			}
			act, detail := e.blockIP(a.String(), until)
			if act == "blocked" || act == "ip_blocked" {
				blocked = append(blocked, a.String())
			} else if detail != "" {
				errs = append(errs, detail)
			}
		}
		action := "ip_blocked"
		if len(blocked) == 0 {
			action = "failed"
		}
		r.Fields["blocked_ips"] = blocked
		e.emit(r, action, strings.Join(errs, "; "))
	})
}

// blockIP adds an address to the kernel tier when it runs, otherwise to the
// block_ip response action, remembering it so it is lifted at until.
func (e *Engine) blockIP(ip string, until time.Time) (action, detail string) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "failed", "bad address"
	}
	a = a.Unmap()
	if e.protected(a) {
		return "failed", "protected address (manager, resolver or gateway)"
	}
	if e.kernel != nil {
		e.mu.Lock()
		if _, ok := e.ips[a]; !ok {
			e.ips[a] = Entry{V: a.String(), Until: until.Unix(), Src: "domain-answer"}
		}
		e.mu.Unlock()
		e.syncKernel()
		e.save()
		return "blocked", "refused in the kernel from now on"
	}
	if e.resp == nil {
		return "failed", "response actions are not available in this build"
	}
	res := e.resp.Handle(context.Background(), "block_ip", response.Params{IP: a.String()})
	if !res.OK {
		return "failed", res.Message
	}
	e.mu.Lock()
	if strings.Contains(res.Message, "already blocked") {
		// Someone else's block: never lift it.
	} else if old, ok := e.owned[a]; !ok || until.After(old) {
		e.owned[a] = until
	}
	e.mu.Unlock()
	e.save()
	return "ip_blocked", res.Message
}

func (e *Engine) isSelf(pid int) bool { return pid == osGetpid() }

func isStart(ev *schema.Event) bool {
	var r struct {
		Action string `json:"action"`
	}
	if len(ev.Raw) > 0 && json.Unmarshal(ev.Raw, &r) == nil {
		switch r.Action {
		case "exec", "start", "process_create":
			return true
		case "exit", "stop":
			return false
		}
	}
	return ev.EventID == 1 || ev.EventID == 4688
}

// report is a prevention event under construction.
type report struct {
	Kind   string
	Value  string
	Mode   string
	Entry  Entry
	Fields map[string]any
	pid    int
	proc   string
	image  string
	cmd    string
	user   string
}

func (e *Engine) report(kind, value string, x Entry, mode string) *report {
	return &report{Kind: kind, Value: value, Mode: mode, Entry: x, Fields: map[string]any{}}
}

func (r *report) addProcess(ev *schema.Event) {
	r.pid, r.proc, r.image, r.cmd, r.user = ev.PID, ev.ProcessName, ev.ImagePath, ev.CommandLine, ev.UserName
	if ev.PID > 0 {
		r.Fields["pid"] = ev.PID
	}
}

// emit sends the report. action: audit, blocked (kernel), ip_blocked
// (block_ip), killed, quarantined, killed+quarantined, failed.
func (e *Engine) emit(r *report, action, detail string) {
	raw := map[string]any{
		"kind": r.Kind, "indicator": r.Value, "mode": r.Mode, "action": action,
		"ioc_source": r.Entry.Src, "confidence": r.Entry.Conf, "malware": r.Entry.Name,
	}
	if detail != "" {
		raw["detail"] = detail
	}
	for k, v := range r.Fields {
		raw[k] = v
	}
	b, _ := json.Marshal(raw)
	sev := schema.SeverityMedium
	switch action {
	case "audit":
		sev = schema.SeverityMedium
	case "failed":
		sev = schema.SeverityHigh
	default:
		sev = schema.SeverityHigh
	}
	ev := schema.Event{
		ID: newID(), Time: time.Now().UTC(), AgentID: e.agentID, Host: e.host, OS: e.osName,
		EventType: EventType, Severity: sev, Source: "prevention", Raw: b,
		PID: r.pid, ProcessName: r.proc, ImagePath: r.image, CommandLine: r.cmd, UserName: r.user,
	}
	if r.Kind == "ip" {
		ev.DstIP = r.Value
	}
	if r.Kind == "hash" {
		ev.FileHash = r.Value
	}
	if p, ok := r.Fields["path"].(string); ok {
		ev.FilePath = p
	}
	if e.out == nil {
		return
	}
	select {
	case e.out <- ev:
	default:
		e.logger.Warn("prevention: report dropped (pipeline full)", "kind", r.Kind, "indicator", r.Value)
	}
	e.logger.Warn("prevention: match", "kind", r.Kind, "indicator", r.Value, "mode", r.Mode, "action", action, "detail", detail)
}

// systemPath reports operating-system locations the engine never acts on.
func systemPath(p string) bool {
	if p == "" {
		return false
	}
	l := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	for _, pre := range []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/",
		"/usr/libexec/", "/system/", "c:/windows/", "/opt/obsidianwatch/", "c:/program files/obsidianwatch/"} {
		if strings.HasPrefix(l, pre) {
			return true
		}
	}
	return false
}
