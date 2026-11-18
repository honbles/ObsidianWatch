package api

// app_rules_host.go - Tier 0 host-runtime rules (spec 10.2): H01–H08 and H11.
//
// Events come from the eBPF sensor (source "ebpf", with raw.proc) or from the existing
// process/network/file collectors. raw.proc carries what only the sensor knows:
//
//	{"ancestors":[{"pid":1234,"name":"java","exe":"/usr/bin/java"}],   // nearest parent first
//	 "tty":false, "container_id":"...",
//	 "priv_change":{"kind":"setuid","detail":"0"},                      // process events
//	 "escape":"mount|setns|runtime_socket",                             // any event
//	 "dns":"api.example.com", "prior_dns":true,                         // network events
//	 "op":"create|write|read|open", "mode":"0755"}                      // file events
//
// Without ancestors the lineage is the event's pid and ppid only, so only a direct child of the
// service process is recognised (a degraded input, recorded as such).

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

type appAnc struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Exe  string `json:"exe"`
}

// appProcInfo is the parsed view of a host event.
type appProcInfo struct {
	PID, PPID   int
	Name, Image string
	Cmd, User   string
	Ancestors   []appAnc
	HasLineage  bool // the sensor supplied ancestors
	TTY         bool
	ContainerID string
	PrivKind    string
	PrivDetail  string
	Escape      string
	DNS         string
	PriorDNS    *bool
	Op, Mode    string
}

func appParseProc(ev store.Event) appProcInfo {
	var p appProcInfo
	if ev.PID != nil {
		p.PID = *ev.PID
	}
	if ev.PPID != nil {
		p.PPID = *ev.PPID
	}
	if ev.ProcessName != nil {
		p.Name = *ev.ProcessName
	}
	if ev.ImagePath != nil {
		p.Image = *ev.ImagePath
	}
	if ev.CommandLine != nil {
		p.Cmd = *ev.CommandLine
	}
	if ev.UserName != nil {
		p.User = *ev.UserName
	}
	var raw struct {
		Proc struct {
			Ancestors  []appAnc `json:"ancestors"`
			TTY        bool     `json:"tty"`
			Container  string   `json:"container_id"`
			PrivChange *struct {
				Kind   string `json:"kind"`
				Detail string `json:"detail"`
			} `json:"priv_change"`
			Escape   string `json:"escape"`
			DNS      string `json:"dns"`
			PriorDNS *bool  `json:"prior_dns"`
			Op       string `json:"op"`
			Mode     string `json:"mode"`
		} `json:"proc"`
	}
	if len(ev.Raw) > 0 && json.Unmarshal(ev.Raw, &raw) == nil {
		r := raw.Proc
		p.Ancestors, p.HasLineage = r.Ancestors, len(r.Ancestors) > 0
		p.TTY, p.ContainerID, p.Escape = r.TTY, r.Container, r.Escape
		p.DNS, p.PriorDNS, p.Op, p.Mode = appLower(r.DNS), r.PriorDNS, appLower(r.Op), r.Mode
		if r.PrivChange != nil {
			p.PrivKind, p.PrivDetail = appLower(r.PrivChange.Kind), appLower(r.PrivChange.Detail)
		}
	}
	return p
}

func (p appProcInfo) base() string {
	if p.Name != "" {
		return appBaseName(p.Name)
	}
	return appBaseName(p.Image)
}

// lineagePIDs returns the pids to match against service instances: the process itself, then
// its ancestors nearest first (or just the parent when the sensor gave no ancestry).
func (p appProcInfo) lineagePIDs() []int {
	out := []int{p.PID}
	if p.HasLineage {
		for _, a := range p.Ancestors {
			out = append(out, a.PID)
		}
	} else if p.PPID > 0 {
		out = append(out, p.PPID)
	}
	return out
}

func (p appProcInfo) lineageText(inst appInst, idx int) string {
	var parts []string
	for _, a := range p.Ancestors {
		parts = append(parts, fmt.Sprintf("%s(%d)", a.Name, a.PID))
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("parent(%d)", p.PPID))
	}
	s := strings.Join(parts, " > ") + fmt.Sprintf(" > %s(%d)", p.base(), p.PID)
	if idx >= 0 {
		s += fmt.Sprintf("  [service process pid %d]", inst.PID)
	}
	return s
}

// ancestorName returns the name of the lineage member with the given pid.
func (p appProcInfo) ancestorName(pid int, fallback string) string {
	for _, a := range p.Ancestors {
		if a.PID == pid {
			if a.Name != "" {
				return appBaseName(a.Name)
			}
			return appBaseName(a.Exe)
		}
	}
	return fallback
}

// ── rule data tables ───────────────────────────────────────────────────────

var appShells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ash": true, "ksh": true, "csh": true, "tcsh": true, "fish": true,
	"busybox": true, "python": true, "python2": true, "python3": true, "perl": true, "ruby": true, "lua": true, "php": true,
	"php-cli": true, "pwsh": true, "powershell": true,
}

var appDownloaders = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true, "tftp": true, "ftp": true,
	"fetch": true, "aria2c": true, "lwp-download": true, "busybox-wget": true,
}

var appRuntimeTools = map[string]bool{
	"dockerd": true, "docker": true, "containerd": true, "containerd-shim": true, "containerd-shim-runc-v2": true,
	"runc": true, "crun": true, "crio": true, "conmon": true, "podman": true, "buildah": true, "kubelet": true,
	"nerdctl": true, "ctr": true, "cri-dockerd": true, "rootlesskit": true, "k3s": true, "kube-proxy": true,
	"dockerd-rootless": true, "systemd": true, "runsc": true, "kata-runtime": true,
}

var appSecretReaders = map[string]bool{ // legitimate readers of credential files
	"sshd": true, "login": true, "sudo": true, "su": true, "unix_chkpwd": true, "passwd": true, "chage": true,
	"chpasswd": true, "useradd": true, "usermod": true, "userdel": true, "vipw": true, "pwck": true, "grpck": true,
	"polkitd": true, "systemd-logind": true, "gdm": true, "lightdm": true, "cron": true, "crond": true, "atd": true,
	"nscd": true, "sssd": true, "dbus-daemon": true, "ssh": true, "ssh-agent": true, "ssh-add": true, "git": true,
	"rsync": true, "borg": true, "restic": true, "dpkg": true, "rpm": true, "apt": true, "yum": true, "dnf": true,
}

var appWatchedDirs = []string{
	"/var/www/", "/srv/www/", "/usr/share/nginx/html", "/webapps/", "/uploads/", "/upload/", "/htdocs/", "/wwwroot/",
	"/public_html/", "/public/", "/static/", "/html/",
}

var appScriptExts = []string{
	".php", ".phtml", ".php5", ".php7", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cgi", ".pl", ".py", ".sh", ".so", ".war", ".jar",
}

var appMetadataIPs = map[string]bool{
	"169.254.169.254": true, "fd00:ec2::254": true, "100.100.100.200": true, "169.254.170.2": true, "192.0.0.192": true,
}

var appMetadataNames = map[string]bool{"metadata.google.internal": true, "metadata": true, "metadata.azure.internal": true}

var appSecretMarkers = []string{
	"/.ssh/id_", "/.aws/credentials", "/.config/gcloud/", "/.azure/", "/.kube/config", "/.docker/config.json",
	"/.git-credentials", "/.netrc",
}

func appIsSecretPath(path string, ownPID int) bool {
	p := strings.ToLower(path)
	if p == "/etc/shadow" || p == "/etc/gshadow" || p == "/etc/shadow-" || p == "/etc/sudoers" {
		return true
	}
	for _, m := range appSecretMarkers {
		if strings.Contains(p, m) && !strings.HasSuffix(p, ".pub") {
			return true
		}
	}
	// another process's environment
	if strings.HasPrefix(p, "/proc/") && strings.HasSuffix(p, "/environ") {
		seg := strings.Split(p, "/")
		if len(seg) == 4 && seg[2] != "self" && seg[2] != fmt.Sprint(ownPID) {
			return true
		}
	}
	return false
}

// ── the evaluator ──────────────────────────────────────────────────────────

type appPending struct {
	svc     appSvc
	inst    appInst
	pid     int
	at      time.Time
	host    string
	agentID string
	cmd     string
	lineage string
	source  string
}

// appRules evaluates every Application rule. Host rules react to events (OnEvent); the
// data-driven rules run from Scan (app_rules_app.go, app_rules_ops.go).
type appRules struct {
	d    appData
	emit appAlertEmitter
	gate func(ctx context.Context, ruleID string, svc appSvc) RuleGate
	now  func() time.Time

	mu      sync.Mutex
	pending map[string]appPending // H01 follow-on watch, keyed agent|pid
}

func appNewRules(d appData, em appAlertEmitter, gate func(context.Context, string, appSvc) RuleGate) *appRules {
	return &appRules{d: d, emit: em, gate: gate, now: time.Now, pending: map[string]appPending{}}
}

func (r *appRules) enabled(ctx context.Context, rule string, svc appSvc) (RuleGate, bool) {
	g := r.gate(ctx, rule, svc)
	return g, g.Enabled
}

func (r *appRules) fire(ctx context.Context, f appFinding) bool {
	if f.Time.IsZero() {
		f.Time = r.now()
	}
	_, created, err := r.emit.Emit(ctx, f)
	if err != nil { // never silent: a rule that cannot create its alert is an operational problem
		slog.Error("application rule could not create its alert", "rule", f.RuleID, "service", f.Svc.Key(), "err", err)
	}
	return err == nil && created
}

// OnEvent evaluates the host rules for one event.
func (r *appRules) OnEvent(ctx context.Context, ev store.Event) {
	switch ev.EventType {
	case "process", "network", "file":
	default:
		return
	}
	p := appParseProc(ev)
	if p.PID == 0 && p.PPID == 0 {
		return
	}
	svc, inst, idx, ok := r.d.ServiceForLineage(ctx, ev.AgentID, p.ContainerID, p.lineagePIDs())
	switch ev.EventType {
	case "process":
		if ok {
			r.h01(ctx, ev, p, svc, inst, idx)
			r.h02(ctx, ev, p, svc, inst, idx)
			r.h08(ctx, ev, p, svc, inst)
		}
	case "network":
		if ok {
			r.followOn(ctx, ev, p, svc, "network connection")
			r.h04(ctx, ev, p, svc, inst)
			r.h05(ctx, ev, p, svc, inst)
			r.h06(ctx, ev, p, svc, inst)
		}
	case "file":
		if ok {
			r.followOn(ctx, ev, p, svc, "file write")
			r.h03(ctx, ev, p, svc, inst)
			r.h07(ctx, ev, p, svc, inst)
		}
	}
	r.h11(ctx, ev, p, svc, inst, ok) // host-wide: a service is optional
}

func (r *appRules) base(ev store.Event, p appProcInfo, svc appSvc, inst appInst, rule string) appFinding {
	f := appFinding{RuleID: rule, Svc: svc, InstanceID: inst.ID, AgentID: ev.AgentID, Host: ev.Host, Identity: inst.Identity,
		SourceEventID: ev.ID, EventType: ev.EventType, Time: ev.Time}
	if ev.EventType == "" {
		f.EventType = "process"
	}
	return f
}

// appDegradedLineage marks findings that rely on parent-pid matching only.
func appDegradedLineage(p appProcInfo, inst appInst, f *appFinding) {
	// Only a process matched through its parent depends on ancestry; the service's own process does not.
	if !p.HasLineage && p.PID != inst.PID {
		f.Degraded = true
		f.DegradeNote = "no process ancestry from the host sensor; only a direct child of the service process is recognised"
	}
}

func appCmdText(p appProcInfo) string {
	if p.Cmd != "" {
		return p.Cmd
	}
	return p.Image
}

// ── H01: web server or runtime spawns a shell ──────────────────────────────

func (r *appRules) h01(ctx context.Context, ev store.Event, p appProcInfo, svc appSvc, inst appInst, idx int) {
	if !appShells[p.base()] || p.TTY || idx < 1 {
		return
	}
	g, on := r.enabled(ctx, "APP-H01", svc)
	if !on {
		return
	}
	parent := p.ancestorName(inst.PID, inst.Name)
	if parent == "" {
		parent = "service process"
	}
	f := r.base(ev, p, svc, inst, "APP-H01")
	f.BaseSev, f.Summary = appSevHigh, "Service process spawned a shell"
	f.Detail = fmt.Sprintf("%s (pid %d) started %s with no terminal; its ancestor is the service's own process (%s).\nCommand: %s", parent, inst.PID, p.base(), parent, appCmdText(p))
	f.Lineage = p.lineageText(inst, idx)
	f.DedupKey = fmt.Sprintf("%d:%d:%s", svc.ID, p.PID, ev.Time.UTC().Format("2006010215"))
	f.AllowVals = []string{p.base(), parent + ">" + p.base()}
	appDegradedLineage(p, inst, &f)
	if r.fire(ctx, f) {
		r.mu.Lock()
		r.prune()
		r.pending[fmt.Sprintf("%s|%d", ev.AgentID, p.PID)] = appPending{svc: svc, inst: inst, pid: p.PID, at: ev.Time, host: ev.Host,
			agentID: ev.AgentID, cmd: appCmdText(p), lineage: f.Lineage, source: ev.ID}
		r.mu.Unlock()
		r.x02(ctx, ev, p, svc, inst, "APP-H01")
	}
	_ = g
}

func (r *appRules) prune() { // caller holds r.mu
	cut := r.now().Add(-30 * time.Minute)
	for k, v := range r.pending {
		if v.at.Before(cut) {
			delete(r.pending, k)
		}
	}
}

// followOn escalates H01 to Critical when the shell connects out or writes a file within the window.
func (r *appRules) followOn(ctx context.Context, ev store.Event, p appProcInfo, svc appSvc, what string) {
	if what == "file write" && p.Op != "create" && p.Op != "write" && p.Op != "rename" {
		return
	}
	r.mu.Lock()
	var hit *appPending
	var key string
	for _, pid := range p.lineagePIDs() {
		k := fmt.Sprintf("%s|%d", ev.AgentID, pid)
		if v, ok := r.pending[k]; ok {
			vv := v
			hit, key = &vv, k
			break
		}
	}
	r.mu.Unlock()
	if hit == nil {
		return
	}
	g, on := r.enabled(ctx, "APP-H01", svc)
	if !on {
		return
	}
	window := time.Duration(g.Param("followon_window_s", 300)) * time.Second
	if ev.Time.Sub(hit.at) > window || ev.Time.Before(hit.at) {
		return
	}
	f := r.base(ev, p, svc, hit.inst, "APP-H01")
	f.BaseSev, f.Summary = appSevCrit, "Shell spawned by a service process then made a "+what
	detail := what
	if ev.DstIP != nil && what == "network connection" {
		detail = fmt.Sprintf("connection to %s", *ev.DstIP)
		if ev.DstPort != nil {
			detail += fmt.Sprintf(":%d", *ev.DstPort)
		}
	}
	if ev.FilePath != nil && what == "file write" {
		detail = "write to " + *ev.FilePath
	}
	f.Detail = fmt.Sprintf("A shell started by the service process made a %s within %s of starting.\nShell command: %s", detail, ev.Time.Sub(hit.at).Round(time.Second), hit.cmd)
	f.Lineage = hit.lineage
	f.DedupKey = fmt.Sprintf("%d:%d:followon", svc.ID, hit.pid)
	f.AllowVals = []string{p.base()}
	if ev.DstIP != nil {
		f.AllowVals = append(f.AllowVals, *ev.DstIP)
	}
	if r.fire(ctx, f) {
		r.mu.Lock()
		delete(r.pending, key)
		r.mu.Unlock()
	}
}

// ── H02: download tool run by an app process ───────────────────────────────

func (r *appRules) h02(ctx context.Context, ev store.Event, p appProcInfo, svc appSvc, inst appInst, idx int) {
	if !appDownloaders[p.base()] || idx < 1 {
		return
	}
	if _, on := r.enabled(ctx, "APP-H02", svc); !on {
		return
	}
	f := r.base(ev, p, svc, inst, "APP-H02")
	f.BaseSev, f.Summary = appSevHigh, "Service process ran a download tool"
	f.Detail = fmt.Sprintf("%s was started by the service's own process.\nCommand: %s", p.base(), appCmdText(p))
	f.Lineage = p.lineageText(inst, idx)
	f.DedupKey = fmt.Sprintf("%d:%s:%s", svc.ID, p.base(), ev.Time.UTC().Format("2006010215"))
	f.AllowVals = []string{p.base()}
	appDegradedLineage(p, inst, &f)
	if r.fire(ctx, f) {
		r.x02(ctx, ev, p, svc, inst, "APP-H02")
	}
}

// ── H03: executable written to a web or upload directory ───────────────────

func (r *appRules) h03(ctx context.Context, ev store.Event, p appProcInfo, svc appSvc, inst appInst) {
	if ev.FilePath == nil || (p.Op != "create" && p.Op != "write" && p.Op != "rename") {
		return
	}
	path := strings.ToLower(*ev.FilePath)
	inWatched := false
	for _, d := range appWatchedDirs {
		if strings.Contains(path, d) {
			inWatched = true
			break
		}
	}
	if !inWatched {
		return
	}
	exec := strings.ContainsAny(p.Mode, "1357") && len(p.Mode) >= 3 // any execute bit
	script := false
	for _, x := range appScriptExts {
		if strings.HasSuffix(path, x) {
			script = true
			break
		}
	}
	if !script && !exec {
		return
	}
	g, on := r.enabled(ctx, "APP-H03", svc)
	if !on {
		return
	}
	window := time.Duration(g.Param("deploy_window_min", 30)) * time.Minute
	if r.d.InDeployWindow(ctx, svc, ev.AgentID, ev.Time, window) {
		appSkip("APP-H03", "deploy window")
		return
	}
	f := r.base(ev, p, svc, inst, "APP-H03")
	f.BaseSev, f.Summary = appSevHigh, "Executable written to a web or upload directory"
	kind := "script or binary"
	if exec && !script {
		kind = "file with execute permission"
	}
	f.Detail = fmt.Sprintf("%s wrote a %s: %s", p.base(), kind, *ev.FilePath)
	f.Lineage = p.lineageText(inst, 0)
	f.DedupKey = fmt.Sprintf("%d:%s", svc.ID, path)
	f.AllowVals = []string{p.base(), *ev.FilePath}
	appDegradedLineage(p, inst, &f)
	r.fire(ctx, f)
}

// ── learning helpers shared by H04, H06, H08 ───────────────────────────────

func appLearningStart(svc appSvc) time.Time {
	if svc.Settings.LearningStarted != nil {
		return *svc.Settings.LearningStarted
	}
	return svc.FirstSeen
}

// learned reports whether a first-seen rule may alert: at least min_days since learning began AND
// at least min_samples observations of the baseline kind (spec 10.1).
func (r *appRules) learned(ctx context.Context, svc appSvc, g RuleGate, kind string, defSamples float64, now time.Time) bool {
	days := g.Param("min_days", 7)
	if now.Sub(appLearningStart(svc)) < time.Duration(days*24)*time.Hour {
		return false
	}
	if min := int64(g.Param("min_samples", defSamples)); min > 0 {
		n, err := r.d.BaselineSamples(ctx, svc.ID, kind)
		if err != nil || n < min {
			return false
		}
	}
	return true
}

func appDestKey(dns string, ip string) (string, string) {
	if dns != "" {
		parts := strings.Split(strings.Trim(dns, "."), ".")
		dom := dns
		if len(parts) > 2 {
			dom = strings.Join(parts[len(parts)-2:], ".")
		}
		return "dns:" + dns, "dnsdom:" + dom
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return "ip:" + v4.Mask(net.CIDRMask(24, 32)).String() + "/24", ""
		}
		return "ip:" + parsed.Mask(net.CIDRMask(48, 128)).String() + "/48", ""
	}
	return "", ""
}

// ── H04: new outbound destination ──────────────────────────────────────────

func (r *appRules) h04(ctx context.Context, ev store.Event, p appProcInfo, svc appSvc, inst appInst) {
	if ev.DstIP == nil {
		return
	}
	cls := appClassifyIP(*ev.DstIP)
	if cls == appIPLoopback || cls == appIPInvalid || cls == appIPLinkLocal {
		return
	}
	key, domKey := appDestKey(p.DNS, *ev.DstIP)
	if key == "" {
		return
	}
	g, on := r.enabled(ctx, "APP-H04", svc)
	if !on {
		return
	}
	now := ev.Time
	known, err := r.d.Baseline(ctx, svc.ID, "destination", key)
	if err != nil {
		return
	}
	ready := r.learned(ctx, svc, g, "destination", 200, now)
	window := time.Duration(g.Param("deploy_window_min", 30)) * time.Minute
	deploy := r.d.InDeployWindow(ctx, svc, ev.AgentID, now, window)
	domainSeen := false
	if domKey != "" {
		domainSeen, _ = r.d.Baseline(ctx, svc.ID, "destination", domKey)
	}
	if !known && ready && !deploy {
		f := r.base(ev, p, svc, inst, "APP-H04")
		f.BaseSev, f.Summary = appSevMed, "New outbound destination"
		dest := *ev.DstIP
		if p.DNS != "" {
			dest = p.DNS + " (" + *ev.DstIP + ")"
		}
		f.Detail = fmt.Sprintf("The service connected to a destination it did not use while learning: %s.", dest)
		if domainSeen {
			f.BaseSev = appSevLow
			f.Detail += " The domain was seen before under another name."
		}
		f.DedupKey = fmt.Sprintf("%d:%s", svc.ID, key)
		f.AllowVals = []string{*ev.DstIP, p.DNS, key}
		appDegradedLineage(p, inst, &f)
		r.fire(ctx, f)
	} else if !known && ready && deploy {
		appSkip("APP-H04", "deploy window")
	}
	// Learning and deploy windows record into the baseline; after learning a reported destination is recorded too.
	_ = r.d.RecordBaseline(ctx, svc.ID, "destination", key, now)
	if domKey != "" {
		_ = r.d.RecordBaseline(ctx, svc.ID, "destination", domKey, now)
	}
}

// ── H05: public IP literal or known-bad address ────────────────────────────

func (r *appRules) h05(ctx context.Context, ev store.Event, p appProcInfo, svc appSvc, inst appInst) {
	if ev.DstIP == nil || appClassifyIP(*ev.DstIP) != appIPPublic {
		return
	}
	if _, on := r.enabled(ctx, "APP-H05", svc); !on {
		return
	}
	intel, hit := r.d.IPIntel(ctx, *ev.DstIP)
	literal := p.PriorDNS != nil && !*p.PriorDNS && p.DNS == ""
	if !hit && !literal {
		if p.PriorDNS == nil {
			appSkip("APP-H05", "no DNS lookup information from the sensor")
		}
		return
	}
	f := r.base(ev, p, svc, inst, "APP-H05")
	f.BaseSev, f.Summary = appSevMed, "Connection to a public IP address with no DNS lookup"
	f.Detail = fmt.Sprintf("The service connected to public address %s", *ev.DstIP)
	if ev.DstPort != nil {
		f.Detail += fmt.Sprintf(":%d", *ev.DstPort)
	}
	if literal {
		f.Detail += " without a preceding DNS lookup by that process."
	} else {
		f.Detail += "."
	}
	if hit {
		f.BaseSev, f.Summary = appSevHigh, "Connection to a known-bad address"
		f.Detail += " Threat-intelligence match: " + intel + "."
	}
	f.DedupKey = fmt.Sprintf("%d:%s", svc.ID, *ev.DstIP)
	f.AllowVals = []string{*ev.DstIP}
	r.fire(ctx, f)
}

// ── H06: cloud metadata endpoint ───────────────────────────────────────────

func (r *appRules) h06(ctx context.Context, ev store.Event, p appProcInfo, svc appSvc, inst appInst) {
	if ev.DstIP == nil {
		return
	}
	isMeta := appMetadataIPs[*ev.DstIP] || appMetadataNames[p.DNS]
	if !isMeta {
		return
	}
	g, on := r.enabled(ctx, "APP-H06", svc)
	if !on {
		return
	}
	key := "meta:" + *ev.DstIP
	known, err := r.d.Baseline(ctx, svc.ID, "metadata", key)
	if err != nil {
		return
	}
	ready := r.learned(ctx, svc, g, "destination", 200, ev.Time)
	if !known && ready {
		f := r.base(ev, p, svc, inst, "APP-H06")
		f.BaseSev, f.Summary = appSevMed, "Cloud metadata endpoint accessed"
		f.Detail = fmt.Sprintf("The service contacted the cloud metadata endpoint %s, which it did not do while learning.", *ev.DstIP)
		f.DedupKey = fmt.Sprintf("%d:%s", svc.ID, key)
		f.AllowVals = []string{*ev.DstIP, p.DNS}
		appDegradedLineage(p, inst, &f)
		r.fire(ctx, f)
	}
	_ = r.d.RecordBaseline(ctx, svc.ID, "metadata", key, ev.Time)
}

// ── H07: secret or credential file read ────────────────────────────────────

func (r *appRules) h07(ctx context.Context, ev store.Event, p appProcInfo, svc appSvc, inst appInst) {
	if ev.FilePath == nil || (p.Op != "read" && p.Op != "open") {
		return
	}
	if !appIsSecretPath(*ev.FilePath, p.PID) || appSecretReaders[p.base()] {
		return
	}
	if _, on := r.enabled(ctx, "APP-H07", svc); !on {
		return
	}
	f := r.base(ev, p, svc, inst, "APP-H07")
	f.BaseSev, f.Summary = appSevHigh, "Service process read a secret or credential file"
	f.Detail = fmt.Sprintf("%s read %s.\nCommand: %s", p.base(), *ev.FilePath, appCmdText(p))
	f.Lineage = p.lineageText(inst, 0)
	f.DedupKey = fmt.Sprintf("%d:%s:%s", svc.ID, p.base(), strings.ToLower(*ev.FilePath))
	f.AllowVals = []string{p.base(), *ev.FilePath}
	appDegradedLineage(p, inst, &f)
	r.fire(ctx, f)
}

// ── H08: privilege change in a service process ─────────────────────────────

func (r *appRules) h08(ctx context.Context, ev store.Event, p appProcInfo, svc appSvc, inst appInst) {
	if p.PrivKind == "" {
		return
	}
	g, on := r.enabled(ctx, "APP-H08", svc)
	if !on {
		return
	}
	key := "priv:" + p.PrivKind + ":" + p.PrivDetail
	known, err := r.d.Baseline(ctx, svc.ID, "priv", key)
	if err != nil {
		return
	}
	ready := r.learned(ctx, svc, g, "priv", 0, ev.Time)
	if !known && ready {
		f := r.base(ev, p, svc, inst, "APP-H08")
		f.BaseSev, f.Summary = appSevHigh, "Privilege change in a service process"
		f.Detail = fmt.Sprintf("%s (pid %d) changed privileges (%s %s), which it did not do while learning.\nCommand: %s", p.base(), p.PID, p.PrivKind, p.PrivDetail, appCmdText(p))
		f.Lineage = p.lineageText(inst, 0)
		f.DedupKey = fmt.Sprintf("%d:%s", svc.ID, key)
		f.AllowVals = []string{p.base(), p.PrivKind + ":" + p.PrivDetail, p.PrivDetail}
		appDegradedLineage(p, inst, &f)
		r.fire(ctx, f)
	}
	_ = r.d.RecordBaseline(ctx, svc.ID, "priv", key, ev.Time)
}

// ── H11: container escape signals ──────────────────────────────────────────

func (r *appRules) h11(ctx context.Context, ev store.Event, p appProcInfo, svc appSvc, inst appInst, haveSvc bool) {
	signal := p.Escape
	if signal == "" && ev.FilePath != nil && (p.Op == "open" || p.Op == "read" || p.Op == "write") {
		fp := strings.ToLower(*ev.FilePath)
		for _, s := range []string{"/docker.sock", "/containerd.sock", "/crio.sock", "/podman.sock", "/cri-dockerd.sock"} {
			if strings.HasSuffix(fp, s) {
				signal = "runtime_socket"
				break
			}
		}
	}
	if signal == "" || appRuntimeTools[p.base()] {
		return
	}
	if p.ContainerID == "" && !haveSvc {
		return // not inside a container and not a known service process
	}
	scope := svc
	if !haveSvc {
		scope = appSvc{}
	}
	if _, on := r.enabled(ctx, "APP-H11", scope); !on {
		return
	}
	f := r.base(ev, p, scope, inst, "APP-H11")
	f.BaseSev, f.Summary = appSevCrit, "Container escape signal"
	f.Detail = fmt.Sprintf("%s (pid %d) showed a container escape signal: %s.", p.base(), p.PID, signal)
	if ev.FilePath != nil {
		f.Detail += " Path: " + *ev.FilePath + "."
	}
	if p.ContainerID != "" {
		f.Detail += " Container: " + p.ContainerID + "."
	}
	f.Lineage = p.lineageText(inst, -1)
	f.DedupKey = fmt.Sprintf("%s:%d:%s", ev.Host, p.PID, signal)
	f.AllowVals = []string{p.base()}
	r.fire(ctx, f)
}
