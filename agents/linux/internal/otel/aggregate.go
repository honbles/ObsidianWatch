package otel

// aggregate.go - in-agent aggregation (spec section 7, "Processing in the agent"):
// per-minute RED statistics per route, the route inventory with a cardinality cap,
// dependency edges from client spans, instance heartbeats and sampled traces.
// Raw spans never leave the agent.

import (
	"encoding/json"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"time"
)

// AggOptions tunes the aggregator; zero values take the defaults.
type AggOptions struct {
	SlowMs        int            // trace is kept as "slow" at or above this root duration
	SlowMsBy      map[string]int // per service ("name|env") override
	BaselinePct   float64        // share of ordinary traces kept, in percent
	MaxRoutes     int            // distinct (route, method) per service before collapsing to "other"
	MaxOpenTraces int            // bounded trace buffer; oldest is dropped first and counted
	MaxSpans      int            // spans kept per trace
	TraceIdle     time.Duration  // a trace is complete after this long without a new span
	MaxStatKeys   int            // bound on in-memory per-minute keys
	MaxClientKeys int            // distinct (route, client) failure keys per service per minute
	// IPMode returns the client-address storage mode for a service (full | truncated | off).
	IPMode func(service, env string) string
	// SlowFn returns a per-service slow-trace threshold in ms; <= 0 means use SlowMs.
	SlowFn func(service, env string) int
}

func (o *AggOptions) defaults() {
	if o.SlowMs <= 0 {
		o.SlowMs = 1000
	}
	if o.BaselinePct < 0 {
		o.BaselinePct = 0
	} else if o.BaselinePct == 0 {
		o.BaselinePct = 1
	}
	if o.MaxRoutes <= 0 {
		o.MaxRoutes = 500
	}
	if o.MaxOpenTraces <= 0 {
		o.MaxOpenTraces = 2000
	}
	if o.MaxSpans <= 0 {
		o.MaxSpans = 500
	}
	if o.TraceIdle <= 0 {
		o.TraceIdle = 10 * time.Second
	}
	if o.MaxStatKeys <= 0 {
		o.MaxStatKeys = 100000
	}
	if o.MaxClientKeys <= 0 {
		o.MaxClientKeys = 200
	}
}

// DurBounds are the histogram upper bounds in ms; the final bucket is +Inf.
// They match backend store.AppDurBounds.
var DurBounds = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

const (
	histLen      = 12
	maxTraceJSON = 64 << 10
	otherRoute   = "other"
	unmatched    = "(unmatched)"
	maxSkew      = 5 * time.Minute
)

type svcKey struct{ name, env string }

type statKey struct {
	minute        time.Time
	svc           svcKey
	route, method string
}

type statVal struct {
	calls, errors, s2xx, s4013, s429, s5xx int64
	hist                                   [histLen]int64
}

type clientKey struct {
	minute        time.Time
	svc           svcKey
	route, method string
	client, peer  string
	exc           string
}

type clientVal struct{ failures, s4013, s429, s4o, s5 int64 }

type svcMinute struct {
	svc    svcKey
	minute time.Time
}

type edgeKey struct {
	svc            svcKey
	kind, dst, src string
}

type instKey struct {
	svc       svcKey
	pid       int
	procStart time.Time
	container string
}

type instVal struct {
	res          Resource
	peer         Peer
	identity     string
	lastSeen     time.Time
	lastSent     time.Time
	dirty        bool
	source       string // otel | discovered
	listen       json.RawMessage
	sensor       string
	exe          string
	instrumented bool
}

type openTrace struct {
	id       string
	spans    []Span
	last     time.Time
	haveRoot bool
	dropped  bool
}

// AggStats are counters for health reporting.
type AggStats struct {
	Spans, ServerSpans, ClientSpans, NoService, ClockSkew, StatDrops, TracesKept, TracesDropped int64
}

// Aggregator is safe for concurrent use.
type Aggregator struct {
	mu   sync.Mutex
	opt  AggOptions
	now  func() time.Time
	st   map[statKey]*statVal
	ed   map[edgeKey]*[2]int64 // calls, errors since last flush
	in   map[instKey]*instVal
	seen map[svcKey]map[[2]string]bool
	ovf  map[svcKey]int64
	drp  map[svcKey]int64
	cl   map[clientKey]*clientVal
	clN  map[svcMinute]int
	clOv map[svcKey]int64

	traces map[string]*openTrace
	order  []string
	sec    map[string]time.Time
	kept   []BatchTrace
	Stats  AggStats
}

func NewAggregator(opt AggOptions, now func() time.Time) *Aggregator {
	opt.defaults()
	if now == nil {
		now = time.Now
	}
	return &Aggregator{opt: opt, now: now,
		st: map[statKey]*statVal{}, ed: map[edgeKey]*[2]int64{}, in: map[instKey]*instVal{},
		seen: map[svcKey]map[[2]string]bool{}, ovf: map[svcKey]int64{}, drp: map[svcKey]int64{},
		cl: map[clientKey]*clientVal{}, clN: map[svcMinute]int{}, clOv: map[svcKey]int64{},
		traces: map[string]*openTrace{}, sec: map[string]time.Time{}}
}

func envOf(s string) string {
	if s == "" {
		return "default"
	}
	return s
}

func durBucket(ms float64) int {
	for i, b := range DurBounds {
		if ms <= b {
			return i
		}
	}
	return histLen - 1
}

// MarkSecurity flags a trace so it is kept when it completes (spec: "every request
// touched by a security event").
func (a *Aggregator) MarkSecurity(traceID string) {
	if traceID == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.sec) > 20000 {
		cut := a.now().Add(-10 * time.Minute)
		for k, t := range a.sec {
			if t.Before(cut) {
				delete(a.sec, k)
			}
		}
	}
	a.sec[traceID] = a.now()
}

// Ingest adds one span. peer and identity describe the verified (or asserted) sender.
func (a *Aggregator) Ingest(s Span, peer Peer, identity string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Stats.Spans++
	if s.Res.Service == "" {
		a.Stats.NoService++
		return
	}
	svc := svcKey{s.Res.Service, envOf(s.Res.Environment)}
	now := a.now()
	a.touchInstance(svc, s.Res, peer, identity, now)

	switch s.Kind {
	case kindServer:
		a.Stats.ServerSpans++
		a.addRED(svc, s, now)
	case kindClient, kindProducer:
		a.Stats.ClientSpans++
		a.addEdge(svc, s)
	}
	a.bufferSpan(s, now)
}

func (a *Aggregator) touchInstance(svc svcKey, res Resource, p Peer, identity string, now time.Time) {
	k := instKey{svc, p.PID, p.ProcStart, p.ContainerID}
	v := a.in[k]
	if v == nil {
		if len(a.in) > 5000 {
			return
		}
		v = &instVal{}
		a.in[k] = v
	}
	if v.res.Version != res.Version || v.res.InstanceRef != res.InstanceRef || v.identity != identity {
		v.dirty = true
	}
	if v.identity == IdentityVerified {
		identity = IdentityVerified // never downgrade a bound process
	}
	v.res, v.peer, v.identity, v.lastSeen = res, p, identity, now
	v.source, v.instrumented, v.exe = "otel", true, p.Exe
	if v.lastSent.IsZero() {
		v.dirty = true
	}
}

// AddDiscovered records service instances the host sensor found (Tier 0). It runs every few seconds,
// so it only refreshes what the next flush reports. An instance that OpenTelemetry has since bound to the
// same process is reported once, as the instrumented one.
func (a *Aggregator) AddDiscovered(list []BatchInstance) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for _, d := range list {
		if d.Service == "" || a.instrumentedPID(d.PID, d.ProcStart) {
			continue // the process already reports OpenTelemetry under its own service name
		}
		svc := svcKey{d.Service, envOf(d.Environment)}
		k := instKey{svc, d.PID, d.ProcStart, d.ContainerID}
		v := a.in[k]
		if v == nil {
			if len(a.in) > 5000 {
				continue
			}
			v = &instVal{dirty: true}
			a.in[k] = v
		}
		if v.source == "otel" { // already known as instrumented; keep that
			v.lastSeen = now
			continue
		}
		if v.sensor != d.Sensor || string(v.listen) != string(d.Listen) {
			v.dirty = true
		}
		v.res = Resource{Service: d.Service, Environment: d.Environment, Language: d.Language}
		v.peer = Peer{Resolved: true, PID: d.PID, ProcStart: d.ProcStart, ContainerID: d.ContainerID, Exe: d.Exe}
		v.identity, v.lastSeen, v.source = IdentityVerified, now, "discovered"
		v.listen, v.sensor, v.exe, v.instrumented = d.Listen, d.Sensor, d.Exe, false
	}
}

// instrumentedPID reports whether an OpenTelemetry-bound instance exists for this process. Discovered names
// come from the executable and rarely equal the application's service.name, so the merge keys on the process.
func (a *Aggregator) instrumentedPID(pid int, start time.Time) bool {
	if pid <= 0 {
		return false
	}
	for k, v := range a.in {
		if v.source == "otel" && k.pid == pid && (start.IsZero() || k.procStart.IsZero() || k.procStart.Equal(start)) {
			return true
		}
	}
	return false
}

// PIDs returns the process ids of instrumented service instances active recently; the host sensor
// watches their descendants.
func (a *Aggregator) PIDs() []int {
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := a.now().Add(-instanceActive)
	var out []int
	for _, v := range a.in {
		if v.source == "otel" && v.peer.PID > 0 && v.identity == IdentityVerified && v.lastSeen.After(cut) {
			out = append(out, v.peer.PID)
		}
	}
	return out
}

func (a *Aggregator) addRED(svc svcKey, s Span, now time.Time) {
	method := s.Method
	if method == "" {
		if i := strings.IndexByte(s.Name, ' '); i > 0 && i <= 8 {
			method = strings.ToUpper(s.Name[:i])
		}
	}
	if method == "" && s.Route == "" && s.HTTPStatus == 0 {
		return // not an HTTP-style server span; nothing to aggregate by route
	}
	if method == "" {
		method = "*"
	}
	route := s.Route
	if route == "" {
		route = unmatched // never fall back to the raw path: that is the cardinality explosion
	}
	if len(route) > 256 {
		route = route[:256]
	}

	// Cardinality cap per service: overflow collapses into one "other" route.
	seen := a.seen[svc]
	if seen == nil {
		seen = map[[2]string]bool{}
		a.seen[svc] = seen
	}
	rk := [2]string{route, method}
	if !seen[rk] {
		if len(seen) >= a.opt.MaxRoutes {
			a.ovf[svc]++
			route, rk = otherRoute, [2]string{otherRoute, method}
			seen[rk] = true
		} else {
			seen[rk] = true
		}
	}

	// Server spans use the app's clock; far-off clocks are bucketed by receive time.
	t := time.Unix(0, int64(s.EndNano))
	if s.EndNano == 0 || t.After(now.Add(maxSkew)) || t.Before(now.Add(-maxSkew)) {
		t = now
		if s.EndNano != 0 {
			a.Stats.ClockSkew++
		}
	}
	key := statKey{minute: t.UTC().Truncate(time.Minute), svc: svc, route: route, method: method}
	v := a.st[key]
	if v == nil {
		if len(a.st) >= a.opt.MaxStatKeys {
			a.Stats.StatDrops++
			return
		}
		v = &statVal{}
		a.st[key] = v
	}
	v.calls++
	v.hist[durBucket(s.DurationMs())]++
	switch {
	case s.HTTPStatus >= 200 && s.HTTPStatus < 300:
		v.s2xx++
	case s.HTTPStatus == 401 || s.HTTPStatus == 403:
		v.s4013++
	case s.HTTPStatus == 429:
		v.s429++
	case s.HTTPStatus >= 500:
		v.s5xx++
	}
	if s.IsError() {
		v.errors++
	}
	a.addClientFailure(svc, route, method, s, key.minute)
}

// addClientFailure records a failed request against the client address, for the source-based
// rules. Only failures are kept, the addresses follow the service's storage mode, and the number
// of distinct keys per service per minute is capped (the overflow is counted, not hidden).
func (a *Aggregator) addClientFailure(svc svcKey, route, method string, s Span, minute time.Time) {
	code := s.HTTPStatus
	failed := code == 401 || code == 403 || code == 429 || (code >= 400 && code < 600) || s.ExcType != ""
	if !failed {
		return
	}
	mode := ClientIPFull
	if a.opt.IPMode != nil {
		if m := a.opt.IPMode(svc.name, svc.env); m != "" {
			mode = m
		}
	}
	client, peer := ApplyClientIP(s.ClientAddr, mode), ApplyClientIP(s.PeerAddr, mode)
	if client == "" && peer == "" {
		return
	}
	exc := s.ExcType
	if len(exc) > 128 {
		exc = exc[:128]
	}
	k := clientKey{minute, svc, route, method, client, peer, exc}
	v := a.cl[k]
	if v == nil {
		sm := svcMinute{svc, minute}
		if a.clN[sm] >= a.opt.MaxClientKeys {
			a.clOv[svc]++
			return
		}
		a.clN[sm]++
		v = &clientVal{}
		a.cl[k] = v
	}
	v.failures++
	switch {
	case code == 401 || code == 403:
		v.s4013++
	case code == 429:
		v.s429++
	case code >= 400 && code < 500:
		v.s4o++
	case code >= 500:
		v.s5++
	}
}

// edgeOf derives a dependency from a client span: database type, peer service or
// server address (spec section 7). Credentials, paths and queries never appear.
func edgeOf(s Span) (kind, dst string) {
	host := s.ServerAddr
	if host != "" && s.ServerPort > 0 {
		host += ":" + itoa(s.ServerPort)
	}
	switch {
	case s.DBSystem != "":
		if host != "" {
			return "database", s.DBSystem + "@" + host
		}
		return "database", s.DBSystem
	case s.Messaging != "":
		if host != "" {
			return "queue", s.Messaging + "@" + host
		}
		return "queue", s.Messaging
	case s.PeerService != "":
		return "service", s.PeerService
	case host != "":
		return "external", host
	}
	return "", ""
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func (a *Aggregator) addEdge(svc svcKey, s Span) {
	kind, dst := edgeOf(s)
	if kind == "" {
		return
	}
	k := edgeKey{svc, kind, strings.ToLower(dst), "otel"}
	v := a.ed[k]
	if v == nil {
		if len(a.ed) > 20000 {
			return
		}
		v = &[2]int64{}
		a.ed[k] = v
	}
	v[0]++
	if s.IsError() {
		v[1]++
	}
}

func (a *Aggregator) bufferSpan(s Span, now time.Time) {
	if s.TraceID == "" {
		return
	}
	t := a.traces[s.TraceID]
	if t == nil {
		if len(a.traces) >= a.opt.MaxOpenTraces && len(a.order) > 0 {
			a.dropOldestTrace()
		}
		t = &openTrace{id: s.TraceID}
		a.traces[s.TraceID] = t
		a.order = append(a.order, s.TraceID)
	}
	t.last = now
	if s.ParentID == "" || strings.Trim(s.ParentID, "0") == "" {
		t.haveRoot = true
	}
	if len(t.spans) < a.opt.MaxSpans {
		t.spans = append(t.spans, s)
	} else {
		t.dropped = true
	}
}

func (a *Aggregator) dropOldestTrace() {
	for len(a.order) > 0 {
		id := a.order[0]
		a.order = a.order[1:]
		if t, ok := a.traces[id]; ok {
			if len(t.spans) > 0 {
				sv := svcKey{t.spans[0].Res.Service, envOf(t.spans[0].Res.Environment)}
				a.drp[sv]++
			}
			delete(a.traces, id)
			a.Stats.TracesDropped++
			return
		}
	}
}

func (a *Aggregator) slowMs(svc svcKey) int {
	if a.opt.SlowFn != nil {
		if v := a.opt.SlowFn(svc.name, svc.env); v > 0 {
			return v
		}
	}
	if v, ok := a.opt.SlowMsBy[svc.name+"|"+svc.env]; ok && v > 0 {
		return v
	}
	return a.opt.SlowMs
}

func baselineHit(id string, pct float64) bool {
	h := fnv.New32a()
	h.Write([]byte(id))
	return float64(h.Sum32()%10000) < pct*100
}

type traceSpanOut struct {
	SpanID   string  `json:"span_id"`
	ParentID string  `json:"parent_id,omitempty"`
	Name     string  `json:"name"`
	Kind     int     `json:"kind"`
	Service  string  `json:"service"`
	StartMs  float64 `json:"start_ms"` // offset from the first span
	DurMs    float64 `json:"dur_ms"`
	Status   string  `json:"status,omitempty"`
	Route    string  `json:"route,omitempty"`
	Method   string  `json:"method,omitempty"`
	Code     int     `json:"code,omitempty"`
	DB       string  `json:"db,omitempty"`
	Peer     string  `json:"peer,omitempty"`
	Exc      string  `json:"exception,omitempty"`
}

// finishTrace decides whether a completed trace is kept and builds its record.
func (a *Aggregator) finishTrace(t *openTrace) {
	if len(t.spans) == 0 {
		return
	}
	sort.Slice(t.spans, func(i, j int) bool { return t.spans[i].StartNano < t.spans[j].StartNano })
	first := t.spans[0]
	minStart, maxEnd := first.StartNano, uint64(0)
	var root *Span
	isErr := false
	for i := range t.spans {
		s := &t.spans[i]
		if s.StartNano != 0 && s.StartNano < minStart {
			minStart = s.StartNano
		}
		if s.EndNano > maxEnd {
			maxEnd = s.EndNano
		}
		if s.IsError() {
			isErr = true
		}
		if root == nil && (s.ParentID == "" || strings.Trim(s.ParentID, "0") == "") {
			root = s
		}
	}
	if root == nil {
		root = &t.spans[0]
	}
	svc := svcKey{root.Res.Service, envOf(root.Res.Environment)}
	durMs := 0.0
	if maxEnd > minStart {
		durMs = float64(maxEnd-minStart) / 1e6
	}
	reason := ""
	switch {
	case isErr:
		reason = "error"
	case durMs >= float64(a.slowMs(svc)):
		reason = "slow"
	case a.sec[t.id] != (time.Time{}):
		reason = "security"
	case baselineHit(t.id, a.opt.BaselinePct):
		reason = "baseline"
	}
	if reason == "" {
		return
	}
	if reason != "security" && a.sec[t.id] != (time.Time{}) {
		reason = "security" // a security flag outranks the generic reasons
	}

	outs := make([]traceSpanOut, 0, len(t.spans))
	for _, s := range t.spans {
		o := traceSpanOut{SpanID: s.SpanID, ParentID: s.ParentID, Name: s.Name, Kind: s.Kind, Service: s.Res.Service,
			StartMs: float64(s.StartNano-minStart) / 1e6, DurMs: s.DurationMs(), Route: s.Route, Method: s.Method,
			Code: s.HTTPStatus, DB: s.DBSystem, Peer: s.PeerService, Exc: s.ExcType}
		if s.IsError() {
			o.Status = "error"
		}
		outs = append(outs, o)
	}
	var raw []byte
	for len(outs) > 0 { // cap at 64 KB by dropping the tail
		raw, _ = json.Marshal(outs)
		if len(raw) <= maxTraceJSON {
			break
		}
		outs = outs[:len(outs)*3/4]
	}
	if len(outs) == 0 {
		raw = []byte("[]")
	}
	rootRoute := root.Route
	if root.Method != "" && rootRoute != "" {
		rootRoute = root.Method + " " + rootRoute
	}
	status := "ok"
	if isErr {
		status = "error"
	}
	a.kept = append(a.kept, BatchTrace{TraceID: t.id, Service: svc.name, Environment: svc.env,
		Started: time.Unix(0, int64(minStart)).UTC(), DurationMs: int(durMs), RootRoute: rootRoute,
		Status: status, KeepReason: reason, SpanCount: len(t.spans), Spans: raw})
	a.Stats.TracesKept++
}

// closeTraces completes traces that have been idle long enough (or all, when final).
func (a *Aggregator) closeTraces(now time.Time, final bool) {
	if len(a.traces) == 0 {
		return
	}
	var keep []string
	for _, id := range a.order {
		t, ok := a.traces[id]
		if !ok {
			continue
		}
		idle := now.Sub(t.last)
		if final || idle >= a.opt.TraceIdle || (t.haveRoot && idle >= 2*time.Second) {
			a.finishTrace(t)
			delete(a.traces, id)
			delete(a.sec, id)
			continue
		}
		keep = append(keep, id)
	}
	a.order = keep
	if len(a.sec) > 0 {
		cut := now.Add(-15 * time.Minute)
		for k, t := range a.sec {
			if t.Before(cut) {
				delete(a.sec, k)
			}
		}
	}
}

const instanceHeartbeat = 60 * time.Second
const instanceActive = 5 * time.Minute

// Flush returns what is ready to send and removes it from memory. Statistics for the
// current, still-open minute stay until the minute closes (or final is true).
func (a *Aggregator) Flush(agentID string, final bool) *Batch {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.closeTraces(now, final)
	b := &Batch{AgentID: agentID, SentAt: now.UTC()}

	for k, v := range a.in {
		if v.source == "discovered" && a.instrumentedPID(k.pid, k.procStart) {
			delete(a.in, k) // superseded by the instrumented instance of the same process
			continue
		}
		if now.Sub(v.lastSeen) > instanceActive && !v.dirty {
			if now.Sub(v.lastSeen) > time.Hour {
				delete(a.in, k)
			}
			continue
		}
		if !v.dirty && now.Sub(v.lastSent) < instanceHeartbeat && !final {
			continue
		}
		src := v.source
		if src == "" {
			src = "otel"
		}
		b.Instances = append(b.Instances, BatchInstance{
			Service: k.svc.name, Environment: k.svc.env, Source: src, InstanceRef: v.res.InstanceRef,
			Version: v.res.Version, PID: v.peer.PID, ProcStart: v.peer.ProcStart, ContainerID: v.peer.ContainerID,
			Identity: v.identity, Instrumented: v.instrumented, Listen: v.listen, Sensor: v.sensor,
			Language: v.res.Language, SDK: v.res.SDK, Exe: v.peer.Exe})
		v.lastSent, v.dirty = now, false
	}

	cur := now.UTC().Truncate(time.Minute)
	for k, v := range a.st {
		if !final && !k.minute.Before(cur) {
			continue
		}
		h := make([]int64, histLen)
		copy(h, v.hist[:])
		b.Routes = append(b.Routes, BatchRoute{Service: k.svc.name, Environment: k.svc.env, Route: k.route, Method: k.method,
			Minute: k.minute, Calls: v.calls, Errors: v.errors, Status2xx: v.s2xx, Status40103: v.s4013,
			Status429: v.s429, Status5xx: v.s5xx, DurBuckets: h})
		delete(a.st, k)
	}
	for k, v := range a.cl {
		if !final && !k.minute.Before(cur) {
			continue
		}
		b.Clients = append(b.Clients, BatchClient{Service: k.svc.name, Environment: k.svc.env, Route: k.route, Method: k.method,
			Minute: k.minute, ClientIP: k.client, PeerIP: k.peer, ExcType: k.exc, Failures: v.failures,
			Status40103: v.s4013, Status429: v.s429, Status4xxOther: v.s4o, Status5xx: v.s5})
		delete(a.cl, k)
		if n := a.clN[svcMinute{k.svc, k.minute}]; n > 0 {
			a.clN[svcMinute{k.svc, k.minute}] = n - 1
		}
	}
	for sm, n := range a.clN {
		if n <= 0 {
			delete(a.clN, sm)
		}
	}
	for k, v := range a.ed {
		b.Edges = append(b.Edges, BatchEdge{Service: k.svc.name, Environment: k.svc.env, DstKind: k.kind, DstName: k.dst,
			Source: k.src, Calls: v[0], Errors: v[1]})
		delete(a.ed, k)
	}
	b.Traces, a.kept = a.kept, nil

	notes := map[svcKey]*BatchNote{}
	note := func(s svcKey) *BatchNote {
		if notes[s] == nil {
			notes[s] = &BatchNote{Service: s.name, Environment: s.env}
		}
		return notes[s]
	}
	for s, n := range a.ovf {
		note(s).RouteOverflow = n
	}
	for s, n := range a.drp {
		note(s).TraceDrops = n
	}
	for s, n := range a.clOv {
		note(s).ClientOverflow = n
	}
	a.ovf, a.drp, a.clOv = map[svcKey]int64{}, map[svcKey]int64{}, map[svcKey]int64{}
	for _, n := range notes {
		b.Notes = append(b.Notes, *n)
	}

	sort.Slice(b.Routes, func(i, j int) bool { return b.Routes[i].Minute.Before(b.Routes[j].Minute) })
	if b.Empty() {
		return nil
	}
	return b
}

// Requeue puts routes, edges and notes of a batch that could not be delivered back
// into memory so the next flush carries them (statistics are additive, so merging
// is exact). Traces and instances are not requeued: instances are re-sent as
// heartbeats and traces are short-lived by design.
func (a *Aggregator) Requeue(b *Batch) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range b.Routes {
		k := statKey{r.Minute, svcKey{r.Service, r.Environment}, r.Route, r.Method}
		v := a.st[k]
		if v == nil {
			if len(a.st) >= a.opt.MaxStatKeys {
				a.Stats.StatDrops++
				continue
			}
			v = &statVal{}
			a.st[k] = v
		}
		v.calls += r.Calls
		v.errors += r.Errors
		v.s2xx += r.Status2xx
		v.s4013 += r.Status40103
		v.s429 += r.Status429
		v.s5xx += r.Status5xx
		for i := 0; i < histLen && i < len(r.DurBuckets); i++ {
			v.hist[i] += r.DurBuckets[i]
		}
	}
	for _, c := range b.Clients {
		k := clientKey{c.Minute, svcKey{c.Service, c.Environment}, c.Route, c.Method, c.ClientIP, c.PeerIP, c.ExcType}
		v := a.cl[k]
		if v == nil {
			sm := svcMinute{svcKey{c.Service, c.Environment}, c.Minute}
			if a.clN[sm] >= a.opt.MaxClientKeys {
				a.clOv[sm.svc]++
				continue
			}
			a.clN[sm]++
			v = &clientVal{}
			a.cl[k] = v
		}
		v.failures += c.Failures
		v.s4013 += c.Status40103
		v.s429 += c.Status429
		v.s4o += c.Status4xxOther
		v.s5 += c.Status5xx
	}
	for _, e := range b.Edges {
		k := edgeKey{svcKey{e.Service, e.Environment}, e.DstKind, e.DstName, e.Source}
		v := a.ed[k]
		if v == nil {
			v = &[2]int64{}
			a.ed[k] = v
		}
		v[0] += e.Calls
		v[1] += e.Errors
	}
	for _, n := range b.Notes {
		s := svcKey{n.Service, n.Environment}
		a.ovf[s] += n.RouteOverflow
		a.drp[s] += n.TraceDrops
		a.clOv[s] += n.ClientOverflow
	}
}
