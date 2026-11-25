package api

// app_batch.go - POST /api/v1/app/batch. Owned by the Application build.
//
// The batch is sent by the agent's local OTLP receiver, never by the instrumented
// application. Host identity is taken from the registered agent record, so a
// payload cannot claim another host. Only metadata is accepted: route templates
// (no concrete paths), no query strings, no headers, no bodies.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"obsidianwatch/backend/internal/store"
	"obsidianwatch/backend/pkg/schema"
)

const (
	appMaxBatchBytes    = 4 << 20  // request body cap
	appMaxTraceBytes    = 64 << 10 // spans per trace
	appMaxInstances     = 200
	appMaxRoutes        = 2000
	appMaxEdges         = 500
	appMaxTraces        = 50
	appMaxClients       = 3000
	appMaxParams        = 5000
	appMaxPayloads      = 500
	appMaxChildren      = 5000
	appMaxQueries       = 3000
	appMaxNPlusOne      = 500
	appMaxQueryText     = 512
	appMaxErrors        = 1500
	appMaxMetrics       = 4000
	appMaxSampling      = 200
	appMaxOperations    = 1500
	appMaxPayloadParams = 50
	appMaxPayloadValue  = 256
	appMaxParamNameLen  = 64
	appMaxNameRunes     = 128
	appMaxEnvRunes      = 64
	appMaxRouteRunes    = 256
	appMaxTargetRunes   = 255
	appItemsPerSec      = 200.0 // per-agent sustained items/s across the batch endpoint
	appItemsBurst       = 5000.0
	appAgentCacheTTL    = 60 * time.Second
	appMaxFutureSkew    = 10 * time.Minute
	appMaxStatAge       = 24 * time.Hour
	appMaxStatRequests  = 1 << 40
	appEventSourceLabel = "app"
)

var appEdgeKinds = map[string]bool{"service": true, "database": true, "queue": true, "external": true}
var appKeepReasons = map[string]bool{"error": true, "slow": true, "security": true, "baseline": true}
var appMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true, "GRPC": true, "*": true}

// appBatchStore is the persistence the handler needs; satisfied by *store.DB.
type appBatchStore interface {
	AppAgentInfo(ctx context.Context, id string) (host, osName string, ok bool, err error)
	AppIngestBatch(ctx context.Context, agentID, host string, b store.AppBatch, now time.Time) (store.AppIngestResult, error)
	InsertEvents(ctx context.Context, events []schema.Event) error
}

// ── per-agent limiter and registered-agent cache ───────────────────────────

type appBucket struct {
	tokens float64
	last   time.Time
}

type appLimiter struct {
	mu sync.Mutex
	m  map[string]*appBucket
}

func appNewLimiter() *appLimiter { return &appLimiter{m: map[string]*appBucket{}} }

func (l *appLimiter) allow(agent string, n int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[agent]
	if b == nil {
		if len(l.m) > 50000 {
			l.m = map[string]*appBucket{}
		}
		b = &appBucket{tokens: appItemsBurst, last: now}
		l.m[agent] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * appItemsPerSec
	if b.tokens > appItemsBurst {
		b.tokens = appItemsBurst
	}
	b.last = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

type appAgentEntry struct {
	host, os string
	ok       bool
	at       time.Time
}

type appAgentCache struct {
	mu sync.Mutex
	m  map[string]appAgentEntry
}

func (c *appAgentCache) get(id string, now time.Time) (appAgentEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[id]
	if !ok || now.Sub(e.at) > appAgentCacheTTL {
		return appAgentEntry{}, false
	}
	return e, true
}

func (c *appAgentCache) put(id string, e appAgentEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 50000 {
		c.m = map[string]appAgentEntry{}
	}
	c.m[id] = e
}

// ── sanitising ─────────────────────────────────────────────────────────────

func appClean(s string, max int) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

// appRouteTemplate keeps only the path template: no scheme, host, query or fragment.
func appRouteTemplate(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Path
		}
	}
	s = appClean(s, appMaxRouteRunes)
	if s == "" {
		return "/"
	}
	return s
}

// appEdgeTarget reduces a URL or address to host[:port]; credentials, path and
// query never leave the agent's view of the dependency.
func appEdgeTarget(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			s = u.Host
		}
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return appClean(strings.ToLower(s), appMaxTargetRunes)
}

// appValidParamName accepts only names that look like a parameter name. The agent already filters, and the backend
// does not trust it: anything else (spaces, long tokens, control characters) is dropped, never stored.
func appValidParamName(n string) bool {
	if n == "" || len(n) > appMaxParamNameLen {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '[' || c == ']') {
			return false
		}
	}
	return true
}

func appValidID(s string, max int) bool {
	if s == "" || utf8.RuneCountInString(s) > max {
		return false
	}
	return true
}

// appSanitizeBatch validates and normalises in place. It returns the number of
// items dropped; a dropped item never fails the whole batch.
func appSanitizeBatch(b *store.AppBatch, now time.Time) (dropped int) {
	ins := b.Instances[:0]
	for _, in := range b.Instances {
		in.Service, in.Environment = appClean(in.Service, appMaxNameRunes), appEnv(in.Environment)
		if !appValidID(in.Service, appMaxNameRunes) {
			dropped++
			continue
		}
		if in.Source != "otel" {
			in.Source = "discovered"
		}
		if in.Identity != "verified" {
			in.Identity = "asserted"
		}
		in.InstanceRef, in.Version = appClean(in.InstanceRef, 128), appClean(in.Version, 64)
		in.Language, in.SDK = appClean(in.Language, 32), appClean(in.SDK, 64)
		in.ContainerID, in.Exe = appClean(in.ContainerID, 128), appClean(in.Exe, 512)
		in.Unit, in.ContainerName, in.Image = appClean(in.Unit, 128), appClean(in.ContainerName, 128), appClean(in.Image, 256)
		in.VCSRevision = appCleanRevision(in.VCSRevision)
		in.VCSRepo, in.VCSBranch = appClean(in.VCSRepo, 300), appClean(in.VCSBranch, 200)
		switch in.VCSSource {
		case "otel", "oci", "git":
		default:
			in.VCSSource = ""
		}
		if in.VCSRevision == "" {
			in.VCSSource = ""
		}
		if in.PID < 0 {
			in.PID = 0
		}
		in.ProcStart = in.ProcStart.UTC()
		if in.ProcStart.After(now.Add(appMaxFutureSkew)) {
			in.ProcStart = time.Time{}
		}
		if len(in.Listen) > 0 && (len(in.Listen) > 4096 || !json.Valid(in.Listen)) {
			in.Listen = nil
		}
		ins = append(ins, in)
	}
	b.Instances = ins

	rts := b.Routes[:0]
	for _, r := range b.Routes {
		r.Service, r.Environment = appClean(r.Service, appMaxNameRunes), appEnv(r.Environment)
		r.Method = strings.ToUpper(appClean(r.Method, 8))
		if !appValidID(r.Service, appMaxNameRunes) || !appMethods[r.Method] {
			dropped++
			continue
		}
		r.Route = appRouteTemplate(r.Route)
		r.Minute = r.Minute.UTC().Truncate(time.Minute)
		if r.Minute.IsZero() || r.Minute.After(now.Add(appMaxFutureSkew)) || r.Minute.Before(now.Add(-appMaxStatAge)) {
			dropped++
			continue
		}
		counts := []int64{r.Calls, r.Errors, r.Status2xx, r.Status40103, r.Status429, r.Status5xx}
		bad := false
		for _, v := range counts {
			if v < 0 || v > appMaxStatRequests {
				bad = true
			}
		}
		if bad {
			dropped++
			continue
		}
		if len(r.DurBuckets) != store.AppHistLen {
			h := make([]int64, store.AppHistLen)
			copy(h, r.DurBuckets)
			r.DurBuckets = h
		}
		for _, v := range r.DurBuckets {
			if v < 0 {
				bad = true
			}
		}
		if bad {
			dropped++
			continue
		}
		if r.Sketch != nil { // a sketch that is malformed, or counts more than the row's calls, is dropped; the histogram still counts
			if sk := store.SketchFromWire(r.Sketch); sk == nil || sk.Count() > r.Calls {
				r.Sketch = nil
			}
		}
		rts = append(rts, r)
	}
	b.Routes = rts

	eds := b.Edges[:0]
	for _, e := range b.Edges {
		e.Service, e.Environment = appClean(e.Service, appMaxNameRunes), appEnv(e.Environment)
		e.DstKind = strings.ToLower(appClean(e.DstKind, 16))
		e.Source = strings.ToLower(appClean(e.Source, 8))
		e.DstName = appEdgeTarget(e.DstName)
		if !appValidID(e.Service, appMaxNameRunes) || !appEdgeKinds[e.DstKind] || (e.Source != "otel" && e.Source != "ebpf") ||
			e.DstName == "" || e.Calls < 0 || e.Errors < 0 {
			dropped++
			continue
		}
		eds = append(eds, e)
	}
	b.Edges = eds

	trs := b.Traces[:0]
	for _, t := range b.Traces {
		t.Service, t.Environment = appClean(t.Service, appMaxNameRunes), appEnv(t.Environment)
		t.TraceID = strings.ToLower(appClean(t.TraceID, 64))
		if !appValidID(t.Service, appMaxNameRunes) || t.TraceID == "" || len(t.Spans) > appMaxTraceBytes ||
			(len(t.Spans) > 0 && !json.Valid(t.Spans)) {
			dropped++
			continue
		}
		t.Started = t.Started.UTC()
		if t.Started.IsZero() || t.Started.After(now.Add(appMaxFutureSkew)) {
			t.Started = now
		}
		t.RootRoute, t.Status = appRouteTemplate(t.RootRoute), appClean(t.Status, 16)
		if !appKeepReasons[t.KeepReason] {
			t.KeepReason = "baseline"
		}
		if t.DurationMs < 0 {
			t.DurationMs = 0
		}
		trs = append(trs, t)
	}
	b.Traces = trs

	cls := b.Clients[:0]
	for _, c := range b.Clients {
		c.Service, c.Environment = appClean(c.Service, appMaxNameRunes), appEnv(c.Environment)
		c.Method = strings.ToUpper(appClean(c.Method, 8))
		if !appValidID(c.Service, appMaxNameRunes) || !appMethods[c.Method] {
			dropped++
			continue
		}
		c.Route = appRouteTemplate(c.Route)
		c.Minute = c.Minute.UTC().Truncate(time.Minute)
		if c.Minute.IsZero() || c.Minute.After(now.Add(appMaxFutureSkew)) || c.Minute.Before(now.Add(-appMaxStatAge)) {
			dropped++
			continue
		}
		c.ClientIP, c.PeerIP = appClientAddr(c.ClientIP), appClientAddr(c.PeerIP)
		c.ExcType = appClean(c.ExcType, 128)
		if (c.ClientIP == "" && c.PeerIP == "") || c.Failures < 0 || c.Failures > appMaxStatRequests ||
			c.Status40103 < 0 || c.Status429 < 0 || c.Status4xxOther < 0 || c.Status5xx < 0 {
			dropped++
			continue
		}
		cls = append(cls, c)
	}
	b.Clients = cls

	pms := b.Params[:0]
	for _, p := range b.Params {
		p.Service, p.Environment = appClean(p.Service, appMaxNameRunes), appEnv(p.Environment)
		p.Method = strings.ToUpper(appClean(p.Method, 8))
		if !appValidID(p.Service, appMaxNameRunes) || !appMethods[p.Method] || !appValidParamName(p.Name) || p.Count < 1 || p.Count > appMaxStatRequests {
			dropped++
			continue
		}
		p.Route = appRouteTemplate(p.Route)
		pms = append(pms, p)
	}
	b.Params = pms

	pls := b.Payloads[:0]
	for _, p := range b.Payloads {
		p.Service, p.Environment = appClean(p.Service, appMaxNameRunes), appEnv(p.Environment)
		p.Method = strings.ToUpper(appClean(p.Method, 8))
		if !appValidID(p.Service, appMaxNameRunes) || !appMethods[p.Method] {
			dropped++
			continue
		}
		p.Route = appRouteTemplate(p.Route)
		p.Time = p.Time.UTC()
		if p.Time.IsZero() || p.Time.After(now.Add(appMaxFutureSkew)) || p.Time.Before(now.Add(-appMaxStatAge)) {
			p.Time = now
		}
		if p.Status < 0 || p.Status > 999 {
			p.Status = 0
		}
		if !(p.DurationMs >= 0) || p.DurationMs > 3.6e6 { // also catches NaN
			p.DurationMs = 0
		}
		p.TraceID = strings.ToLower(appClean(p.TraceID, 64))
		clean := map[string]string{}
		for n, v := range p.Params {
			if len(clean) >= appMaxPayloadParams || !appValidParamName(n) || store.PayloadNameDenied(n) {
				continue
			}
			v = appClean(v, appMaxPayloadValue)
			if store.PayloadValueMasked(v) {
				continue
			}
			clean[n] = v
		}
		p.Params = clean
		wh := p.Withheld[:0]
		for _, n := range p.Withheld {
			if len(wh) < appMaxPayloadParams && appValidParamName(n) {
				wh = append(wh, n)
			}
		}
		p.Withheld = wh
		pls = append(pls, p)
	}
	b.Payloads = pls

	chs := b.Children[:0]
	for _, c := range b.Children {
		c.Service, c.Environment = appClean(c.Service, appMaxNameRunes), appEnv(c.Environment)
		c.Method = strings.ToUpper(appClean(c.Method, 8))
		c.Kind = appClean(c.Kind, 16)
		c.Minute = c.Minute.UTC().Truncate(time.Minute)
		if !appValidID(c.Service, appMaxNameRunes) || !appMethods[c.Method] || !appChildKinds[c.Kind] ||
			c.Minute.IsZero() || c.Minute.After(now.Add(appMaxFutureSkew)) || c.Minute.Before(now.Add(-appMaxStatAge)) ||
			c.Calls < 0 || c.Calls > appMaxStatRequests || c.TotalMs < 0 || c.TotalMs > 1e12 || c.TotalMs != c.TotalMs {
			dropped++
			continue
		}
		c.Route = appRouteTemplate(c.Route)
		c.Target, c.Name = appClean(c.Target, 128), appClean(c.Name, 80)
		chs = append(chs, c)
	}
	b.Children = chs

	qs := b.Queries[:0]
	for _, q := range b.Queries {
		q.Service, q.Environment = appClean(q.Service, appMaxNameRunes), appEnv(q.Environment)
		q.Minute = q.Minute.UTC().Truncate(time.Minute)
		if !appValidID(q.Service, appMaxNameRunes) || q.Minute.IsZero() || q.Minute.After(now.Add(appMaxFutureSkew)) ||
			q.Minute.Before(now.Add(-appMaxStatAge)) || q.Calls < 0 || q.Calls > appMaxStatRequests || q.Errors < 0 ||
			q.TotalMs < 0 || q.TotalMs > 1e12 || q.TotalMs != q.TotalMs {
			dropped++
			continue
		}
		q.System, q.Operation, q.Table = appClean(q.System, 64), appClean(q.Operation, 32), appClean(q.Table, 64)
		if q.System == "" {
			dropped++
			continue
		}
		q.Fingerprint = appClean(q.Fingerprint, 32)
		q.Text = appClean(q.Text, appMaxQueryText)
		if q.Fingerprint == "" || appLooksLikeLiteral(q.Text) { // text without a fingerprint, or with a literal left in, is never stored
			q.Text = ""
		}
		if len(q.DurBuckets) > 12 {
			q.DurBuckets = q.DurBuckets[:12]
		}
		qs = append(qs, q)
	}
	b.Queries = qs

	n1s := b.NPlusOne[:0]
	for _, n := range b.NPlusOne {
		n.Service, n.Environment = appClean(n.Service, appMaxNameRunes), appEnv(n.Environment)
		n.Method = strings.ToUpper(appClean(n.Method, 8))
		if !appValidID(n.Service, appMaxNameRunes) || !appMethods[n.Method] || n.Count < 0 || n.Count > appMaxStatRequests {
			dropped++
			continue
		}
		n.Route = appRouteTemplate(n.Route)
		n1s = append(n1s, n)
	}
	b.NPlusOne = n1s

	ers := b.Errors[:0]
	for _, e := range b.Errors {
		e.Service, e.Environment = appClean(e.Service, appMaxNameRunes), appEnv(e.Environment)
		e.Method = strings.ToUpper(appClean(e.Method, 8))
		e.Time = e.Time.UTC()
		if !appValidID(e.Service, appMaxNameRunes) || !appFingerprintRe.MatchString(e.Fingerprint) || e.Count <= 0 || e.Count > appMaxStatRequests ||
			(e.Method != "" && !appMethods[e.Method]) || e.Time.After(now.Add(appMaxFutureSkew)) {
			dropped++
			continue
		}
		if e.Route != "" {
			e.Route = appRouteTemplate(e.Route)
		}
		e.Type, e.Frame, e.Version = appClean(e.Type, 128), appClean(e.Frame, 200), appClean(e.Version, 64)
		e.Message = appClean(e.Message, 200)
		if appLooksLikeLiteral(e.Message) { // a masked message has no quotes or long numbers; one that does was not masked
			e.Message = ""
		}
		if !appTraceIDRe.MatchString(e.TraceID) {
			e.TraceID = ""
		}
		if len(e.Frames) > 30 {
			e.Frames = e.Frames[:30]
		}
		size := 0
		fr := e.Frames[:0]
		for _, f := range e.Frames {
			f = appClean(f, 200)
			if size += len(f); size > 4096 {
				break
			}
			fr = append(fr, f)
		}
		e.Frames = fr
		ers = append(ers, e)
	}
	b.Errors = ers

	mts := b.Metrics[:0]
	for _, m := range b.Metrics {
		m.Service, m.Environment = appClean(m.Service, appMaxNameRunes), appEnv(m.Environment)
		m.Name, m.Attr, m.Unit = appClean(m.Name, 96), appClean(m.Attr, 200), appClean(m.Unit, 16)
		m.Instance = appClean(m.Instance, 128)
		m.Minute = m.Minute.UTC().Truncate(time.Minute)
		if m.Identity != "verified" {
			m.Identity = "asserted"
		}
		if !appValidID(m.Service, appMaxNameRunes) || m.Instance == "" || !appMetricNameOK(m.Name) || m.Count <= 0 || m.Count > appMaxStatRequests ||
			!appFinite(m.Last, m.Min, m.Max, m.Sum) || m.Min > m.Max || m.Minute.After(now.Add(appMaxFutureSkew)) || m.Minute.Before(now.Add(-appMaxStatAge)) {
			dropped++
			continue
		}
		mts = append(mts, m)
	}
	b.Metrics = mts

	sps := b.Sampling[:0]
	for _, sm := range b.Sampling {
		sm.Service, sm.Environment = appClean(sm.Service, appMaxNameRunes), appEnv(sm.Environment)
		if !appValidID(sm.Service, appMaxNameRunes) || (sm.Reason != "error" && sm.Reason != "slow" && sm.Reason != "security" && sm.Reason != "baseline") ||
			sm.Seen < 0 || sm.Kept < 0 || sm.Kept > sm.Seen+appMaxStatRequests || sm.Seen > appMaxStatRequests*100 {
			dropped++
			continue
		}
		sps = append(sps, sm)
	}
	b.Sampling = sps

	ops := b.Operations[:0]
	for _, o := range b.Operations {
		o.Service, o.Environment = appClean(o.Service, appMaxNameRunes), appEnv(o.Environment)
		o.Name = appClean(o.Name, 96)
		o.Minute, o.LastRun = o.Minute.UTC().Truncate(time.Minute), o.LastRun.UTC()
		bad := !appValidID(o.Service, appMaxNameRunes) || (o.Kind != "job" && o.Kind != "consumer") || o.Name == "" ||
			o.Runs <= 0 || o.Runs > appMaxStatRequests || o.Failures < 0 || o.Failures > o.Runs ||
			o.Minute.After(now.Add(appMaxFutureSkew)) || o.Minute.Before(now.Add(-appMaxStatAge)) || o.LastRun.After(now.Add(appMaxFutureSkew))
		if o.LastRun.IsZero() {
			o.LastRun = o.Minute
		}
		if len(o.DurBuckets) != store.AppHistLen {
			h := make([]int64, store.AppHistLen)
			copy(h, o.DurBuckets)
			o.DurBuckets = h
		}
		for _, v := range o.DurBuckets {
			if v < 0 {
				bad = true
			}
		}
		if bad {
			dropped++
			continue
		}
		if o.Sketch != nil {
			if sk := store.SketchFromWire(o.Sketch); sk == nil || sk.Count() > o.Runs {
				o.Sketch = nil
			}
		}
		ops = append(ops, o)
	}
	b.Operations = ops

	nts := b.Notes[:0]
	for _, n := range b.Notes {
		n.Service, n.Environment = appClean(n.Service, appMaxNameRunes), appEnv(n.Environment)
		if !appValidID(n.Service, appMaxNameRunes) || n.RouteOverflow < 0 || n.TraceDrops < 0 || n.ClientOverflow < 0 {
			dropped++
			continue
		}
		nts = append(nts, n)
	}
	b.Notes = nts
	return dropped
}

// appClientAddr accepts an IP address or the truncated "a.b.c.0/24" form and nothing else.
func appClientAddr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return ""
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n.String()
	}
	return ""
}

// appEnv normalises the deployment environment; empty means "default".
func appEnv(s string) string {
	s = appClean(s, appMaxEnvRunes)
	if s == "" {
		return "default"
	}
	return s
}

// ── events for new services, instances, versions and dependencies ──────────

func appNewEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func appChangeEvents(agentID, host, osName string, changes []store.AppChange, now time.Time) []schema.Event {
	out := make([]schema.Event, 0, len(changes))
	for _, c := range changes {
		app := map[string]any{"service": c.Service, "environment": c.Environment, "baseline": c.Baseline}
		if c.InstanceID > 0 {
			app["instance"] = strconv.FormatInt(c.InstanceID, 10) // entity key for kind service_instance
		}
		if c.InstanceRef != "" {
			app["instance_ref"] = c.InstanceRef
		}
		if c.Identity != "" {
			app["identity"] = c.Identity
		}
		var et schema.EventType
		ev := schema.Event{ID: appNewEventID(), Time: now, AgentID: agentID, Host: host, OS: osName,
			Severity: schema.SeverityInfo, Source: appEventSourceLabel, PID: c.PID}
		switch c.Kind {
		case "service":
			et = "app.service_change"
			app["event.name"], app["change"] = "service_new", "service"
		case "instance":
			et = "app.service_change"
			app["event.name"], app["change"] = "instance_new", "instance"
			app["version"] = c.Version
			if c.ContainerID != "" {
				app["container_id"] = c.ContainerID
			}
		case "version":
			et = "app.service_change"
			app["event.name"], app["change"] = "version_changed", "version"
			app["version"], app["previous_version"] = c.Version, c.PrevVersion
		case "edge":
			et = "app.dependency_new"
			app["event.name"] = "dependency_new"
			app["dependency_kind"], app["dependency"], app["dependency_source"] = c.DstKind, c.DstName, c.Source
		default:
			continue
		}
		ev.EventType = et
		ev.Raw, _ = json.Marshal(map[string]any{"app": app})
		out = append(out, ev)
	}
	return out
}

// ── handler ────────────────────────────────────────────────────────────────

func appHandleBatch(db appBatchStore, logger *slog.Logger) http.HandlerFunc {
	limiter := appNewLimiter()
	cache := &appAgentCache{m: map[string]appAgentEntry{}}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, appMaxBatchBytes)
		var b store.AppBatch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if b.AgentID == "" || len(b.AgentID) > 128 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing or invalid agent_id"})
			return
		}
		if boundAgentMismatch(r, b.AgentID) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "agent_id does not match the client certificate"})
			return
		}
		if len(b.Instances) > appMaxInstances || len(b.Routes) > appMaxRoutes || len(b.Edges) > appMaxEdges || len(b.Traces) > appMaxTraces || len(b.Clients) > appMaxClients || len(b.Params) > appMaxParams || len(b.Payloads) > appMaxPayloads || len(b.Children) > appMaxChildren || len(b.Queries) > appMaxQueries || len(b.NPlusOne) > appMaxNPlusOne || len(b.Errors) > appMaxErrors || len(b.Metrics) > appMaxMetrics || len(b.Sampling) > appMaxSampling || len(b.Operations) > appMaxOperations {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "batch too large"})
			return
		}
		now := time.Now().UTC()

		ent, ok := cache.get(b.AgentID, now)
		if !ok {
			host, osName, found, err := db.AppAgentInfo(r.Context(), b.AgentID)
			if err != nil {
				logger.Error("app batch: agent lookup failed", "agent", b.AgentID, "err", err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
				return
			}
			ent = appAgentEntry{host: host, os: osName, ok: found, at: now}
			if found { // only cache hits so a freshly registered agent is accepted at once
				cache.put(b.AgentID, ent)
			}
		}
		if !ent.ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "unknown agent"})
			return
		}

		items := len(b.Instances) + len(b.Routes) + len(b.Edges) + len(b.Traces) + len(b.Clients) + len(b.Params) + len(b.Payloads) + len(b.Children) + len(b.Queries) + len(b.NPlusOne) + len(b.Errors) + len(b.Metrics) + len(b.Sampling) + len(b.Operations)
		if items == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"accepted": 0, "dropped": 0})
			return
		}
		if !limiter.allow(b.AgentID, items, now) {
			logger.Warn("app batch: per-agent rate limit exceeded", "agent", b.AgentID, "items", items)
			w.Header().Set("Retry-After", "30")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
			return
		}

		dropped := appSanitizeBatch(&b, now)
		res, err := db.AppIngestBatch(r.Context(), b.AgentID, ent.host, b, now)
		if err != nil {
			logger.Error("app batch: write failed", "agent", b.AgentID, "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}
		if evs := appChangeEvents(b.AgentID, ent.host, ent.os, res.Changes, now); len(evs) > 0 {
			if err := db.InsertEvents(r.Context(), evs); err != nil {
				logger.Error("app batch: event insert failed", "agent", b.AgentID, "err", err) // data is already stored
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"accepted": res.Instances + res.Routes + res.Edges + res.Traces + res.Clients + res.Params + res.Payloads, "dropped": dropped,
			"instances": res.Instances, "routes": res.Routes, "edges": res.Edges, "traces": res.Traces, "clients": res.Clients, "params": res.Params, "payloads": res.Payloads, "payloads_rejected": res.PayloadsRejected,
		})
	}
}

var appChildKinds = map[string]bool{"db": true, "http": true, "queue": true, "client": true}

// appLooksLikeLiteral reports text that still holds a quoted string or a long number, so a fingerprint that
// the agent failed to clean is dropped here rather than stored.
func appLooksLikeLiteral(t string) bool {
	if strings.Contains(t, "'") {
		return true
	}
	run := 0
	for _, r := range t {
		if r >= '0' && r <= '9' {
			if run++; run >= 6 {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

var appFingerprintRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
var appTraceIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// appMetricPrefixes are the metric names the platform stores (keep in step with the agent allowlist).
var appMetricPrefixes = []string{"process.cpu.", "process.memory.", "process.runtime.", "process.uptime", "v8js.", "nodejs.", "jvm.", "dotnet.",
	"db.client.connections.", "db.client.connection.", "http.server.active_requests"}

func appMetricNameOK(n string) bool {
	for _, p := range appMetricPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func appFinite(vs ...float64) bool {
	for _, v := range vs {
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 1e18 {
			return false
		}
	}
	return true
}

// appCleanRevision keeps a commit id of 7 to 64 lower-case hex characters.
func appCleanRevision(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 7 || len(s) > 64 {
		return ""
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return s
}
