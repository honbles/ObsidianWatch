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
	"net"
	"net/http"
	"net/url"
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
		if len(b.Instances) > appMaxInstances || len(b.Routes) > appMaxRoutes || len(b.Edges) > appMaxEdges || len(b.Traces) > appMaxTraces || len(b.Clients) > appMaxClients {
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

		items := len(b.Instances) + len(b.Routes) + len(b.Edges) + len(b.Traces) + len(b.Clients)
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
			"accepted": res.Instances + res.Routes + res.Edges + res.Traces + res.Clients, "dropped": dropped,
			"instances": res.Instances, "routes": res.Routes, "edges": res.Edges, "traces": res.Traces, "clients": res.Clients,
		})
	}
}
