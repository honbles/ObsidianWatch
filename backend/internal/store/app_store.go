package store

// app_store.go - Application Monitoring persistence on the ingest backend.
// Owned by the Application build. Every identifier starts with App/app.
// Shapes follow Application Monitoring Spec v0.2 sections 4 and 5.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/lib/pq"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AppDurBounds are the fixed upper bounds (ms) of the latency histogram; the
// last bucket is +Inf, so a histogram has len(AppDurBounds)+1 counts.
var AppDurBounds = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

// AppHistLen is the number of histogram buckets stored per route per minute.
const AppHistLen = 12

// AppInstance is one running copy of a service. Process and container identity are
// stamped by the agent after it identified the sending process; the instrumented
// application never supplies them. Identity is "verified" when the sending process
// was bound to the service, "asserted" otherwise.
type AppInstance struct {
	Service       string          `json:"service"`
	Environment   string          `json:"environment"`
	Source        string          `json:"source"` // otel | discovered
	InstanceRef   string          `json:"instance_ref"`
	Version       string          `json:"version"`
	PID           int             `json:"pid"`
	ProcStart     time.Time       `json:"proc_start"`
	ContainerID   string          `json:"container_id"`
	Identity      string          `json:"identity"`
	Instrumented  bool            `json:"instrumented"`
	Listen        json.RawMessage `json:"listen"`
	Language      string          `json:"language"`
	SDK           string          `json:"sdk"`
	Exe           string          `json:"exe"`
	Sensor        string          `json:"sensor"` // host sensor tier: ebpf | procevent | poll (discovered instances)
	Unit          string          `json:"unit"`
	ContainerName string          `json:"container_name"`
	Image         string          `json:"image"`
	VCSRevision   string          `json:"vcs_revision"` // commit the process was built from
	VCSRepo       string          `json:"vcs_repo"`
	VCSBranch     string          `json:"vcs_branch"`
	VCSSource     string          `json:"vcs_source"` // otel | oci | git
}

// AppRouteStat is one per-minute aggregate for a route template.
type AppRouteStat struct {
	Service     string      `json:"service"`
	Environment string      `json:"environment"`
	Route       string      `json:"route"`
	Method      string      `json:"method"`
	Minute      time.Time   `json:"minute"`
	Calls       int64       `json:"calls"`
	Errors      int64       `json:"errors"`
	Status2xx   int64       `json:"status_2xx"`
	Status40103 int64       `json:"status_401_403"`
	Status429   int64       `json:"status_429"`
	Status5xx   int64       `json:"status_5xx"`
	DurBuckets  []int64     `json:"duration_buckets"`
	Sketch      *SketchWire `json:"sketch"`
}

// AppEdge is an outbound dependency observed from a service.
type AppEdge struct {
	Service     string `json:"service"`
	Environment string `json:"environment"`
	DstKind     string `json:"dst_kind"` // service | database | queue | external
	DstName     string `json:"dst_name"`
	Source      string `json:"source"` // otel | ebpf
	Calls       int64  `json:"calls"`
	Errors      int64  `json:"errors"`
}

// AppTrace is one sampled trace. Spans is opaque metadata JSON (<= 64 KB).
type AppTrace struct {
	TraceID     string          `json:"trace_id"`
	Service     string          `json:"service"`
	Environment string          `json:"environment"`
	Started     time.Time       `json:"started"`
	DurationMs  int             `json:"duration_ms"`
	RootRoute   string          `json:"root_route"`
	Status      string          `json:"status"`
	KeepReason  string          `json:"keep_reason"` // error | slow | security | baseline
	SpanCount   int             `json:"span_count"`
	Spans       json.RawMessage `json:"spans"`
}

// AppClientStat is a per-minute failure counter for one (route, client address) pair
// (spec rules A01, A09, A13). Only failures are reported.
type AppClientStat struct {
	Service        string    `json:"service"`
	Environment    string    `json:"environment"`
	Route          string    `json:"route"`
	Method         string    `json:"method"`
	Minute         time.Time `json:"minute"`
	ClientIP       string    `json:"client_ip"`
	PeerIP         string    `json:"peer_ip"`
	ExcType        string    `json:"exc_type"`
	Failures       int64     `json:"failures"`
	Status40103    int64     `json:"status_401_403"`
	Status429      int64     `json:"status_429"`
	Status4xxOther int64     `json:"status_4xx_other"`
	Status5xx      int64     `json:"status_5xx"`
}

// AppServiceNote carries per-service counters the agent could not store as rows:
// routes collapsed into the overflow route and traces dropped by the agent buffer.
// Values are deltas since the previous batch.
type AppServiceNote struct {
	Service        string `json:"service"`
	Environment    string `json:"environment"`
	RouteOverflow  int64  `json:"route_overflow"`
	TraceDrops     int64  `json:"trace_drops"`
	ClientOverflow int64  `json:"client_overflow"`
}

// AppBatch is the body of POST /api/v1/app/batch.
type AppBatch struct {
	AgentID    string           `json:"agent_id"`
	SentAt     time.Time        `json:"sent_at"`
	Instances  []AppInstance    `json:"instances"`
	Routes     []AppRouteStat   `json:"routes"`
	Edges      []AppEdge        `json:"edges"`
	Traces     []AppTrace       `json:"traces"`
	Clients    []AppClientStat  `json:"clients"`
	Params     []AppRouteParam  `json:"params"`
	Payloads   []AppPayload     `json:"payloads"`
	Children   []AppChild       `json:"children"`
	Queries    []AppQuery       `json:"queries"`
	NPlusOne   []AppNPlusOne    `json:"n_plus_one"`
	Errors     []AppError       `json:"errors"`
	Metrics    []AppMetric      `json:"metrics"`
	Sampling   []AppSampling    `json:"sampling"`
	Operations []AppOperation   `json:"operations"`
	Notes      []AppServiceNote `json:"notes"`
	// SchemaVersion is 2 when the agent sends children, queries and n_plus_one; an older agent omits it.
	SchemaVersion int `json:"schema_version"`
}

// AppOperation is one job or message consumer's runs in one minute.
type AppOperation struct {
	Service     string      `json:"service"`
	Environment string      `json:"environment"`
	Kind        string      `json:"kind"`
	Name        string      `json:"name"`
	Minute      time.Time   `json:"minute"`
	Runs        int64       `json:"runs"`
	Failures    int64       `json:"failures"`
	DurBuckets  []int64     `json:"duration_buckets"`
	Sketch      *SketchWire `json:"sketch"`
	LastRun     time.Time   `json:"last_run"`
}

// AppSampling counts the traces of one kind a service completed (seen) and kept since the agent's last flush.
type AppSampling struct {
	Service     string `json:"service"`
	Environment string `json:"environment"`
	Reason      string `json:"reason"`
	Seen        int64  `json:"seen"`
	Kept        int64  `json:"kept"`
}

// AppMetric is one runtime or pool series for one instance and minute.
type AppMetric struct {
	Service     string    `json:"service"`
	Environment string    `json:"environment"`
	Instance    string    `json:"instance"`
	Name        string    `json:"name"`
	Attr        string    `json:"attr"`
	Unit        string    `json:"unit"`
	Identity    string    `json:"identity"`
	Minute      time.Time `json:"minute"`
	Last        float64   `json:"last"`
	Min         float64   `json:"min"`
	Max         float64   `json:"max"`
	Sum         float64   `json:"sum"`
	Count       int64     `json:"count"`
}

// AppError is one error group's occurrences since the agent's last flush, with one scrubbed sample.
type AppError struct {
	Service     string    `json:"service"`
	Environment string    `json:"environment"`
	Route       string    `json:"route"`
	Method      string    `json:"method"`
	Fingerprint string    `json:"fingerprint"`
	Type        string    `json:"type"`
	Frame       string    `json:"frame"`
	Frames      []string  `json:"frames"`
	Message     string    `json:"message"`
	Version     string    `json:"version"`
	TraceID     string    `json:"trace_id"`
	Count       int64     `json:"count"`
	Time        time.Time `json:"time"`
}

// AppChild is one slow-downstream aggregate for a route in a minute.
type AppChild struct {
	Service     string    `json:"service"`
	Environment string    `json:"environment"`
	Route       string    `json:"route"`
	Method      string    `json:"method"`
	Minute      time.Time `json:"minute"`
	Kind        string    `json:"kind"`
	Target      string    `json:"target"`
	Name        string    `json:"name"`
	Calls       int64     `json:"calls"`
	TotalMs     float64   `json:"total_ms"`
}

// AppQuery is database calls grouped by operation, table and fingerprint for a minute.
type AppQuery struct {
	Service     string    `json:"service"`
	Environment string    `json:"environment"`
	Minute      time.Time `json:"minute"`
	System      string    `json:"system"`
	Operation   string    `json:"operation"`
	Table       string    `json:"table"`
	Fingerprint string    `json:"fingerprint"`
	Text        string    `json:"text"`
	Calls       int64     `json:"calls"`
	Errors      int64     `json:"errors"`
	TotalMs     float64   `json:"total_ms"`
	DurBuckets  []int64   `json:"duration_buckets"`
}

// AppNPlusOne counts the N+1 patterns the agent found under a route.
type AppNPlusOne struct {
	Service     string `json:"service"`
	Environment string `json:"environment"`
	Route       string `json:"route"`
	Method      string `json:"method"`
	Count       int64  `json:"count"`
}

// AppRouteParam counts one request parameter NAME seen on a route since the agent's last flush.
type AppRouteParam struct {
	Service     string `json:"service"`
	Environment string `json:"environment"`
	Route       string `json:"route"`
	Method      string `json:"method"`
	Name        string `json:"name"`
	Count       int64  `json:"count"`
}

// AppPayload is one sampled request's parameters from a route whose parameters were reviewed.
type AppPayload struct {
	Service     string            `json:"service"`
	Environment string            `json:"environment"`
	Route       string            `json:"route"`
	Method      string            `json:"method"`
	Time        time.Time         `json:"time"`
	Status      int               `json:"status"`
	DurationMs  float64           `json:"duration_ms"`
	TraceID     string            `json:"trace_id"`
	Params      map[string]string `json:"params"`
	Withheld    []string          `json:"withheld"`
}

// AppMaxParamsPerRoute bounds the distinct parameter names kept for one route.
const AppMaxParamsPerRoute = 200

// AppChange reports a first-seen service, instance, version or dependency so the
// API layer can emit app.service_change / app.dependency_new events.
type AppChange struct {
	Kind        string // "service" | "instance" | "version" | "edge"
	Service     string
	Environment string
	InstanceID  int64 // service_instances.id (entity kind service_instance)
	InstanceRef string
	Version     string
	PrevVersion string
	PID         int
	ContainerID string
	Identity    string
	DstKind     string
	DstName     string
	Source      string
	Baseline    bool // true when the service had nothing of this kind before (learning)
}

// AppIngestResult summarises what a batch wrote.
type AppIngestResult struct {
	Instances, Routes, Edges, Traces, Clients, Params, Payloads, PayloadsRejected, Children, Queries, Errors, Metrics, Operations int
	Changes                                                                                                                       []AppChange
	// KeptPayloads are the payloads stored after the route's capture policy, holding only the parameters it
	// allows; they are also recorded as app.payload events.
	KeptPayloads []AppPayload
}

// AppAgentInfo returns the registered agent's hostname and OS. ok is false when
// the agent id is not registered.
func (db *DB) AppAgentInfo(ctx context.Context, id string) (host, osName string, ok bool, err error) {
	err = db.QueryRowContext(ctx, `SELECT hostname, os FROM agents WHERE id = $1`, id).Scan(&host, &osName)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return host, osName, true, nil
}

func appNonEmptyJSON(raw json.RawMessage, def string) string {
	if len(raw) == 0 {
		return def
	}
	return string(raw)
}

// AppIngestBatch writes a validated batch in one transaction.
func (db *DB) AppIngestBatch(ctx context.Context, agentID, host string, b AppBatch, now time.Time) (AppIngestResult, error) {
	var res AppIngestResult
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()

	svcIDs := map[string]int64{}
	// svc finds or creates the service. The returned bool is true when it was created now.
	svc := func(name, env, source, lang string) (int64, bool, error) {
		k := name + "|" + env
		if id, ok := svcIDs[k]; ok {
			return id, false, nil
		}
		attrs := "{}"
		if lang != "" {
			a, _ := json.Marshal(map[string]string{"language": lang})
			attrs = string(a)
		}
		if source == "" {
			source = "discovered"
		}
		var id int64
		var created bool
		err := tx.QueryRowContext(ctx, `
			INSERT INTO services (name, environment, source, first_seen, last_seen, attrs)
			VALUES ($1,$2,$3,$4,$4,$5::jsonb)
			ON CONFLICT (name, environment) DO UPDATE SET
			  last_seen = GREATEST(services.last_seen, EXCLUDED.last_seen),
			  source    = CASE WHEN EXCLUDED.source = 'otel' THEN 'otel' ELSE services.source END,
			  attrs     = services.attrs || EXCLUDED.attrs
			RETURNING id, (xmax = 0)`, name, env, source, now, attrs).Scan(&id, &created)
		if err != nil {
			return 0, false, err
		}
		svcIDs[k] = id
		return id, created, nil
	}

	touchedVersions := map[string]bool{}
	for _, in := range b.Instances {
		sid, created, err := svc(in.Service, in.Environment, in.Source, in.Language)
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		if created {
			res.Changes = append(res.Changes, AppChange{Kind: "service", Service: in.Service, Environment: in.Environment, Source: in.Source, Baseline: true})
		}
		// Previous latest version, read before this instance's version is recorded.
		var prevVer sql.NullString
		var knownVersions int
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_versions WHERE service_id=$1`, sid).Scan(&knownVersions)
		_ = tx.QueryRowContext(ctx, `SELECT version FROM service_versions WHERE service_id=$1 ORDER BY first_seen DESC LIMIT 1`, sid).Scan(&prevVer)

		procStart := in.ProcStart
		if procStart.IsZero() {
			procStart = time.Unix(0, 0).UTC()
		}
		attrs, _ := json.Marshal(map[string]string{"language": in.Language, "sdk": in.SDK, "exe": in.Exe, "sensor": in.Sensor,
			"unit": in.Unit, "container_name": in.ContainerName, "image": in.Image,
			"vcs_revision": in.VCSRevision, "vcs_repo": in.VCSRepo, "vcs_branch": in.VCSBranch, "vcs_source": in.VCSSource})
		identity := in.Identity
		if identity != "verified" {
			identity = "asserted" // default to the weaker claim
		}
		if in.Source == "otel" && in.PID > 0 {
			if err := appMergeDiscovered(ctx, tx, sid, agentID, in.PID, procStart, now); err != nil {
				return res, fmt.Errorf("merge discovered: %w", err)
			}
		}
		var iid int64
		var inserted bool
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO service_instances (service_id, agent_id, host, container_id, pid, proc_start, instance_ref, version,
			                               listen, instrumented, identity, attrs, first_seen, last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12::jsonb,$13,$13)
			ON CONFLICT (service_id, agent_id, container_id, pid, proc_start) DO UPDATE SET
			  host=EXCLUDED.host, instance_ref=EXCLUDED.instance_ref, version=EXCLUDED.version,
			  listen=CASE WHEN EXCLUDED.listen <> '[]'::jsonb THEN EXCLUDED.listen ELSE service_instances.listen END,
			  instrumented = service_instances.instrumented OR EXCLUDED.instrumented,
			  identity = CASE WHEN service_instances.identity = 'verified' THEN 'verified' ELSE EXCLUDED.identity END,
			  attrs = service_instances.attrs || COALESCE((SELECT jsonb_object_agg(e.k, e.v) FROM jsonb_each(EXCLUDED.attrs) e(k, v) WHERE e.v <> '""'::jsonb), '{}'::jsonb),
			  last_seen=EXCLUDED.last_seen, stopped_at=NULL
			RETURNING id, (xmax = 0)`,
			sid, agentID, host, in.ContainerID, in.PID, procStart, in.InstanceRef, in.Version,
			appNonEmptyJSON(in.Listen, "[]"), in.Instrumented, identity, string(attrs), now).Scan(&iid, &inserted); err != nil {
			return res, fmt.Errorf("instance: %w", err)
		}
		res.Instances++
		if in.Source == "otel" && in.PID > 0 {
			if err := appFoldDiscoveredRows(ctx, tx, sid, agentID, in.PID, iid); err != nil {
				return res, fmt.Errorf("fold discovered: %w", err)
			}
		}
		if inserted {
			if in.InstanceRef != "" { // a restart replaces the previous process of the same instance
				_, _ = tx.ExecContext(ctx, `UPDATE service_instances SET stopped_at=$1
					WHERE service_id=$2 AND agent_id=$3 AND instance_ref=$4 AND id<>$5 AND stopped_at IS NULL`,
					now, sid, agentID, in.InstanceRef, iid)
			}
			res.Changes = append(res.Changes, AppChange{Kind: "instance", Service: in.Service, Environment: in.Environment,
				InstanceID: iid, InstanceRef: in.InstanceRef, Version: in.Version, PID: in.PID, ContainerID: in.ContainerID,
				Identity: identity, Baseline: created})
		}
		if in.Version == "" {
			continue
		}
		var newVer bool
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO service_versions (service_id, version, first_seen, last_seen) VALUES ($1,$2,$3,$3)
			ON CONFLICT (service_id, version) DO UPDATE SET last_seen = EXCLUDED.last_seen
			RETURNING (xmax = 0)`, sid, in.Version, now).Scan(&newVer); err != nil {
			return res, fmt.Errorf("version: %w", err)
		}
		touchedVersions[fmt.Sprintf("%d|%s", sid, in.Version)] = true
		if newVer {
			res.Changes = append(res.Changes, AppChange{Kind: "version", Service: in.Service, Environment: in.Environment,
				InstanceID: iid, InstanceRef: in.InstanceRef, Version: in.Version, PrevVersion: prevVer.String,
				Identity: identity, Baseline: knownVersions == 0})
		}
	}
	for k := range touchedVersions {
		var sid int64
		var ver string
		for i := 0; i < len(k); i++ {
			if k[i] == '|' {
				sid, _ = strconv.ParseInt(k[:i], 10, 64)
				ver = k[i+1:]
				break
			}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE service_versions SET instances = (
			  SELECT COUNT(*) FROM service_instances WHERE service_id=$1 AND version=$2 AND stopped_at IS NULL AND last_seen > $3)
			WHERE service_id=$1 AND version=$2`, sid, ver, now.Add(-10*time.Minute)); err != nil {
			return res, fmt.Errorf("version count: %w", err)
		}
	}

	for _, r := range b.Routes {
		sid, _, err := svc(r.Service, r.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,$2,$3,$4,$4)
			ON CONFLICT (service_id, route, method) DO UPDATE SET last_seen = GREATEST(service_routes.last_seen, EXCLUDED.last_seen)`,
			sid, r.Route, r.Method, now); err != nil {
			return res, fmt.Errorf("route: %w", err)
		}
		hist, _ := json.Marshal(r.DurBuckets)
		var skJSON any // nil keeps whatever sketch the row already has
		var skCalls int64
		if sk := SketchFromWire(r.Sketch); sk != nil && sk.Count() > 0 {
			var cur []byte
			_ = tx.QueryRowContext(ctx, `SELECT sketch FROM app_route_stats WHERE minute=$1 AND service_id=$2 AND route=$3 AND method=$4 FOR UPDATE`,
				r.Minute, sid, r.Route, r.Method).Scan(&cur)
			if len(cur) > 0 {
				var w SketchWire
				if json.Unmarshal(cur, &w) == nil {
					sk.Merge(SketchFromWire(&w))
				}
			}
			skCalls = SketchFromWire(r.Sketch).Count()
			b, _ := json.Marshal(sk.Wire())
			skJSON = string(b)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_route_stats (minute, service_id, route, method, calls, errors, status_2xx, status_401_403, status_429, status_5xx, duration_buckets, sketch, sketch_calls)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13)
			ON CONFLICT (minute, service_id, route, method) DO UPDATE SET
			  calls          = app_route_stats.calls          + EXCLUDED.calls,
			  errors         = app_route_stats.errors         + EXCLUDED.errors,
			  status_2xx     = app_route_stats.status_2xx     + EXCLUDED.status_2xx,
			  status_401_403 = app_route_stats.status_401_403 + EXCLUDED.status_401_403,
			  status_429     = app_route_stats.status_429     + EXCLUDED.status_429,
			  status_5xx     = app_route_stats.status_5xx     + EXCLUDED.status_5xx,
			  duration_buckets = (SELECT COALESCE(jsonb_agg(
			      COALESCE((app_route_stats.duration_buckets->>g.i)::bigint,0) + COALESCE((EXCLUDED.duration_buckets->>g.i)::bigint,0)
			      ORDER BY g.i), '[]'::jsonb) FROM generate_series(0, 11) AS g(i)),
			  sketch       = COALESCE(EXCLUDED.sketch, app_route_stats.sketch),
			  sketch_calls = app_route_stats.sketch_calls + EXCLUDED.sketch_calls`,
			r.Minute, sid, r.Route, r.Method, r.Calls, r.Errors, r.Status2xx, r.Status40103, r.Status429, r.Status5xx, string(hist), skJSON, skCalls); err != nil {
			return res, fmt.Errorf("route stats: %w", err)
		}
		res.Routes++
	}

	for _, e := range b.Edges {
		sid, _, err := svc(e.Service, e.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		var known int
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM service_edges WHERE src_service=$1`, sid).Scan(&known)
		var inserted bool
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO service_edges (src_service, dst_kind, dst_name, source, calls, errors, first_seen, last_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
			ON CONFLICT (src_service, dst_kind, dst_name, source) DO UPDATE SET
			  calls = service_edges.calls + EXCLUDED.calls, errors = service_edges.errors + EXCLUDED.errors,
			  last_seen = EXCLUDED.last_seen
			RETURNING (xmax = 0)`, sid, e.DstKind, e.DstName, e.Source, e.Calls, e.Errors, now).Scan(&inserted); err != nil {
			return res, fmt.Errorf("edge: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_edge_stats (hour, src_service, dst_kind, dst_name, source, calls, errors)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (hour, src_service, dst_kind, dst_name, source) DO UPDATE SET
			  calls = app_edge_stats.calls + EXCLUDED.calls, errors = app_edge_stats.errors + EXCLUDED.errors`,
			now.Truncate(time.Hour), sid, e.DstKind, e.DstName, e.Source, e.Calls, e.Errors); err != nil {
			return res, fmt.Errorf("edge stats: %w", err)
		}
		res.Edges++
		if inserted {
			res.Changes = append(res.Changes, AppChange{Kind: "edge", Service: e.Service, Environment: e.Environment,
				DstKind: e.DstKind, DstName: e.DstName, Source: e.Source, Baseline: known == 0})
		}
	}

	for _, t := range b.Traces {
		sid, _, err := svc(t.Service, t.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_traces (trace_id, service_id, agent_id, started, duration_ms, root_route, status, keep_reason, span_count, spans)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
			ON CONFLICT (trace_id) DO NOTHING`,
			t.TraceID, sid, agentID, t.Started, t.DurationMs, t.RootRoute, t.Status, t.KeepReason, t.SpanCount,
			appNonEmptyJSON(t.Spans, "[]")); err != nil {
			return res, fmt.Errorf("trace: %w", err)
		}
		res.Traces++
	}

	for _, c := range b.Clients {
		sid, _, err := svc(c.Service, c.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_client_stats (minute, service_id, route, method, client_ip, peer_ip, exc_type, failures,
			                              status_401_403, status_429, status_4xx_other, status_5xx)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (minute, service_id, route, method, client_ip, peer_ip, exc_type) DO UPDATE SET
			  failures         = app_client_stats.failures         + EXCLUDED.failures,
			  status_401_403   = app_client_stats.status_401_403   + EXCLUDED.status_401_403,
			  status_429       = app_client_stats.status_429       + EXCLUDED.status_429,
			  status_4xx_other = app_client_stats.status_4xx_other + EXCLUDED.status_4xx_other,
			  status_5xx       = app_client_stats.status_5xx       + EXCLUDED.status_5xx`,
			c.Minute, sid, c.Route, c.Method, c.ClientIP, c.PeerIP, c.ExcType, c.Failures,
			c.Status40103, c.Status429, c.Status4xxOther, c.Status5xx); err != nil {
			return res, fmt.Errorf("client stats: %w", err)
		}
		res.Clients++
	}

	for _, p := range b.Params {
		sid, _, err := svc(p.Service, p.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO service_routes (service_id, route, method, first_seen, last_seen) VALUES ($1,$2,$3,$4,$4)
			ON CONFLICT (service_id, route, method) DO UPDATE SET last_seen = GREATEST(service_routes.last_seen, EXCLUDED.last_seen)`,
			sid, p.Route, p.Method, now); err != nil {
			return res, fmt.Errorf("param route: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO service_route_params (service_id, route, method, name, requests, first_seen, last_seen)
			SELECT $1,$2,$3,$4,$5,$6,$6
			WHERE EXISTS (SELECT 1 FROM service_route_params WHERE service_id=$1 AND route=$2 AND method=$3 AND name=$4)
			   OR (SELECT COUNT(*) FROM service_route_params WHERE service_id=$1 AND route=$2 AND method=$3 AND source <> 'declared') < $7
			ON CONFLICT (service_id, route, method, name) DO UPDATE SET
			  requests = service_route_params.requests + EXCLUDED.requests,
			  source = CASE WHEN service_route_params.source = 'declared' THEN 'both' ELSE service_route_params.source END,
			  first_seen = CASE WHEN service_route_params.source = 'declared' THEN EXCLUDED.first_seen ELSE service_route_params.first_seen END,
			  last_seen = GREATEST(service_route_params.last_seen, EXCLUDED.last_seen)`,
			sid, p.Route, p.Method, p.Name, p.Count, now, AppMaxParamsPerRoute); err != nil {
			return res, fmt.Errorf("route params: %w", err)
		}
		res.Params++
	}

	for _, c := range b.Children {
		sid, _, err := svc(c.Service, c.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_route_children (minute, service_id, route, method, kind, target, name, calls, total_ms)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (service_id, route, method, minute, kind, target, name) DO UPDATE SET
			  calls = app_route_children.calls + EXCLUDED.calls, total_ms = app_route_children.total_ms + EXCLUDED.total_ms`,
			c.Minute, sid, c.Route, c.Method, c.Kind, c.Target, c.Name, c.Calls, c.TotalMs); err != nil {
			return res, fmt.Errorf("route children: %w", err)
		}
		res.Children++
	}
	for _, q := range b.Queries {
		sid, _, err := svc(q.Service, q.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		hist, _ := json.Marshal(appPadHist(q.DurBuckets))
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_db_stats (minute, service_id, system, operation, tbl, fingerprint, text, calls, errors, total_ms, duration_buckets)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
			ON CONFLICT (service_id, minute, system, operation, tbl, fingerprint) DO UPDATE SET
			  calls = app_db_stats.calls + EXCLUDED.calls, errors = app_db_stats.errors + EXCLUDED.errors,
			  total_ms = app_db_stats.total_ms + EXCLUDED.total_ms,
			  text = CASE WHEN app_db_stats.text = '' THEN EXCLUDED.text ELSE app_db_stats.text END,
			  duration_buckets = (SELECT COALESCE(jsonb_agg(
			      COALESCE((app_db_stats.duration_buckets->>g.i)::bigint,0) + COALESCE((EXCLUDED.duration_buckets->>g.i)::bigint,0)
			      ORDER BY g.i), '[]'::jsonb) FROM generate_series(0, 11) AS g(i))`,
			q.Minute, sid, q.System, q.Operation, q.Table, q.Fingerprint, q.Text, q.Calls, q.Errors, q.TotalMs, string(hist)); err != nil {
			return res, fmt.Errorf("db stats: %w", err)
		}
		res.Queries++
	}
	for _, n := range b.NPlusOne {
		sid, _, err := svc(n.Service, n.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_route_n1 (minute, service_id, route, method, count) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (service_id, route, method, minute) DO UPDATE SET count = app_route_n1.count + EXCLUDED.count`,
			now.Truncate(time.Minute), sid, n.Route, n.Method, n.Count); err != nil {
			return res, fmt.Errorf("n+1: %w", err)
		}
	}

	for _, e := range b.Errors {
		sid, _, err := svc(e.Service, e.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		if err := appUpsertErrorGroup(ctx, tx, sid, e, now); err != nil {
			return res, fmt.Errorf("error group: %w", err)
		}
		res.Errors++
	}
	for _, o := range b.Operations {
		sid, _, err := svc(o.Service, o.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		hist, _ := json.Marshal(o.DurBuckets)
		var skJSON any
		var skCalls int64
		if sk := SketchFromWire(o.Sketch); sk != nil && sk.Count() > 0 {
			var cur []byte
			_ = tx.QueryRowContext(ctx, `SELECT sketch FROM app_operations WHERE minute=$1 AND service_id=$2 AND kind=$3 AND name=$4 FOR UPDATE`,
				o.Minute, sid, o.Kind, o.Name).Scan(&cur)
			if len(cur) > 0 {
				var w SketchWire
				if json.Unmarshal(cur, &w) == nil {
					sk.Merge(SketchFromWire(&w))
				}
			}
			skCalls = SketchFromWire(o.Sketch).Count()
			b, _ := json.Marshal(sk.Wire())
			skJSON = string(b)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_operations (minute, service_id, kind, name, runs, failures, duration_buckets, sketch, sketch_calls, last_run)
			VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10)
			ON CONFLICT (service_id, kind, name, minute) DO UPDATE SET
			  runs = app_operations.runs + EXCLUDED.runs, failures = app_operations.failures + EXCLUDED.failures,
			  duration_buckets = (SELECT COALESCE(jsonb_agg(
			      COALESCE((app_operations.duration_buckets->>g.i)::bigint,0) + COALESCE((EXCLUDED.duration_buckets->>g.i)::bigint,0)
			      ORDER BY g.i), '[]'::jsonb) FROM generate_series(0, 11) AS g(i)),
			  sketch = COALESCE(EXCLUDED.sketch, app_operations.sketch),
			  sketch_calls = app_operations.sketch_calls + EXCLUDED.sketch_calls,
			  last_run = GREATEST(app_operations.last_run, EXCLUDED.last_run)`,
			o.Minute, sid, o.Kind, o.Name, o.Runs, o.Failures, string(hist), skJSON, skCalls, o.LastRun); err != nil {
			return res, fmt.Errorf("operations: %w", err)
		}
		res.Operations++
	}
	for _, sm := range b.Sampling {
		sid, _, err := svc(sm.Service, sm.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_sampling_stats (hour, service_id, reason, seen, kept) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (service_id, reason, hour) DO UPDATE SET seen = app_sampling_stats.seen + EXCLUDED.seen, kept = app_sampling_stats.kept + EXCLUDED.kept`,
			now.Truncate(time.Hour), sid, sm.Reason, sm.Seen, sm.Kept); err != nil {
			return res, fmt.Errorf("sampling: %w", err)
		}
	}
	for _, m := range b.Metrics {
		sid, _, err := svc(m.Service, m.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_metrics (minute, service_id, instance, name, attr, unit, identity, last, min, max, sum, count)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			ON CONFLICT (service_id, instance, name, attr, minute) DO UPDATE SET
			  last = EXCLUDED.last, min = LEAST(app_metrics.min, EXCLUDED.min), max = GREATEST(app_metrics.max, EXCLUDED.max),
			  sum = app_metrics.sum + EXCLUDED.sum, count = app_metrics.count + EXCLUDED.count`,
			m.Minute, sid, m.Instance, m.Name, m.Attr, m.Unit, m.Identity, m.Last, m.Min, m.Max, m.Sum, m.Count); err != nil {
			return res, fmt.Errorf("metrics: %w", err)
		}
		res.Metrics++
	}
	if len(b.Payloads) > 0 {
		var havePolicy bool
		_ = tx.QueryRowContext(ctx, `SELECT to_regclass('app_route_payload_policy') IS NOT NULL`).Scan(&havePolicy)
		type pk struct {
			sid           int64
			route, method string
		}
		allowOf := map[pk]map[string]bool{}
		for _, p := range b.Payloads {
			sid, _, err := svc(p.Service, p.Environment, "otel", "")
			if err != nil {
				return res, fmt.Errorf("service: %w", err)
			}
			k := pk{sid, p.Route, p.Method}
			allow, loaded := allowOf[k]
			if !loaded && havePolicy {
				var reviewed, masked []byte
				err := tx.QueryRowContext(ctx, `SELECT reviewed_names, masked FROM app_route_payload_policy WHERE service_id=$1 AND route=$2 AND method=$3`,
					sid, p.Route, p.Method).Scan(&reviewed, &masked)
				if err == nil {
					allow = appPayloadAllow(reviewed, masked)
				} else if err != sql.ErrNoRows {
					return res, fmt.Errorf("payload policy: %w", err)
				}
				allowOf[k] = allow
			}
			if allow == nil { // no saved policy for this route: nothing is stored, whatever the agent sent
				res.PayloadsRejected++
				continue
			}
			kept, withheld := map[string]string{}, append([]string{}, p.Withheld...)
			for n, v := range p.Params {
				if allow[n] && !PayloadNameDenied(n) && !PayloadValueMasked(v) {
					kept[n] = v
				} else {
					withheld = append(withheld, n)
				}
			}
			if len(kept) == 0 && len(withheld) == 0 {
				continue
			}
			sort.Strings(withheld)
			pj, _ := json.Marshal(kept)
			wj, _ := json.Marshal(withheld)
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO app_payloads (service_id, agent_id, time, route, method, status, duration_ms, trace_id, params, withheld)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb)`,
				sid, agentID, p.Time, p.Route, p.Method, p.Status, p.DurationMs, p.TraceID, string(pj), string(wj)); err != nil {
				return res, fmt.Errorf("payload: %w", err)
			}
			res.Payloads++
			kp := p
			kp.Params, kp.Withheld = kept, withheld
			res.KeptPayloads = append(res.KeptPayloads, kp)
		}
	}

	for _, n := range b.Notes {
		sid, _, err := svc(n.Service, n.Environment, "otel", "")
		if err != nil {
			return res, fmt.Errorf("service: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE services SET attrs = attrs || jsonb_build_object(
			  'route_overflow', COALESCE((attrs->>'route_overflow')::bigint,0) + $2::bigint,
			  'trace_drops',    COALESCE((attrs->>'trace_drops')::bigint,0)    + $3::bigint,
			  'client_overflow', COALESCE((attrs->>'client_overflow')::bigint,0) + $4::bigint)
			WHERE id = $1`, sid, n.RouteOverflow, n.TraceDrops, n.ClientOverflow); err != nil {
			return res, fmt.Errorf("note: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return res, err
	}
	return res, nil
}

// AppRemoteService is one service's agent-relevant settings (client-address mode, cleartext
// opt-in, latency target). The agent polls these so changes made in the UI take effect without
// rebuilding it.
type AppRemoteService struct {
	Service          string `json:"service"`
	Environment      string `json:"environment"`
	StoreClientIP    string `json:"store_client_ip"`
	CleartextUsers   bool   `json:"cleartext_users"`
	LatencyTargetMs  int    `json:"latency_target_ms"`
	DBStatementMode  string `json:"db_statement_mode,omitempty"`  // off | fingerprint
	ErrorMessageMode string `json:"error_message_mode,omitempty"` // off | masked
	// Sampling is the trace sampling policy; nil means the agent's defaults.
	Sampling *AppSamplingPolicy `json:"sampling,omitempty"`
	// PolicyOnly marks an entry that exists only to carry payload routes: the service has no saved settings,
	// so the agent must not treat the privacy fields above as an override.
	PolicyOnly bool                    `json:"policy_only,omitempty"`
	Payload    []AppRemotePayloadRoute `json:"payload_routes,omitempty"`
}

// AppSamplingPolicy mirrors the agent's SamplePolicy.
type AppSamplingPolicy struct {
	BaselinePct    *float64 `json:"baseline_pct,omitempty"`
	ErrorMaxPerMin int      `json:"error_max_per_min,omitempty"`
	MaxPerFlush    int      `json:"max_per_flush,omitempty"`
}

// AppRemotePayloadRoute is a route an admin has reviewed and the parameter names left unmasked.
type AppRemotePayloadRoute struct {
	Route  string   `json:"route"`
	Method string   `json:"method"`
	Allow  []string `json:"allow"`
}

// appPayloadAllow turns a saved policy (the names the admin saw, the names they masked) into the names that
// may be forwarded: reviewed, not masked, not on the always-masked list.
func appPayloadAllow(reviewedJSON, maskedJSON []byte) map[string]bool {
	var reviewed, masked []string
	_ = json.Unmarshal(reviewedJSON, &reviewed)
	_ = json.Unmarshal(maskedJSON, &masked)
	m := map[string]bool{}
	for _, n := range masked {
		m[n] = true
	}
	allow := map[string]bool{}
	for _, n := range reviewed {
		if !m[n] && !PayloadNameDenied(n) {
			allow[n] = true
		}
	}
	return allow
}

// AppRemoteConfig reads service_settings (created by the management migration; the two backends
// share one database). A missing table means no settings yet, not an error. Every known service is sent:
// one whose settings were never saved gets the defaults (the console's appDefaultSettings), so a default
// such as statement fingerprints reaches the agent without anyone saving the settings page.
func (db *DB) AppRemoteConfig(ctx context.Context) ([]AppRemoteService, error) {
	const q = `
		SELECT s.name, s.environment, COALESCE(st.store_client_ip, 'full'), COALESCE(st.cleartext_users, false),
		       COALESCE(st.latency_target_ms, 0), %s
		FROM services s LEFT JOIN service_settings st ON s.id = st.service_id
		ORDER BY s.name, s.environment LIMIT 5000`
	// Newest column set first; an older management schema falls back to fewer columns.
	variants := []string{
		"COALESCE(st.db_statement_mode, '" + AppDefaultDBStatementMode + "'), COALESCE(st.error_message_mode, 'off'), COALESCE(st.sampling, '{}'::jsonb)",
		"COALESCE(st.db_statement_mode, '" + AppDefaultDBStatementMode + "'), COALESCE(st.error_message_mode, 'off'), '{}'::jsonb",
		"'off', 'off', '{}'::jsonb",
	}
	var rows *sql.Rows
	var err error
	for _, v := range variants {
		rows, err = db.QueryContext(ctx, fmt.Sprintf(q, v))
		if pe, ok := err.(*pq.Error); ok && pe.Code == "42703" { // management migration 066, 067 or 068 not applied yet
			continue
		}
		break
	}
	if err != nil {
		if pe, ok := err.(*pq.Error); ok && pe.Code == "42P01" { // undefined_table
			return db.appAddPayloadRoutes(ctx, []AppRemoteService{})
		}
		return nil, err
	}
	defer rows.Close()
	out := []AppRemoteService{}
	for rows.Next() {
		var r AppRemoteService
		var samp []byte
		if err := rows.Scan(&r.Service, &r.Environment, &r.StoreClientIP, &r.CleartextUsers, &r.LatencyTargetMs, &r.DBStatementMode, &r.ErrorMessageMode, &samp); err != nil {
			return nil, err
		}
		var sp AppSamplingPolicy
		if json.Unmarshal(samp, &sp) == nil && (sp.BaselinePct != nil || sp.ErrorMaxPerMin != 0 || sp.MaxPerFlush != 0) {
			r.Sampling = &sp
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return db.appAddPayloadRoutes(ctx, out)
}

// AppDefaultDBStatementMode is the statement mode of a service whose settings were never saved (management
// migration 084 made fingerprints the default).
const AppDefaultDBStatementMode = "fingerprint"

// appAddPayloadRoutes attaches each service's reviewed routes. A service with a policy but no saved settings
// gets a PolicyOnly entry. A missing policy table means no route has been reviewed.
func (db *DB) appAddPayloadRoutes(ctx context.Context, out []AppRemoteService) ([]AppRemoteService, error) {
	var have bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('app_route_payload_policy') IS NOT NULL`).Scan(&have); err != nil || !have {
		return out, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT s.name, s.environment, p.route, p.method, p.reviewed_names, p.masked
		FROM app_route_payload_policy p JOIN services s ON s.id = p.service_id
		ORDER BY s.name, s.environment, p.route LIMIT 20000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	idx := map[string]int{}
	for i, r := range out {
		idx[r.Service+"|"+r.Environment] = i
	}
	for rows.Next() {
		var name, env, route, method string
		var reviewed, masked []byte
		if err := rows.Scan(&name, &env, &route, &method, &reviewed, &masked); err != nil {
			return nil, err
		}
		i, ok := idx[name+"|"+env]
		if !ok {
			out = append(out, AppRemoteService{Service: name, Environment: env, PolicyOnly: true})
			i = len(out) - 1
			idx[name+"|"+env] = i
		}
		allow := []string{}
		for n := range appPayloadAllow(reviewed, masked) {
			allow = append(allow, n)
		}
		sort.Strings(allow)
		out[i].Payload = append(out[i].Payload, AppRemotePayloadRoute{Route: route, Method: method, Allow: allow})
		// A route reviewed from an API spec may be written in the other template style than the framework
		// reports ("/users/{id}" or "/users/:id"). Send both; the agent matches on the route it actually sees.
		if alt := appRouteOtherStyle(route); alt != route {
			out[i].Payload = append(out[i].Payload, AppRemotePayloadRoute{Route: alt, Method: method, Allow: allow})
		}
	}
	return out, rows.Err()
}

// appMergeDiscovered folds a host-discovered service into the instrumented one that now reports the
// same process (same agent and pid; same start time when both know it). The discovered name comes from
// the executable and rarely equals the application's own service.name, so the process is the key.
// The instance, the learned baselines, the analyst's settings and the learning clock all move to the
// instrumented service, and the discovered service is removed when nothing is left under it.
func appMergeDiscovered(ctx context.Context, tx *sql.Tx, newID int64, agentID string, pid int, procStart time.Time, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT i.id, i.service_id FROM service_instances i JOIN services s ON s.id = i.service_id
		WHERE i.agent_id = $1 AND i.pid = $2 AND s.source = 'discovered' AND i.service_id <> $3
		  AND (i.proc_start = $4 OR i.proc_start = 'epoch' OR $4 = 'epoch')`, agentID, pid, newID, procStart)
	if err != nil {
		return err
	}
	type pair struct{ inst, svc int64 }
	var found []pair
	for rows.Next() {
		var p pair
		if rows.Scan(&p.inst, &p.svc) == nil {
			found = append(found, p)
		}
	}
	rows.Close()
	for _, p := range found {
		// If the instrumented service already has this exact process row, the discovered row is redundant.
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM service_instances d USING service_instances o
			WHERE d.id = $1 AND o.service_id = $2 AND o.agent_id = d.agent_id AND o.container_id = d.container_id
			  AND o.pid = d.pid AND o.proc_start = d.proc_start`, p.inst, newID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE service_instances SET service_id = $2 WHERE id = $1`, p.inst, newID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE services SET first_seen = LEAST(services.first_seen, o.first_seen)
			FROM services o WHERE services.id = $1 AND o.id = $2`, newID, p.svc); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_baselines (service_id, kind, key, stats, samples, first_seen, updated)
			SELECT $1, kind, key, stats, samples, first_seen, updated FROM app_baselines WHERE service_id = $2
			ON CONFLICT DO NOTHING`, newID, p.svc); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM app_baselines WHERE service_id = $1`, p.svc); err != nil {
			return err
		}
		// service_settings is created by the management migration; it may not exist yet. A savepoint keeps a
		// missing table from aborting the whole batch.
		if _, err := tx.ExecContext(ctx, `SAVEPOINT app_merge_settings`); err != nil {
			return err
		}
		_, e1 := tx.ExecContext(ctx, `
			UPDATE service_settings SET service_id = $1
			WHERE service_id = $2 AND NOT EXISTS (SELECT 1 FROM service_settings WHERE service_id = $1)`, newID, p.svc)
		if e1 == nil {
			_, e1 = tx.ExecContext(ctx, `DELETE FROM service_settings WHERE service_id = $1`, p.svc)
		}
		if e1 != nil {
			if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT app_merge_settings`); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT app_merge_settings`); err != nil {
			return err
		}
		// Remove the discovered service when it has nothing left (its stats/routes would be empty by construction).
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM services WHERE id = $1 AND source = 'discovered'
			  AND NOT EXISTS (SELECT 1 FROM service_instances WHERE service_id = $1)`, p.svc); err != nil {
			return err
		}
	}
	return nil
}

// appFoldDiscoveredRows collapses the host sensor's row for a process into the instrumented row of the same
// process (the two can differ slightly in process start time, which keeps them from matching exactly). The
// instrumented row keeps its own values and gains what only the sensor knew: listening ports and any
// attribute it lacks (unit, container name, image, host sensor tier, executable).
func appFoldDiscoveredRows(ctx context.Context, tx *sql.Tx, serviceID int64, agentID string, pid int, keepID int64) error {
	_, err := tx.ExecContext(ctx, `
		WITH d AS (
			DELETE FROM service_instances
			WHERE service_id = $1 AND agent_id = $2 AND pid = $3 AND id <> $4 AND NOT instrumented AND stopped_at IS NULL
			RETURNING listen, attrs, last_seen
		), x AS (SELECT listen, attrs FROM d ORDER BY last_seen DESC LIMIT 1)
		UPDATE service_instances o SET
		  listen = CASE WHEN o.listen = '[]'::jsonb THEN x.listen ELSE o.listen END,
		  attrs = o.attrs || COALESCE((SELECT jsonb_object_agg(e.k, e.v) FROM jsonb_each(x.attrs) e(k, v)
		                               WHERE e.v <> '""'::jsonb AND COALESCE(o.attrs->>e.k, '') = ''), '{}'::jsonb)
		FROM x WHERE o.id = $4`, serviceID, agentID, pid, keepID)
	return err
}

// appRouteOtherStyle rewrites path parameters to the other common template style: a route written with "{id}"
// becomes ":id" and the reverse (a mixed route is made all ":id"). A route that uses neither is returned unchanged.
func appRouteOtherStyle(route string) string {
	parts := strings.Split(route, "/")
	braces := false
	for _, p := range parts {
		if len(p) > 2 && p[0] == '{' && p[len(p)-1] == '}' && !strings.ContainsAny(p[1:len(p)-1], "{}:/") {
			braces = true
		}
	}
	changed := false
	for i, p := range parts {
		switch {
		case braces && len(p) > 2 && p[0] == '{' && p[len(p)-1] == '}' && !strings.ContainsAny(p[1:len(p)-1], "{}:/"):
			parts[i], changed = ":"+p[1:len(p)-1], true
		case !braces && len(p) > 1 && p[0] == ':' && !strings.ContainsAny(p[1:], "{}:/"):
			parts[i], changed = "{"+p[1:]+"}", true
		case braces && len(p) > 1 && p[0] == ':':
			changed = true // already the colon style; keep as is
		}
	}
	if !changed {
		return route
	}
	return strings.Join(parts, "/")
}

// appPadHist returns exactly 12 histogram buckets.
func appPadHist(h []int64) []int64 {
	out := make([]int64, 12)
	copy(out, h)
	return out
}

// appUpsertErrorGroup counts occurrences into a group. A resolved group that fails again under a different
// version than the one it was resolved in is reopened and marked regressed; an ignored group stays ignored.
func appUpsertErrorGroup(ctx context.Context, tx *sql.Tx, sid int64, e AppError, now time.Time) error {
	seen := e.Time.UTC()
	if seen.IsZero() || seen.After(now) {
		seen = now
	}
	frames, _ := json.Marshal(e.Frames)
	var id int64
	var status, resolvedVer string
	var traces []byte
	err := tx.QueryRowContext(ctx, `SELECT id, status, resolved_version, sample_traces FROM error_groups WHERE service_id=$1 AND fingerprint=$2 FOR UPDATE`,
		sid, e.Fingerprint).Scan(&id, &status, &resolvedVer, &traces)
	if err == sql.ErrNoRows {
		tj, _ := json.Marshal(appTraceList(nil, e.TraceID))
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO error_groups (service_id, fingerprint, type, route, method, frame, frames, message, first_seen, last_seen, count,
			                          first_version, last_version, sample_traces)
			VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$9,$10,$11,$11,$12::jsonb) RETURNING id`,
			sid, e.Fingerprint, e.Type, e.Route, e.Method, e.Frame, string(frames), e.Message, seen, e.Count, e.Version, string(tj)).Scan(&id); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO error_group_hours (group_id, hour, count) VALUES ($1,$2,$3)`, id, seen.Truncate(time.Hour), e.Count)
		return err
	}
	if err != nil {
		return err
	}
	regress := status == "resolved" && e.Version != "" && e.Version != resolvedVer
	var prev []string
	_ = json.Unmarshal(traces, &prev)
	tj, _ := json.Marshal(appTraceList(prev, e.TraceID))
	if _, err := tx.ExecContext(ctx, `
		UPDATE error_groups SET count = count + $2, last_seen = GREATEST(last_seen, $3),
		  last_version = CASE WHEN $4 <> '' THEN $4 ELSE last_version END,
		  frame = CASE WHEN frame = '' THEN $5 ELSE frame END,
		  frames = CASE WHEN frames = '[]'::jsonb THEN $6::jsonb ELSE frames END,
		  message = CASE WHEN message = '' THEN $7 ELSE message END,
		  sample_traces = $8::jsonb,
		  status = CASE WHEN $9 THEN 'open' ELSE status END,
		  regressed = regressed OR $9,
		  regressed_at = CASE WHEN $9 THEN $10 ELSE regressed_at END
		WHERE id = $1`, id, e.Count, seen, e.Version, e.Frame, string(frames), e.Message, string(tj), regress, now); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO error_group_hours (group_id, hour, count) VALUES ($1,$2,$3)
		ON CONFLICT (group_id, hour) DO UPDATE SET count = error_group_hours.count + EXCLUDED.count`, id, seen.Truncate(time.Hour), e.Count)
	return err
}

// appTraceList keeps the five most recent distinct sample trace ids.
func appTraceList(prev []string, add string) []string {
	out := []string{}
	if add != "" {
		out = append(out, add)
	}
	for _, t := range prev {
		if t != add && len(out) < 5 {
			out = append(out, t)
		}
	}
	return out
}
