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
}

// AppRouteStat is one per-minute aggregate for a route template.
type AppRouteStat struct {
	Service     string    `json:"service"`
	Environment string    `json:"environment"`
	Route       string    `json:"route"`
	Method      string    `json:"method"`
	Minute      time.Time `json:"minute"`
	Calls       int64     `json:"calls"`
	Errors      int64     `json:"errors"`
	Status2xx   int64     `json:"status_2xx"`
	Status40103 int64     `json:"status_401_403"`
	Status429   int64     `json:"status_429"`
	Status5xx   int64     `json:"status_5xx"`
	DurBuckets  []int64   `json:"duration_buckets"`
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
	AgentID   string           `json:"agent_id"`
	SentAt    time.Time        `json:"sent_at"`
	Instances []AppInstance    `json:"instances"`
	Routes    []AppRouteStat   `json:"routes"`
	Edges     []AppEdge        `json:"edges"`
	Traces    []AppTrace       `json:"traces"`
	Clients   []AppClientStat  `json:"clients"`
	Params    []AppRouteParam  `json:"params"`
	Payloads  []AppPayload     `json:"payloads"`
	Notes     []AppServiceNote `json:"notes"`
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
	Instances, Routes, Edges, Traces, Clients, Params, Payloads, PayloadsRejected int
	Changes                                                                       []AppChange
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
			"unit": in.Unit, "container_name": in.ContainerName, "image": in.Image})
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
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO app_route_stats (minute, service_id, route, method, calls, errors, status_2xx, status_401_403, status_429, status_5xx, duration_buckets)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
			ON CONFLICT (minute, service_id, route, method) DO UPDATE SET
			  calls          = app_route_stats.calls          + EXCLUDED.calls,
			  errors         = app_route_stats.errors         + EXCLUDED.errors,
			  status_2xx     = app_route_stats.status_2xx     + EXCLUDED.status_2xx,
			  status_401_403 = app_route_stats.status_401_403 + EXCLUDED.status_401_403,
			  status_429     = app_route_stats.status_429     + EXCLUDED.status_429,
			  status_5xx     = app_route_stats.status_5xx     + EXCLUDED.status_5xx,
			  duration_buckets = (SELECT COALESCE(jsonb_agg(
			      COALESCE((app_route_stats.duration_buckets->>g.i)::bigint,0) + COALESCE((EXCLUDED.duration_buckets->>g.i)::bigint,0)
			      ORDER BY g.i), '[]'::jsonb) FROM generate_series(0, 11) AS g(i))`,
			r.Minute, sid, r.Route, r.Method, r.Calls, r.Errors, r.Status2xx, r.Status40103, r.Status429, r.Status5xx, string(hist)); err != nil {
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
			   OR (SELECT COUNT(*) FROM service_route_params WHERE service_id=$1 AND route=$2 AND method=$3) < $7
			ON CONFLICT (service_id, route, method, name) DO UPDATE SET
			  requests = service_route_params.requests + EXCLUDED.requests,
			  last_seen = GREATEST(service_route_params.last_seen, EXCLUDED.last_seen)`,
			sid, p.Route, p.Method, p.Name, p.Count, now, AppMaxParamsPerRoute); err != nil {
			return res, fmt.Errorf("route params: %w", err)
		}
		res.Params++
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
				INSERT INTO app_payloads (service_id, agent_id, time, route, method, status, trace_id, params, withheld)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb)`,
				sid, agentID, p.Time, p.Route, p.Method, p.Status, p.TraceID, string(pj), string(wj)); err != nil {
				return res, fmt.Errorf("payload: %w", err)
			}
			res.Payloads++
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
	Service         string `json:"service"`
	Environment     string `json:"environment"`
	StoreClientIP   string `json:"store_client_ip"`
	CleartextUsers  bool   `json:"cleartext_users"`
	LatencyTargetMs int    `json:"latency_target_ms"`
	// PolicyOnly marks an entry that exists only to carry payload routes: the service has no saved settings,
	// so the agent must not treat the privacy fields above as an override.
	PolicyOnly bool                    `json:"policy_only,omitempty"`
	Payload    []AppRemotePayloadRoute `json:"payload_routes,omitempty"`
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
// share one database). A missing table means no settings yet, not an error.
func (db *DB) AppRemoteConfig(ctx context.Context) ([]AppRemoteService, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT s.name, s.environment, st.store_client_ip, st.cleartext_users, COALESCE(st.latency_target_ms, 0)
		FROM service_settings st JOIN services s ON s.id = st.service_id
		ORDER BY s.name, s.environment LIMIT 5000`)
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
		if err := rows.Scan(&r.Service, &r.Environment, &r.StoreClientIP, &r.CleartextUsers, &r.LatencyTargetMs); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return db.appAddPayloadRoutes(ctx, out)
}

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
