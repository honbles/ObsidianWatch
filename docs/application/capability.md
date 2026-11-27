# Application monitoring: what it does, end to end

This document follows application telemetry from the application process to the console and the alerts. It is framework independent. For setup see [deployment.md](deployment.md) and the `configuration-*.md` files. For the server-side settings see [configuration-platform.md](configuration-platform.md).

It describes the code as it is in this repository (Linux agent 0.3.1). Every major section names the files that implement it. Where the code has a defect that changes what you see, the section says so. Section 15 lists the defects in one place. Read it before you rely on a feature.

Contents

1. Overview and data path
2. Receiving OTLP on the host
3. Which process is sending (identity)
4. What is kept from a span, a log and a metric (allowlists)
5. Aggregation in the agent
6. Sending to the backend
7. Ingest and storage
8. Settings pulled by the agent
9. Host runtime sensor and service discovery
10. Management engines: what is computed and where you see it
11. Detection rules
12. Limits and caps
13. Privacy guarantees
14. What is not supported
15. Known defects

---

## 1. Overview and data path

```
application (OpenTelemetry SDK or Java agent)
   │  OTLP over HTTP, protobuf or JSON, to 127.0.0.1:4318 or a Unix socket
   ▼
ObsidianWatch agent, same host
   receiver ─► identity (which pid sent this?) ─► allowlist decode ─► aggregator
   (raw spans never leave the host; only per-minute statistics, names, sampled trace skeletons)
   │  every 30 s, HTTPS with the agent's enrolled client certificate
   ▼
ingest backend  POST /api/v1/app/batch   ─► PostgreSQL tables (services, app_route_stats, ...)
   ▲  GET /api/v1/app/agent-config (agent pulls per-service settings every 5 min)
   │
management backend  /api/v1/app/*  ─► rule engine (1-minute scan + host-event tap) ─► alerts
   ▼
console  Applications → Overview, Services, Dependencies, Coverage, Settings, service pages
```

Two other streams join the picture:

- **Security-helper events.** Optional OTLP log records with an `event.name` such as `auth.login`. The agent turns them into `app.security` events and sends them through its normal event channel, not the batch endpoint. When that channel is full (a busy host), the receiver waits up to 2 s for room before dropping the event; before this fix they were dropped at once, which lost every helper event on a busy Docker host.
- **Host runtime sensor.** Part of the same agent profile. It discovers services by their listening ports (Tier 0) and reports process, network and file events under service processes. Those go through the normal event channel too.

Telemetry tiers:

| Tier | Condition (code) | What you get |
|---|---|---|
| T0 | Service known only from the host sensor (`services.source = 'discovered'`) | Service, host, listening ports, container, runtime events, host rules |
| T1 | Service has sent OTLP (`source = 'otel'`), from an SDK in the app or from the agent's eBPF instrumentation (shown "T1·eBPF") | Routes, RED metrics, dependencies, traces, errors, request-based rules |
| T2 | T1 and at least one `app.security` event in the last 14 days | Security tab, hashed user ids on events |

Implemented in: `management/backend/internal/api/app_tier.go`, `app_services.go` (`appTier`).

### 1.1 Request tracing without code changes (eBPF)

When the Agent builder option **Trace requests without code changes (eBPF, Linux)** is on, the package carries OpenTelemetry eBPF Instrumentation (OBI, Apache-2.0) and the agent runs it as a child process (`app_monitoring.ebpf.requests.enabled: true`; binary `/usr/local/lib/obsidianwatch/obi`, installed by `install`).

- **What it instruments.** The listening ports of discovered services, except processes that already send OpenTelemetry from an SDK (they would be counted twice). The agent writes `/var/lib/obsidianwatch/obi/obi.yaml` (OBI config v1: `discovery.instrument.open_ports`, `attributes.instance_id.override_hostname: ow`, `routes.unmatched: heuristic`, traces to `http://<receiver>/v1/traces` over OTLP/HTTP) and restarts OBI when the set of ports changes, at most every 10 minutes (`min_restart`). A crash is restarted with backoff (10 s doubling to 30 min). OBI's output goes to `/var/lib/obsidianwatch/obi/obi.log`. OBI runs without the Docker API (`DOCKER_HOST` points nowhere) so its instance ids stay `ow:<pid>`.
- **Attribution.** The receiver recognises a connection from the OBI child (pid and executable), reads the target pid from `service.instance.id` (`ow:<pid>`), and rewrites the telemetry to the discovered service of that process (its name, environment, pid, start time, container, commit). The binding is therefore to the real application process, verified. Telemetry about a process the sensor does not know is dropped. The receiver counts both (`Proxied`, `ProxyDropped`).
- **Result.** The discovered service moves to Tier 1 under the same name and keeps its history; its instances report sdk `ebpf opentelemetry-ebpf-instrumentation`, and the service shows `instrumentation: ebpf` (badge "T1·eBPF"). Endpoints come from OBI's route heuristic, so they are templates such as `/items/{id}`. Exception details, custom spans and runtime metrics still need an SDK; the security helper is still needed for Tier 2.
- **Requirements.** Linux 5.8 or later with BTF (`/sys/kernel/btf/vmlinux`), or RHEL/CentOS 4.18 kernels with eBPF backports; the agent as root. Not available on Windows and macOS.

Implemented in: `agents/linux/internal/obi`, `agents/linux/internal/otel/receiver.go` (`ProxyRewriter`), `agents/linux/internal/config/config_app.go`, `agents/linux/internal/service/service.go`, management `agent_builder.go`, `app_agent_profile.go`, `management/docker/Dockerfile` (downloads OBI `v1.0.0`, `OBI_VERSION` build argument, optional SHA-256 arguments).

### 1.2 The commit an instance runs

Each instance reports the commit it was built from when it is known, in this order: OpenTelemetry resource attributes `vcs.ref.head.revision` (or `vcs.repository.ref.revision`, `git.commit.sha`) with `vcs.repository.url.full` / `git.repository_url` and `vcs.ref.head.name` / `git.branch`; for discovered processes in Docker containers the image labels `org.opencontainers.image.revision` and `org.opencontainers.image.source` (or the label-schema equivalents); otherwise a `.git` directory in the process's working directory or executable directory, or up to four parents (HEAD, loose or packed ref, `origin` URL), read through `/proc/<pid>/`. Credentials in a remote URL are removed before it leaves the host. The values are stored on the instance (`vcs_revision`, `vcs_repo`, `vcs_branch`, `vcs_source` = `otel`, `oci` or `git`) and shown in the Instances tab and the Tier 0 overview. Codebase capability.md section 4.15 says how linked services use them.

---

When an instance reports its repository (`vcs.repository.url.full` or `git.repository_url`, or the OCI source label) and that repository belongs to a connected code platform, the service is linked to it automatically the first time its Code tab is opened. The link shows "reported by the service". An analyst's links are never changed. The ObsidianWatch console reports its own commit without configuration when it is built from a source archive: `git archive` writes the commit into `management/backend/internal/telemetry/build_commit.txt` (`export-subst` in `.gitattributes`). Set `OW_SOURCE_REPO` (for example `https://github.com/acme/obsidianwatch`) to link it automatically too.

## 2. Receiving OTLP on the host

The agent runs an HTTP server only when the agent was built with the app-server profile (`app_monitoring.enabled: true`).

| Item | Value |
|---|---|
| Endpoints | `POST /v1/traces`, `POST /v1/logs`, `POST /v1/metrics` |
| Listen | `app_monitoring.otlp.listen`, default `127.0.0.1:4318`. Optional `app_monitoring.otlp.socket` (Unix socket, file mode 0666) |
| Protocol | OTLP/HTTP only. gRPC (4317) is not implemented |
| Content types | `application/x-protobuf` or `application/json`. Anything else: HTTP 415 |
| Compression | none or `gzip`. Other `Content-Encoding`: HTTP 415 |
| Body size | 4 MiB as sent, 16 MiB after gunzip. Larger: HTTP 413 |
| Items per request | 20 000 spans, 5 000 log records, 20 000 metric points. More: HTTP 400 |
| Attributes | first 256 per span, resource or log record are read |
| String values | span, event and attribute names are cut to 4 096 bytes; attribute values (helper bodies, stack traces) to 32 KiB (defect D2, fixed) |
| Timeouts | header 10 s, request 30 s, idle 120 s, headers 64 KiB |
| Success reply | empty `Export*ServiceResponse` in the request's encoding (`{}` for JSON) |

The receiver never binds a routable address. It checks three times: the configuration is rejected unless the host is a loopback IP literal or `localhost` (config validation); after `listen()` the bound address is checked again; and the service refuses to run if any listener is not loopback or a Unix socket (`OnlyLocal`). A stale socket file from an earlier run is removed at start and the socket is removed at shutdown.

Spans with no start and no end time are skipped. Spans without `service.name` are counted (`NoService`) and dropped.

Implemented in: `agents/linux/internal/otel/receiver.go`, `otlp.go`, `pb.go` (hand-written protobuf reader, no protobuf library), `metrics.go` (metrics decoding), `internal/config/config_app.go` (validation).

---

## 3. Which process is sending (identity)

The application cannot say which host, container or process it runs in. Any `host.*`, `container.*` or `k8s.*` attribute it sets is ignored, because those keys are not on the resource allowlist. The agent works out the sender from the connection.

### 3.1 Peer resolution (Linux)

Per connection, once, on the first request:

| Connection | Method |
|---|---|
| Unix socket | `SO_PEERCRED` gives the sender's pid from the kernel |
| Loopback TCP | find the client socket in `/proc/net/tcp` or `/proc/net/tcp6` (local = peer address, remote = our address), take its inode, then scan `/proc/<pid>/fd` for `socket:[inode]` |

For the pid the agent reads `/proc/<pid>/stat` (parent pid and start time; start time assumes USER_HZ = 100), `/proc/<pid>/exe` (executable path) and `/proc/<pid>/cgroup` (the first 64-hex-digit string is taken as the container id).

At most four identifications run at once. A request that waits more than 2 seconds for a slot is treated as unresolved ("identification busy"). If the socket is not found (for example the sender is in another network namespace and connected over TCP), the peer is unresolved.

Windows and macOS have their own resolvers (`GetExtendedTcpTable` on Windows, `lsof` and `ps` on macOS). Unix-socket peer credentials exist only on Linux.

### 3.2 Binding: verified or asserted

For each `(service.name, deployment environment)` pair the agent keeps the processes allowed to speak for it.

| Situation | Identity |
|---|---|
| Peer unresolved | `asserted` |
| First resolved process to claim the name | `verified`; it becomes the binding |
| Same pid and start time as a bound process | `verified` |
| Other process, same executable path as a bound process (worker, second copy) | `verified`; added to the binding (max 64 per service) |
| All bound processes have exited (pid gone or start time changed) | the new process takes over: `verified` |
| Anything else | `asserted`, and it is **not** added to the binding |

A per-instance identity is never downgraded once verified. More than 2 000 distinct service names: new names are `asserted` and not recorded.

The binding lives in agent memory. After an agent restart the first process to send a given service name wins it again.

Effects of `asserted`:
- the instance shows "asserted" on the Instances tab;
- the service is listed under "Needs attention" on the Overview with reason `asserted_identity`;
- a non-operational alert that carries the identity is capped at Medium (section 11.1).

Implemented in: `otel/identity.go`, `otel/peer_linux.go`, `agents/windows/internal/otel/peer_windows.go`, `agents/macos/internal/otel/peer_darwin.go`.

---

## 4. What is kept from a span, a log and a metric (allowlists)

Everything not listed here is discarded while decoding.

### 4.1 Resource attributes

`service.name`, `deployment.environment.name` (preferred) or `deployment.environment`, `service.instance.id`, `service.version`, `telemetry.sdk.language`, `telemetry.sdk.name`, `telemetry.sdk.version`.

An empty environment becomes `default`.

### 4.2 Span fields and attributes

Always: trace id, span id, parent id, name, kind, start, end, status code. From the first span event named `exception`: `exception.type`, `exception.message`, `exception.stacktrace` (the first exception on a span wins).

| Attribute(s) | Used for |
|---|---|
| `http.route` | route template |
| `http.request.method`, `http.method` | method (upper-cased) |
| `http.response.status_code`, `http.status_code` | status class |
| `client.address`; `http.client_ip` (only if `client.address` is absent) | client address |
| `network.peer.address`; `net.sock.peer.addr`, `client.socket.address`, `net.peer.ip` | direct peer address |
| `db.system`, `db.operation.name`/`db.operation`, `db.collection.name`/`db.sql.table`/`db.mongodb.collection` | database dependency and query grouping (names, cut to 64 bytes) |
| `db.statement`, `db.query.text` | read in memory only to build a literal-free fingerprint when the service allows it (section 5.7); never forwarded raw |
| `server.address`, `server.port`, `peer.service` | dependency target |
| `messaging.system`, `messaging.destination.name`, `messaging.operation`/`messaging.operation.type` | queue dependency and consumer names |
| `code.function`, `code.function.name`, `ow.job.name` | job and consumer names |
| `exception.type` (as attribute) | exception type |
| `url.query`; `http.target`, `http.url` (part after `?`) | parameter names and in-memory values (section 5.4) |
| `ow.request.body` | JSON body from a helper: parameter names and in-memory values |
| `enduser.id` | read but not used anywhere |

### 4.3 Log records (security-helper events)

Only records whose `event.name` attribute (or the OTLP `event_name` field) is one of: `auth.login`, `auth.mfa`, `authz.deny`, `input.rejected`, `ssrf.blocked`, `deserialization.blocked`, `ratelimit.hit`, `admin.action`, `data.export`, `session.anomaly`, `data.access`. The log body and severity are never read.

Kept attributes: `outcome`, `method`, `user`, `reason`, `mfa`, `resource_type`, `action`, `route`, `policy`, `kind`, `parameter`, `target_host`, `type_name`, `limit_name`, `target_type`, `target_id`, `rows`, `bytes`, `format`, `session`, `object_type`, `object_id`, `helper_version`, `client.address`, `network.peer.address`, `enduser.id`.

**Helper functions.** Every language helper (v2; Go v1) has one function per event name, all sending the attribute names above:

| Event | Node (`ow-security.js`) | Python (`ow_security.py`) | Java (`OwSecurity`) | .NET (`OwSecurity`) | Go (`owsecurity`) | Main attributes |
|---|---|---|---|---|---|---|
| `auth.login` | `login` | `login` | `login` | `Login` | `Login` | outcome, user, method, reason, mfa |
| `auth.mfa` | `mfa` | `mfa` | `mfa` | `Mfa` | `MFA` | outcome, user, method |
| `authz.deny` | `authzDenied` | `authz_denied` | `authzDenied` | `AuthzDenied` | `AuthzDenied` | resource_type, action, policy, user |
| `input.rejected` | `inputRejected` | `input_rejected` | `inputRejected` | `InputRejected` | `InputRejected` | kind, parameter |
| `ssrf.blocked` | `ssrfBlocked` | `ssrf_blocked` | `ssrfBlocked` | `SsrfBlocked` | `SSRFBlocked` | target_host |
| `deserialization.blocked` | `deserializationBlocked` | `deserialization_blocked` | `deserializationBlocked` | `DeserializationBlocked` | `DeserializationBlocked` | type_name |
| `ratelimit.hit` | `rateLimited` | `rate_limited` | `rateLimited` | `RateLimited` | `RateLimited` | limit_name |
| `admin.action` | `adminAction` | `admin_action` | `adminAction` | `AdminAction` | `AdminAction` | action, target_type, target_id, outcome |
| `data.export` | `dataExport` | `data_export` | `dataExport` | `DataExport` | `DataExport` | object_type, format, rows, bytes |
| `data.access` | `dataAccess` | `data_access` | `dataAccess` | `DataAccess` | `DataAccess` | object_type, object_id, action |
| `session.anomaly` | `sessionAnomaly` | `session_anomaly` | `sessionAnomaly` | `SessionAnomaly` | `SessionAnomaly` | kind, session, reason |

All also take `route` and the client address (sent as `client.address`), and every language has a generic `emit`. Each record carries the trace and span of the request it was raised in.

**Event ids.** The agent gives each event an id from its time, type and source; for events without a source record number (helper events) it also hashes the collector's own random id. Before this, helper events from the same agent in the same millisecond (Node, Java and .NET send millisecond times) shared an id and the backend kept only the first; a test with eleven events in two milliseconds stored three.

### 4.4 Metrics

Kept only when the name starts with one of: `process.cpu.`, `process.memory.`, `process.runtime.`, `process.uptime`, `v8js.`, `nodejs.`, `jvm.`, `dotnet.`, `db.client.connections.`, `db.client.connection.`, `http.server.active_requests` (names up to 96 bytes).

Kept attributes (enumerations only): `state`, `type`, `pool.name`, `gc`, `db.client.connection.state`, `db.client.connection.pool.name`, `v8js.heap.space.name`, `jvm.memory.pool.name`, `jvm.memory.type`, `jvm.gc.name`, `dotnet.gc.heap.generation`.

Gauges and sums are kept as values. Explicit-bucket histograms are reduced to one value (their mean). Exponential histograms and summaries are rejected and counted. Metric names not on the list are dropped and counted.

Implemented in: `otel/model.go`, `otel/otlp.go`, `otel/metrics.go`.

---

## 5. Aggregation in the agent

Raw spans never leave the host. The aggregator turns them into the streams below. All of it happens in memory under one lock.

Implemented in: `otel/aggregate.go` unless noted.

### 5.1 Request statistics (RED) per route

A **server span** (kind SERVER) contributes when it has a method, a route or an HTTP status.

- **Route**: `http.route` only. A server span without it is counted as `(unmatched)`. The raw path is never used. Routes longer than 256 bytes are cut.
- **Method**: the attribute, or the first word of the span name when it is at most 8 characters, else `*`.
- **Cardinality cap**: 2,000 distinct `(route, method)` pairs per service (`app_monitoring.max_routes_per_service`). Further pairs are counted under the route `other` and the overflow is reported (Overview → Needs attention, reason `route_overflow`). The set of seen pairs is never reset while the agent runs.
- **Minute**: the span's end time, truncated to the minute. If the application clock is more than 5 minutes off, the receive time is used and the skew is counted.

Per `(minute, service, route, method)` the agent keeps:

| Counter | Rule |
|---|---|
| `calls` | every counted span |
| `errors` | span status ERROR or HTTP status ≥ 500 |
| `status_2xx` | 200–299 |
| `status_401_403` | 401 or 403 |
| `status_429` | 429 |
| `status_5xx` | ≥ 500 |
| `duration_buckets` | 12-bucket histogram, upper bounds 5, 10, 25, 50, 100, 250, 500, 1 000, 2 500, 5 000, 10 000 ms, then +∞ |
| `sketch` | latency sketch (5.2) |

Other 4xx codes are counted in `calls` only. A 4xx is not an error.

### 5.2 Latency sketch

A DDSketch with 1 % relative accuracy (γ = 1.01/0.99), values in ms. Values ≤ 0.001 ms go to a zero bucket. At most 2 048 bins; when exceeded the lowest bins are merged, which only affects the lowest quantiles. The maximum value is kept exactly. Sketches of two minutes or two instances merge without loss. The same code exists in the agent, the ingest store and the management API.

Implemented in: `otel/sketch.go`, `backend/internal/store` (Sketch), `management/backend/internal/api/app_sketch.go`.

### 5.3 Per-client failure counters

For the source-based rules (A01, A09, A13). Only **failed** requests are recorded: HTTP 4xx or 5xx, an exception on the span, or an injection signature (5.4).

Key: `(minute, service, route, method, client address, peer address, exception type)`. Counters: failures, 401/403, 429, other 4xx, 5xx. The exception type is the injection signature when there is one (`param.sql-injection`), else the exception type (max 128 bytes).

Addresses follow the service's client-address mode (`full`, `truncated` to /24 or /48, `off`). With `off`, or when neither address is present, nothing is recorded. At most 200 keys per service per minute; overflow is counted (`client_overflow`).

### 5.4 Parameter names, payload samples and injection signatures

The agent reads parameter **names** from the query string (`url.query`, or the part after `?` in `http.target`/`http.url`) and from `ow.request.body` (a JSON object set by a language helper).

- Query: names are URL-decoded; a name must be 1–64 characters of `A–Z a–z 0–9 _ - . [ ]`; a bare token longer than 32 characters with no `=` is ignored; the first value of each name is kept in memory, cut to 256 bytes; at most 50 names per span.
- Body: must be a JSON object of at most 32 KiB. Nested names are joined with dots (`address.zip`); an array contributes the shape of its first element (`items[].sku`); depth at most 4; at most 200 elements walked; scalars become strings cut to 256 bytes.

What leaves the host:

- **Names with counts**, per route per flush, at most 100 names per route and 5 000 keys in total. Requests on `(unmatched)` and `other` are not tracked.
- **Values**, only for a route an administrator has reviewed (section 10.9). Up to 5 sampled requests per route and 500 in total per flush. For each sampled request, a value is sent only when the name is in the route's allowed list, the name is not on the always-masked list, and the value does not look like a credential. Every other name is listed as withheld. Each sample carries time, status, duration and trace id.

**Injection signatures.** Before values are dropped, each parameter value of a server span is matched (first 2 KiB, URL-decoded up to twice) against six conservative patterns: `sql-injection`, `script-injection`, `command-injection`, `path-traversal`, `jndi-injection`, `template-injection`. The first hit becomes the label `param.<class>`. The label replaces the exception type in the client failure counter, the request counts as failed for that counter even if it returned 200, and the trace is flagged for keeping as `security`. The value itself is never sent.

The parsed values are deleted from the span as soon as the request is aggregated.

Implemented in: `otel/model.go` (query parsing, deny lists), `otel/bodyparams.go`, `otel/signatures.go`, `otel/aggregate.go` (`capturePayload`, `addParams`).

### 5.5 Dependencies (edges)

Every CLIENT or PRODUCER span adds a call (and an error when the span failed) to an edge:

| First match | Kind | Target |
|---|---|---|
| `db.system` set | `database` | `<db.system>@<server.address>:<port>` or `<db.system>` |
| `messaging.system` set | `queue` | `<messaging.system>@host:port` or the system |
| `peer.service` set | `service` | the peer service name |
| `server.address` set | `external` | `host:port` |

Targets are lower-cased. Spans matching none of these add no edge. At most 20 000 edge keys are held between flushes.

### 5.6 Traces: completion and sampling

Spans with a trace id are buffered per trace: at most 2 000 open traces (`app_monitoring.max_open_traces`; when full the oldest is dropped and counted as `trace_drops`) and 500 spans per trace (the rest are dropped). A trace is complete when no span has arrived for 10 seconds, or 2 seconds once a root span has been seen. The agent sees only the spans sent to it; a trace that spans several hosts is evaluated per host.

When a trace completes it is classified, in this order:

| Class | Condition |
|---|---|
| `security` | a helper event with this trace id arrived in the last 15 minutes, or a server span in it matched an injection signature |
| `error` | any span failed (status ERROR or HTTP ≥ 500) |
| `slow` | trace duration (earliest start to latest end) ≥ the service's latency target (`latency_target_ms` from the console), else `slow_ms` (default 1 000 ms) |
| `baseline` | everything else |

Keeping:
- `security`, `error`, `slow`: kept unless a cap below applies.
- `baseline`: kept when `fnv32a(trace_id) mod 10 000 < pct × 100`. Default 1 % (`baseline_sample_pct`, or the service's `sampling.baseline_pct`). Because it hashes the trace id, every agent makes the same decision for a trace.
- Per-service error cap: `sampling.error_max_per_min` (0 = no cap).
- Per-flush budget: `sampling.max_per_flush`, default 500, max 5 000. When the budget is full a new trace evicts a lower-ranked kept trace (baseline < slow < error). `security` traces are always kept, even above the budget.

For each reason the agent reports how many traces were completed (`seen`) and kept (`kept`).

A kept trace is sent as a skeleton: per span the id, parent id, name, kind, service, start offset, duration, self time, route, method, HTTP status, `db.system`, `peer.service`, exception type, DB operation and table, and an N+1 flag. No attribute values, no statements, no messages. It is cut to 64 KB by dropping the last quarter of spans repeatedly.

Implemented in: `otel/aggregate.go` (`bufferSpan`, `closeTraces`, `finishTrace`), `otel/sampling.go`.

### 5.7 Trace diagnosis: self time, slow children, queries, N+1

Run on every completed trace, before the sampling decision, so it covers all buffered traffic, not only kept traces. It uses the minute in which the trace completed.

- **Self time** per span = duration − sum of the durations of its direct children present in the trace, never below 0.
- **Slow downstream calls** ("top children"): for each CLIENT or PRODUCER span whose nearest ancestor is a SERVER span with a route, add calls and total time to `(route, minute, kind, target, name)`. Kind is `db` (has `db.system`), `queue` (PRODUCER), `http` (has `peer.service` or `server.address`) or `client`. The name is the span name with UUIDs, long hex strings and digits replaced by `?` (80 characters max). At most 20 keys per route and 5 000 in total per flush; more collapse into `(other)`.
- **Database calls**: for every span with `db.system`, group by `(system, operation, table, fingerprint)` per minute with calls, errors, total time and the 12-bucket histogram. Operation = `db.operation.name`/`db.operation`, else the first word of the span name, upper-cased. At most 200 groups per service per flush; more collapse into `(other)`.
- **Statement fingerprint**: when the service's `db_statement_mode` is `fingerprint`, the default since November 2026 (migration 084 switched existing services; a service can be set back to names only). Comments are removed, string literals, hex literals, numbers and `$1`/`@p` placeholders become `?`, `IN (?, ?, ...)` and `VALUES (...)` lists collapse to `(?)`, whitespace is normalised and the text is lower-cased. The id is the first 8 bytes of SHA-256 of that text (16 hex characters). The text is cut to 512 bytes.
- **N+1**: within one trace, when 10 or more database spans with the same group (fingerprint, or `operation|table` without one) share the same parent span and sit under a routed server span, every one of them is flagged and the route's N+1 count goes up by one.

Implemented in: `otel/diagnose.go`.

### 5.8 Error groups

For every span in a completed trace that carries an exception:

1. **Stack parsing.** Lines in these formats are recognised: Python (`File "x.py", line N, in f`), Java/Kotlin/Scala/Groovy (`at pkg.Cls.m(File.java:N)`), .NET with file information (`at Ns.Cls.M() in /p/F.cs:line N`), Node.js (`at f (/p/f.js:N:C)`), Go (a `pkg.Func(...)` line followed by a tab-indented `/p/file.go:N +0x..` line, as `runtime/debug.Stack` and panics print them; frames in GOROOT, `vendor/`, the module cache, `runtime.`, `net/`, `sync.`, `reflect.` and well-known module hosts count as library frames). Other formats (Ruby, PHP, .NET without PDB line info) give no frames.
2. **Library frames**: paths containing `node_modules/`, `site-packages/`, `dist-packages/`, `/lib/python`, `node:` or `internal/`, or functions starting with `java.`, `javax.`, `jdk.`, `sun.`, `kotlin.`, `System.`, `Microsoft.`.
3. **File paths** are shortened to the last three segments; function names to 80 characters; columns and arguments are dropped.
4. **Fingerprint**: SHA-256 over exception type, the owning route (nearest routed server ancestor) and the top five in-app frames as `function@file` (line numbers excluded, so a deploy that shifts lines keeps the group). With no in-app frame, the top three frames of any kind. With no frames, type and route only. First 8 bytes, 16 hex characters.
5. Per group per flush: count, type, route, method, the top in-app frame, up to 30 frames (4 096 bytes), version, one trace id, time.
6. **Message**: only when the service's `error_message_mode` is `masked`. Whitespace is collapsed and e-mail addresses, UUIDs, quoted text, opaque strings of 20+ characters and digit runs become `?`; at most 200 characters.

At most 100 groups per service per flush. A span with an error status but no `exception` event creates no error group.

Implemented in: `otel/errors.go`.

### 5.9 Jobs and message consumers (operations)

A span is an operation when it carries `ow.job.name` and is a root span or a CONSUMER span (kind `job`), or when it is a CONSUMER span (kind `consumer`, name = messaging system + destination + operation, else the span name, else `code.function`). Names are templated (ids and digits → `?`), 96 characters max. Per `(minute, service, kind, name)`: runs, failures (span failed), histogram, sketch, last run time. At most 100 names per service; more go to `other`.

Implemented in: `otel/operations.go`.

### 5.10 Runtime metrics

Per `(service, instance, name, attributes)` the agent keeps last value, min, max, sum and count since the last flush, stamped with the flush minute. The instance is `service.instance.id`, else `pid:<pid>`. At most 100 series per instance; more are dropped and counted. Metric data points do not create or refresh service instances.

Implemented in: `otel/metrics.go`.

### 5.11 Instances

Each `(service, pid, process start, container id)` seen sending spans is an instance with its resource (version, instance id, language, SDK), identity and executable. It is reported when it changes, then as a heartbeat every 60 s while it sent spans in the last 5 minutes. It is forgotten after an hour without spans. At most 5 000 are held.

### 5.12 Flush

Every `app_monitoring.flush_interval` (default 30 s) the agent builds one batch. Statistics for the current, still-open minute stay in memory until the minute closes (all of it is flushed at shutdown). Notes per service carry `route_overflow`, `trace_drops` and `client_overflow`.

---

## 6. Sending to the backend

- `POST <backend_url>/api/v1/app/batch`, JSON, over HTTPS, TLS 1.3 minimum, with the CA from the build and the agent's **enrolled client certificate**. No API key is sent.
- A batch is first split into pieces that respect the backend caps (section 12). See defect D1: the split drops several sections.
- Queue of 100 batches. When full, the oldest is dropped and its statistics are merged back into memory for the next flush.
- Up to 3 attempts with backoff 1 s then 3 s, honouring `Retry-After` under 120 s. HTTP 429 and 5xx and network errors are retried; other 4xx are dropped and logged ("app batch rejected, dropping"). After the last attempt the batch is handed back: route statistics, parameter names, payload samples, client counters, edges and notes are merged into the next flush. Traces, instances (re-sent as heartbeats), errors, queries, metrics and operations are not requeued.
- 30 s HTTP timeout. At shutdown queued batches are posted with a 5 s timeout each.

Implemented in: `otel/sender.go`, `otel/batch.go`, `otel/service.go`.

---

## 7. Ingest and storage

### 7.1 Batch endpoint

`POST /api/v1/app/batch` on the ingest backend. The request must come with a valid, unrevoked agent certificate (agent routes have no other authentication).

| Check | Result on failure |
|---|---|
| JSON body ≤ 4 MiB | 400 |
| `agent_id` present, ≤ 128 characters | 400 |
| `agent_id` equals the certificate's agent id | 403 "agent_id does not match the client certificate". Note: the event ingest endpoint re-attributes events to the certificate's agent instead; the application endpoints still refuse |
| Per-section counts within caps (section 12) | 413 "batch too large" (whole batch) |
| Agent exists in `agents` | 403 "unknown agent" (only found agents are cached, 60 s) |
| Per-agent rate: 200 items/s, burst 5 000 | 429 with `Retry-After: 30` |

The host name and OS come from the agent record, never from the payload.

Each item is then cleaned; a bad item is dropped and counted, it never fails the batch:

- service names ≤ 128 characters, environment ≤ 64 (empty → `default`), control characters removed;
- methods outside `GET POST PUT PATCH DELETE HEAD OPTIONS GRPC *` drop the row;
- routes lose scheme, host, query and fragment (≤ 256 characters);
- edge targets lose scheme, credentials (`user:pw@`), path and query; kinds must be `service`, `database`, `queue`, `external`;
- minute rows older than 24 h or more than 10 min in the future are dropped;
- a latency sketch that does not parse or counts more requests than the row's calls is removed (the histogram still counts);
- client addresses must be an IP or a CIDR such as `10.1.2.0/24`;
- parameter names are re-validated; payload values are re-checked against the always-masked names and credential patterns;
- a query text without a fingerprint, or still holding a `'` or a run of 6+ digits, is blanked;
- an error message holding a `'` or 6+ digits is blanked; frames ≤ 30 and 4 096 bytes; fingerprint must be 16 hex characters;
- metric names must match the agent allowlist prefixes; values must be finite.

### 7.2 Storage

All writes for one batch run in one transaction.

| Table (ingest migration) | Content |
|---|---|
| `services` (030) | one row per `(name, environment)`; `source` becomes `otel` once OTLP arrives; `attrs` holds language and the overflow counters |
| `service_instances` (030) | per process; identity never downgrades from `verified`; `stopped_at` set when a new process reports the same `service.instance.id` |
| `service_versions` (030) | first/last seen and live instance count per version |
| `service_routes` (030) | route inventory with first/last seen |
| `app_route_stats` (030, 038) | per-minute RED counters, histogram, merged sketch and `sketch_calls` |
| `service_edges` (030), `app_edge_stats` (031) | cumulative dependency counters and hourly deltas |
| `app_traces` (030) | kept trace skeletons; a trace id is stored once (`ON CONFLICT DO NOTHING`) |
| `app_client_stats` (031) | per-minute failure counters per client |
| `service_route_params` (032, 035) | parameter names per route, `source` observed / declared / both; at most 200 observed names per route |
| `app_payloads` (033, 034) | sampled values of reviewed routes |
| `service_declared_routes`, `service_openapi` (035) | routes from a loaded API spec |
| `app_route_children`, `app_db_stats`, `app_route_n1` (036) | diagnosis data |
| `error_groups`, `error_group_hours` (037) | error groups and hourly counts |
| `app_metrics` (039) | per-minute runtime series |
| `app_sampling_stats` (040) | hourly seen/kept per reason |
| `app_operations` (041) | jobs and consumers per minute |
| `app_baselines` (030) | learned destinations and privilege changes, written by the rules |

Management migrations add `service_settings` and `app_service_merges` (060, the latter unused), `app_route_payload_policy` and its log (063), and the settings columns `db_statement_mode` (064, repeated in 066), `error_message_mode` (067), `sampling` (068), `slo` (069).

Change events. The ingest backend writes events for the first sighting of a service (`app.service_change`, `service_new`), an instance (`instance_new`), a version (`version_changed`) and a dependency (`app.dependency_new`). They carry `baseline: true` while the service is new.

**Merge of discovered and instrumented services.** When an OTLP instance reports a pid that a discovered service of the same agent holds (same start time, or either unknown), the discovered instance moves to the instrumented service, its baselines and settings move with it, the earlier `first_seen` is kept (so learning time is kept), and the discovered service is deleted when empty. The host sensor's row for the process is folded into the instrumented row (listening ports, unit, container name, image).

**Error groups.** Groups are keyed by `(service, fingerprint)`. Each report adds to the count and the hourly table and keeps the five latest sample trace ids. A group in status `resolved` that reports again with a non-empty version different from the version it was resolved in is reopened and marked regressed. Services that send no `service.version` never regress.

Implemented in: `backend/internal/api/app_batch.go`, `backend/internal/store/app_store.go`, `backend/internal/store/migrations/030`–`041`, `management/backend/internal/store/migrations/060`–`069`.

### 7.3 Retention

The management backend purges shortly after start and every 6 hours. Values come from the `settings` table of the management database:

| Key | Default | Tables |
|---|---|---|
| `app.retention_stats_days` | 90 | route stats, edge stats, sampling stats, operations, children, DB stats, N+1, metrics, error group hours; error groups not seen for that long |
| `app.retention_trace_days` | 7 | `app_traces` |
| `app.retention_client_days` | 7 | `app_client_stats` |
| `app.retention_payload_days` | 7 | `app_payloads` |

Inventory tables (services, instances, routes, edges, versions, parameter names) are not purged.

Implemented in: `management/backend/internal/store/app_retention.go`, `management/backend/cmd/server/main.go`.

---

## 8. Settings pulled by the agent

The agent pulls `GET /api/v1/app/agent-config?agent_id=<id>` 2 s after start, then every 5 minutes (`settings_poll_interval`), every 30 s while it fails. Until the first success the build configuration alone applies. Same certificate checks as the batch endpoint.

The answer lists every service that has saved settings (up to 5 000) and every reviewed route (up to 20 000), for all services, not only those on this agent.

| Field | Effect in the agent |
|---|---|
| `store_client_ip` | client-address mode. The stricter of build value and pulled value wins (`off` > `truncated` > `full`) |
| `cleartext_users` | send helper user/session/object ids unhashed. Pulled value is authoritative when present; otherwise the build list `cleartext_services` |
| `latency_target_ms` | slow-trace threshold |
| `db_statement_mode` | `fingerprint` enables statement fingerprints |
| `error_message_mode` | `masked` enables scrubbed error messages |
| `sampling` | baseline %, error cap per minute, traces per flush |
| `payload_routes` | reviewed routes with the allowed names. A route reviewed in `{id}` style is also sent in `:id` style and the reverse |
| `policy_only` | the service has a reviewed route but no saved settings; only `payload_routes` is used |

The agent re-applies the always-masked list to the allowed names it receives.

Implemented in: `otel/remoteconfig.go`, `otel/service.go`, `backend/internal/api/app_agentconfig.go`, `backend/internal/store/app_store.go` (`AppRemoteConfig`).

---

## 9. Host runtime sensor and service discovery

Enabled by the app-server profile (`app_monitoring.ebpf.enabled: true`). Besides process, network and file events, the sensor reports a `runtime_inventory` event per service process every 15 minutes (re-sent every 6 hours when unchanged): the third-party packages loaded into it or installed for it. Code uses these for runtime reachability of dependency vulnerabilities (see [codebase capability 4.11](../codebase/capability.md)). Linux tiers, chosen by `app_monitoring.ebpf.mode`:

| Tier | Needs | Process starts | Connections | File events | Privilege changes | DNS before connect | Escape signals |
|---|---|---|---|---|---|---|---|
| `ebpf` | build tag `ebpf`, clang, cilium/ebpf | kernel | kernel | kernel | kernel | yes | yes |
| `procevent` | root | netlink proc connector | `/proc` poll | fanotify | uid change from proc connector | no | only a runtime-socket file access |
| `poll` | nothing | `/proc` poll (short-lived processes missed) | `/proc` poll | fanotify if allowed | uid change seen by polling | no | only a runtime-socket file access |

`auto` (the builder default) tries `ebpf`, then `procevent`, then `poll`. The `ebpf` tier is **not built or tested**; the repository has no compiled kernel object, so `auto` in practice runs `procevent` as root or `poll`.

Poll interval: `app_monitoring.ebpf.poll_interval`, default 2 s.

**Discovery (Tier 0).** Each round the sensor lists listening TCP sockets, finds their owning processes and names each service from what an operator would call it: the jar (`java -jar x.jar`) or main class (`tomcat` for Catalina), the Node script, the Python module or script (`gunicorn app.wsgi:application` → `app`), the .NET DLL, else the executable. Version suffixes are removed; generic names (`index`, `server`, `app`, `main`...) are replaced by the parent directory. A systemd unit or container name can give a better name. System daemons (sshd, systemd, dockerd, containerd and shims, docker-proxy, kubelet, the agent itself and others) are ignored. Children that inherited the parent's listening socket with the same name are folded into the parent. Discovered services get the environment from `app_monitoring.ebpf.environment` (builder field "Environment for discovered services"), else `default`.

**What the sensor reports.** Only activity whose process lineage contains a discovered or OTLP-verified service process (OTLP instances active in the last 5 minutes): process starts, new outbound connections (loopback and inbound connections excluded), file events in watched directories (`/var/www`, `/srv/www`, `/usr/share/nginx/html`, `/var/lib/tomcat/webapps`, `/opt/tomcat/webapps`) and reads of `/etc/shadow` and `/etc/gshadow`. The first round only records what exists. Command lines are redacted. Events carry `pid`, `ppid` and a `raw.proc` block (ancestors, tty, container id, privilege change, escape signal, DNS name, operation, file mode) and go through the agent's normal event channel (normaliser, own-activity filter, rate limiter).

`watch_dirs` and `secret_files` exist in the agent config but the Agent builder does not write them, so a built agent uses the defaults.

Windows and macOS run a polling sensor only (no file events, no privilege changes).

Implemented in: `agents/linux/internal/ebpf/*` (`sensor_linux.go`, `naming.go`, `filter.go`, `fanotify_linux.go`, `procevent_linux.go`, `event.go`, `redact.go`), `otel/aggregate.go` (`AddDiscovered`).

---

## 10. Management engines: what is computed and where you see it

All read APIs are under `/api/v1/app/` on the management backend, authenticated like the rest of `/api/v1`. Ranges take `from` and `to` in RFC 3339; default the last 24 hours; at most 90 days. Data is read from the ingest database (`backend_db`) when configured, else the management database.

UI section: **Applications** (`/applications`). Service page tabs: Overview, Endpoints, Traces, Queries, Errors, Jobs and queues, Metrics, SLO, Instances, Security, Alerts, and under **More**: Dependencies, Compare versions, Events, Runtime, Settings.

### 10.1 RED metrics and percentiles

Where: Applications → Services (list columns), service page → Overview (charts and totals), Endpoints tab (per route).
API: `GET /services/{id}/red?route=&method=&step=`, `GET /services/{id}/routes`.

- **Rate**: `calls` per bucket. **Errors**: `errors / calls`. **Status classes**: 2xx, 401/403, 429, 5xx.
- **Step** (series bucket): 60 s up to 2 h, 300 s up to 12 h, 1 800 s up to 3 days, 3 600 s up to 14 days, 21 600 s beyond; doubled until there are at most 2 000 points. A requested step is clamped to 60 s–86 400 s.
- **Percentiles (p50, p95, p99)**: from the merged sketch when the range is 7 days or shorter and every stored minute row in the range has a complete sketch (`sketch_calls = calls`); the response then says `percentile_method: "sketch"` and adds `max_ms`. Otherwise from the 12-bucket histogram with linear interpolation inside the bucket; a quantile in the open last bucket is reported as 10 000 ms with `over_range: true`; method `histogram`, or `mixed` when only some rows had sketches.
- **Apdex** (only with a latency target T and sketch data): (requests ≤ T + ½ × requests in (T, 4T]) / all requests, three decimals.

Implemented in: `app_red.go`, `app_sketch.go`.

### 10.2 Routes (Endpoints tab)

Failing routes are listed first: the table is sorted by error rate, and routes with the same rate by calls.


Each row: route template, method, first/last seen, active in range, RED totals, Apdex, parameter names with their state, review state, top 3 slow downstream calls (by total time), N+1 count, and spec flags. States of a parameter: `always_masked`, `pending`, `new`, `masked`, `captured`. Route review: `needs_review` (has names, no policy), `reviewed`, `new_fields` (a name not in the saved review). With an API spec: `declared`, `not_in_spec` (observed, spec loaded, not listed), declared-only rows, and `undocumented` fields (observed on a route the spec lists, not in the spec). Declared and observed templates are matched by shape (`/users/{id}` = `/users/:id`). At most 1 000 route rows.

The tab shows 100 routes per page (First / Previous / Next / Last), sorted across all pages, with a finder that matches the method and path (`POST /orders`) and a count of matching routes. The server returns the 2,000 busiest routes in the range; the agent tracks at most 2,000 routes per service (`max_routes_per_service`) and counts the rest under `other`, which the tab reports at the top.

Implemented in: `app_red.go` (`appHandleRoutes`), `app_diagnosis.go`, `app_openapi*.go`, `app_payload_policy.go`.

### 10.3 Traces

Where: service page → Traces tab; trace page `/applications/traces/<trace id>`.
API: `GET /traces?service_id=&route=&status=&reason=&min_duration_ms=`, `GET /traces/{trace_id}`.

The trace page draws a waterfall with each span's self time and highlights the **critical path**: from the root, the child that finished last, then its child that finished last, and so on. N+1 spans are tagged. Traces are kept 7 days.

API: `GET /services/{id}/sampling` returns seen and kept per reason for the range.

Implemented in: `app_traces.go`, `app_diagnosis.go` (`appEnrichSpans`), `app_sampling.go`, frontend `components/app/AppTraceWaterfall.jsx`.

### 10.4 Queries (database) tab

Statements show with their values removed, which is the default. A service set to names only shows **Show statements**, linking to its settings.


API: `GET /services/{id}/queries?sort=total_ms|p95|calls|errors`. Rows by system, operation, table and fingerprint with calls, errors, average, p95 (from the histogram) and total time; the fingerprint text when the service sends fingerprints. At most 200 rows.

Implemented in: `app_diagnosis.go`. See defect D1.

### 10.5 Errors tab and error page

API: `GET /services/{id}/errors?status=open|resolved|ignored`, `GET /errors/{id}`, `PATCH /errors/{id}` with `{"status": "...", "assignee": "..."}`.

A group shows type, route, top frame, frames, masked message (when enabled), first/last seen, total and in-range counts (hourly resolution), first and last version, status, assignee, regression flag and sample traces. Resolving stores the group's last version; a later failure in another version reopens it as regressed (7.2). Admins and analysts can change status and assignee; viewers cannot. Error page: `/applications/services/<service>/errors/<id>`.

Implemented in: `app_errors.go`. See defect D1.

### 10.6 Dependencies and the estate map

Where: service page → More → Dependencies; Applications → Dependencies (`/applications/map`).
API: `GET /services/{id}/edges`, `GET /map`.

- Edge counters for a range come from the hourly table, so the first and last hour of the range are counted whole.
- An edge is **new** when first seen inside the range and more than one hour after the calling service was first seen (edges on a service's first hour are its baseline).
- **Local resolution**: an edge to `localhost:<port>`, `127.0.0.1:<port>` or `[::1]:<port>` is shown as a call to the service that listens on that port on one of the caller's hosts.
- **Reachable from the internet**: services with effective exposure `internet`, and every service reachable from them through service-to-service edges (breadth-first search). Databases and external hosts are not marked.

Implemented in: `app_map.go`, `app_localedge.go`, `app_services.go`.

### 10.7 Exposure classification

A service's exposure is set by an analyst (`internet`, `internal`, `unknown`). When it is `unknown` the console infers one from the client and peer addresses in `app_client_stats` of the last 7 days (that is, from **failed** requests only): any public address → `internet`; only private ones → `internal`; none → `unknown`. The reason is shown next to the value. The effective exposure drives alert weighting and the map.

Implemented in: `app_exposure.go`.

### 10.8 Metrics tab and runtime summary

API: `GET /services/{id}/metrics` (catalogue with latest, average, min, max), `GET /services/{id}/metrics?name=&step=&instance=` (points; up to 300 series). The service detail returns a runtime summary per live instance:

| Summary | Source metrics |
|---|---|
| CPU % | `process.cpu.utilization`, `jvm.cpu.recent_utilization`, `process.runtime.jvm.cpu.utilization` (× 100) |
| Memory | `process.memory.usage`, `process.runtime.memory.rss` |
| Event loop delay | `nodejs.eventloop.delay.p99` |
| Heap % | `v8js.memory.heap.used` / `v8js.memory.heap.limit`; `jvm.memory.used` / `jvm.memory.limit` with `jvm.memory.type=heap` |
| Pool % | `db.client.connection.count` or `db.client.connections.usage` with state `used`, over `db.client.connection.max` / `db.client.connections.max` |

Other kept metrics (for example `dotnet.*`, `process.runtime.cpython.*`) appear in the catalogue but feed no summary and no rule.

Implemented in: `app_metrics.go`. See defect D1.

### 10.9 Payload review and masking

API (admin only): `PUT /services/{id}/payload-policy` (one route: names seen, names masked), `DELETE /services/{id}/payload-policy?route=&method=`, `POST /services/{id}/payload-policy/bulk`, `GET /services/{id}/payloads`.

- A route with no saved policy forwards no values. The agent, the ingest handler, the ingest store and the management API each check the policy and the always-masked rules.
- Allowed names = names listed in the review − masked names − always-masked names. A name that appears later is `new` and withheld until the route is reviewed again.
- Bulk: scope `needs_review` or `needs_review_and_new_fields`, or an explicit route list; mode `capture` (everything except always-masked) or `names_only` (all masked). At most 1 000 routes per request, at most 200 names per policy. Existing masks are kept; only new names are approved. Every route is audit-logged.
- Route review page: `/applications/services/<service>/routes/<method>/<route>`. Samples are paged and visible to admins only, kept 7 days.

**Always-masked names**: a name is masked when, with separators removed and lower-cased, it contains `password`, `passwd`, `passphrase`, `secret`, `token`, `apikey`, `authorization`, `cookie`, `creditcard`, `cardnumber`, `cvv`, `cvc`, `sessionid`, `privatekey`, `accesskey`, `clientsecret` or `refreshtoken`, or when one of its words (split on separators and camelCase) is `pwd`, `pass`, `jwt`, `bearer`, `auth`, `sid`, `otp`, `pin`, `ssn`, `card`, `pan`, `iban`, `cvv`, `cvc`, `signature`, `sig`, `credential(s)`, `session`, `sess`, `csrf`, `xsrf`, `secret`, `token`, `password`, `passwd`, `cookie`.

**Credential-looking values** (never forwarded): values starting `bearer ` or `basic `, containing `-----BEGIN`, JWTs (`eyJ` with two dots), 13–19 digit numbers passing the Luhn check, and strings of 32+ characters made only of letters, digits and `+/_=-.` that contain both a letter and a digit.

Implemented in: `otel/model.go`, `app_payload_policy.go`, `app_payload_bulk.go`, `app_payload_names.go`, `backend/internal/store/app_payload_names.go`.

### 10.10 API spec (OpenAPI)

API (admin only): `GET/POST/DELETE /services/{id}/openapi`. OpenAPI 3.x or Swagger 2.0, JSON or YAML, up to 5 MB, by upload or URL (fetched by the management server; loopback and link-local addresses refused), optional `base_path`. Up to 2,000 routes and 100 field names per route. Path, query and header parameter names and request-body property names (depth 4, `a.b`, `items[].sku`) are read; cookie parameters, examples and defaults are not; external `$ref` files are not followed.

Implemented in: `app_openapi.go`, `app_openapi_parse.go`.

### 10.11 SLO tab

API: `GET /services/{id}/slo`.

Objectives:
- **Availability**: target % = `slo.availability_target_pct`, else 100 − `error_budget_pct`, else 99.9. A bad request is an error (`errors` counter).
- **Latency** (only when `latency_target_ms` is set): target % = `slo.latency_target_pct`, else 95. A bad request is one slower than the latency target, estimated from the 12-bucket histogram by linear interpolation inside the bucket that contains the target (everything in the open last bucket counts as slow).
- Window: `slo.window_days`, 7 or 28 (default 28), rolling.

Figures, for each objective over the window:
- SLI % = (1 − bad / calls) × 100.
- Allowed bad requests = calls × (100 − target) / 100.
- Budget remaining % = (1 − bad / allowed) × 100 (can go negative).
- Burn rate over 1 h and 6 h = (bad / calls over that period) / ((100 − target) / 100). A burn rate of 1 spends the budget exactly over the window.
- Projected exhaustion = now + (allowed − bad) / (bad in the last 24 h / 24) hours; shown only when that time falls inside one window length.

Implemented in: `app_slo.go`.

### 10.12 Jobs and queues tab

API: `GET /services/{id}/operations`. Runs, failures, p50 and p95, last run, and for jobs the learned interval (median gap between run minutes, needs 5 runs). See defect D1.

Implemented in: `app_operations.go`.

### 10.13 Compare versions

API: `GET /services/{id}/compare?a=&b=` (versions) or `a_from, a_to, b_from, b_to`. A version's window runs from its first sighting to the first sighting of the next version (or now). Output: calls, error rate, p50, p95 per side, per-route changes, and what is new in B: routes, error groups, dependencies (up to 100 each).

Implemented in: `app_compare.go`.

### 10.14 Instances, Runtime, Events, Security, Alerts, Code tabs

**Tabs follow the tier.** A tab shows only when the service's tier gives it data:

| Tier | Tabs |
|---|---|
| T0 (host only) | Overview (host view), Instances, Host activity (the Runtime tab), Timeline (the Events tab), Alerts, Code; More: Dependencies, Settings |
| T1 | adds Endpoints, Traces, Queries, Errors, Jobs and queues, Metrics, SLO; More: Compare versions, Events, Runtime |
| T2 | adds Security |

A link to a tab the tier does not have opens the Overview. The **Tier 0 Overview** shows running instances and hosts, listening ports, open alerts, linked code and outbound destinations, a "Where it runs" list (host, pid, container, ports, start time), open alerts, the host rules that run without instrumentation (APP-H01–H08, H11) and the OpenTelemetry set-up hint. It loads no request statistics. **Settings** shows on Tier 0 only exposure, criticality, data sensitivity, owner, notification route, maintenance windows and learning; route, latency, SLO, sampling, database statement, error message and client-IP settings appear from Tier 1, clear-text user identifiers from Tier 2.

- **Code**: repositories linked to the service and their findings checked against what the service's processes run (Codebase capability.md section 4.15).

- **Instances**: host, pid, container, version, instrumented or discovered, identity, listening ports, last seen, runtime summary.
- **Runtime**: sensor tier per instance and host events attributed to the service through `raw.proc.ancestors` (`GET /services/{id}/runtime`).
- **Events**: one timeline (`GET /services/{id}/timeline`) of connections, process starts, file events, lifecycle changes, alerts, security events and (admins) request samples. A connection to a destination not contacted by the service's processes in the previous 30 days is marked.
- **Security**: `app.security` events (`GET /services/{id}/events`) with hashed user ids.
- **Alerts**: alerts linked to the service entity (`GET /services/{id}/alerts`).

Implemented in: `app_services.go`, `app_timeline.go`, `app_overview.go`.

### 10.15 Hosts, Overview, Services, Coverage, Settings pages

- **Hosts** (`/applications`, the landing page of Applications): every host with an application-monitoring agent and at least one live service instance in the last 24 hours (other agents are not listed). Per host: top risk, services by tier, open service and host alerts, the latest host vulnerability scan (critical, high, medium, cached CVEs), vulnerable code its services load, agent state. Worst first (`GET /api/v1/app/hosts`).
- **Host page** (`/applications/hosts/{agent}`, `GET /api/v1/app/hosts/{agent}`):
  - **Services on this host**: tier, what it is, the OS package it runs from, ports, exposure, open alerts, vulnerable code it loads, host-scan risks attributed to it, linked repositories. Ordered like the Services list.
  - **Open risks**, one list, worst first, filterable by type and service: service alerts (alerts linked to a service on the host), host alerts (the rest of the agent's open alerts), vulnerable code (dependency findings from any repository's latest scan whose package version a service here runs; marked linked or not linked to that service), exposed ports (host-scan port findings, medium or worse, attributed to the service listening on the port), host CVEs (cached NVD results, attributed to a service whose name or OS package matches), host configuration findings. Service-attributed items are weighted by the service (internet-facing +1, high or critical criticality +1, capped at critical); vulnerable code on disk but not loaded is lowered one level.
- **Overview** (`/applications/overview`): counts by tier, exposure and criticality; coverage = share of services at T1 or T2; open alerts by service (top 20); changes in range (new routes, dependencies, deploys); **Needs attention** with reasons `asserted_identity`, `route_overflow`, `trace_drops`, `not_reporting` (an OTLP service with no live instance).
- **Services** (`/applications/services`): every service with tier, exposure, criticality, request and error rate, containers, images, units, hosts; filter by text and environment; bulk exposure/criticality edit for admins. Default order: Tier 2, Tier 1, then Tier 0. Tier 0 services are ranked by what they are, recognised from the process name, executable or container image: databases (PostgreSQL, MySQL/MariaDB, MongoDB, SQL Server, Oracle, ClickHouse, MinIO…), then caches (Redis, Valkey, Memcached, etcd), web servers and proxies (nginx, Apache, Caddy, HAProxy, Envoy, Traefik, IIS…), app servers and runtimes (PHP-FPM, Tomcat, JBoss/WildFly, Jetty, Gunicorn, uWSGI, Keycloak, Vault, Jenkins…), brokers and search (RabbitMQ, Kafka, NATS, Elasticsearch/OpenSearch…), then other processes with a language runtime (likely your own applications), then everything else. The name column shows the recognised product and "code" when a repository is linked; a **What it is** facet filters by kind. Tier 0 rows show **Running** or **Stopped** instead of request health. Services cannot be deleted; unneeded ones simply sort last.
- **Coverage** (`/applications/coverage`): per service what is and is not set up; services that never sent telemetry; the application rule list with counters since the management backend started (fired, fired in observe mode, degraded, skipped by reason); whether the rule engine runs and how many host events it dropped because its queue was full.
- **Settings** (`/applications/settings`): services with learning status (click to edit), rule catalogue with default mode, retention text.

Implemented in: `app_overview.go`, `app_services.go`, `app_rules_engine.go` (`/rules/status`), frontend `pages/app/*.route.jsx`.

### 10.16 Learning

A service's learning clock starts at its `first_seen` (kept across the discovered → instrumented merge), or at `learning_started` when an admin uses "Restart learning" on the Settings tab. "Learning calls" counts requests since then.

---

## 11. Detection rules

### 11.1 How a rule becomes an alert

The management backend runs the rules in two ways:

- **Host-event tap**: every `process`, `network` and `file` event the backend's detection engine evaluates is copied (non-blocking) into a queue of 20 000. A full queue drops events and counts them (shown on Coverage).
- **Scan**: once a minute, for every service seen in the last 24 hours (max 2 000), the data-driven rules run against the stored statistics.

A finding then passes through:

1. **Rule gate** (`rule_settings`): disabled → nothing. A global row (no scope) applies first, then a row with `scope_kind: "service"` and `scope_id: "<name>|<environment>"`. Allowlist entries match case-insensitively or as a CIDR against the rule's allowlist values (for example the client address, the process name, the destination, or `parent>child` for H01).
2. **Weighting** (non-operational rules only): +1 when the service's effective exposure is `internet`, +1 when criticality is `high` or `critical` (both capped at Critical); −1 when an input was degraded (not below Low); capped at Medium when the finding's identity is `asserted`.
3. **Observe mode**: every application rule starts in observe mode. In observe mode the alert is created with severity Info (1) whatever the computed severity; the body records "Mode: observe".
4. **Dedup**: `CreateAlertDeduped` with `event_id = app:<RULE>:<dedup key>`. Dedup keys usually contain the service id and the hour (see table), so the same finding alerts at most once per hour.

Severity scale: 1 Info, 2 Low, 3 Medium, 4 High, 5 Critical.

Alert title: `[<RULE>] <summary> - <service> (<environment>)`. The body lists service, environment, instance, host, route, client address, hashed user, trace, process lineage, tier, identity, exposure/criticality, the severity factors, degraded input, MITRE ATT&CK ids, "What to check" and "Likely false positives". Entities linked: service, route (`name|env|METHOD /route`), service instance, host, IP, user.

To promote a rule out of observe mode, change thresholds or add an allowlist, an admin calls `PUT /api/v1/rules/settings` (section 3 of [configuration-platform.md](configuration-platform.md)). The Applications pages show the rules but have no control to change them.

**Deploy window** (used by H03, H04, A08, X06, O05): within `deploy_window_min` (default 30) after a new version was first seen, or after a new instance on the same agent started while a package or deploy tool ran (`apt`, `apt-get`, `dpkg`, `yum`, `dnf`, `rpm`, `apk`, `zypper`, `pip`, `pip3`, `npm`, `yarn`, `helm`, `kubectl`, `docker`, `ansible`, ...). Versions and instances in the service's first hour do not open a window.

**Maintenance windows** (service setting) silence all APM-O rules and APP-X06 while they are open.

Implemented in: `app_rules_engine.go`, `app_rules_core.go`, `rule_gate.go`, `app_rules_pg.go`, `app_rules_meta.go`.

### 11.2 Rule catalogue

27 rules are registered. All start in observe mode. "Base" is the severity before weighting and observe mode. Tunables are the `params` keys.

**Host runtime rules (Tier 0; need the host sensor)**

| Rule | Title | Fires when | Base | Tunables (default) | Dedup |
|---|---|---|---|---|---|
| APP-H01 | Service process spawned a shell | a process named `sh`, `bash`, `dash`, `zsh`, `ash`, `ksh`, `csh`, `tcsh`, `fish`, `busybox`, `python`, `python2/3`, `perl`, `ruby`, `lua`, `php`, `php-cli`, `pwsh` or `powershell`, with no terminal, starts below a service process. Follow-on: if that shell, or a descendant, then makes a network connection or writes a file within the window, a second alert "Shell spawned by a service process then made a ..." fires at Critical | High; follow-on Critical | `followon_window_s` 300 | service, pid, hour |
| APP-H02 | Service process ran a download tool | `curl`, `wget`, `nc`, `ncat`, `netcat`, `socat`, `tftp`, `ftp`, `fetch`, `aria2c`, `lwp-download`, `busybox-wget` starts below a service process | High | – | service, tool, hour |
| APP-H03 | Executable written to a web or upload directory | a create/write/rename in a path containing `/var/www/`, `/srv/www/`, `/usr/share/nginx/html`, `/webapps/`, `/uploads/`, `/upload/`, `/htdocs/`, `/wwwroot/`, `/public_html/`, `/public/`, `/static/`, `/html/`, of a file with a script extension (`.php`, `.jsp`, `.asp(x)`, `.cgi`, `.pl`, `.py`, `.sh`, `.so`, `.war`, `.jar`...) or an execute bit; not in a deploy window | High | `deploy_window_min` 30 | service, path |
| APP-H04 | New outbound destination | a connection to a non-loopback, non-link-local destination (DNS name, else the /24 or /48) not seen while learning; after learning (7 days and 200 recorded destinations); not in a deploy window. Low instead of Medium when the parent domain was seen | Medium (Low) | `min_days` 7, `min_samples` 200, `deploy_window_min` 30 | service, destination |
| APP-H05 | Connection to a public IP address with no DNS lookup / to a known-bad address | a public destination with a threat-intelligence IOC match (High), or with the sensor reporting no prior DNS lookup (Medium). The fallback tiers never report DNS, so without a kernel tier only IOC matches fire and the rest is counted as skipped | Medium; High on IOC | – | service, IP |
| APP-H06 | Cloud metadata endpoint accessed | connection to 169.254.169.254, fd00:ec2::254, 100.100.100.200, 169.254.170.2, 192.0.0.192 or `metadata.google.internal` / `metadata.azure.internal`, not seen while learning | Medium | `min_days` 7, `min_samples` 200 | service, endpoint |
| APP-H07 | Service process read a secret or credential file | a read/open of `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `~/.ssh/id_*` (not `.pub`), `~/.aws/credentials`, gcloud, Azure, kube, Docker config, `.git-credentials`, `.netrc`, or another process's `/proc/<pid>/environ`, by a process not on the legitimate-reader list (sshd, sudo, cron, package managers, git, rsync, backup tools...) | High | – | service, process, path |
| APP-H08 | Privilege change in a service process | a setuid/capability change of a kind and value not seen while learning | High | `min_days` 7 | service, change |
| APP-H11 | Container escape signal | a mount/setns/runtime-socket signal from the sensor, or an open/read/write of `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `cri-dockerd.sock`, by a process that is not a container runtime tool, inside a container or under a service | Critical | – | host, pid, signal |

Host rules are degraded (−1) when the sensor gave no ancestry and the event is not from the service process itself; without ancestry only a direct child of the service process is recognised.

**Application rules (Tier 1; need OTLP)**

| Rule | Title | Fires when | Base | Tunables (default) | Dedup |
|---|---|---|---|---|---|
| APP-A01 | Login failure burst | one client address has ≥ 20 responses 401/403 on login routes in 5 min. Login routes = the service's `login_routes`; when none is configured, routes containing `login`, `signin`, `sign-in`, `/token` or `/auth`. Reads per-client failure counters only; helper `auth.login` events are not counted | High | `threshold` 20, `window_min` 5 | service, client, hour |
| APP-A08 | New route | a route first seen after learning (7 days and 1 000 requests), not `other` or `(unmatched)`, not in a deploy window; the text notes when it is a configured public route | Low | `min_days` 7, `min_samples` 1000, `deploy_window_min` 30 | service, method+route |
| APP-A09 | Injection attempts | one client on one route has ≥ 3 failures in 5 min whose exception type is injection-class: starts with `param.` (agent signature), contains `injection`, `ognl`, `spelevaluation` or `spelparse`, or contains `sql` together with `syntax`, `grammar` or `parse` | Medium | `threshold` 3, `window_min` 5 | service, client, route, hour |
| APP-A13 | Rate-limit abuse | one client address receives ≥ 50 responses 429 in 5 min | Medium | `threshold` 50, `window_min` 5 | service, client, hour |

**Client address for A01, A09, A13.** The forwarded `client.address` is used only when the direct peer is in the service's trusted proxies. Otherwise the peer address is used. When the peer is a private or loopback address that differs from the forwarded one and no trusted proxies are set, the finding is marked degraded with a note to add the proxy. With client-address mode `off` nothing is recorded and these rules cannot fire.

**Cross-layer rules**

| Rule | Title | Fires when | Base | Tunables (default) | Dedup |
|---|---|---|---|---|---|
| APP-X02 | Application anomaly followed by host execution | APP-H01 or APP-H02 fires for a service that, in the previous 15 min, had an APP-A09 alert or ≥ 30 5xx responses | Critical | `window_min` 15, `spike_5xx` 30 | service, pid |
| APP-X06 | Instrumentation stopped while the process runs | an OTLP service sent no request statistics for ≥ 10 min (and < 24 h) after ≥ 20 requests in the hour before, its host agent reported in the last 2 min, and the host has events from that pid since; not in a deploy or maintenance window | Medium | `grace_min` 10, `deploy_window_min` 30 | service, hour |

**Operational rules (APM-O; not weighted)**

| Rule | Title | Fires when | Base | Tunables (default) | Dedup |
|---|---|---|---|---|---|
| APM-O01 | Error rate above budget / Route error rate above budget | over the last 10 min (ending 2 min ago), ≥ 50 requests and error rate > the service's `error_budget_pct` (default 5 %). Service-level first; if the service is under budget, each route with ≥ 50 calls is checked | High | `min_calls` 50, `window_min` 10, `default_budget_pct` 5 | service (or route), hour |
| APM-O03 | Traffic dropped sharply | after 24 h of learning and 1 000 requests: requests in the last 10 min ≤ 20 % of the usual. Usual = previous day's average per 10 min, or, with 3 weeks of history, the median of the same 10 minutes in each of the last 4 weeks. Skipped when the usual is < 100 | High | `drop_pct` 80, `min_baseline` 100, `window_min` 10 | service, hour |
| APM-O05 | N of M instances stopped reporting | an instance has been silent for > 10 min (and < 24 h) while at least one other instance reports, the host agent reported in the last 2 min, no newer instance replaced it in the same place, and no deploy window is open | High | `grace_min` 10 | service, hour |
| APM-O06 | Database call slowed down | per (system, operation, table, fingerprint): average time per call over the last 30 min ≥ 2 × the previous day's and ≥ 20 ms more, with ≥ 50 calls in each; not in the first day of learning | Medium | `factor` 2, `min_calls` 50, `min_delta_ms` 20, `window_min` 30 | service, query group |
| APM-O07 | Runtime saturated | per instance with ≥ 3 minutes of data in the last 10 min: event loop p99 ≥ 200 ms, heap ≥ 90 %, connection pool ≥ 95 % (High), or CPU ≥ 90 % | Medium; pool High | `eventloop_ms` 200, `heap_pct` 90, `pool_pct` 95, `cpu_pct` 90, `window_min` 10, `min_minutes` 3 | service, instance, kind |
| APM-O08 | New error group | a group first seen in the last 30 min reaches ≥ 3 occurrences; not `ignored`; not in the first day of learning | Medium | `min_count` 3, `window_min` 30 | service, fingerprint |
| APM-O09 | Resolved error is back | a group regressed in the last 30 min and is open | High | `window_min` 30 | service, fingerprint, regression time |
| APM-O10 | Job has stopped running | a job with ≥ 5 runs in 14 days has not run for ≥ 3 × its median interval and ≥ 5 min, and for less than 7 days | Medium | `interval_multiple` 3, `min_runs` 5, `min_late_min` 5, `max_age_days` 7 | service, job |
| APM-O11 | Job failing | a job or consumer with ≥ 5 runs in the last 30 min failed ≥ 25 % | Medium | `rate_pct` 25, `min_runs` 5, `window_min` 30 | service, kind, name |
| APM-O12 | Post-deploy regression | 5–30 min after a new version first appeared, with ≥ 100 calls before and after: error rate ≥ 2 points and ≥ 1.5 × the 24 h before, or p95 ≥ 1.5 × and ≥ 50 ms more | High | `window_min` 30, `min_wait_min` 5, `min_calls` 100, `error_delta_pct` 2, `error_factor` 1.5, `p95_factor` 1.5, `p95_delta_ms` 50 | service, version |
| APM-O13 | Error budget burning fast | after 24 h of learning, for availability and (if set) latency: burn rate ≥ 14.4 over both 1 h and 5 min (High), else ≥ 6 over both 6 h and 30 min (Medium); ≥ 100 requests in the long window | High / Medium | `fast_factor` 14.4, `slow_factor` 6, `min_calls` 100 | service, objective, fast/slow |
| APM-O14 | Error rate / Latency unusual for this time of week; Traffic spike for this time of week | with ≥ 100 requests in the last 10 min and ≥ 3 of the last 4 weeks having ≥ 100 requests in the same 10 minutes (needs 22 days of learning): error rate ≥ 3 × the weekly median and ≥ 2 points higher; or p95 ≥ 2 × and ≥ 100 ms higher; or requests ≥ 4 × the median (median ≥ 100) | Medium | `window_min` 10, `min_calls` 100, `error_factor` 3, `error_delta_pct` 2, `p95_factor` 2, `p95_delta_ms` 100, `spike_factor` 4, `min_baseline` 100 | service, kind, hour |

O06, O07, O08, O09, O10 and O11 depend on data that the current agent does not deliver (defect D1).

Rules named in the specification but **not built**: H09, H10, H12–H14, A02–A07, A10–A12, A14, A15, X01, X03–X05, O02, O04.

Implemented in: `app_rules_meta.go`, `app_rules_host.go`, `app_rules_app.go`, `app_rules_ops.go`, `app_slowquery.go`, `app_metrics.go`, `app_errors.go`, `app_operations.go`, `app_compare.go`, `app_slo.go`, `app_anomaly.go`.

---

## 12. Limits and caps

### 12.1 Agent

| Limit | Value | Constant / key |
|---|---|---|
| OTLP body | 4 MiB compressed, 16 MiB decompressed | `maxRequestBytes`, `maxDecompressedBytes` |
| Items per OTLP request | 20 000 spans / 5 000 logs / 20 000 metric points | `maxSpansPerRequest`, `maxLogsPerRequest`, `maxMetricPointsPerRequest` |
| Attributes per item | 256 | `maxAttrsPerItem` |
| Attribute string length | 4 096 bytes | `maxStringBytes` |
| Concurrent peer identifications | 4 (2 s wait) | `resolveSem` |
| Bound processes per service / services | 64 / 2 000 | `maxBoundPerService`, `maxBoundServices` |
| Routes per service | 2,000 (then `other`) | `max_routes_per_service` |
| Route length | 256 | |
| Stat keys in memory | 100 000 | `MaxStatKeys` |
| Client failure keys | 200 per service per minute | `MaxClientKeys` |
| Parameter names | 50 per span; 100 per route per flush; 5 000 keys | `maxParamsPerSpan`, `maxParamsPerRoute`, `maxParamKeys` |
| Parameter name / value | 64 / 256 bytes | `maxParamNameLen`, `maxParamValueLen` |
| Body attribute | 32 KiB, depth 4, 200 elements | `maxBodyAttrLen`, `maxBodyDepth`, `maxBodyElements` |
| Payload samples | 5 per route, 500 per flush | `maxPayloadsPerRoute`, `maxPayloadsPerFlush` |
| Open traces / spans per trace | 2 000 / 500 | `max_open_traces`, `MaxSpans` |
| Trace completion | 10 s idle, 2 s with root | `TraceIdle` |
| Trace JSON | 64 KB | `maxTraceJSON` |
| Kept traces per flush | 500 default, ≤ 5 000 | `defaultMaxKeptPerFlush` |
| Edge keys | 20 000 | |
| Slow children | 20 per route, 5 000 per flush | `maxChildrenPerRoute`, `maxChildKeys` |
| DB query groups | 200 per service per flush | `maxQueryKeys` |
| Fingerprint text | 512 bytes | `maxFingerprintText` |
| N+1 threshold | 10 repeats | `nPlusOneThreshold` |
| Error groups | 100 per service per flush; 30 frames; 4 096 frame bytes; message 200 | `maxErrGroupsPerSvc`, `maxErrFrames`, `maxErrFrameBytes`, `maxErrMessage` |
| Operations | 100 names per service | `maxOpsPerService` |
| Metric series | 100 per instance | `maxMetricSeriesPerInst` |
| Instances held | 5 000 | |
| Sender queue | 100 batches | |

### 12.2 Ingest backend (per batch)

| Section | Max | Constant |
|---|---|---|
| Body | 4 MiB | `appMaxBatchBytes` |
| instances | 200 | `appMaxInstances` |
| routes | 2 000 | `appMaxRoutes` |
| edges | 500 | `appMaxEdges` |
| traces | 50 (each ≤ 64 KB) | `appMaxTraces`, `appMaxTraceBytes` |
| clients | 3 000 | `appMaxClients` |
| params | 5 000 | `appMaxParams` |
| payloads | 500 (50 params each, values 256) | `appMaxPayloads` |
| children | 5 000 | `appMaxChildren` |
| queries | 3 000 (text 512) | `appMaxQueries`, `appMaxQueryText` |
| n_plus_one | 500 | `appMaxNPlusOne` |
| errors | 1 500 | `appMaxErrors` |
| metrics | 4 000 | `appMaxMetrics` |
| sampling | 200 | `appMaxSampling` |
| operations | 1 500 | `appMaxOperations` |
| Rate | 200 items/s, burst 5 000 per agent | `appItemsPerSec`, `appItemsBurst` |
| Row age | 24 h back, 10 min ahead | `appMaxStatAge`, `appMaxFutureSkew` |
| Observed parameter names per route | 200 | `AppMaxParamsPerRoute` |

### 12.3 Management

| Limit | Value |
|---|---|
| Query range | 90 days (`appMaxRangeDays`) |
| Series points | 2 000 (`appMaxSeriesPts`) |
| Route rows | 1 000 (`appMaxRouteRows`) |
| Sketch percentiles | ranges up to 7 days (`appSketchMaxRange`) |
| Settings lists (proxies, routes) | 200 entries, 256 characters each (`appMaxListItems`) |
| Maintenance windows | 50 |
| Payload policy names | 200 (`appMaxPolicyNames`) |
| Bulk approve | 2 000 routes (`appBulkMaxRoutes`) |
| API spec | 5 MB, 2,000 routes, 100 fields per route, depth 4 |
| Metric series per request | 300 (`appMetricMaxSeries`) |
| Rule queue | 20 000 events; scan every minute; 2 000 services per scan |

---

## 13. Privacy guarantees

What the code guarantees, and where:

- **Nothing listens on the network.** Loopback or Unix socket only, checked at configuration, at bind and before running (`receiver.go`, `config_app.go`).
- **Allowlists.** Only the attributes in section 4 are decoded. Headers, request and response bodies (other than the helper's body attribute, which is reduced to names and reviewed values), URLs and log bodies are never read.
- **Routes are templates.** The raw path is never used as a route; ingest strips query strings and hosts again (`aggregate.go`, `app_batch.go`).
- **Parameter values** leave the host only for reviewed routes and allowed, non-sensitive names and values; checked in four places (10.9).
- **Database statements** never leave raw. With fingerprints on, literals are removed first and ingest drops anything that still looks like a literal (`diagnose.go`, `app_batch.go`).
- **Error messages** are off by default; when on they are scrubbed in the agent and re-checked at ingest (`errors.go`, `app_batch.go`). Stack frames keep function, short path and line only.
- **User, session and object ids** from helper events are HMAC-SHA-256 pseudonyms (16 hex characters) keyed per organisation. With no key they are not sent at all. Cleartext only when an admin turns on "cleartext users" for the service (`privacy.go`, `events.go`).
- **Client addresses** follow the service's mode; the stricter of build and console setting wins (`privacy.go`, `remoteconfig.go`).
- **Credentials and paths** are stripped from dependency targets at ingest (`app_batch.go`).
- **Command lines** from the host sensor are redacted on the host (`internal/ebpf/redact.go`).
- **Host identity** comes from the agent record, not the payload.

The user-hash key is derived in the Agent builder as HMAC-SHA-256(`OW_SECRET_KEY`, "obsidianwatch/app-monitoring/user-hash/v1"). Changing `OW_SECRET_KEY` and rebuilding agents changes every pseudonym.

The settings endpoint gives every agent the settings and reviewed routes of all services, not only its own (service names, environments, privacy modes, allowed field names). No values are included.

---

## 14. What is not supported

- OTLP over gRPC; OTLP to a non-loopback address; an OpenTelemetry Collector in between is fine only if it exports OTLP/HTTP to the local agent (process identity is then that of the Collector).
- Exponential histograms and summaries; metrics outside the allowlist.
- Response bodies, request headers, cookies.
- Stack-frame parsing for Ruby, PHP, Rust, and .NET stacks without line information.
- Runtime summaries for Python, .NET and Go (their metrics are stored but not summarised).
- Merging a distributed trace across hosts: each agent keeps its own part, and the backend stores the first part that arrives for a trace id.
- Kubernetes pod-to-service mapping. Pods reach the agent only through a shared hostPath Unix socket; `k8s.*` attributes are discarded.
- Promoting, tuning and allowlisting rules from the Applications pages (API only).
- The kernel (`ebpf`) sensor tier; DNS-before-connect information (APP-H05 literal case).
- Configuring `watch_dirs` and `secret_files` from the Agent builder.
- The weekly report; the rules listed at the end of 11.2.

---

## 15. Known defects

### 15.1 Defects found while writing this document

| Id | Where | Effect |
|---|---|---|
| D1 | `agents/{linux,windows,macos}/internal/otel/batch.go` `(*Batch).Split` | **Fixed.** `Split` now carries queries, errors, metrics and operations into the pieces it sends (`splitInto`); the Queries, Errors, Metrics and Jobs tabs fill when the application sends that data |
| D2 | `otel/otlp.go` `clip` | **Fixed.** Names are cut to 4 096 bytes and attribute values to 32 KiB (`clipValue`), so helper bodies up to 32 KiB yield field names; stack traces keep 16 KiB, statements 4 KiB |
| D3 | `agents/*/internal/otel/aggregate.go` (`seen` map) | **Fixed.** The per-service route set is cleared every hour (`seenSince`), so a service that once hit the route limit no longer puts new routes in `other` until a restart |
| D4 | `backend/internal/api/app_batch.go:685`, `app_agentconfig.go:28` | A batch whose `agent_id` differs from the certificate is refused (403) while the event endpoint now re-attributes. Today the agent passes its certificate's id to the application service (`cmd/agent/main.go:106`), so this only bites if the id and the certificate ever diverge in a running agent; then all application statistics are dropped as non-retryable |
| D5 | `management/backend/cmd/server/main.go:91` | The purge runs on the management database. When `backend_db` points at a separate database the application tables are not there and the purge fails with a warning every 6 hours. The bundled docker-compose uses one database, where it works |


## 11. Application records in the event store

The ingest writes every application record it stores individually to the platform's event store, with the full payload under `raw.app`:

| Event type | One per | Payload |
|---|---|---|
| `app.request` | kept trace (every error, slow and security request, and the baseline sample) | service, environment, route, method, status, duration, keep reason, trace id and every span (a trace over 256 KiB keeps its first spans) |
| `app.payload` | captured request parameters (reviewed routes) | route, method, HTTP status, duration, trace id, the parameters the route's policy allows, the names withheld |
| `app.error` | error report | type, message (as the error-message setting allows), frames, route, fingerprint, version, trace id, count |
| `app.operation` | job or message consumer, per minute | kind, name, runs, failures, last run |

The existing `app.security`, `app.service_change` and `app.dependency_new` events stay as they are.

How many requests are recorded is the service's **Baseline sample** setting. The default is 1%; errors, slow and security-relevant requests are always kept. At 100%, every request is recorded, up to 5,000 per agent flush (30 seconds).

**Searching.**
- On **Detect → Events**, choose the application in the picker next to the search box, or write `app:<service>` (also `service:`, `route:`, `trace:`, `status:`).
- Console searches leave the four record types out unless the query names an application or an `app.*` type. Host searches stay fast however busy the services are.
- On a service page, **Events → Records** searches the same records with the application already chosen. Each record opens to its full payload, and **Open in Events** continues on the Events page.
- Detection, alert rules and correlation read every event, but the endpoint signatures, Sigma rules and IOC matching skip the four record types (the application rules work on the aggregates).
- Ingest migration 044 adds a partial index on `raw->'app'->>'service'` for these searches.
