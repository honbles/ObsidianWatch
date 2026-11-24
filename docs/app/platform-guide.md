# ObsidianWatch Applications: platform guide

What every page, tab and function in the Applications area does, in the order you meet them. For connecting an app, use the setup guide for its language: [Node.js](node-security-guide.md), [Python](setup-python.md), [Java](setup-java.md), [.NET](setup-dotnet.md).

## 1. How a service gets here, and what you see at each tier

| Tier | What reports | What you get |
|---|---|---|
| T0 | The host agent only (listening ports, connections, process starts) | The service exists, with its host, ports and runtime activity. No routes, no request numbers, no request-based rules. |
| T1 | T0 plus OpenTelemetry from the app | Routes, error rates, latency, dependencies, traces, and the request-based rules (login bursts, new routes, error budget, traffic drop). |
| T2 | T1 plus security-helper events in the last 14 days | Sign-ins, authorization failures and exports with hashed user ids, plus the route field review. |

There is no T3. A service shows "not set up" on Coverage for whatever it lacks. When an app later starts sending OpenTelemetry, its host-discovered record is merged with it by process, so learning, settings and history are kept.

The agent receives OTLP/HTTP on `127.0.0.1:4318` (protobuf or JSON, `/v1/traces` and `/v1/logs`; `/v1/metrics` is accepted and ignored; gRPC is not supported). It never listens on a routable address. It decides which process is sending from the connection itself, so telemetry is **verified** when it comes from the process that claimed the service name and **asserted** otherwise. Asserted telemetry is shown but cannot raise high-severity alerts on its own.

## 2. Pages

### Overview (`/applications`)
The estate at a glance: services, coverage, internet-facing count and open alerts. Below that: open alerts by service, exposure and criticality, what changed in the range (new routes, new dependencies, deploys), and "Needs attention" (telemetry the agent could not bind to a service, services that exceeded the route limit, trace buffer overflow, instrumented services that stopped reporting).

### Services (`/applications/services`)
Every service seen on a host with an agent, discovered or instrumented, with tier, exposure, criticality, request rate and error rate. Filter by text and environment. Admins can select several services and set exposure and criticality in one step (other settings are kept).

### Dependencies (`/applications/map`)
Which services call which databases, queues and external hosts, from client spans. Highlights new dependencies and critical services an internet-facing service can reach (exposure paths). Filter by environment, internet-reachable and new in range.

### Coverage (`/applications/coverage`)
What each service tells us today and what to add for the next tier. Also lists services that never sent telemetry, the rule catalogue with activity since the backend started, and how to unlock routes, dependencies and request-based detections.

### Settings (`/applications/settings`)
Per-service tuning (including trace sampling: ordinary-trace share, error cap per minute, traces per flush) and learning status (click a service to edit it), the rule catalogue, and data retention (request statistics 90 days, sampled traces 7 days, changeable by an admin).

## 3. Service detail (`/applications/services/:id`)

The top of the page shows the service's tier, exposure, criticality and owner, four numbers (requests, error rate, p95, open alerts, instances), request and latency charts, and cards for new routes, new dependencies and deploys in the range. Then the tabs.

| Tab | What it does |
|---|---|
| **Overview** | The charts and change cards above. |
| **Routes** | Every route (`http.route` template, never the raw path) with calls, error rate, 401/403, 429, p95, last seen, and the field names seen on it. Tags: new, login, export, public, needs review, reviewed, new fields, and (with a spec) declared with no traffic yet, or not in spec. Each route also shows its slowest downstream calls (per request) and an N+1 tag when the same query ran 10 or more times under one parent. Holds the API spec panel and the bulk approve bar (section 4). |
| **Dependencies** | What this service calls, with calls and errors in the range and a `new` mark for edges first seen inside it. |
| **Database** | What the service asks its databases: calls, errors, average, p95 and total time by operation and table, sortable. With "statement fingerprints" on (Settings), each row also shows the query shape with every value replaced by `?`, so `WHERE id = 5` and `WHERE id = 9` are one query. Names only by default. |
| **Errors** | Error groups: the same failure counted once, however many requests hit it. Open one for its stack (function and file, no values), the versions it appeared in, sample traces and occurrences. Resolve it when you ship the fix, ignore expected failures, or assign it. A resolved group that fails again in a different version reopens as "regressed". Admins and analysts can triage; viewers read. |
| **Metrics** | Runtime and pool metrics the service reports (CPU, memory, event loop delay, heap, connection pools): latest, average and max per series, with a chart per row and an instance filter. Empty until the application turns on the OpenTelemetry metrics exporter. |
| **Jobs and queues** | Scheduled jobs and message consumers: runs, failures, p50 and p95, how often a job usually runs and when it last ran. |
| **SLO** | The objective (availability, and latency when a latency target is set), what was achieved over its 7 or 28 day window, the error budget left, burn rates over 1 h and 6 h, and when the budget would run out at the last day's pace. Defaults: 100 minus the error budget (99.9 % when none), 95 % of requests under the latency target, 28 days. |
| **Compare** | Two versions side by side: calls, error rate, p50 and p95, per-route changes, and what is new in the later version (routes, error groups, dependencies). A version's window runs from first seen to the next version's first seen. |
| **Instances and hosts** | Each running instance: host, process, version, whether it is instrumented, identity (verified or asserted), last seen. |
| **Events** | Everything that happened under the service: connections, process starts, file access (from the host sensor) and lifecycle entries (instance, version, route and dependency changes). Connections to destinations not contacted in the previous 30 days are marked. Admins also see the requests captured for reviewed routes. |
| **Runtime** | The host sensor per instance (kernel programs, kernel notifications plus polling, or polling only) and the host activity under the service. Empty until the agent has the app-server profile. |
| **Security** | Events from the security helper: sign-in success and failure, authorization denied, export, with hashed user identifiers (hover shows the hash, never a name). Needs T2. |
| **Traces** | Sampled traces: all errors, slow requests (over the latency target) and requests touched by a security event, plus 1 % of the rest. Filter by route, status, reason and minimum duration. Open one for the span waterfall: each bar shows the span's own time (children excluded) and the critical path, the chain of spans that decided when the request finished, is highlighted; repeated queries are tagged N+1. Kept 7 days, up to 64 KB each. |
| **Alerts** | The alerts linked to this service (the count shows beside the tab). Application detections start in observe mode, so a quiet list while baselines learn is normal. |
| **Settings** | Exposure, criticality, data sensitivity, owner, trusted proxies, login, export and public routes, latency target, error budget, maintenance windows, client address storage mode, database statement mode (names only or fingerprints), error message mode (none or masked), and "restart learning". Admin only to save. |

### Route review page
Review on any route opens `/applications/services/:id/review?route=...&method=...`: the route's calls, error rate, 401/403, p95, every field with its state, the masking choices, and the captured requests (paged, with status filter, latency and trace link). Captured samples are kept 7 days and are admin only.

## 4. Route fields, review, and bulk approve

For every route the agent reports the **names** of query-string and body fields. It sends **values** only when all of these hold:

1. an administrator reviewed the route,
2. the field is not masked in that review,
3. the name is not on the always-masked list (passwords, tokens, keys, card and national numbers and similar), and the value does not look like a secret (card number, JWT, long token).

The same checks run in the agent, the ingest API, the ingest store and the management API. A field that appears after a review is **new** and withheld until reviewed. Route states: needs review, reviewed, new fields.

**Approve one route:** Review, tick the fields to mask, Save. Everything not ticked is approved.

**Approve many:** on the Routes tab, a bar shows how many routes need review and how many have new fields. "Approve all" asks for one choice:
- *Capture values for all fields except the always-masked ones*, or
- *Approve but mask every field*: the routes count as reviewed and no value leaves the host; unmask single fields later.

Choices you already made on a route are kept; only its new fields are approved. Each route is written to the audit log. Up to 1000 routes per request (repeat for more). Admin only. API: `POST /api/v1/app/services/{id}/payload-policy/bulk` with `{"scope":"needs_review"|"needs_review_and_new_fields","mode":"capture"|"names_only"}` or `{"routes":[{"method","route"}],"mode":...}`.

### API spec (OpenAPI)
Upload or fetch an OpenAPI 3.x or Swagger 2.0 document (JSON or YAML, up to 5 MB) on the Routes tab. Declared routes and fields appear straight away, before any traffic. Declared-only routes show "declared, no traffic yet"; traffic on a route the spec lacks shows "not in spec"; a field seen in traffic but not in the spec is highlighted (a common sign of mass assignment). A URL is fetched by the management server, which refuses loopback and link-local addresses.

## 5. Detection rules

Twenty rules, all in **observe mode** by default: the alert is created but shown as Info until an admin promotes the rule. Each rule can be disabled, tuned and allowlisted per service.

| Rule | Tier | Fires when |
|---|---|---|
| APP-H01 | host | a shell or interpreter with no terminal is a descendant of the service process (Critical if it then connects out or writes a file within 5 min) |
| APP-H02 | host | curl, wget, nc and similar run by a descendant of the service |
| APP-H03 | host | a script or executable file is created in a web or upload directory outside a deploy window |
| APP-H04 | host | first connection to a destination not seen while learning |
| APP-H05 | host | connection to a public IP with no DNS lookup, or a threat-intel hit |
| APP-H06 | host | cloud metadata endpoint contacted by a service that did not do so while learning |
| APP-H07 | host | credential or secret files read by a non-system reader |
| APP-H08 | host | setuid or capability change not in the baseline |
| APP-H11 | host | mount, namespace or runtime-socket signal from a non-runtime process |
| APP-A01 | T1 | 20 or more login failures (401/403) from one client in 5 min |
| APP-A08 | T1 | a route first seen after learning, outside a deploy window |
| APP-A09 | T1 | 3 or more injection-class errors from one client on one route in 5 min (includes the agent's own parameter signatures such as `param.sql-injection`) |
| APP-A13 | T1 | 50 or more 429 responses for one client in 5 min |
| APP-X02 | cross | H01 or H02 within 15 min of an A09 alert or a 5xx spike on the same service (Critical) |
| APP-X06 | cross | no telemetry for 10 min after real traffic while the process is still active |
| APM-O01 | T1 | error rate above the error budget (default 5 %) over 10 min |
| APM-O03 | T1 | traffic 80 % below the usual rate: the previous day, or the same time of the week once three weeks of history exist |
| APM-O05 | T1 | an instance stopped reporting while the host is up and others report |
| APM-O10 | T1 | a job with a learned cadence (5 runs) has not run for 3 usual intervals (and at least 5 min) |
| APM-O11 | T1 | a job or consumer fails 25 % or more of at least 5 runs in 30 min |
| APM-O13 | T1 | the error budget burns at 14.4x over 1 h and 5 min (high), or 6x over 6 h and 30 min, for the availability or latency objective |
| APM-O14 | T1 | error rate, p95 or traffic is far outside the median of the same window in the last 4 weeks (needs 3 weeks of history; error rate 3x and 2 points, p95 2x and 100 ms, traffic 4x) |
| APM-O12 | T1 | within 30 min of a new version (after 5 min and 100 calls), the error rate is 2 points and 1.5x above the previous day, or p95 is 1.5x and 50 ms above it |
| APM-O06 | T1 | a database call averages 2x or more of the previous day's time per call (at least 50 calls in each window and 20 ms slower; quiet during the first day of learning) |
| APM-O07 | T1 | an instance stays saturated for 10 min: event loop delay p99 over 200 ms, heap over 90 % full, a connection pool over 95 % in use, or CPU over 90 % (needs 3 minutes of data) |
| APM-O08 | T1 | a new error group reaches 3 occurrences within 30 min of first appearing (quiet during the first day of learning; ignored groups never alert) |
| APM-O09 | T1 | a resolved error group fails again in a different version |

**Severity:** base per rule, +1 if internet-facing, +1 if criticality is high or critical, -1 when an input was degraded, capped at Medium when telemetry is asserted. Operational (APM) rules are not weighted.
**Learning:** first-seen rules (H04, H06, H08, A08) stay quiet until the service has learned for 7 days and 200 outbound connections or 1000 requests. A deploy window (default 30 min, opened by a new version or a restart during a package-manager run) suppresses H03, H04, A08, X06 and O05.
**Client address:** a forwarded address is used only when the direct peer is a trusted proxy for that service; otherwise the peer is counted and the finding is marked degraded.
**Limits:** X02 needs the application anomaly first. The H01 follow-on watch is in memory. Not built: H09, H10, H12 to H14, A02 to A07, A10 to A12, A14, A15, X01, X03 to X05, O02, O04.

## 6. What leaves the host

- Only allowlisted attributes survive decoding. Route templates only; no URLs, headers or response bodies.
- Command lines are redacted on the host (`--password=`, tokens, `KEY=`, `user:pw@`, bearer values).
- User, session and object ids are HMAC-hashed with a key derived from the agent API key. With no key, ids are not sent.
- Client addresses follow the service's mode: full, truncated (/24 or /48) or off.
- Where time goes (slowest downstream calls per route, at most 20) and database operation and table names are sent as names and numbers. Error groups send the exception type, the route and stack frames (function and short file path with line, no arguments); the message is sent only when an admin turns on masked messages. A database statement is never sent raw; if an admin turns on fingerprints for a service, only the statement with every value removed is sent (512 bytes at most).
- Every 30 s the agent sends per-minute statistics, edges, heartbeats and sampled traces. Raw spans stay on the host. At most 500 routes per service; the rest count as "other".
- Every 5 min the agent pulls per-service settings (client address mode, cleartext ids, latency target); the build configuration is a floor, so the stricter setting wins.

## 7. Host sensor

Part of the app-server profile. It reports only activity under a service: processes in its lineage, its connections, and file access in watched directories. Linux picks the best of `ebpf` (not built or tested yet), `procevent` (needs root) and `poll`. Windows and macOS use `poll` only: no file events and no privilege-change events, so H03 and H08 do not fire there. The Windows and macOS code has been unit tested and cross-built but not run on real hosts.

## 8. Read API (`/api/v1/app/*`)

Authenticated like the rest of `/api/v1`; viewers are read-only. `from` and `to` are RFC3339 (default last 24 h, maximum 90 days).

| Route | Purpose |
|---|---|
| `GET /services`, `GET /services/{id}` | Services with tier, instances, settings and RED summary. |
| `PUT /services/{id}/settings` | Admin. Service settings. |
| `GET /services/{id}/red` | RED time series. |
| `GET /services/{id}/routes` | Routes with RED, fields, review state, spec flags, `top_children` and `n_plus_one_count`. |
| `GET/POST/DELETE /services/{id}/openapi` | Admin. The service's API spec. |
| `PUT/DELETE /services/{id}/payload-policy` | Admin. Review one route. |
| `POST /services/{id}/payload-policy/bulk` | Admin. Approve many routes. |
| `GET /services/{id}/payloads` | Admin. Captured requests of reviewed routes. |
| `GET /services/{id}/slo` | Objectives with achieved percentage, budget left, burn rates and projected exhaustion. |
| `GET /services/{id}/operations` | Jobs and consumers in the range: runs, failures, p50, p95, last run and (jobs) the learned interval. |
| `GET /services/{id}/sampling` | Traces seen and kept per reason (security, error, slow, baseline) in the range. |
| `GET /services/{id}/compare` | `a` and `b` (two versions) or `a_from`, `a_to`, `b_from`, `b_to`: totals, per-route changes, new routes, error groups and dependencies. |
| `GET /services/{id}/metrics` | Runtime and pool series: without `name` the catalogue with latest, average, min and max; with `name` the points (`step` in minutes, optional `instance`). The service detail also returns a `runtime` summary per running instance. |
| `GET /services/{id}/errors`, `GET /errors/{id}`, `PATCH /errors/{id}` | Error groups with counts in the range (`status` filter), one group's stack and sample traces, and triage (`status` open, resolved or ignored; `assignee`). Admin or analyst for the PATCH. |
| `GET /services/{id}/queries` | Database calls by operation, table and fingerprint; `sort` is `total_ms`, `p95`, `calls` or `errors`. |
| `GET /services/{id}/edges`, `/alerts`, `/events` | Dependencies, alerts and events of a service. |
| `GET /map`, `GET /overview` | Estate graph and overview data. |
| `GET /traces`, `GET /traces/{id}` | Sampled traces and one trace's spans, with `self_ms` per span and the `critical_path` span ids. |

Percentiles come from a mergeable latency sketch (1 % accuracy, no ceiling, max latency reported) when every agent in the range sends one and the range is 7 days or shorter. Otherwise they are estimated from 12 histogram buckets (5 ms to 10 s; a value past 10 s is returned as 10000 with `over_range: true`). Responses carry `percentile_method`: `sketch`, `histogram`, or `mixed` (some agents older). Apdex is shown when the service has a latency target: satisfied up to the target, tolerating up to 4 times it.

## 9. Planned, not built

Java and .NET helper packages, Kubernetes pod-to-service mapping beyond the node socket, and the remaining rules listed in section 5.
