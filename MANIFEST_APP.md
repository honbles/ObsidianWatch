# MANIFEST_APP - Application Monitoring, checkpoints 1 (revised) to 7

Built against Application Monitoring Spec v0.2 and PARALLEL_BUILD_CONTRACT.md.

## IMPORTANT: checkpoint 1 was reworked
The first CP1 zip (`obsidianwatch_app_cp1.zip`) was built before the spec was available. This zip
**replaces** it: `030_app_services.sql`, `060_app_service_settings.sql`, the ingest store, the batch handler
and the management service API were rewritten to the spec's tables and shapes. I assumed CP1 was not
deployed anywhere; if migrations 030/060 from the first zip were applied to a database, drop those tables
(`services`, `service_*`, `app_*`) before applying these (the files keep their names, so `schema_migrations`
would otherwise skip them).

## Files added
Ingest backend: `migrations/030_app_services.sql`, `store/app_store.go`(+test), `api/app_batch.go`(+test)
Management backend: `migrations/060_app_service_settings.sql`, `store/app_retention.go`(+test),
`api/app_services.go`(+test), `api/app_agent_profile.go`(+test), **(CP3)** `api/app_red.go`, `api/app_traces.go`, `api/app_red_test.go`, `api/app_routes_test.go`; **(CP4)** `api/app_overview.go`(+test); **(CP5)** `api/app_map.go`(+test); **(CP6)** `api/app_rules_{meta,core,data,host,app,ops,pg,engine}.go` + tests (`app_rules_fixture_test.go`, `_host_test`, `_app_test`, `_pg_test`, `_zz_test`); ingest `api/app_agentconfig.go`; agent `otel/clients_test.go`, `otel/remoteconfig(.go,_test.go)`; frontend `pages/app/AppMap.route.jsx`
Agents (linux, windows, macos): `internal/otel/*` (pb, otlp, model, identity, privacy, aggregate, batch, events,
sender, receiver, service, os_<os>, peer_linux / peer_other, tests incl. `appconfig_test.go`), and `internal/config/config_app.go`,
which holds the config types **and** `(*Config).StartAppMonitoring` (the only code `main.go` calls; `main.go` imports cannot be edited outside markers)
Frontend (CP4): `src/api/app.js`; `src/components/app/` (AppPageHeader, AppStatCard, AppREDCharts, AppDependencyGraph, AppTraceWaterfall,
AppServiceSettingsForm, AppSetupHint, AppBadges, **AppHostApplications**, useAppLoad, appFormat); `src/pages/app/*.route.jsx`
(AppOverview, AppServices, AppServiceDetail, AppCoverage, AppSettings, AppEntityInstance, AppEntityRoute) and `src/pages/app/tabs/*`.
Host sensor (CP7): agent `internal/ebpf/` (types, redact, naming, filter, event, procfs, sensor, procevent, fanotify, kernel stub, `bpf/sensor.bpf.c`, `kernel_ebpf_linux.go` [build tag `ebpf`], tests); `otel` aggregator carries discovered instances; ingest merge `appMergeDiscovered`; mgmt `GET .../runtime`; frontend `AppTabRuntime`.
Docs: `docs/app/agent-otlp.md`, `docs/app/api.md`, `docs/app/ui.md`, `docs/app/rules.md`, `docs/app/sensor.md`

## Files edited (owned stubs)
`backend/.../api/app_routes.go`, `management/.../api/app_routes.go`, `management/.../api/app_agent_profile.go`,
`agents/{linux,windows,macos}/internal/config/config_app.go`

## Shared-file edits (inside markers only)
| File | Marker | Change |
|---|---|---|
| `management/backend/internal/api/agent_builder.go` | `[APP-FIELDS-*]` | added `AppOTLPSocket`, `AppClientIPMode` |
| `agents/{linux,windows,macos}/cmd/agent/main.go` | `[APP-COLLECTORS-*]` | one call: `cfg.StartAppMonitoring(...)` |
| `management/frontend/src/App.jsx` | `[APP-ROUTES-*]` | registers every `pages/app/*.route.jsx` via `import.meta.glob` (imports are outside the marker, so none could be added) |
| `management/frontend/src/components/Navbar.jsx` | `[APP-NAV-*]` | one "Applications" dropdown (reuses the already-imported `Boxes` icon) |
| `management/backend/internal/api/agent_builder.go` | `[APP-FIELDS-*]` | (CP7) also `AppSensorMode`, `AppEnvironment` |
| `management/frontend/src/pages/AgentBuilder.jsx` | `[APP-FORM-*]`, `[APP-BUILDER-*]` | form defaults and the app-server profile checkbox + socket / client-IP options (under the "Connection" group) |

`go.mod` / `go.sum` / `package*.json`: unchanged. Linux `otel` uses `golang.org/x/sys/unix`, already required.

## Migrations
| # | Name | Migrator | Tables |
|---|---|---|---|
| 030 | `030_app_services.sql` | ingest | services, service_instances, service_edges, service_routes, service_versions, app_baselines, app_route_stats, app_traces |
| 031 | `031_app_edge_client_stats.sql` | ingest | app_edge_stats (hourly dependency deltas), app_client_stats (per-client failure counters) |
| 060 | `060_app_service_settings.sql` | mgmt | service_settings, app_service_merges |

Deviations from spec section 4/5 (all deliberate, all small):
- `service_instances`: `pid` and `proc_start` are `NOT NULL` (0 / epoch when unknown) so they can be part of the unique key; added `instance_ref`, `identity` ('verified'|'asserted') and `attrs` (language, sdk, exe).
- `criticality` lives in `service_settings` (contract: "weighting uses service_settings.exposure and criticality"), not in `services`. Values: low|normal|high|critical.
- `service_settings.service_id` has **no foreign key** to `services`: the two backends migrate independently and in either order.
- `service_settings` gained `cleartext_users` (spec section 9 opt-in). `app_service_merges` uses service ids.
- `services.attrs` carries `language`, and counters `route_overflow` / `trace_drops` reported by agents.

## Routes
- Ingest: `POST /api/v1/app/batch`
- Mgmt: `GET /api/v1/app/services`, `GET /api/v1/app/services/{id}`, `PUT /api/v1/app/services/{id}/settings` (adminOnly, audited by existing middleware)
- Mgmt (CP3, read-only): `GET /api/v1/app/services/{id}/red`, `.../routes`, `.../edges`, `GET /api/v1/app/traces`, `GET /api/v1/app/traces/{trace_id}` - see `docs/app/api.md`. `GET /services` now also returns a per-service `red` summary for the range.
- Mgmt (CP7): `GET /api/v1/app/services/{id}/runtime` (host instances with listening ports and sensor tier + host events under the service, attributed through `raw.proc.ancestors`); `GET /api/v1/app/overview` gained `sensors` and `poll_hosts`.
- Mgmt (CP6): `GET /api/v1/app/rules/status` (per-rule fired / observe / degraded / skipped counters for the Coverage page).
- Ingest (CP5): `GET /api/v1/app/agent-config?agent_id=` (agents poll per-service settings). Batch gained `clients[]` and `notes[].client_overflow`.
- Mgmt (CP5): `GET /api/v1/app/map`; `GET /services/{id}/edges` now returns `range_calls` / `range_errors` from hourly `app_edge_stats`.
- Mgmt (CP4, read-only): `GET /api/v1/app/overview`, `GET /api/v1/app/services/{id}/alerts` (via alert entity links), `.../events` (app.security events, read through backendDB), `GET /api/v1/app/instances/{id}`; `GET /services` gained `agent_id` filter, `learning_calls`.

## Batch endpoint behaviour
Registered agents only (403 otherwise); host/OS come from the agent record; per-agent token bucket (200 items/s, burst 5000) with `Retry-After`;
caps 4 MiB / 200 instances / 2000 route rows / 500 edges / 50 traces; trace spans <= 64 KB; invalid items are dropped and counted;
routes lose query strings, edge targets lose credentials/paths; first-seen service, instance, version and dependency emit
`app.service_change` / `app.dependency_new` (with `baseline: true` during learning, `raw.app.instance` = `service_instances.id`).

## Agent (checkpoint 2)
- OTLP/HTTP receiver (protobuf + JSON, gzip, 4 MiB/16 MiB caps) on loopback or a Unix socket only; refuses routable addresses at config validation, at listen time, and at run time.
- Hand-written protobuf wire reader (no protobuf dependency). Allowlisted attributes only.
- Identity: process resolved from the connection (SO_PEERCRED / `/proc`), start time, exe, container id from cgroup; first claimant binds a service; others are `asserted`; self-reported host/container/k8s attributes discarded.
- In-agent aggregation: per-minute RED with 12-bucket histogram and 2xx/401-403/429/5xx classes, route inventory with 500/service cap (`other`), edges, instance heartbeats, trace sampling (error/slow/security/baseline), bounded buffer with counted drops, clock-skew handling, requeue of undelivered statistics.
- `app.security` events from helper logs go through `rawCh` / `dispatchCh` (the **normal event channel**: normaliser, own-activity filter, rate limiter) with PID and PPID set. Users/sessions/objects HMAC-hashed; client IP full/truncated/off per service via build config.
- Sender: outbound HTTPS only, same CA/client-cert/API key as the forwarder; retries, bounded queue.

## Frontend (CP4)
Section **Applications** at `/applications` (Overview, Services, service detail with Overview / Routes / Dependencies / Instances and hosts / Security / Traces / Alerts / Settings tabs, Coverage, Settings), `AppHostApplications` for the host page, entity redirect pages for `service_instance` and `route` chips.
Every page handles loading, empty and error through `StateBlock`; time range through `useTimeRange`; no new dependency and no global CSS.
**Not built yet:** Runtime tab (CP7, needs the sensor), weekly report. The Security and Alerts tabs are wired and show honest empty states until Tier 2 events / rules exist.
Verified with a jsdom smoke test (29 checks over all pages and tabs against fixture API data); the harness is delivered separately in `ui-smoke-test/` and is not part of the tree.

## Detection rules (CP6) - see `docs/app/rules.md`
18 rules registered with `RegisterRuleMeta` (family, layer, tier, ATT&CK, WhatToCheck, false positives, tunables, `DefaultObserve: true`,
`Operational` for APM): APP-H01–H08, H11; APP-A01, A08, A09, A13; APP-X02, X06; APM-O01, O03, O05. Each has positive and negative fixtures
(`TestAppRuleFixtureCoverage` fails if a rule lacks either), tunables, allowlist support (CIDR, case-insensitive, `parent>child` pairs) and observe mode.
- **Mechanism.** `RegisterSigProvider(appTap)` is used only as an event tap (it returns no signatures); a bounded queue feeds a worker, and a
  one-minute scan reads the aggregate tables. Alerts go through `ruleGate` -> `appWeigh` -> `CreateAlertDeduped` (never the engine's static-severity
  signature path). The worker starts from `registerAppRoutes` (so it needs no edit to `server.go`).
- **Alert conventions.** `Alert` has no source column, so the rule is identified by title prefix `[APP-H01]` and by `event_id = app:<RULE>:<dedup key>`.
  Entities linked: service, service_instance, route (`name|env|METHOD /tpl`), host, ip, user. EventType is the source event's type, or `app.alert`.
- **Host event contract.** The `raw.proc` shape the eBPF sensor must produce is defined in `docs/app/rules.md`; checkpoint 7 must follow it.
- The rules write `app_baselines` (created by the ingest migration) from the management backend; both share one database.

## Host runtime sensor (CP7) - see `docs/app/sensor.md`
Three tiers, `auto` picks the best that works: **ebpf** (kernel programs, build tag), **procevent** (netlink proc connector + `/proc` polling + fanotify),
**poll** (`/proc` only). Opt-in through the app-server profile (`app_monitoring.ebpf.enabled`). Events go through `rawCh`/`dispatchCh` (the normal channel) with
`pid`, `ppid` and the `raw.proc` contract; only activity under a service's processes is reported. Discovered services (Tier 0) are named from their jar / script /
module / DLL and are merged into the instrumented service **by process, not name**, carrying baselines, settings and the learning clock.
- **Verified on a real kernel (6.18) in this environment:** the `/proc` readers, the polling tier (process, connection, listener discovery), the netlink proc connector
  (genuine exec events), fanotify file events, redaction, naming, the `raw.proc` JSON contract; the merge and Runtime API on PostgreSQL.
- **NOT built or tested:** the kernel tier (`bpf/sensor.bpf.c`, `kernel_ebpf_linux.go`). This environment has no clang and no `github.com/cilium/ebpf`. The Go loader only
  parses; the C struct layout was checked against the Go mirror with gcc. `go vet -tags ebpf` fails here on the missing module, as documented. Follow `bpf/README.md`.
- No redaction existed in the Linux agent (the contract assumed one); `internal/ebpf/redact.go` is new and conservative.

## Event types / rule IDs
Event types emitted: `app.service_change`, `app.dependency_new` (backend), `app.security` (agent), alert event type `app.alert` (rules). Rule IDs: see above.

## Config keys
Agent `app_monitoring.*`: `enabled`, `otlp.listen`, `otlp.socket`, `user_hash_key`, `cleartext_services`, `client_ip_default`, `client_ip_by_service`,
`slow_ms`, `slow_ms_by_service`, `baseline_sample_pct`, `max_routes_per_service`, `max_open_traces`, `flush_interval`, `settings_poll_interval`. Builder JSON: `enable_app_profile`, `app_otlp_socket`, `app_client_ip_mode`.
Settings keys: `app.retention_stats_days` (90; also edge stats), `app.retention_trace_days` (7), `app.retention_client_days` (7). `AppPurge` is ready for the scheduler.

## Dependency changes
None. Missing offline and therefore not used: OTLP gRPC / protobuf libraries (receiver is HTTP-only). **`github.com/cilium/ebpf` is required only for the optional `ebpf` build tag** (not added to `go.mod`; pin a version when building the kernel tier - see `internal/ebpf/bpf/README.md`; also needs clang and bpftool).

## Verification
`go vet` + `go test -count=1`: ingest, management, linux agent (with `-race`); `go vet` (compiles tests): windows (GOOS=windows) and macos (GOOS=darwin).
Integration tests run on a real PostgreSQL when `OW_TEST_PG_DSN` is set (skipped otherwise). Real process identification is tested on Linux for TCP and Unix sockets.
`npm install && npx vite build` passes (no frontend change yet).
Environment notes: Go 1.27.3 was used (contract path absent); the management `api` tests need `OW_ALLOW_INTERNAL_OUTBOUND=true` (foundation SSRF guard);
Windows `go vet` reports two `unsafe.Pointer` warnings in `collector/location.go` and `collector/network.go` that are **already present in the foundation**.

## Requests
000. Reuse of "their argument redaction" (contract section 1) was not possible: no redaction exists in the Linux agent. If one exists on the Windows or macOS side, point me at it and I will align.
00. The Alerts/Detections pages can derive the rule family from the alert title prefix or `event_id` prefix `app:`; `/api/v1/rules/meta` already carries families and the Operational flag for the owner's family filter and observe-promotion UI.
0. The integration owner may want to replace the `import.meta.glob` route registration with explicit imports when merging (see `docs/app/ui.md`).
1. (nice to have) A way for the builder to receive a per-organization secret, so the user-hash key need not be derived from the agent API key.

## Decisions taken (owner: "do what is best") and open questions
1. **Kubernetes node address - decided: loopback / Unix socket only.** The contract's rule that no agent port is ever reachable from the network wins over the spec's "node address". DaemonSet pods share a hostPath Unix socket (`app_monitoring.otlp.socket`, documented in `docs/app/agent-otlp.md`).
2. **Per-client counters for A01/A09/A13 - decided: agent-side failure counters in a new table.** The agent records, for failed requests only, a per-minute counter per (service, route, client address, peer address, exception type), capped at 200 keys/service/minute (overflow counted), into `app_client_stats` (7-day retention). Rules (checkpoint 6) read it together with the service's trusted proxies, login routes and thresholds. Addresses follow the service's storage mode; `off` records nothing. Exception types are stored raw so injection classification can be tuned server-side without an agent rebuild.
3. **Settings reaching agents - decided: pull, not push.** Agents poll `GET /api/v1/app/agent-config` over their existing outbound HTTPS (5 min) for client-address mode, cleartext user ids and latency target per service. The build configuration is a floor (stricter client-address mode wins; cleartext only if the pulled settings say so). Consequence to be aware of: the ingest backend reads `service_settings`, a table the management migration creates (they share one database); a missing table is treated as "no settings".
4. Spec section 4 wants instrumented services merged with discovered ones; that needs the eBPF sensor (CP7). Still open.

## Known gaps
- Windows and macOS: no process identification yet (all telemetry `asserted`); no Unix-socket peer credentials there.
- OTLP over loopback TCP cannot identify processes in another network namespace (use the Unix socket).
- The kernel (eBPF) tier is unbuilt (see above). The fallback tiers do not supply DNS lookups, so APP-H05 is skipped (and counted) until the kernel tier or a DNS source provides `prior_dns`. Sensor is Linux-only (Windows/macOS log that and continue). No weekly report.
- The existing process collector and the sensor can both report an exec; rule dedup keys make that harmless, but event volume for service-descended processes is doubled.
- Rules not in the v1 list (see `docs/app/rules.md`). X02 correlates anomaly-then-execution only; the H01 follow-on watch is in memory.
- Alert weighting also goes through the foundation's host weighting inside `CreateAlertDeduped`.
- Alert links go to the generic `/alerts` page (no per-alert deep link existed to target).
- The settings form PUT replaces the whole settings object; the UI always sends the complete current values (bulk edit merges first).
- RED percentiles are histogram estimates (12 buckets); values above 10 s are reported as `10000` with `over_range: true`.
- Dependency counts per range have hourly resolution (`app_edge_stats`); the first and last hour of a range are included whole.
- `app_service_merges` is created but unused (`app_baselines` is now written by the rules).
