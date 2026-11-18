# Application Monitoring - agent OTLP receiver

The agent's OTLP/HTTP receiver is part of the **app-server profile** (Agent Builder →
`enable_app_profile`). It is off unless that profile is selected.

## What listens, and where
- `127.0.0.1:4318` (OTLP/HTTP; protobuf or JSON, optional gzip). Paths: `/v1/traces`, `/v1/logs`;
  `/v1/metrics` is accepted and ignored.
- Optionally a Unix socket (`app_monitoring.otlp.socket`) for containers.
- **Never a routable address.** `ValidateListen` refuses anything that is not a loopback IP,
  the receiver verifies what it actually bound, and the service refuses to run if it is
  reachable beyond the host. The agent opens no inbound network port.
- gRPC is not implemented (it needs a library the offline build lacks). Use OTLP/HTTP:
  `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`, endpoint `http://127.0.0.1:4318`.

## Identity: who is sending?
The application never says which host, process or container it runs in. For each connection
the agent resolves the sending process itself (Linux: `SO_PEERCRED` for Unix sockets, a `/proc`
socket lookup for loopback TCP) and records pid, process start time, executable and container id
(from the process cgroup). `host.*`, `container.*` and `k8s.*` resource attributes are discarded.

A service name is bound to the first process that claims it. Later telemetry is **verified**
when it comes from a known process or one running the same executable, otherwise **asserted**.
Asserted telemetry is stored and shown but cannot raise high-severity alerts on its own.
On Windows and macOS process identification is not implemented yet, so telemetry there is
always `asserted`. A container whose network namespace differs from the agent's cannot be
resolved over loopback TCP; use the Unix socket for those.

## What is kept
Only allowlisted attributes survive decoding (`otel/model.go`). Route templates only
(`http.route`; a request with no route becomes `(unmatched)`, never the raw path). No URLs,
query strings, headers or bodies. Per service, at most 500 distinct routes; the rest collapse
into `other` and the overflow is counted.

## What is sent
Every 30 s the agent posts aggregate batches to `/api/v1/app/batch` over the existing outbound
HTTPS settings: per-minute RED statistics, dependency edges, instance heartbeats and sampled
traces (kept when errored, slow, touched by a security event, or 1 % baseline; <= 64 KB each;
bounded buffer, oldest dropped and counted). Raw spans never leave the agent.

## Security events and personal data
Helper log events become `app.security` events and enter the agent's **normal event channel**
(enrichment, normaliser, agent-own-activity filter, rate limiter), carrying the sender's pid and
parent pid. User, session and object identifiers are HMAC-hashed with a per-organization key
derived from the agent API key (rotating that key changes the pseudonyms). Without a key,
identifiers are not sent. Client addresses follow `client_ip_default` / `client_ip_by_service`
(`full`, `truncated` to /24 or /48, `off`).

## Per-client failure counters (source-based rules)
For rules A01 (login failure burst), A09 (injection attempts) and A13 (rate-limit abuse) the agent keeps, **for failed
requests only** (401/403, 429, other 4xx, 5xx, or a span exception), a per-minute counter per (route, client address,
direct peer address, exception type). At most 200 distinct keys per service per minute; the overflow is counted and shown on
the Overview as "needs attention". Rows go to `app_client_stats` (7-day retention). The client address follows the service's
storage mode (`full`, `truncated`, `off`); with `off` nothing is recorded. Rules apply the service's trusted proxies server-side.

## Per-service settings pulled by the agent
Every 5 minutes (`app_monitoring.settings_poll_interval`) the agent calls `GET /api/v1/app/agent-config` over its outbound HTTPS
connection and applies, per service: client-address mode, cleartext user identifiers, and the latency target (used as the slow-trace
threshold). A change in the UI therefore takes effect without rebuilding the agent. **The build configuration is a floor**: the stricter
client-address mode wins, and cleartext user ids are sent only when the pulled settings say so (or, if a service has no pulled settings,
when the build lists it). If the poll fails the agent keeps using the build configuration.

## Kubernetes
Run the agent as a DaemonSet and share a hostPath Unix socket with the application pods (`app_monitoring.otlp.socket`). The receiver
never binds a node or pod address.
