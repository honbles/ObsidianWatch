# Application monitoring: deployment

How application monitoring gets onto a host, from the Agent builder to a verified service in the console. For what the data means see [capability.md](capability.md). For per-language steps see the `configuration-<runtime>.md` files.

## 1. What runs where

| Component | Where | Role |
|---|---|---|
| Your application with an OpenTelemetry SDK or agent | the application host | sends OTLP/HTTP to the local agent |
| ObsidianWatch agent built with the **app-server profile** | the same host | receives OTLP on loopback or a Unix socket, identifies the sending process, aggregates, sends statistics; runs the host runtime sensor |
| Ingest backend | server | `POST /api/v1/app/batch`, `GET /api/v1/app/agent-config` |
| Management backend and console | server | Applications pages, settings, rules |

The application never talks to the server. Only the agent does, over its existing outbound HTTPS connection with its own enrolled client certificate. No inbound port is opened on the application host.

## 2. Build an agent with the app-server profile

1. Open **Agent builder** in the console.
2. Fill in the connection fields as for any agent (backend URL, CA certificate, enrollment token lifetime and host limit).
3. In the **Connection** group tick **Enable the app-server profile (Application Monitoring)**. It is off by default. Four more fields appear:

| Field | Builder JSON key | Values | Default | Effect in the agent configuration |
|---|---|---|---|---|
| Unix socket path (optional) | `app_otlp_socket` | absolute path, 1–200 characters of `A–Z a–z 0–9 . _ / -`, no `..` | empty | `app_monitoring.otlp.socket`. An invalid path is silently left out |
| Host sensor tier (Linux) | `app_sensor_mode` | `auto`, `procevent`, `poll` | `auto` | `app_monitoring.ebpf.mode` |
| Environment for discovered services | `app_environment` | 1–64 characters of `A–Z a–z 0–9 . _ -` | empty (agent uses `default`) | `app_monitoring.ebpf.environment` |
| Client address storage | `app_client_ip_mode` | `full`, `truncated`, `off` | `full` | `app_monitoring.client_ip_default` |

4. Click **Build** for the platform, wait for the compile (1–2 minutes the first time), then **Download**.

The server compiles the configuration into the binary. The profile adds this block (example with a socket and an environment):

```yaml
app_monitoring:
  enabled: true
  otlp:
    listen: "127.0.0.1:4318"
    socket: "/run/obsidianwatch/otlp.sock"
  user_hash_key: "<64 hex characters>"
  client_ip_default: full
  ebpf:
    enabled: true
    mode: auto
    environment: "prod"
  slow_ms: 1000
  baseline_sample_pct: 1
```

- `listen` is always `127.0.0.1:4318`. The builder offers no other address.
- `user_hash_key` is derived from the server's `OW_SECRET_KEY` (HMAC-SHA-256 with a fixed label). Every agent of the installation gets the same key, so a user is pseudonymised the same way on every host. If `OW_SECRET_KEY` is empty, no key is written and the agent does not send user ids at all. Changing `OW_SECRET_KEY` changes all pseudonyms for agents built afterwards.
- The host sensor is always enabled with the profile. There is no builder switch to have the receiver without the sensor.
- Settings not written by the builder keep their agent defaults: `max_routes_per_service` 2000, `max_open_traces` 2000, `flush_interval` 30 s, `settings_poll_interval` 5 min, `ebpf.poll_interval` 2 s, no extra `watch_dirs` or `secret_files`, no `cleartext_services`, no `client_ip_by_service`, no `slow_ms_by_service`.

Implemented in: `management/backend/internal/api/agent_builder.go` (`[APP-FIELDS]`, `[APP-YAML]` markers), `app_agent_profile.go`; `management/frontend/src/pages/AgentBuilder.jsx` (`[APP-BUILDER]`); `agents/linux/internal/config/config_app.go`.

### Sensor tier choice

| Tier | Choose when | Needs |
|---|---|---|
| `auto` | normal case | tries the kernel tier, then `procevent`, then `poll`. The kernel tier is not built in this release, so `auto` means `procevent` when the agent runs as root, else `poll` |
| `procevent` | you want exec events without gaps | root (netlink proc connector); fanotify for file events |
| `poll` | the agent cannot run as root (for example inside a container) | nothing; processes shorter than the 2 s poll interval can be missed |

## 3. Install

Copy the binary to the application host and install it as for any agent:

| Platform | Install | Uninstall |
|---|---|---|
| Linux | `chmod +x obsidianwatch-linux-agent && sudo ./obsidianwatch-linux-agent install` | `sudo ./obsidianwatch-linux-agent uninstall` |
| Windows | `.\obsidianwatch-win-agent.exe install` | `.\obsidianwatch-win-agent.exe uninstall` |
| macOS | `chmod +x obsidianwatch-macos-agent && sudo ./obsidianwatch-macos-agent install` | `sudo ./obsidianwatch-macos-agent uninstall` |

On first start the agent enrolls with the embedded token and receives its client certificate. It then starts the collectors. When the profile is on and the configuration is valid, the agent log shows `otlp receiver listening addr=127.0.0.1:4318` (and the socket path when set) and `host sensor running mode=<tier>`. The list of active collectors contains `app-otlp` and `app-sensor`.

If the configuration is invalid (for example a non-loopback listen address in a hand-written development config), the log shows `app monitoring disabled: invalid configuration` and the rest of the agent runs normally.

Port 4318 must be free on loopback. If another OpenTelemetry Collector already listens there, the receiver fails to start (`otlp listen: ...`). Stop the other collector or point it at the agent (it will then be the identified sender, see section 6).

Windows and macOS: the receiver and a polling sensor run, but neither has been run on a real host. Treat them as untested.

## 4. Point the application at the agent

The application exports OTLP over HTTP to `http://127.0.0.1:4318` (`/v1/traces`, `/v1/logs`, `/v1/metrics`), protobuf or JSON. gRPC is not accepted. Set at least:

- `service.name` (the console groups by it),
- `deployment.environment.name` (empty becomes `default`),
- `service.version` (enables deploy detection, version compare, error regressions and the deploy window).

Do not set `host.*`, `container.*` or `k8s.*`; they are discarded.

Per-runtime steps: [Java](configuration-java.md), [.NET](configuration-dotnet.md), [Python](configuration-python.md), [Node.js](configuration-node.md), [Go](configuration-go.md), [other OpenTelemetry SDKs](configuration-other-sdks.md).

Quick receiver check from the host:

```
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:4318/v1/traces
```

`200` means the receiver is up. `000` means nothing listens. `415` means the content type header was wrong.

## 5. How services are discovered

Two independent ways, merged by process:

1. **Host discovery (Tier 0).** The sensor lists listening TCP sockets every poll round and names each owning process (jar, script, module, DLL, systemd unit or container name). System daemons are skipped. These services appear with source `discovered`, the environment from the builder field, their ports, and no request data.
2. **OpenTelemetry (Tier 1).** The first span from a process creates the service `(service.name, environment)` with source `otel`.

When an OpenTelemetry instance reports a pid that a discovered service holds on the same agent, the backend moves the instance, its learned baselines, its settings and its first-seen time to the instrumented service and deletes the empty discovered one. The names do not need to match.

A service reaches Tier 2 once it sends security-helper events.

## 6. Containers and Kubernetes

The agent identifies the sender from the connection. That works over loopback TCP only when the application and the agent share a network namespace (and the agent can read the application's `/proc` entries).

| Setup | What to do | Identity |
|---|---|---|
| Application on the host | export to `http://127.0.0.1:4318` | verified |
| Container with `--network host` | same | verified when the agent can see the process in `/proc` |
| Container with its own network namespace | build the agent with a Unix socket path; mount the socket's directory into the container; export over that socket | verified through `SO_PEERCRED` |
| Kubernetes | run the agent on each node (DaemonSet) with the socket on a hostPath volume; mount the same hostPath into the pods | verified through `SO_PEERCRED`; there is no pod-to-service mapping beyond the container id |

The socket is created with mode 0666; identity comes from the kernel's peer credentials, not from file permissions. The agent records the container id from the sender's cgroup. Docker's `docker-proxy` and the containerd shims are not reported as services; the sensor adds the container name and image to the instance on the Runtime and Instances tabs.

Not every SDK can export OTLP/HTTP over a Unix socket. If yours cannot, put a small local forwarder in the pod that listens on loopback and writes to the socket; the agent will then identify the forwarder process, not the application. This pattern has not been tested.

The Kubernetes setup (DaemonSet, hostPath socket) is a design decision (loopback or Unix socket only; no agent port is reachable from the network). It has not been run on a real cluster.

## 7. Verify that it works

Allow one to two minutes: the agent flushes every 30 s and holds the current minute until it closes.

1. **Applications → Hosts** (the landing page). The host appears once one of its services has a live instance; open it to see its services and open risks. Hosts without an application-monitoring agent are not listed here (they stay under Endpoint → Fleet).
2. **Applications → Services.** The service appears with its environment. Tier T1 (or T2 with helper events). Host-only services (T0) appear without instrumentation, with databases, caches and web servers listed first.
3. Service page → **Endpoints** tab (T1 and up; a T0 service has no such tab). Routes appear as templates (`/orders/{id}`), never raw paths. Only `(unmatched)` or `other` means the framework does not set `http.route`.
4. Service page → **Instances** tab. The instance says **verified** with the executable. **asserted** means the agent could not match the connection to a process: see section 6.
5. **Applications → Coverage.** The row for the service shows what is set up and what is "not set up" for the next tier. The detection-rules card shows whether the rule engine is running and per rule how often it fired, fired in observe mode, ran degraded, or was skipped and why (for example "learning", "deploy window", "no login routes configured or recognised").
6. **Applications → Overview → Needs attention.** Lists services with `asserted_identity`, `route_overflow`, `trace_drops`, or `not_reporting`.
7. With **Trace requests without code changes** built in: discovered services turn "T1·eBPF" within a few minutes and their Endpoints tab fills. If they stay T0, read `/var/lib/obsidianwatch/obi/obi.log` (kernel without BTF, agent not root) and check the agent log for `request tracing (OBI) running`.
8. Service page → **Traces** tab.
9. Service page → **Code** tab (optional): link the repository and branch the service is built from to see its code findings checked against what this service runs. Error and slow traces appear, plus about 1 % of ordinary ones.

Agent log lines that help:

| Log line | Meaning |
|---|---|
| `app monitoring: no user_hash_key configured; user identifiers will not be sent` | `OW_SECRET_KEY` was empty when the agent was built |
| `app monitoring: could not pull service settings; using build configuration` | the agent cannot reach `/api/v1/app/agent-config`; retried every 30 s |
| `app batch rejected, dropping status=403` | the backend does not know this agent, or the `agent_id` does not match the certificate |
| `app batch rejected, dropping status=413` | a batch section exceeded the backend's cap |
| `host sensor running mode=poll` | the agent is not root or the proc connector is unavailable |

Known gaps that affect verification today are listed in [capability.md](capability.md) section 15. Request tracing with eBPF has been tested with a stand-in for the OBI binary only, not with OBI on a real kernel.

## 7a. Monitor the ObsidianWatch management server itself

The management server (Go) is instrumented with the official OpenTelemetry Go SDK (`go.opentelemetry.io/otel` v1.46.0, `otlptracehttp`, `otelhttp` v0.71.0; the newest release that builds with Go 1.25) plus the ObsidianWatch security helper, so it reaches **Tier 2**. Code: `management/backend/internal/telemetry`. It is off until an OTLP endpoint is set:

| Variable | Meaning |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Base URL of the agent's receiver, e.g. `http://127.0.0.1:4318` (traces go to `/v1/traces`), or `unix:///run/obsidianwatch/otlp.sock` |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Full traces URL, used as given (overrides the above) |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | Full URL for the security events (default: the base URL + `/v1/logs`, or the traces URL with `/v1/traces` replaced) |
| `OTEL_SERVICE_NAME` | Default `obsidianwatch-management` |
| `OTEL_RESOURCE_ATTRIBUTES` | `deployment.environment=prod`; `vcs.*` keys are passed on |
| `OW_VERSION`, `OW_BUILD_COMMIT` | `service.version` and the commit (`vcs.ref.head.revision`); without `OW_BUILD_COMMIT` the commit Go stamped into the binary is used when the build had git metadata |
| `OTEL_SDK_DISABLED=true` | Off |

What it records: a server span per API request, with the query string (`url.query`) and, for JSON POST/PUT/PATCH bodies up to 32 KiB, the body (`ow.request.body`), so **Endpoints** lists each route's parameters and its **Review** page can show captured requests once an administrator has reviewed the route (values are sampled only after review, never credential-like ones; `/auth/*` bodies, which carry passwords, are never reported); method, route template from the router, e.g. `/api/v1/app/services/{id}`; unknown API paths are `(unmatched)`; status; peer and forwarded client address); a client span per database statement made while serving a request (operation, table, statement text, which the agent turns into a value-free fingerprint only when the service's statement setting is on); a job span per background run (`detection.pass`, `detection.devops`, `code-scan.<kind>`, `runtime-inventory.index`, `deployed-commit.sweep`), shown on the Jobs tab; a client span per outgoing HTTP call from any client (`http.DefaultTransport` is wrapped at start-up; the DevOps, AWS and default clients wrap their own), joined to the request or job that made it or as a trace of its own: GitHub, GitLab, Azure DevOps, cloud APIs, NVD, threat-intel feeds, AI providers, IP enrichment and VirusTotal all become dependencies. No trace headers are sent to those third parties; an `exception` event with the Go stack when a handler panics, and an error status for 5xx answers. WebSocket upgrades are not traced. Spans go out as OTLP/HTTP protobuf through the SDK batch processor (every 2 s or 512 spans, queue 8 192, dropped when full); a trace keeps at most 200 child spans.

Security events (Tier 2), sent as OTLP log records (JSON, `helper_version` `ow-go/1`) with the trace and span of the request, route and client address:

| Event | Raised when |
|---|---|
| `auth.login` | sign-in succeeds or fails (`outcome`, `method=password`, `reason=invalid_credentials`) |
| `ratelimit.hit` | the login limiter (`limit_name=login`) or the AI request limiter (`limit_name=ai`) refuses a request |
| `authz.deny` | `adminOnly` (`policy=admin_only`) or the viewer read-only guard (`policy=read_only_role`) answers 403 |
| `admin.action` | every audited change the handlers record (`action` = the audit action, e.g. `create_user`, `response_isolate`; `target_type`/`target_id` from the audit target). The generic `api:<method>` audit rows are not repeated |
| `data.export` | event export, collected-file download, SBOM download, fleet-hunt CSV, agent package download (`object_type`, `format`) |

User names, object ids and sessions are pseudonymised by the agent with the organisation key unless the service is set to cleartext users.

**Docker, step by step** (`docker-compose.yml` already passes the variables and mounts the host's `/run/obsidianwatch/otlp` at `/run/ow-otlp` in the container; not under `/run/obsidianwatch`, because in the Alpine image `/var/run` is `/run` and the restart-signal volume at `/var/run/obsidianwatch` would hide it):

1. On the Docker host, install an agent built with the app-server profile and **Unix socket path** `/run/obsidianwatch/otlp/otlp.sock` (Agent builder).
2. In the `.env` next to `docker-compose.yml` add `OTEL_EXPORTER_OTLP_ENDPOINT=unix:///run/ow-otlp/otlp.sock` (the path inside the container), optionally `OW_ENVIRONMENT=prod` and `OW_BUILD_COMMIT=<git rev-parse HEAD of the build>`.
3. `docker compose up -d mgmt-api`. The management log shows `telemetry: OpenTelemetry SDK exporting traces`; within two minutes **Applications → Services** lists `obsidianwatch-management` at Tier 1, and at Tier 2 after the first security event (any sign-in).

**If the service does not appear**, check in this order:

1. `docker compose exec mgmt-api env | grep OTEL` shows the endpoint, and `docker compose exec mgmt-api ls -l /run/ow-otlp/` lists `otlp.sock`. If empty, `.env` was not picked up; run `docker compose up -d mgmt-api` again (a restart does not reread `.env`).
2. `docker compose logs mgmt-api | grep telemetry`. `OpenTelemetry SDK exporting traces` means it is on; `first export accepted by the receiver` means the agent took the data. `export failing ... no such file or directory` means the socket is not in the mounted directory (agent built without the socket, or with another path); `connection refused` means the agent is not running.
3. On the host, `ls -l /run/obsidianwatch/otlp/` must show `otlp.sock`, and `journalctl -u obsidianwatch-agent | grep "otlp receiver listening"` must list it.
4. The image must be rebuilt after updating the code: `docker compose build mgmt-api && docker compose up -d mgmt-api`.

The directory is mounted (not the socket file) so an agent restart, which recreates the socket, does not break it.

**Why a socket.** The management container cannot reach the host agent's loopback receiver. Build the host's agent with the OTLP Unix socket (Agent builder, "Unix socket path" `/run/obsidianwatch/otlp/otlp.sock`), mount that directory into the management container (docker-compose mounts it at `/run/ow-otlp`), and set `OTEL_EXPORTER_OTLP_ENDPOINT=unix:///run/ow-otlp/otlp.sock`. On a host install without Docker, `http://127.0.0.1:4318` is enough. The service then appears as `obsidianwatch-management` at Tier 2 (sdk `opentelemetry 1.46.0`), bound to the server process (identity verified), with its database as a dependency. Linking this repository to it (Code tab) checks findings against the exact commit when `OW_BUILD_COMMIT` is set at build time.

**SDK version.** OpenTelemetry Go v1.47 and later need Go 1.26. To move up, raise the Go version in `go.mod` and in `management/docker/Dockerfile` first, then run `tools/fetch-otel-sdk.ps1` (or `.sh`) with the new versions. The repository keeps only `go.mod`/`go.sum`; `vendor/` is git-ignored and the Docker build downloads the modules.

## 8. Disable or uninstall

- **Stop application monitoring but keep the agent:** rebuild the agent with the profile unticked and reinstall it. There is no runtime switch; the configuration is compiled in.
- **Stop one application:** remove its OpenTelemetry exporter configuration. The service stays in the console with its history. APP-X06 may fire if its process keeps running after real traffic stopped, and APM-O05 if it was one of several instances.
- **Uninstall the agent:** use the uninstall command in section 3. The receiver stops and the Unix socket file is removed.
- **Reinstall:** a reinstall enrolls a new agent identity. The old agent record is marked superseded and hidden from agent lists. Instances recorded under the old agent id stay in the service history; rules that need the host to be reporting (APM-O05, APP-X06) skip them because the old agent no longer reports.

Data already stored is removed by retention only (section 7.3 of [capability.md](capability.md)). There is no "delete service" action: a discovered service reappears at the next discovery round while its process listens, and removing it would also stop the host rules (APP-H01–H11) that watch its processes. Lists rank services instead (instrumented first, then platform software, then the rest).
