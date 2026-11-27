# Application monitoring: Go

Connect a Go service (`net/http`, or any router on top of it) to the local ObsidianWatch agent with the official OpenTelemetry Go SDK, and reach Tier 2 with the Go security helper.

Verified: the sample in `samples/app/go` (Go 1.25, OpenTelemetry Go v1.46.0, `otelhttp` v0.71.0) ran against the agent's real Linux receiver with `samples/app/verify.sh`: identity verified with pid and executable, sdk `opentelemetry 1.46.0`, route templates (`/orders/{orderId}`), 401s on `/login`, the injection and command-injection signatures, the exception type, and 32 security events (`auth.login`, `input.rejected`). The ObsidianWatch management server uses the same pattern (`management/backend/internal/telemetry`) and reaches Tier 2 in production. A PostgreSQL order service built step by step from this page (otelsql v0.44.0, all eleven steps) ran end to end through the server: route templates, fingerprinted statements per operation and table including a failing one, error groups, the commit, and the login, rate-limit, authz, admin, export and access events.

## Prerequisites

- An ObsidianWatch agent built with the app-server profile on the same host ([deployment.md](deployment.md)), listening on `127.0.0.1:4318` (or a Unix socket for containers).
- Go 1.22 or later for the sample's routing (`http.ServeMux` patterns). OpenTelemetry Go v1.47 and later need Go 1.26; on Go 1.25 use v1.46.0 with `otelhttp` v0.71.0 (the contrib minor version is the core minor plus 25).

## Steps

1. Add the modules:
   ```
   go get go.opentelemetry.io/otel@v1.46.0 go.opentelemetry.io/otel/sdk@v1.46.0 \
          go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@v1.46.0 \
          go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp@v0.71.0
   ```
2. Copy `samples/app/go/owsecurity` and `samples/app/go/owpayload` into your module (change the import path).
3. At start-up, create the tracer provider and the helper with the **same** `service.name` and environment (see `samples/app/go/main.go`):
   ```go
   endpoint := "http://127.0.0.1:4318"
   attrs := map[string]string{"service.name": "orders-api", "deployment.environment.name": "prod", "service.version": version}
   exp, _ := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint+"/v1/traces"))
   res, _ := resource.New(ctx, resource.WithTelemetrySDK(), resource.WithAttributes(kv(attrs)...))
   tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(exp))
   otel.SetTracerProvider(tp)
   otel.SetTextMapPropagator(propagation.TraceContext{})
   stopSec := owsecurity.Init(endpoint+"/v1/logs", attrs)
   defer stopSec()
   defer tp.Shutdown(context.Background())
   ```
4. Wrap the router: `otelhttp.NewHandler(owpayload.Middleware("/login", "/auth/")(mux), "http.server")`. `owpayload` must be inside `otelhttp` so the server span is in the request context. List the paths whose bodies carry passwords or tokens; they are never reported.
5. Name spans after the route template. `otelhttp` v0.71 reads `http.route` from the `http.ServeMux` pattern (Go 1.22+) when the middleware between it and the mux passes the request on unchanged, but the span name stays the operation name. The sample registers each route through a small `handle(mux, "GET /orders/{orderId}", fn)` that sets both the span name and `http.route`, which works whatever sits in between. With gin, chi or gorilla/mux use `otelgin`, `otelchi` or `otelmux`.
6. Record the client address on the server span (`client.address`, `network.peer.address`); the sample's `clientAddress` middleware does it. Behind a reverse proxy, read `X-Forwarded-For` only when the connection comes from the proxy itself (a private or loopback address), and take the right-most public entry. Otherwise any client can write its own address. `ClientIP` in `management/backend/internal/telemetry/clientip.go` is a working example.
7. Raise security events where your code decides, with the request context so the event joins the trace:
   ```go
   owsecurity.Login(r.Context(), "failure", user, clientIP(r), "/login", "password", "invalid_credentials")
   owsecurity.AuthzDenied(r.Context(), "invoice", "delete", user, "/invoices/{id}", clientIP(r), "owner_only")
   owsecurity.DataExport(r.Context(), "orders", user, "csv", 1200, "/export", clientIP(r))
   ```
   All eleven event names have a function; see [capability.md](capability.md) section 4.3.
8. Record errors on the server span: `span.RecordError(err, trace.WithStackTrace(true))` and `span.SetStatus(codes.Error, ...)`. The exception type is the Go type (`*main.SqlSyntaxError`); Go stack traces are parsed into frames.
9. Background jobs: start a root span and set `ow.job.name` (they show on the Jobs and queues tab).
10. Database queries: open the database through [`github.com/XSAM/otelsql`](https://github.com/XSAM/otelsql) instead of `sql.Open`:
    ```go
    db, err := otelsql.Open("postgres", dsn, otelsql.WithAttributes(semconv.DBSystemPostgreSQL))
    ```
    otelsql v0.44.0 is the release for OpenTelemetry Go v1.46.0. Also pass `otelsql.WithSpanOptions(otelsql.SpanOptions{OmitConnResetSession: true, OmitConnectorConnect: true, OmitRows: true})`: those connection and row spans carry no statement and only add noise to traces (the agent leaves them out of the Queries tab either way).
    Each query becomes a span with the database system and the statement (`db.statement`). When a span has no `db.operation.name` or `db.collection.name`, the agent reads the operation and table from the statement; it takes the keyword and table name, never a value. The Queries tab then lists calls, errors and latency per operation and table. With statement fingerprints on (the default), each statement shows with its values removed on the host. To make database spans by hand, set `db.system`, `db.operation.name`, `db.collection.name` and `db.query.text` on a client span; `management/backend/internal/telemetry/sql.go` does this. Both the older (`db.statement`, `db.system`) and current (`db.query.text`, `db.system.name`) attribute names are read.
11. The commit and repository: set the resource attributes `vcs.ref.head.revision` (the full commit) and `vcs.repository.url.full` (the repository URL) next to `service.name`, for example from build flags (`-ldflags "-X main.commit=$(git rev-parse HEAD)"`). The Code tab then shows the findings of exactly that commit, and links the service to its repository on a connected code platform. Two cases need nothing: a binary run from a git clone on the host (the agent reads `.git`), and a container image with the labels `org.opencontainers.image.revision` and `org.opencontainers.image.source`, which most CI image builds add. Section 1.2 of [capability.md](capability.md) lists the sources in order.

**In a container**, mount the agent's socket directory and use `unix:///path/otlp.sock`: pass `otlptracehttp.WithHTTPClient` with a client that dials the socket, `WithEndpoint("localhost")`, `WithURLPath("/v1/traces")` and `WithInsecure()`; `owsecurity.Init("unix:///path/otlp.sock/v1/logs", attrs)` handles the socket itself. `management/backend/internal/telemetry/telemetry.go` (`exporterOptions`) is a working example. Do not mount it under a directory that another volume shadows (see [deployment.md](deployment.md) section 7a).

## What each part gives you

| Part | Result |
|---|---|
| SDK + `otelhttp` | Tier 1: endpoints, latency, errors, traces, dependencies (with `otelhttp.NewTransport` on outgoing clients) |
| `owpayload` | parameter names per route; after an administrator reviews a route, captured requests with allowed values |
| `owsecurity` | Tier 2: the Security tab, sign-in and denial events joined to traces |
| `otelsql` | the Queries tab: calls, errors and latency per operation and table, with the statement (values removed) |
| `vcs.*` attributes | the Code tab shows the findings of the commit that runs |

Every kept request, captured payload, error and job run is also an event on **Detect → Events**, with its spans or payload. Choose the application in the picker to search them. **Ordinary traces kept (%)** in the service's settings decides how many requests are kept (1% by default; errors, slow and security-relevant requests always); see [configuration-platform.md](configuration-platform.md).

`owsecurity` posts OTLP/HTTP JSON itself (standard library plus `go.opentelemetry.io/otel/trace`), batched every second; a full queue drops events and counts them (`owsecurity.Stats()`), so a call never blocks a request. The official logs SDK (`go.opentelemetry.io/otel/sdk/log` with `otlploghttp`) works too if every record carries the `event.name` attribute.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Service missing | exporter endpoint wrong; for containers the socket is not mounted (check with `ls` inside the container) |
| Every request on one route `(unmatched)` | `http.route` not set (step 5) |
| Stays Tier 1 | no security event sent yet, or the helper's `service.name`/environment differ from the traces' |
| Endpoints show no parameters | `owpayload` outside `otelhttp`, body not JSON, or the path is in the skip list |
| Instance shows the wrong process | a Collector sits between the app and the agent |
| Queries tab empty | the database is not opened through `otelsql` (step 10), or the spans carry no database system |
| Queries show no statement | the service is set to names only (Settings → Database); rows recorded before statements were on stay without one until they leave the range. A brand-new service also sends no statements until the agent's next settings pull, at most 5 minutes after the service first appears |
| Queries list an operation `SQL` with no table | an agent older than this release counts otelsql's connection and row spans; update the agent, or omit those spans (step 10) |
| Code tab says "Commit not reported yet" | no instance reports `vcs.ref.head.revision` and none runs from a git clone or a labelled image (step 11) |
| Client address is your proxy's | the proxy does not pass the address, or the service trusts `X-Forwarded-For` from the wrong peer (step 6) |
