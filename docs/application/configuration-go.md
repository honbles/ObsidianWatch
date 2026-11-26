# Application monitoring: Go

Connect a Go service (`net/http`, or any router on top of it) to the local ObsidianWatch agent with the official OpenTelemetry Go SDK, and reach Tier 2 with the Go security helper.

Verified: the sample in `samples/app/go` (Go 1.25, OpenTelemetry Go v1.46.0, `otelhttp` v0.71.0) ran against the agent's real Linux receiver with `samples/app/verify.sh`: identity verified with pid and executable, sdk `opentelemetry 1.46.0`, route templates (`/orders/{orderId}`), 401s on `/login`, the injection and command-injection signatures, the exception type, and 32 security events (`auth.login`, `input.rejected`). The ObsidianWatch management server uses the same pattern (`management/backend/internal/telemetry`) and reaches Tier 2 in production.

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
6. Record the client address on the server span (`client.address`, `network.peer.address`); the sample's `clientAddress` middleware does it. Behind a proxy, use the address your proxy reports.
7. Raise security events where your code decides, with the request context so the event joins the trace:
   ```go
   owsecurity.Login(r.Context(), "failure", user, clientIP(r), "/login", "password", "invalid_credentials")
   owsecurity.AuthzDenied(r.Context(), "invoice", "delete", user, "/invoices/{id}", clientIP(r), "owner_only")
   owsecurity.DataExport(r.Context(), "orders", user, "csv", 1200, "/export", clientIP(r))
   ```
   All eleven event names have a function; see [capability.md](capability.md) section 4.3.
8. Record errors on the server span: `span.RecordError(err, trace.WithStackTrace(true))` and `span.SetStatus(codes.Error, ...)`. The exception type is the Go type (`*main.SqlSyntaxError`); Go stack traces are parsed into frames.
9. Background jobs: start a root span and set `ow.job.name` (they show on the Jobs and queues tab).

**In a container**, mount the agent's socket directory and use `unix:///path/otlp.sock`: pass `otlptracehttp.WithHTTPClient` with a client that dials the socket, `WithEndpoint("localhost")`, `WithURLPath("/v1/traces")` and `WithInsecure()`; `owsecurity.Init("unix:///path/otlp.sock/v1/logs", attrs)` handles the socket itself. `management/backend/internal/telemetry/telemetry.go` (`exporterOptions`) is a working example. Do not mount it under a directory that another volume shadows (see [deployment.md](deployment.md) section 7a).

## What each part gives you

| Part | Result |
|---|---|
| SDK + `otelhttp` | Tier 1: endpoints, latency, errors, traces, dependencies (with `otelhttp.NewTransport` on outgoing clients) |
| `owpayload` | parameter names per route; after an administrator reviews a route, captured requests with allowed values |
| `owsecurity` | Tier 2: the Security tab, sign-in and denial events joined to traces |

`owsecurity` posts OTLP/HTTP JSON itself (standard library plus `go.opentelemetry.io/otel/trace`), batched every second; a full queue drops events and counts them (`owsecurity.Stats()`), so a call never blocks a request. The official logs SDK (`go.opentelemetry.io/otel/sdk/log` with `otlploghttp`) works too if every record carries the `event.name` attribute; it was not run here.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Service missing | exporter endpoint wrong; for containers the socket is not mounted (check with `ls` inside the container) |
| Every request on one route `(unmatched)` | `http.route` not set (step 5) |
| Stays Tier 1 | no security event sent yet, or the helper's `service.name`/environment differ from the traces' |
| Endpoints show no parameters | `owpayload` outside `otelhttp`, body not JSON, or the path is in the skip list |
| Instance shows the wrong process | a Collector sits between the app and the agent |
