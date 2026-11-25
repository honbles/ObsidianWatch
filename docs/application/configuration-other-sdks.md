# Application monitoring: other OpenTelemetry SDKs (Go, Ruby, PHP, Rust, Collector)

The receiver speaks plain OTLP/HTTP, so any OpenTelemetry SDK that can export OTLP over HTTP with protobuf or JSON can send to it. Nothing in this page has been run against the receiver; it follows from the decoder's allowlists. Java, .NET, Python and Node have their own pages.

## Requirements for any SDK

| Requirement | Why |
|---|---|
| Export OTLP over HTTP (`http/protobuf` or `http/json`) to `http://127.0.0.1:4318` | gRPC is not accepted |
| Paths `/v1/traces`, `/v1/logs`, `/v1/metrics` | other paths return 404 |
| `Content-Type: application/x-protobuf` or `application/json`; optional gzip | other types return 415 |
| Resource `service.name`, `deployment.environment.name`, `service.version` | grouping, deploy detection, version compare |
| Server spans of kind SERVER with `http.route`, `http.request.method`, `http.response.status_code` | routes and RED; no `http.route` means `(unmatched)` |
| Client spans of kind CLIENT with `db.system` / `server.address` / `peer.service` / `messaging.system` | dependencies |
| Exceptions as span events named `exception` with `exception.type` | error groups, APP-A09 |
| The SDK process connects to the agent itself | the agent identifies the sending process; a Collector in between becomes the identified sender |

Both current (`http.request.method`, `url.query`, `client.address`, `network.peer.address`, `db.operation.name`, `db.collection.name`, `db.query.text`) and older semantic conventions (`http.method`, `http.status_code`, `http.target`, `http.url`, `net.peer.ip`, `net.sock.peer.addr`, `db.operation`, `db.sql.table`, `db.statement`) are read. See [capability.md](capability.md) section 4 for the full allowlist.

## Go

Exporter: `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` with `otlptracehttp.WithEndpoint("127.0.0.1:4318")` and `otlptracehttp.WithInsecure()`, or `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318`. Routes: `otelhttp` sets `http.route` only when you pass it (for example with `otelhttp.WithRouteTag` or a router-specific instrumentation such as `otelgin`, `otelmux`, `otelchi`).

Limits for Go:
- Stack traces in Go format are not parsed. Error groups are keyed on exception type and route only.
- Go runtime metrics named `go.*` are not on the allowlist and are dropped; older `process.runtime.go.*` names are stored but not summarised.

## Ruby, PHP, Rust and others

Use the SDK's OTLP HTTP exporter with `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf` and `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318`. Their stack trace formats are not parsed (groups by type and route), and their runtime metrics are not on the allowlist.

## OpenTelemetry Collector

A Collector on the same host can forward to the agent with the `otlphttp` exporter (`endpoint: http://127.0.0.1:4318`). Two consequences:

- every service sent through the Collector is bound to the Collector process: it shows as **verified**, but the instance, pid, executable and container are the Collector's, not the application's. Host rules then watch the Collector's descendants, not the application's;
- the Collector must not listen on 127.0.0.1:4318 itself.

Prefer sending from the application directly.

## Helpers

There are no helpers for these languages. The conventions are simple to reproduce:

- **Body fields**: set the string attribute `ow.request.body` on the server span to a JSON object of the parsed body (at most 4 KiB in practice, defect D2).
- **Jobs**: a root span (or CONSUMER span) with the attribute `ow.job.name`.
- **Security events**: an OTLP log record with attribute `event.name` set to one of `auth.login`, `auth.mfa`, `authz.deny`, `input.rejected`, `ssrf.blocked`, `deserialization.blocked`, `ratelimit.hit`, `admin.action`, `data.export`, `session.anomaly`, `data.access`, and the fields from [capability.md](capability.md) section 4.3 (`outcome`, `user`, `route`, `client.address`, ...). Pass the trace id on the record to keep the request's trace.

## Verify

Same as for any runtime: **Applications → Services**, the **Endpoints** tab, and **Instances** (verified). See [deployment.md](deployment.md) section 7.
