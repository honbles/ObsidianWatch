# Application monitoring: .NET

Connect an ASP.NET Core application to the local ObsidianWatch agent with the OpenTelemetry .NET SDK.

Check your setup with `samples/app/verify.sh` (it runs the sample against the agent's receiver and prints what was recorded).

## Prerequisites

- An ObsidianWatch agent built with the app-server profile on the same host ([deployment.md](deployment.md)), listening on `127.0.0.1:4318`, OTLP over HTTP.
- .NET 8 or later for current OpenTelemetry packages (1.9.0 and later target `net8.0`; 1.14 targets `net8.0` and `net10.0`). The sample uses 1.9.0. If your solution pins `Microsoft.Extensions.*` 8.0 packages centrally, stay on a 1.9 to 1.11 release, or newer OpenTelemetry versions can fail restore with a package downgrade error (NU1605).

## Steps

1. Add the packages:

```
dotnet add package OpenTelemetry.Extensions.Hosting
dotnet add package OpenTelemetry.Exporter.OpenTelemetryProtocol
dotnet add package OpenTelemetry.Instrumentation.AspNetCore
```

Add `OpenTelemetry.Instrumentation.Http` and `OpenTelemetry.Instrumentation.SqlClient` (or the instrumentation for your database client) for dependencies.

2. Configure tracing in `Program.cs`:

```csharp
using OpenTelemetry.Exporter;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

var resource = ResourceBuilder.CreateDefault()
    .AddService("orders-api", serviceVersion: "1.4.2")
    .AddAttributes(new[] { new KeyValuePair<string, object>("deployment.environment.name", "production") });

builder.Services.AddOpenTelemetry().WithTracing(t => t
    .SetResourceBuilder(resource)
    .AddAspNetCoreInstrumentation(o => o.RecordException = true)
    .AddHttpClientInstrumentation()
    .AddOtlpExporter(o =>
    {
        o.Endpoint = new Uri("http://127.0.0.1:4318/v1/traces");
        o.Protocol = OtlpExportProtocol.HttpProtobuf;
    }));
```

Notes:
- `OtlpExportProtocol.HttpProtobuf` is required: the .NET exporter defaults to gRPC, which the receiver does not accept.
- With an explicit `Endpoint` the .NET exporter does not append the signal path. Give the full `/v1/traces` (and `/v1/logs`, `/v1/metrics` for the other exporters).
- `RecordException = true` adds the `exception` span event; without it there are no error groups and no exception types for APP-A09.
- The environment variables `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf` work as well when you do not set the values in code.

## What is captured automatically

| Data | Source | Notes |
|---|---|---|
| Routes, RED, status classes | ASP.NET Core server spans with `http.route` | minimal APIs report the template with constraints, for example `/orders/{orderId:int}` |
| Query-string field names, injection signatures | `url.query` | names only leave the host |
| Dependencies | HttpClient and database client spans | |
| Error groups | `exception` events when `RecordException = true` | .NET frames are parsed only when they carry `in <file>:line <n>` (PDB files deployed). Without line information the group is keyed on exception type and route only. `System.` and `Microsoft.` frames count as library frames |
| Client address | `client.address` / `network.peer.address` (older SDKs `net.sock.peer.addr`) | the sample also sets `client.address` explicitly from `HttpContext.Connection.RemoteIpAddress` |
| Instance identity | the `dotnet` process (or the app host executable) | verified |

## What needs manual work

- **Exception types for APP-A09.** Exception type names are recorded as the full type name. Names containing `injection`, or `sql` with `syntax`, `grammar` or `parse`, count as injection-class. `Microsoft.Data.SqlClient.SqlException` does not match; the agent's parameter-value signatures still work for query-string attacks.
- **Request body fields.** No .NET helper exists. Set `Activity.Current?.SetTag("ow.request.body", JsonSerializer.Serialize(parsedBody))` on the server activity after model binding (JSON object, at most 32 KiB).
- **Database statements.** `OpenTelemetry.Instrumentation.SqlClient` (beta) with `SetDbStatementForText = true` (versions up to 1.9; later versions record the text by default) gives `db.statement`, which the agent fingerprints. Entity Framework Core on SQL Server goes through SqlClient; the EF in-memory provider produces no database spans.
- **Cookie authentication.** ASP.NET Core Identity answers unauthenticated and forbidden requests with a redirect (302) to the login or access-denied page, not 401/403, so a status-code middleware sees no denials. Override `RedirectToLogin` and `RedirectToAccessDenied` in your `CookieAuthenticationEvents` and call `AuthzDenied` there. Failed logins in the default Identity UI return 200, so APP-A01 does not count them; the helper's `Login("failure", ...)` events still fill the Security tab.
- **Request context.** The route template of the current request is `(HttpContext.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText`; resolve the helper with `HttpContext.RequestServices.GetService<OwSecurity>()` when you do not want to change constructors.
- **Scheduled jobs.** Start a root activity per run with the tag `ow.job.name` set to a stable name; set its status to error on failure.
- **Metrics.** Add `.WithMetrics(m => m.AddRuntimeInstrumentation().AddOtlpExporter(...))` with `HttpProtobuf` and `/v1/metrics`. Metrics with names starting `dotnet.` or `process.runtime.` are stored and shown on the Metrics tab, but no .NET metric feeds the runtime summary or APM-O07.

## Security helper (optional, Tier 2)

`samples/app/dotnet/OwSecurity.cs` writes helper events through `ILogger`. Register the OpenTelemetry logging provider with `ParseStateValues = true` so the helper's attributes (`event.name`, `route`, ...) are exported:

```csharp
builder.Logging.AddOpenTelemetry(o =>
{
    o.SetResourceBuilder(resource);
    o.IncludeFormattedMessage = false;
    o.ParseStateValues = true;
    o.IncludeScopes = false;
    o.AddOtlpExporter(x => { x.Endpoint = new Uri("http://127.0.0.1:4318/v1/logs"); x.Protocol = OtlpExportProtocol.HttpProtobuf; });
});
builder.Services.AddSingleton<OwSecurity>();
// in a handler:
sec.Login("failure", user, client, "/login");
sec.DataExport("orders", user, "csv", "1200", "/export", client);
```

`OwSecurity` (helper version `dotnet-2`) has one method per event name; see the table in [capability.md](capability.md) section 4.3.

Only records with a recognised `event.name` are used; every other log record is dropped by the agent. The events fill the Security tab and make the service Tier 2. No rule reads them today; APP-A01 counts 401/403 responses.

## Verify

1. Send requests and wait one to two minutes.
2. **Applications → Services**: the service, tier T1.
3. Service page → **Endpoints**: route templates.
4. Service page → **Instances**: **verified**.

Sample: `cd samples/app/dotnet && OW_ALLOW_VULN_DEMO=1 dotnet run` (port 5004), then `python3 ../attack_sim.py --base http://127.0.0.1:5004`. The sample is intentionally vulnerable and must never be deployed.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Nothing arrives | protocol left at gRPC; endpoint without `/v1/traces`; the exporter is registered after the host started |
| 404 in the exporter's self-diagnostics | the path is missing or wrong (`/v1/traces`, `/v1/logs`, `/v1/metrics`) |
| Instance **asserted** | container with its own network namespace: use the Unix socket ([deployment.md](deployment.md)); the .NET OTLP exporter has no Unix-socket transport, so a forwarder is needed |
| Errors grouped too coarsely | stack frames without line information; deploy PDB files |
| Security tab empty | `ParseStateValues` not set, or the logs exporter is not `HttpProtobuf` with `/v1/logs` |
