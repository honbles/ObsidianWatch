# Application Monitoring - .NET setup

Send traces from a .NET application to the local agent and, optionally, security events.

## Before you start
1. The host runs the ObsidianWatch agent built with the **app-server profile** (Agent Builder, "Enable the app-server profile"). The agent then listens on `127.0.0.1:4318` (OTLP over HTTP). gRPC is not supported.
2. The application and the agent run on the same host (or the application uses the agent's Unix socket from a container, see `agent-otlp.md`).
3. You change **no** host or deployment attribute. The agent works out which host, process and container are sending, and discards any `host.*`, `container.*` and `k8s.*` you set.

## What the sample shows
`samples/app/dotnet` is a small application with the routes `/health`, `POST /login`, `/orders/{id}`, `/search` and `/debug/exec`. It is **intentionally vulnerable**: it refuses to start unless `OW_ALLOW_VULN_DEMO=1`, binds `127.0.0.1` only, and must never be deployed. `samples/app/attack_sim.py` drives it through normal traffic, a login brute force, injection attempts, a request burst and a command-execution request, so you can watch the rules fire (`rules.md`: A01, A09, A13, H01, X02). Rules are observe-only until you switch a service to enforce.

## 1. Install
```
dotnet add package OpenTelemetry.Extensions.Hosting
dotnet add package OpenTelemetry.Exporter.OpenTelemetryProtocol
dotnet add package OpenTelemetry.Instrumentation.AspNetCore
```

## 2. Configure
```csharp
builder.Services.AddOpenTelemetry().WithTracing(t => t
    .SetResourceBuilder(ResourceBuilder.CreateDefault().AddService("orders-api")
        .AddAttributes(new[] { new KeyValuePair<string, object>("deployment.environment.name", "production") }))
    .AddAspNetCoreInstrumentation(o => o.RecordException = true)
    .AddOtlpExporter(o => { o.Endpoint = new Uri("http://127.0.0.1:4318/v1/traces"); o.Protocol = OtlpExportProtocol.HttpProtobuf; }));
```
Set `OtlpExportProtocol.HttpProtobuf` and the full `/v1/traces` path: with an explicit endpoint the .NET exporter does not append it. The default protocol is gRPC, which the agent does not accept.

## 3. Security helper
Add `OwSecurity.cs`, register the OpenTelemetry logging provider (see `Program.cs`, with `ParseStateValues = true`), inject `OwSecurity` and call for example `sec.Login("failure", user, client, "/login")`.

## Run the sample
```
cd samples/app/dotnet
OW_ALLOW_VULN_DEMO=1 dotnet run               # port 5004
python3 ../attack_sim.py --base http://127.0.0.1:5004
```

> **Not verified.** The .NET sample was written but not built or run in the environment used to build ObsidianWatch (no .NET SDK, NuGet unreachable). Run it once with `samples/app/verify.sh` before relying on it, and tell us what differs.

## Checking it works
In the console open **Applications, Services**. Within about a minute you should see the service, its environment, and each route as a **template** (for example `/orders/{id}`), never the raw URL. The instance should say **verified** with the process executable. If it says **asserted**, the agent could not match the sender to a local process (container with its own network namespace, or an agent without the required privilege): use the Unix socket or run the agent in the host pid namespace.

## What is never sent
Request and response bodies, query strings, headers and parameter values. Only route templates, status codes, timings, exception type names and the security-event fields below. Identifiers you pass to the helper (user, object id) are hashed by the agent before they leave the host.

## Security helper (optional)
The helper emits events the rules read: `auth.login`, `auth.mfa`, `authz.deny`, `input.rejected`, `ratelimit.hit`, `data.access`, `data.export`, `admin.action`, `session.anomaly`. Call it where your code already makes the decision (login result, validation rejection, rate limiter). It never sends bodies or parameter values. Without it you still get traces, route health and exception-based rules; with it you get login-failure and rejection signals that do not depend on framework error types.

## Proof
This language has not been run against the receiver yet. Use `samples/app/verify.sh` to check it.
