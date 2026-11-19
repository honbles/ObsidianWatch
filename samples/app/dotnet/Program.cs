// ObsidianWatch sample application - .NET (minimal API + OpenTelemetry).
// INTENTIONALLY VULNERABLE (fake SQL layer, debug shell endpoint). Refuses to start unless
// OW_ALLOW_VULN_DEMO=1 and binds 127.0.0.1 only. Never deploy it. See docs/app/setup-dotnet.md.
using System.Diagnostics;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

if (Environment.GetEnvironmentVariable("OW_ALLOW_VULN_DEMO") != "1")
{
    Console.Error.WriteLine("This sample is intentionally vulnerable. Set OW_ALLOW_VULN_DEMO=1 to run it (binds 127.0.0.1 only).");
    return 1;
}
var endpoint = Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT") ?? "http://127.0.0.1:4318";
var resource = ResourceBuilder.CreateDefault().AddService(Environment.GetEnvironmentVariable("OTEL_SERVICE_NAME") ?? "sample-dotnet", serviceVersion: "1.0.0")
    .AddAttributes(new[] { new KeyValuePair<string, object>("deployment.environment.name", "demo") });

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://127.0.0.1:{Environment.GetEnvironmentVariable("PORT") ?? "5004"}");
builder.Services.AddOpenTelemetry().WithTracing(t => t
    .SetResourceBuilder(resource)
    .AddAspNetCoreInstrumentation(o => o.RecordException = true)
    .AddOtlpExporter(o => { o.Endpoint = new Uri(endpoint + "/v1/traces"); o.Protocol = OtlpExportProtocol.HttpProtobuf; }));
builder.Logging.AddOpenTelemetry(o =>
{
    o.SetResourceBuilder(resource);
    o.IncludeFormattedMessage = false;
    o.ParseStateValues = true;      // exports the helper's attributes (event.name, route, ...)
    o.IncludeScopes = false;
    o.AddOtlpExporter(x => { x.Endpoint = new Uri(endpoint + "/v1/logs"); x.Protocol = OtlpExportProtocol.HttpProtobuf; });
});
builder.Services.AddSingleton<OwSecurity>();
var app = builder.Build();

string Client(HttpContext c) { var a = c.Connection.RemoteIpAddress?.ToString() ?? ""; Activity.Current?.SetTag("client.address", a); return a; }
var users = new Dictionary<string, string> { ["alice"] = "correct-horse" };

app.MapGet("/health", () => Results.Json(new { ok = true }));
app.MapPost("/login", (LoginBody b, HttpContext c, OwSecurity sec) =>
{
    var client = Client(c);
    if (users.TryGetValue(b.User ?? "", out var pw) && pw == b.Password && !string.IsNullOrEmpty(pw))
    { sec.Login("success", b.User, client, "/login"); return Results.Json(new { token = "demo-token" }); }
    sec.Login("failure", b.User, client, "/login");
    return Results.Json(new { error = "invalid credentials" }, statusCode: 401);
});
app.MapGet("/orders/{orderId:int}", (int orderId, HttpContext c) => { Client(c); return Results.Json(new { id = orderId, status = "shipped" }); });
app.MapGet("/search", (string? q, HttpContext c, OwSecurity sec) =>
{
    var client = Client(c); q ??= "";
    if (q.Contains('\'') || q.Contains("--") || q.Contains(" or ", StringComparison.OrdinalIgnoreCase))
    {
        sec.InputRejected("sqli", "/search", "q", client);
        throw new SqlSyntaxException("syntax error near the supplied search text"); // exception.type = SqlSyntaxException
    }
    return Results.Json(new { results = Array.Empty<object>() });
});
// Intentionally vulnerable: runs a command given by the caller (rule APP-H01 should fire).
app.MapGet("/debug/exec", (string? cmd, HttpContext c) =>
{
    Client(c);
    var p = Process.Start(new ProcessStartInfo("/bin/sh") { ArgumentList = { "-c", cmd ?? "id" }, RedirectStandardOutput = true })!;
    var o = p.StandardOutput.ReadToEnd(); p.WaitForExit();
    return Results.Json(new { output = o.Length > 500 ? o[..500] : o });
});
app.UseExceptionHandler(e => e.Run(async ctx => { ctx.Response.StatusCode = 500; await ctx.Response.WriteAsJsonAsync(new { error = "error" }); }));
app.Run();
return 0;

record LoginBody(string? User, string? Password);
class SqlSyntaxException(string message) : Exception(message);
