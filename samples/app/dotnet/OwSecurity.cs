// ObsidianWatch security helper for .NET (optional). Emits the security events the Application rules
// read as OpenTelemetry log records (through ILogger) to the local agent. Pass identifiers only,
// never request bodies, parameter values or headers (the agent drops them anyway).
public sealed class OwSecurity
{
    const string HelperVersion = "dotnet-1";
    readonly ILogger _log;
    public OwSecurity(ILoggerFactory f) => _log = f.CreateLogger("obsidianwatch.security");

    public void Emit(string eventName, params (string Key, string? Value)[] attrs)
    {
        var state = new List<KeyValuePair<string, object?>> { new("event.name", eventName), new("helper_version", HelperVersion) };
        foreach (var (k, v) in attrs) if (!string.IsNullOrEmpty(v)) state.Add(new(k, v));
        _log.Log(LogLevel.Warning, new EventId(0, eventName), state, null, (s, _) => eventName);
    }

    public void Login(string outcome, string? user, string? client, string? route) =>
        Emit("auth.login", ("outcome", outcome), ("user", user), ("client.address", client), ("route", route));
    public void InputRejected(string kind, string? route, string? parameter, string? client) =>
        Emit("input.rejected", ("kind", kind), ("route", route), ("parameter", parameter), ("client.address", client));
    public void RateLimited(string limitName, string? route, string? client) =>
        Emit("ratelimit.hit", ("limit_name", limitName), ("route", route), ("client.address", client));
    public void AuthzDenied(string resourceType, string action, string? user, string? route, string? client) =>
        Emit("authz.deny", ("resource_type", resourceType), ("action", action), ("user", user), ("route", route), ("client.address", client));
}
