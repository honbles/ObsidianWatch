// ObsidianWatch security helper for .NET (optional). Emits the security events the Application rules
// read as OpenTelemetry log records (through ILogger) to the local agent. Pass identifiers only,
// never request bodies, parameter values or headers (the agent drops them anyway).
public sealed class OwSecurity
{
    const string HelperVersion = "dotnet-2";
    readonly ILogger _log;
    public OwSecurity(ILoggerFactory f) => _log = f.CreateLogger("obsidianwatch.security");

    public void Emit(string eventName, params (string Key, string? Value)[] attrs)
    {
        var state = new List<KeyValuePair<string, object?>> { new("event.name", eventName), new("helper_version", HelperVersion) };
        foreach (var (k, v) in attrs) if (!string.IsNullOrEmpty(v)) state.Add(new(k, v));
        _log.Log(LogLevel.Warning, new EventId(0, eventName), state, null, (s, _) => eventName);
    }

    // One helper per event name the agent accepts. Attribute names are the ones the agent keeps
    // (docs/application/capability.md 4.3). user, session and object_id are pseudonymised by the agent
    // unless the service is set to cleartext users.
    public void Login(string outcome, string? user, string? client, string? route, string? method = null, string? reason = null) =>
        Emit("auth.login", ("outcome", outcome), ("user", user), ("client.address", client), ("route", route), ("method", method), ("reason", reason));
    public void Mfa(string outcome, string? user, string? client, string? route, string? method = null) =>
        Emit("auth.mfa", ("outcome", outcome), ("user", user), ("client.address", client), ("route", route), ("method", method));
    public void AuthzDenied(string resourceType, string action, string? user, string? route, string? client) =>
        Emit("authz.deny", ("resource_type", resourceType), ("action", action), ("user", user), ("route", route), ("client.address", client));
    public void InputRejected(string kind, string? route, string? parameter, string? client) =>
        Emit("input.rejected", ("kind", kind), ("route", route), ("parameter", parameter), ("client.address", client));
    public void SsrfBlocked(string targetHost, string? route, string? client) =>
        Emit("ssrf.blocked", ("target_host", targetHost), ("route", route), ("client.address", client));
    public void DeserializationBlocked(string typeName, string? route, string? client) =>
        Emit("deserialization.blocked", ("type_name", typeName), ("route", route), ("client.address", client));
    public void RateLimited(string limitName, string? route, string? client) =>
        Emit("ratelimit.hit", ("limit_name", limitName), ("route", route), ("client.address", client));
    public void AdminAction(string action, string? user, string? targetType, string? targetId, string? client) =>
        Emit("admin.action", ("action", action), ("user", user), ("target_type", targetType), ("target_id", targetId), ("outcome", "success"), ("client.address", client));
    public void DataExport(string objectType, string? user, string? format, string? rows, string? route, string? client) =>
        Emit("data.export", ("object_type", objectType), ("user", user), ("format", format), ("rows", rows), ("route", route), ("client.address", client));
    public void DataAccess(string objectType, string? objectId, string? user, string? route, string? client) =>
        Emit("data.access", ("object_type", objectType), ("object_id", objectId), ("user", user), ("action", "read"), ("route", route), ("client.address", client));
    public void SessionAnomaly(string kind, string? user, string? session, string? reason, string? client) =>
        Emit("session.anomaly", ("kind", kind), ("user", user), ("session", session), ("reason", reason), ("client.address", client));
}
