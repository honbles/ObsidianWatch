package ng.obsidianwatch.sample;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.logs.Logger;
import io.opentelemetry.api.logs.Severity;

/**
 * ObsidianWatch security helper for Java (optional). Emits the security events the Application rules
 * read as OpenTelemetry log records through the javaagent, to the local agent. Pass identifiers only,
 * never request bodies, parameter values or headers (the agent drops them anyway).
 */
public final class OwSecurity {
    static final String HELPER_VERSION = "java-2";
    private static volatile Logger logger;

    private OwSecurity() {}

    private static Logger logger() {
        if (logger == null) {
            logger = GlobalOpenTelemetry.get().getLogsBridge().get("obsidianwatch.security");
        }
        return logger;
    }

    public static void emit(String eventName, String... kv) {
        var b = logger().logRecordBuilder().setSeverity(Severity.WARN).setSeverityText("WARN").setBody(eventName)
                .setAttribute(AttributeKey.stringKey("event.name"), eventName)
                .setAttribute(AttributeKey.stringKey("helper_version"), HELPER_VERSION);
        for (int i = 0; i + 1 < kv.length; i += 2) {
            if (kv[i + 1] != null && !kv[i + 1].isEmpty()) b.setAttribute(AttributeKey.stringKey(kv[i]), kv[i + 1]);
        }
        b.emit();
    }

    // One helper per event name the agent accepts. Attribute names are the ones the agent keeps
    // (docs/application/capability.md 4.3). user, session and object_id are pseudonymised by the agent
    // unless the service is set to cleartext users. Pass null for anything you do not have.

    public static void login(String outcome, String user, String client, String route) {
        login(outcome, user, client, route, null, null);
    }

    public static void login(String outcome, String user, String client, String route, String method, String reason) {
        emit("auth.login", "outcome", outcome, "user", user, "client.address", client, "route", route, "method", method, "reason", reason);
    }

    public static void mfa(String outcome, String user, String client, String route, String method) {
        emit("auth.mfa", "outcome", outcome, "user", user, "client.address", client, "route", route, "method", method);
    }

    public static void authzDenied(String resourceType, String action, String user, String route, String client) {
        emit("authz.deny", "resource_type", resourceType, "action", action, "user", user, "route", route, "client.address", client);
    }

    public static void inputRejected(String kind, String route, String parameter, String client) {
        emit("input.rejected", "kind", kind, "route", route, "parameter", parameter, "client.address", client);
    }

    public static void ssrfBlocked(String targetHost, String route, String client) {
        emit("ssrf.blocked", "target_host", targetHost, "route", route, "client.address", client);
    }

    public static void deserializationBlocked(String typeName, String route, String client) {
        emit("deserialization.blocked", "type_name", typeName, "route", route, "client.address", client);
    }

    public static void rateLimited(String limitName, String route, String client) {
        emit("ratelimit.hit", "limit_name", limitName, "route", route, "client.address", client);
    }

    public static void adminAction(String action, String user, String targetType, String targetId, String client) {
        emit("admin.action", "action", action, "user", user, "target_type", targetType, "target_id", targetId,
                "outcome", "success", "client.address", client);
    }

    public static void dataExport(String objectType, String user, String format, String rows, String route, String client) {
        emit("data.export", "object_type", objectType, "user", user, "format", format, "rows", rows, "route", route, "client.address", client);
    }

    public static void dataAccess(String objectType, String objectId, String user, String route, String client) {
        emit("data.access", "object_type", objectType, "object_id", objectId, "user", user, "action", "read",
                "route", route, "client.address", client);
    }

    public static void sessionAnomaly(String kind, String user, String session, String reason, String client) {
        emit("session.anomaly", "kind", kind, "user", user, "session", session, "reason", reason, "client.address", client);
    }
}
