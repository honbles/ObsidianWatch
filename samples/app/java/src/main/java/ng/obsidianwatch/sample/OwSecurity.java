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
    static final String HELPER_VERSION = "java-1";
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

    public static void login(String outcome, String user, String client, String route) {
        emit("auth.login", "outcome", outcome, "user", user, "client.address", client, "route", route);
    }

    public static void inputRejected(String kind, String route, String parameter, String client) {
        emit("input.rejected", "kind", kind, "route", route, "parameter", parameter, "client.address", client);
    }

    public static void rateLimited(String limitName, String route, String client) {
        emit("ratelimit.hit", "limit_name", limitName, "route", route, "client.address", client);
    }

    public static void authzDenied(String resourceType, String action, String user, String route, String client) {
        emit("authz.deny", "resource_type", resourceType, "action", action, "user", user, "route", route, "client.address", client);
    }
}
