# Application monitoring: Java

Connect a Java application (Spring Boot, Servlet containers, Quarkus, Micronaut and other frameworks supported by the OpenTelemetry Java agent) to the local ObsidianWatch agent.

Check your setup with `samples/app/verify.sh` (it runs the sample against the agent's receiver and prints what was recorded).

Verified: OpenTelemetry Java agent 2.34.0 on Java 21 with the settings below sent traces and JVM metrics through the ObsidianWatch agent to the server (routes, verified `java` instance, version, metrics).

## Prerequisites

- The host runs an ObsidianWatch agent built with the app-server profile ([deployment.md](deployment.md)). It listens on `127.0.0.1:4318`, OTLP over HTTP.
- Java 8 or later for the Java agent (the sample targets Java 17, Spring Boot 3.3; Spring Boot 3 and 4 need Java 17).
- The OpenTelemetry Java agent jar, `opentelemetry-javaagent.jar`, from the OpenTelemetry Java instrumentation releases on GitHub (for example `https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/download/v2.34.0/opentelemetry-javaagent.jar`).

## Steps

1. Put the agent jar on the host, for example `/opt/otel/opentelemetry-javaagent.jar`.
2. Set these environment variables for the application process (systemd `Environment=`, container `ENV`, or the shell):

```
OTEL_SERVICE_NAME=orders-api
OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=production,service.version=1.4.2
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
OTEL_TRACES_EXPORTER=otlp
OTEL_METRICS_EXPORTER=none
OTEL_LOGS_EXPORTER=none
```

3. Start the JVM with the agent:

```
java -javaagent:/opt/otel/opentelemetry-javaagent.jar -jar app.jar
```

Notes:
- `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf` is required with Java agent 1.x, whose default is gRPC. The ObsidianWatch receiver does not accept gRPC.
- With the endpoint variable (no signal suffix) the Java agent appends `/v1/traces`, `/v1/logs` and `/v1/metrics` itself.
- Set `service.version` from your build. Without it there is no deploy detection, no version compare and no error regression.
- Set `OTEL_LOGS_EXPORTER=otlp` only if you use the security helper (below). With `otlp` the Java agent also forwards ordinary application logs; the ObsidianWatch agent drops every log record that is not a helper event, but they still cross loopback.
- For runtime metrics set `OTEL_METRICS_EXPORTER=otlp` (section "Metrics").

## What is captured automatically

| Data | Source | Notes |
|---|---|---|
| Routes, RED, status classes | server spans with `http.route` | Spring MVC/WebFlux, JAX-RS and Servlet frameworks set `http.route` templates. A request without one is counted as `(unmatched)` |
| Query-string field names, injection signatures | `url.query` (agent 2.x) or `http.target`/`http.url` (1.x) | names only leave the host; values only for reviewed routes |
| Dependencies | client spans: JDBC (`db.system`, `server.address`), HTTP clients, Kafka/JMS/RabbitMQ producers | |
| Database query groups and N+1 | JDBC spans: `db.operation`, `db.sql.table`; `db.statement` read only for fingerprints | statements are fingerprinted (literals become `?`) when the service's statement setting is `fingerprint`, the default |
| Error groups | `exception` span events with Java stack traces (`at pkg.Cls.m(File.java:N)`) | frames from `java.`, `javax.`, `jdk.`, `sun.`, `kotlin.` count as library frames. Stack text over 16 KiB is cut; the top frames are still parsed |
| Message consumers | CONSUMER spans from Kafka, JMS, RabbitMQ, SQS instrumentation | Jobs and queues tab |
| Client address | `client.address`, `network.peer.address` (or older `net.sock.peer.addr`) | behind a proxy set Trusted proxies in the service settings |
| Instance identity | the JVM process | verified with the `java` executable |

## What needs manual work

- **Exception types for injection detection.** APP-A09 counts failures whose exception type contains `injection`, `ognl`, `spelevaluation`, `spelparse`, or `sql` with `syntax`, `grammar` or `parse`. JDBC drivers usually throw `java.sql.SQLSyntaxErrorException`, which matches. Wrapped exceptions (for example Spring's `BadSqlGrammarException`) also match. Custom wrappers may need a matching name. The agent's own parameter-value signatures work regardless.
- **Request body fields.** There is no Java helper in the repository. To report body field names, set the span attribute `ow.request.body` on the server span to the JSON of the parsed body (object only, at most 32 KiB):
  ```java
  Span.current().setAttribute("ow.request.body", objectMapper.writeValueAsString(bodyMap));
  ```
  Do this in a filter or controller advice after the body is parsed.
- **Scheduled jobs.** Wrap each run in a root span with the attribute `ow.job.name` (a stable name without ids). Spans with an error status count as failed runs.
- **Security events (Tier 2).** Optional; see below.
- **Request context for the helper.** Helper calls deep in a controller need the route template and client address. A servlet filter can keep the request in a `ThreadLocal`; Spring MVC puts the matched template in the request attribute `org.springframework.web.servlet.HandlerMapping.bestMatchingPattern`. The same filter can set `ow.request.body` from `request.getParameterMap()` for form posts.

## Metrics

Set `OTEL_METRICS_EXPORTER=otlp`. The Java agent's JVM metrics (`jvm.memory.used`, `jvm.memory.limit`, `jvm.cpu.recent_utilization`, `jvm.gc.*`, `jvm.thread.*`) and HikariCP pool metrics (`db.client.connections.*` or `db.client.connection.*`) are on the allowlist. CPU, heap and pool use feed the runtime summary and APM-O07. Use explicit-bucket histograms (the default); exponential histograms are rejected.

## Security helper (optional, Tier 2)

`samples/app/java/src/main/java/ng/obsidianwatch/sample/OwSecurity.java` emits helper events through the OpenTelemetry Logs API. It needs `io.opentelemetry:opentelemetry-api` as a compile dependency (the Java agent supplies the implementation) and `OTEL_LOGS_EXPORTER=otlp`.

```java
OwSecurity.login("failure", user, request.getRemoteAddr(), "/login");
OwSecurity.authzDenied("invoice", "read", user, "/invoices/{id}", request.getRemoteAddr());
OwSecurity.inputRejected("sqli", "/search", "q", request.getRemoteAddr());
OwSecurity.rateLimited("login", "/login", request.getRemoteAddr());
OwSecurity.dataExport("orders", user, "csv", "1200", "/export", request.getRemoteAddr());
```

`OwSecurity` (helper version `java-2`) has one method per event name; see the table in [capability.md](capability.md) section 4.3. Pass route templates, not raw paths. User ids are hashed by the agent. The events appear on the service's Security tab and make the service Tier 2. No detection rule reads them today: APP-A01 counts 401/403 responses, not `auth.login` events. Return 401 or 403 on a failed login so A01 can count it.

## Verify

1. Send a few requests and wait one to two minutes.
2. **Applications → Services**: the service with its environment, tier T1.
3. Service page → **Endpoints**: templates such as `/orders/{orderId}`.
4. Service page → **Instances**: **verified**, executable `java`.

The sample: `cd samples/app/java && mvn -q package`, then

```
OW_ALLOW_VULN_DEMO=1 OTEL_SERVICE_NAME=sample-java OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
  OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf OTEL_METRICS_EXPORTER=none \
  java -javaagent:opentelemetry-javaagent.jar -jar target/ow-sample-java-1.0.0.jar      # port 5003
python3 ../attack_sim.py --base http://127.0.0.1:5003
```

The sample is intentionally vulnerable, refuses to start without `OW_ALLOW_VULN_DEMO=1`, binds 127.0.0.1 only, and must never be deployed.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Service never appears | exporter uses gRPC (set `http/protobuf`); agent not built with the profile; port 4318 used by another collector; `-javaagent` flag missing |
| Instance **asserted** | the JVM runs in a container with its own network namespace: use the Unix socket ([deployment.md](deployment.md) section 6) |
| All requests under `(unmatched)` | the framework is not instrumented by the Java agent, or instrumentation is disabled |
| Many routes, then `other` | a framework reports raw paths as `http.route` (custom servlets); fix the route attribute; the 500-route set resets only when the ObsidianWatch agent restarts |
| A01 never fires | no login route configured or recognised; login failures not returned as 401/403; proxy not in Trusted proxies; rule still in observe mode (fires at Info) |
| Error tab empty | exceptions must be recorded as span events, which the Java agent does for uncaught exceptions; an exception a Spring `@ExceptionHandler` or error page turns into a normal response is not recorded unless you call `Span.current().recordException(e)` |
