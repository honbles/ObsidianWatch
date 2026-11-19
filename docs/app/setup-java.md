# Application Monitoring - Java setup

Send traces from a Java application to the local agent and, optionally, security events.

## Before you start
1. The host runs the ObsidianWatch agent built with the **app-server profile** (Agent Builder, "Enable the app-server profile"). The agent then listens on `127.0.0.1:4318` (OTLP over HTTP). gRPC is not supported.
2. The application and the agent run on the same host (or the application uses the agent's Unix socket from a container, see `agent-otlp.md`).
3. You change **no** host or deployment attribute. The agent works out which host, process and container are sending, and discards any `host.*`, `container.*` and `k8s.*` you set.

## What the sample shows
`samples/app/java` is a small application with the routes `/health`, `POST /login`, `/orders/{id}`, `/search` and `/debug/exec`. It is **intentionally vulnerable**: it refuses to start unless `OW_ALLOW_VULN_DEMO=1`, binds `127.0.0.1` only, and must never be deployed. `samples/app/attack_sim.py` drives it through normal traffic, a login brute force, injection attempts, a request burst and a command-execution request, so you can watch the rules fire (`rules.md`: A01, A09, A13, H01, X02). Rules are observe-only until you switch a service to enforce.

## 1. Get the agent
Download `opentelemetry-javaagent.jar` from the OpenTelemetry Java instrumentation releases. No code changes are needed for traces.

## 2. Run with the agent
```
export OTEL_SERVICE_NAME=orders-api
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=production
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_METRICS_EXPORTER=none
java -javaagent:/opt/otel/opentelemetry-javaagent.jar -jar app.jar
```
`http/protobuf` matters: the agent does not accept gRPC. Spring MVC, Servlet and most frameworks give you `http.route` templates automatically.

## 3. Security helper
Add `io.opentelemetry:opentelemetry-api` (the javaagent supplies the implementation), copy `OwSecurity.java`, and call for example `OwSecurity.login("failure", user, request.getRemoteAddr(), "/login")`. Log export is on by default in the agent (`OTEL_LOGS_EXPORTER=otlp`).

## Run the sample
```
cd samples/app/java && mvn -q package
OW_ALLOW_VULN_DEMO=1 OTEL_SERVICE_NAME=sample-java OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
  OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf OTEL_METRICS_EXPORTER=none \
  java -javaagent:opentelemetry-javaagent.jar -jar target/ow-sample-java-1.0.0.jar   # port 5003
python3 ../attack_sim.py --base http://127.0.0.1:5003
```

> **Not verified.** The Java sample was written but not compiled or run in the environment used to build ObsidianWatch (Maven Central was unreachable). Run it once with `samples/app/verify.sh` before relying on it, and tell us what differs.

## Checking it works
In the console open **Applications, Services**. Within about a minute you should see the service, its environment, and each route as a **template** (for example `/orders/{id}`), never the raw URL. The instance should say **verified** with the process executable. If it says **asserted**, the agent could not match the sender to a local process (container with its own network namespace, or an agent without the required privilege): use the Unix socket or run the agent in the host pid namespace.

## What is never sent
Request and response bodies, query strings, headers and parameter values. Only route templates, status codes, timings, exception type names and the security-event fields below. Identifiers you pass to the helper (user, object id) are hashed by the agent before they leave the host.

## Security helper (optional)
The helper emits events the rules read: `auth.login`, `auth.mfa`, `authz.deny`, `input.rejected`, `ratelimit.hit`, `data.access`, `data.export`, `admin.action`, `session.anomaly`. Call it where your code already makes the decision (login result, validation rejection, rate limiter). It never sends bodies or parameter values. Without it you still get traces, route health and exception-based rules; with it you get login-failure and rejection signals that do not depend on framework error types.

## Proof
This language has not been run against the receiver yet. Use `samples/app/verify.sh` to check it.
