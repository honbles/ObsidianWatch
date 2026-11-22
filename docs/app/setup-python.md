# Application Monitoring - Python setup

Send traces from a Python application to the local agent and, optionally, security events.

## Before you start
1. The host runs the ObsidianWatch agent built with the **app-server profile** (Agent Builder, "Enable the app-server profile"). The agent then listens on `127.0.0.1:4318` (OTLP over HTTP). gRPC is not supported.
2. The application and the agent run on the same host (or the application uses the agent's Unix socket from a container, see the Node.js guide).
3. You change **no** host or deployment attribute. The agent works out which host, process and container are sending, and discards any `host.*`, `container.*` and `k8s.*` you set.

## What the sample shows
`samples/app/python` is a small application with the routes `/health`, `POST /login`, `/orders/{id}`, `/search` and `/debug/exec`. It is **intentionally vulnerable**: it refuses to start unless `OW_ALLOW_VULN_DEMO=1`, binds `127.0.0.1` only, and must never be deployed. `samples/app/attack_sim.py` drives it through normal traffic, a login brute force, injection attempts, a request burst and a command-execution request, so you can watch the rules fire (`platform-guide.md`: A01, A09, A13, H01, X02). Rules are observe-only until you switch a service to enforce.

## 1. Install
```
pip install opentelemetry-sdk opentelemetry-exporter-otlp-proto-http opentelemetry-instrumentation-flask
```
(Django, FastAPI and others have an `opentelemetry-instrumentation-*` package; the steps are the same.)

## 2. Configure (traces)
```python
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

resource = Resource.create({"service.name": "orders-api", "deployment.environment.name": "production", "service.version": "1.4.2"})
provider = TracerProvider(resource=resource)
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint="http://127.0.0.1:4318/v1/traces")))
trace.set_tracer_provider(provider)

from opentelemetry.instrumentation.flask import FlaskInstrumentor
FlaskInstrumentor().instrument_app(app)
```
Set `service.name` and `deployment.environment.name`; the console groups by them.

## 3. Security helper
Copy `samples/app/python/ow_security.py` into your project, call `ow_security.init(resource, "http://127.0.0.1:4318/v1/logs")` once, then for example `ow_security.login("failure", user=name, client=request.remote_addr, route="/login")`.

## 4. Request fields (optional)
Copy `samples/app/python/ow_payload.py`. For Flask call `ow_payload.flask_install(app)` after instrumenting; for Django or FastAPI call `ow_payload.set_body(parsed_dict)` from a middleware or dependency. The agent gets the parsed body as one span attribute; nested fields arrive as `address.zip`, arrays as `items[].sku`. Field names are kept for every route, values only after an admin reviews the route (Routes tab, Review). Deny-listed fields and credential-looking values are never forwarded. Multipart and binary bodies are skipped. This needs the agent from this build or later.

## Version note
This was verified with `opentelemetry-sdk 1.45.2`. SDK 1.40+ changed the logs API (`Logger.emit` takes keyword arguments and `LogRecord` moved); the helper handles both forms.

## Run the sample
```
cd samples/app/python && pip install -r requirements.txt
OW_ALLOW_VULN_DEMO=1 python app.py          # port 5001
python ../attack_sim.py --base http://127.0.0.1:5001
```
Verified against the agent's receiver with a real SDK: see "Proof" below.

## Checking it works
In the console open **Applications, Services**. Within about a minute you should see the service, its environment, and each route as a **template** (for example `/orders/{id}`), never the raw URL. The instance should say **verified** with the process executable. If it says **asserted**, the agent could not match the sender to a local process (container with its own network namespace, or an agent without the required privilege): use the Unix socket or run the agent in the host pid namespace.

## What is never sent
Request and response bodies, headers, and query-string or parameter values. Only the parameter names of the query string are kept, so the console can show which parameters a route takes. Only route templates, status codes, timings, exception type names and the security-event fields below. Identifiers you pass to the helper (user, object id) are hashed by the agent before they leave the host.

## Security helper (optional)
The helper emits events the rules read: `auth.login`, `auth.mfa`, `authz.deny`, `input.rejected`, `ratelimit.hit`, `data.access`, `data.export`, `admin.action`, `session.anomaly`. Call it where your code already makes the decision (login result, validation rejection, rate limiter). It never sends bodies or parameter values. Without it you still get traces, route health and exception-based rules; with it you get login-failure and rejection signals that do not depend on framework error types.

## Proof
`samples/app/verify.sh <port> <command>` starts the agent's real receiver (real process identification), starts the sample, runs `attack_sim.py`, and prints what the receiver decoded: identity, per-route RED, per-client failure counters and security events.

Run on the Linux agent receiver with the real SDK output of this sample: service and environment decoded, identity **verified** (pid and executable), route templates (not raw paths), 25 failed logins counted against `/login`, 6 injection-class exceptions against `/search`, and 32 helper events delivered. Verified with opentelemetry-sdk 1.45.2 and Flask.
