# Application monitoring: Python

Connect a Python web application (Flask, Django, FastAPI and others with an `opentelemetry-instrumentation-*` package) to the local ObsidianWatch agent.

Verified: the Flask sample ran against the agent's real Linux receiver with `opentelemetry-sdk 1.45.2`: service and environment decoded, identity verified, route templates, 25 failed logins counted on `/login`, 6 injection-class exceptions on `/search`, 32 helper events. That test exercised the receiver and aggregator, not the sending path to the server. Django and FastAPI were not run.

## Prerequisites

- An ObsidianWatch agent built with the app-server profile on the same host ([deployment.md](deployment.md)), listening on `127.0.0.1:4318`.
- Python 3.8 or later.

## Steps

1. Install:

```
pip install opentelemetry-sdk opentelemetry-exporter-otlp-proto-http opentelemetry-instrumentation-flask
```

Use `opentelemetry-exporter-otlp-proto-http`, not the gRPC exporter. For Django or FastAPI install `opentelemetry-instrumentation-django` or `opentelemetry-instrumentation-fastapi` instead of the Flask package.

2. Configure before the framework handles requests:

```python
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor

resource = Resource.create({
    "service.name": "orders-api",
    "deployment.environment.name": "production",
    "service.version": "1.4.2",
})
provider = TracerProvider(resource=resource)
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint="http://127.0.0.1:4318/v1/traces")))
trace.set_tracer_provider(provider)

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)
```

The `endpoint` argument must include `/v1/traces`.

Alternative without code: `opentelemetry-distro` with `opentelemetry-instrument python app.py` and the variables `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=production,service.version=1.4.2`, `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318`, `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`, `OTEL_METRICS_EXPORTER=none`, `OTEL_LOGS_EXPORTER=none`. Not tested here.

3. Client address. The sample sets both addresses on every server span because instrumentation versions differ in what they record:

```python
@app.before_request
def tag_client():
    span = trace.get_current_span()
    span.set_attribute("client.address", request.remote_addr)
    span.set_attribute("network.peer.address", request.remote_addr)
```

Behind a proxy, set `client.address` from the forwarded header and add the proxy to the service's Trusted proxies.

## What is captured automatically

| Data | Source | Notes |
|---|---|---|
| Routes, RED, status classes | server spans with `http.route` | Flask reports `/orders/<int:order_id>`; Django and FastAPI report their templates |
| Query-string field names, injection signatures | `url.query` or `http.target` | |
| Dependencies and queries | client spans from `requests`, `httpx`, `psycopg2`, `sqlalchemy` and similar instrumentations (install them) | queries: defect D1 |
| Error groups | `exception` events; Python tracebacks (`File "...", line N, in f`) | frames under `site-packages/`, `dist-packages/`, `/lib/python` count as library frames. Defect D1 |
| Instance identity | the Python process (gunicorn and uvicorn workers that share the executable are verified too) | |

## What needs manual work

- **Exception types for APP-A09.** Python records the class name, for example `SyntaxError` from a driver wrapper or `psycopg2.errors.SyntaxError`. Names with `sql` and `syntax` (or containing `injection`) are injection-class. The sample defines `SqlSyntaxError` for this reason.
- **Request body fields.** Copy `samples/app/python/ow_payload.py`. For Flask call `ow_payload.flask_install(app)` after instrumenting. For Django or FastAPI call `ow_payload.set_body(parsed_dict)` from a middleware or dependency. The helper sets `ow.request.body` on the current server span; multipart and binary bodies are skipped. Bodies whose JSON exceeds 4 KiB produce no field names (defect D2), although the helper accepts 32 KiB.
- **Scheduled jobs.** No Python job helper exists. Start a root span per run with the attribute `ow.job.name`:
  ```python
  with tracer.start_as_current_span("nightly-report", context=Context(), attributes={"ow.job.name": "nightly-report"}):
      run()
  ```
- **Metrics.** Python runtime metrics are stored when their names start with `process.runtime.` or `process.cpu.`/`process.memory.`, but none feeds the runtime summary or APM-O07. Pool metrics (`db.client.connection*`) from SQLAlchemy instrumentation are summarised. Defect D1 currently prevents delivery.

## Security helper (optional, Tier 2)

Copy `samples/app/python/ow_security.py`. It needs the OpenTelemetry logs SDK and the HTTP log exporter (both in `opentelemetry-sdk` and `opentelemetry-exporter-otlp-proto-http`). It handles both the older and the 1.40+ logs API.

```python
import ow_security
ow_security.init(resource, "http://127.0.0.1:4318/v1/logs")      # once, same resource as the traces
ow_security.login("failure", user=name, client=request.remote_addr, route="/login")
ow_security.authz_denied("invoice", "read", user=uid, route="/invoices/<id>", client=request.remote_addr)
ow_security.input_rejected("sqli", route="/search", parameter="q", client=request.remote_addr)
ow_security.rate_limited("login", route="/login", client=request.remote_addr)
ow_security.emit("data.export", rows="1200", format="csv", route="/export")
```

The events fill the Security tab and make the service Tier 2. No rule reads them today; APP-A01 counts 401/403 responses.

## Verify

Sample:

```
cd samples/app/python && pip install -r requirements.txt
OW_ALLOW_VULN_DEMO=1 python app.py                     # port 5001
python ../attack_sim.py --base http://127.0.0.1:5001
```

Or prove the receiver side alone with `samples/app/verify.sh 5001 python3 python/app.py` (needs Go; prints what the receiver decoded). Then check **Applications → Services**, the **Endpoints** tab and **Instances** (verified).

The sample is intentionally vulnerable and must never be deployed.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Nothing arrives | gRPC exporter installed instead of `proto-http`; endpoint without `/v1/traces`; the provider is set after the app was instrumented in a forking server (configure per worker, for example in gunicorn's `post_fork`) |
| Instance **asserted** | container with its own network namespace; use the Unix socket ([deployment.md](deployment.md)) |
| POST routes show no fields | `ow_payload` not installed, body not a JSON object or form, body over 4 KiB |
| Security tab empty | `ow_security.init` not called, or wrong logs URL |
