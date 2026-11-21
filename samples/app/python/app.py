"""ObsidianWatch sample application - Python (Flask + OpenTelemetry SDK).

Purpose: give the agent's OTLP receiver real SDK output and give you something to attack safely.
It is INTENTIONALLY VULNERABLE (a fake SQL layer that errors on injection-looking input, and a
debug endpoint that runs a shell command). It refuses to start unless OW_ALLOW_VULN_DEMO=1 and it
only ever binds 127.0.0.1. Never deploy it.

Run:  OW_ALLOW_VULN_DEMO=1 python app.py          (agent receiver on 127.0.0.1:4318)
"""
import os
import subprocess
import sys

from flask import Flask, jsonify, request
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

import ow_payload
import ow_security

if os.environ.get("OW_ALLOW_VULN_DEMO") != "1":
    sys.exit("This sample is intentionally vulnerable. Set OW_ALLOW_VULN_DEMO=1 to run it (binds 127.0.0.1 only).")

ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
resource = Resource.create({
    "service.name": os.environ.get("OTEL_SERVICE_NAME", "sample-python"),
    "deployment.environment.name": "demo",
    "service.version": "1.0.0",
})
provider = TracerProvider(resource=resource)
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=ENDPOINT + "/v1/traces"), schedule_delay_millis=1000))
trace.set_tracer_provider(provider)
ow_security.init(resource, ENDPOINT + "/v1/logs")

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)
ow_payload.flask_install(app)
USERS = {"alice": "correct-horse"}


class SqlSyntaxError(Exception):
    """Stand-in for a database driver's syntax error."""


def client_ip():
    return request.remote_addr


def tag_client():
    """The instrumentation records the client address on the span; make sure both addresses are set."""
    span = trace.get_current_span()
    span.set_attribute("client.address", client_ip())
    span.set_attribute("network.peer.address", request.remote_addr)


@app.before_request
def before():
    tag_client()


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    user, pw = body.get("user", ""), body.get("password", "")
    if USERS.get(user) == pw and pw:
        ow_security.login("success", user=user, client=client_ip(), route="/login")
        return jsonify(token="demo-token")
    ow_security.login("failure", user=user, client=client_ip(), route="/login")
    return jsonify(error="invalid credentials"), 401


@app.get("/orders/<int:order_id>")
def order(order_id):
    return jsonify(id=order_id, status="shipped")


@app.get("/search")
def search():
    q = request.args.get("q", "")
    if "'" in q or "--" in q or " or " in q.lower():
        # a real driver would raise here; the exception type is what the injection rule classifies
        ow_security.input_rejected("sqli", route="/search", parameter="q", client=client_ip())
        raise SqlSyntaxError("syntax error near the supplied search text")
    return jsonify(results=[])


@app.get("/debug/exec")
def debug_exec():
    """Intentionally vulnerable: runs a command given by the caller (rule APP-H01 should fire)."""
    cmd = request.args.get("cmd", "id")
    out = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=10)
    return jsonify(output=out.stdout[:500])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5001")), threaded=True)
