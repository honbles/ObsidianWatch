"""ObsidianWatch request-field helper for Python (optional).

It hands the PARSED request body to the local agent as one span attribute. The agent decides what leaves
the host: field names always, values only for routes an admin has reviewed, never fields on the deny list
(password, token, card ...). Nothing is sent anywhere except the agent on this host.

Flask:   ow_payload.flask_install(app)          (after FlaskInstrumentor().instrument_app(app))
Others:  ow_payload.set_body(parsed_dict)       (call from a Django middleware, a FastAPI dependency, ...)
"""
import json

from opentelemetry import trace

MAX_BYTES = 32 * 1024
ATTR = "ow.request.body"


def set_body(body):
    """Record a parsed body (dict) on the current server span. Never raises."""
    try:
        if not isinstance(body, dict) or not body:
            return
        s = json.dumps(body, default=str)
        if len(s) <= MAX_BYTES:
            span = trace.get_current_span()
            if span.is_recording():
                span.set_attribute(ATTR, s)
    except Exception:
        pass  # observability must never break a request


def flask_install(app):
    from flask import request

    @app.before_request
    def _ow_payload():
        try:
            ct = (request.content_type or "").lower()
            if "multipart" in ct or "octet-stream" in ct:
                return
            body = request.get_json(silent=True)
            if not isinstance(body, dict):
                body = request.form.to_dict(flat=True) if request.form else None
            set_body(body)
        except Exception:
            pass
