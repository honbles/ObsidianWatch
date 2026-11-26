"""ObsidianWatch security helper for Python (optional).

Emits the security events the Application rules read (auth.login, input.rejected, ratelimit.hit,
authz.deny, admin.action, data.export, ...) as OpenTelemetry log records. Nothing here sends data
anywhere by itself: the records go to the same local OTLP endpoint as the traces (the agent on
127.0.0.1:4318). Pass identifiers (user, object ids); the agent hashes them before they leave the host.
Never pass request bodies, parameter values or headers: the agent drops them anyway.
"""
import logging
import time

from opentelemetry._logs import SeverityNumber
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter

HELPER_VERSION = "py-2"
_logger = None


def init(resource, endpoint="http://127.0.0.1:4318/v1/logs"):
    """Call once at start-up with the same Resource used for tracing."""
    global _logger
    provider = LoggerProvider(resource=resource)
    provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(endpoint=endpoint), schedule_delay_millis=1000))
    _logger = provider.get_logger("obsidianwatch.security", HELPER_VERSION)
    return provider


def emit(event_name, **attrs):
    """Emit one helper event. event_name must be one the agent accepts (docs/application/capability.md 4.3)."""
    if _logger is None:
        return
    attributes = {"event.name": event_name, "helper_version": HELPER_VERSION}
    attributes.update({k: str(v) for k, v in attrs.items() if v not in (None, "")})
    kw = dict(timestamp=time.time_ns(), observed_timestamp=time.time_ns(), severity_number=SeverityNumber.WARN,
              severity_text="WARN", body=event_name, attributes=attributes)
    try:
        _logger.emit(event_name=event_name, **kw)  # opentelemetry-sdk 1.40+ (emit takes keyword arguments)
    except TypeError:
        from opentelemetry.sdk._logs import LogRecord  # older SDKs: carry the active trace explicitly
        from opentelemetry import trace
        sc = trace.get_current_span().get_span_context()
        if sc.is_valid:
            kw.update(trace_id=sc.trace_id, span_id=sc.span_id, trace_flags=sc.trace_flags)
        _logger.emit(LogRecord(**kw))


# One helper per event name the agent accepts. Attribute names are the ones the agent keeps
# (docs/application/capability.md 4.3); anything else is dropped on the host. user, session and
# object_id are pseudonymised by the agent unless the service is set to cleartext users.

def _c(client):
    return {"client.address": client}


def login(outcome, user=None, client=None, route=None, method=None, reason=None, mfa=None):
    emit("auth.login", outcome=outcome, user=user, route=route, method=method, reason=reason, mfa=mfa, **_c(client))


def mfa(outcome, user=None, client=None, route=None, method=None, reason=None):
    emit("auth.mfa", outcome=outcome, user=user, route=route, method=method, reason=reason, **_c(client))


def authz_denied(resource_type, action, user=None, route=None, client=None, policy=None):
    emit("authz.deny", resource_type=resource_type, action=action, user=user, route=route, policy=policy, **_c(client))


def input_rejected(kind, route=None, parameter=None, client=None):
    emit("input.rejected", kind=kind, route=route, parameter=parameter, **_c(client))


def ssrf_blocked(target_host, route=None, client=None, reason=None):
    emit("ssrf.blocked", target_host=target_host, route=route, reason=reason, **_c(client))


def deserialization_blocked(type_name, route=None, client=None):
    emit("deserialization.blocked", type_name=type_name, route=route, **_c(client))


def rate_limited(limit_name, route=None, client=None, user=None):
    emit("ratelimit.hit", limit_name=limit_name, route=route, user=user, **_c(client))


def admin_action(action, user=None, target_type=None, target_id=None, outcome="success", route=None, client=None):
    emit("admin.action", action=action, user=user, target_type=target_type, target_id=target_id, outcome=outcome,
         route=route, **_c(client))


def data_export(object_type, user=None, format=None, rows=None, bytes=None, route=None, client=None):
    emit("data.export", object_type=object_type, user=user, format=format, rows=rows, bytes=bytes, route=route, **_c(client))


def data_access(object_type, object_id, user=None, action="read", route=None, client=None):
    emit("data.access", object_type=object_type, object_id=object_id, user=user, action=action, route=route, **_c(client))


def session_anomaly(kind, user=None, session=None, reason=None, route=None, client=None):
    emit("session.anomaly", kind=kind, user=user, session=session, reason=reason, route=route, **_c(client))
