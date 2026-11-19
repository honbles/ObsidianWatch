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

HELPER_VERSION = "py-1"
_logger = None


def init(resource, endpoint="http://127.0.0.1:4318/v1/logs"):
    """Call once at start-up with the same Resource used for tracing."""
    global _logger
    provider = LoggerProvider(resource=resource)
    provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(endpoint=endpoint), schedule_delay_millis=1000))
    _logger = provider.get_logger("obsidianwatch.security", HELPER_VERSION)
    return provider


def emit(event_name, **attrs):
    """Emit one helper event. event_name must be one of the names listed in docs/app/api.md."""
    if _logger is None:
        return
    attributes = {"event.name": event_name, "helper_version": HELPER_VERSION}
    attributes.update({k: str(v) for k, v in attrs.items() if v not in (None, "")})
    kw = dict(timestamp=time.time_ns(), observed_timestamp=time.time_ns(), severity_number=SeverityNumber.WARN,
              severity_text="WARN", body=event_name, attributes=attributes)
    try:
        _logger.emit(event_name=event_name, **kw)  # opentelemetry-sdk 1.40+ (emit takes keyword arguments)
    except TypeError:
        from opentelemetry.sdk._logs import LogRecord  # older SDKs
        _logger.emit(LogRecord(**kw))


def login(outcome, user=None, client=None, route=None, mfa=None):
    emit("auth.login", outcome=outcome, user=user, **{"client.address": client}, route=route, mfa=mfa)


def input_rejected(kind, route=None, parameter=None, client=None):
    emit("input.rejected", kind=kind, route=route, parameter=parameter, **{"client.address": client})


def rate_limited(limit_name, route=None, client=None):
    emit("ratelimit.hit", limit_name=limit_name, route=route, **{"client.address": client})


def authz_denied(resource_type, action, user=None, route=None, client=None):
    emit("authz.deny", resource_type=resource_type, action=action, user=user, route=route, **{"client.address": client})
