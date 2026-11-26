'use strict'
// ObsidianWatch security helper for Node (optional). Emits the security events the Application rules
// read as OpenTelemetry log records to the local agent. Pass identifiers only, never request bodies,
// parameter values or headers (the agent drops them anyway).
// init() works with sdk-logs 0.x and 1.x; OW_SECURITY_CONSOLE=1 echoes events to stdout for debugging.
const { logs, SeverityNumber } = require('@opentelemetry/api-logs')
const { LoggerProvider, BatchLogRecordProcessor } = require('@opentelemetry/sdk-logs')
const { OTLPLogExporter } = require('@opentelemetry/exporter-logs-otlp-http')

const HELPER_VERSION = 'js-2'
let logger = null

// sdk-logs 0.x processors take (exporter, config); newer ones take ({ exporter, ...config }). Build whichever works.
function makeProcessor(Cls, exporter, config) {
  const legacy = new Cls(exporter, config)
  if (legacy && legacy._exporter) return legacy
  return new Cls(Object.assign({ exporter }, config))
}

function init(resource, endpoint) {
  const processors = [makeProcessor(BatchLogRecordProcessor, new OTLPLogExporter({ url: endpoint }), { scheduledDelayMillis: 1000 })]
  if (process.env.OW_SECURITY_CONSOLE === '1') { // print each security event to stdout as well (debugging)
    const { SimpleLogRecordProcessor, ConsoleLogRecordExporter } = require('@opentelemetry/sdk-logs')
    processors.push(makeProcessor(SimpleLogRecordProcessor, new ConsoleLogRecordExporter(), {}))
  }
  let provider
  if (typeof LoggerProvider.prototype.addLogRecordProcessor === 'function') { // sdk-logs 0.x
    provider = new LoggerProvider({ resource })
    processors.forEach((p) => provider.addLogRecordProcessor(p))
  } else { // sdk-logs 1.x and later: processors go in the constructor
    provider = new LoggerProvider({ resource, processors })
  }
  logs.setGlobalLoggerProvider(provider)
  logger = provider.getLogger('obsidianwatch.security', HELPER_VERSION)
  return provider
}

function emit(eventName, attrs = {}) {
  if (!logger) return
  const attributes = { 'event.name': eventName, helper_version: HELPER_VERSION }
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null && v !== '') attributes[k] = String(v)
  logger.emit({ severityNumber: SeverityNumber.WARN, severityText: 'WARN', body: eventName, attributes })
}

// One helper per event name the agent accepts. Attribute names are the ones the agent keeps
// (docs/application/capability.md 4.3); anything else is dropped on the host. user, session and
// object_id are pseudonymised by the agent unless the service is set to cleartext users.
const c = (client) => ({ 'client.address': client })
module.exports = {
  init, emit, HELPER_VERSION,
  login: (outcome, { user, client, route, method, reason, mfa } = {}) =>
    emit('auth.login', { outcome, user, route, method, reason, mfa, ...c(client) }),
  mfa: (outcome, { user, client, route, method, reason } = {}) =>
    emit('auth.mfa', { outcome, user, route, method, reason, ...c(client) }),
  authzDenied: (resourceType, action, { user, route, client, policy } = {}) =>
    emit('authz.deny', { resource_type: resourceType, action, user, route, policy, ...c(client) }),
  inputRejected: (kind, { route, parameter, client } = {}) =>
    emit('input.rejected', { kind, route, parameter, ...c(client) }),
  ssrfBlocked: (targetHost, { route, client, reason } = {}) =>
    emit('ssrf.blocked', { target_host: targetHost, route, reason, ...c(client) }),
  deserializationBlocked: (typeName, { route, client } = {}) =>
    emit('deserialization.blocked', { type_name: typeName, route, ...c(client) }),
  rateLimited: (limitName, { route, client, user } = {}) =>
    emit('ratelimit.hit', { limit_name: limitName, route, user, ...c(client) }),
  adminAction: (action, { user, targetType, targetId, outcome = 'success', route, client } = {}) =>
    emit('admin.action', { action, user, target_type: targetType, target_id: targetId, outcome, route, ...c(client) }),
  dataExport: (objectType, { user, format, rows, bytes, route, client } = {}) =>
    emit('data.export', { object_type: objectType, user, format, rows, bytes, route, ...c(client) }),
  dataAccess: (objectType, objectId, { user, action = 'read', route, client } = {}) =>
    emit('data.access', { object_type: objectType, object_id: objectId, user, action, route, ...c(client) }),
  sessionAnomaly: (kind, { user, session, reason, route, client } = {}) =>
    emit('session.anomaly', { kind, user, session, reason, route, ...c(client) }),
}
