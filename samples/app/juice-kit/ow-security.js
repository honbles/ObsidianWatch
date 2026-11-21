'use strict'
// ObsidianWatch security helper for Node (optional). Emits the security events the Application rules
// read as OpenTelemetry log records to the local agent. Pass identifiers only, never request bodies,
// parameter values or headers (the agent drops them anyway).
// init() works with sdk-logs 0.x and 1.x; OW_SECURITY_CONSOLE=1 echoes events to stdout for debugging.
const { logs, SeverityNumber } = require('@opentelemetry/api-logs')
const { LoggerProvider, BatchLogRecordProcessor } = require('@opentelemetry/sdk-logs')
const { OTLPLogExporter } = require('@opentelemetry/exporter-logs-otlp-http')

const HELPER_VERSION = 'js-1'
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

module.exports = {
  init, emit,
  login: (outcome, { user, client, route, mfa } = {}) => emit('auth.login', { outcome, user, 'client.address': client, route, mfa }),
  inputRejected: (kind, { route, parameter, client } = {}) => emit('input.rejected', { kind, route, parameter, 'client.address': client }),
  rateLimited: (limitName, { route, client } = {}) => emit('ratelimit.hit', { limit_name: limitName, route, 'client.address': client }),
  authzDenied: (resourceType, action, { user, route, client } = {}) => emit('authz.deny', { resource_type: resourceType, action, user, route, 'client.address': client }),
}
