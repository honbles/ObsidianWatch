'use strict'
// ObsidianWatch preload for OWASP Juice Shop (Node). Loaded with NODE_OPTIONS="--require <this file>".
//
// Replaces @opentelemetry/auto-instrumentations-node/register so one thing can be added: the HTTP
// instrumentation gets ow-payload's requestHook (it remembers the server span), and Juice Shop's body
// parsers are wrapped so that, right after a request body has been parsed, ow-payload hands the parsed
// body to the local agent as the span attribute "ow.request.body". The agent turns that into field names
// (values only for routes an admin has reviewed; password, token, card ... never).
//
// Juice Shop is not edited. Its body parsing is `app.use(express.text(...))` followed by its own
// `jsonParser` function, plus `express.urlencoded()`. This file wraps app.use() so that middleware named
// jsonParser / urlencodedParser (the names body-parser gives its functions) is followed by the capture.
//
// Security events (the Security tab, Tier 2): Juice Shop never calls the ObsidianWatch security helper, so this
// file watches each finished response and reports, through ow-security.js, what the helper would:
//   auth.login      POST /rest/user/login, success on 2xx, failure otherwise (user = the email field)
//   authz.deny      any other route answering 401 or 403
//   input.rejected  a 500 on a request whose query string looks like SQL injection (heuristic)
//
// Env: OW_JUICE_DIR   Juice Shop directory (default: current directory)
//      OW_BODY_CAPTURE=0     start without request-body capture
//      OW_SECURITY_EVENTS=0  do not report security events
//      OW_SECURITY_CONSOLE=1 also print each security event to the Juice Shop log
const path = require('path')
const { createRequire } = require('module')

if (process.env.OW_JUICE_PRELOADED === '1') return // child processes of Juice Shop: do not start a second SDK
process.env.OW_JUICE_PRELOADED = '1'

const api = require('@opentelemetry/api')
const { NodeSDK } = require('@opentelemetry/sdk-node')
const { getNodeAutoInstrumentations, getResourceDetectors } = require('@opentelemetry/auto-instrumentations-node')
const payload = require('./ow-payload')

const bodyCapture = process.env.OW_BODY_CAPTURE !== '0'
const securityEvents = process.env.OW_SECURITY_EVENTS !== '0'
const log = (m) => process.stderr.write('[ow-juice-preload] ' + m + '\n')

// ---- security events -------------------------------------------------------------------------------------
let security = null
let securityProvider = null
if (securityEvents) {
  try {
    security = require('./ow-security')
    const attrs = { 'service.name': process.env.OTEL_SERVICE_NAME || 'juice-shop', 'telemetry.sdk.language': 'nodejs', 'telemetry.sdk.name': 'opentelemetry' }
    for (const kv of String(process.env.OTEL_RESOURCE_ATTRIBUTES || '').split(',')) {
      const i = kv.indexOf('=')
      if (i > 0) attrs[kv.slice(0, i).trim()] = kv.slice(i + 1).trim()
    }
    const res = require('@opentelemetry/resources')
    const resource = res.resourceFromAttributes ? res.resourceFromAttributes(attrs) : new res.Resource(attrs)
    const base = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://127.0.0.1:4318'
    securityProvider = security.init(resource, base.replace(/\/$/, '') + '/v1/logs')
    log('security events enabled (auth.login, authz.deny, input.rejected)')
  } catch (e) {
    security = null
    log('security events not enabled (' + e.message + ')')
  }
}

const INJECTION = /('|%27|--|\bunion\b.+\bselect\b|\bor\b\s+\d+\s*=\s*\d+)/i
function reportSecurity(req, res) {
  try {
    if (!security) return
    const status = res.statusCode
    const client = req.socket && req.socket.remoteAddress
    const route = (req.route && typeof req.route.path === 'string') ? (req.baseUrl || '') + req.route.path : String(req.url || '').split('?')[0]
    if (req.method === 'POST' && /^\/rest\/user\/login\/?$/.test(route)) {
      const user = req.body && typeof req.body === 'object' ? req.body.email : undefined
      security.login(status >= 200 && status < 300 ? 'success' : 'failure', { user, client, route })
      return
    }
    if (status === 401 || status === 403) security.authzDenied('route', req.method, { route, client })
    const q = String(req.url || '').split('?')[1] || ''
    if (status >= 500 && q && INJECTION.test(q)) security.inputRejected('sqli', { route, client })
  } catch (_) { /* never affect the app */ }
}
const httpHooks = {}
if (bodyCapture) httpHooks.requestHook = payload.requestHook
if (security) {
  httpHooks.responseHook = (_span, response) => {
    try { if (response && typeof response.once === 'function' && response.req) response.once('finish', () => reportSecurity(response.req, response)) } catch (_) { /* ignore */ }
  }
}

const instrumentations = getNodeAutoInstrumentations(
  Object.keys(httpHooks).length ? { '@opentelemetry/instrumentation-http': httpHooks } : {})
const sdk = new NodeSDK({ instrumentations, resourceDetectors: getResourceDetectors() })
try { sdk.start(); log('OpenTelemetry SDK started') } catch (e) { log('SDK start failed: ' + e.message) }
let closing = false
const flush = () => Promise.allSettled([sdk.shutdown(), securityProvider ? securityProvider.shutdown() : null])
// Having a SIGTERM listener stops node from exiting on SIGTERM, so flush telemetry and then re-raise the signal
// (unless Juice Shop registered its own handler, which then decides) or `./ow-juice.sh stop` would not stop it.
function onSigterm() {
  if (closing) return
  closing = true
  const done = () => { process.removeListener('SIGTERM', onSigterm); if (process.listenerCount('SIGTERM') === 0) process.kill(process.pid, 'SIGTERM') }
  flush().then(done, done)
  setTimeout(done, 3000).unref()
}
process.on('SIGTERM', onSigterm)
process.once('beforeExit', () => { if (!closing) { closing = true; flush() } })

if (bodyCapture) {
  try {
    // Load Juice Shop's own express AFTER the SDK started, so the express instrumentation patches it first.
    const juiceRequire = createRequire(path.join(path.resolve(process.env.OW_JUICE_DIR || process.cwd()), 'package.json'))
    const express = juiceRequire('express')
    const capture = payload.middleware()
    const PARSERS = new Set(['jsonParser', 'urlencodedParser'])
    const wrap = (fn) => {
      const wrapped = function (req, res, next) {
        return fn.call(this, req, res, function () {
          try { capture(req, res, () => {}) } catch (_) { /* never affect the app */ }
          return next.apply(this, arguments)
        })
      }
      Object.defineProperty(wrapped, 'name', { value: fn.name })
      return wrapped
    }
    const origUse = express.application.use
    let hooked = new Set()
    express.application.use = function () {
      for (let i = 0; i < arguments.length; i++) {
        const a = arguments[i]
        if (typeof a === 'function' && PARSERS.has(a.name) && !a.__owWrapped) {
          arguments[i] = wrap(a)
          arguments[i].__owWrapped = true
          if (!hooked.has(a.name)) { hooked.add(a.name); log('request-body capture hooked after ' + a.name) }
        }
      }
      return origUse.apply(this, arguments)
    }
  } catch (e) {
    log('body capture not enabled (' + e.message + '); routes and query parameters still work')
  }
}
void api
