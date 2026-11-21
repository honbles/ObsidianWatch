'use strict'
// ObsidianWatch request-field helper for Node (optional, Express or any framework with a parsed body).
// It hands the PARSED request body to the local agent as one span attribute. The agent decides what
// leaves the host: field names always, values only for routes an admin has reviewed, never fields on the
// deny list (password, token, card ...). Nothing is sent anywhere except the agent on this host.
//
// Use:
//   const payload = require('./ow-payload')
//   new HttpInstrumentation({ requestHook: payload.requestHook })   // remembers the server span
//   app.use(express.json()); app.use(payload.middleware())          // after body parsing

const { trace } = require('@opentelemetry/api')

const MAX_BYTES = 32 * 1024
const SPAN = Symbol('ow.serverSpan')

// HttpInstrumentation requestHook: keep the server span, which is the one the agent reads.
function requestHook(span, request) {
  try { if (request && request.headers) request[SPAN] = span } catch (_) { /* never affect the app */ }
}

// Record a parsed body for a request. Works for any framework: pass the raw Node request (Fastify:
// request.raw, Koa: ctx.req) and its parsed body object.
function record(req, body) {
  try {
    const span = (req && req[SPAN]) || trace.getActiveSpan()
    const ct = String(req && req.headers && req.headers['content-type'] || '')
    if (span && body && typeof body === 'object' && !/multipart|octet-stream/i.test(ct)) {
      const s = JSON.stringify(body)
      if (s && s.length <= MAX_BYTES) span.setAttribute('ow.request.body', s)
    }
  } catch (_) { /* observability must never break a request */ }
}

// Express (or anything that sets req.body): use after the body parser.
function middleware() {
  return function owPayload(req, _res, next) {
    record(req, req.body)
    next()
  }
}

module.exports = { requestHook, middleware, record }
