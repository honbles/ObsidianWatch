'use strict'
// ObsidianWatch sample application - Node (Express + OpenTelemetry SDK).
// INTENTIONALLY VULNERABLE (fake SQL layer that errors on injection-looking input, and a debug
// endpoint that runs a shell command). Refuses to start unless OW_ALLOW_VULN_DEMO=1 and only binds
// 127.0.0.1. Never deploy it.   Run: OW_ALLOW_VULN_DEMO=1 node app.js   (agent receiver on 127.0.0.1:4318)
if (process.env.OW_ALLOW_VULN_DEMO !== '1') {
  console.error('This sample is intentionally vulnerable. Set OW_ALLOW_VULN_DEMO=1 to run it (binds 127.0.0.1 only).')
  process.exit(1)
}
const { NodeSDK } = require('@opentelemetry/sdk-node')
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http')
const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http')
const { ExpressInstrumentation } = require('@opentelemetry/instrumentation-express')
const { Resource } = require('@opentelemetry/resources')
const { trace } = require('@opentelemetry/api')
const security = require('./ow-security')

const ENDPOINT = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://127.0.0.1:4318'
const resource = new Resource({
  'service.name': process.env.OTEL_SERVICE_NAME || 'sample-node',
  'deployment.environment.name': 'demo',
  'service.version': '1.0.0',
})
const sdk = new NodeSDK({
  resource,
  traceExporter: new OTLPTraceExporter({ url: ENDPOINT + '/v1/traces' }),
  instrumentations: [new HttpInstrumentation(), new ExpressInstrumentation()],
})
sdk.start()
security.init(resource, ENDPOINT + '/v1/logs')

const express = require('express')
const { execFile } = require('child_process')
const app = express()
app.use(express.json())
const USERS = { alice: 'correct-horse' }

class SqlSyntaxError extends Error { constructor(m) { super(m); this.name = 'SqlSyntaxError' } } // JS records err.name as the exception type, so set it

// The instrumentation records the peer address; also record the client address on the active span.
app.use((req, _res, next) => {
  const span = trace.getActiveSpan()
  if (span) { span.setAttribute('client.address', req.socket.remoteAddress); span.setAttribute('network.peer.address', req.socket.remoteAddress) }
  next()
})

app.get('/health', (_req, res) => res.json({ ok: true }))

app.post('/login', (req, res) => {
  const { user = '', password = '' } = req.body || {}
  if (USERS[user] === password && password) {
    security.login('success', { user, client: req.socket.remoteAddress, route: '/login' })
    return res.json({ token: 'demo-token' })
  }
  security.login('failure', { user, client: req.socket.remoteAddress, route: '/login' })
  res.status(401).json({ error: 'invalid credentials' })
})

app.get('/orders/:orderId', (req, res) => res.json({ id: Number(req.params.orderId), status: 'shipped' }))

app.get('/search', (req, res, next) => {
  const q = String(req.query.q || '')
  if (q.includes("'") || q.includes('--') || q.toLowerCase().includes(' or ')) {
    security.inputRejected('sqli', { route: '/search', parameter: 'q', client: req.socket.remoteAddress })
    const err = new SqlSyntaxError('syntax error near the supplied search text')
    trace.getActiveSpan()?.recordException(err)
    return next(err)
  }
  res.json({ results: [] })
})

// Intentionally vulnerable: runs a command given by the caller (rule APP-H01 should fire).
app.get('/debug/exec', (req, res) => {
  execFile('/bin/sh', ['-c', String(req.query.cmd || 'id')], { timeout: 10000 }, (_e, out) => res.json({ output: String(out).slice(0, 500) }))
})

app.use((err, _req, res, _next) => res.status(500).json({ error: err.message }))

const server = app.listen(Number(process.env.PORT || 5002), '127.0.0.1')
process.on('SIGTERM', () => { sdk.shutdown().finally(() => server.close(() => process.exit(0))) })
