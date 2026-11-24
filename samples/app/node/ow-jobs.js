'use strict'
// ObsidianWatch job helper for Node (optional). Wrap a function that runs on a schedule or from a queue so every
// run is reported as one operation: runs, failures, duration and the time of the last run. A missed run raises an
// alert once the job has a steady cadence. Needs only @opentelemetry/api (installed with the SDK).
//
//   const { job } = require('./ow-jobs')
//   const nightly = job('nightly-report', async () => { ... })
//   setInterval(nightly, 10 * 60 * 1000)        // or cron.schedule('*/10 * * * *', nightly)
//
// Use a stable name with no ids in it ("sync-inventory", not "sync-inventory-8842"). The name is the only thing
// sent; arguments and results never are.
const { trace, context, SpanKind, SpanStatusCode, ROOT_CONTEXT } = require('@opentelemetry/api')

const tracer = trace.getTracer('obsidianwatch.jobs', 'js-1')

function job(name, fn) {
  if (typeof name !== 'string' || !name) throw new Error('job name is required')
  return async function wrapped(...args) {
    const span = tracer.startSpan(name, { kind: SpanKind.INTERNAL, attributes: { 'ow.job.name': name.slice(0, 96) } }, ROOT_CONTEXT)
    try {
      return await context.with(trace.setSpan(ROOT_CONTEXT, span), () => fn.apply(this, args))
    } catch (err) {
      span.recordException(err)
      span.setStatus({ code: SpanStatusCode.ERROR })
      throw err
    } finally {
      span.end()
    }
  }
}

module.exports = { job }
