// The state rules, in one place, so every page that shows a host or service state agrees.
const SEVW = { 5: 'critical', 4: 'high', 3: 'medium', 2: 'low', 1: 'info' }

export const isProbe = (a) => (a.os || '').toLowerCase().includes('network-probe')

// Hosts have no health verdict: they are online or offline (a.online). Open alerts are shown beside them.

export function alertsByHost(alerts) {
  const m = {}
  for (const a of alerts) { const x = m[a.host || ''] || (m[a.host || ''] = { n: 0, max: 0 }); x.n++; x.max = Math.max(x.max, a.severity || 0) }
  return m
}

// Service (list level, from RED totals): no traffic → none; error rate ≥ 5% → crit;
// error rate ≥ 1% or p95 over the latency target → warn; else ok. The service page adds SLO budget and alerts.
export function serviceListState(svc) {
  const t = svc.red
  if (!t || !t.calls) return { state: 'none', why: 'No requests in range' }
  const target = svc.settings?.latency_target_ms
  if (t.error_rate >= 0.05) return { state: 'crit', why: `Error rate ${(t.error_rate * 100).toFixed(1)}%` }
  if (t.error_rate >= 0.01) return { state: 'warn', why: `Error rate ${(t.error_rate * 100).toFixed(1)}%` }
  if (target && t.p95_ms > target) return { state: 'warn', why: `p95 ${Math.round(t.p95_ms)} ms over the ${target} ms target` }
  return { state: 'ok', why: 'Error rate and latency within limits' }
}
