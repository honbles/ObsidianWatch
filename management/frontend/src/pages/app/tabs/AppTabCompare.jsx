import { useState } from 'react'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appInt, appMs } from '../../../components/app/appFormat'

const pct = v => `${((v || 0) * 100).toFixed(1)}%`
const delta = (a, b, f, worseUp = true) => {
  if (a == null || b == null) return <span className="text-siem-muted">-</span>
  const d = b - a
  if (Math.abs(d) < 1e-9) return <span className="text-siem-muted">same</span>
  const bad = worseUp ? d > 0 : d < 0
  return <span className={bad ? 'text-red-300' : 'text-emerald-300'}>{d > 0 ? '+' : ''}{f(d)}</span>
}

// Two versions side by side: what changed in traffic, errors and latency, and what is new in the later one.
export default function AppTabCompare({ service, versions }) {
  const vs = (versions || []).map(v => v.version)
  const [a, setA] = useState(vs[1] || '')
  const [b, setB] = useState(vs[0] || '')
  const ready = a && b && a !== b
  const { data, loading, error } = useAppLoad(() => (ready ? appApi.compare(service.id, a, b) : Promise.resolve(null)), [service.id, a, b])
  if (vs.length < 2) return <div className="card p-4 text-xs text-siem-muted">Needs two versions of this service (service.version).</div>
  const sel = (val, set) => <select className="bg-siem-surface2 border border-siem-border rounded px-1.5 py-1 text-siem-text" value={val} onChange={e => set(e.target.value)}>{vs.map(v => <option key={v}>{v}</option>)}</select>
  const row = (label, x, y, f, worseUp = true) => (
    <tr className="border-t border-siem-border/50"><td className="px-3 py-1.5 text-siem-muted">{label}</td><td className="text-right">{f(x)}</td><td className="text-right">{f(y)}</td><td className="text-right px-3">{delta(x, y, f, worseUp)}</td></tr>)
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-xs text-siem-muted">Compare {sel(a, setA)} with {sel(b, setB)}</div>
      {!ready ? <div className="card p-4 text-xs text-siem-muted">Pick two different versions.</div>
        : error ? <div className="card p-4 text-xs text-red-300">{String(error)}</div>
        : loading || !data ? <div className="card p-4 text-xs text-siem-muted">Loading...</div> : (
          <>
            <div className="card"><table className="w-full text-xs">
              <thead><tr className="text-siem-muted"><th className="text-left px-3 py-2"></th><th className="text-right">{a}</th><th className="text-right">{b}</th><th className="text-right px-3">Change</th></tr></thead>
              <tbody>
                {row('Calls', data.a.calls, data.b.calls, appInt, false)}
                {row('Error rate', data.a.error_rate, data.b.error_rate, pct)}
                {row('p50', data.a.p50_ms, data.b.p50_ms, appMs)}
                {row('p95', data.a.p95_ms, data.b.p95_ms, appMs)}
              </tbody></table></div>
            <div className="grid md:grid-cols-3 gap-2">
              {[['New routes', data.new_routes], ['New error groups', data.new_error_groups], ['New dependencies', data.new_dependencies]].map(([t, l]) => (
                <div key={t} className="card"><div className="card-head"><span className="text-sm font-medium text-siem-text">{t} in {b}</span></div>
                  {(l || []).length === 0 ? <div className="p-3 text-xs text-siem-muted">None</div> : <ul className="p-3 text-xs space-y-1 font-mono">{l.map(x => <li key={x} className="break-all">{x}</li>)}</ul>}</div>))}
            </div>
            <div className="card"><table className="w-full text-xs">
              <thead><tr className="text-siem-muted text-left"><th className="px-3 py-2">Route</th><th className="text-right">Calls {a}</th><th className="text-right">Calls {b}</th><th className="text-right">Errors {a}</th><th className="text-right">Errors {b}</th><th className="text-right">p95 {a}</th><th className="text-right">p95 {b}</th><th className="text-right px-3">Change</th></tr></thead>
              <tbody>{(data.routes || []).map(r => (
                <tr key={r.method + r.route} className="border-t border-siem-border/50">
                  <td className="px-3 py-1.5 font-mono">{r.method} {r.route}{!r.a && <span className="ml-1 text-sky-300">new</span>}{!r.b && <span className="ml-1 text-siem-muted">gone</span>}</td>
                  <td className="text-right">{r.a ? appInt(r.a.calls) : '-'}</td><td className="text-right">{r.b ? appInt(r.b.calls) : '-'}</td>
                  <td className="text-right">{r.a ? pct(r.a.error_rate) : '-'}</td><td className="text-right">{r.b ? pct(r.b.error_rate) : '-'}</td>
                  <td className="text-right">{r.a ? appMs(r.a.p95_ms) : '-'}</td><td className="text-right">{r.b ? appMs(r.b.p95_ms) : '-'}</td>
                  <td className="text-right px-3">{r.a && r.b ? delta(r.a.p95_ms, r.b.p95_ms, appMs) : '-'}</td></tr>))}</tbody></table></div>
            <div className="text-xs text-siem-muted">Latency comes from the histogram, so it is approximate.</div>
          </>)}
    </div>
  )
}
