import { useEffect, useState } from 'react'
import api from '../../api/client'

const STATUS_ORDER = { fail: 0, unknown: 1, pass: 2 }
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }
const STATUS_CLS = { pass: 'text-emerald-400', fail: 'text-red-400', unknown: 'text-amber-400' }

// TabCompliance shows the endpoint compliance (hardening) posture reported by
// the agent's vulnerability scan. The agent scans 30s after start and then
// every 5 days, so a freshly installed host shows "waiting for first scan".
export function TabCompliance({ agent }) {
  const [hc, setHc] = useState(null)
  const [state, setState] = useState('loading') // loading | ok | waiting | error
  const [err, setErr] = useState('')
  const [filter, setFilter] = useState('issues')

  const load = async () => {
    setState('loading')
    try {
      const r = await api.get('/api/v1/agents/' + encodeURIComponent(agent.hostname) + '/compliance')
      setHc(r.data); setState('ok')
    } catch (e) {
      if (e.response?.status === 404) setState('waiting')
      else { setErr(e.response?.data?.error || 'Could not load compliance'); setState('error') }
    }
  }
  useEffect(() => { load() }, [agent.hostname])

  const checks = (hc?.checks || []).filter(c => filter === 'all' || c.status !== 'pass')
    .sort((a, b) => (STATUS_ORDER[a.status] ?? 3) - (STATUS_ORDER[b.status] ?? 3)
      || (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4))
  const hasPosture = (hc?.checks || []).some(c => /^EC-/.test(c.id))

  return (
    <div className="p-5 overflow-y-auto h-full">
      <div className="flex items-center gap-3 mb-4">
        <h3 className="text-sm font-semibold text-siem-text">Device compliance</h3>
        <button onClick={load} className="text-xs px-3 py-1.5 rounded-lg border border-siem-border bg-siem-surface hover:bg-siem-bg">Refresh</button>
        {state === 'ok' && (
          <select value={filter} onChange={e => setFilter(e.target.value)} className="text-xs bg-siem-surface border border-siem-border rounded-lg px-2 py-1.5 text-siem-text">
            <option value="issues">Failed / unknown only</option>
            <option value="all">All checks</option>
          </select>
        )}
      </div>

      {state === 'loading' && <div className="text-sm text-siem-muted">Loading…</div>}
      {state === 'error' && <div className="text-sm text-red-400">{err}</div>}
      {state === 'waiting' && (
        <div className="text-sm text-siem-muted bg-siem-surface border border-siem-border rounded-xl p-4">
          Waiting for the first scan from this host. The agent runs a scan about 30 seconds after it starts, then every 5 days.
          If this host was installed before the compliance collector existed, rebuild the agent in Agent Builder and reinstall it.
        </div>
      )}
      {state === 'ok' && (<>
        <div className="mb-3 flex flex-wrap gap-4 text-xs">
          <span className="text-emerald-400">{hc.passed} passed</span>
          <span className="text-red-400">{hc.failed ?? (hc.total - hc.passed)} failed</span>
          {hc.unknown > 0 && <span className="text-amber-400">{hc.unknown} could not be checked</span>}
          <span className="text-siem-muted">{hc.scope}</span>
        </div>
        {!hasPosture && (
          <div className="mb-3 text-xs text-amber-400 bg-siem-surface border border-siem-border rounded-xl p-3">
            This scan has no posture results — the agent on this host is an older build. Rebuild it in Agent Builder and reinstall to get the full compliance checks.
          </div>
        )}
        <div className="bg-siem-surface border border-siem-border rounded-xl">
          {checks.length === 0 && <div className="px-4 py-6 text-sm text-siem-muted text-center">Nothing to show.</div>}
          {checks.map(c => (
            <div key={c.id} className="px-4 py-2 border-b border-siem-border/15 last:border-0 text-[11px]">
              <span className={STATUS_CLS[c.status] || 'text-siem-muted'}>{(c.status || '').toUpperCase()}</span>
              <span className="ml-2 text-siem-text">{c.id} {c.title}</span>
              {c.category && <span className="ml-2 text-siem-muted/60">{c.category}</span>}
              {c.status !== 'pass' && c.severity && <span className="ml-2 text-siem-muted uppercase">{c.severity}</span>}
              {c.status !== 'pass' && <div className="text-siem-muted mt-0.5">{c.detail ? c.detail + ' — ' : ''}{c.fix}</div>}
            </div>
          ))}
        </div>
      </>)}
    </div>
  )
}
