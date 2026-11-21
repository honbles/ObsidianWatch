import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { DataTable } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appInt, appPct, appMs, appRel } from '../../../components/app/appFormat'
import { appReviewPath } from '../../../components/app/appFormat'

const tag = (cls, t) => <span key={t} className={`ml-1 text-[10px] rounded border px-1 ${cls}`}>{t}</span>

// Route inventory with RED, new routes flagged, login / export / public tags (spec 11.3).
export default function AppTabRoutes({ service, range, focus }) {
  const [q, setQ] = useState(focus || '')
  const [reviewOnly, setReviewOnly] = useState(false)
  const [expanded, setExpanded] = useState({}) // routes whose full parameter list is shown
  const { data, loading, error } = useAppLoad(() => appApi.routes(service.id, range), [service.id, range.from, range.to])
  const st = service.settings
  const rows = useMemo(() => {
    const base = new Date(service.first_seen).getTime() + 3600e3
    return (data?.routes || []).filter(r => (!q || r.route.toLowerCase().includes(q.toLowerCase())) && (!reviewOnly || r.payload_review === 'needs_review')).map(r => ({
      ...r, isNew: new Date(r.first_seen) >= new Date(range.from) && new Date(r.first_seen).getTime() > base,
    }))
  }, [data, q, reviewOnly, service.first_seen, range.from])
  const cols = [
    { key: 'method', label: 'Method', width: 70 },
    { key: 'route', label: 'Route', render: r => (
      <span className="font-mono text-xs">{r.route}
        {r.isNew && tag('border-orange-500/40 text-orange-300', 'new')}
        {st.login_routes?.includes(r.route) && tag('border-sky-500/40 text-sky-300', 'login')}
        {st.export_routes?.includes(r.route) && tag('border-purple-500/40 text-purple-300', 'export')}
        {st.public_routes?.includes(r.route) && tag('border-slate-500/40 text-slate-300', 'public')}
        {!r.active && <span className="ml-1 text-[10px] text-siem-muted">no traffic in range</span>}
      </span>), sort: r => r.route },
    { key: 'params', label: 'Parameters', render: r => {
      const ps = r.params || []
      const k = r.method + ' ' + r.route
      if (!ps.length) {
        return <span className="text-siem-muted text-xs" title="No query-string or body fields have been reported for this route. A route that takes only a path or no input shows nothing; a POST route with no fields usually means the app is not reporting request bodies (see the Node.js and Python setup guides).">no query or body fields seen</span>
      }
      const shown = expanded[k] ? ps : ps.slice(0, 5)
      return (
        <span className="text-xs">
          {shown.map(p => <span key={p.name} title={`${p.name} (${p.requests} requests)`} className="mr-1 inline-block rounded border border-siem-border px-1 font-mono text-[10px]">{p.name}</span>)}
          {ps.length > 5 && (
            <button className="text-siem-accent hover:underline" onClick={() => setExpanded(e => ({ ...e, [k]: !e[k] }))}>
              {expanded[k] ? 'show fewer' : `+${ps.length - 5} more`}
            </button>)}
          {r.payload_review === 'needs_review' && tag('border-amber-500/40 text-amber-300', 'needs review')}
          {r.payload_review === 'new_fields' && tag('border-orange-500/40 text-orange-300', 'new fields')}
          {r.payload_review === 'reviewed' && tag('border-emerald-500/40 text-emerald-300', 'reviewed')}
          <Link className="ml-2 text-siem-accent hover:underline" to={appReviewPath(service, r.method, r.route)}>Review</Link>
        </span>)
    }, sort: r => (r.params || []).length },
    { key: 'calls', label: 'Calls', align: 'right', render: r => appInt(r.stats.calls), sort: r => r.stats.calls },
    { key: 'err', label: 'Error rate', align: 'right', render: r => <span className={r.stats.error_rate > 0.05 ? 'text-red-300' : ''}>{appPct(r.stats.error_rate)}</span>, sort: r => r.stats.error_rate },
    { key: 'auth', label: '401/403', align: 'right', render: r => appInt(r.stats.status_401_403), sort: r => r.stats.status_401_403 },
    { key: 'rl', label: '429', align: 'right', render: r => appInt(r.stats.status_429), sort: r => r.stats.status_429 },
    { key: 'p95', label: 'p95', align: 'right', render: r => appMs(r.stats.p95_ms, r.stats.over_range), sort: r => r.stats.p95_ms },
    { key: 'last_seen', label: 'Last seen', render: r => appRel(r.last_seen), sort: r => r.last_seen },
  ]
  return (
    <div className="space-y-2">
      <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter routes…"
        className="bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text w-64" />
      <label className="ml-3 inline-flex items-center gap-1.5 text-xs text-siem-muted">
        <input type="checkbox" checked={reviewOnly} onChange={e => setReviewOnly(e.target.checked)} /> Needs review only
      </label>
      <div className="card"><DataTable columns={cols} rows={rows} loading={loading} error={error} rowKey={(r) => r.method + r.route}
        emptyText="No routes yet. Routes appear once this service sends OpenTelemetry server spans with http.route." initialSort={{ key: 'calls', dir: 'desc' }} /></div>
      <div className="text-[11px] text-siem-muted">Parameter names come from the request query string and are shown without values. Open Review on a route to choose which fields are masked and to see the requests captured for it. A route that shows "needs review" has not been reviewed; no parameter values are collected for it until it is.</div>
      {service.attrs?.route_overflow > 0 && (
        <div className="text-[11px] text-amber-300">{appInt(service.attrs.route_overflow)} requests were counted under "other" because this service exceeded the per-service route limit. Check that http.route is a template, not a raw path.</div>
      )}
    </div>
  )
}
