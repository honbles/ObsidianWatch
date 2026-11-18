import { useMemo, useState } from 'react'
import { DataTable } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appInt, appPct, appMs, appRel } from '../../../components/app/appFormat'

const tag = (cls, t) => <span key={t} className={`ml-1 text-[10px] rounded border px-1 ${cls}`}>{t}</span>

// Route inventory with RED, new routes flagged, login / export / public tags (spec 11.3).
export default function AppTabRoutes({ service, range, focus }) {
  const [q, setQ] = useState(focus || '')
  const { data, loading, error } = useAppLoad(() => appApi.routes(service.id, range), [service.id, range.from, range.to])
  const st = service.settings
  const rows = useMemo(() => {
    const base = new Date(service.first_seen).getTime() + 3600e3
    return (data?.routes || []).filter(r => !q || r.route.toLowerCase().includes(q.toLowerCase())).map(r => ({
      ...r, isNew: new Date(r.first_seen) >= new Date(range.from) && new Date(r.first_seen).getTime() > base,
    }))
  }, [data, q, service.first_seen, range.from])
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
      <div className="card"><DataTable columns={cols} rows={rows} loading={loading} error={error} rowKey={(r) => r.method + r.route}
        emptyText="No routes yet. Routes appear once this service sends OpenTelemetry server spans with http.route." initialSort={{ key: 'calls', dir: 'desc' }} /></div>
      {service.attrs?.route_overflow > 0 && (
        <div className="text-[11px] text-amber-300">{appInt(service.attrs.route_overflow)} requests were counted under "other" because this service exceeded the per-service route limit. Check that http.route is a template, not a raw path.</div>
      )}
    </div>
  )
}
