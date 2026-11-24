import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { DataTable } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appInt, appPct, appMs, appRel } from '../../../components/app/appFormat'
import { appReviewPath, appIsAdmin } from '../../../components/app/appFormat'
import AppSpecPanel from '../../../components/app/AppSpecPanel'

const tag = (cls, t) => <span key={t} className={`ml-1 text-[10px] rounded border px-1 ${cls}`}>{t}</span>

// Route inventory with RED, new routes flagged, login / export / public tags (spec 11.3).
export default function AppTabRoutes({ service, range, focus }) {
  const [q, setQ] = useState(focus || '')
  const [reviewOnly, setReviewOnly] = useState(false)
  const [expanded, setExpanded] = useState({}) // routes whose full parameter list is shown
  const [rev, setRev] = useState(0)
  const [bulk, setBulk] = useState(null) // { scope } while the confirm is open
  const [mode, setMode] = useState('capture')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const admin = appIsAdmin()
  const { data, loading, error } = useAppLoad(() => appApi.routes(service.id, range), [service.id, range.from, range.to, rev])
  const st = service.settings
  const rows = useMemo(() => {
    const base = new Date(service.first_seen).getTime() + 3600e3
    return (data?.routes || []).filter(r => (!q || r.route.toLowerCase().includes(q.toLowerCase())) && (!reviewOnly || r.payload_review === 'needs_review')).map(r => ({
      ...r, isNew: new Date(r.first_seen) >= new Date(range.from) && new Date(r.first_seen).getTime() > base,
    }))
  }, [data, q, reviewOnly, service.first_seen, range.from])
  const needs = (data?.routes || []).filter(r => r.payload_review === 'needs_review' && (r.params || []).length > 0).length
  const newf = (data?.routes || []).filter(r => r.payload_review === 'new_fields').length
  const runBulk = async () => {
    setBusy(true); setMsg('')
    try {
      const r = await appApi.bulkPayloadPolicy(service.id, { scope: bulk.scope, mode })
      setMsg(`Approved ${r.approved} route${r.approved === 1 ? '' : 's'}.`)
      setBulk(null); setRev(x => x + 1)
    } catch (e) { setMsg(e?.response?.data?.error || 'Could not approve.') }
    setBusy(false)
  }
  const cols = [
    { key: 'method', label: 'Method', width: 70 },
    { key: 'route', label: 'Route', render: r => (
      <span className="font-mono text-xs">{r.route}
        {r.isNew && tag('border-orange-500/40 text-orange-300', 'new')}
        {st.login_routes?.includes(r.route) && tag('border-sky-500/40 text-sky-300', 'login')}
        {st.export_routes?.includes(r.route) && tag('border-purple-500/40 text-purple-300', 'export')}
        {st.public_routes?.includes(r.route) && tag('border-slate-500/40 text-slate-300', 'public')}
        {r.declared && !r.observed && tag('border-teal-500/40 text-teal-300', 'declared, no traffic yet')}
        {r.n_plus_one_count > 0 && tag('border-amber-500/40 text-amber-300', `N+1 x${r.n_plus_one_count}`)}
        {r.not_in_spec && tag('border-amber-500/40 text-amber-300', 'not in spec')}
        {r.observed && !r.active && <span className="ml-1 text-[10px] text-siem-muted">no traffic in range</span>}
        {r.top_children?.length > 0 && (
          <span className="block text-[10px] text-siem-muted mt-0.5" title="The downstream calls that took the most total time for this route in the range">
            slowest: {r.top_children.map(c => `${c.name}${c.target ? ` (${c.target})` : ''} ${appMs(c.total_ms / Math.max(1, r.stats.calls))}/req`).join(' · ')}
          </span>)}
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
          {shown.map(p => <span key={p.name} title={`${p.name}: ${p.requests} requests${p.location ? `, ${p.location}` : ''}${p.undocumented ? '. Seen in traffic but not in the API spec.' : p.source === 'declared' ? '. Declared in the API spec, not seen yet.' : ''}`}
            className={`mr-1 inline-block rounded border px-1 font-mono text-[10px] ${p.undocumented ? 'border-amber-500/60 text-amber-300' : p.source === 'declared' ? 'border-dashed border-siem-border text-siem-muted' : 'border-siem-border'}`}>{p.name}</span>)}
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
    { key: 'apdex', label: 'Apdex', align: 'right', render: r => (r.stats.apdex != null ? <span className={r.stats.apdex < 0.7 ? 'text-red-300' : r.stats.apdex < 0.85 ? 'text-amber-300' : ''} title="Satisfied up to the latency target, tolerating up to 4 times it">{r.stats.apdex.toFixed(2)}</span> : '-'), sort: r => r.stats.apdex ?? -1 },
    { key: 'last_seen', label: 'Last seen', render: r => (r.observed ? appRel(r.last_seen) : '-'), sort: r => r.last_seen },
  ]
  return (
    <div className="space-y-2">
      <AppSpecPanel service={service} onChanged={() => setRev(x => x + 1)} />
      <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter routes…"
        className="bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text w-64" />
      <label className="ml-3 inline-flex items-center gap-1.5 text-xs text-siem-muted">
        <input type="checkbox" checked={reviewOnly} onChange={e => setReviewOnly(e.target.checked)} /> Needs review only
      </label>
      {admin && (needs > 0 || newf > 0) && (
        <div className="card p-3 text-xs space-y-2">
          <div className="flex flex-wrap items-center gap-3">
            <span>{needs > 0 && `${needs} route${needs === 1 ? '' : 's'} need review`}{needs > 0 && newf > 0 && ', '}{newf > 0 && `${newf} ha${newf === 1 ? 's' : 've'} new fields`}.</span>
            <button className="btn-primary px-2 py-1 rounded" onClick={() => setBulk({ scope: newf > 0 ? 'needs_review_and_new_fields' : 'needs_review' })}>Approve all…</button>
            {msg && <span className="text-siem-muted">{msg}</span>}
          </div>
          {bulk && (
            <div className="space-y-2 border-t border-siem-border pt-2">
              <label className="flex items-start gap-2"><input type="radio" checked={mode === 'capture'} onChange={() => setMode('capture')} />
                <span>Capture values for all fields except the always-masked ones (passwords, tokens, keys, card numbers).</span></label>
              <label className="flex items-start gap-2"><input type="radio" checked={mode === 'names_only'} onChange={() => setMode('names_only')} />
                <span>Approve but mask every field. The routes count as reviewed and no values leave the host. Unmask single fields later on the route's Review page.</span></label>
              <div className="text-siem-muted">Choices you already made on a route are kept; only its new fields are approved. Each route is written to the audit log.</div>
              <button disabled={busy} className="btn-primary px-2 py-1 rounded" onClick={runBulk}>{busy ? 'Approving…' : 'Confirm'}</button>
              <button disabled={busy} className="ml-2 text-siem-muted hover:underline" onClick={() => setBulk(null)}>Cancel</button>
            </div>)}
        </div>)}
      <div className="card"><DataTable columns={cols} rows={rows} loading={loading} error={error} rowKey={(r) => r.method + r.route}
        emptyText="No routes yet. Routes appear once this service sends OpenTelemetry server spans with http.route." initialSort={{ key: 'calls', dir: 'desc' }} /></div>
      <div className="text-[11px] text-siem-muted">Parameter names come from the request query string and are shown without values. Open Review on a route to choose which fields are masked and to see the requests captured for it. Dashed names are declared in the API spec and not seen yet; amber names were seen in traffic but are not in the spec (undocumented, a common sign of mass assignment). A route that shows "needs review" has not been reviewed; no parameter values are collected for it until it is.</div>
      {service.attrs?.route_overflow > 0 && (
        <div className="text-[11px] text-amber-300">{appInt(service.attrs.route_overflow)} requests were counted under "other" because this service exceeded the per-service route limit. Check that http.route is a template, not a raw path.</div>
      )}
    </div>
  )
}
