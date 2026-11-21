import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTimeRange, DataTable } from '../../components/shared'
import { appApi } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import AppPageHeader from '../../components/app/AppPageHeader'
import { AppTierBadge, AppExposureBadge, AppCriticalityBadge } from '../../components/app/AppBadges'
import { appInt, appPct, appMs, appRel, appIsAdmin } from '../../components/app/appFormat'

export const appPath = '/applications/services'
const sel = 'bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text'

// Services: what are we running? (spec 11.3)
export default function AppServices() {
  const range = useTimeRange(24 * 3600e3)
  const navigate = useNavigate()
  const admin = appIsAdmin()
  const [q, setQ] = useState('')
  const [env, setEnv] = useState('')
  const [exposure, setExposure] = useState('')
  const [tier, setTier] = useState('')
  const [picked, setPicked] = useState({})
  const [bulk, setBulk] = useState({ exposure: '', criticality: '', busy: false, msg: '' })
  const { data, loading, error, reload } = useAppLoad(() => appApi.services(range, { limit: 500 }), [range.from, range.to])
  const all = data?.services || []
  const envs = useMemo(() => [...new Set(all.map(s => s.environment))].sort(), [all])
  const rows = useMemo(() => all.filter(s =>
    (!q || s.name.toLowerCase().includes(q.toLowerCase())) && (!env || s.environment === env) &&
    (!exposure || s.settings.exposure === exposure) && (tier === '' || String(s.tier) === tier)), [all, q, env, exposure, tier])
  const ids = Object.keys(picked).filter(k => picked[k])

  const applyBulk = async () => {
    setBulk(b => ({ ...b, busy: true, msg: '' }))
    let ok = 0, fail = 0
    for (const id of ids) {
      const s = all.find(x => String(x.id) === id)
      if (!s) continue
      // PUT replaces the whole settings object, so send the current values with the change merged in.
      const body = { ...s.settings, exposure: bulk.exposure || s.settings.exposure, criticality: bulk.criticality || s.settings.criticality }
      delete body.updated_at; delete body.updated_by
      try { await appApi.saveSettings(s.id, body); ok++ } catch { fail++ }
    }
    setBulk({ exposure: '', criticality: '', busy: false, msg: `${ok} updated${fail ? `, ${fail} failed` : ''}` })
    setPicked({})
    reload()
  }

  const cols = [
    ...(admin ? [{ key: 'pick', label: '', width: 30, render: s => (
      <input type="checkbox" checked={!!picked[s.id]} onClick={e => e.stopPropagation()} onChange={e => setPicked(p => ({ ...p, [s.id]: e.target.checked }))} />) }] : []),
    { key: 'name', label: 'Service', render: s => <span className="text-siem-text font-medium">{s.name}</span>, sort: s => s.name },
    { key: 'environment', label: 'Env', sort: s => s.environment },
    { key: 'runs_on', label: 'Runs on', render: s => {
      const c = s.containers || [], im = s.images || [], u = s.units || [], h = s.hosts || []
      if (c.length) return <span className="text-xs" title={im.join(', ')}><span className="font-mono">{c.slice(0, 2).join(', ')}{c.length > 2 ? ` +${c.length - 2}` : ''}</span>{im.length ? <span className="text-siem-muted"> {im[0].split('/').pop()}</span> : null}</span>
      if (u.length) return <span className="text-xs font-mono" title={h.join(', ')}>{u.slice(0, 2).join(', ')}</span>
      return <span className="text-xs text-siem-muted">{h.length ? `host ${h.slice(0, 2).join(', ')}` : '-'}</span>
    }, sort: s => (s.containers || [])[0] || (s.units || [])[0] || '' },
    { key: 'tier', label: 'Tier', render: s => <AppTierBadge tier={s.tier} />, sort: s => s.tier, width: 60 },
    { key: 'exposure', label: 'Exposure', render: s => <AppExposureBadge exposure={s.settings.exposure} settings={s.settings} />, sort: s => s.settings.exposure },
    { key: 'criticality', label: 'Criticality', render: s => <AppCriticalityBadge criticality={s.settings.criticality} />, sort: s => s.settings.criticality },
    { key: 'instances', label: 'Inst.', align: 'right', sort: s => s.instances },
    { key: 'calls', label: 'Requests', align: 'right', render: s => (s.red ? appInt(s.red.calls) : '-'), sort: s => s.red?.calls || 0 },
    { key: 'err', label: 'Error rate', align: 'right', render: s => (s.red ? <span className={s.red.error_rate > 0.05 ? 'text-red-300' : ''}>{appPct(s.red.error_rate)}</span> : '-'), sort: s => s.red?.error_rate || 0 },
    { key: 'p95', label: 'p95', align: 'right', render: s => (s.red ? appMs(s.red.p95_ms, s.red.over_range) : '-'), sort: s => s.red?.p95_ms || 0 },
    { key: 'last_seen', label: 'Last seen', render: s => appRel(s.last_seen), sort: s => s.last_seen },
  ]
  return (
    <div className="p-6 space-y-4">
      <AppPageHeader title="Services" range={range} subtitle="Every service seen on a host with an application-monitoring agent, discovered or instrumented." />
      <div className="flex flex-wrap gap-2 items-center">
        <input className={`${sel} w-56`} placeholder="Search services…" value={q} onChange={e => setQ(e.target.value)} />
        <select className={sel} value={env} onChange={e => setEnv(e.target.value)}><option value="">All environments</option>{envs.map(x => <option key={x}>{x}</option>)}</select>
        <select className={sel} value={exposure} onChange={e => setExposure(e.target.value)}><option value="">Any exposure</option><option>internet</option><option>internal</option><option>unknown</option></select>
        <select className={sel} value={tier} onChange={e => setTier(e.target.value)}><option value="">Any tier</option><option value="0">Tier 0</option><option value="1">Tier 1</option><option value="2">Tier 2</option></select>
        <span className="text-xs text-siem-muted">{rows.length} of {all.length}</span>
      </div>
      {admin && ids.length > 0 && (
        <div className="card p-3 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-siem-text">{ids.length} selected</span>
          <select className={sel} value={bulk.exposure} onChange={e => setBulk(b => ({ ...b, exposure: e.target.value }))}><option value="">Exposure: keep</option><option>internet</option><option>internal</option><option>unknown</option></select>
          <select className={sel} value={bulk.criticality} onChange={e => setBulk(b => ({ ...b, criticality: e.target.value }))}><option value="">Criticality: keep</option>{['low', 'normal', 'high', 'critical'].map(x => <option key={x}>{x}</option>)}</select>
          <button className="btn btn-primary" disabled={bulk.busy || (!bulk.exposure && !bulk.criticality)} onClick={applyBulk}>{bulk.busy ? 'Applying…' : 'Apply'}</button>
          <button className="btn btn-ghost" onClick={() => setPicked({})}>Clear</button>
        </div>
      )}
      {bulk.msg && <div className="text-xs text-emerald-300">{bulk.msg}</div>}
      <div className="card">
        <DataTable columns={cols} rows={rows} loading={loading} error={error} rowKey={s => s.id}
          onRowClick={s => navigate(`/applications/services/${encodeURIComponent(s.key)}${window.location.search}`)}
          emptyText="No services in this range. Build an agent with the app-server profile and run your application on that host."
          initialSort={{ key: 'last_seen', dir: 'desc' }} />
      </div>
    </div>
  )
}
