import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTimeRange } from '../../components/shared'
import { appApi } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import { PageHeader, Num, Facets, countBy, useFacetFilter, DenseTable, StatePill, SelectionBar } from '../../components/ui'
import { serviceListState } from '../../utils/states'
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
  const ids = Object.keys(picked).filter(k => picked[k]).map(k => (isNaN(k) ? k : Number(k)))

  const applyBulk = async () => {
    setBulk(b => ({ ...b, busy: true, msg: '' }))
    let ok = 0, fail = 0
    for (const id of ids) {
      const s = all.find(x => String(x.id) === String(id))
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

  const [facets, setFacets] = useState({})
  const [sort, setSort] = useState({ key: 'rank', dir: 'desc' })
  const withState = useMemo(() => all.map((x, i) => ({ ...x, _rank: i, _st: x.tier === 0 ? { state: x.instances ? 'ok' : 'none', why: 'Host only: request health needs OpenTelemetry' } : serviceListState(x) })), [all])
  const G = useMemo(() => ({ role: x => x.role || 'other', state: x => x._st.state, env: x => x.environment, exposure: x => x.settings.exposure || 'unknown', tier: x => x.tier, crit: x => x.settings.criticality || 'normal' }), [])
  const faceted = useFacetFilter(withState, G, facets)
  const spanMin = (new Date(range.to) - new Date(range.from)) / 60000
  const ORDER = { crit: 0, warn: 1, ok: 2, none: 3 }
  const shown = useMemo(() => {
    const t = q.trim().toLowerCase()
    const d = sort.dir === 'asc' ? 1 : -1
    const by = {
      rank: (a, b) => b._rank - a._rank, // server order: T2, T1, then T0 platforms first
      state: (a, b) => (ORDER[b._st.state] - ORDER[a._st.state]) || ((b.red?.calls || 0) - (a.red?.calls || 0)),
      name: (a, b) => b.name.localeCompare(a.name),
      rpm: (a, b) => (a.red?.calls || 0) - (b.red?.calls || 0),
      err: (a, b) => (a.red?.error_rate || 0) - (b.red?.error_rate || 0),
      p95: (a, b) => (a.red?.p95_ms || 0) - (b.red?.p95_ms || 0),
    }[sort.key]
    return faceted.filter(x => !t || `${x.name} ${(x.hosts || []).join(' ')} ${(x.containers || []).join(' ')}`.toLowerCase().includes(t)).sort((a, b) => by(a, b) * d)
  }, [faceted, q, sort]) // eslint-disable-line react-hooks/exhaustive-deps
  const toggleFacet = (k, v) => setFacets(f => { const n = { ...f }; const set = new Set(n[k] || []); set.has(v) ? set.delete(v) : set.add(v); n[k] = set; return n })
  const selection = { selected: new Set(ids), onSelect: (k, v) => setPicked(p => ({ ...p, [k]: v })) }
  const n = st => withState.filter(x => x._st.state === st).length

  const cols = [
    { key: 'st', label: 'State', width: '96px', sortKey: 'state', render: x => x.tier === 0
      ? <StatePill state={x.instances ? 'ok' : 'none'} title="Host only: request health needs OpenTelemetry">{x.instances ? 'Running' : 'Stopped'}</StatePill>
      : <StatePill state={x._st.state} title={x._st.why}>{{ ok: 'OK', warn: 'Degraded', crit: 'Failing', none: 'No traffic' }[x._st.state]}</StatePill> },
    { key: 'name', label: 'Service', width: 'minmax(160px, 1.3fr)', sortKey: 'name', render: x => <span><span className="mono t1">{x.name}</span>{x.role_label && <span className="t3" style={{ fontSize: 11.5 }}> · {x.role_label}</span>}{x.code_links > 0 && <span className="t3" style={{ fontSize: 11.5 }} title="Repository linked"> · code</span>}</span> },
    { key: 'env', label: 'Env', width: '80px', render: x => <span className="t2">{x.environment}</span> },
    { key: 'runs', label: 'Runs on', width: 'minmax(140px, 1fr)', render: x => {
      const c = x.containers || [], u = x.units || [], h = x.hosts || []
      const v = c.length ? c : u.length ? u : h
      return <span className="mono t2" title={[...c, ...u, ...h].join(', ')}>{v.length ? v.slice(0, 2).join(', ') + (v.length > 2 ? ` +${v.length - 2}` : '') : '—'}</span>
    } },
    { key: 'tier', label: 'Tier', width: '56px', render: x => <AppTierBadge tier={x.tier}/> },
    { key: 'exp', label: 'Exposure', width: '96px', render: x => <AppExposureBadge exposure={x.settings.exposure} settings={x.settings}/> },
    { key: 'rpm', label: 'req/min', width: '84px', align: 'right', sortKey: 'rpm', render: x => <span className="mono">{x.red ? (x.red.calls / spanMin).toFixed(x.red.calls / spanMin < 10 ? 1 : 0) : '—'}</span> },
    { key: 'err', label: 'Errors', width: '76px', align: 'right', sortKey: 'err', render: x => <span className="mono" style={{ color: x.red?.error_rate >= 0.05 ? 'var(--crit)' : x.red?.error_rate >= 0.01 ? 'var(--warn)' : undefined }}>{x.red ? appPct(x.red.error_rate) : '—'}</span> },
    { key: 'p95', label: 'p95', width: '80px', align: 'right', sortKey: 'p95', render: x => <span className="mono" style={{ color: x.settings.latency_target_ms && x.red?.p95_ms > x.settings.latency_target_ms ? 'var(--warn)' : undefined }}>{x.red ? appMs(x.red.p95_ms, x.red.over_range) : '—'}</span> },
    { key: 'inst', label: 'Inst.', width: '52px', align: 'right', render: x => <span className="mono t2">{x.instances}</span> },
  ]
  return (
    <div>
      <PageHeader title="Services"
        state={loading ? undefined : n('crit') ? 'crit' : n('warn') ? 'warn' : all.length ? 'ok' : 'none'}
        stateText={n('crit') ? `${n('crit')} failing` : n('warn') ? `${n('warn')} degraded` : all.length ? 'All healthy' : 'No services yet'}
        sub="Every service seen on a host with an application-monitoring agent. Instrumented services (T2, T1) come first, then host-only (T0) services with databases, caches, web servers and runtimes ahead of the rest. State uses error rate and the latency target."
        nums={<>
          <Num k="Services" v={all.length}/>
          <Num k="Failing" v={n('crit')} tone={n('crit') ? 'crit' : undefined}/>
          <Num k="Degraded" v={n('warn')} tone={n('warn') ? 'warn' : undefined}/>
          <Num k="No traffic" v={n('none')}/>
          <Num k="Internet-facing" v={all.filter(x => (x.settings.exposure || x.settings.exposure_inferred) === 'internet').length}/>
        </>}/>
      <div className="ow-body" style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
        <Facets selected={facets} onToggle={toggleFacet} onClear={() => setFacets({})} groups={[
          { key: 'state', label: 'State', values: countBy(withState, G.state, ['crit', 'warn', 'ok', 'none'], { crit: 'Failing', warn: 'Degraded', ok: 'OK', none: 'No traffic' }) },
          { key: 'env', label: 'Environment', values: countBy(withState, G.env) },
          { key: 'exposure', label: 'Exposure', values: countBy(withState, G.exposure, ['internet', 'internal', 'unknown'], { internet: 'Internet', internal: 'Internal', unknown: 'Unknown' }) },
          { key: 'role', label: 'What it is', values: countBy(withState, G.role, ['app', 'database', 'cache', 'web', 'runtime', 'queue', 'search', 'other'], { app: 'Application', database: 'Database', cache: 'Cache', web: 'Web / proxy', runtime: 'App server', queue: 'Broker', search: 'Search', other: 'Other' }) },
          { key: 'tier', label: 'Telemetry tier', values: countBy(withState, G.tier, [2, 1, 0], { 2: 'T2 · security events', 1: 'T1 · OpenTelemetry', 0: 'T0 · host only' }) },
          { key: 'crit', label: 'Criticality', values: countBy(withState, G.crit, ['critical', 'high', 'normal', 'low'], { critical: 'Critical', high: 'High', normal: 'Normal', low: 'Low' }) },
        ]}/>
        <div className="ow-card" style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
          {admin && ids.length > 0 ? (
            <SelectionBar count={ids.length} total={shown.length} onClear={() => setPicked({})}
              onSelectAllMatching={() => setPicked(Object.fromEntries(shown.map(x => [x.id, true])))} allMatching={shown.every(x => picked[x.id])}>
              <select className="input" style={{ height: 26, width: 150 }} value={bulk.exposure} onChange={e => setBulk(b => ({ ...b, exposure: e.target.value }))}><option value="">Exposure: keep</option><option>internet</option><option>internal</option><option>unknown</option></select>
              <select className="input" style={{ height: 26, width: 160 }} value={bulk.criticality} onChange={e => setBulk(b => ({ ...b, criticality: e.target.value }))}><option value="">Criticality: keep</option>{['low', 'normal', 'high', 'critical'].map(x => <option key={x}>{x}</option>)}</select>
              <button className="ow-btn primary" style={{ height: 26 }} disabled={bulk.busy || (!bulk.exposure && !bulk.criticality)} onClick={applyBulk}>{bulk.busy ? 'Applying…' : 'Apply'}</button>
            </SelectionBar>
          ) : (
            <div className="ow-card-bar">
              <label className="ow-field" style={{ flex: 1, maxWidth: 380, height: 28 }}>
                <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter by service, host or container" aria-label="Filter services"/>
              </label>
              <span className="t2" style={{ fontSize: 12 }}>{shown.length} of {all.length}</span>
              {bulk.msg && <span className="c-ok" style={{ fontSize: 12 }}>{bulk.msg}</span>}
            </div>
          )}
          {error && <div className="c-crit" style={{ padding: '10px 14px' }}>{String(error)}</div>}
          <DenseTable cols={cols} rows={loading ? [] : shown} rowKey={x => x.id} rowState={x => x._st.state === 'ok' ? null : x._st.state}
            onRow={x => navigate(`/applications/services/${encodeURIComponent(x.key)}${window.location.search}`)}
            sort={sort} onSort={k => setSort(s => ({ key: k, dir: s.key === k && s.dir === 'desc' ? 'asc' : 'desc' }))}
            {...(admin ? { selected: selection.selected, onSelect: selection.onSelect, onSelectAll: v => setPicked(v ? Object.fromEntries(shown.map(x => [x.id, true])) : {}) } : {})}
            empty={loading ? 'Loading…' : all.length ? 'No services match these filters.' : 'No services in this range. Build an agent with the app-server profile and run your application on that host.'}/>
        </div>
      </div>
    </div>
  )
}
