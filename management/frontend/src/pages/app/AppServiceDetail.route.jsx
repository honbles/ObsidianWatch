import { useMemo, useState, useRef, useEffect } from 'react'
import { useParams, useSearchParams, useNavigate } from 'react-router-dom'
import { useTimeRange, StateBlock } from '../../components/shared'
import { appApi, appResolveService } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import { PageHeader, StatTile, StatePill, Meter, DenseTable, relTime } from '../../components/ui'
import AppREDCharts from '../../components/app/AppREDCharts'
import AppSetupHint from '../../components/app/AppSetupHint'
import AppDependencyGraph from '../../components/app/AppDependencyGraph'
import AppServiceSettingsForm from '../../components/app/AppServiceSettingsForm'
import { AppTierBadge, AppExposureBadge, AppCriticalityBadge } from '../../components/app/AppBadges'
import { appInt, appPct, appMs, appRel, appLearning, appLearningText, APP_LEARN_REQUESTS, appReviewPath } from '../../components/app/appFormat'
import AppTabRoutes from './tabs/AppTabRoutes'
import AppTabInstances from './tabs/AppTabInstances'
import AppTabDatabase from './tabs/AppTabDatabase'
import AppTabErrors from './tabs/AppTabErrors'
import AppTabMetrics from './tabs/AppTabMetrics'
import AppTabCompare from './tabs/AppTabCompare'
import AppTabOperations from './tabs/AppTabOperations'
import AppTabSLO from './tabs/AppTabSLO'
import AppTabRuntime from './tabs/AppTabRuntime'
import AppTabEvents from './tabs/AppTabEvents'
import AppTabSecurity from './tabs/AppTabSecurity'
import AppTabTraces from './tabs/AppTabTraces'
import AppTabAlerts from './tabs/AppTabAlerts'
import AppTabCode from './tabs/AppTabCode'
import AppT0Overview from './tabs/AppT0Overview'

export const appPath = '/applications/services/:key'

// Tabs: the ones used most stay visible; the rest sit under "More" so the row never wraps.
// Each tab names the lowest telemetry tier that gives it data, so a host-only
// (Tier 0) service shows only what the host agent can see.
const TABS = [
  ['overview', 'Overview', 0], ['routes', 'Endpoints', 1], ['traces', 'Traces', 1], ['database', 'Queries', 1], ['errors', 'Errors', 1],
  ['operations', 'Jobs and queues', 1], ['metrics', 'Metrics', 1], ['slo', 'SLO', 1], ['instances', 'Instances', 0], ['security', 'Security', 2],
  ['alerts', 'Alerts', 0], ['code', 'Code', 0],
]
const MORE = [['dependencies', 'Dependencies', 0], ['compare', 'Compare versions', 1], ['events', 'Events', 0], ['runtime', 'Runtime', 0], ['settings', 'Settings', 0]]
// Tier 0 has few tabs, so host activity moves out of "More".
const T0_TABS = [['overview', 'Overview', 0], ['instances', 'Instances', 0], ['runtime', 'Host activity', 0], ['events', 'Timeline', 0], ['alerts', 'Alerts', 0], ['code', 'Code', 0]]
const T0_MORE = [['dependencies', 'Dependencies', 0], ['settings', 'Settings', 0]]
const ALL_TABS = [...TABS, ...MORE]
function tabsFor(tier) {
  if (!tier) return { main: T0_TABS, more: T0_MORE }
  return { main: TABS.filter(t => t[2] <= tier), more: MORE.filter(t => t[2] <= tier) }
}

function ChangeCard({ title, children, empty }) {
  return (
    <div className="ow-card" style={{ padding: '12px 14px', flex: '1 1 260px', minWidth: 0 }}>
      <div style={{ fontWeight: 500, marginBottom: 6 }}>{title}</div>
      {empty ? <div className="t3" style={{ fontSize: 12.5 }}>{empty}</div> : <div style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: 12.5 }}>{children}</div>}
    </div>
  )
}

function MoreTabs({ tab, go, items }) {
  const MORE = items
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', h); return () => document.removeEventListener('mousedown', h)
  }, [])
  const cur = MORE.find(m => m[0] === tab)
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button className={`ow-tab ${cur ? 'on' : ''}`} onClick={() => setOpen(o => !o)} aria-haspopup="menu" aria-expanded={open}>{cur ? cur[1] : 'More'} <span className="t3">▾</span></button>
      {open && (
        <div className="dropdown" role="menu" style={{ top: 38 }}>
          {MORE.map(([k, l]) => <div key={k} role="menuitem" className={`dropdown-item ${tab === k ? 'active' : ''}`} onClick={() => { setOpen(false); go(k) }}>{l}</div>)}
        </div>
      )}
    </div>
  )
}

// "▲ 38% vs previous 24 hours". Lower is better for latency and errors, higher for apdex.
function delta(cur, prev, { pct = true, betterUp = false, unit = '', label } = {}) {
  if (cur == null || prev == null || !isFinite(cur) || !isFinite(prev)) return null
  if (prev === 0 && cur === 0) return { text: `steady ${label}`, tone: undefined }
  if (prev === 0) return null
  const d = pct ? ((cur - prev) / prev) * 100 : cur - prev
  if (Math.abs(d) < (pct ? 3 : 0.005)) return { text: `steady ${label}`, tone: undefined }
  const up = d > 0
  const bad = betterUp ? !up : up
  const mag = pct ? `${Math.round(Math.abs(d))}%` : `${Math.abs(d).toFixed(unit === ' pts' ? 1 : 2)}${unit}`
  return { text: `${up ? '▲' : '▼'} ${mag} ${label}`, tone: bad ? 'warn' : 'ok' }
}

// State in one pill. Thresholds are deliberately simple so the tooltip can say exactly why.
function serviceState({ t, target, slo, alerts }) {
  if (!t || !t.calls) return { state: 'none', text: 'No traffic in range', why: 'No server spans received in this range' }
  const reasons = []
  let state = 'ok'
  if (t.error_rate >= 0.05) { state = 'crit'; reasons.push(`error rate ${(t.error_rate * 100).toFixed(1)}% (≥ 5%)`) }
  else if (t.error_rate >= 0.01) { state = 'warn'; reasons.push(`error rate ${(t.error_rate * 100).toFixed(1)}% (≥ 1%)`) }
  if (target && t.p95_ms > target) { if (state === 'ok') state = 'warn'; reasons.push(`p95 ${appMs(t.p95_ms)} over the ${appMs(target)} target`) }
  if (slo && slo.budget_remaining_pct <= 0) { state = 'crit'; reasons.push('SLO error budget exhausted') }
  else if (slo && slo.budget_remaining_pct < 25) { if (state === 'ok') state = 'warn'; reasons.push(`${Math.round(slo.budget_remaining_pct)}% SLO budget left`) }
  if (alerts > 0) { if (state === 'ok') state = 'warn'; reasons.push(`${alerts} open alert${alerts === 1 ? '' : 's'}`) }
  const text = { ok: 'Healthy', warn: 'Degraded', crit: 'Failing' }[state]
  return { state, text, why: reasons.join('; ') || 'Error rate, latency and SLO budget within limits' }
}

function routeState(r, target) {
  const s = r.stats || {}
  if (!s.calls) return 'none'
  if (s.error_rate >= 0.05) return 'crit'
  if (s.error_rate >= 0.01 || (target && s.p95_ms > target)) return 'warn'
  return 'ok'
}

// Service detail: is it healthy and what changed, then tabs (spec 11.3).
export default function AppServiceDetail() {
  const { key } = useParams()
  const navigate = useNavigate()
  const range = useTimeRange(24 * 3600e3)
  const prev = useMemo(() => {
    const span = new Date(range.to) - new Date(range.from)
    return { from: new Date(new Date(range.from).getTime() - span).toISOString(), to: range.from }
  }, [range.from, range.to])
  const [sp, setSp] = useSearchParams()
  const wanted = ALL_TABS.some(t => t[0] === sp.get('tab')) ? sp.get('tab') : 'overview'
  const go = (t, extra = {}) => {
    const n = new URLSearchParams(sp); n.set('tab', t)
    Object.entries(extra).forEach(([k, v]) => (v == null ? n.delete(k) : n.set(k, v)))
    setSp(n, { replace: true })
  }

  const svcQ = useAppLoad(() => appResolveService(key), [key])
  const svc = svcQ.data
  const on = !!svc
  const tierTabs = tabsFor(svc?.tier || 0)
  const tab = !svc || [...tierTabs.main, ...tierTabs.more].some(t => t[0] === wanted) ? wanted : 'overview'
  const t0 = !!svc && !svc.tier
  const detail = useAppLoad(() => appApi.service(svc.id), [svc?.id], on)
  const samp = useAppLoad(() => appApi.sampling(svc.id, range), [svc?.id, range.from, range.to], on && !t0)
  const red = useAppLoad(() => appApi.red(svc.id, range), [svc?.id, range.from, range.to], on && !t0)
  const redPrev = useAppLoad(() => appApi.red(svc.id, prev), [svc?.id, prev.from, prev.to], on && !t0 && tab === 'overview')
  const edges = useAppLoad(() => appApi.edges(svc.id, range), [svc?.id, range.from, range.to], on)
  const routes = useAppLoad(() => appApi.routes(svc.id, range), [svc?.id, range.from, range.to], on && !t0 && (tab === 'overview'))
  const slo = useAppLoad(() => appApi.slo(svc.id), [svc?.id], on && !t0)
  const openAlerts = useAppLoad(() => appApi.alerts(svc.id, 'open'), [svc?.id], on)

  const full = detail.data?.service || svc // the detail response carries fresh settings after a save
  const deploys = useMemo(() => {
    if (!full) return []
    const base = new Date(full.first_seen).getTime() + 3600e3 // the first version is the baseline, not a deploy
    return (detail.data?.versions || []).filter(v => new Date(v.first_seen).getTime() > base)
  }, [detail.data, full])
  const newRoutes = useMemo(() => {
    if (!full || !routes.data) return []
    const base = new Date(full.first_seen).getTime() + 3600e3
    return routes.data.routes.filter(r => new Date(r.first_seen) >= new Date(range.from) && new Date(r.first_seen).getTime() > base)
  }, [routes.data, full, range.from])
  const newRouteKeys = new Set(newRoutes.map(r => r.method + ' ' + r.route))
  const newEdges = (edges.data?.edges || []).filter(e => e.new && full && new Date(e.first_seen).getTime() > new Date(full.first_seen).getTime() + 3600e3)
  const versionsInRange = deploys.filter(v => new Date(v.first_seen) >= new Date(range.from))
  const lastDeploy = deploys[0]

  const t = red.data?.totals
  const tp = redPrev.data?.totals
  const series = red.data?.series || []
  const learn = full ? appLearning(full.first_seen, full.settings.learning_started, full.learning_calls) : null
  const instances = detail.data?.instances || []
  const liveInst = instances.filter(i => !i.stopped_at)
  const liveAsserted = liveInst.filter(i => i.identity === 'asserted').length
  const avail = (slo.data?.slos || []).find(x => x.name === 'availability')
  const nAlerts = openAlerts.data?.alerts?.length || 0
  const target = full?.settings?.latency_target_ms
  const st = !full ? null : t0
    ? (nAlerts ? { state: 'warn', text: `${nAlerts} open alert${nAlerts === 1 ? '' : 's'}`, why: 'Open alerts on this service' }
      : liveInst.length ? { state: 'ok', text: 'Running', why: 'Live instances, no open alerts. Request health needs OpenTelemetry.' }
      : { state: 'none', text: 'Not running', why: 'No live instance' })
    : serviceState({ t, target, slo: avail, alerts: nAlerts })
  const spanMin = (new Date(range.to) - new Date(range.from)) / 60000
  const rpm = (x) => (x && x.calls != null ? x.calls / spanMin : null)
  const lang = (() => { try { const a = typeof full?.attrs === 'string' ? JSON.parse(full.attrs) : full?.attrs; return a?.language } catch { return null } })()
  const vsLabel = 'vs previous period'

  const dApdex = delta(t?.apdex, tp?.apdex, { pct: false, betterUp: true, label: vsLabel })
  const dP95 = delta(t?.p95_ms, tp?.p95_ms, { label: vsLabel })
  const dErr = delta(t ? t.error_rate * 100 : null, tp ? tp.error_rate * 100 : null, { pct: false, unit: ' pts', label: vsLabel })
  const dRpm = delta(rpm(t), rpm(tp), { betterUp: true, label: vsLabel })

  const topRoutes = useMemo(() => {
    const list = (routes.data?.routes || []).filter(r => r.observed !== false && r.stats?.calls)
    const order = { crit: 0, warn: 1, ok: 2, none: 3 }
    return list.map(r => ({ ...r, _st: routeState(r, target), _impact: (r.stats.errors || 0) * 10 + (r.stats.calls * (r.stats.p95_ms || 0)) / 1e4 }))
      .sort((a, b) => order[a._st] - order[b._st] || b._impact - a._impact).slice(0, 8)
  }, [routes.data, target])

  const subParts = full ? [
    lang, `${liveInst.length || full.instances} instance${(liveInst.length || full.instances) === 1 ? '' : 's'}`, full.environment,
    lastDeploy ? `${lastDeploy.version} deployed ${appRel(lastDeploy.first_seen)}` : `first seen ${appRel(full.first_seen)}`,
  ].filter(Boolean) : []

  return (
    <div>
      <PageHeader
        title={svc ? svc.name : 'Service'} mono
        state={st?.state} stateText={st && (st.state === 'warn' && lastDeploy && versionsInRange.length ? `Degraded since ${lastDeploy.version}` : st.text)} stateTitle={st?.why}
        sub={full ? <>{subParts.join(' · ')}
          <span style={{ display: 'inline-flex', gap: 6, marginLeft: 10, verticalAlign: 'middle' }}>
            <AppTierBadge tier={full.tier} instrumentation={full.instrumentation} /><AppExposureBadge exposure={full.settings.exposure} settings={full.settings} /><AppCriticalityBadge criticality={full.settings.criticality} />
          </span>
          {full.settings.owner && <> · owner <span className="t1">{full.settings.owner}</span></>}
          {liveAsserted > 0 && <span className="c-warn"> · {liveAsserted} instance{liveAsserted > 1 ? 's' : ''} with asserted identity</span>}
        </> : (svcQ.loading ? 'Loading…' : undefined)}
        actions={full && <>
          {!t0 && <button className="ow-btn" onClick={() => go('compare')}>Compare versions</button>}
          <button className="ow-btn primary" onClick={() => go('settings')}>Settings</button>
        </>}
        tabs={full && (
          <nav className="ow-tabs" role="tablist">
            {tierTabs.main.map(([k, label]) => (
              <button key={k} role="tab" aria-selected={tab === k} className={`ow-tab ${tab === k ? 'on' : ''}`} onClick={() => go(k)}>
                {label}{k === 'alerts' && nAlerts ? <span className="ow-tab-n" style={{ color: 'var(--crit)' }}>{nAlerts}</span> : null}
              </button>))}
            <MoreTabs tab={tab} go={go} items={tierTabs.more}/>
          </nav>
        )}
      />
      <div className="ow-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <StateBlock loading={svcQ.loading && !svc} error={svcQ.error} empty={!svcQ.loading && !svc} emptyText="Service not found. It may not have reported in the last 90 days.">
        {full && (<>
          {tab === 'overview' && t0 && <AppT0Overview service={full} detail={detail.data} alerts={openAlerts.data?.alerts || []} edges={edges.data?.edges || []} go={go} />}
          {tab === 'overview' && !t0 && (<>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <StatTile k="Apdex" v={t?.apdex != null ? t.apdex.toFixed(2) : '–'} note={dApdex?.text || (target ? `target ${appMs(target)}` : 'set a latency target for Apdex')} noteTone={dApdex?.tone}/>
              <StatTile k="p95 latency" v={t ? appMs(t.p95_ms, t.over_range).replace(/ (ms|s)$/, '') : '–'} unit={t?.p95_ms ? (t.p95_ms >= 1000 ? 's' : 'ms') : undefined}
                tone={target && t?.p95_ms > target ? 'warn' : undefined} note={dP95?.text || (target ? `target ${appMs(target)}` : null)} noteTone={dP95?.tone}/>
              <StatTile k="Error rate" v={t ? (t.error_rate * 100).toFixed(t.error_rate > 0 && t.error_rate < 0.001 ? 2 : 1) : '–'} unit="%"
                tone={t?.error_rate >= 0.05 ? 'crit' : t?.error_rate >= 0.01 ? 'warn' : undefined} note={dErr?.text} noteTone={dErr?.tone === 'warn' ? 'crit' : dErr?.tone}/>
              <StatTile k="Throughput" v={t ? Math.round(rpm(t)).toLocaleString() : '–'} unit="req/min" note={dRpm ? dRpm.text.replace(/^steady.*/, 'steady') : null} noteTone={undefined}/>
              <StatTile k={avail ? `SLO · ${avail.target_pct}% availability, ${slo.data.window_days} d` : 'SLO'} style={{ flex: '1 1 220px' }}
                v={avail ? Math.max(0, Math.round(avail.budget_remaining_pct)) : '–'} unit={avail ? '% budget left' : undefined}
                note={avail ? (avail.exhausts_at ? `Exhausted ${appRel(avail.exhausts_at)} at this burn` : avail.budget_remaining_pct <= 0 ? 'Budget spent for this window' : 'Not burning faster than allowed') : 'No SLO set. Add one in Settings.'}
                noteTone={avail && (avail.exhausts_at || avail.budget_remaining_pct < 25) ? 'warn' : undefined}>
                {avail && <div style={{ margin: '6px 0 4px' }}><Meter pct={avail.budget_remaining_pct} state={avail.budget_remaining_pct < 25 ? (avail.budget_remaining_pct <= 0 ? 'crit' : 'warn') : 'ok'}/></div>}
              </StatTile>
            </div>

            {red.data?.percentile_method && red.data.percentile_method !== 'sketch' && (
              <div className="t3" style={{ fontSize: 12 }}>Percentiles are estimated from a coarse histogram (capped at 10 s) because {red.data.percentile_method === 'mixed' ? 'some agents in this range are older and do not send latency sketches' : 'this range is longer than 7 days or no agent sends latency sketches yet'}. Update agents for exact percentiles with no ceiling.</div>)}
            <StateBlock loading={red.loading && !red.data} error={red.error} empty={!red.loading && series.length === 0}
              emptyText="No request statistics in this range.">
              <AppREDCharts series={series} deploys={deploys} step={red.data?.step_seconds || 60} />
            </StateBlock>

            <div className="ow-card" style={{ overflow: 'hidden' }}>
              <div className="ow-card-bar">
                <span style={{ fontWeight: 600 }}>Endpoints</span>
                <span className="t3" style={{ fontSize: 12 }}>Worst first: state, then errors and time spent</span>
                <button className="ow-btn quiet" style={{ marginLeft: 'auto' }} onClick={() => go('routes')}>All {routes.data?.routes?.length ?? ''} endpoints</button>
              </div>
              <DenseTable rowKey={r => r.method + ' ' + r.route} rows={topRoutes} rowState={r => r._st}
                onRow={r => navigate(appReviewPath(full, r.method, r.route))}
                empty={routes.loading ? 'Loading…' : 'No endpoint traffic in this range.'}
                cols={[
                  { key: 's', label: 'State', width: '90px', render: r => <StatePill state={r._st}>{{ ok: 'OK', warn: 'Warning', crit: 'Critical', none: 'No data' }[r._st]}</StatePill> },
                  { key: 'r', label: 'Route', width: '1.6fr', render: r => <span className="mono t1">{r.method} {r.route}</span>, title: r => `${r.method} ${r.route}` },
                  { key: 'q', label: 'req/min', width: '90px', render: r => <span className="mono">{(r.stats.calls / spanMin).toFixed(r.stats.calls / spanMin < 10 ? 1 : 0)}</span> },
                  { key: 'p', label: 'p95', width: '90px', render: r => <span className="mono" style={{ color: target && r.stats.p95_ms > target ? 'var(--warn)' : undefined }}>{appMs(r.stats.p95_ms, r.stats.over_range)}</span> },
                  { key: 'e', label: 'Errors', width: '80px', render: r => <span className="mono" style={{ color: r.stats.error_rate >= 0.05 ? 'var(--crit)' : r.stats.error_rate >= 0.01 ? 'var(--warn)' : 'var(--t2)' }}>{appPct(r.stats.error_rate)}</span> },
                  { key: 'n', label: 'Last call', width: '100px', render: r => newRouteKeys.has(r.method + ' ' + r.route) ? <StatePill state="info" title={`First seen ${appRel(r.first_seen)}`}>New</StatePill> : <span className="t2">{relTime(r.last_seen)}</span> },
                ]}/>
            </div>

            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <ChangeCard title="New routes" empty={newRoutes.length === 0 && 'None in this range'}>
                {newRoutes.slice(0, 6).map(r => <div key={r.method + r.route} className="mono">{r.method} {r.route}</div>)}
                {newRoutes.length > 6 && <button className="ow-btn quiet" style={{ alignSelf: 'flex-start', padding: 0, height: 22, color: 'var(--acc)' }} onClick={() => go('routes')}>and {newRoutes.length - 6} more</button>}
              </ChangeCard>
              <ChangeCard title="New dependencies" empty={newEdges.length === 0 && 'None in this range'}>
                {newEdges.slice(0, 6).map(e => <div key={e.dst_kind + e.dst_name}><span className="mono">{e.dst_name}</span> <span className="t3">{e.dst_kind}</span></div>)}
              </ChangeCard>
              <ChangeCard title="Deploys" empty={versionsInRange.length === 0 && 'No new versions in this range'}>
                {versionsInRange.map(v => <div key={v.version}><span className="mono">{v.version}</span> <span className="t3">{appRel(v.first_seen)}</span></div>)}
              </ChangeCard>
            </div>

            <div className="ow-card" style={{ padding: '12px 14px', display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: 240 }}><span className="t2">Baseline: </span>{appLearningText(learn, full.tier)}</div>
              {(samp.data?.sampling || []).length > 0 && (
                <div className="t2" style={{ fontSize: 12, display: 'flex', gap: 12, flexWrap: 'wrap' }}>Traces kept / seen
                  {samp.data.sampling.map(x => <span key={x.reason}><span className="t3">{x.reason}</span> <span className="mono t1">{appInt(x.kept)} / {appInt(x.seen)}</span></span>)}
                </div>)}
              <div style={{ width: 180 }}><Meter pct={Math.min(100, Math.round(Math.min(learn.requests / APP_LEARN_REQUESTS, 1) * 50 + Math.min(learn.days / 7, 1) * 50))} state="acc"/></div>
            </div>
            <AppSetupHint tier={full.tier} name={full.name} environment={full.environment} instrumentation={full.instrumentation} />
          </>)}

          {tab === 'routes' && <AppTabRoutes service={full} range={range} focus={sp.get('route') || ''} />}
          {tab === 'dependencies' && <AppDependencyGraph service={full} edges={edges.data?.edges} loading={edges.loading} error={edges.error} />}
          {tab === 'errors' && <AppTabErrors service={full} range={range} focus={sp.get('error')} />}
          {tab === 'slo' && <AppTabSLO service={full} />}
          {tab === 'operations' && <AppTabOperations service={full} range={range} />}
          {tab === 'compare' && <AppTabCompare service={full} versions={detail.data?.versions} />}
          {tab === 'metrics' && <AppTabMetrics service={{ ...full, instances_list: liveInst.map(i => i.instance_ref || ('pid:' + i.pid)) }} range={range} />}
          {tab === 'database' && <AppTabDatabase service={full} range={range} />}
          {tab === 'instances' && <AppTabInstances detail={detail.data} loading={detail.loading} error={detail.error} highlight={sp.get('instance')} />}
          {tab === 'events' && <AppTabEvents service={full} range={range} />}
          {tab === 'runtime' && <AppTabRuntime service={full} range={range} />}
          {tab === 'security' && <AppTabSecurity service={full} range={range} />}
          {tab === 'traces' && <AppTabTraces service={full} range={range} traceId={sp.get('trace')} onSelect={id => go('traces', { trace: id })} />}
          {tab === 'alerts' && <AppTabAlerts service={full} />}
          {tab === 'code' && <AppTabCode service={full} />}
          {tab === 'settings' && (
            <div className="ow-card" style={{ padding: 16 }}><AppServiceSettingsForm key={full.settings.updated_at || full.id} service={full} requests={full.learning_calls}
              onSaved={() => { detail.reload(); svcQ.reload(); slo.reload() }} /></div>)}
        </>)}
      </StateBlock>
      </div>
    </div>
  )
}
