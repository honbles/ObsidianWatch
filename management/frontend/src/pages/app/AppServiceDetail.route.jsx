import { useMemo } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useTimeRange, StateBlock } from '../../components/shared'
import { appApi, appResolveService } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import AppPageHeader from '../../components/app/AppPageHeader'
import AppStatCard from '../../components/app/AppStatCard'
import AppREDCharts from '../../components/app/AppREDCharts'
import AppSetupHint from '../../components/app/AppSetupHint'
import AppDependencyGraph from '../../components/app/AppDependencyGraph'
import AppServiceSettingsForm from '../../components/app/AppServiceSettingsForm'
import { AppTierBadge, AppExposureBadge, AppCriticalityBadge } from '../../components/app/AppBadges'
import { appInt, appPct, appMs, appRel, appLearning, appLearningText, APP_LEARN_REQUESTS } from '../../components/app/appFormat'
import AppTabRoutes from './tabs/AppTabRoutes'
import AppTabInstances from './tabs/AppTabInstances'
import AppTabDatabase from './tabs/AppTabDatabase'
import AppTabRuntime from './tabs/AppTabRuntime'
import AppTabEvents from './tabs/AppTabEvents'
import AppTabSecurity from './tabs/AppTabSecurity'
import AppTabTraces from './tabs/AppTabTraces'
import AppTabAlerts from './tabs/AppTabAlerts'

export const appPath = '/applications/services/:key'

const TABS = [
  ['overview', 'Overview'], ['routes', 'Routes'], ['dependencies', 'Dependencies'], ['database', 'Database'], ['instances', 'Instances and hosts'],
  ['events', 'Events'], ['runtime', 'Runtime'], ['security', 'Security'], ['traces', 'Traces'], ['alerts', 'Alerts'], ['settings', 'Settings'],
]

function ChangeCard({ title, children, empty }) {
  return (
    <div className="card p-3 text-xs space-y-1">
      <div className="text-[10px] uppercase tracking-wide text-siem-muted">{title}</div>
      {empty ? <div className="text-siem-muted">{empty}</div> : children}
    </div>
  )
}

// Service detail: state at a glance, then tabs (spec 11.3).
export default function AppServiceDetail() {
  const { key } = useParams()
  const range = useTimeRange(24 * 3600e3)
  const [sp, setSp] = useSearchParams()
  const tab = TABS.some(t => t[0] === sp.get('tab')) ? sp.get('tab') : 'overview'
  const go = (t, extra = {}) => {
    const n = new URLSearchParams(sp); n.set('tab', t)
    Object.entries(extra).forEach(([k, v]) => (v == null ? n.delete(k) : n.set(k, v)))
    setSp(n, { replace: true })
  }

  const svcQ = useAppLoad(() => appResolveService(key), [key])
  const svc = svcQ.data
  const on = !!svc
  const detail = useAppLoad(() => appApi.service(svc.id), [svc?.id], on)
  const red = useAppLoad(() => appApi.red(svc.id, range), [svc?.id, range.from, range.to], on)
  const edges = useAppLoad(() => appApi.edges(svc.id, range), [svc?.id, range.from, range.to], on)
  const routes = useAppLoad(() => appApi.routes(svc.id, range), [svc?.id, range.from, range.to], on && (tab === 'overview'))
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
  const newEdges = (edges.data?.edges || []).filter(e => e.new && full && new Date(e.first_seen).getTime() > new Date(full.first_seen).getTime() + 3600e3)
  const versionsInRange = deploys.filter(v => new Date(v.first_seen) >= new Date(range.from))

  const t = red.data?.totals
  const series = red.data?.series || []
  const learn = full ? appLearning(full.first_seen, full.settings.learning_started, full.learning_calls) : null
  const instances = detail.data?.instances || []
  const liveAsserted = instances.filter(i => !i.stopped_at && i.identity === 'asserted').length

  return (
    <div className="p-6 space-y-5">
      <AppPageHeader title={svc ? svc.name : 'Service'} range={range}
        subtitle={svc ? `${svc.environment} · first seen ${appRel(svc.first_seen)} · last seen ${appRel(svc.last_seen)}` : undefined} />
      <StateBlock loading={svcQ.loading && !svc} error={svcQ.error} empty={!svcQ.loading && !svc} emptyText="Service not found. It may not have reported in the last 90 days.">
        {full && (<>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <AppTierBadge tier={full.tier} /><AppExposureBadge exposure={full.settings.exposure} settings={full.settings} /><AppCriticalityBadge criticality={full.settings.criticality} />
            {full.settings.owner && <span className="text-siem-muted">owner <b className="text-siem-text">{full.settings.owner}</b></span>}
            {liveAsserted > 0 && <span className="text-amber-300">{liveAsserted} instance{liveAsserted > 1 ? 's' : ''} with asserted identity</span>}
            <Link to="/applications/services" className="ml-auto text-siem-accent hover:underline">All services</Link>
          </div>

          <div className="flex gap-1 border-b border-siem-border flex-wrap">
            {TABS.map(([k, label]) => (
              <button key={k} onClick={() => go(k)}
                className={`px-3 py-1.5 text-xs border-b-2 -mb-px ${tab === k ? 'border-siem-accent text-siem-text' : 'border-transparent text-siem-muted hover:text-siem-text'}`}>
                {label}{k === 'alerts' && openAlerts.data?.alerts?.length ? <span className="ml-1 text-red-300">({openAlerts.data.alerts.length})</span> : null}
              </button>))}
          </div>

          {tab === 'overview' && (<>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              <AppStatCard label="Requests" value={t ? appInt(t.calls) : '-'} values={series.map(p => p.calls)} />
              <AppStatCard label="Error rate" value={t ? appPct(t.error_rate) : '-'} values={series.map(p => (p.calls ? p.errors / p.calls : 0))} color="var(--red)" tone={t?.error_rate > 0.05 ? 'bad' : undefined} />
              <AppStatCard label="p95 latency" value={t ? appMs(t.p95_ms, t.over_range) : '-'} values={series.map(p => p.p95_ms)} color="var(--yellow)" hint={full.settings.latency_target_ms ? `target ${appMs(full.settings.latency_target_ms)}` : undefined}
                tone={full.settings.latency_target_ms && t?.p95_ms > full.settings.latency_target_ms ? 'warn' : undefined} />
              <AppStatCard label="Open alerts" value={openAlerts.data ? openAlerts.data.alerts.length : '-'} tone={openAlerts.data?.alerts?.length ? 'bad' : undefined} />
              <AppStatCard label="Instances" value={full.instances} hint={`${full.versions} version${full.versions === 1 ? '' : 's'}`} />
            </div>

            <StateBlock loading={red.loading && !red.data} error={red.error} empty={!red.loading && series.length === 0}
              emptyText="No request statistics in this range. They appear once this service sends OpenTelemetry server spans.">
              <AppREDCharts series={series} deploys={deploys} step={red.data?.step_seconds || 60} />
            </StateBlock>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <ChangeCard title="New routes" empty={newRoutes.length === 0 && 'None in this range'}>
                {newRoutes.slice(0, 6).map(r => <div key={r.method + r.route} className="font-mono">{r.method} {r.route}</div>)}
                {newRoutes.length > 6 && <button className="text-siem-accent" onClick={() => go('routes')}>and {newRoutes.length - 6} more</button>}
              </ChangeCard>
              <ChangeCard title="New dependencies" empty={newEdges.length === 0 && 'None in this range'}>
                {newEdges.slice(0, 6).map(e => <div key={e.dst_kind + e.dst_name}><span className="font-mono">{e.dst_name}</span> <span className="text-siem-muted">{e.dst_kind}</span></div>)}
              </ChangeCard>
              <ChangeCard title="Deploys" empty={versionsInRange.length === 0 && 'No new versions in this range'}>
                {versionsInRange.map(v => <div key={v.version}>{v.version} <span className="text-siem-muted">{appRel(v.first_seen)}</span></div>)}
              </ChangeCard>
            </div>

            <div className="card p-3 text-xs flex items-center justify-between gap-3 flex-wrap">
              <div><span className="text-siem-muted">Learning: </span>{appLearningText(learn, full.tier)}</div>
              <div className="w-48 h-1.5 rounded bg-white/10 overflow-hidden"><div className="h-full bg-siem-accent" style={{ width: `${Math.min(100, Math.round(Math.min(learn.requests / APP_LEARN_REQUESTS, 1) * 50 + Math.min(learn.days / 7, 1) * 50))}%` }} /></div>
            </div>
            <AppSetupHint tier={full.tier} name={full.name} environment={full.environment} />
          </>)}

          {tab === 'routes' && <AppTabRoutes service={full} range={range} focus={sp.get('route') || ''} />}
          {tab === 'dependencies' && <AppDependencyGraph service={full} edges={edges.data?.edges} loading={edges.loading} error={edges.error} />}
          {tab === 'database' && <AppTabDatabase service={full} range={range} />}
          {tab === 'instances' && <AppTabInstances detail={detail.data} loading={detail.loading} error={detail.error} highlight={sp.get('instance')} />}
          {tab === 'events' && <AppTabEvents service={full} range={range} />}
          {tab === 'runtime' && <AppTabRuntime service={full} range={range} />}
          {tab === 'security' && <AppTabSecurity service={full} range={range} />}
          {tab === 'traces' && <AppTabTraces service={full} range={range} traceId={sp.get('trace')} onSelect={id => go('traces', { trace: id })} />}
          {tab === 'alerts' && <AppTabAlerts service={full} />}
          {tab === 'settings' && (
            <div className="card p-4"><AppServiceSettingsForm key={full.settings.updated_at || full.id} service={full} requests={full.learning_calls}
              onSaved={() => { detail.reload(); svcQ.reload() }} /></div>)}
        </>)}
      </StateBlock>
    </div>
  )
}
