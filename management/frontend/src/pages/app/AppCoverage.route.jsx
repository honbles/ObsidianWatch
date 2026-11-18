import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useTimeRange, DataTable } from '../../components/shared'
import { appApi } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import AppPageHeader from '../../components/app/AppPageHeader'
import AppSetupHint from '../../components/app/AppSetupHint'
import { AppTierBadge } from '../../components/app/AppBadges'
import { appRel, appInt } from '../../components/app/appFormat'

export const appPath = '/applications/coverage'

const ISSUE = {
  asserted_identity: 'asserted identity', route_overflow: 'route overflow', trace_drops: 'trace drops', not_reporting: 'not reporting',
}
const yes = <span className="text-emerald-300">yes</span>
const no = <span className="text-amber-300">missing</span>

// Coverage: where are we blind? (spec 11.3)
export default function AppCoverage() {
  const range = useTimeRange(7 * 24 * 3600e3)
  const svcs = useAppLoad(() => appApi.services(range, { limit: 500 }), [range.from, range.to])
  const ov = useAppLoad(() => appApi.overview(range), [range.from, range.to])
  const rules = useAppLoad(() => appApi.ruleStatus().catch(() => ({ rules: [], engine: {} })), [])
  const issues = useMemo(() => {
    const m = {}
    for (const d of ov.data?.degraded || []) m[d.service.key] = d.reasons
    return m
  }, [ov.data])
  const appRules = rules.data?.rules || []
  const engine = rules.data?.engine || {}
  const rows = svcs.data?.services || []
  const never = rows.filter(s => s.tier === 0)

  const cols = [
    { key: 'name', label: 'Service', render: s => <Link className="text-siem-text hover:underline" to={`/applications/services/${encodeURIComponent(s.key)}`}>{s.name}</Link>, sort: s => s.name },
    { key: 'environment', label: 'Env' },
    { key: 'tier', label: 'Tier', render: s => <AppTierBadge tier={s.tier} />, sort: s => s.tier, width: 60 },
    { key: 'otel', label: 'OpenTelemetry', render: s => (s.tier >= 1 ? yes : no), sort: s => s.tier },
    { key: 'helper', label: 'Security helper', render: s => (s.tier >= 2 ? yes : no), sort: s => s.tier },
    { key: 'instances', label: 'Instances', align: 'right', sort: s => s.instances },
    { key: 'issues', label: 'Issues', render: s => (issues[s.key] || []).map(r => <span key={r} className="mr-1 text-[10px] rounded border border-amber-500/40 text-amber-300 px-1">{ISSUE[r] || r}</span>), sort: s => (issues[s.key] || []).length },
    { key: 'last_seen', label: 'Last seen', render: s => appRel(s.last_seen), sort: s => s.last_seen },
  ]
  const ruleCols = [
    { key: 'id', label: 'Rule', render: r => <span className="font-mono text-xs">{r.id}</span>, sort: r => r.id, width: 90 },
    { key: 'tier', label: 'Needs', render: r => (r.tier === 0 ? 'host only' : `T${r.tier}`), width: 80 },
    { key: 'fired', label: 'Fired', align: 'right', render: r => appInt(r.fired), sort: r => r.fired },
    { key: 'observed', label: 'In observe', align: 'right', render: r => appInt(r.observed), sort: r => r.observed },
    { key: 'degraded', label: 'Degraded', align: 'right', render: r => (r.degraded ? <span className="text-amber-300">{appInt(r.degraded)}</span> : 0), sort: r => r.degraded },
    { key: 'skipped', label: 'Skipped (reason)', render: r => Object.entries(r.skipped || {}).map(([k, v]) => <span key={k} className="mr-2 text-[10px] rounded border border-slate-500/40 px-1 text-siem-muted">{k} ×{v}</span>) },
  ]
  return (
    <div className="p-6 space-y-5">
      <AppPageHeader title="Coverage" range={range} subtitle="What each service tells us today, and what is missing for the next tier." />
      <div className="card"><DataTable columns={cols} rows={rows} loading={svcs.loading} error={svcs.error} rowKey={s => s.id}
        emptyText="No services in this range." initialSort={{ key: 'tier', dir: 'asc' }} /></div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <div className="card-head"><span className="text-sm font-medium text-siem-text">Detection rules</span></div>
          <div className="p-3 text-xs text-siem-muted space-y-1">
            <div><b className="text-siem-text">{appRules.length}</b> application rules registered; all start in observe mode (shown as Info until promoted).
              {engine.running === false && <span className="text-amber-300"> The rule engine is not running.</span>}
              {engine.events_dropped > 0 && <span className="text-amber-300"> {appInt(engine.events_dropped)} events were dropped because the rule queue was full.</span>}</div>
            <div>Host sensor: {['ebpf', 'procevent', 'poll', 'unknown'].map(k => `${ov.data?.sensors?.[k] ?? 0} ${k === 'procevent' ? 'proc connector' : k === 'poll' ? 'polling' : k === 'ebpf' ? 'eBPF' : 'not reported'}`).join(' · ')} host(s).
              {ov.data?.poll_hosts?.length > 0 && <span className="text-amber-300"> Polling only (can miss short-lived processes): {ov.data.poll_hosts.join(', ')}.</span>}</div>
          </div>
        </div>
        <div className="card">
          <div className="card-head"><span className="text-sm font-medium text-siem-text">Services that never sent telemetry</span></div>
          {never.length === 0 ? <div className="p-3 text-xs text-siem-muted">Every service in this range has sent OpenTelemetry.</div> : (
            <ul className="divide-y divide-siem-border/50 max-h-64 overflow-y-auto">
              {never.map(s => <li key={s.id} className="px-3 py-1.5 text-xs flex justify-between"><span className="text-siem-text">{s.name} <span className="text-siem-muted">{s.environment}</span></span><span className="text-siem-muted">host only</span></li>)}
            </ul>)}
        </div>
      </div>
      <div className="card">
        <div className="card-head"><span className="text-sm font-medium text-siem-text">Rule activity since the backend started</span></div>
        <DataTable columns={ruleCols} rows={appRules} loading={rules.loading} error={rules.error} rowKey={r => r.id}
          emptyText="No application rules are registered." initialSort={{ key: 'id', dir: 'asc' }} />
      </div>
      <div>
        <div className="text-xs font-medium text-siem-text mb-2">How to unlock routes, dependencies and request-based detections</div>
        <AppSetupHint tier={0} />
      </div>
    </div>
  )
}
