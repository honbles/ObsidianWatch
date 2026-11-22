import { Link } from 'react-router-dom'
import { useTimeRange, DataTable } from '../../components/shared'
import { appApi } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import AppPageHeader from '../../components/app/AppPageHeader'
import { AppExposureBadge, AppCriticalityBadge } from '../../components/app/AppBadges'
import { appLearning, appLearningText } from '../../components/app/appFormat'

export const appPath = '/applications/settings'

// Settings: how is it tuned? Per-service tuning and learning status, plus the rule catalogue. (spec 11.3)
export default function AppSettings() {
  const range = useTimeRange(7 * 24 * 3600e3)
  const svcs = useAppLoad(() => appApi.services(range, { limit: 500 }), [range.from, range.to])
  const rules = useAppLoad(() => appApi.ruleMeta().catch(() => ({ items: [] })), [])
  const appRules = (rules.data?.items || []).filter(r => /^(app|apm)/.test(r.family || ''))
  const rows = (svcs.data?.services || []).map(s => ({ ...s, learn: appLearning(s.first_seen, s.settings.learning_started, s.learning_calls) }))

  const cols = [
    { key: 'name', label: 'Service', render: s => <Link className="text-siem-text hover:underline" to={`/applications/services/${encodeURIComponent(s.key)}?tab=settings`}>{s.name} <span className="text-siem-muted text-xs">{s.environment}</span></Link>, sort: s => s.name },
    { key: 'exposure', label: 'Exposure', render: s => <AppExposureBadge exposure={s.settings.exposure} settings={s.settings} />, sort: s => s.settings.exposure },
    { key: 'criticality', label: 'Criticality', render: s => <AppCriticalityBadge criticality={s.settings.criticality} />, sort: s => s.settings.criticality },
    { key: 'owner', label: 'Owner', render: s => s.settings.owner || <span className="text-siem-muted">-</span> },
    { key: 'learn', label: 'Learning', render: s => <span className={s.tier === 0 ? 'text-siem-muted' : s.learn.state === 'ready' ? 'text-emerald-300' : 'text-amber-300'}>{appLearningText(s.learn, s.tier)}</span>, sort: s => s.learn.state },
    { key: 'maint', label: 'Maintenance', render: s => (s.settings.maintenance?.length ? `${s.settings.maintenance.length} window${s.settings.maintenance.length > 1 ? 's' : ''}` : '-') },
  ]
  const ruleCols = [
    { key: 'id', label: 'Rule', render: r => <span className="font-mono text-xs">{r.id}</span>, sort: r => r.id, width: 90 },
    { key: 'family', label: 'Family', width: 80 },
    { key: 'tier', label: 'Tier', width: 50, render: r => (r.tier ? `T${r.tier}` : '-') },
    { key: 'default_observe', label: 'Starts in', render: r => (r.default_observe ? 'observe' : 'active'), width: 80 },
    { key: 'what_to_check', label: 'What to check', render: r => <span className="text-xs text-siem-muted">{r.what_to_check}</span> },
  ]
  return (
    <div className="p-6 space-y-5">
      <AppPageHeader title="Settings" range={range}
        subtitle="Per-service tuning and learning status. Click a service to edit its exposure, criticality, trusted proxies, routes, targets and maintenance windows." />
      <div className="card"><DataTable columns={cols} rows={rows} loading={svcs.loading} error={svcs.error} rowKey={s => s.id}
        emptyText="No services yet." initialSort={{ key: 'learn', dir: 'asc' }} /></div>

      <div className="card">
        <div className="card-head"><span className="text-sm font-medium text-siem-text">Detection rules</span></div>
        <DataTable columns={ruleCols} rows={appRules} loading={rules.loading} error={rules.error} rowKey={r => r.id}
          emptyText="No application rules are registered yet. Rule modes, allowlists and precision appear here as the detection catalogue ships." />
      </div>

      <div className="card p-3 text-xs text-siem-muted space-y-1">
        <div className="text-siem-text font-medium">Data retention</div>
        <div>Per-minute request statistics are kept for 90 days and sampled traces for 7 days. Both are configurable by an administrator (settings keys <span className="font-mono">app.retention_stats_days</span> and <span className="font-mono">app.retention_trace_days</span>).</div>
      </div>
    </div>
  )
}
