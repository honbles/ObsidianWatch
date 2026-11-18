import { Link } from 'react-router-dom'
import { DataTable } from '../../../components/shared'
import { AppIdentityBadge } from '../../../components/app/AppBadges'
import { appRel, appTime } from '../../../components/app/appFormat'

// Where it runs: instances, versions, hosts (spec 11.3).
export default function AppTabInstances({ detail, loading, error, highlight }) {
  const inst = detail?.instances || []
  const cols = [
    { key: 'host', label: 'Host', render: i => <Link className="text-siem-accent hover:underline" to={`/agents?host=${encodeURIComponent(i.host)}`}>{i.host}</Link>, sort: i => i.host },
    { key: 'pid', label: 'Process', render: i => <span className="font-mono text-xs">{i.pid || '-'}{i.instance_ref ? <span className="text-siem-muted"> · {i.instance_ref}</span> : ''}</span> },
    { key: 'container_id', label: 'Container', render: i => <span className="font-mono text-xs">{i.container_id ? i.container_id.slice(0, 12) : '-'}</span> },
    { key: 'version', label: 'Version', sort: i => i.version },
    { key: 'identity', label: 'Identity', render: i => <AppIdentityBadge identity={i.identity} />, width: 90 },
    { key: 'instrumented', label: 'Telemetry', render: i => (i.instrumented ? 'OpenTelemetry' : 'host only'), width: 110 },
    { key: 'last_seen', label: 'Last seen', render: i => appRel(i.last_seen), sort: i => i.last_seen },
    { key: 'stopped_at', label: 'State', render: i => (i.stopped_at ? <span className="text-siem-muted">stopped {appRel(i.stopped_at)}</span> : <span className="text-emerald-300">running</span>), sort: i => (i.stopped_at ? 0 : 1) },
  ]
  const versions = detail?.versions || []
  return (
    <div className="space-y-4">
      <div className="card"><DataTable columns={cols} rows={inst} loading={loading} error={error} rowKey={i => i.id}
        emptyText="No instances seen yet." initialSort={{ key: 'stopped_at', dir: 'desc' }}
        onRowClick={null} /></div>
      {highlight && <div className="text-[11px] text-siem-muted">Opened from instance {highlight}.</div>}
      <div className="card">
        <div className="card-head"><span className="text-sm font-medium text-siem-text">Versions</span></div>
        {versions.length === 0 ? <div className="p-4 text-xs text-siem-muted">No version reported. Set service.version in OpenTelemetry resource attributes to see deploys.</div> : (
          <ul className="divide-y divide-siem-border/50">
            {versions.map(v => (
              <li key={v.version} className="px-3 py-2 text-xs flex justify-between">
                <span className="text-siem-text">{v.version}</span>
                <span className="text-siem-muted">first seen {appTime(v.first_seen)} · {v.instances} running</span>
              </li>))}
          </ul>)}
      </div>
    </div>
  )
}
