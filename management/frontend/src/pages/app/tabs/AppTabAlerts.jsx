import { useState } from 'react'
import { Link } from 'react-router-dom'
import { DataTable } from '../../../components/shared'
import { SeverityBadge } from '../../../components/SeverityBadge'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appRel } from '../../../components/app/appFormat'

// Alerts for this service, all families (spec 11.3).
export default function AppTabAlerts({ service }) {
  const [state, setState] = useState('open')
  const { data, loading, error } = useAppLoad(() => appApi.alerts(service.id, state), [service.id, state])
  const cols = [
    { key: 'severity', label: 'Severity', render: a => <SeverityBadge severity={a.severity} />, sort: a => a.severity, width: 90 },
    { key: 'title', label: 'Alert' },
    { key: 'status', label: 'Status', width: 110 },
    { key: 'host', label: 'Host', render: a => (a.host ? <Link className="text-siem-accent hover:underline" to={`/agents?host=${encodeURIComponent(a.host)}`}>{a.host}</Link> : '-') },
    { key: 'created_at', label: 'Raised', render: a => appRel(a.created_at), sort: a => a.created_at },
  ]
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        <select value={state} onChange={e => setState(e.target.value)} className="bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text">
          <option value="open">Open</option><option value="all">All</option></select>
        <Link to="/alerts" className="text-xs text-siem-accent hover:underline">Open the Alerts page</Link>
      </div>
      <div className="card"><DataTable columns={cols} rows={data?.alerts} loading={loading} error={error} rowKey={a => a.id}
        emptyText="No alerts linked to this service. Application detections are in observe mode first, so a quiet list is normal while baselines learn." initialSort={{ key: 'created_at', dir: 'desc' }} /></div>
    </div>
  )
}
