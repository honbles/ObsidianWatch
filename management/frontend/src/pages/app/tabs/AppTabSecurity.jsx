import { useState } from 'react'
import { DataTable } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appTime } from '../../../components/app/appFormat'

const NAMES = ['auth.login', 'auth.mfa', 'authz.deny', 'input.rejected', 'ssrf.blocked', 'deserialization.blocked', 'ratelimit.hit', 'admin.action', 'data.export', 'session.anomaly', 'data.access']

// app.security feed by user hash, route and client address (spec 11.3). Needs Tier 2.
export default function AppTabSecurity({ service, range }) {
  const [name, setName] = useState('')
  const { data, loading, error } = useAppLoad(() => appApi.events(service.id, range, name ? { event_name: name, limit: 200 } : { limit: 200 }), [service.id, range.from, range.to, name])
  const cols = [
    { key: 'time', label: 'Time', render: e => appTime(e.time), sort: e => e.time, width: 170 },
    { key: 'name', label: 'Event', render: e => <span className="font-mono text-xs">{e.app?.['event.name']}</span>, sort: e => e.app?.['event.name'] },
    { key: 'outcome', label: 'Outcome', render: e => e.app?.outcome || '-' },
    { key: 'user', label: 'User', render: e => <span className="font-mono text-xs" title="Hashed identifier">{e.user || '-'}</span> },
    { key: 'route', label: 'Route', render: e => <span className="font-mono text-xs">{e.app?.route || '-'}</span> },
    { key: 'client', label: 'Client address', render: e => <span className="font-mono text-xs">{e.app?.client_ip || e.app?.peer_ip || '-'}</span> },
    { key: 'identity', label: 'Identity', render: e => e.app?.identity || '-' },
    { key: 'host', label: 'Host' },
  ]
  return (
    <div className="space-y-2">
      <select value={name} onChange={e => setName(e.target.value)} className="bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text">
        <option value="">All security events</option>{NAMES.map(n => <option key={n}>{n}</option>)}
      </select>
      <div className="card"><DataTable columns={cols} rows={data?.events} loading={loading} error={error} rowKey={e => e.id}
        emptyText="No security events in this range. They appear once the security helper reports authentication, authorization and export events (Tier 2)." /></div>
      <div className="text-[11px] text-siem-muted">User identifiers are shown as hashes unless cleartext is enabled for this service.</div>
    </div>
  )
}
