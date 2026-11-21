import { useState } from 'react'
import { Link } from 'react-router-dom'
import { DataTable } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appTime } from '../../../components/app/appFormat'

const sel = 'bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text'
const CATS = [['', 'All activity'], ['connection', 'Connections'], ['process', 'Processes'], ['file', 'Files'], ['lifecycle', 'Lifecycle'], ['alert', 'Alerts'], ['security', 'Security']]
const CAT_CLS = {
  connection: 'border-sky-500/40 text-sky-300', process: 'border-slate-500/40 text-slate-300', file: 'border-violet-500/40 text-violet-300',
  lifecycle: 'border-emerald-500/40 text-emerald-300', alert: 'border-red-500/40 text-red-300', security: 'border-amber-500/40 text-amber-300',
}

// One timeline per service: host activity, lifecycle changes, alerts and security events together.
export default function AppTabEvents({ service, range }) {
  const [category, setCategory] = useState('')
  const [host, setHost] = useState('')
  const extra = {}
  if (category) extra.category = category
  if (host) extra.host = host
  const { data, loading, error } = useAppLoad(() => appApi.timeline(service.id, range, extra), [service.id, range.from, range.to, category, host])
  const cols = [
    { key: 'time', label: 'Time', width: 170, render: e => appTime(e.time), sort: e => e.time },
    { key: 'category', label: 'Type', width: 100, render: e => <span className={`inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium ${CAT_CLS[e.category] || ''}`}>{e.category}</span> },
    { key: 'host', label: 'Host', width: 120, render: e => e.host || <span className="text-siem-muted">-</span> },
    { key: 'title', label: 'Event', render: e => (
      <span>
        {e.alert_id ? <Link className="text-siem-accent hover:underline" to={e.host ? `/alerts?host=${encodeURIComponent(e.host)}` : "/alerts"}>{e.title}</Link> : e.title}
        {e.first_seen && <span className="ml-1.5 rounded border border-orange-500/40 px-1 text-[10px] text-orange-300" title="Not contacted by this service in the 30 days before the range">first seen</span>}
      </span>) },
    { key: 'detail', label: 'Detail', render: e => <span className="font-mono text-xs break-all">{e.detail}</span> },
  ]
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <select className={sel} value={category} onChange={e => setCategory(e.target.value)}>
          {CATS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
        <select className={sel} value={host} onChange={e => setHost(e.target.value)}>
          <option value="">All hosts</option>{(data?.hosts || []).map(h => <option key={h} value={h}>{h}</option>)}</select>
        {data?.counts && <span className="text-xs text-siem-muted">{Object.entries(data.counts).map(([k, v]) => `${v} ${k}`).join(' · ') || 'no activity'}</span>}
      </div>
      <div className="card"><DataTable columns={cols} rows={data?.items} loading={loading} error={error} rowKey={(e, i) => `${e.time}${e.kind}${i}`}
        emptyText="No activity in this range. Connections, process starts and file access come from the host sensor under this service's processes; lifecycle entries come from instance, version, route and dependency changes." /></div>
      <div className="text-[11px] text-siem-muted">Newest first. Only activity under the service's own processes is shown; counts are before the row limit is applied.</div>
    </div>
  )
}
