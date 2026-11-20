import { useState } from 'react'
import { Link } from 'react-router-dom'
import { DataTable } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appRel, appTime } from '../../../components/app/appFormat'

const SENSOR = {
  ebpf: ['eBPF', 'border-emerald-500/40 text-emerald-300', 'Kernel programs: every process, connection and file access of the service is seen'],
  procevent: ['proc connector', 'border-sky-500/40 text-sky-300', 'Kernel exec notifications plus polling: process starts are seen in real time, connections within a couple of seconds'],
  poll: ['polling', 'border-amber-500/40 text-amber-300', 'Polling only: processes or connections that start and end between two polls can be missed'],
}
const sel = 'bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text'

function SensorBadge({ tier }) {
  const [label, cls, title] = SENSOR[tier] || ['not reported', 'border-slate-500/40 text-slate-400', 'No host sensor reports for this process']
  return <span className={`inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium ${cls}`} title={title}>{label}</span>
}

const detail = (e) => {
  const p = e.proc || {}
  if (e.type === 'network') return <span className="font-mono">{e.dst_ip}:{e.dst_port}{p.dns ? ` (${p.dns})` : ''}</span>
  if (e.type === 'file') return <span className="font-mono">{p.op || 'access'} {e.path}</span>
  if (p.priv_change) return <span className="text-amber-300">privilege change: {p.priv_change.kind} {p.priv_change.detail}</span>
  if (p.escape) return <span className="text-red-300">container escape signal: {p.escape}</span>
  return <span className="font-mono">{e.command_line}</span>
}

// Runtime: what the host sensor saw under this service's processes (spec 11.3).
export default function AppTabRuntime({ service, range }) {
  const [type, setType] = useState('')
  const { data, loading, error } = useAppLoad(() => appApi.runtime(service.id, range, type ? { type } : {}), [service.id, range.from, range.to, type])
  const insts = data?.instances || []
  const live = insts.filter(i => !i.stopped)
  const tiers = new Set(live.map(i => i.sensor || ''))
  const icols = [
    { key: 'host', label: 'Host', render: i => <Link className="text-siem-accent hover:underline" to={`/agents?host=${encodeURIComponent(i.host)}`}>{i.host}</Link> },
    { key: 'pid', label: 'Process', render: i => <span className="font-mono text-xs">{i.pid || '-'}{i.exe ? <span className="text-siem-muted"> {i.exe.split('/').pop()}</span> : ''}</span> },
    { key: 'container', label: 'Container / unit', render: i => (i.container_name || i.unit)
      ? <span className="text-xs">{i.container_name ? <span className="font-mono">{i.container_name}{i.image ? <span className="text-siem-muted"> ({i.image})</span> : ''}</span> : null}{i.unit ? <span className="text-siem-muted"> {i.unit}</span> : null}</span>
      : <span className="text-siem-muted">-</span> },
    { key: 'listen', label: 'Listening', render: i => <span className="font-mono text-xs">{(i.listen || []).join(', ') || '-'}</span> },
    { key: 'sensor', label: 'Host sensor', render: i => <SensorBadge tier={i.sensor} /> },
    { key: 'instrumented', label: 'Telemetry', render: i => (i.instrumented ? 'OpenTelemetry' : 'host only') },
    { key: 'last_seen', label: 'Last seen', render: i => (i.stopped ? <span className="text-siem-muted">stopped</span> : appRel(i.last_seen)) },
  ]
  const ecols = [
    { key: 'time', label: 'Time', render: e => appTime(e.time), sort: e => e.time, width: 170 },
    { key: 'type', label: 'Type', width: 70 },
    { key: 'process', label: 'Process', render: e => <span className="font-mono text-xs">{e.process}<span className="text-siem-muted"> {e.pid}←{e.ppid}</span></span> },
    { key: 'detail', label: 'Detail', render: detail },
    { key: 'user', label: 'User', width: 90 },
    { key: 'source', label: 'Via', width: 80 },
  ]
  return (
    <div className="space-y-4">
      {tiers.has('poll') && (
        <div className="text-[11px] text-amber-300">Some hosts only have polling: processes or connections that start and end between two polls can be missed. Run the agent as root on a Linux host for real-time process events.</div>
      )}
      <div className="card"><DataTable columns={icols} rows={insts} loading={loading} error={error} rowKey={i => i.id}
        emptyText="No host instances. Build an agent with the app-server profile on the host that runs this service." /></div>
      <div className="flex items-center gap-2">
        <select className={sel} value={type} onChange={e => setType(e.target.value)}>
          <option value="">All host activity</option><option value="process">Processes</option><option value="network">Connections</option><option value="file">Files</option></select>
        {data?.counts && <span className="text-xs text-siem-muted">{Object.entries(data.counts).map(([k, v]) => `${v} ${k}`).join(' · ') || 'no activity'}</span>}
      </div>
      <div className="card"><DataTable columns={ecols} rows={data?.events} loading={loading} error={error} rowKey={e => e.id}
        emptyText="No host activity under this service in this range. Events appear when the host sensor sees processes started by the service, its outbound connections, or access to watched files." /></div>
      <div className="text-[11px] text-siem-muted">Only activity under the service's own processes is shown. Command lines are redacted on the host; credentials in arguments never leave it.</div>
    </div>
  )
}
