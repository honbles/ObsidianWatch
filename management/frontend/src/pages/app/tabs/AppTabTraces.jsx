import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { DataTable } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appMs, appTime, appReviewPath, appSplitRequest } from '../../../components/app/appFormat'

const sel = 'bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text'

// Sampled traces with keep reason and a waterfall; mainly reached from an alert (spec 11.3).
export default function AppTabTraces({ service, range, traceId, onSelect }) {
  const [reason, setReason] = useState('')
  const [status, setStatus] = useState('')
  const [slow, setSlow] = useState('')
  const list = useAppLoad(() => appApi.traces(range, { service_id: service.id, reason, status, min_duration_ms: slow || undefined, limit: 100 }),
    [service.id, range.from, range.to, reason, status, slow])
  const navigate = useNavigate()
  // Old links (?tab=traces&trace=…) still work: they forward to the trace page.
  useEffect(() => { if (traceId) navigate(`/applications/traces/${encodeURIComponent(traceId)}?svc=${encodeURIComponent(`${service.name}|${service.environment}`)}`, { replace: true }) }, [traceId]) // eslint-disable-line react-hooks/exhaustive-deps
  const cols = [
    { key: 'started', label: 'Started', render: t => appTime(t.started), sort: t => t.started, width: 170 },
    { key: 'root_route', label: 'Request', render: t => <span className="font-mono text-xs">{t.root_route || '-'}</span> },
    { key: 'duration_ms', label: 'Duration', align: 'right', render: t => appMs(t.duration_ms), sort: t => t.duration_ms },
    { key: 'status', label: 'Status', render: t => <span className={t.status === 'error' ? 'text-red-300' : ''}>{t.status}</span> },
    { key: 'keep_reason', label: 'Kept because' },
    { key: 'span_count', label: 'Spans', align: 'right' },
    { key: 'review', label: 'Route', align: 'right', render: t => {
      const q = appSplitRequest(t.root_route)
      return q ? <Link className="text-siem-accent hover:underline" to={appReviewPath(service, q.method, q.route)} onClick={e => e.stopPropagation()}>Review route</Link> : '-'
    } },
  ]
  return (
    <div className="space-y-3">
      <div className="flex gap-2 flex-wrap">
        <select className={sel} value={reason} onChange={e => setReason(e.target.value)}>
          <option value="">Any reason</option>{['error', 'slow', 'security', 'baseline'].map(x => <option key={x}>{x}</option>)}</select>
        <select className={sel} value={status} onChange={e => setStatus(e.target.value)}>
          <option value="">Any status</option><option>ok</option><option>error</option></select>
        <input className={`${sel} w-40`} type="number" min="0" placeholder="min duration ms" value={slow} onChange={e => setSlow(e.target.value)} />
      </div>
      <div className="card"><DataTable columns={cols} rows={list.data?.traces} loading={list.loading} error={list.error} rowKey={t => t.trace_id}
        onRowClick={t => navigate(`/applications/traces/${encodeURIComponent(t.trace_id)}?svc=${encodeURIComponent(`${service.name}|${service.environment}`)}`)}
        emptyText="No sampled traces in this range." /></div>
    </div>
  )
}
