import { useEffect, useState } from 'react'
import { DataTable, StateBlock } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import AppTraceWaterfall from '../../../components/app/AppTraceWaterfall'
import { appMs, appTime } from '../../../components/app/appFormat'

const sel = 'bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text'

// Sampled traces with keep reason and a waterfall; mainly reached from an alert (spec 11.3).
export default function AppTabTraces({ service, range, traceId, onSelect }) {
  const [reason, setReason] = useState('')
  const [status, setStatus] = useState('')
  const [slow, setSlow] = useState('')
  const list = useAppLoad(() => appApi.traces(range, { service_id: service.id, reason, status, min_duration_ms: slow || undefined, limit: 100 }),
    [service.id, range.from, range.to, reason, status, slow])
  const one = useAppLoad(() => appApi.trace(traceId), [traceId], !!traceId)
  const [pick, setPick] = useState(traceId || '')
  useEffect(() => { setPick(traceId || '') }, [traceId])
  const cols = [
    { key: 'started', label: 'Started', render: t => appTime(t.started), sort: t => t.started, width: 170 },
    { key: 'root_route', label: 'Request', render: t => <span className="font-mono text-xs">{t.root_route || '-'}</span> },
    { key: 'duration_ms', label: 'Duration', align: 'right', render: t => appMs(t.duration_ms), sort: t => t.duration_ms },
    { key: 'status', label: 'Status', render: t => <span className={t.status === 'error' ? 'text-red-300' : ''}>{t.status}</span> },
    { key: 'keep_reason', label: 'Kept because' },
    { key: 'span_count', label: 'Spans', align: 'right' },
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
        onRowClick={t => { setPick(t.trace_id); onSelect && onSelect(t.trace_id) }}
        emptyText="No sampled traces in this range. Errors, slow requests and requests touched by a security event are always kept; others are sampled at 1%." /></div>
      {pick && (
        <StateBlock loading={one.loading && !one.data} error={one.error}>
          {one.data && <AppTraceWaterfall trace={one.data} />}
        </StateBlock>
      )}
    </div>
  )
}
