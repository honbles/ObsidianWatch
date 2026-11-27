import { useState, useEffect } from 'react'
import api from '../../../api/client'
import { searchError } from '../../events/library'
import { Link } from 'react-router-dom'
import { DataTable } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appTime, appReviewPath } from '../../../components/app/appFormat'

const sel = 'bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text'
const CATS = [['', 'All activity'], ['connection', 'Connections'], ['process', 'Processes'], ['file', 'Files'], ['lifecycle', 'Lifecycle'], ['alert', 'Alerts'], ['security', 'Security'], ['request', 'Request samples']]
const CAT_CLS = {
  connection: 'border-sky-500/40 text-sky-300', process: 'border-slate-500/40 text-slate-300', file: 'border-violet-500/40 text-violet-300',
  lifecycle: 'border-emerald-500/40 text-emerald-300', alert: 'border-red-500/40 text-red-300', security: 'border-amber-500/40 text-amber-300', request: 'border-teal-500/40 text-teal-300',
}

const REC_TYPES = [['', 'All records'], ['app.request', 'Requests'], ['app.payload', 'Payloads'], ['app.error', 'Errors'], ['app.operation', 'Jobs and queues'], ['app.security', 'Security'], ['app.service_change', 'Changes']]

// Search over this service's records in the event store (each with its full payload): the same search as
// Detect → Events with the application chosen.
function RecordSearch({ service, range }) {
  const [text, setText] = useState('')
  const [type, setType] = useState('')
  const [rows, setRows] = useState(null)
  const [err, setErr] = useState('')
  const [open, setOpen] = useState(null)
  const q = [`app:"${service.name.replace(/"/g, '')}"`, type ? `type:${type}` : '', text.trim() ? `(${text.trim()})` : ''].filter(Boolean).join(' ')
  useEffect(() => {
    const t = setTimeout(() => {
      setErr('')
      api.get('/api/v1/events/search', { params: { q, since: range.from, until: range.to, limit: 200 } })
        .then(r => setRows(r.data?.events || []))
        .catch(e => { setRows([]); setErr(searchError(e)) })
    }, 300)
    return () => clearTimeout(t)
  }, [q, range.from, range.to])
  const parse = (raw) => { try { return typeof raw === 'string' ? JSON.parse(raw) : raw } catch { return raw } }
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <input className={sel + ' font-mono'} style={{ minWidth: 320, flex: '1 1 320px' }} value={text} onChange={e => setText(e.target.value)}
          placeholder='status:500   route:/orders   trace:4bf9   or any text in the payload' aria-label="Search records"/>
        <select className={sel} value={type} onChange={e => setType(e.target.value)}>{REC_TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
        <span className="text-xs text-siem-muted">{rows ? `${rows.length}${rows.length === 200 ? '+' : ''} records` : 'Searching…'}</span>
        <Link className="text-xs text-siem-accent hover:underline ml-auto" to={`/events?app=${encodeURIComponent(service.name)}`}>Open in Events</Link>
      </div>
      {err && <div className="text-xs text-red-300">{err}</div>}
      <div className="card">
        {(rows || []).length === 0 && !err && <div className="p-4 text-xs text-siem-muted">{rows ? 'No records match in this range.' : ''}</div>}
        {(rows || []).map(ev => {
          const app = parse(ev.raw)?.app || {}
          const title = ev.event_type === 'app.request' ? `${app.route || ''}  ${app.status || ''}  ${app.duration_ms ?? ''} ms`
            : ev.event_type === 'app.payload' ? `${app.method || ''} ${app.route || ''}  ${app.http_status || ''}`
            : ev.event_type === 'app.error' ? `${app.error_type || 'error'}: ${app.message || app.frame || ''}`
            : ev.event_type === 'app.operation' ? `${app.operation_kind || ''} ${app.operation || ''} · ${app.runs} runs, ${app.failures || 0} failed`
            : app['event.name'] || ev.event_type
          return (
            <div key={ev.id} className="border-b border-siem-border last:border-0">
              <button data-rec className="w-full text-left px-3 py-2 flex items-center gap-3 hover:bg-siem-surface2" onClick={() => setOpen(o => o === ev.id ? null : ev.id)} aria-expanded={open === ev.id}>
                <span className="text-xs text-siem-muted font-mono whitespace-nowrap" style={{ width: 200, flex: 'none' }}>{appTime(ev.time)}</span>
                <span className="text-mini font-mono text-siem-muted whitespace-nowrap" style={{ width: 130, flex: 'none' }}>{ev.event_type}</span>
                <span className="text-xs font-mono truncate">{title}</span>
                <span className="text-xs text-siem-muted ml-auto">{ev.host}</span>
              </button>
              {open === ev.id && <pre className="px-3 pb-3 text-mini font-mono whitespace-pre-wrap break-all text-siem-muted">{JSON.stringify(parse(ev.raw), null, 2)}</pre>}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// One timeline per service: host activity, lifecycle changes, alerts and security events together; and a
// search over the service's records with their payloads.
export default function AppTabEvents({ service, range }) {
  const [mode, setMode] = useState('records')
  const [category, setCategory] = useState('')
  const [host, setHost] = useState('')
  const extra = {}
  if (category) extra.category = category
  if (host) extra.host = host
  const { data, loading, error } = useAppLoad(() => appApi.timeline(service.id, range, extra), [service.id, range.from, range.to, category, host])
  const cols = [
    { key: 'time', label: 'Time', width: 170, render: e => appTime(e.time), sort: e => e.time },
    { key: 'category', label: 'Type', width: 100, render: e => <span className={`inline-flex rounded border px-1.5 py-0.5 text-mini font-medium ${CAT_CLS[e.category] || ''}`}>{e.category}</span> },
    { key: 'host', label: 'Host', width: 120, render: e => e.host || <span className="text-siem-muted">-</span> },
    { key: 'title', label: 'Event', render: e => (
      <span>
        {e.kind === 'request' ? <Link className="text-siem-accent hover:underline" to={appReviewPath(service, e.method, e.route)}>{e.title}</Link> : e.alert_id ? <Link className="text-siem-accent hover:underline" to={e.host ? `/alerts?host=${encodeURIComponent(e.host)}` : "/alerts"}>{e.title}</Link> : e.title}
        {e.first_seen && <span className="ml-1.5 rounded border border-orange-500/40 px-1 text-mini text-orange-300" title="Not contacted by this service in the 30 days before the range">first seen</span>}
      </span>) },
    { key: 'detail', label: 'Detail', render: e => <span className="font-mono text-xs break-all">{e.detail}</span> },
  ]
  const modes = (
    <div className="flex gap-1" role="tablist">
      {[['records', 'Records'], ['timeline', 'Timeline']].map(([k, l]) => (
        <button key={k} role="tab" aria-selected={mode === k} onClick={() => setMode(k)}
          className={`px-3 py-1.5 rounded-lg text-xs border ${mode === k ? 'border-siem-accent text-siem-accent bg-siem-accent/10' : 'border-siem-border text-siem-muted'}`}>{l}</button>))}
    </div>)
  if (mode === 'records') return <div className="space-y-3">{modes}<RecordSearch service={service} range={range}/></div>
  return (
    <div className="space-y-4">
      {modes}
      <div className="flex flex-wrap items-center gap-2">
        <select className={sel} value={category} onChange={e => setCategory(e.target.value)}>
          {CATS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
        <select className={sel} value={host} onChange={e => setHost(e.target.value)}>
          <option value="">All hosts</option>{(data?.hosts || []).map(h => <option key={h} value={h}>{h}</option>)}</select>
        {data?.counts && <span className="text-xs text-siem-muted">{Object.entries(data.counts).map(([k, v]) => `${v} ${k}`).join(' · ') || 'no activity'}</span>}
      </div>
      <div className="card"><DataTable columns={cols} rows={data?.items} loading={loading} error={error} rowKey={(e, i) => `${e.time}${e.kind}${i}`}
        emptyText="No activity in this range." /></div>
      <div className="text-xs text-siem-muted">Newest first.</div>
    </div>
  )
}
