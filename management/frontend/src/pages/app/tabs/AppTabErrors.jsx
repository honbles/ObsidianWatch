import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { DataTable } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appInt, appRel, appCanTriage } from '../../../components/app/appFormat'

const STATUS_TONE = { open: 'border-red-500/40 text-red-300', resolved: 'border-emerald-500/40 text-emerald-300', ignored: 'border-slate-500/40 text-slate-300' }

// Error groups: the same failure counted once, with its stack, the versions it appeared in and a status.
export default function AppTabErrors({ service, range, focus }) {
  const [status, setStatus] = useState('open')
  const [rev, setRev] = useState(0)
  const [openId, setOpenId] = useState(focus ? Number(focus) : null)
  const { data, loading, error } = useAppLoad(() => appApi.errors(service.id, range, status ? { status } : {}), [service.id, range.from, range.to, status, rev])
  const rows = data?.errors || []
  const cols = [
    { key: 'type', label: 'Error', render: g => (
      <button className="text-left hover:underline" onClick={() => setOpenId(g.id)}>
        <span className="font-mono text-xs text-siem-text">{g.type || 'error'}</span>
        {g.regressed && <span className="ml-1 text-[10px] rounded border border-orange-500/40 text-orange-300 px-1" title="Resolved earlier and back in a newer version">regressed</span>}
        <span className="block text-[11px] text-siem-muted font-mono">{g.method} {g.route || '(no route)'} {g.frame ? `· ${g.frame}` : ''}</span>
        {g.message && <span className="block text-[11px] text-siem-muted">{g.message}</span>}
      </button>), sort: g => g.type },
    { key: 'status', label: 'Status', width: 90, render: g => <span className={`text-[10px] rounded border px-1 ${STATUS_TONE[g.status] || ''}`}>{g.status}</span> },
    { key: 'range', label: 'In range', align: 'right', render: g => appInt(g.range_count), sort: g => g.range_count },
    { key: 'count', label: 'All time', align: 'right', render: g => appInt(g.count), sort: g => g.count },
    { key: 'versions', label: 'Versions', render: g => <span className="text-xs">{g.first_version || '-'}{g.last_version && g.last_version !== g.first_version ? ` to ${g.last_version}` : ''}</span> },
    { key: 'assignee', label: 'Assignee', render: g => g.assignee || <span className="text-siem-muted">-</span> },
    { key: 'last', label: 'Last seen', render: g => appRel(g.last_seen), sort: g => g.last_seen },
  ]
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-xs text-siem-muted">
        Show
        <select className="bg-siem-surface2 border border-siem-border rounded px-1.5 py-1 text-siem-text" value={status} onChange={e => setStatus(e.target.value)}>
          <option value="open">Open</option><option value="resolved">Resolved</option><option value="ignored">Ignored</option><option value="">All</option>
        </select>
      </div>
      <div className="card"><DataTable columns={cols} rows={rows} loading={loading} error={error} rowKey={g => g.id}
        initialSort={{ key: 'range', dir: 'desc' }}
        emptyText="No error groups in this range. They appear when the app records exceptions on its spans (most frameworks do for failed requests)." /></div>
      {openId && <AppErrorDetail id={openId} service={service} onClose={() => setOpenId(null)} onChanged={() => setRev(x => x + 1)} />}
      <div className="text-[11px] text-siem-muted">
        Failures are grouped by exception type, the top frames of your own code and the route, so two requests that fail at the same line with different ids are one group.
        Resolve a group when you ship the fix; if it fails again in a different version it reopens as "regressed". The message is hidden unless you turn on masked messages in Settings.
      </div>
    </div>
  )
}

function AppErrorDetail({ id, service, onClose, onChanged }) {
  const [rev, setRev] = useState(0)
  const [assignee, setAssignee] = useState('')
  const [err, setErr] = useState('')
  const { data: g } = useAppLoad(() => appApi.errorGroup(id), [id, rev])
  const admin = appCanTriage()
  useEffect(() => { if (g) setAssignee(g.assignee || '') }, [g])
  const patch = async (body) => {
    setErr('')
    try { await appApi.patchError(id, body); setRev(x => x + 1); onChanged() } catch (e) { setErr(e?.response?.data?.error || 'Could not save.') }
  }
  if (!g) return null
  return (
    <div className="card p-3 text-xs space-y-2">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="font-mono text-sm text-siem-text">{g.type || 'error'}</div>
          <div className="text-siem-muted font-mono">{g.method} {g.route || '(no route)'}</div>
          {g.message && <div className="text-siem-muted mt-1">{g.message}</div>}
        </div>
        <button className="text-siem-muted hover:underline" onClick={onClose}>Close</button>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-siem-muted">
        <span>First seen <b className="text-siem-text">{appRel(g.first_seen)}</b> in {g.first_version || 'unknown version'}</span>
        <span>Last seen <b className="text-siem-text">{appRel(g.last_seen)}</b> in {g.last_version || 'unknown version'}</span>
        <span>Occurrences <b className="text-siem-text">{appInt(g.count)}</b></span>
        <span>Status <b className="text-siem-text">{g.status}</b>{g.resolved_version ? ` (resolved in ${g.resolved_version})` : ''}</span>
      </div>
      <div>
        <div className="text-[10px] uppercase tracking-wide text-siem-muted mb-1">Stack (your code and libraries, values removed)</div>
        {(g.frames || []).length ? <pre className="bg-black/20 rounded p-2 overflow-x-auto text-[11px] leading-relaxed">{g.frames.join('\n')}</pre>
          : <div className="text-siem-muted">No stack was reported for this error.</div>}
      </div>
      {(g.sample_traces || []).length > 0 && (
        <div>Sample traces: {g.sample_traces.map(t => <Link key={t} className="mr-2 font-mono text-siem-accent hover:underline" to={`/applications/services/${service.id}?tab=traces&trace=${t}`}>{t.slice(0, 8)}</Link>)}
          <span className="text-siem-muted">(traces are kept 7 days, so an old sample may be gone)</span></div>
      )}
      {admin ? (
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-siem-border">
          {g.status !== 'resolved' && <button className="btn btn-ghost" onClick={() => patch({ status: 'resolved' })}>Resolve</button>}
          {g.status !== 'ignored' && <button className="btn btn-ghost" onClick={() => patch({ status: 'ignored' })}>Ignore</button>}
          {g.status !== 'open' && <button className="btn btn-ghost" onClick={() => patch({ status: 'open' })}>Reopen</button>}
          <input value={assignee} onChange={e => setAssignee(e.target.value)} placeholder="Assignee" maxLength={128}
            className="bg-siem-surface2 border border-siem-border rounded px-2 py-1 text-siem-text w-40" />
          <button className="btn btn-ghost" onClick={() => patch({ assignee })}>Assign</button>
          {err && <span className="text-red-300">{err}</span>}
        </div>) : null}
    </div>
  )
}
