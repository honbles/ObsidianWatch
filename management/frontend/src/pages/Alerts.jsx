import { useEffect, useState, useCallback } from 'react'
import { createPortal } from 'react-dom'
import {
  Bell, CheckCircle, XCircle, RefreshCw, Plus, X, ChevronRight,
  User, MessageSquare, Clock, AlertTriangle, UserCheck, Shield,
  ExternalLink, Filter, Search, ArrowUpRight, Circle, Minus
} from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'
import { useSearchParams } from 'react-router-dom'
import api from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'
import AlertPanel from '../components/AlertPanel'

const SEV_COLOR   = { 5:'#ef4444', 4:'#f97316', 3:'#eab308', 2:'#3b82f6', 1:'#64748b' }
const SEV_LABEL   = { 5:'Critical', 4:'High', 3:'Medium', 2:'Low', 1:'Info' }
const SEV_BG      = { 5:'bg-red-950/40 border-red-800/50', 4:'bg-orange-950/30 border-orange-800/40', 3:'bg-yellow-950/20 border-yellow-800/30', 2:'bg-blue-950/20 border-blue-800/30', 1:'bg-siem-surface border-siem-border' }

function StatusPill({ status }) {
  const s = {
    open:         'text-red-400 bg-red-950/30 ring-red-500/20',
    acknowledged: 'text-yellow-400 bg-yellow-950/30 ring-yellow-500/20',
    closed:       'text-siem-muted bg-siem-bg ring-siem-border',
  }
  return (
    <span className={`inline-flex items-center gap-1 text-[9px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full ring-1 ${s[status] || s.closed}`}>
      {status === 'open' && <span className="w-1 h-1 rounded-full bg-red-400 animate-pulse"/>}
      {status === 'acknowledged' && <span className="w-1 h-1 rounded-full bg-yellow-400"/>}
      {status === 'closed' && <span className="w-1 h-1 rounded-full bg-siem-muted/50"/>}
      {status}
    </span>
  )
}

function AssignModal({ alert, users, onClose, onDone }) {
  const [assignTo, setAssignTo] = useState(alert.assigned_to || '')
  const [notes, setNotes]       = useState(alert.case_notes || '')
  const [saving, setSaving]     = useState(false)
  const [error, setError]       = useState('')

  const save = async () => {
    if (!assignTo.trim()) { setError('Please select an analyst'); return }
    setSaving(true)
    try {
      await api.patch(`/api/v1/alerts/${alert.id}/assign`, { assigned_to: assignTo, notes })
      onDone(); onClose()
    } catch (e) {
      setError(e.response?.data?.error || 'Failed to assign')
    } finally { setSaving(false) }
  }

  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm"
         onClick={e => { e.stopPropagation(); onClose() }}>
      <div className="bg-siem-surface border border-siem-border rounded-2xl p-6 w-full max-w-md shadow-2xl"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-4">
          <UserCheck size={15} className="text-siem-accent"/>
          <h2 className="text-sm font-bold text-siem-text">Assign to Analyst</h2>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={14}/></button>
        </div>
        <div className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 mb-4 text-xs text-siem-text truncate">{alert.title}</div>
        <div className="space-y-3">
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1.5">Analyst *</label>
            {users.length > 0 ? (
              <select value={assignTo} onChange={e => setAssignTo(e.target.value)}
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent">
                <option value="">— Select analyst —</option>
                {users.map(u => <option key={u.id} value={u.username}>{u.username} ({u.role})</option>)}
              </select>
            ) : (
              <input value={assignTo} onChange={e => setAssignTo(e.target.value)} placeholder="Enter username"
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"/>
            )}
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1.5">Notes</label>
            <textarea rows={3} value={notes} onChange={e => setNotes(e.target.value)}
              placeholder="Initial investigation notes…"
              className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent resize-none"/>
          </div>
          {error && <div className="text-red-400 text-xs">{error}</div>}
          <div className="flex gap-2">
            <button onClick={save} disabled={saving || !assignTo}
              className="flex-1 text-xs bg-siem-accent hover:bg-siem-accent/90 disabled:opacity-40 text-white px-4 py-2 rounded-lg font-medium">
              {saving ? 'Assigning…' : 'Assign & Acknowledge'}
            </button>
            <button onClick={onClose} className="text-xs text-siem-muted border border-siem-border rounded-lg px-4 py-2">Cancel</button>
          </div>
        </div>
      </div>
    </div>, document.body
  )
}

function CloseModal({ alert, onClose, onDone }) {
  const [comment, setComment] = useState(alert.review_comment || '')
  const [saving, setSaving]   = useState(false)
  const [error, setError]     = useState('')

  const save = async () => {
    if (!comment.trim()) { setError('Add a review comment before closing'); return }
    setSaving(true)
    try {
      await api.patch(`/api/v1/alerts/${alert.id}/close-review`, { comment })
      onDone(); onClose()
    } catch (e) {
      setError(e.response?.data?.error || 'Failed to close')
    } finally { setSaving(false) }
  }

  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm"
         onClick={e => { e.stopPropagation(); onClose() }}>
      <div className="bg-siem-surface border border-siem-border rounded-2xl p-6 w-full max-w-md shadow-2xl"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-4">
          <XCircle size={15} className="text-siem-muted"/>
          <h2 className="text-sm font-bold text-siem-text">Close Alert</h2>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={14}/></button>
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1.5">Review Comment *</label>
            <textarea rows={4} value={comment} onChange={e => setComment(e.target.value)}
              placeholder="What was found, actions taken, and resolution…"
              className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent resize-none"/>
          </div>
          {error && <div className="text-red-400 text-xs">{error}</div>}
          <div className="flex gap-2">
            <button onClick={save} disabled={saving}
              className="flex-1 text-xs bg-emerald-900/40 border border-emerald-700 hover:bg-emerald-900/60 text-emerald-300 px-4 py-2 rounded-lg font-medium">
              {saving ? 'Closing…' : 'Close Alert'}
            </button>
            <button onClick={onClose} className="text-xs text-siem-muted border border-siem-border rounded-lg px-4 py-2">Cancel</button>
          </div>
        </div>
      </div>
    </div>, document.body
  )
}

function CreateModal({ onClose, onCreated }) {
  const [form, setForm] = useState({ title: '', description: '', severity: 3, host: '', event_type: '' })
  const [error, setError] = useState('')
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const submit = async e => {
    e.preventDefault(); setError('')
    try { await api.post('/api/v1/alerts', form); onCreated(); onClose() }
    catch (err) { setError(err.response?.data?.error || 'Failed') }
  }

  return createPortal(
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-black/60 backdrop-blur-sm"
         onClick={e => { e.stopPropagation(); onClose() }}>
      <div className="bg-siem-surface border border-siem-border rounded-2xl p-6 w-full max-w-md shadow-2xl"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-4">
          <Bell size={14} className="text-siem-accent"/>
          <h2 className="text-sm font-bold text-siem-text">Create Alert</h2>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={14}/></button>
        </div>
        <form onSubmit={submit} className="space-y-3">
          <input className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
            placeholder="Title *" value={form.title} onChange={e => set('title', e.target.value)} required/>
          <textarea rows={3} className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent resize-none"
            placeholder="Description" value={form.description} onChange={e => set('description', e.target.value)}/>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">Severity</label>
              <select className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none"
                value={form.severity} onChange={e => set('severity', Number(e.target.value))}>
                {[5,4,3,2,1].map(s => <option key={s} value={s}>{SEV_LABEL[s]}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">Host</label>
              <input className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
                placeholder="(optional)" value={form.host} onChange={e => set('host', e.target.value)}/>
            </div>
          </div>
          {error && <div className="text-red-400 text-xs">{error}</div>}
          <div className="flex gap-2">
            <button type="submit" className="text-xs bg-siem-accent text-white px-4 py-2 rounded-lg font-medium">Create</button>
            <button type="button" onClick={onClose} className="text-xs text-siem-muted border border-siem-border rounded-lg px-4 py-2">Cancel</button>
          </div>
        </form>
      </div>
    </div>, document.body
  )
}

// ── Alert row ─────────────────────────────────────────────────────────────────
function AlertRow({ alert, selected, onClick }) {
  const isSelected = selected === alert.id
  return (
    <div onClick={() => onClick(alert.id)}
      className={`flex items-start gap-3 px-4 py-3.5 cursor-pointer transition-all border-b border-siem-border/40 last:border-0 group ${
        isSelected ? 'bg-siem-accent/5 border-l-2 border-l-siem-accent' : 'hover:bg-white/[0.02] border-l-2 border-l-transparent'
      }`}>

      {/* Severity stripe */}
      <div className="mt-1 w-1.5 h-1.5 rounded-full shrink-0" style={{ background: SEV_COLOR[alert.severity] || SEV_COLOR[1] }}/>

      <div className="flex-1 min-w-0 space-y-1">
        {/* Title row */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border"
            style={{ color: SEV_COLOR[alert.severity], borderColor: SEV_COLOR[alert.severity] + '40', background: SEV_COLOR[alert.severity] + '15' }}>
            {SEV_LABEL[alert.severity] || alert.severity}
          </span>
          <StatusPill status={alert.status}/>
          {alert.assigned_to && (
            <span className="flex items-center gap-1 text-[9px] text-yellow-400 bg-yellow-950/20 border border-yellow-800/30 rounded-full px-2 py-0.5">
              <User size={8}/>{alert.assigned_to}
            </span>
          )}
        </div>

        {/* Alert title */}
        <div className={`text-sm font-medium leading-snug ${isSelected ? 'text-siem-text' : 'text-siem-text/90'}`}>
          {alert.title}
        </div>

        {/* Meta row */}
        <div className="flex items-center gap-3 flex-wrap">
          {alert.host && (
            <span className="text-[10px] font-mono text-siem-muted/70 bg-siem-bg border border-siem-border/50 rounded px-1.5 py-0.5">
              {alert.host}
            </span>
          )}
          {alert.event_type && (
            <span className="text-[10px] text-siem-muted/50">{alert.event_type}</span>
          )}
          <span className="text-[10px] text-siem-muted/50 ml-auto flex items-center gap-1">
            <Clock size={9}/>
            {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
          </span>
        </div>

        {/* Notes preview */}
        {alert.case_notes && (
          <div className="flex items-center gap-1.5 text-[9px] text-siem-muted/60">
            <MessageSquare size={9}/>
            <span className="truncate">{alert.case_notes}</span>
          </div>
        )}
      </div>

      <ChevronRight size={13} className={`shrink-0 mt-1 transition-colors ${isSelected ? 'text-siem-accent' : 'text-siem-muted/30 group-hover:text-siem-muted'}`}/>
    </div>
  )
}

// ── Severity summary bar ──────────────────────────────────────────────────────
function SeverityBar({ alerts }) {
  const counts = alerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1
    return acc
  }, {})
  const total = alerts.length
  if (total === 0) return null

  return (
    <div className="flex items-center gap-3">
      {[5,4,3,2,1].filter(s => counts[s]).map(s => (
        <div key={s} className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full" style={{ background: SEV_COLOR[s] }}/>
          <span className="text-[10px] text-siem-muted">{counts[s]} {SEV_LABEL[s]}</span>
        </div>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Alerts() {
  const [alerts, setAlerts]         = useState([])
  const [counts, setCounts]         = useState({})
  const [filter, setFilter]         = useState('open')
  const [loading, setLoading]       = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [selectedId, setSelectedId] = useState(null)
  const [users, setUsers]           = useState([])
  const [search, setSearch]         = useState('')
  const [checked, setChecked]       = useState(() => new Set())
  const [bulkBusy, setBulkBusy]     = useState(false)
  const [sla, setSla]               = useState(null)
  const [searchParams] = useSearchParams()
  const hostParam = searchParams.get('host') || ''
  const [hostFilter, setHostFilter] = useState(hostParam)

  useEffect(() => { setHostFilter(searchParams.get('host') || '') }, [searchParams])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = { status: filter, limit: 200 }
      if (hostFilter) params.host = hostFilter
      const { data } = await api.get('/api/v1/alerts', { params })
      setAlerts(data.alerts || [])
      setCounts(data.counts || {})
    } finally { setLoading(false) }
  }, [filter, hostFilter])

  useEffect(() => {
    api.get('/api/v1/users').then(r => setUsers(r.data.users || [])).catch(() => {})
  }, [])

  useEffect(() => { load() }, [load])
  useEffect(() => { setChecked(new Set()) }, [filter, hostFilter])
  useEffect(() => { api.get('/api/v1/alerts/sla').then(r => setSla(r.data)).catch(() => {}) }, [alerts])

  const bulk = async (action) => {
    if (checked.size === 0) return
    if (action === 'close' && !window.confirm(`Close ${checked.size} alert(s)?`)) return
    setBulkBusy(true)
    try {
      await api.post('/api/v1/alerts/bulk', { ids: [...checked], action })
      setChecked(new Set())
      await load()
    } catch (e) { window.alert(e.response?.data?.error || 'Bulk action failed') }
    finally { setBulkBusy(false) }
  }

  const filtered = search
    ? alerts.filter(a => (a.title + a.description + a.host).toLowerCase().includes(search.toLowerCase()))
    : alerts

  const STATUS_TABS = [
    { key: 'open',         label: 'Open',         dot: 'bg-red-400' },
    { key: 'acknowledged', label: 'In Progress',  dot: 'bg-yellow-400' },
    { key: 'closed',       label: 'Resolved',     dot: 'bg-emerald-400' },
    { key: '',             label: 'All',          dot: 'bg-siem-muted' },
  ]

  return (
    <div className="flex h-screen overflow-hidden bg-siem-bg">

      {/* Modals */}
      {showCreate && <CreateModal onClose={() => setShowCreate(false)} onCreated={load}/>}

      {/* Left panel — alert list */}
      <div className={`flex flex-col border-r border-siem-border transition-all duration-300 ${selectedId ? 'w-[420px]' : 'flex-1'}`}>

        {/* Header */}
        <div className="flex-shrink-0 px-5 pt-5 pb-4 border-b border-siem-border bg-siem-surface">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className="text-lg font-bold text-siem-text tracking-tight">Alerts</h1>
              {hostFilter && (
                <div className="flex items-center gap-1.5 mt-0.5">
                  <span className="text-[10px] text-siem-muted">host:</span>
                  <span className="text-[10px] font-mono text-siem-accent bg-siem-accent/10 border border-siem-accent/20 rounded px-1.5 py-0.5">{hostFilter}</span>
                  <button onClick={() => setHostFilter('')} className="text-[9px] text-siem-muted/60 hover:text-red-400 underline">clear</button>
                </div>
              )}
            </div>
            <div className="flex items-center gap-2">
              <button onClick={load}
                className="p-1.5 rounded-lg text-siem-muted hover:text-siem-text hover:bg-white/[0.05] transition-colors">
                <RefreshCw size={13}/>
              </button>
              <button onClick={() => setShowCreate(true)}
                className="flex items-center gap-1.5 text-xs bg-siem-accent hover:bg-siem-accent/90 text-white px-3 py-1.5 rounded-lg font-medium">
                <Plus size={12}/> New
              </button>
            </div>
          </div>

          {/* Status tabs */}
          <div className="flex gap-1">
            {STATUS_TABS.map(({ key, label, dot }) => (
              <button key={key} onClick={() => setFilter(key)}
                className={`flex items-center gap-1.5 text-[11px] px-3 py-1.5 rounded-lg transition-all font-medium ${
                  filter === key
                    ? 'bg-siem-accent/10 text-siem-accent border border-siem-accent/20'
                    : 'text-siem-muted hover:text-siem-text border border-transparent'
                }`}>
                {filter === key && <span className={`w-1.5 h-1.5 rounded-full ${dot}`}/>}
                {label}
                {key && counts[key] != null && (
                  <span className={`text-[9px] px-1.5 py-0.5 rounded-full font-bold ${
                    filter === key ? 'bg-siem-accent/20 text-siem-accent' : 'bg-siem-border text-siem-muted'
                  }`}>{counts[key]}</span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Search */}
        <div className="flex-shrink-0 px-4 py-2 border-b border-siem-border">
          <div className="relative">
            <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-siem-muted"/>
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search alerts…"
              className="w-full bg-siem-bg border border-siem-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-siem-text focus:outline-none focus:border-siem-accent placeholder:text-siem-muted/40"/>
          </div>
        </div>

        {/* Summary bar */}
        {filtered.length > 0 && !loading && (
          <div className="flex-shrink-0 px-4 py-2 border-b border-siem-border/40 bg-siem-surface/50">
            <div className="flex items-center justify-between">
              <SeverityBar alerts={filtered}/>
              <span className="text-[10px] text-siem-muted">{filtered.length} alert{filtered.length !== 1 ? 's' : ''}</span>
            </div>
          </div>
        )}

        {/* List */}
        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex flex-col gap-2 p-4">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="h-20 bg-siem-surface/60 rounded-xl animate-pulse border border-siem-border/30"/>
              ))}
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-siem-muted gap-3">
              <div className="w-14 h-14 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
                <Bell size={24} className="opacity-30"/>
              </div>
              <div className="text-center">
                <div className="text-sm font-medium text-siem-text/60">
                  {filter === 'open' ? 'No open alerts' : `No ${filter || ''} alerts`}
                </div>
                {filter === 'open' && (
                  <div className="text-xs text-siem-muted/50 mt-1">Your environment looks clean ✓</div>
                )}
              </div>
            </div>
          ) : (
            <>
              {sla && (sla.breached || []).length > 0 && (
                <div className="px-4 py-2 text-xs text-red-300 bg-red-950/30 border-b border-red-900/40">
                  {sla.breached.length} open alert(s) past response SLA
                  {' '}({Object.entries(sla.by_severity || {}).sort((a, b) => b[0] - a[0]).map(([s, n]) => `sev ${s}: ${n}`).join(', ')}).
                  {' '}Targets: sev 5 → 1h, sev 4 → 4h, sev 3 → 24h, sev 2 → 72h.
                </div>
              )}
              <div className="flex items-center gap-3 px-4 py-2 text-xs text-siem-muted border-b border-siem-border/50">
                <label className="flex items-center gap-1.5">
                  <input type="checkbox"
                    checked={filtered.length > 0 && filtered.every(a => checked.has(a.id))}
                    onChange={e => setChecked(e.target.checked ? new Set(filtered.map(a => a.id)) : new Set())}/>
                  Select all ({filtered.length})
                </label>
                {checked.size > 0 && (
                  <>
                    <span>{checked.size} selected</span>
                    <button disabled={bulkBusy} onClick={() => bulk('acknowledge')} className="border border-siem-border rounded px-2 py-0.5 hover:text-siem-text">Acknowledge</button>
                    <button disabled={bulkBusy} onClick={() => bulk('close')} className="border border-siem-border rounded px-2 py-0.5 hover:text-siem-text">Close</button>
                  </>
                )}
              </div>
              {filtered.map(alert => (
                <div key={alert.id} className="flex items-stretch">
                  <label className="pl-4 flex items-center">
                    <input type="checkbox" checked={checked.has(alert.id)}
                      onChange={e => setChecked(c => { const n = new Set(c); e.target.checked ? n.add(alert.id) : n.delete(alert.id); return n })}/>
                  </label>
                  <div className="flex-1 min-w-0">
                    <AlertRow alert={alert} selected={selectedId}
                      onClick={id => setSelectedId(id === selectedId ? null : id)}/>
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      </div>

      {/* Right panel — alert detail (slide-in drawer) */}
      {selectedId && (
        <div className="flex-1 min-w-0 overflow-hidden bg-siem-bg">
          <AlertPanel
            alertId={selectedId}
            users={users}
            onClose={() => setSelectedId(null)}
            onStatusChange={load}
            inline
          />
        </div>
      )}
    </div>
  )
}
