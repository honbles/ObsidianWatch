import { useEffect, useState, useCallback } from 'react'
import { ShieldAlert, ShieldCheck, Skull, FileX2, Loader2, RotateCcw, WifiOff } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { Link } from 'react-router-dom'
import api from '../api/client'
import { ProcessPicker } from './ProcessList.jsx'

// One-click response: isolate / release a host, kill a process, quarantine a
// file. Everything is confirmed, audited server-side and shown in the history.

export const isAdminUser = () => { try { return JSON.parse(localStorage.getItem('user') || '{}').role === 'admin' } catch { return false } }

export async function runAction(agentId, action, params = {}, extra = {}) {
  try {
    const { data } = await api.post(`/api/v1/agents/${agentId}/actions`, { action, params, ...extra })
    return { ok: data.status === 'ok' || data.status === 'queued' || data.status === 'sent', data }
  } catch (e) {
    const d = e.response?.data
    return { ok: false, data: d, error: d?.message || d?.error || e.message }
  }
}

const TTLS = [['Until I release it', 0], ['1 hour', 60], ['4 hours', 240], ['24 hours', 1440]]

export function useResponseState(agentId) {
  const [st, setSt] = useState(null)
  const load = useCallback(async () => {
    if (!agentId) return
    try { setSt((await api.get(`/api/v1/agents/${agentId}/response`)).data) } catch { /* not available */ }
  }, [agentId])
  useEffect(() => { load(); const t = setInterval(load, 8000); return () => clearInterval(t) }, [load])
  return [st, load]
}

export function IsolatedBadge({ state }) {
  const s = state?.state
  if (!s || !(s.isolated || s.desired_isolated)) return null
  const pending = s.desired_isolated && !s.isolated
  return (
    <span className={`text-2xs px-2 py-0.5 rounded-full border font-semibold ${pending ? 'bg-amber-900/30 text-amber-300 border-amber-700' : 'bg-red-900/40 text-red-300 border-red-700'}`}
      title="Network isolated: only the ObsidianWatch server is reachable">
      {pending ? 'ISOLATION PENDING' : 'ISOLATED'}
    </span>
  )
}

function statusStyle(s) {
  return s === 'ok' ? 'text-emerald-400' : s === 'failed' || s === 'timeout' ? 'text-red-400' : 'text-amber-300'
}

// Host detail › Response: this host's containment state and history. Actions are taken on the Response page,
// which handles one or many hosts the same way.
export function TabResponse({ agent }) {
  const [st] = useResponseState(agent.id)
  const state = st?.state
  const isolated = !!state?.isolated
  const pending = !!state?.desired_isolated && !isolated
  const acts = st?.actions || []
  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto', height: '100%' }}>
      <div className="ow-card" style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 14 }}>
        {isolated ? <ShieldAlert size={22} style={{ color: 'var(--crit)' }}/> : <ShieldCheck size={22} style={{ color: pending ? 'var(--warn)' : 'var(--ok)' }}/>}
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600 }}>{isolated ? 'Network-isolated' : pending ? 'Isolation pending: applied when the host reconnects' : 'Connected normally'}</div>
          <div className="t2" style={{ fontSize: 13.5 }}>
            {isolated && state.isolated_since ? `Since ${formatDistanceToNow(new Date(state.isolated_since), { addSuffix: true })}. ` : ''}
            {isolated && state.expires_at ? `Releases ${formatDistanceToNow(new Date(state.expires_at), { addSuffix: true })}. ` : ''}
            {st ? (st.tunnel_online ? 'Response tunnel connected.' : 'Response tunnel not connected: only isolate and release can be queued.') : 'Loading…'}
            {' '}{state?.quarantined ? `${state.quarantined} file${state.quarantined === 1 ? '' : 's'} in quarantine.` : ''}
          </div>
        </div>
        <Link to={`/response?host=${encodeURIComponent(agent.hostname)}`} className="ow-btn primary" style={{ textDecoration: 'none' }}>Take action</Link>
        <Link to={`/response?tab=live&host=${encodeURIComponent(agent.hostname)}`} className="ow-btn" style={{ textDecoration: 'none' }}>Live response</Link>
      </div>
      <div className="ow-card" style={{ overflow: 'hidden' }}>
        <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Actions on this host</span><Link to="/response?tab=history" className="c-acc" style={{ marginLeft: 'auto', fontSize: 13.5 }}>Fleet history</Link></div>
        {acts.length === 0 ? <div className="t3" style={{ padding: 16 }}>No response actions yet.</div> : acts.map(a => (
          <div key={a.id} className="ow-grid" style={{ gridTemplateColumns: '123px 168px minmax(179px, 1.4fr) minmax(157px, 1fr) 112px' }}>
            <span className="t2">{formatDistanceToNow(new Date(a.requested_at), { addSuffix: true })}</span>
            <span className="t1">{a.action.replace(/_/g, ' ')}</span>
            <span className="mono t2" title={JSON.stringify(a.params)}>{a.params?.pid ? `PID ${a.params.pid} ${a.params.image || ''}` : a.params?.path || a.params?.id || ''}</span>
            <span title={a.reason}><span className="t1">{a.requested_by}</span>{a.reason && <span className="t3"> · {a.reason}</span>}</span>
            <span className={a.status === 'ok' ? 'c-ok' : ['failed', 'timeout'].includes(a.status) ? 'c-crit' : 'c-acc'} title={a.message}>{a.status}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// Compact buttons for a process/file/host the analyst is already looking at
// (alert graph, alert panel).
export function QuickActions({ agentId, host, pid, image, path, alertId }) {
  const [busy, setBusy] = useState('')
  const [msg, setMsg] = useState(null)
  if (!agentId || !isAdminUser()) return null
  const go = async (key, action, params, confirmText) => {
    if (!window.confirm(confirmText)) return
    setBusy(key); setMsg(null)
    const r = await runAction(agentId, action, params, { alert_id: alertId ? String(alertId) : '', reason: alertId ? `from alert #${alertId}` : '' })
    setMsg({ ok: r.ok, text: r.data?.message || r.error || (r.ok ? 'Done' : 'Failed') })
    setBusy('')
  }
  const btn = 'px-2 py-1 rounded border text-mini font-semibold disabled:opacity-50'
  return (
    <div className="space-y-1.5">
      <div className="text-2xs uppercase tracking-wider text-siem-muted">Respond</div>
      <div className="flex flex-wrap gap-1.5">
        {pid > 1 && <button disabled={!!busy} className={`${btn} border-red-800 text-red-300 hover:bg-red-950/40`} onClick={() => go('k', 'kill_process', { pid, image: image || '', tree: true }, `Kill ${image || 'process'} (PID ${pid}) and its children on ${host}?`)}>{busy === 'k' ? '…' : 'Kill process'}</button>}
        {path && <button disabled={!!busy} className={`${btn} border-orange-800 text-orange-300 hover:bg-orange-950/40`} onClick={() => go('q', 'quarantine_file', { path }, `Quarantine ${path} on ${host}?`)}>{busy === 'q' ? '…' : 'Quarantine file'}</button>}
        <button disabled={!!busy} className={`${btn} border-red-800 text-red-300 hover:bg-red-950/40`} onClick={() => go('i', 'isolate', { ttl_minutes: 0 }, `Isolate ${host}? It loses access to every other host and the internet; ObsidianWatch stays reachable.`)}>{busy === 'i' ? '…' : 'Isolate host'}</button>
      </div>
      {msg && <div className={`text-mini ${msg.ok ? 'text-emerald-300' : 'text-red-300'}`}>{msg.text}</div>}
    </div>
  )
}
