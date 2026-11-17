import { useEffect, useState, useCallback } from 'react'
import { ShieldAlert, ShieldCheck, Skull, FileX2, Loader2, RotateCcw, WifiOff } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api from '../api/client'

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
    <span className={`text-[9px] px-2 py-0.5 rounded-full border font-semibold ${pending ? 'bg-amber-900/30 text-amber-300 border-amber-700' : 'bg-red-900/40 text-red-300 border-red-700'}`}
      title="Network isolated: only the ObsidianWatch server is reachable">
      {pending ? 'ISOLATION PENDING' : 'ISOLATED'}
    </span>
  )
}

function statusStyle(s) {
  return s === 'ok' ? 'text-emerald-400' : s === 'failed' || s === 'timeout' ? 'text-red-400' : 'text-amber-300'
}

export function TabResponse({ agent }) {
  const admin = isAdminUser()
  const [st, reload] = useResponseState(agent.id)
  const [busy, setBusy] = useState('')
  const [msg, setMsg] = useState(null)
  const [ttl, setTtl] = useState(0)
  const [reason, setReason] = useState('')
  const [pid, setPid] = useState('')
  const [image, setImage] = useState('')
  const [tree, setTree] = useState(true)
  const [path, setPath] = useState('')
  const [quar, setQuar] = useState(null)

  const state = st?.state
  const isolated = !!state?.isolated
  const pending = !!state?.desired_isolated && !isolated
  const online = !!st?.tunnel_online

  const go = async (key, action, params, confirmText) => {
    if (confirmText && !window.confirm(confirmText)) return
    setBusy(key); setMsg(null)
    const r = await runAction(agent.id, action, params, { reason })
    setMsg({ ok: r.ok, text: r.data?.message || r.error || (r.ok ? 'Done' : 'Failed') })
    setBusy(''); reload()
    if (action === 'list_quarantine' && r.data?.result) setQuar(r.data.result)
    return r
  }
  const loadQuar = async () => {
    const r = await go('quar', 'list_quarantine', {})
    if (r?.data?.result) setQuar(r.data.result)
  }

  return (
    <div className="p-5 space-y-5 overflow-y-auto h-full">
      {!online && (
        <div className="rounded-lg border border-amber-800/60 bg-amber-950/20 p-3 text-xs text-amber-200 flex gap-2">
          <WifiOff size={14} className="shrink-0 mt-0.5" />
          <div>The agent's Live Response tunnel is not connected. Isolate and release will be queued and applied when it reconnects; kill and quarantine need a live agent. Response actions require <code>live_response.enabled</code> on the agent.</div>
        </div>
      )}

      <div className={`rounded-xl border p-4 ${isolated ? 'border-red-800 bg-red-950/20' : pending ? 'border-amber-800 bg-amber-950/10' : 'border-siem-border bg-siem-surface/40'}`}>
        <div className="flex items-center gap-3">
          {isolated ? <ShieldAlert className="text-red-400" size={22} /> : <ShieldCheck className="text-emerald-400" size={22} />}
          <div className="flex-1">
            <div className="text-sm font-semibold text-siem-text">
              {isolated ? 'Host is network-isolated' : pending ? 'Isolation pending (host offline)' : 'Host is connected normally'}
            </div>
            <div className="text-[11px] text-siem-muted">
              {isolated
                ? `Only the ObsidianWatch backend and management server are reachable. No other host and no internet.${state.isolated_since ? ' Since ' + formatDistanceToNow(new Date(state.isolated_since), { addSuffix: true }) + '.' : ''}${state.expires_at ? ' Auto-releases ' + formatDistanceToNow(new Date(state.expires_at), { addSuffix: true }) + '.' : ''}`
                : 'Isolation cuts the host off from every other machine and the internet, but keeps it talking to ObsidianWatch so you can still investigate with Live Response.'}
            </div>
          </div>
        </div>
        {admin && (
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <input value={reason} onChange={e => setReason(e.target.value)} placeholder="Reason (kept in the audit log)" className="flex-1 min-w-[200px] bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text" />
            {!isolated && !pending && (
              <>
                <select value={ttl} onChange={e => setTtl(+e.target.value)} className="bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text">
                  {TTLS.map(([l, v]) => <option key={v} value={v}>{l}</option>)}
                </select>
                <button disabled={!!busy} onClick={() => go('iso', 'isolate', { ttl_minutes: ttl }, `Isolate ${agent.hostname}?\n\nIt will lose access to every other host and the internet. Only ObsidianWatch stays reachable.`)}
                  className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50">
                  {busy === 'iso' ? <Loader2 size={12} className="animate-spin" /> : <ShieldAlert size={12} />} Isolate host
                </button>
              </>
            )}
            {(isolated || pending) && (
              <button disabled={!!busy} onClick={() => go('rel', 'release', {}, `Release ${agent.hostname} from isolation?`)}
                className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50">
                {busy === 'rel' ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />} Release host
              </button>
            )}
          </div>
        )}
      </div>

      {msg && <div className={`rounded-lg border p-2.5 text-xs ${msg.ok ? 'border-emerald-800 bg-emerald-950/20 text-emerald-200' : 'border-red-800 bg-red-950/20 text-red-200'}`}>{msg.text}</div>}

      {admin && (
        <div className="grid md:grid-cols-2 gap-4">
          <div className="rounded-xl border border-siem-border bg-siem-surface/40 p-4 space-y-2">
            <div className="text-xs font-semibold text-siem-text flex items-center gap-1.5"><Skull size={13} className="text-red-400" /> Kill process</div>
            <input value={pid} onChange={e => setPid(e.target.value.replace(/\D/g, ''))} placeholder="PID" className="w-full bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text font-mono" />
            <input value={image} onChange={e => setImage(e.target.value)} placeholder="Expected image, e.g. C:\Users\x\evil.exe (guards against PID reuse)" className="w-full bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text font-mono" />
            <label className="flex items-center gap-2 text-[11px] text-siem-muted"><input type="checkbox" checked={tree} onChange={e => setTree(e.target.checked)} /> Also kill child processes</label>
            <button disabled={!pid || !!busy || !online} onClick={() => go('kill', 'kill_process', { pid: +pid, image, tree }, `Kill PID ${pid}${tree ? ' and its children' : ''} on ${agent.hostname}?`)}
              className="px-3 py-1.5 rounded bg-red-700 hover:bg-red-600 text-white text-xs font-semibold disabled:opacity-40">{busy === 'kill' ? 'Killing…' : 'Kill process'}</button>
          </div>
          <div className="rounded-xl border border-siem-border bg-siem-surface/40 p-4 space-y-2">
            <div className="text-xs font-semibold text-siem-text flex items-center gap-1.5"><FileX2 size={13} className="text-orange-400" /> Quarantine file</div>
            <input value={path} onChange={e => setPath(e.target.value)} placeholder="Full path, e.g. /tmp/payload or C:\Users\x\evil.exe" className="w-full bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text font-mono" />
            <div className="text-[10px] text-siem-muted">The file is moved to a locked vault on the host with its SHA-256 recorded. It can be restored.</div>
            <div className="flex gap-2">
              <button disabled={!path || !!busy || !online} onClick={() => go('q', 'quarantine_file', { path }, `Quarantine ${path} on ${agent.hostname}?`)}
                className="px-3 py-1.5 rounded bg-orange-700 hover:bg-orange-600 text-white text-xs font-semibold disabled:opacity-40">{busy === 'q' ? 'Working…' : 'Quarantine'}</button>
              <button disabled={!!busy || !online} onClick={loadQuar} className="px-3 py-1.5 rounded border border-siem-border text-siem-muted hover:text-siem-text text-xs disabled:opacity-40">View vault ({state?.quarantined ?? 0})</button>
            </div>
          </div>
        </div>
      )}

      {quar && (
        <div className="rounded-xl border border-siem-border overflow-hidden">
          <div className="px-3 py-2 text-[10px] uppercase tracking-wider text-siem-muted bg-siem-surface/40">Quarantine vault</div>
          {quar.length === 0 ? <div className="p-3 text-xs text-siem-muted">Nothing quarantined.</div> : (
            <table className="w-full text-xs"><tbody>
              {quar.map(q => (
                <tr key={q.id} className="border-t border-siem-border/40">
                  <td className="px-3 py-2 font-mono break-all">{q.orig_path}</td>
                  <td className="px-3 py-2 font-mono text-[10px] text-siem-muted">{q.sha256?.slice(0, 16)}…</td>
                  <td className="px-3 py-2 text-right">{admin && <button onClick={() => go('r' + q.id, 'restore_file', { id: q.id }, `Restore ${q.orig_path}? It will be put back where it was.`).then(loadQuar)} className="text-siem-muted hover:text-siem-text flex items-center gap-1 ml-auto"><RotateCcw size={11} /> Restore</button>}</td>
                </tr>
              ))}
            </tbody></table>
          )}
        </div>
      )}

      <div>
        <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-1.5">Action history</div>
        <div className="rounded-xl border border-siem-border overflow-hidden">
          {(st?.actions || []).length === 0 ? <div className="p-3 text-xs text-siem-muted">No response actions yet.</div> : (
            <table className="w-full text-xs">
              <thead><tr className="text-[9px] uppercase text-siem-muted bg-siem-surface/40"><th className="text-left px-3 py-1.5">When</th><th className="text-left px-3 py-1.5">Action</th><th className="text-left px-3 py-1.5">By</th><th className="text-left px-3 py-1.5">Outcome</th></tr></thead>
              <tbody>
                {st.actions.map(a => (
                  <tr key={a.id} className="border-t border-siem-border/40 align-top">
                    <td className="px-3 py-2 text-siem-muted whitespace-nowrap">{formatDistanceToNow(new Date(a.requested_at), { addSuffix: true })}</td>
                    <td className="px-3 py-2 font-mono">{a.action}{a.params?.pid ? ` #${a.params.pid}` : ''}{a.params?.path ? ` ${a.params.path}` : ''}</td>
                    <td className="px-3 py-2">{a.requested_by}{a.reason ? <div className="text-[10px] text-siem-muted">{a.reason}</div> : null}</td>
                    <td className={`px-3 py-2 ${statusStyle(a.status)}`}>{a.status}<div className="text-[10px] text-siem-muted break-all">{a.message}</div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
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
  const btn = 'px-2 py-1 rounded border text-[10px] font-semibold disabled:opacity-50'
  return (
    <div className="space-y-1.5">
      <div className="text-[9px] uppercase tracking-wider text-siem-muted">Respond</div>
      <div className="flex flex-wrap gap-1.5">
        {pid > 1 && <button disabled={!!busy} className={`${btn} border-red-800 text-red-300 hover:bg-red-950/40`} onClick={() => go('k', 'kill_process', { pid, image: image || '', tree: true }, `Kill ${image || 'process'} (PID ${pid}) and its children on ${host}?`)}>{busy === 'k' ? '…' : 'Kill process'}</button>}
        {path && <button disabled={!!busy} className={`${btn} border-orange-800 text-orange-300 hover:bg-orange-950/40`} onClick={() => go('q', 'quarantine_file', { path }, `Quarantine ${path} on ${host}?`)}>{busy === 'q' ? '…' : 'Quarantine file'}</button>}
        <button disabled={!!busy} className={`${btn} border-red-800 text-red-300 hover:bg-red-950/40`} onClick={() => go('i', 'isolate', { ttl_minutes: 0 }, `Isolate ${host}? It loses access to every other host and the internet; ObsidianWatch stays reachable.`)}>{busy === 'i' ? '…' : 'Isolate host'}</button>
      </div>
      {msg && <div className={`text-[10px] ${msg.ok ? 'text-emerald-300' : 'text-red-300'}`}>{msg.text}</div>}
    </div>
  )
}
