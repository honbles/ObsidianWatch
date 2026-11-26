import { useCallback, useEffect, useMemo, useState } from 'react'
import { ChevronRight, ChevronDown, RefreshCw, Loader2, Search, Skull, Ban } from 'lucide-react'
import api from '../api/client'

// Live process table read from the host through the Live Response tunnel.
export function useProcesses(agentId, enabled = true) {
  const [st, setSt] = useState({ rows: [], loading: false, error: '', at: null })
  const load = useCallback(async () => {
    setSt(s => ({ ...s, loading: true, error: '' }))
    try {
      const { data } = await api.get(`/api/v1/agents/${agentId}/processes`)
      const cols = data.table?.columns || []
      const ix = n => cols.indexOf(n)
      const rows = (data.table?.rows || []).map(r => ({
        pid: +r[ix('pid')], ppid: +r[ix('ppid')], user: r[ix('user')] || '', name: r[ix('name')] || '',
        mem: r[ix('mem_mb')] || '', path: r[ix('path')] || '', cmd: r[ix('cmdline')] || '',
      }))
      setSt({ rows, loading: false, error: '', at: new Date() })
    } catch (e) {
      setSt(s => ({ ...s, loading: false, error: e.response?.data?.error || e.message }))
    }
  }, [agentId])
  useEffect(() => { if (enabled) load() }, [enabled, load])
  return { ...st, reload: load }
}

// Builds [{p, depth, hasKids}] in tree order. Orphans (parent not listed) become roots.
// Windows has a real process with pid 0 (System Idle), so the virtual root must not be 0.
const ROOT = -1

function flatten(rows, open, q) {
  const byPid = new Map(rows.map(r => [r.pid, r]))
  // Windows reuses PIDs, so a listed "parent" can be a descendant (or the process itself): a loop in
  // the parent chain made the old recursion run forever. A process whose chain loops becomes a root.
  const loops = r => {
    const seen = new Set([r.pid])
    let cur = byPid.get(r.ppid)
    for (let i = 0; cur && i < 200; i++) {
      if (seen.has(cur.pid)) return true
      seen.add(cur.pid)
      if (cur.ppid === cur.pid) return false // a self-parented root (System Idle) ends the chain, it is not a loop
      cur = byPid.get(cur.ppid)
    }
    return false
  }
  const kids = new Map()
  for (const r of rows) {
    const par = byPid.has(r.ppid) && r.ppid !== r.pid && !loops(r) ? r.ppid : ROOT
    if (!kids.has(par)) kids.set(par, [])
    kids.get(par).push(r)
  }
  const match = r => !q || `${r.pid} ${r.name} ${r.user} ${r.path} ${r.cmd}`.toLowerCase().includes(q)
  const keep = new Map()
  const mark = (r, depth) => {
    if (depth > 100) return false
    let k = match(r)
    for (const c of kids.get(r.pid) || []) if (mark(c, depth + 1)) k = true
    keep.set(r.pid, k)
    return k
  }
  for (const r of kids.get(ROOT) || []) mark(r, 0)
  const out = []
  const walk = (r, depth) => {
    if (depth > 100 || !keep.get(r.pid)) return
    const ch = kids.get(r.pid) || []
    out.push({ p: r, depth, hasKids: ch.length > 0 })
    if (q || open.has(r.pid)) for (const c of ch) walk(c, depth + 1)
  }
  for (const r of (kids.get(ROOT) || []).sort((a, b) => a.pid - b.pid)) walk(r, 0)
  return out
}

export function ProcessTree({ agent, onKill, onBlock, canKill }) {
  const { rows, loading, error, at, reload } = useProcesses(agent.id)
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(new Set())
  const [flat, setFlat] = useState(false)
  const ql = q.trim().toLowerCase()
  const list = useMemo(() => flat
    ? rows.filter(r => !ql || `${r.pid} ${r.name} ${r.user} ${r.path} ${r.cmd}`.toLowerCase().includes(ql)).sort((a, b) => a.name.localeCompare(b.name)).map(p => ({ p, depth: 0, hasKids: false }))
    : flatten(rows, open, ql), [rows, open, ql, flat])
  const toggle = pid => setOpen(o => { const n = new Set(o); n.has(pid) ? n.delete(pid) : n.add(pid); return n })
  const expandAll = () => setOpen(new Set(rows.map(r => r.pid)))

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={12} className="absolute left-2 top-2 text-siem-muted" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search PID, name, user, path, command line"
            className="w-full bg-siem-bg border border-siem-border rounded pl-7 pr-2 py-1.5 text-xs text-siem-text" />
        </div>
        <button onClick={() => setFlat(f => !f)} className="px-2 py-1.5 rounded border border-siem-border text-xs text-siem-muted hover:text-siem-text">{flat ? 'Tree view' : 'Flat list'}</button>
        {!flat && <button onClick={expandAll} className="px-2 py-1.5 rounded border border-siem-border text-xs text-siem-muted hover:text-siem-text">Expand all</button>}
        {!flat && <button onClick={() => setOpen(new Set())} className="px-2 py-1.5 rounded border border-siem-border text-xs text-siem-muted hover:text-siem-text">Collapse</button>}
        <button onClick={reload} disabled={loading} className="px-2 py-1.5 rounded border border-siem-border text-xs text-siem-text flex items-center gap-1 disabled:opacity-50">
          {loading ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />} Refresh
        </button>
        <span className="text-xs text-siem-muted">{rows.length} processes{at ? ` · read ${at.toLocaleTimeString()}` : ''}</span>
      </div>
      {error && <div className="rounded border border-red-800 bg-red-950/20 p-2 text-xs text-red-200">{error}. Needs the agent online with Live Response enabled.</div>}
      <div className="rounded-lg border border-siem-border overflow-auto max-h-[calc(60*var(--vh))]">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-siem-surface text-siem-muted">
            <tr><th className="text-left p-1.5">Name</th><th className="text-left p-1.5">PID</th><th className="text-left p-1.5">PPID</th>
              <th className="text-left p-1.5">User</th><th className="text-right p-1.5">Memory</th><th className="text-left p-1.5">Command line / path</th>{canKill && <th className="p-1.5" />}</tr>
          </thead>
          <tbody>
            {list.map(({ p, depth, hasKids }) => (
              <tr key={p.pid} className="border-t border-siem-border/50 hover:bg-siem-surface/50">
                <td className="p-1.5 whitespace-nowrap" style={{ paddingLeft: 6 + depth * 16 }}>
                  {hasKids ? <button onClick={() => toggle(p.pid)} className="inline-block align-middle mr-1 text-siem-muted">{(ql || open.has(p.pid)) ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</button> : <span className="inline-block w-[16px]" />}
                  <span className="text-siem-text font-medium">{p.name}</span>
                </td>
                <td className="p-1.5 font-mono text-siem-text">{p.pid}</td>
                <td className="p-1.5 font-mono text-siem-muted">{p.ppid}</td>
                <td className="p-1.5 text-siem-muted whitespace-nowrap">{p.user}</td>
                <td className="p-1.5 text-right text-siem-muted whitespace-nowrap">{p.mem ? `${p.mem} MB` : ''}</td>
                <td className="p-1.5 text-siem-muted font-mono truncate max-w-[34rem]" title={p.cmd || p.path}>{p.cmd || p.path}</td>
                {canKill && <td className="p-1.5"><button onClick={() => onKill(p)} title="Kill this process" className="text-red-400 hover:text-red-300"><Skull size={13} /></button>{onBlock && p.path && <button onClick={() => onBlock(p)} title="Block this program from running" className="ml-2 text-orange-400 hover:text-orange-300"><Ban size={13} /></button>}</td>}
              </tr>
            ))}
            {!list.length && !loading && <tr><td colSpan={7} className="p-4 text-center text-siem-muted">{error ? '' : 'No processes'}</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// Dropdown used by the Kill process card: every running process with its PID.
export function ProcessPicker({ agentId, onPick, enabled }) {
  const { rows, loading, error, reload } = useProcesses(agentId, enabled)
  const [q, setQ] = useState('')
  const ql = q.trim().toLowerCase()
  const shown = rows.filter(r => !ql || `${r.pid} ${r.name} ${r.user} ${r.path}`.toLowerCase().includes(ql)).sort((a, b) => a.name.localeCompare(b.name) || a.pid - b.pid)
  return (
    <div className="space-y-1">
      <div className="flex gap-1.5">
        <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter running processes" className="flex-1 bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text" />
        <button onClick={reload} title="Reload process list" className="px-2 rounded border border-siem-border text-siem-muted hover:text-siem-text">{loading ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}</button>
      </div>
      <select value="" onChange={e => { const p = rows.find(r => String(r.pid) === e.target.value); if (p) onPick(p) }}
        className="w-full bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text font-mono">
        <option value="">{loading ? 'Loading processes...' : error ? 'Could not load processes' : `Pick a running process (${shown.length})`}</option>
        {shown.map(r => <option key={r.pid} value={r.pid}>{r.name}  |  PID {r.pid}  |  {r.user || '-'}{r.mem ? `  |  ${r.mem} MB` : ''}</option>)}
      </select>
      {error && <div className="text-xs text-red-300">{error}</div>}
    </div>
  )
}
