import { useEffect, useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import { Maximize2, Minimize2, AlertTriangle, Loader2, RefreshCw, X } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'

// Alert Graph: what happened around this alert and how it got here, built
// from evidence (process GUIDs, parent links) and never from time proximity.
// Layout is a layered tree (lineage left to right), artifacts in lanes to the
// right. No force simulation.

const COLW = 230, ROWH = 64, NW = 188, NH = 44, LANEW = 210, PAD = 24
const LANES = ['ip', 'domain', 'file', 'reg', 'burst']
const LANE_TITLE = { ip: 'Network', domain: 'DNS', file: 'Files', reg: 'Registry', burst: 'Collapsed' }
const TYPE_COLOR = { ip: '#38bdf8', domain: '#a78bfa', file: '#fbbf24', reg: '#f472b6', burst: '#94a3b8' }
const ROLE_COLOR = { anchor: '#ef4444', ancestor: '#64748b', descendant: '#3b82f6', gap: '#f59e0b', entity: '#94a3b8' }
const EDGE_COLOR = { spawned: '#64748b', connected: '#38bdf8', resolved: '#a78bfa', wrote: '#fbbf24', modified: '#f472b6', unseen: '#f59e0b', about: '#94a3b8' }
const SEV_COLOR = { 5: '#ef4444', 4: '#f97316', 3: '#eab308' }

function layout(graph) {
  const nodes = graph.nodes || [], edges = graph.edges || []
  const byId = Object.fromEntries(nodes.map(n => [n.id, n]))
  const isTree = n => n.type === 'process' || n.type === 'gap' || n.type === 'entity'
  const treeNodes = nodes.filter(isTree)
  const kids = {}, hasParent = new Set()
  edges.forEach(e => {
    if ((e.type === 'spawned' || e.type === 'unseen') && byId[e.source] && byId[e.target]) {
      ;(kids[e.source] = kids[e.source] || []).push(e.target)
      hasParent.add(e.target)
    }
  })
  const pos = {}
  let leaf = 0, maxDepth = 0
  const place = (id, depth, seen) => {
    if (seen.has(id)) return pos[id]?.y ?? 0
    seen.add(id)
    maxDepth = Math.max(maxDepth, depth)
    const ch = (kids[id] || []).slice().sort((a, b) => (byId[a].first || '').localeCompare(byId[b].first || ''))
    let y
    if (!ch.length) { y = leaf++ * ROWH }
    else { const ys = ch.map(c => place(c, depth + 1, seen)); y = (ys[0] + ys[ys.length - 1]) / 2 }
    pos[id] = { x: PAD + depth * COLW, y: PAD + 28 + y }
    return y
  }
  const seen = new Set()
  treeNodes.filter(n => !hasParent.has(n.id)).sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .forEach(n => place(n.id, 0, seen))
  treeNodes.forEach(n => { if (!pos[n.id]) place(n.id, 0, seen) })

  // artifacts: lane per type, y near the owning process, no overlaps
  const owners = {}
  edges.forEach(e => { if (byId[e.target] && !isTree(byId[e.target]) && pos[e.source]) (owners[e.target] = owners[e.target] || []).push(pos[e.source].y) })
  const laneX = {}
  LANES.forEach((l, i) => { laneX[l] = PAD + (maxDepth + 1) * COLW + 30 + i * LANEW })
  const usedLanes = LANES.filter(l => nodes.some(n => n.type === l))
  usedLanes.forEach((l, i) => { laneX[l] = PAD + (maxDepth + 1) * COLW + 30 + i * LANEW })
  usedLanes.forEach(l => {
    const ln = nodes.filter(n => n.type === l).map(n => {
      const ys = owners[n.id] || [0]
      return { n, want: ys.reduce((a, b) => a + b, 0) / ys.length }
    }).sort((a, b) => a.want - b.want || a.n.id.localeCompare(b.n.id))
    let prev = -1e9
    ln.forEach(({ n, want }) => { const y = Math.max(want, prev + NH + 8); pos[n.id] = { x: laneX[l], y }; prev = y })
  })
  const maxY = Math.max(0, ...Object.values(pos).map(p => p.y)) + NH + PAD
  const width = Math.max(PAD * 2 + (maxDepth + 1) * COLW, usedLanes.length ? laneX[usedLanes[usedLanes.length - 1]] + NW + PAD : 0)
  return { pos, width, height: maxY, usedLanes, laneX }
}

function NodeBox({ n, p, selected, onClick }) {
  const color = n.role === 'artifact' || n.type === 'burst' ? (TYPE_COLOR[n.type] || '#94a3b8') : (ROLE_COLOR[n.role] || '#94a3b8')
  const sev = SEV_COLOR[n.severity]
  const dashed = n.type === 'gap' || n.confidence === 'low'
  return (
    <g transform={`translate(${p.x},${p.y})`} onClick={onClick} style={{ cursor: 'pointer' }}>
      <rect width={NW} height={NH} rx="8" fill="#0d1117" stroke={selected ? '#e6edf3' : color} strokeWidth={selected ? 2 : 1.3}
        strokeDasharray={dashed ? '4 3' : undefined} />
      <rect width="4" height={NH} rx="2" fill={color} />
      {sev && <circle cx={NW - 10} cy={10} r="4" fill={sev} />}
      <text x="12" y="18" fontSize="11" fontWeight="600" fill="#e6edf3">{(n.label || '').slice(0, 26)}</text>
      <text x="12" y="33" fontSize="9" fill="#8b949e">
        {n.type === 'process' ? (n.user ? n.user.slice(0, 16) + ' · ' : '') + (n.pid ? 'pid ' + n.pid : '') : (n.detail || n.type).slice(0, 30)}
        {n.collapsed ? `  +${n.collapsed} hidden` : ''}
      </text>
      {n.alerts?.length > 0 && <g><circle cx={NW - 10} cy={NH - 10} r="7" fill="#7f1d1d" /><text x={NW - 10} y={NH - 7} fontSize="9" textAnchor="middle" fill="#fecaca">{n.alerts.length}</text></g>}
    </g>
  )
}

function edgePath(a, b) {
  const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2
  const dx = Math.max(24, (x2 - x1) / 2)
  return `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`
}

function Detail({ node, edges, nodesById, onClose }) {
  const [events, setEvents] = useState(null)
  useEffect(() => { setEvents(null) }, [node?.id])
  if (!node) return null
  const myEdges = edges.filter(e => e.source === node.id || e.target === node.id)
  const loadEvents = async () => {
    const ids = [...(node.event_ids || []), ...myEdges.flatMap(e => e.event_ids || [])].filter((v, i, a) => a.indexOf(v) === i).slice(0, 12)
    const out = []
    for (const id of ids) {
      try { out.push((await api.get(`/api/v1/events/${id}`)).data) } catch { /* retention */ }
    }
    setEvents(out)
  }
  const ts = t => { try { return format(new Date(t), 'MMM d HH:mm:ss') } catch { return '' } }
  return (
    <div className="w-72 shrink-0 border-l border-siem-border overflow-y-auto p-3 space-y-3 text-xs">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="font-semibold text-siem-text break-all">{node.label}</div>
          <div className="text-[10px] uppercase tracking-wide text-siem-muted">{node.role} · {node.type}{node.confidence === 'low' ? ' · low confidence' : ''}</div>
        </div>
        <button onClick={onClose} className="text-siem-muted hover:text-siem-text"><X size={12} /></button>
      </div>
      {node.detail && <div className="font-mono text-[10px] text-siem-muted break-all">{node.detail}</div>}
      {node.cmd && <div className="font-mono text-[10px] bg-siem-bg border border-siem-border rounded p-2 break-all">{node.cmd}</div>}
      <div className="text-[10px] text-siem-muted space-y-0.5">
        {node.user && <div>User: <span className="text-siem-text">{node.user}</span></div>}
        <div>First: {ts(node.first)}</div>
        <div>Last: {ts(node.last)}</div>
        {node.ended && <div>Ended: {ts(node.ended)}</div>}
        {node.meta?.start_seen === 'false' && <div className="text-amber-400">Start event not seen</div>}
        {node.meta?.extensions && <div>Extensions: {node.meta.extensions}</div>}
        {node.meta?.items && <div>Includes: {node.meta.items}</div>}
        {node.collapsed > 0 && <div>{node.collapsed} more not drawn (budget)</div>}
      </div>
      {node.alerts?.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wide text-siem-muted mb-1">Alerts on this node</div>
          <div className="flex flex-wrap gap-1">{node.alerts.map(a => <span key={a} className="px-1.5 py-0.5 rounded bg-red-950/40 border border-red-900/50 text-red-300 font-mono text-[10px]">#{a}</span>)}</div>
        </div>
      )}
      {myEdges.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wide text-siem-muted mb-1">Links (evidence)</div>
          <div className="space-y-1">
            {myEdges.slice(0, 20).map((e, i) => {
              const other = nodesById[e.source === node.id ? e.target : e.source]
              return <div key={i} className="text-[10px]"><span style={{ color: EDGE_COLOR[e.type] }}>{e.type}</span> {e.source === node.id ? '→' : '←'} <span className="text-siem-text">{other?.label}</span> <span className="text-siem-muted">[{e.evidence}{e.count > 1 ? ` ×${e.count}` : ''}]</span></div>
            })}
          </div>
        </div>
      )}
      {(node.event_ids?.length > 0 || myEdges.some(e => e.event_ids?.length)) && (
        <div>
          {events === null
            ? <button onClick={loadEvents} className="text-[10px] border border-siem-border rounded px-2 py-1 text-siem-muted hover:text-siem-text">Show raw events</button>
            : events.length === 0 ? <div className="text-[10px] text-siem-muted">Events no longer retained.</div>
            : <div className="space-y-1">{events.map((e, i) => (
                <div key={i} className="border border-siem-border rounded p-1.5 font-mono text-[10px] break-all">
                  <div className="text-siem-muted">{ts(e.time)} · {e.event_type}</div>
                  <div>{e.command_line || e.file_path || e.reg_key || (e.dst_ip ? `${e.dst_ip}${e.dst_port ? ':' + e.dst_port : ''}` : e.process_name) || ''}</div>
                </div>))}</div>}
        </div>
      )}
    </div>
  )
}

function GraphBody({ graph, selected, setSelected }) {
  const L = useMemo(() => layout(graph), [graph])
  const nodesById = useMemo(() => Object.fromEntries(graph.nodes.map(n => [n.id, n])), [graph])
  const sel = selected ? nodesById[selected] : null
  return (
    <div className="flex flex-1 min-h-0">
      <div className="flex-1 overflow-auto">
        <svg width={L.width} height={L.height} className="block">
          {L.usedLanes.map(l => (
            <text key={l} x={L.laneX[l]} y={PAD} fontSize="10" fill="#8b949e" style={{ textTransform: 'uppercase', letterSpacing: 1 }}>{LANE_TITLE[l]}</text>
          ))}
          {graph.edges.map((e, i) => {
            const a = L.pos[e.source], b = L.pos[e.target]
            if (!a || !b) return null
            const hot = selected && (e.source === selected || e.target === selected)
            return <path key={i} d={edgePath(a, b)} fill="none" stroke={EDGE_COLOR[e.type] || '#64748b'}
              strokeWidth={hot ? 2 : 1.2} opacity={selected && !hot ? 0.25 : 0.85} strokeDasharray={e.type === 'unseen' ? '4 3' : undefined} />
          })}
          {graph.edges.filter(e => e.label && L.pos[e.source] && L.pos[e.target]).map((e, i) => {
            const a = L.pos[e.source], b = L.pos[e.target]
            return <text key={'l' + i} x={(a.x + NW + b.x) / 2} y={(a.y + b.y) / 2 + NH / 2 - 4} fontSize="9" fill="#8b949e" textAnchor="middle">{e.label}</text>
          })}
          {graph.nodes.map(n => L.pos[n.id] && <NodeBox key={n.id} n={n} p={L.pos[n.id]} selected={selected === n.id} onClick={() => setSelected(selected === n.id ? null : n.id)} />)}
        </svg>
      </div>
      <Detail node={sel} edges={graph.edges} nodesById={nodesById} onClose={() => setSelected(null)} />
    </div>
  )
}

function Panel({ alertId, full, onToggleFull }) {
  const [graph, setGraph] = useState(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)
  const [days, setDays] = useState(3)
  const [maxNodes, setMaxNodes] = useState(60)
  const [selected, setSelected] = useState(null)
  const [tlOpen, setTlOpen] = useState(false)

  const load = () => {
    setLoading(true); setErr('')
    api.get(`/api/v1/alerts/${alertId}/graph`, { params: { days, max_nodes: maxNodes } })
      .then(r => setGraph(r.data))
      .catch(e => setErr(e.response?.data?.error || 'Could not build the graph'))
      .finally(() => setLoading(false))
  }
  useEffect(load, [alertId, days, maxNodes])

  const cov = graph?.coverage
  const modeNote = { process: 'Exact process instance (GUID).', process_pid: 'No process GUID: identity is pid + image + time (low confidence).', fallback: 'No process evidence for this alert.' }[cov?.mode]
  const ts = t => { try { return format(new Date(t), 'MMM d HH:mm:ss') } catch { return '' } }

  return (
    <div className={`flex flex-col ${full ? 'h-full' : 'h-[640px]'} bg-siem-bg`}>
      <div className="shrink-0 flex items-center gap-3 px-4 py-2 border-b border-siem-border text-[11px]">
        <span className="text-siem-muted">Window</span>
        <select value={days} onChange={e => setDays(+e.target.value)} className="bg-siem-bg border border-siem-border rounded px-1.5 py-0.5">
          {[1, 3, 7, 14].map(d => <option key={d} value={d}>{d}d back</option>)}
        </select>
        <span className="text-siem-muted">Nodes</span>
        <select value={maxNodes} onChange={e => setMaxNodes(+e.target.value)} className="bg-siem-bg border border-siem-border rounded px-1.5 py-0.5">
          {[30, 60, 100, 150].map(d => <option key={d} value={d}>{d}</option>)}
        </select>
        <button onClick={load} className="text-siem-muted hover:text-siem-text" title="Reload"><RefreshCw size={12} /></button>
        <div className="flex-1" />
        {graph && <span className="text-siem-muted hidden md:inline">{graph.nodes.length} nodes · {graph.edges.length} edges · explicit evidence only</span>}
        <button onClick={onToggleFull} className="text-siem-muted hover:text-siem-text" title={full ? 'Close full screen' : 'Full screen'}>
          {full ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
        </button>
      </div>

      {loading && <div className="flex-1 flex items-center justify-center text-siem-muted text-xs gap-2"><Loader2 size={14} className="animate-spin" /> Building graph…</div>}
      {err && !loading && <div className="p-4 text-xs text-red-400">{err}</div>}

      {graph && !loading && (<>
        {(cov.gaps.length > 0 || cov.truncated || modeNote) && (
          <div className="shrink-0 px-4 py-2 space-y-1 border-b border-siem-border bg-amber-950/10">
            {modeNote && <div className="text-[10px] text-siem-muted">{modeNote} Window {ts(cov.from)} → {ts(cov.to)}.</div>}
            {cov.gaps.map(g => (
              <div key={g.id} className="flex items-start gap-1.5 text-[10px] text-amber-300/90"><AlertTriangle size={10} className="mt-0.5 shrink-0" />{g.note}</div>
            ))}
          </div>
        )}
        <GraphBody graph={graph} selected={selected} setSelected={setSelected} />
        <div className="shrink-0 border-t border-siem-border">
          <button onClick={() => setTlOpen(o => !o)} className="w-full text-left px-4 py-1.5 text-[10px] uppercase tracking-wide text-siem-muted hover:text-siem-text">
            Timeline ({graph.timeline.length}) {tlOpen ? '▾' : '▸'}
          </button>
          {tlOpen && (
            <div className="max-h-44 overflow-y-auto px-4 pb-2 space-y-0.5 font-mono text-[10px]">
              {graph.timeline.map((t, i) => (
                <div key={i} onClick={() => setSelected(t.node)} className="cursor-pointer hover:bg-siem-surface rounded px-1 flex gap-2">
                  <span className="text-siem-muted shrink-0">{ts(t.t)}</span><span className="truncate">{t.what}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </>)}
    </div>
  )
}

export default function AlertGraph({ alertId }) {
  const [full, setFull] = useState(false)
  useEffect(() => {
    if (!full) return
    const h = e => { if (e.key === 'Escape') { e.stopPropagation(); setFull(false) } }
    document.addEventListener('keydown', h, true)
    return () => document.removeEventListener('keydown', h, true)
  }, [full])
  if (full) {
    return createPortal(
      <div className="fixed inset-0 z-[200] bg-siem-bg flex flex-col">
        <Panel alertId={alertId} full onToggleFull={() => setFull(false)} />
      </div>, document.body)
  }
  return <Panel alertId={alertId} full={false} onToggleFull={() => setFull(true)} />
}
