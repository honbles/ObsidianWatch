import { useCallback, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTimeRange, ForceGraph, DataTable, StateBlock } from '../../components/shared'
import { appApi } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import AppPageHeader from '../../components/app/AppPageHeader'
import { appInt, appRel } from '../../components/app/appFormat'

export const appPath = '/applications/map'

const KIND_COLOR = { database: 'var(--violet)', queue: 'var(--teal)', external: 'var(--t2)' }
const sel = 'bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text'
const nodeColor = (n) => {
  if (n.type !== 'service') return KIND_COLOR[n.type] || 'var(--t2)'
  if (n.reachable_from_internet && ['high', 'critical'].includes(n.criticality) && n.exposure !== 'internet') return 'var(--crit)' // critical, reachable from the internet
  if (n.exposure === 'internet') return 'var(--high)'
  if (n.reachable_from_internet) return 'var(--warn)'
  return 'var(--info)'
}

// Dependencies: the estate map. Which services talk to what, what is new, and which critical
// services an internet-facing service can reach. (spec 11.3)
export default function AppMap() {
  const range = useTimeRange(7 * 24 * 3600e3)
  const navigate = useNavigate()
  const { data, loading, error } = useAppLoad(() => appApi.map(range), [range.from, range.to])
  const [env, setEnv] = useState('')
  const [exposedOnly, setExposedOnly] = useState(false)
  const [newOnly, setNewOnly] = useState(false)
  const [q, setQ] = useState('')

  const nodesById = useMemo(() => Object.fromEntries((data?.nodes || []).map(n => [n.id, n])), [data])
  const envs = useMemo(() => [...new Set((data?.nodes || []).filter(n => n.type === 'service').map(n => n.environment))].sort(), [data])
  const edges = useMemo(() => (data?.edges || []).filter(e => {
    const s = nodesById[e.source], t = nodesById[e.target]
    if (!s || !t) return false
    if (env && ((s.environment && s.environment !== env) || (t.type === 'service' && t.environment && t.environment !== env))) return false
    if (exposedOnly && !s.reachable_from_internet) return false
    if (newOnly && !e.new) return false
    if (q && !(`${s.name} ${t.name}`.toLowerCase().includes(q.toLowerCase()))) return false
    return true
  }), [data, nodesById, env, exposedOnly, newOnly, q])

  const { nodes, links } = useMemo(() => {
    const ids = new Set()
    edges.forEach(e => { ids.add(e.source); ids.add(e.target) })
    const ns = [...ids].map(id => {
      const n = nodesById[id]
      return { ...n, label: n.name, kind: n.type }
    })
    const ls = edges.map(e => ({ source: e.source, target: e.target, weight: e.calls, error: e.calls > 0 && e.errors / e.calls > 0.05 }))
    return { nodes: ns, links: ls }
  }, [edges, nodesById])

  const onNodeClick = useCallback((n) => { if (n.type === 'service' && n.key) navigate(`/applications/services/${encodeURIComponent(n.key)}?tab=dependencies`) }, [navigate])
  const paths = useMemo(() => (data?.nodes || []).filter(n => n.type === 'service' && n.reachable_from_internet && n.exposure !== 'internet' && ['high', 'critical'].includes(n.criticality)), [data])
  const exposed = useMemo(() => (data?.nodes || []).filter(n => n.type === 'service' && n.exposure === 'internet'), [data])

  const cols = [
    { key: 'source', label: 'From', render: e => nodesById[e.source]?.name, sort: e => nodesById[e.source]?.name },
    { key: 'target', label: 'To', render: e => <span>{nodesById[e.target]?.name} <span className="text-[10px] text-siem-muted">{e.kind}</span></span>, sort: e => nodesById[e.target]?.name },
    { key: 'calls', label: 'Calls (range)', align: 'right', render: e => appInt(e.calls), sort: e => e.calls },
    { key: 'errors', label: 'Errors', align: 'right', render: e => <span className={e.errors ? 'text-red-300' : ''}>{appInt(e.errors)}</span>, sort: e => e.errors },
    { key: 'first', label: 'First seen', render: e => <>{appRel(e.first_seen)} {e.new && <span className="ml-1 text-[10px] text-orange-300">new</span>}</>, sort: e => e.first_seen },
  ]
  const empty = data && data.nodes.length === 0
  return (
    <div className="p-6 space-y-4">
      <AppPageHeader title="Dependencies" range={range}
        subtitle="Highlighted: new dependencies and critical services reachable from the internet." />
      <StateBlock loading={loading && !data} error={error} empty={empty} emptyText="No dependencies yet. They appear once services send OpenTelemetry client spans.">
        {data && (<>
          <div className="flex flex-wrap gap-2 items-center">
            <input className={`${sel} w-52`} placeholder="Search…" value={q} onChange={e => setQ(e.target.value)} />
            <select className={sel} value={env} onChange={e => setEnv(e.target.value)}><option value="">All environments</option>{envs.map(x => <option key={x}>{x}</option>)}</select>
            <label className="text-xs text-siem-muted flex items-center gap-1"><input type="checkbox" checked={exposedOnly} onChange={e => setExposedOnly(e.target.checked)} /> Reachable from the internet</label>
            <label className="text-xs text-siem-muted flex items-center gap-1"><input type="checkbox" checked={newOnly} onChange={e => setNewOnly(e.target.checked)} /> New in range</label>
            <span className="text-xs text-siem-muted">{edges.length} dependencies</span>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-[1fr_280px] gap-4">
            <div className="card p-2">
              {nodes.length === 0 ? <div className="p-8 text-center text-xs text-siem-muted">Nothing matches these filters.</div>
                : <ForceGraph nodes={nodes} links={links} width={820} height={460} colorFor={nodeColor} onNodeClick={onNodeClick} />}
              <div className="flex gap-3 text-[10px] text-siem-muted px-2 pb-1 flex-wrap">
                <span><span style={{ color: 'var(--high)' }}>●</span> internet-facing</span>
                <span><span style={{ color: 'var(--warn)' }}>●</span> reachable from the internet</span>
                <span><span style={{ color: 'var(--crit)' }}>●</span> critical, reachable</span>
                <span><span style={{ color: 'var(--info)' }}>●</span> internal service</span>
                {Object.entries(KIND_COLOR).map(([k, c]) => <span key={k}><span style={{ color: c }}>●</span> {k}</span>)}
                <span><span style={{ color: 'var(--crit)' }}>-</span> errors above 5%</span>
              </div>
            </div>
            <div className="space-y-3">
              <div className="card p-3 text-xs">
                <div className="text-[10px] uppercase tracking-wide text-siem-muted mb-1">Exposure paths</div>
                <div className="text-siem-muted mb-2"><b className="text-siem-text">{exposed.length}</b> internet-facing service{exposed.length === 1 ? '' : 's'}</div>
                {paths.length === 0 ? <div className="text-siem-muted">No high or critical service is reachable from an internet-facing one.</div>
                  : paths.map(n => <div key={n.id}><button className="text-red-300 hover:underline" onClick={() => onNodeClick(n)}>{n.name}</button> <span className="text-siem-muted">{n.environment} · {n.criticality}</span></div>)}
              </div>
              <div className="card p-3 text-xs">
                <div className="text-[10px] uppercase tracking-wide text-siem-muted mb-1">New dependencies</div>
                {(data.edges.filter(e => e.new)).length === 0 ? <div className="text-siem-muted">None in this range.</div>
                  : data.edges.filter(e => e.new).slice(0, 8).map((e, i) => <div key={i}>{nodesById[e.source]?.name} → <span className="font-mono">{nodesById[e.target]?.name}</span></div>)}
              </div>
            </div>
          </div>
          <div className="card"><DataTable columns={cols} rows={edges} rowKey={(e, i) => `${e.source}${e.target}${e.via}${i}`} emptyText="No dependencies match." initialSort={{ key: 'calls', dir: 'desc' }} /></div>
        </>)}
      </StateBlock>
    </div>
  )
}
