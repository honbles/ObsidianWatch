import { useMemo } from 'react'
import { ForceGraph, DataTable } from '../shared'
import { appInt, appRel } from './appFormat'

const KIND_COLOR = { service: '#60a5fa', database: '#a78bfa', queue: '#2dd4bf', external: '#f59e0b' }

// One-hop dependency map of a service plus a table. New edges (first seen inside the
// range, after the service's own baseline) are highlighted.
export default function AppDependencyGraph({ service, edges, loading, error }) {
  const centre = `svc:${service.key}`
  const { nodes, links } = useMemo(() => {
    const ns = [{ id: centre, label: service.name, kind: 'self' }]
    const ls = []
    for (const e of edges || []) {
      const id = `${e.dst_kind}:${e.dst_name}`
      if (!ns.find(n => n.id === id)) ns.push({ id, label: e.dst_name, kind: e.dst_kind, isNew: e.new })
      const c = e.range_calls ?? e.calls, er = e.range_errors ?? e.errors
      ls.push({ source: centre, target: id, weight: c, error: c > 0 && er / c > 0.05 })
    }
    return { nodes: ns, links: ls }
  }, [edges, service, centre])
  const colorFor = (n) => (n.kind === 'self' ? '#38bdf8' : n.isNew ? '#f97316' : KIND_COLOR[n.kind] || '#94a3b8')

  const cols = [
    { key: 'dst_kind', label: 'Kind', width: 90 },
    { key: 'dst_name', label: 'Destination', render: e => <span className="font-mono text-xs">{e.dst_name}</span> },
    { key: 'range_calls', label: 'Calls (range)', align: 'right', render: e => appInt(e.range_calls), sort: e => e.range_calls },
    { key: 'range_errors', label: 'Errors (range)', align: 'right', render: e => <span className={e.range_errors ? 'text-red-300' : ''}>{appInt(e.range_errors)}</span>, sort: e => e.range_errors },
    { key: 'calls', label: 'Total calls', align: 'right', render: e => <span className="text-siem-muted">{appInt(e.calls)}</span>, sort: e => e.calls },
    { key: 'first_seen', label: 'First seen', render: e => <>{appRel(e.first_seen)} {e.new && <span className="ml-1 text-[10px] text-orange-300">new</span>}</>, sort: e => e.first_seen },
    { key: 'source', label: 'Via', width: 60 },
  ]
  return (
    <div className="space-y-3">
      {!loading && !error && edges?.length > 0 && (
        <div className="card p-2">
          <ForceGraph nodes={nodes} links={links} width={760} height={340} colorFor={colorFor} />
          <div className="flex gap-3 text-[10px] text-siem-muted px-2 pb-1 flex-wrap">
            {Object.entries(KIND_COLOR).map(([k, c]) => <span key={k}><span style={{ color: c }}>●</span> {k}</span>)}
            <span><span style={{ color: '#f97316' }}>●</span> new in range</span>
            <span><span style={{ color: '#ef4444' }}>-</span> error volume above 5%</span>
          </div>
        </div>
      )}
      <div className="card"><DataTable columns={cols} rows={edges} loading={loading} error={error}
        emptyText="No dependencies seen yet. They appear once this service sends OpenTelemetry client spans." rowKey={(e, i) => `${e.dst_kind}${e.dst_name}${e.source}${i}`}
        initialSort={{ key: 'range_calls', dir: 'desc' }} /></div>
    </div>
  )
}
