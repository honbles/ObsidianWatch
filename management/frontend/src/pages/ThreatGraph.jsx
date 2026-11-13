import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import * as d3 from 'd3'
import { Monitor, Cloud, Search, RefreshCw, X, ZoomIn, ZoomOut,
         Maximize2, ChevronRight, AlertTriangle, Shield, Globe, FileText,
         Key, Cpu, Wifi, Terminal, User, GitBranch, Database, Lock,
         Eye, Clock, Hash, ExternalLink, Bell, Crosshair } from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'
import api from '../api/client'

// ── Constants ─────────────────────────────────────────────────────────────────

const NODE_COLORS = {
  host:           '#00d4ff',
  process:        '#6366f1',
  dns:            '#06b6d4',
  ip:             '#ef4444',
  file:           '#f59e0b',
  registry:       '#a855f7',
  logon:          '#10b981',
  cloud_account:  '#f97316',
  identity:       '#ec4899',
  api_call:       '#84cc16',
  resource:       '#14b8a6',
  device:         '#3b82f6',
  external_ip:    '#ef4444',
  unknown_device: '#6b7280',
}

const NODE_SHAPES = {
  host:           'diamond',
  process:        'circle',
  dns:            'circle',
  ip:             'square',
  file:           'triangle',
  registry:       'square',
  logon:          'circle',
  cloud_account:  'diamond',
  identity:       'circle',
  api_call:       'hexagon',
  resource:       'square',
  device:         'diamond',
  external_ip:    'square',
  unknown_device: 'circle',
}

const EDGE_COLORS = {
  spawned:   '#94a3b8',
  runs:      '#64748b',
  connected: '#3b82f6',
  queried:   '#06b6d4',
  wrote:     '#f59e0b',
  created:   '#22c55e',
  deleted:   '#ef4444',
  modified:  '#f97316',
  executed:  '#a855f7',
  lateral:   '#dc2626',
  auth:      '#10b981',
  called:    '#84cc16',
  accessed:  '#14b8a6',
  from_ip:   '#64748b',
  contains:  '#475569',
}

const SEV_COLORS = { 5: '#ef4444', 4: '#f97316', 3: '#eab308', 2: '#3b82f6', 1: '#475569' }

const TABS = [
  { id: 'endpoint', label: 'Endpoint', Icon: Monitor },
  { id: 'cloud',    label: 'Cloud',    Icon: Cloud   },
]

const HOURS = [6, 24, 48, 168]

// ── D3 Graph Component ────────────────────────────────────────────────────────

function GraphCanvas({ graph, onNodeClick, onEdgeClick, selectedNode, selectedEdge, tab, showSuspicious = true, filterText = '', zoomFitRef }) {
  const svgRef  = useRef(null)
  const simRef  = useRef(null)
  const zoomRef = useRef(null)

  useEffect(() => {
    if (!graph || !svgRef.current) return

    const el = svgRef.current
    const W  = el.clientWidth  || 900
    const H  = el.clientHeight || 600

    d3.select(el).selectAll('*').remove()

    const svg = d3.select(el).attr('width', W).attr('height', H)

    // Arrow markers
    const defs = svg.append('defs')
    Object.entries(EDGE_COLORS).forEach(([type, color]) => {
      defs.append('marker')
        .attr('id', `arrow-${type}`)
        .attr('viewBox', '0 -4 8 8').attr('refX', 18).attr('refY', 0)
        .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
        .append('path').attr('d', 'M0,-4L8,0L0,4')
        .attr('fill', color).attr('opacity', 0.7)
    })

    const g = svg.append('g')

    const zoom = d3.zoom().scaleExtent([0.05, 4]).on('zoom', e => g.attr('transform', e.transform))
    svg.call(zoom).on('dblclick.zoom', null).style('cursor', 'grab')
    svg.on('mousedown.cur', () => svg.style('cursor', 'grabbing')).on('mouseup.cur', () => svg.style('cursor', 'grab'))
    zoomRef.current = zoom

    const zoomFit = () => {
      const bounds = g.node().getBBox()
      if (!bounds.width || !bounds.height) return
      const padding = 80
      const scale = Math.min((W - padding * 2) / bounds.width, (H - padding * 2) / bounds.height, 1.2)
      const tx = W / 2 - scale * (bounds.x + bounds.width  / 2)
      const ty = H / 2 - scale * (bounds.y + bounds.height / 2)
      svg.transition().duration(600).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale))
    }

    // Expose zoomFit externally
    if (zoomFitRef) zoomFitRef.current = zoomFit

    const nodes = graph.nodes || []
    const edges = graph.edges || []

    const neighborCount = {}
    edges.forEach(e => {
      neighborCount[e.source] = (neighborCount[e.source] || 0) + 1
      neighborCount[e.target] = (neighborCount[e.target] || 0) + 1
    })

    // Use radial layout for hosts with many nodes to avoid spaghetti
    const useRadial = nodes.length > 60
    const hostNode  = nodes.find(n => n.type === 'host')

    let fitted = false  // fit once; re-fitting after every drag undid the move
    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(edges).id(d => d.id)
        .distance(d => d.type === 'spawned' || d.type === 'runs' ? 70 : 110)
        .strength(0.5))
      .force('charge', d3.forceManyBody().strength(d => -(neighborCount[d.id] || 1) * 60 - 180))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide().radius(d => nodeRadius(d) + 14))
      .force('x', d3.forceX(W / 2).strength(useRadial ? 0.02 : 0.04))
      .force('y', d3.forceY(H / 2).strength(useRadial ? 0.02 : 0.04))

    if (hostNode) {
      hostNode.fx = W / 2
      hostNode.fy = H / 2
      sim.on('end', () => { if (fitted) return; fitted = true; hostNode.fx = null; hostNode.fy = null; zoomFit() })
    } else {
      sim.on('end', () => { if (fitted) return; fitted = true; zoomFit() })
    }

    simRef.current = sim

    // Edges — thin visible line + thick invisible hit area for easier clicking
    const edgeG = g.append('g').attr('class', 'edges')

    // Invisible wide hit area
    edgeG.selectAll('line.hit')
      .data(edges).join('line')
      .attr('class', 'hit')
      .attr('stroke', 'transparent')
      .attr('stroke-width', 12)
      .attr('cursor', 'pointer')
      .on('click', (event, d) => { event.stopPropagation(); onEdgeClick && onEdgeClick(d) })

    const link = edgeG.selectAll('line.visible')
      .data(edges).join('line')
      .attr('class', d => `visible edge edge-src-${d.source.id || d.source} edge-dst-${d.target.id || d.target}`)
      .attr('stroke', d => EDGE_COLORS[d.type] || '#475569')
      .attr('stroke-width', d => Math.min(1 + Math.log(d.count + 1), 4))
      .attr('stroke-opacity', 0.45)
      .attr('pointer-events', 'none')
      .attr('marker-end', d => `url(#arrow-${d.type || 'connected'})`)
    link.append('title').text(d => `${d.type} × ${d.count}`)

    // Nodes
    const node = g.append('g').attr('class', 'nodes').selectAll('g')
      .data(nodes).join('g')
      .attr('class', d => `node node-${d.id}`)
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (event, d) => { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag',  (event, d) => { d.fx = event.x; d.fy = event.y })
        .on('end',   (event, d) => { if (!event.active) sim.alphaTarget(0) }))  // stay where dropped; double-click releases
      .on('dblclick', (event, d) => { event.stopPropagation(); d.fx = null; d.fy = null; sim.alpha(0.3).restart() })
      .on('click', (event, d) => { event.stopPropagation(); onNodeClick(d) })

    node.each(function(d) {
      const el  = d3.select(this)
      const r   = nodeRadius(d)
      const susp = showSuspicious && d.suspicious
      const color = susp ? '#ef4444' : (NODE_COLORS[d.type] || '#6b7280')
      drawNodeShape(el, NODE_SHAPES[d.type] || 'circle', r, color, susp ? 1 : 0.85, d.severity)

      if (showSuspicious && d.severity >= 4) {
        el.append('circle').attr('r', r + 5).attr('fill', 'none')
          .attr('stroke', SEV_COLORS[d.severity] || '#ef4444')
          .attr('stroke-width', 1.5).attr('stroke-dasharray', '3,3').attr('opacity', 0.6)
      }

      el.append('text').attr('dy', r + 13).attr('text-anchor', 'middle')
        .attr('font-size', '10px').attr('font-family', 'monospace')
        .attr('fill', susp ? '#fca5a5' : '#94a3b8')
        .text(truncate(d.label, 20))

      if (d.event_count > 1) {
        el.append('circle').attr('cx', r - 2).attr('cy', -r + 2).attr('r', 8)
          .attr('fill', '#1e293b').attr('stroke', '#475569').attr('stroke-width', 1)
        el.append('text').attr('x', r - 2).attr('y', -r + 6)
          .attr('text-anchor', 'middle').attr('font-size', '8px').attr('fill', '#94a3b8')
          .text(d.event_count > 99 ? '99+' : d.event_count)
      }
      el.append('title').text(`${d.label}\nType: ${d.type}\nEvents: ${d.event_count}\nSeverity: ${d.severity}`)
    })

    sim.on('tick', () => {
      // Update both visible lines and invisible hit areas
      edgeG.selectAll('line').attr('x1', d => d.source.x).attr('y1', d => d.source.y)
           .attr('x2', d => d.target.x).attr('y2', d => d.target.y)
      node.attr('transform', d => `translate(${d.x},${d.y})`)
    })

    svg.on('click', () => { onNodeClick(null); onEdgeClick && onEdgeClick(null) })

    return () => { sim.stop(); if (zoomFitRef) zoomFitRef.current = null }
  }, [graph, tab])

  // Highlight selected node + its edges, dim everything else
  useEffect(() => {
    if (!svgRef.current) return
    const svg = d3.select(svgRef.current)
    if (!selectedNode && !selectedEdge) {
      svg.selectAll('g.nodes g').attr('opacity', 1)
      svg.selectAll('g.edges line.visible').attr('stroke-opacity', 0.45)
      return
    }
    if (selectedEdge) {
      // Highlight only the selected edge and its two endpoint nodes
      const src = selectedEdge.source?.id || selectedEdge.source
      const dst = selectedEdge.target?.id || selectedEdge.target
      svg.selectAll('g.nodes g').attr('opacity', d => (d.id === src || d.id === dst) ? 1 : 0.1)
      svg.selectAll('g.edges line.visible').attr('stroke-opacity', d => {
        const eSrc = d.source?.id || d.source
        const eDst = d.target?.id || d.target
        return (eSrc === src && eDst === dst) ? 1 : 0.05
      })
      return
    }
    const connectedIDs = new Set([selectedNode.id])
    svg.selectAll('g.edges line.visible').each(function(d) {
      const src = d.source?.id || d.source
      const dst = d.target?.id || d.target
      if (src === selectedNode.id || dst === selectedNode.id) {
        connectedIDs.add(src); connectedIDs.add(dst)
      }
    })
    svg.selectAll('g.nodes g')
      .attr('opacity', d => connectedIDs.has(d.id) ? 1 : 0.15)
    svg.selectAll('g.edges line.visible')
      .attr('stroke-opacity', d => {
        const src = d.source?.id || d.source
        const dst = d.target?.id || d.target
        return (src === selectedNode.id || dst === selectedNode.id) ? 0.9 : 0.07
      })
  }, [selectedNode, selectedEdge])

  // Filter text — highlight matching nodes without re-running simulation
  useEffect(() => {
    if (!svgRef.current) return
    const svg = d3.select(svgRef.current)
    if (!filterText) {
      svg.selectAll('g.nodes g').attr('opacity', d => (selectedNode || selectedEdge) ? 0.1 : 1)
      return
    }
    const q = filterText.toLowerCase()
    svg.selectAll('g.nodes g').attr('opacity', d => {
      const matches = d.label?.toLowerCase().includes(q) || d.type?.toLowerCase().includes(q) ||
        JSON.stringify(d.meta || {}).toLowerCase().includes(q)
      return matches ? 1 : 0.1
    })
  }, [filterText, selectedNode])

  return <svg ref={svgRef} className="w-full h-full" style={{ background: 'transparent' }}/>
}



function nodeRadius(d) {
  const base = d.type === 'host' || d.type === 'device' || d.type === 'cloud_account' ? 18 : 10
  return base + Math.min(Math.sqrt(d.event_count || 1) * 2, 12)
}

function drawNodeShape(el, shape, r, color, opacity, sev) {
  const strokeColor = SEV_COLORS[sev] || '#475569'
  const strokeWidth = sev >= 3 ? 2 : 1

  switch (shape) {
    case 'diamond':
      el.append('polygon')
        .attr('points', `0,${-r} ${r},0 0,${r} ${-r},0`)
        .attr('fill', color).attr('opacity', opacity)
        .attr('stroke', strokeColor).attr('stroke-width', strokeWidth)
      break
    case 'square':
      el.append('rect')
        .attr('x', -r).attr('y', -r).attr('width', r * 2).attr('height', r * 2)
        .attr('rx', 3)
        .attr('fill', color).attr('opacity', opacity)
        .attr('stroke', strokeColor).attr('stroke-width', strokeWidth)
      break
    case 'triangle':
      el.append('polygon')
        .attr('points', `0,${-r} ${r * 0.87},${r * 0.5} ${-r * 0.87},${r * 0.5}`)
        .attr('fill', color).attr('opacity', opacity)
        .attr('stroke', strokeColor).attr('stroke-width', strokeWidth)
      break
    case 'hexagon': {
      const pts = d3.range(6).map(i => {
        const a = (i * Math.PI) / 3 - Math.PI / 6
        return `${r * Math.cos(a)},${r * Math.sin(a)}`
      }).join(' ')
      el.append('polygon').attr('points', pts)
        .attr('fill', color).attr('opacity', opacity)
        .attr('stroke', strokeColor).attr('stroke-width', strokeWidth)
      break
    }
    default:
      el.append('circle').attr('r', r)
        .attr('fill', color).attr('opacity', opacity)
        .attr('stroke', strokeColor).attr('stroke-width', strokeWidth)
  }
}

function truncate(s, n) {
  if (!s) return ''
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

// ── Node Detail Panel ─────────────────────────────────────────────────────────

// ── Edge Detail Panel ─────────────────────────────────────────────────────────

function EdgeDetail({ edge, graph, onClose }) {
  if (!edge) return null

  const navigate = useNavigate()
  const color  = EDGE_COLORS[edge.type] || '#475569'

  // Resolve source/target node labels from graph
  const nodes    = graph?.nodes || []
  const srcNode  = nodes.find(n => n.id === (edge.source?.id || edge.source))
  const dstNode  = nodes.find(n => n.id === (edge.target?.id || edge.target))
  const srcLabel = srcNode?.label || edge.source?.id || edge.source || '?'
  const dstLabel = dstNode?.label || edge.target?.id || edge.target || '?'

  const EDGE_DESCRIPTIONS = {
    spawned:  'Process spawned a child process',
    runs:     'Host runs this process',
    connected:'Network connection established',
    queried:  'DNS query performed',
    wrote:    'File written or modified',
    created:  'File or resource created',
    deleted:  'File deleted',
    modified: 'Registry key or file modified',
    executed: 'File executed',
    auth:     'Authentication event',
    called:   'API call made',
    accessed: 'Resource accessed',
    from_ip:  'Connection originated from this IP',
    lateral:  'Lateral movement detected',
  }

  return (
    <div className="w-80 shrink-0 bg-siem-surface border-l border-siem-border flex flex-col overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-siem-border" style={{ borderLeftColor: color, borderLeftWidth: 3 }}>
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <div className="text-[9px] uppercase tracking-wider font-semibold mb-1" style={{ color }}>
              Edge — {edge.type}
            </div>
            <div className="text-xs text-siem-text font-mono truncate">{srcLabel}</div>
            <div className="flex items-center gap-1 my-0.5">
              <div className="flex-1 h-px" style={{ background: color }}/>
              <span className="text-[9px] text-siem-muted px-1">→</span>
              <div className="flex-1 h-px" style={{ background: color }}/>
            </div>
            <div className="text-xs text-siem-text font-mono truncate">{dstLabel}</div>
          </div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text shrink-0 mt-0.5">
            <X size={12}/>
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Description */}
        <div className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2">
          <div className="text-[10px] text-siem-muted leading-relaxed">
            {EDGE_DESCRIPTIONS[edge.type] || `Relationship: ${edge.type}`}
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-center">
            <div className="text-lg font-bold font-mono text-siem-text">{edge.count || 1}</div>
            <div className="text-[9px] text-siem-muted">occurrences</div>
          </div>
          <div className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-center">
            <div className="text-lg font-bold font-mono" style={{ color: SEV_COLORS[edge.severity] || '#475569' }}>
              {['','Info','Low','Med','High','Crit'][edge.severity] || '—'}
            </div>
            <div className="text-[9px] text-siem-muted">max severity</div>
          </div>
        </div>

        {/* Timeline */}
        {edge.first_seen && (
          <div>
            <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-2 flex items-center gap-1">
              <Clock size={8}/> Timeline
            </div>
            <div className="space-y-1.5">
              <div className="flex justify-between text-[10px]">
                <span className="text-siem-muted">First seen</span>
                <span className="font-mono text-siem-text">{format(new Date(edge.first_seen), 'MM/dd HH:mm:ss')}</span>
              </div>
              <div className="flex justify-between text-[10px]">
                <span className="text-siem-muted">Last seen</span>
                <span className="font-mono text-siem-text">{edge.last_seen ? format(new Date(edge.last_seen), 'MM/dd HH:mm:ss') : '—'}</span>
              </div>
              {edge.first_seen && edge.last_seen && (
                <div className="flex justify-between text-[10px]">
                  <span className="text-siem-muted">Duration</span>
                  <span className="font-mono text-siem-text">
                    {formatDistanceToNow(new Date(edge.first_seen), { addSuffix: false })}
                  </span>
                </div>
              )}
              {edge.count > 1 && edge.first_seen && edge.last_seen && (() => {
                const ms = new Date(edge.last_seen) - new Date(edge.first_seen)
                const rate = ms > 0 ? (edge.count / (ms / 60000)).toFixed(1) : '—'
                return (
                  <div className="flex justify-between text-[10px]">
                    <span className="text-siem-muted">Rate</span>
                    <span className="font-mono text-siem-text">{rate}/min</span>
                  </div>
                )
              })()}
            </div>
          </div>
        )}

        {/* Involved nodes */}
        <div>
          <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-2">Involved</div>
          <div className="space-y-1.5">
            {[['Source', srcNode, srcLabel], ['Target', dstNode, dstLabel]].map(([role, node, label]) => (
              <div key={role} className="flex items-center gap-2 bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5">
                <div className="w-2 h-2 rounded-full shrink-0" style={{ background: node ? (NODE_COLORS[node.type] || '#6b7280') : '#475569' }}/>
                <div className="flex-1 min-w-0">
                  <div className="text-[9px] text-siem-muted">{role} · {node?.type || '?'}</div>
                  <div className="text-[10px] font-mono text-siem-text truncate">{label}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Navigate to Events */}
        <div className="border-t border-siem-border pt-3">
          <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-2">Investigate</div>
          {srcNode?.type === 'process' && (
            <button onClick={() => navigate(`/events?search=${encodeURIComponent(srcLabel)}&event_type=${edge.type === 'queried' ? 'dns' : edge.type === 'connected' ? 'network' : edge.type === 'spawned' ? 'process' : 'file'}`)}
              className="w-full flex items-center gap-2 text-[10px] px-3 py-2 bg-siem-bg border border-siem-border rounded-lg text-siem-muted hover:text-siem-accent hover:border-siem-accent/40 transition-colors">
              <ExternalLink size={10}/> View {edge.type} events for {srcLabel}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function NodeDetail({ node, onClose, host }) {
  if (!node) return null
  const navigate = useNavigate()
  const color = NODE_COLORS[node.type] || '#6b7280'
  const meta  = node.meta || {}

  // Build Events drilldown URL for this node
  const eventsUrl = () => {
    const params = new URLSearchParams()
    if (host) params.set('host', host)
    if (node.type === 'process' && node.label) params.set('search', node.label)
    if (node.type === 'dns')     params.set('event_type', 'dns')
    if (node.type === 'file')    params.set('event_type', 'file')
    if (node.type === 'registry') params.set('event_type', 'registry')
    if (node.type === 'logon')   params.set('event_type', 'logon')
    if ((node.type === 'ip' || node.type === 'external_ip') && node.label) params.set('search', node.label)
    return `/events?${params.toString()}`
  }

  return (
    <div className="w-80 shrink-0 bg-siem-surface border-l border-siem-border flex flex-col overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-siem-border" style={{ borderLeftColor: color, borderLeftWidth: 3 }}>
        <div className="flex items-start gap-2">
          <div className="flex-1 min-w-0">
            <div className="text-xs font-mono font-bold text-siem-text truncate" title={node.label}>
              {node.label}
            </div>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-[9px] text-siem-muted uppercase tracking-wider"
                style={{ color }}>{node.type}</span>
              {node.suspicious && (
                <span className="text-[9px] px-1.5 py-px bg-red-900/40 text-red-400 border border-red-800 rounded-full font-bold">
                  SUSPICIOUS
                </span>
              )}
              <span className="text-[9px] text-siem-muted ml-auto">{node.event_count} events</span>
            </div>
          </div>          <button onClick={onClose} className="text-siem-muted hover:text-siem-text shrink-0">
            <X size={12}/>
          </button>
        </div>
        {/* Severity bar */}
        <div className="flex gap-1 mt-2">
          {[1,2,3,4,5].map(s => (
            <div key={s} className="h-1 flex-1 rounded-full"
              style={{ background: s <= node.severity ? SEV_COLORS[s] : '#1e293b' }}/>
          ))}
        </div>
      </div>

      {/* Meta */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Time range */}
        {node.first_seen && (
          <div>
            <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-1.5 flex items-center gap-1">
              <Clock size={8}/> Timeline
            </div>
            <div className="text-[10px] text-siem-muted space-y-0.5">
              <div>First: {format(new Date(node.first_seen), 'HH:mm:ss dd/MM')}</div>
              <div>Last: {format(new Date(node.last_seen), 'HH:mm:ss dd/MM')}</div>
            </div>
          </div>
        )}

        {/* Process-specific */}
        {node.type === 'process' && (
          <>
            {meta.pid && <MetaRow label="PID" value={meta.pid}/>}
            {meta.ppid && <MetaRow label="PPID" value={meta.ppid}/>}
            {meta.user && <MetaRow label="User" value={meta.user}/>}
            {meta.image_path && <MetaRow label="Image" value={meta.image_path} mono/>}
            {meta.total_connections > 0 && (
              <MetaRow label="Connections" value={`${meta.total_connections} total`}/>
            )}
            {meta.cmdlines?.length > 0 && (
              <div>
                <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-1">
                  Commands ({meta.cmdlines.length})
                </div>
                <div className="space-y-1 max-h-40 overflow-y-auto">
                  {meta.cmdlines.map((cmd, i) => (
                    <div key={i} className="bg-siem-bg border border-siem-border/50 rounded px-2 py-1.5
                      text-[9px] font-mono text-emerald-300 break-all leading-relaxed">
                      {cmd}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {meta.top_connections?.length > 0 && (
              <div>
                <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-1">
                  Top Connections
                </div>
                <div className="space-y-0.5 max-h-32 overflow-y-auto">
                  {meta.top_connections.map((c, i) => (
                    <div key={i} className="flex items-center gap-2 text-[9px]">
                      <span className={`font-mono ${c.ext ? 'text-orange-300' : 'text-siem-muted'}`}>
                        {c.ip}:{c.port}
                      </span>
                      <span className="text-siem-muted/50">×{c.count}</span>
                      {c.ext && <span className="text-[8px] text-orange-400/60">ext</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}

        {/* DNS-specific */}
        {node.type === 'dns' && (
          <>
            <MetaRow label="Domain" value={meta.domain} mono/>
            {meta.query_type && <MetaRow label="Type" value={meta.query_type}/>}
            {meta.resolved_ips?.length > 0 && (
              <div>
                <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-1">
                  Resolved IPs
                </div>
                {meta.resolved_ips.map((ip, i) => (
                  <div key={i} className="text-[10px] font-mono text-blue-400">{ip}</div>
                ))}
              </div>
            )}
          </>
        )}

        {/* IP-specific */}
        {(node.type === 'ip' || node.type === 'external_ip') && (
          <>
            <MetaRow label="IP" value={meta.ip} mono/>
            {meta.port && <MetaRow label="Port" value={meta.port}/>}
            {meta.proto && <MetaRow label="Proto" value={meta.proto}/>}
            <MetaRow label="External" value={meta.is_external ? 'Yes' : 'No'}/>
          </>
        )}

        {/* File-specific */}
        {node.type === 'file' && (
          <>
            <MetaRow label="Path" value={meta.path} mono/>
            {meta.action && <MetaRow label="Action" value={meta.action}/>}
            {meta.hash && <MetaRow label="SHA256" value={meta.hash?.slice(0, 16) + '...'} mono/>}
          </>
        )}

        {/* Registry-specific */}
        {node.type === 'registry' && (
          <>
            <MetaRow label="Key" value={meta.key} mono/>
            {meta.value && <MetaRow label="Value" value={meta.value} mono/>}
            {meta.data && <MetaRow label="Data" value={String(meta.data).slice(0, 60)} mono/>}
          </>
        )}

        {/* Cloud identity */}
        {node.type === 'identity' && (
          <>
            <MetaRow label="Identity" value={node.label} mono/>
            {meta.provider && <MetaRow label="Provider" value={meta.provider?.toUpperCase()}/>}
          </>
        )}

        {/* Device */}
        {node.type === 'device' && (
          <>
            {meta.ip && <MetaRow label="IP" value={meta.ip} mono/>}
            {meta.os && <MetaRow label="OS" value={meta.os}/>}
            <MetaRow label="Agent" value={meta.has_agent ? 'Installed' : 'None'}/>
          </>
        )}

        {/* Alert correlation — shown for any node type */}
        {meta.alert_title && (
          <div className="border-t border-siem-border pt-3">
            <div className="text-[9px] uppercase tracking-wider text-red-400 font-semibold mb-1.5 flex items-center gap-1">
              <span>⚠</span> Detection Alert
            </div>
            <div className="bg-red-950/30 border border-red-900/40 rounded-lg px-3 py-2">
              <div className="text-[10px] text-red-300 break-words">{meta.alert_title}</div>
              {meta.alert_severity && (
                <div className="text-[9px] text-red-400/70 mt-0.5">Severity {meta.alert_severity}</div>
              )}
            </div>
          </div>
        )}

        {/* Drilldown actions */}
        <div className="border-t border-siem-border pt-3 space-y-1.5">
          <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-2">Investigate</div>
          <button onClick={() => navigate(eventsUrl())}
            className="w-full flex items-center gap-2 text-[10px] px-3 py-2 bg-siem-bg border border-siem-border rounded-lg text-siem-muted hover:text-siem-accent hover:border-siem-accent/40 transition-colors">
            <ExternalLink size={10}/> View events for this node
          </button>
          {host && (
            <button onClick={() => navigate(`/events?host=${encodeURIComponent(host)}&event_type=${node.type === 'process' ? 'process' : node.type === 'dns' ? 'dns' : node.type === 'file' ? 'file' : node.type === 'registry' ? 'registry' : node.type === 'logon' ? 'logon' : 'network'}`)}
              className="w-full flex items-center gap-2 text-[10px] px-3 py-2 bg-siem-bg border border-siem-border rounded-lg text-siem-muted hover:text-siem-accent hover:border-siem-accent/40 transition-colors">
              <ExternalLink size={10}/> All {node.type} events on host
            </button>
          )}
          {meta.alert_title && (
            <button onClick={() => navigate(`/alerts?host=${encodeURIComponent(host || '')}`)}
              className="w-full flex items-center gap-2 text-[10px] px-3 py-2 bg-red-950/20 border border-red-800/40 rounded-lg text-red-400 hover:bg-red-950/40 transition-colors">
              <Bell size={10}/> View alerts for this host
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function MetaRow({ label, value, mono }) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-[9px] text-siem-muted uppercase tracking-wider w-14 shrink-0 pt-0.5">{label}</span>
      <span className={`text-[10px] ${mono ? 'font-mono text-emerald-300' : 'text-siem-text'} break-all flex-1`}>
        {String(value)}
      </span>
    </div>
  )
}

// ── Legend ────────────────────────────────────────────────────────────────────

function Legend({ tab }) {
  const items = tab === 'endpoint'
    ? [
        { color: NODE_COLORS.host, label: 'Host', shape: '◆' },
        { color: NODE_COLORS.process, label: 'Process', shape: '●' },
        { color: NODE_COLORS.dns, label: 'DNS', shape: '●' },
        { color: NODE_COLORS.ip, label: 'IP/Port', shape: '■' },
        { color: NODE_COLORS.file, label: 'File', shape: '▲' },
        { color: NODE_COLORS.registry, label: 'Registry', shape: '■' },
      ]
    : [
        { color: NODE_COLORS.cloud_account, label: 'Account', shape: '◆' },
        { color: NODE_COLORS.identity, label: 'Identity', shape: '●' },
        { color: NODE_COLORS.api_call, label: 'API Call', shape: '⬡' },
        { color: NODE_COLORS.resource, label: 'Resource', shape: '■' },
        { color: NODE_COLORS.external_ip, label: 'Source IP', shape: '■' },
      ]

  return (
    <div className="absolute bottom-4 left-4 bg-siem-surface/80 backdrop-blur border border-siem-border rounded-xl px-3 py-2">
      <div className="text-[8px] uppercase tracking-wider text-siem-muted font-semibold mb-1.5">Legend</div>
      <div className="space-y-0.5">
        {items.map(({ color, label, shape }) => (
          <div key={label} className="flex items-center gap-1.5 text-[9px] text-siem-muted">
            <span style={{ color }} className="text-xs leading-none">{shape}</span>
            {label}
          </div>
        ))}
        <div className="border-t border-siem-border/30 mt-1 pt-1 space-y-0.5">
          <div className="flex items-center gap-1.5 text-[9px] text-red-400">
            <div className="w-2 h-px" style={{ background: EDGE_COLORS.lateral }}/> Lateral Movement
          </div>
          <div className="flex items-center gap-1.5 text-[9px] text-blue-400">
            <div className="w-2 h-px" style={{ background: EDGE_COLORS.connected }}/> Connection
          </div>
          <div className="flex items-center gap-1.5 text-[9px] text-cyan-400">
            <div className="w-2 h-px" style={{ background: EDGE_COLORS.queried }}/> DNS Query
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Stats Bar ─────────────────────────────────────────────────────────────────

function StatsBar({ graph, tab }) {
  const nodes = graph?.nodes || []
  const edges = graph?.edges || []

  const suspicious = nodes.filter(n => n.suspicious).length
  const critical = nodes.filter(n => n.severity >= 4).length
  const extIPs = nodes.filter(n => n.type === 'ip' || n.type === 'external_ip').length

  return (
    <div className="flex items-center gap-3 px-4 py-1.5 border-b border-siem-border bg-siem-surface shrink-0">
      <Stat label="Nodes" value={nodes.length} color="text-siem-text"/>
      <Stat label="Edges" value={edges.length} color="text-siem-muted"/>
      {suspicious > 0 && <Stat label="Suspicious" value={suspicious} color="text-red-400"/>}
      {critical > 0 && <Stat label="High Sev" value={critical} color="text-orange-400"/>}
      {extIPs > 0 && <Stat label="External IPs" value={extIPs} color="text-blue-400"/>}
      {graph?.meta?.event_count > 0 && (
        <Stat label="Events" value={graph.meta.event_count} color="text-siem-muted"/>
      )}
    </div>
  )
}

function Stat({ label, value, color }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className={`text-xs font-bold font-mono ${color}`}>{value}</span>
      <span className="text-[9px] text-siem-muted">{label}</span>
    </div>
  )
}

// ── Host Selector (Endpoint tab) ──────────────────────────────────────────────

function HostSelector({ agents, selected, onSelect, search, onSearch }) {
  return (
    <div className="w-52 shrink-0 bg-siem-surface border-r border-siem-border flex flex-col">
      <div className="p-3 border-b border-siem-border">
        <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-2">
          Hosts ({agents.length})
        </div>
        <div className="relative">
          <Search size={9} className="absolute left-2 top-1/2 -translate-y-1/2 text-siem-muted"/>
          <input value={search} onChange={e => onSearch(e.target.value)}
            placeholder="Search hosts..."
            className="w-full bg-siem-bg border border-siem-border rounded-lg pl-5 pr-2 py-1.5 text-[9px] text-siem-text placeholder-siem-muted/40 outline-none focus:border-siem-accent/50"/>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-2 space-y-1">
        {agents.length === 0 && (
          <div className="text-center text-[9px] text-siem-muted py-6">No agents</div>
        )}
        {agents.map(a => (
          <button key={a.id} onClick={() => onSelect(a)}
            className={`w-full text-left px-2.5 py-2 rounded-lg border transition-all ${
              selected?.id === a.id
                ? 'bg-siem-accent/10 border-siem-accent text-siem-accent'
                : 'border-transparent text-siem-muted hover:text-siem-text hover:bg-white/[0.02]'
            }`}>
            <div className="flex items-center gap-2">
              <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${a.online ? 'bg-emerald-400' : 'bg-red-500'}`}/>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-medium truncate">{a.hostname}</div>
                <div className="text-[8px] opacity-60">{a.last_ip || '—'} · {a.os}</div>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function ThreatGraph() {
  const [hours, setHours] = useState(24)
  const [agents, setAgents] = useState([])
  const [selectedAgent, setSelectedAgent] = useState(null)
  const [processes, setProcesses] = useState([])
  const [selectedProcess, setSelectedProcess] = useState(null)
  const [graph, setGraph] = useState(null)
  const [loading, setLoading] = useState(false)
  const [loadingProcs, setLoadingProcs] = useState(false)
  const [selectedNode, setSelectedNode] = useState(null)
  const [selectedEdge, setSelectedEdge] = useState(null)
  const [filterText, setFilterText] = useState('')
  const [showSuspicious, setShowSuspicious] = useState(true)
  const [threatIntel, setThreatIntel] = useState(null)
  const zoomFitRef = useRef(null)

  // Load agents
  useEffect(() => {
    api.get('/api/v1/agents').then(r => setAgents(r.data.agents || [])).catch(() => {})
  }, [])

  // Load processes when host or time range changes
  useEffect(() => {
    if (!selectedAgent) return
    setLoadingProcs(true)
    setProcesses([])
    setSelectedProcess(null)
    setGraph(null)
    api.get(`/api/v1/graph/endpoint/${encodeURIComponent(selectedAgent.hostname)}/processes?hours=${hours}`)
      .then(r => setProcesses(r.data.processes || []))
      .catch(() => {})
      .finally(() => setLoadingProcs(false))
  }, [selectedAgent, hours])

  // Load graph when process selected
  useEffect(() => {
    if (!selectedAgent || !selectedProcess) return
    setLoading(true)
    setSelectedNode(null)
    const proc = encodeURIComponent(selectedProcess.name)
    api.get(`/api/v1/graph/endpoint/${encodeURIComponent(selectedAgent.hostname)}?hours=${hours}&process=${proc}`)
      .then(r => {
        setGraph(r.data)
        // Extract IPs/domains for threat intel
        const ips = (r.data.nodes || []).filter(n => n.type === 'ip' || n.type === 'external_ip').map(n => n.label)
        const domains = (r.data.nodes || []).filter(n => n.type === 'dns').map(n => n.label)
        setThreatIntel({ ips, domains, suspicious: (r.data.nodes || []).filter(n => n.suspicious).length })
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [selectedAgent, selectedProcess, hours])

  const handleNodeClick = (node) => { setSelectedNode(node); setSelectedEdge(null) }
  const handleEdgeClick = (edge) => { setSelectedEdge(edge); setSelectedNode(null) }
  const clearSelection = () => { setSelectedNode(null); setSelectedEdge(null) }

  const getSevColor = (sev) => {
    if (sev >= 5) return 'text-red-400'
    if (sev >= 4) return 'text-orange-400'
    if (sev >= 3) return 'text-yellow-400'
    return 'text-siem-muted'
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-siem-bg">

      {/* Top bar */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-siem-border bg-siem-surface shrink-0">
        <GitBranch size={14} className="text-siem-accent"/>
        <span className="text-sm font-bold text-siem-text">Process Graph</span>

        {/* Host selector */}
        <select
          value={selectedAgent?.hostname || ''}
          onChange={e => {
            const a = agents.find(a => a.hostname === e.target.value)
            setSelectedAgent(a || null)
          }}
          className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1 text-xs text-siem-text outline-none focus:border-siem-accent ml-2">
          <option value="">Select host…</option>
          {agents.map(a => (
            <option key={a.id} value={a.hostname}>{a.hostname}</option>
          ))}
        </select>

        {/* Time range */}
        <div className="flex items-center gap-1 ml-2">
          <Clock size={10} className="text-siem-muted"/>
          {HOURS.map(h => (
            <button key={h} onClick={() => setHours(h)}
              className={`text-[9px] px-1.5 py-0.5 rounded ${hours === h ? 'bg-siem-accent text-white' : 'text-siem-muted hover:text-siem-text'}`}>
              {h < 24 ? `${h}h` : h === 168 ? '7d' : `${h/24}d`}
            </button>
          ))}
        </div>

        {selectedProcess && (
          <div className="flex items-center gap-1 ml-2 bg-siem-accent/10 border border-siem-accent/30 rounded-lg px-2 py-1">
            <Cpu size={10} className="text-siem-accent"/>
            <span className="text-[10px] text-siem-accent font-mono">{selectedProcess.name}</span>
            <button onClick={() => { setSelectedProcess(null); setGraph(null) }}
              className="text-siem-muted hover:text-red-400 ml-1"><X size={9}/></button>
          </div>
        )}

        <div className="ml-auto flex items-center gap-2">
          <button onClick={() => setShowSuspicious(s => !s)}
            className={`flex items-center gap-1 text-[9px] border rounded-lg px-2 py-1 transition-colors ${
              showSuspicious
                ? 'bg-red-900/30 border-red-800 text-red-400'
                : 'text-siem-muted border-siem-border hover:text-siem-text'
            }`}>
            <AlertTriangle size={9}/>
            {showSuspicious ? 'Suspicious On' : 'Suspicious Off'}
          </button>
        </div>
      </div>

      {/* Main layout */}
      <div className="flex flex-1 overflow-hidden">

        {/* Left: Process list */}
        <div className="w-56 shrink-0 border-r border-siem-border bg-siem-surface flex flex-col overflow-hidden">
          <div className="px-3 py-2 border-b border-siem-border">
            <div className="flex items-center gap-1.5">
              <Cpu size={10} className="text-siem-muted"/>
              <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Applications</span>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto">
            {!selectedAgent ? (
              <div className="flex flex-col items-center justify-center h-32 text-siem-muted/40 text-[10px] text-center px-4">
                Select a host above to see running applications
              </div>
            ) : loadingProcs ? (
              <div className="flex items-center justify-center h-20 text-siem-muted text-[10px]">
                <RefreshCw size={10} className="animate-spin mr-1"/> Loading…
              </div>
            ) : processes.length === 0 ? (
              <div className="flex items-center justify-center h-20 text-siem-muted/40 text-[10px]">
                No processes found
              </div>
            ) : (
              processes.map(proc => (
                <button key={proc.name}
                  onClick={() => setSelectedProcess(proc)}
                  className={`w-full flex items-center gap-2 px-3 py-2 text-left transition-colors border-b border-siem-border/20 ${
                    selectedProcess?.name === proc.name
                      ? 'bg-siem-accent/10 border-r-2 border-r-siem-accent'
                      : 'hover:bg-white/[0.03]'
                  }`}>
                  {proc.suspicious ? (
                    <AlertTriangle size={10} className="text-red-400 shrink-0"/>
                  ) : (
                    <Cpu size={10} className="text-siem-muted/40 shrink-0"/>
                  )}
                  <div className="flex-1 min-w-0">
                    <div className={`text-[11px] font-mono truncate ${proc.suspicious ? 'text-red-300' : 'text-siem-text'}`}>
                      {proc.name}
                    </div>
                    <div className="text-[9px] text-siem-muted/60">
                      {proc.event_count} events
                      {proc.max_severity >= 4 && <span className={`ml-1 ${getSevColor(proc.max_severity)}`}>sev{proc.max_severity}</span>}
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Center: Graph */}
        <div className="flex-1 relative overflow-hidden">
          {!selectedAgent && (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-siem-muted">
              <Monitor size={48} className="opacity-10 mb-4"/>
              <div className="text-sm font-semibold text-siem-text/30 mb-1">Select a host</div>
              <div className="text-xs opacity-50">Choose a host to see its applications</div>
            </div>
          )}

          {selectedAgent && !selectedProcess && !loadingProcs && (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-siem-muted">
              <Cpu size={48} className="opacity-10 mb-4"/>
              <div className="text-sm font-semibold text-siem-text/30 mb-1">Select an application</div>
              <div className="text-xs opacity-50">Click a process on the left to explore its activity</div>
            </div>
          )}

          {loading && (
            <div className="absolute inset-0 flex items-center justify-center z-10">
              <div className="flex items-center gap-3 bg-siem-surface/90 border border-siem-border rounded-xl px-6 py-4">
                <div className="w-5 h-5 border-2 border-siem-accent/30 border-t-siem-accent rounded-full animate-spin"/>
                <span className="text-sm text-siem-muted">Building graph…</span>
              </div>
            </div>
          )}

          {!loading && graph && graph.nodes?.length === 0 && selectedProcess && (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-siem-muted">
              <Search size={32} className="opacity-20 mb-3"/>
              <div className="text-sm text-siem-text/30">No graph data for {selectedProcess.name}</div>
              <div className="text-xs opacity-40 mt-1">Try a longer time range</div>
            </div>
          )}

          {!loading && graph && graph.nodes?.length > 0 && (
            <>
              <GraphCanvas
                graph={graph}
                onNodeClick={handleNodeClick}
                onEdgeClick={handleEdgeClick}
                selectedNode={selectedNode}
                selectedEdge={selectedEdge}
                tab="endpoint"
                showSuspicious={showSuspicious}
                filterText={filterText}
                zoomFitRef={zoomFitRef}
              />
              <Legend tab="endpoint"/>
              <div className="absolute top-3 right-3 flex flex-col gap-1">
                <button onClick={() => zoomFitRef.current?.()}
                  className="w-7 h-7 bg-siem-surface/80 backdrop-blur border border-siem-border rounded-lg flex items-center justify-center text-siem-muted hover:text-siem-text transition-colors">
                  <Maximize2 size={11}/>
                </button>
              </div>
            </>
          )}
        </div>

        {/* Right: Timeline panel when node selected */}
        {selectedNode && (
          <NodeDetail
            node={selectedNode}
            onClose={clearSelection}
            host={selectedAgent?.hostname}
          />
        )}
        {selectedEdge && !selectedNode && (
          <EdgeDetail
            edge={selectedEdge}
            graph={graph}
            onClose={clearSelection}
          />
        )}
      </div>

      {/* Bottom: Threat Intel strip */}
      {selectedProcess && (
        <div className="shrink-0 border-t border-siem-border bg-siem-surface px-4 py-2 flex items-center gap-6">
          <div className="flex items-center gap-1.5">
            <Shield size={11} className="text-siem-accent"/>
            <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Threat Intel</span>
          </div>
          <div className="flex items-center gap-4 text-[11px]">
            <span className="text-siem-muted">
              IPs: <span className="text-siem-text font-mono">{threatIntel?.ips?.length || 0}</span>
            </span>
            <span className="text-siem-muted">
              Domains: <span className="text-siem-text font-mono">{threatIntel?.domains?.length || 0}</span>
            </span>
            {threatIntel?.suspicious > 0 ? (
              <span className="flex items-center gap-1 text-red-400">
                <AlertTriangle size={10}/>
                {threatIntel.suspicious} suspicious node{threatIntel.suspicious > 1 ? 's' : ''}
              </span>
            ) : threatIntel ? (
              <span className="flex items-center gap-1 text-emerald-400">
                <Shield size={10}/>
                No threats detected
              </span>
            ) : null}
            {threatIntel?.ips?.slice(0, 3).map(ip => (
              <span key={ip} className="font-mono text-siem-muted/60 text-[10px]">{ip}</span>
            ))}
            {threatIntel?.domains?.slice(0, 3).map(d => (
              <span key={d} className="font-mono text-siem-muted/60 text-[10px]">{d}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
