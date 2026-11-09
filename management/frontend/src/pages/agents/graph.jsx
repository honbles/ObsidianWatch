import { useEffect, useState, useRef } from 'react'
import { X, RefreshCw } from 'lucide-react'
import { format } from 'date-fns'
import * as d3 from 'd3'
import api from '../../api/client'
import { EDGE_COLORS, NODE_COLORS, NODE_SHAPES, SEV_COLORS, drawNodeShape, nodeRadius, trunc } from './shared.jsx'

export function GraphCanvas({ graph, onNodeClick, selectedNode }) {
  const svgRef = useRef(null)
  useEffect(() => {
    if (!graph||!svgRef.current) return
    const el=svgRef.current, W=el.clientWidth||800, H=el.clientHeight||480
    d3.select(el).selectAll('*').remove()
    const svg=d3.select(el).attr('width',W).attr('height',H)
    const defs=svg.append('defs')
    Object.entries(EDGE_COLORS).forEach(([t,c]) => {
      defs.append('marker').attr('id',`ag2-${t}`).attr('viewBox','0 -4 8 8').attr('refX',18).attr('refY',0).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
        .append('path').attr('d','M0,-4L8,0L0,4').attr('fill',c).attr('opacity',0.7)
    })
    const g=svg.append('g')
    const zoom=d3.zoom().scaleExtent([0.1,4]).on('zoom',e=>g.attr('transform',e.transform))
    svg.call(zoom)
    const nodes=graph.nodes||[], edges=graph.edges||[]
    const nc={}; edges.forEach(e=>{nc[e.source]=(nc[e.source]||0)+1;nc[e.target]=(nc[e.target]||0)+1})
    const sim=d3.forceSimulation(nodes)
      .force('link',d3.forceLink(edges).id(d=>d.id).distance(d=>d.type==='spawned'?80:120).strength(0.4))
      .force('charge',d3.forceManyBody().strength(d=>-(nc[d.id]||1)*80-200))
      .force('center',d3.forceCenter(W/2,H/2))
      .force('collision',d3.forceCollide().radius(d=>nodeRadius(d)+12))
      .force('x',d3.forceX(W/2).strength(0.04)).force('y',d3.forceY(H/2).strength(0.04))
    const link=g.append('g').selectAll('line').data(edges).join('line')
      .attr('stroke',d=>EDGE_COLORS[d.type]||'#475569').attr('stroke-width',d=>Math.min(1+Math.log(d.count+1),4))
      .attr('stroke-opacity',0.5).attr('marker-end',d=>`url(#ag2-${d.type||'connected'})`)
    link.append('title').text(d=>`${d.type} × ${d.count}`)
    const node=g.append('g').attr('class','nodes').selectAll('g').data(nodes).join('g').attr('cursor','pointer')
      .call(d3.drag()
        .on('start',(e,d)=>{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y})
        .on('drag',(e,d)=>{d.fx=e.x;d.fy=e.y})
        .on('end',(e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}))
      .on('click',(e,d)=>{e.stopPropagation();onNodeClick(d)})
    node.each(function(d) {
      const el=d3.select(this), r=nodeRadius(d)
      const color=selectedNode?.id===d.id?'#ffffff':(d.suspicious?'#ef4444':(NODE_COLORS[d.type]||'#6b7280'))
      drawNodeShape(el,NODE_SHAPES[d.type]||'circle',r,color,d.suspicious?1:0.85,d.severity)
      if(d.severity>=4) el.append('circle').attr('r',r+4).attr('fill','none').attr('stroke',SEV_COLORS[d.severity]).attr('stroke-width',2).attr('stroke-dasharray','3,3').attr('opacity',0.7)
      el.append('text').attr('dy',r+12).attr('text-anchor','middle').attr('font-size','10px').attr('font-family','monospace').attr('fill',d.suspicious?'#fca5a5':'#94a3b8').text(trunc(d.label,22))
      if(d.event_count>1){el.append('circle').attr('cx',r-2).attr('cy',-r+2).attr('r',8).attr('fill','#1e293b').attr('stroke','#475569').attr('stroke-width',1);el.append('text').attr('x',r-2).attr('y',-r+6).attr('text-anchor','middle').attr('font-size','8px').attr('fill','#94a3b8').text(d.event_count>99?'99+':d.event_count)}
      el.append('title').text(`${d.label} (${d.type})\nEvents: ${d.event_count}\nSeverity: ${d.severity}`)
    })
    sim.on('tick',()=>{link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);node.attr('transform',d=>`translate(${d.x},${d.y})`)})
    sim.on('end',()=>{
      const b=g.node().getBBox(); if(!b.width||!b.height) return
      const sc=Math.min((W-80)/b.width,(H-80)/b.height,1.2)
      svg.transition().duration(500).call(zoom.transform,d3.zoomIdentity.translate(W/2-sc*(b.x+b.width/2),H/2-sc*(b.y+b.height/2)).scale(sc))
    })
    svg.on('click',()=>onNodeClick(null))
    return ()=>sim.stop()
  }, [graph])
  useEffect(()=>{
    if(!svgRef.current) return
    d3.select(svgRef.current).selectAll('g.nodes g').attr('opacity',d=>!selectedNode?1:d.id===selectedNode.id?1:0.3)
  }, [selectedNode])
  return <svg ref={svgRef} className="w-full h-full" style={{background:'transparent'}}/>
}

// ── NodeDetail ────────────────────────────────────────────────────────────────

export function NodeDetail({ node, onClose, host }) {
  if(!node) return null
  const [events, setEvents] = useState([])
  const [loadingEvts, setLoadingEvts] = useState(false)
  const color = NODE_COLORS[node.type] || '#6b7280'
  const meta = node.meta || {}

  // Fetch actual events for this node
  useEffect(() => {
    if (!host || !node) return
    setLoadingEvts(true)
    setEvents([])

    const params = { host, limit: 100 }

    // Build query based on node type
    if (node.type === 'process') {
      params.process_name = node.label
      params.event_type = 'process'
    } else if (node.type === 'dns') {
      params.search = node.label
    } else if (node.type === 'ip' || node.type === 'external_ip') {
      params.src_or_dst_ip = node.label
    } else if (node.type === 'file') {
      // collapsed file node — show all file events
      params.event_type = 'file'
    } else if (node.type === 'registry') {
      params.search = node.label
      params.event_type = 'registry'
    } else if (node.type === 'logon') {
      params.event_type = 'logon'
    } else {
      params.search = node.label
    }

    api.get('/api/v1/events', { params })
      .then(r => setEvents(r.data.events || []))
      .catch(() => {})
      .finally(() => setLoadingEvts(false))
  }, [node.id, host])

  return (
    <div className="w-80 shrink-0 bg-siem-surface border-l border-siem-border flex flex-col overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-siem-border" style={{borderLeftColor:color,borderLeftWidth:3}}>
        <div className="flex items-start gap-2">
          <div className="flex-1 min-w-0">
            <div className="text-xs font-mono font-bold text-siem-text truncate">{node.label}</div>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-[9px] uppercase tracking-wider" style={{color}}>{node.type}</span>
              {node.suspicious && <span className="text-[9px] px-1.5 py-px bg-red-900/40 text-red-400 border border-red-800 rounded-full font-bold">SUSPICIOUS</span>}
              <span className="text-[9px] text-siem-muted ml-auto">{node.event_count} events</span>
            </div>
          </div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text shrink-0"><X size={12}/></button>
        </div>
        {/* Severity bar */}
        <div className="flex gap-1 mt-2">
          {[1,2,3,4,5].map(s => <div key={s} className="h-1 flex-1 rounded-full" style={{background:s<=node.severity?SEV_COLORS[s]:'#1e293b'}}/>)}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-3 text-[10px]">

        {/* First/last seen */}
        {node.first_seen && (
          <div className="flex gap-4 text-siem-muted">
            <div><div className="text-[9px] uppercase tracking-wider mb-0.5 text-siem-muted/60">First seen</div>{format(new Date(node.first_seen),'HH:mm:ss dd/MM')}</div>
            <div><div className="text-[9px] uppercase tracking-wider mb-0.5 text-siem-muted/60">Last seen</div>{format(new Date(node.last_seen),'HH:mm:ss dd/MM')}</div>
          </div>
        )}

        {/* Detection alert */}
        {meta.alert_title && (
          <div className="bg-red-950/30 border border-red-900/40 rounded-lg px-2.5 py-2">
            <div className="text-[9px] uppercase tracking-wider text-red-400 font-semibold mb-1">⚠ Detection Alert</div>
            <div className="text-red-300 break-words">{meta.alert_title}</div>
          </div>
        )}

        {/* Commands for process nodes */}
        {node.type === 'process' && meta.cmdlines?.length > 0 && (
          <div>
            <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-1">Commands ({meta.cmdlines.length})</div>
            <div className="space-y-1 max-h-24 overflow-y-auto">
              {meta.cmdlines.map((cmd, i) => (
                <div key={i} className="bg-siem-bg border border-siem-border/50 rounded px-2 py-1 text-[9px] font-mono text-emerald-300/80 break-all">{cmd}</div>
              ))}
            </div>
          </div>
        )}

        {/* Collapsed file list */}
        {node.type === 'file' && meta.file_list?.length > 0 && (
          <div>
            <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-1">Files ({meta.file_list.length})</div>
            <div className="space-y-0.5 max-h-32 overflow-y-auto">
              {meta.file_list.map((f, i) => (
                <div key={i} className="text-[9px] font-mono text-yellow-400/70 truncate px-1" title={f}>{f}</div>
              ))}
            </div>
          </div>
        )}

        {/* Timeline — actual events */}
        <div>
          <div className="text-[9px] uppercase tracking-wider text-siem-muted font-semibold mb-1.5 flex items-center gap-1">
            Timeline
            {loadingEvts && <RefreshCw size={8} className="animate-spin ml-1"/>}
            {!loadingEvts && <span className="text-siem-muted/50 font-normal">({events.length})</span>}
          </div>
          {events.length === 0 && !loadingEvts && (
            <div className="text-siem-muted/40 text-center py-3">No events found</div>
          )}
          <div className="space-y-1 max-h-96 overflow-y-auto">
            {events.map((ev, i) => {
              const raw = ev.raw ? (typeof ev.raw === 'string' ? (() => { try { return JSON.parse(ev.raw) } catch { return {} } })() : ev.raw) : {}
              const detail = ev.command_line || ev.file_path || ev.dst_ip ||
                raw?.query_name || raw?.event_name || ev.process_name || ''
              return (
                <div key={ev.id || i} className="flex gap-2 bg-siem-bg/50 rounded px-2 py-1.5 border border-siem-border/30">
                  <div className="shrink-0">
                    <div className="text-[9px] font-mono text-siem-muted/60">{format(new Date(ev.time), 'HH:mm:ss')}</div>
                    <div className="mt-0.5">
                      {[1,2,3,4,5].map(s => (
                        <span key={s} className="inline-block w-1.5 h-1.5 rounded-full mr-px" style={{background: s <= ev.severity ? SEV_COLORS[s] : '#1e293b'}}/>
                      ))}
                    </div>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-[9px] text-siem-muted/70 uppercase tracking-wider">{ev.event_type}</div>
                    {detail && <div className="text-[9px] font-mono text-siem-text/80 truncate mt-0.5" title={detail}>{detail}</div>}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── ThreatIntel sub-components ────────────────────────────────────────────────

