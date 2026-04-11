import { Terminal as XTerm } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'
import React, { useEffect, useState, useMemo, useRef, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Monitor, Server, Apple, Globe, Wifi, WifiOff, Shield, ShieldOff, ShieldAlert,
         Key, Copy, Check, ChevronRight, X, Lock, Unlock, AlertTriangle, RefreshCw,
         Search, Activity, GitBranch, Crosshair, Clock, LayoutDashboard, Cpu, MapPin,
         Zap, Globe as GlobeIcon, FileText, User, Database, Tag, ExternalLink, Bug,
         CheckCircle, AlertCircle, LogIn, FolderOpen, Bookmark, Terminal, Square, MessageSquare, Maximize2 } from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import * as d3 from 'd3'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts'
import api from '../api/client'
import AlertPanelPortal from '../components/AlertPanel'
import { SAVED_SEARCHES } from '../pages/Events'
import { SeverityBadge } from '../components/SeverityBadge'

// ── OS helpers ────────────────────────────────────────────────────────────────

function getOSCategory(os) {
  if (!os) return 'other'
  const l = os.toLowerCase()
  if (l.includes('win')) return 'windows'
  if (l.includes('linux') || l.includes('ubuntu') || l.includes('debian') || l.includes('centos') || l.includes('rhel')) return 'linux'
  if (l.includes('mac') || l.includes('darwin')) return 'macos'
  return 'other'
}

const OS_GROUPS = {
  windows: { label: 'Windows',  icon: Monitor, color: 'text-blue-400',   border: 'border-blue-800',   bg: 'bg-blue-950/20' },
  linux:   { label: 'Linux',    icon: Server,  color: 'text-orange-400', border: 'border-orange-800', bg: 'bg-orange-950/20' },
  macos:   { label: 'macOS',    icon: Apple,   color: 'text-purple-400', border: 'border-purple-800', bg: 'bg-purple-950/20' },
  other:   { label: 'Other',    icon: Globe,   color: 'text-siem-muted', border: 'border-siem-border',bg: 'bg-siem-bg' },
}

// ── Graph constants ───────────────────────────────────────────────────────────

const NODE_COLORS = { host:'#00d4ff', process:'#6366f1', dns:'#06b6d4', ip:'#ef4444', file:'#f59e0b', registry:'#a855f7', logon:'#10b981', cloud_account:'#f97316', identity:'#ec4899', api_call:'#84cc16', resource:'#14b8a6', device:'#3b82f6', external_ip:'#ef4444', unknown_device:'#6b7280' }
const NODE_SHAPES = { host:'diamond', process:'circle', dns:'circle', ip:'square', file:'triangle', registry:'square', logon:'circle', cloud_account:'diamond', identity:'circle', api_call:'hexagon', resource:'square', device:'diamond', external_ip:'square', unknown_device:'circle' }
const EDGE_COLORS = { spawned:'#94a3b8', runs:'#64748b', connected:'#3b82f6', queried:'#06b6d4', wrote:'#f59e0b', created:'#22c55e', deleted:'#ef4444', modified:'#f97316', executed:'#a855f7', lateral:'#dc2626', auth:'#10b981', called:'#84cc16', accessed:'#14b8a6', from_ip:'#64748b', contains:'#475569' }
const SEV_COLORS = { 5:'#ef4444', 4:'#f97316', 3:'#eab308', 2:'#3b82f6', 1:'#475569' }
const SEV_LABEL  = { 5:'Critical', 4:'High', 3:'Medium', 2:'Low', 1:'Info' }
const SEV_DOT    = { 5:'#ef4444', 4:'#f97316', 3:'#eab308', 2:'#3b82f6', 1:'#475569' }
const TYPE_COLOR = { registry:'#a855f7', dns:'#06b6d4', network:'#3b82f6', process:'#8b949e', file:'#eab308', logon:'#22c55e' }
const CAT_COLOR  = { malware:'#ef4444', botnet_cc:'#ef4444', phishing:'#f97316', malicious:'#f97316', spam:'#eab308' }

// ── Graph helpers ─────────────────────────────────────────────────────────────

function nodeRadius(d) { return (d.type==='host'||d.type==='device'||d.type==='cloud_account'?18:10) + Math.min(Math.sqrt(d.event_count||1)*2,12) }

function drawNodeShape(el, shape, r, color, opacity, sev) {
  const sc=SEV_COLORS[sev]||'#475569', sw=sev>=3?2:1
  switch(shape) {
    case 'diamond': el.append('polygon').attr('points',`0,${-r} ${r},0 0,${r} ${-r},0`).attr('fill',color).attr('opacity',opacity).attr('stroke',sc).attr('stroke-width',sw); break
    case 'square':  el.append('rect').attr('x',-r).attr('y',-r).attr('width',r*2).attr('height',r*2).attr('rx',3).attr('fill',color).attr('opacity',opacity).attr('stroke',sc).attr('stroke-width',sw); break
    case 'triangle': el.append('polygon').attr('points',`0,${-r} ${r*.87},${r*.5} ${-r*.87},${r*.5}`).attr('fill',color).attr('opacity',opacity).attr('stroke',sc).attr('stroke-width',sw); break
    case 'hexagon': { const pts=d3.range(6).map(i=>{const a=(i*Math.PI)/3-Math.PI/6;return `${r*Math.cos(a)},${r*Math.sin(a)}`}).join(' '); el.append('polygon').attr('points',pts).attr('fill',color).attr('opacity',opacity).attr('stroke',sc).attr('stroke-width',sw); break }
    default: el.append('circle').attr('r',r).attr('fill',color).attr('opacity',opacity).attr('stroke',sc).attr('stroke-width',sw)
  }
}

function trunc(s,n) { return s?.length>n ? s.slice(0,n-1)+'…' : (s||'') }

// ── GraphCanvas ───────────────────────────────────────────────────────────────

function GraphCanvas({ graph, onNodeClick, selectedNode }) {
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

function NodeDetail({ node, onClose, host }) {
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

function RankBar({ rows, keyField, valueField, colorFn, onDrilldown, selectedKey }) {
  if(!rows?.length) return <div className="text-[10px] text-siem-muted text-center py-4">No data</div>
  const max=rows[0]?.[valueField]||1
  return (
    <div className="space-y-1.5">
      {rows.map((row,i)=>{
        const label=row[keyField], count=Number(row[valueField]), pct=Math.round((count/max)*100), isSel=selectedKey===label, color=colorFn?.(row)||'#00d4ff'
        return (
          <div key={i} onClick={()=>onDrilldown?.(row)} className={`rounded-lg px-2 py-1.5 cursor-pointer transition-all ${isSel?'bg-siem-accent/10 border border-siem-accent/40':'hover:bg-white/[0.02] border border-transparent'}`}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono truncate flex-1 mr-2 text-siem-text" title={label||'—'}>{label||'—'}</span>
              <span className="text-[9px] text-siem-muted shrink-0">{count.toLocaleString()}</span>
            </div>
            <div className="h-1 bg-siem-border/30 rounded-full overflow-hidden"><div className="h-full rounded-full" style={{width:pct+'%',background:color}}/></div>
          </div>
        )
      })}
    </div>
  )
}

function IntelSection({ title, icon: Icon, color='text-siem-accent', children, count, badge, defaultOpen=true }) {
  const [open,setOpen]=useState(defaultOpen)
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-siem-border cursor-pointer select-none" onClick={()=>setOpen(o=>!o)}>
        <Icon size={13} className={color}/>
        <span className="text-xs font-semibold text-siem-text">{title}</span>
        {count!=null&&count>0&&<span className="text-[9px] text-siem-muted ml-0.5">({count})</span>}
        {badge&&<span className={`ml-1 text-[9px] px-1.5 py-0.5 rounded-full font-bold ${badge.class}`}>{badge.text}</span>}
        <ChevronRight size={12} className={`ml-auto text-siem-muted transition-transform ${open?'rotate-90':''}`}/>
      </div>
      {open&&<div className="p-3">{children}</div>}
    </div>
  )
}

// ── TamperPanel ───────────────────────────────────────────────────────────────

function TamperPanel({ agent, onClose, onUpdated }) {
  const [copied,setCopied]=useState(false), [toggling,setToggling]=useState(false)
  const copy=()=>{navigator.clipboard.writeText(agent.install_key||'');setCopied(true);setTimeout(()=>setCopied(false),2000)}
  const toggleTamper=async()=>{setToggling(true);try{await api.patch(`/api/v1/agents/${agent.id}/tamper`,{locked:!agent.tamper_locked});onUpdated()}finally{setToggling(false)}}
  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-lg bg-siem-surface border-l border-siem-border h-full overflow-y-auto shadow-2xl" onClick={e=>e.stopPropagation()}>
        <div className="flex items-center gap-2 px-5 py-4 border-b border-siem-border sticky top-0 bg-siem-surface z-10">
          <ShieldAlert size={16} className="text-siem-accent"/><span className="font-semibold text-siem-text text-sm">Tamper Protection</span>
          <span className="ml-2 text-[10px] text-siem-muted font-mono">{agent.hostname}</span>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={16}/></button>
        </div>
        <div className="p-5 space-y-5">
          <div className={`rounded-xl border p-4 flex items-center gap-4 ${agent.tamper_locked?'bg-emerald-950/20 border-emerald-800':'bg-siem-bg border-siem-border'}`}>
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center border ${agent.tamper_locked?'bg-emerald-900/40 border-emerald-700':'bg-siem-surface border-siem-border'}`}>
              {agent.tamper_locked?<Lock size={18} className="text-emerald-400"/>:<Unlock size={18} className="text-siem-muted"/>}
            </div>
            <div className="flex-1"><div className={`text-sm font-semibold ${agent.tamper_locked?'text-emerald-400':'text-siem-text'}`}>{agent.tamper_locked?'ENABLED':'DISABLED'}</div><div className="text-[10px] text-siem-muted mt-0.5">{agent.tamper_locked?'Cannot be stopped without install key':'Can be stopped by any administrator'}</div></div>
            <button onClick={toggleTamper} disabled={toggling} className={`text-xs px-3 py-1.5 rounded-lg border font-medium ${agent.tamper_locked?'border-red-800 text-red-400 hover:bg-red-900/20':'border-emerald-800 text-emerald-400 hover:bg-emerald-900/20'}`}>{toggling?'…':agent.tamper_locked?'Disable':'Enable'}</button>
          </div>
          <div><div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2 flex items-center gap-1"><Key size={9}/> Install Key</div>
            <div className="bg-siem-bg border border-siem-border rounded-xl p-3 flex items-center gap-2">
              <code className="text-emerald-300 font-mono text-sm flex-1 truncate">{agent.install_key||'Not yet set'}</code>
              {agent.install_key&&<button onClick={copy} className="shrink-0 p-1.5 rounded border border-siem-border hover:border-siem-accent/40 text-siem-muted hover:text-siem-text">{copied?<Check size={13} className="text-emerald-400"/>:<Copy size={13}/>}</button>}
            </div>
          </div>
          <div><div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">Agent Details</div>
            <div className="bg-siem-bg border border-siem-border rounded-xl overflow-hidden">
              {[['Agent ID',agent.id],['Hostname',agent.hostname],['OS',agent.os||'—'],['Version',agent.version||'—'],['Last IP',agent.last_ip||'—'],['Events',agent.event_count?.toLocaleString()||'0']].map(([k,v],i)=>(
                <div key={k} className={`flex gap-3 px-4 py-2 text-xs ${i%2===0?'':'bg-white/[0.02]'}`}><span className="text-siem-muted w-20 shrink-0">{k}</span><span className="font-mono text-siem-text text-[10px] break-all">{v}</span></div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── OSGroup (fleet view) ──────────────────────────────────────────────────────

function OSGroup({ category, agents, onViewTamper, onSelectHost }) {
  const [collapsed,setCollapsed]=useState(false)
  const style=OS_GROUPS[category]||OS_GROUPS.other, Icon=style.icon, online=agents.filter(a=>a.online).length
  return (
    <div className={`bg-siem-surface border rounded-xl overflow-hidden ${style.border}`}>
      <div className={`flex items-center gap-3 px-4 py-3 cursor-pointer ${style.bg} border-b border-siem-border/50`} onClick={()=>setCollapsed(c=>!c)}>
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center border ${style.border} ${style.bg}`}><Icon size={14} className={style.color}/></div>
        <span className={`text-sm font-bold ${style.color}`}>{style.label}</span>
        <div className="flex items-center gap-2 ml-2 text-[10px]"><span className="text-emerald-400">{online} online</span><span className="text-siem-muted">/ {agents.length} total</span></div>
        <ChevronRight size={13} className={`ml-auto text-siem-muted transition-transform ${collapsed?'':'rotate-90'}`}/>
      </div>
      {!collapsed&&(
        <table className="w-full">
          <thead><tr className="border-b border-siem-border/30 text-siem-muted text-[9px] uppercase tracking-wider">
            <th className="text-left px-4 py-2">Agent</th><th className="text-left px-4 py-2">Status</th>
            <th className="text-left px-4 py-2">OS</th><th className="text-left px-4 py-2">Last IP</th>
            <th className="text-left px-4 py-2">Last Seen</th><th className="text-right px-4 py-2">Events</th><th className="px-4 py-2"></th>
          </tr></thead>
          <tbody>
            {agents.map(a=>(
              <tr key={a.id} className="border-b border-siem-border/30 hover:bg-white/[0.02] group transition-colors cursor-pointer" onClick={()=>onSelectHost(a)}>
                <td className="px-4 py-2.5"><div className="flex items-center gap-2">{a.online?<Wifi size={12} className="text-emerald-400 shrink-0"/>:<WifiOff size={12} className="text-siem-muted/50 shrink-0"/>}<div><div className="text-siem-text font-medium text-sm">{a.hostname}</div><div className="text-siem-muted text-[9px] font-mono">{a.id?.slice(0,16)}…</div></div></div></td>
                <td className="px-4 py-2.5"><span className={`text-[9px] px-2 py-0.5 rounded-full border font-medium ${a.online?'bg-emerald-900/30 text-emerald-400 border-emerald-800':'bg-siem-bg text-siem-muted border-siem-border'}`}>{a.online?'Online':'Offline'}</span></td>
                <td className="px-4 py-2.5 text-siem-muted text-xs">{a.os}</td>
                <td className="px-4 py-2.5 text-siem-muted text-xs font-mono">{a.last_ip}</td>
                <td className="px-4 py-2.5 text-siem-muted text-[10px]">{a.last_seen?formatDistanceToNow(new Date(a.last_seen),{addSuffix:true}):'—'}</td>
                <td className="px-4 py-2.5 text-siem-text text-xs text-right">{a.event_count?.toLocaleString()}</td>
                <td className="px-4 py-2.5"><div className="flex items-center gap-1 justify-end">
                  <button onClick={e=>{e.stopPropagation();onViewTamper(a)}} className="p-1 rounded hover:bg-siem-accent/10">{a.tamper_locked?<Shield size={13} className="text-emerald-400"/>:<ShieldOff size={13} className="text-siem-muted/50"/>}</button>
                  <ChevronRight size={12} className="text-siem-muted/30 group-hover:text-siem-muted"/>
                </div></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

// ── Tab: Overview ─────────────────────────────────────────────────────────────

function TabOverview({ agent }) {
  const navigate = useNavigate()
  const goEvents = () => navigate(`/events?host=${encodeURIComponent(agent.hostname)}`)
  const goAlerts = () => navigate(`/alerts?host=${encodeURIComponent(agent.hostname)}`)
  return (
    <div className="p-5 space-y-4">
      <div className="grid grid-cols-4 gap-3">
        {[{label:'Status',value:agent.online?'Online':'Offline',color:agent.online?'text-emerald-400':'text-siem-muted'},{label:'OS',value:agent.os||'—',color:'text-siem-text'},{label:'Version',value:agent.version||'—',color:'text-siem-text'},{label:'Events',value:agent.event_count?.toLocaleString()||'0',color:'text-siem-text'}].map(({label,value,color})=>(
          <div key={label} className="bg-siem-bg border border-siem-border rounded-xl p-4"><div className="text-[10px] text-siem-muted uppercase tracking-wider mb-1">{label}</div><div className={`text-base font-bold font-mono ${color}`}>{value}</div></div>
        ))}
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
          <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-3">System info</div>
          {[['Hostname',agent.hostname],['Agent ID',agent.id],['Last IP',agent.last_ip||'—'],['Last Seen',agent.last_seen?formatDistanceToNow(new Date(agent.last_seen),{addSuffix:true}):'—'],['Tamper',agent.tamper_locked?'Protected':'Unlocked']].map(([k,v])=>(
            <div key={k} className="flex justify-between text-xs py-1.5 border-b border-siem-border/40 last:border-0"><span className="text-siem-muted">{k}</span><span className="font-mono text-siem-text text-[11px]">{v}</span></div>
          ))}
        </div>
        <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
          <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-3">Quick actions</div>
          <div className="space-y-2">
            <button onClick={goEvents} className="w-full flex items-center gap-2 text-xs text-siem-muted hover:text-siem-accent transition-colors px-3 py-2.5 rounded-lg hover:bg-siem-accent/5 border border-transparent hover:border-siem-accent/20">
              <Activity size={13}/><span>View all events for <strong className="text-siem-text">{agent.hostname}</strong></span><ChevronRight size={11} className="ml-auto"/>
            </button>
            <button onClick={goAlerts} className="w-full flex items-center gap-2 text-xs text-siem-muted hover:text-siem-accent transition-colors px-3 py-2.5 rounded-lg hover:bg-siem-accent/5 border border-transparent hover:border-siem-accent/20">
              <Zap size={13}/><span>View all alerts for <strong className="text-siem-text">{agent.hostname}</strong></span><ChevronRight size={11} className="ml-auto"/>
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Tab: Events (full Events page embedded, host-filtered) ────────────────────

const EVENT_TYPE_META = {
  process:  {label:'Process',  color:'text-indigo-400'},
  network:  {label:'Network',  color:'text-blue-400'},
  dns:      {label:'DNS',      color:'text-cyan-400'},
  logon:    {label:'Logon',    color:'text-emerald-400'},
  file:     {label:'File',     color:'text-yellow-400'},
  registry: {label:'Registry', color:'text-purple-400'},
  sysmon:   {label:'Sysmon',   color:'text-pink-400'},
  health:   {label:'Health',   color:'text-teal-400'},
}

const TAG_COLORS = {
  event_type:'bg-purple-900/40 text-purple-300 border-purple-800/60',
  severity:  'bg-orange-900/40 text-orange-300 border-orange-800/60',
  os:        'bg-blue-900/40 text-blue-300 border-blue-800/60',
  search:    'bg-siem-bg text-siem-text border-siem-border',
  src_or_dst_ip:'bg-red-900/40 text-red-300 border-red-800/60',
  dst_port:  'bg-cyan-900/40 text-cyan-300 border-cyan-800/60',
}

function EventPanel({ event, onClose }) {
  const [detail, setDetail] = useState(null)
  useEffect(() => {
    api.get(`/api/v1/events/${event.id}`).then(r => setDetail(r.data)).catch(()=>{})
  }, [event.id])
  const ev = detail?.event || event
  const raw = ev.raw ? (typeof ev.raw==='string' ? (()=>{try{return JSON.parse(ev.raw)}catch{return {}}})() : ev.raw) : null
  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-xl bg-siem-surface border-l border-siem-border h-full overflow-y-auto" onClick={e=>e.stopPropagation()}>
        <div className="flex items-center gap-2 px-5 py-4 border-b border-siem-border sticky top-0 bg-siem-surface z-10">
          <span className="font-semibold text-siem-text text-sm">Event Detail</span>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={16}/></button>
        </div>
        <div className="p-5 space-y-4 text-xs">
          <div className="grid grid-cols-2 gap-3">
            {[['Host',ev.host],['Time',ev.time?format(new Date(ev.time),'yyyy-MM-dd HH:mm:ss'):'—'],['Type',ev.event_type],['Severity',SEV_LABEL[ev.severity]||ev.severity],['OS',ev.os||'—'],['Source',ev.source||'—'],['User',ev.user_name||'—'],['Process',ev.process_name||'—']].map(([k,v])=>(
              <div key={k}><div className="text-siem-muted mb-0.5">{k}</div><div className="font-mono text-siem-text break-all">{v||'—'}</div></div>
            ))}
          </div>
          {ev.command_line&&<div><div className="text-siem-muted mb-1">Command line</div><div className="bg-siem-bg border border-siem-border rounded p-2 font-mono text-[10px] text-emerald-300 break-all">{ev.command_line}</div></div>}
          {ev.dst_ip&&<div><div className="text-siem-muted mb-0.5">Destination</div><div className="font-mono text-blue-400">{ev.dst_ip}{ev.dst_port?`:${ev.dst_port}`:''}</div></div>}
          {ev.file_path&&<div><div className="text-siem-muted mb-0.5">File path</div><div className="font-mono text-yellow-400 break-all">{ev.file_path}</div></div>}
          {ev.reg_key&&<div><div className="text-siem-muted mb-0.5">Registry key</div><div className="font-mono text-purple-400 break-all">{ev.reg_key}</div></div>}
          {raw&&Object.keys(raw).length>0&&<div><div className="text-siem-muted mb-1">Raw data</div><pre className="bg-siem-bg border border-siem-border rounded p-2 text-[9px] text-siem-muted overflow-x-auto whitespace-pre-wrap">{JSON.stringify(raw,null,2)}</pre></div>}
          {detail?.related?.length>0&&<div><div className="text-siem-muted mb-2 font-semibold uppercase tracking-wider text-[9px]">Related events (±5 min)</div><div className="space-y-1">{detail.related.map((r,i)=><div key={i} className="flex items-center gap-2 text-[10px] bg-siem-bg rounded px-2 py-1.5"><span className="text-siem-muted font-mono">{format(new Date(r.time),'HH:mm:ss')}</span><span className={EVENT_TYPE_META[r.event_type]?.color||'text-siem-muted'}>{r.event_type}</span><span className="text-siem-muted truncate flex-1">{r.process_name||r.dst_ip||r.user_name||'—'}</span></div>)}</div></div>}
        </div>
      </div>
    </div>
  )
}

function TabEvents({ agent }) {
  const [events,setEvents]=useState([])
  const [total,setTotal]=useState(0)
  const [loading,setLoading]=useState(false)
  const [page,setPage]=useState(0)
  const [selected,setSelected]=useState(null)
  const [tags,setTags]=useState([])
  const [inputVal,setInputVal]=useState('')
  const [since,setSince]=useState('')
  const [until,setUntil]=useState('')
  const [showSaved,setShowSaved]=useState(false)
  const inputRef=useRef(null)
  const limit=200

  const classifyTerm = (val) => {
    const v=val.trim(); if(!v) return null
    const lower=v.toLowerCase()
    if(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) return {field:'src_or_dst_ip',label:'IP: '+v,value:v}
    if(/^\d{1,5}$/.test(v)&&parseInt(v)<=65535) return {field:'dst_port',label:'Port: '+v,value:v}
    const types=['process','network','dns','file','logon','registry','sysmon','raw','health','applog']
    if(types.includes(lower)) return {field:'event_type',label:'Type: '+v,value:lower}
    const sevMap={critical:5,high:4,medium:3,low:2,info:1}
    if(sevMap[lower]) return {field:'severity',label:'Severity: '+v,value:String(sevMap[lower])}
    return {field:'search',label:v,value:v}
  }

  const addTag = (raw) => { const t=classifyTerm(raw); if(!t) return; setTags(ts=>[...ts,{id:Date.now()+Math.random(),...t}]); setInputVal('') }
  const removeTag = (id) => setTags(ts=>ts.filter(t=>t.id!==id))
  const handleKeyDown = (e) => {
    if((e.key==='Enter'||e.key===',')&&inputVal.trim()){e.preventDefault();addTag(inputVal)}
    if(e.key==='Backspace'&&!inputVal&&tags.length>0) setTags(ts=>ts.slice(0,-1))
  }

  const buildParams = useCallback((p=0) => {
    const params={limit,offset:p*limit,host:agent.hostname}
    const searchTerms=[]
    tags.forEach(tag=>{ if(tag.field==='src_or_dst_ip'||tag.field==='search') searchTerms.push(tag.value); else params[tag.field]=tag.value })
    if(searchTerms.length>0) params.search=searchTerms.join(' ')
    if(since) params.since=new Date(since).toISOString()
    if(until) params.until=new Date(until+':59').toISOString()
    return params
  }, [tags,since,until,agent.hostname])

  const fetch = useCallback(async(p=0)=>{
    setLoading(true)
    try { const{data}=await api.get('/api/v1/events',{params:buildParams(p)}); setEvents(data.events||[]); setTotal(data.total||0) }
    finally { setLoading(false) }
  }, [buildParams])

  useEffect(()=>{fetch(0);setPage(0)},[tags,since,until])

  const ET_CLS = { process:'et et-process',network:'et et-network',logon:'et et-logon',file:'et et-file',registry:'et et-registry',dns:'et et-dns',sysmon:'et et-sysmon',health:'et et-health' }
  const SEV_CLS = { 1:'bg-siem-bg text-siem-muted border-siem-border',2:'bg-blue-900/30 text-blue-400 border-blue-800',3:'bg-yellow-900/30 text-yellow-400 border-yellow-800',4:'bg-orange-900/30 text-orange-400 border-orange-800',5:'bg-red-900/30 text-red-400 border-red-800' }
  const HINTS=['process','network','dns','logon','file','registry','health','critical','high','medium']
  const PRESETS=[{label:'1h',ms:3600000},{label:'6h',ms:21600000},{label:'24h',ms:86400000},{label:'7d',ms:604800000}]

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {selected&&<EventPanel event={selected} onClose={()=>setSelected(null)}/>}
      <div className="p-4 space-y-3 border-b border-siem-border shrink-0">
        {/* Tag input */}
        <div className="min-h-[38px] flex flex-wrap gap-1.5 items-center bg-siem-bg border border-siem-border rounded-xl px-3 py-2 cursor-text focus-within:border-siem-accent transition-colors" onClick={()=>inputRef.current?.focus()}>
          <Search size={13} className="text-siem-muted shrink-0"/>
          {tags.map(tag=>(
            <span key={tag.id} className={`inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full border font-medium ${TAG_COLORS[tag.field]||TAG_COLORS.search}`}>
              {tag.label}<button onClick={e=>{e.stopPropagation();removeTag(tag.id)}} className="hover:opacity-70 ml-0.5">×</button>
            </span>
          ))}
          <input ref={inputRef} className="flex-1 min-w-[100px] bg-transparent text-sm text-siem-text outline-none placeholder:text-siem-muted/50" placeholder="Type to filter events…" value={inputVal} onChange={e=>setInputVal(e.target.value)} onKeyDown={handleKeyDown}/>
          {(tags.length>0||since||until)&&<button onClick={()=>{setTags([]);setSince('');setUntil('');setInputVal('')}} className="text-[10px] text-siem-muted hover:text-red-400 ml-1 shrink-0">Clear</button>}
        </div>
        {/* Hints + Saved Search */}
        <div className="flex items-center gap-2 flex-wrap">
          {HINTS.map(h=>(
            <button key={h} onClick={()=>addTag(h)} className="text-[10px] px-2 py-0.5 rounded-full border border-siem-border text-siem-muted hover:border-siem-accent hover:text-siem-accent transition-colors">{h}</button>
          ))}
          <span className="text-siem-border text-xs ml-2">|</span>
          {PRESETS.map(p=>(
            <button key={p.label} onClick={()=>{const now=new Date();setSince(new Date(now-p.ms).toISOString().slice(0,16));setUntil(now.toISOString().slice(0,16))}} className="text-[10px] px-2 py-0.5 rounded-full border border-siem-border text-siem-muted hover:border-siem-accent hover:text-siem-accent transition-colors">{p.label}</button>
          ))}
          <button onClick={()=>setShowSaved(s=>!s)} className={`ml-2 flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border transition-colors ${showSaved?'border-siem-accent text-siem-accent bg-siem-accent/10':'border-siem-border text-siem-muted hover:border-siem-accent hover:text-siem-accent'}`}>
            <Bookmark size={9}/> Saved
          </button>
          <span className="text-xs text-siem-muted ml-auto">{loading?'Searching…':`${total.toLocaleString()} events`}</span>
        </div>
        {/* Saved search panel */}
        {showSaved && (
          <AgentSavedSearchPanel
            onSelect={selectedTags => {
              // Strip the host tag — we always filter by this host already
              const filtered = selectedTags.filter(t => t.field !== 'host')
              setTags(filtered.map(t => ({ ...t, id: Date.now() + Math.random() })))
              setShowSaved(false)
            }}
            onClose={() => setShowSaved(false)}
          />
        )}
      </div>

      {/* Event rows — same format as main Events page */}
      <div className="flex-1 overflow-y-auto divide-y divide-siem-border/40">
        {loading ? (
          <div className="text-center py-12 text-siem-muted text-sm">Searching…</div>
        ) : events.length === 0 ? (
          <div className="text-center py-12 text-siem-muted text-sm">{tags.length > 0 || since || until ? 'No events match your filters' : 'No events found for this host'}</div>
        ) : events.map((ev, i) => {
          const raw = ev.raw ? (typeof ev.raw === 'string' ? (() => { try { return JSON.parse(ev.raw) } catch { return {} } })() : ev.raw) : {}
          const summaryParts = []
          if (ev.user_name)    summaryParts.push(ev.user_name)
          if (ev.process_name) summaryParts.push(ev.process_name)
          if (ev.command_line) summaryParts.push(ev.command_line.slice(0, 80))
          if (ev.src_ip)       summaryParts.push(`${ev.src_ip}${ev.src_port ? ':'+ev.src_port : ''}`)
          if (ev.dst_ip)       summaryParts.push(`→ ${ev.dst_ip}${ev.dst_port ? ':'+ev.dst_port : ''}`)
          if (ev.file_path)    summaryParts.push(ev.file_path)
          if (ev.reg_key)      summaryParts.push(ev.reg_key)
          if (!summaryParts.length) {
            const cloudSummary = raw?.event_name || raw?.operation_name || raw?.message || raw?.action
            if (cloudSummary) summaryParts.push(String(cloudSummary))
          }
          const summary = summaryParts.join('  ·  ')
          return (
            <div key={ev.id || i}
              className="flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.03] cursor-pointer transition-colors group"
              onClick={() => setSelected(ev)}>
              <span className="text-[11px] text-siem-muted/70 font-mono whitespace-nowrap w-[120px] shrink-0">
                {format(new Date(ev.time), 'MM/dd HH:mm:ss')}
              </span>
              <SeverityBadge severity={ev.severity}/>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium shrink-0 ${ET_CLS[ev.event_type] || 'bg-siem-bg text-siem-muted'}`}>
                {ev.event_type}
              </span>
              <span className="text-[11px] text-siem-muted/80 truncate flex-1 font-mono">
                {summary || ev.source || ev.event_type}
              </span>
              <ChevronRight size={13} className="text-siem-muted/30 group-hover:text-siem-muted shrink-0"/>
            </div>
          )
        })}
      </div>

      {/* Pagination */}
      {total>limit&&(
        <div className="flex items-center justify-between px-4 py-3 border-t border-siem-border shrink-0">
          <span className="text-xs text-siem-muted">Page {page+1} of {Math.ceil(total/limit)} · {total.toLocaleString()} total</span>
          <div className="flex gap-2">
            <button disabled={page===0} onClick={()=>{const p=page-1;setPage(p);fetch(p)}} className="text-xs px-3 py-1.5 border border-siem-border rounded-lg text-siem-muted hover:text-siem-text disabled:opacity-40">Previous</button>
            <button disabled={(page+1)*limit>=total} onClick={()=>{const p=page+1;setPage(p);fetch(p)}} className="text-xs px-3 py-1.5 border border-siem-border rounded-lg text-siem-muted hover:text-siem-text disabled:opacity-40">Next</button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Tab: Threats (Process Graph) ─────────────────────────────────────────────

function TabThreats({ agent }) {
  const navigate = useNavigate()
  const [hours, setHours] = useState(24)
  const [loading, setLoading] = useState(false)
  const [loadingProcs, setLoadingProcs] = useState(false)
  const [processes, setProcesses] = useState([])
  const [selectedProcess, setSelectedProcess] = useState(null)
  const [graphData, setGraphData] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [showSuspicious, setShowSuspicious] = useState(true)
  const [threatIntel, setThreatIntel] = useState(null)
  const zoomFitRef = useRef(null)

  // Load process list when hours changes
  useEffect(() => {
    setLoadingProcs(true)
    setProcesses([])
    setSelectedProcess(null)
    setGraphData(null)
    api.get(`/api/v1/graph/endpoint/${encodeURIComponent(agent.hostname)}/processes?hours=${hours}`)
      .then(r => setProcesses(r.data.processes || []))
      .catch(() => {})
      .finally(() => setLoadingProcs(false))
  }, [agent.hostname, hours])

  // Load graph when process selected
  useEffect(() => {
    if (!selectedProcess) return
    setLoading(true)
    setSelectedNode(null)
    const proc = encodeURIComponent(selectedProcess.name)
    api.get(`/api/v1/graph/endpoint/${encodeURIComponent(agent.hostname)}?hours=${hours}&process=${proc}`)
      .then(r => {
        const nodes = r.data.nodes || []
        const edges = r.data.edges || []

        // Collapse all file nodes into a single summary node
        const fileNodes = nodes.filter(n => n.type === 'file')
        const nonFileNodes = nodes.filter(n => n.type !== 'file')
        let finalNodes = nonFileNodes
        let finalEdges = edges

        if (fileNodes.length > 1) {
          // Create a single collapsed file node
          const collapsedFile = {
            id: '_files_collapsed',
            type: 'file',
            label: `${fileNodes.length} files`,
            event_count: fileNodes.reduce((s, n) => s + (n.event_count || 0), 0),
            suspicious: fileNodes.some(n => n.suspicious),
            meta: { file_list: fileNodes.map(n => n.label), collapsed: true },
          }
          finalNodes = [...nonFileNodes, collapsedFile]
          // Remap all file edges to point to collapsed node
          const fileIds = new Set(fileNodes.map(n => n.id))
          finalEdges = edges
            .filter(e => !(fileIds.has(e.source) || fileIds.has(e.target)) ||
                        fileIds.has(e.target))
            .map(e => fileIds.has(e.target) ? { ...e, target: '_files_collapsed' } : e)
            // Deduplicate edges to collapsed node
            .filter((e, i, arr) =>
              e.target !== '_files_collapsed' ||
              arr.findIndex(x => x.source === e.source && x.target === '_files_collapsed') === i
            )
        }

        setGraphData({ ...r.data, nodes: finalNodes, edges: finalEdges })

        // Build threat intel from graph nodes
        const ips = nodes.filter(n => n.type === 'ip' || n.type === 'external_ip').map(n => n.label)
        const domains = nodes.filter(n => n.type === 'dns').map(n => n.label)
        const suspicious = nodes.filter(n => n.suspicious).length
        setThreatIntel({ ips, domains, suspicious, fileCount: fileNodes.length })
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [agent.hostname, selectedProcess, hours])

  const getSevColor = (sev) => {
    if (sev >= 5) return 'text-red-400'
    if (sev >= 4) return 'text-orange-400'
    return 'text-siem-muted'
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-siem-border bg-siem-surface shrink-0">
        <GitBranch size={13} className="text-siem-accent"/>
        <span className="text-xs font-semibold text-siem-text">Process Graph</span>
        <div className="flex items-center gap-1 ml-2">
          {[6,24,48,168].map(h => (
            <button key={h} onClick={() => setHours(h)}
              className={`text-[9px] px-1.5 py-0.5 rounded ${hours===h?'bg-siem-accent text-white':'text-siem-muted hover:text-siem-text'}`}>
              {h<24?`${h}h`:h===168?'7d':`${h/24}d`}
            </button>
          ))}
        </div>
        {selectedProcess && (
          <div className="flex items-center gap-1.5 ml-2 bg-siem-accent/10 border border-siem-accent/30 rounded-lg px-2 py-0.5">
            <Cpu size={9} className="text-siem-accent"/>
            <span className="text-[10px] text-siem-accent font-mono">{selectedProcess.name}</span>
            <button onClick={() => { setSelectedProcess(null); setGraphData(null) }}
              className="text-siem-muted hover:text-red-400 ml-1"><X size={9}/></button>
          </div>
        )}
        <div className="ml-auto flex items-center gap-2">
          <button onClick={() => setShowSuspicious(s => !s)}
            className={`flex items-center gap-1 text-[9px] border rounded-lg px-2 py-1 ${showSuspicious?'bg-red-900/30 border-red-800 text-red-400':'text-siem-muted border-siem-border'}`}>
            <AlertTriangle size={9}/>{showSuspicious?'Suspicious On':'Off'}
          </button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden min-h-0">
        {/* Left: Process list */}
        <div className="w-52 shrink-0 border-r border-siem-border bg-siem-surface flex flex-col overflow-hidden">
          <div className="px-3 py-2 border-b border-siem-border">
            <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Applications</span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {loadingProcs ? (
              <div className="flex items-center justify-center h-16 text-siem-muted text-[10px]">
                <RefreshCw size={10} className="animate-spin mr-1"/>Loading…
              </div>
            ) : processes.length === 0 ? (
              <div className="flex items-center justify-center h-16 text-siem-muted/40 text-[10px]">No processes found</div>
            ) : processes.map(proc => (
              <button key={proc.name}
                onClick={() => setSelectedProcess(proc)}
                className={`w-full flex items-center gap-2 px-3 py-2 text-left transition-colors border-b border-siem-border/20 ${
                  selectedProcess?.name === proc.name
                    ? 'bg-siem-accent/10 border-r-2 border-r-siem-accent'
                    : 'hover:bg-white/[0.03]'
                }`}>
                {proc.suspicious
                  ? <AlertTriangle size={9} className="text-red-400 shrink-0"/>
                  : <Cpu size={9} className="text-siem-muted/40 shrink-0"/>}
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
            ))}
          </div>
        </div>

        {/* Center: Graph */}
        <div className="flex-1 relative overflow-hidden">
          {!selectedProcess && !loadingProcs && (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-siem-muted">
              <Cpu size={40} className="opacity-10 mb-3"/>
              <div className="text-sm text-siem-text/30">Select an application</div>
              <div className="text-xs opacity-40 mt-1">Click a process to explore its activity graph</div>
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
          {!loading && graphData && graphData.nodes?.length === 0 && (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-siem-muted">
              <GitBranch size={32} className="opacity-10 mb-2"/>
              <div className="text-sm text-siem-text/30">No graph data for {selectedProcess?.name}</div>
              <div className="text-xs opacity-40 mt-1">Try a longer time range</div>
            </div>
          )}
          {!loading && graphData && graphData.nodes?.length > 0 && (
            <>
              <GraphCanvas
                graph={graphData}
                onNodeClick={setSelectedNode}
                selectedNode={selectedNode}
                showSuspicious={showSuspicious}
                zoomFitRef={zoomFitRef}
              />
              <div className="absolute top-3 right-3">
                <button onClick={() => zoomFitRef.current?.()}
                  className="w-7 h-7 bg-siem-surface/80 backdrop-blur border border-siem-border rounded-lg flex items-center justify-center text-siem-muted hover:text-siem-text">
                  <Maximize2 size={11}/>
                </button>
              </div>
            </>
          )}
        </div>

        {/* Right: Node detail timeline */}
        {selectedNode && (
          <NodeDetail node={selectedNode} onClose={() => setSelectedNode(null)} host={agent.hostname}/>
        )}
      </div>

      {/* Bottom: Threat Intel strip */}
      <div className="shrink-0 border-t border-siem-border bg-siem-surface px-4 py-2.5 flex items-center gap-6 overflow-x-auto">
        <div className="flex items-center gap-1.5 shrink-0">
          <Shield size={11} className="text-siem-accent"/>
          <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Threat Intel</span>
        </div>

        {/* Top processes by event count */}
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-[9px] text-siem-muted uppercase tracking-wider">Top Processes</span>
          {processes.slice(0, 3).map(p => (
            <button key={p.name} onClick={() => setSelectedProcess(p)}
              className={`text-[10px] font-mono px-1.5 py-0.5 rounded border transition-colors ${
                p.suspicious
                  ? 'border-red-800/50 text-red-400 bg-red-950/20'
                  : 'border-siem-border text-siem-muted hover:text-siem-accent hover:border-siem-accent/40'
              }`}>
              {p.name.split('.')[0]}
              <span className="text-[8px] ml-1 opacity-60">{p.event_count}</span>
            </button>
          ))}
        </div>

        <div className="w-px h-4 bg-siem-border/50 shrink-0"/>

        {/* DNS domains from selected process */}
        {selectedProcess && threatIntel && (
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-[9px] text-siem-muted uppercase tracking-wider">DNS</span>
            {threatIntel.domains.length === 0
              ? <span className="text-[10px] text-siem-muted/40">none</span>
              : threatIntel.domains.slice(0, 4).map(d => (
                <span key={d} className="text-[10px] font-mono text-cyan-400/70">{d}</span>
              ))
            }
            {threatIntel.domains.length > 4 && (
              <span className="text-[9px] text-siem-muted">+{threatIntel.domains.length - 4}</span>
            )}
          </div>
        )}

        {selectedProcess && threatIntel && (
          <div className="w-px h-4 bg-siem-border/50 shrink-0"/>
        )}

        {/* IPs */}
        {selectedProcess && threatIntel && (
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-[9px] text-siem-muted uppercase tracking-wider">IPs</span>
            {threatIntel.ips.length === 0
              ? <span className="text-[10px] text-siem-muted/40">none</span>
              : threatIntel.ips.slice(0, 4).map(ip => (
                <span key={ip} className="text-[10px] font-mono text-blue-400/70">{ip}</span>
              ))
            }
          </div>
        )}

        {/* Suspicious indicator */}
        {selectedProcess && threatIntel && (
          <div className="ml-auto shrink-0">
            {(threatIntel.suspicious || 0) > 0 ? (
              <span className="flex items-center gap-1 text-red-400 text-[10px]">
                <AlertTriangle size={10}/>
                {threatIntel.suspicious} suspicious node{threatIntel.suspicious > 1 ? 's' : ''}
              </span>
            ) : (
              <span className="flex items-center gap-1 text-emerald-400/60 text-[10px]">
                <Shield size={10}/>No threats detected
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
// ── Saved Search Panel (agent-scoped) ────────────────────────────────────────

const GROUP_ICONS_MAP = { Windows: Monitor, Linux: Server, macOS: Apple }

function AgentSavedSearchPanel({ onSelect, onClose }) {
  const [activeGroup, setActiveGroup] = useState(SAVED_SEARCHES[0]?.group || '')
  const group = SAVED_SEARCHES.find(g => g.group === activeGroup)
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-siem-border">
        <span className="text-xs font-semibold text-siem-text">Saved Searches</span>
        <button onClick={onClose} className="text-siem-muted hover:text-siem-text"><X size={12}/></button>
      </div>
      <div className="flex">
        <div className="w-28 border-r border-siem-border shrink-0">
          {SAVED_SEARCHES.map(({ group: g }) => {
            const Icon = GROUP_ICONS_MAP[g] || GlobeIcon
            return (
              <button key={g} onClick={() => setActiveGroup(g)}
                className={`w-full flex items-center gap-1.5 px-3 py-2 text-[10px] transition-colors text-left ${activeGroup===g?'bg-siem-accent/10 text-siem-accent border-r-2 border-siem-accent':'text-siem-muted hover:text-siem-text'}`}>
                <Icon size={10}/>{g}
              </button>
            )
          })}
        </div>
        <div className="flex-1 p-2 space-y-1 max-h-64 overflow-y-auto">
          {group?.searches.map((s, i) => (
            <button key={i} onClick={() => onSelect(s.tags)}
              className="w-full text-left px-3 py-2 rounded-lg border border-transparent hover:border-siem-border hover:bg-white/[0.02] transition-colors group">
              <div className="text-[11px] font-medium text-siem-text group-hover:text-siem-accent">{s.label}</div>
              <div className="text-[9px] text-siem-muted mt-0.5">{s.desc}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Shared mini table ─────────────────────────────────────────────────────────

function MiniTable({ cols, rows, empty='No data', onRowClick }) {
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-siem-border text-siem-muted">
            {cols.map(c => <th key={c.key} className="text-left px-4 py-2.5 font-medium whitespace-nowrap">{c.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0
            ? <tr><td colSpan={cols.length} className="text-center py-10 text-siem-muted">{empty}</td></tr>
            : rows.map((row, i) => (
              <tr key={i}
                className={`border-b border-siem-border/40 ${onRowClick?'cursor-pointer hover:bg-white/[0.03]':''} transition-colors`}
                onClick={() => onRowClick?.(row)}>
                {cols.map(c => (
                  <td key={c.key} className={`px-4 py-2.5 ${c.cls||'text-siem-text font-mono text-[10px]'} ${c.truncate?'truncate max-w-[180px]':''}`}>
                    {c.render ? c.render(row) : (row[c.key] ?? '—')}
                  </td>
                ))}
              </tr>
            ))
          }
        </tbody>
      </table>
    </div>
  )
}

// ── Tab: Logons ───────────────────────────────────────────────────────────────

function TabLogons({ agent }) {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')

  useEffect(() => {
    setLoading(true)
    api.get('/api/v1/events', { params: { host: agent.hostname, event_type: 'logon', limit: 500 } })
      .then(r => setEvents(r.data.events || []))
      .catch(() => setEvents([]))
      .finally(() => setLoading(false))
  }, [agent.hostname])

  const parseRaw = ev => {
    if (!ev?.raw) return {}
    if (typeof ev.raw === 'string') { try { return JSON.parse(ev.raw) } catch { return {} } }
    return ev.raw || {}
  }

  // Determine the action label to display — differs by platform
  const getAction = ev => {
    const raw  = parseRaw(ev)
    const eid  = ev.event_id || raw.event_id

    // Windows — use EventID to determine action
    if (eid) {
      const id = parseInt(eid)
      if (id === 4624) return { label: 'Logon success',        fail: false }
      if (id === 4625) return { label: 'Logon failure',         fail: true  }
      if (id === 4634) return { label: 'Logoff',                fail: false }
      if (id === 4647) return { label: 'User initiated logoff', fail: false }
      if (id === 4648) return { label: 'Explicit credentials',  fail: false }
      if (id === 4672) return { label: 'Special privileges',    fail: false }
      if (id === 4776) return { label: 'Credential validation', fail: false }
      if (id === 4768) return { label: 'Kerberos TGT request',  fail: false }
      if (id === 4769) return { label: 'Kerberos service ticket',fail: false }
      if (id === 4771) return { label: 'Kerberos pre-auth fail', fail: true  }
      return { label: `EventID ${id}`, fail: false }
    }

    // Linux — raw.action is the classified action string
    const action = raw.action || ''
    const FAIL_ACTIONS = new Set([
      'ssh_login_failure','ssh_invalid_user','ssh_brute_force',
      'sudo_failure','pam_auth_failure','su_attempt',
    ])
    const LABELS = {
      ssh_login_success:  'SSH login success',
      ssh_login_failure:  'SSH login failure',
      ssh_invalid_user:   'SSH invalid user',
      ssh_brute_force:    'SSH brute force',
      ssh_logout:         'SSH logout',
      ssh_event:          'SSH event',
      sudo_exec:          'Sudo exec',
      sudo_failure:       'Sudo failure',
      su_success:         'su success',
      su_attempt:         'su attempt',
      pam_session_open:   'Session opened',
      pam_session_close:  'Session closed',
      pam_auth_failure:   'Auth failure',
    }
    return {
      label: LABELS[action] || action || ev.source || '—',
      fail:  FAIL_ACTIONS.has(action),
    }
  }

  // True failure = known failure action OR Windows severity >= 3 (4625 is Medium)
  const isFail = ev => {
    const { fail } = getAction(ev)
    return fail || (ev.event_id === 4625) || (parseRaw(ev).event_id === 4625)
  }

  const filtered = events.filter(ev => {
    if (filter === 'success') return !isFail(ev)
    if (filter === 'failure') return isFail(ev)
    return true
  })

  const failures     = events.filter(isFail).length
  const unique_users = [...new Set(events.map(e => e.user_name).filter(Boolean))]
  const isWindows    = agent.os?.toLowerCase().includes('win')

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Summary bar */}
      <div className="px-5 py-3 border-b border-siem-border shrink-0 flex items-center gap-6">
        <div>
          <div className="text-[10px] text-siem-muted">Total logon events</div>
          <div className="text-lg font-bold text-siem-text">{events.length}</div>
        </div>
        <div>
          <div className="text-[10px] text-siem-muted">Failed logons</div>
          <div className={`text-lg font-bold ${failures > 0 ? 'text-red-400' : 'text-siem-green'}`}>{failures}</div>
        </div>
        <div>
          <div className="text-[10px] text-siem-muted">Unique users</div>
          <div className="text-lg font-bold text-siem-text">{unique_users.length}</div>
        </div>
        <div className="ml-auto flex gap-1">
          {[['all','All'],['success','Success'],['failure','Failures']].map(([v,l]) => (
            <button key={v} onClick={() => setFilter(v)}
              className={`text-[10px] px-3 py-1 rounded-full border transition-colors ${filter===v?'border-siem-accent text-siem-accent bg-siem-accent/10':'border-siem-border text-siem-muted hover:text-siem-text'}`}>
              {l}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        {loading ? <div className="text-center py-12 text-siem-muted">Loading…</div> : (
          <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-siem-border text-siem-muted">
                  <th className="text-left px-4 py-2.5 whitespace-nowrap">Time</th>
                  <th className="text-left px-4 py-2.5"></th>
                  <th className="text-left px-4 py-2.5">User</th>
                  <th className="text-left px-4 py-2.5">Src IP</th>
                  <th className="text-left px-4 py-2.5">Action</th>
                  {isWindows && <th className="text-left px-4 py-2.5">Event ID</th>}
                  <th className="text-left px-4 py-2.5">{isWindows ? 'Logon Type' : 'Process'}</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0
                  ? <tr><td colSpan={isWindows ? 7 : 6} className="text-center py-10 text-siem-muted">No logon events match filter</td></tr>
                  : filtered.map((ev, i) => {
                    const { label, fail } = getAction(ev)
                    const raw = parseRaw(ev)
                    const eid = ev.event_id || raw.event_id
                    const logonType = raw.event_data?.LogonType
                    const logonTypeLabel = logonType ? {
                      '2':'Interactive','3':'Network','4':'Batch','5':'Service',
                      '7':'Unlock','8':'NetworkCleartext','10':'RemoteInteractive','11':'CachedInteractive'
                    }[logonType] || `Type ${logonType}` : null

                    return (
                      <tr key={ev.id||i} className={`border-b border-siem-border/40 hover:bg-white/[0.02] transition-colors ${fail ? 'bg-red-900/5' : ''}`}>
                        <td className="px-4 py-2.5 font-mono text-[10px] text-siem-muted whitespace-nowrap">
                          {format(new Date(ev.time), 'MM/dd HH:mm:ss')}
                        </td>
                        <td className="px-4 py-2.5"><SeverityBadge severity={ev.severity}/></td>
                        <td className="px-4 py-2.5 text-siem-text max-w-[160px] truncate">{ev.user_name || '—'}</td>
                        <td className="px-4 py-2.5 font-mono text-[10px] text-siem-muted">{ev.src_ip || '—'}</td>
                        <td className="px-4 py-2.5">
                          <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                            fail
                              ? 'bg-red-900/30 text-red-400 border border-red-800/40'
                              : label.includes('success') || label.includes('opened') || label.includes('exec')
                                ? 'bg-emerald-900/20 text-emerald-400 border border-emerald-800/30'
                                : 'bg-siem-bg text-siem-muted border border-siem-border'
                          }`}>{label}</span>
                        </td>
                        {isWindows && (
                          <td className="px-4 py-2.5 font-mono text-[10px] text-siem-muted">{eid || '—'}</td>
                        )}
                        <td className="px-4 py-2.5 text-[10px] text-siem-muted">
                          {isWindows
                            ? (logonTypeLabel || '—')
                            : (ev.process_name || raw.syslog_identifier || '—')
                          }
                        </td>
                      </tr>
                    )
                  })
                }
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Tab: Network ──────────────────────────────────────────────────────────────

function TabNetwork({ agent }) {
  const [data, setData]         = useState({})
  const [loading, setLoading]   = useState(true)
  const [search, setSearch]     = useState('')
  const [hours, setHours]       = useState(24)
  const [ispData, setIspData]   = useState({})

  useEffect(() => {
    setLoading(true)
    api.get(`/api/v1/threat-intel/${agent.hostname}`, { params: { hours } })
      .then(r => {
        setData(r.data || {})
        // Enrich external IPs with ISP data
        const conns = r.data?.top_connections || []
        const extIPs = conns
          .map(c => c.dst_ip).filter(ip => ip && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip))
          .slice(0, 20)
        if (extIPs.length > 0) {
          api.post('/api/v1/enrichment/isp', { ips: extIPs })
            .then(r => setIspData(r.data?.enriched || {}))
            .catch(() => {})
        }
      })
      .catch(() => setData({}))
      .finally(() => setLoading(false))
  }, [agent.hostname, hours])

  const connections  = data.top_connections  || []
  const flaggedIPs   = data.flagged_ips      || []

  const filtered = connections.filter(r =>
    !search ||
    String(r.dst_ip||'').includes(search) ||
    String(r.dst_port||'').includes(search) ||
    String(r.proto||'').includes(search)
  )

  const maxCount    = Math.max(...filtered.map(r => Number(r.count)||0), 1)
  const flaggedSet  = new Set(flaggedIPs.map(f => f.dst_ip))

  const isPrivate = ip => /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fd)/.test(ip||'')

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Toolbar */}
      <div className="px-5 py-3 border-b border-siem-border shrink-0 flex items-center gap-3 flex-wrap">
        {flaggedIPs.length > 0 && (
          <span className="text-[10px] px-2 py-1 bg-red-900/20 border border-red-800/40 text-red-400 rounded-lg shrink-0">
            ⚠ {flaggedIPs.length} malicious IP{flaggedIPs.length > 1 ? 's' : ''}
          </span>
        )}
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Filter by IP, port, protocol…"
          className="flex-1 min-w-[140px] bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text placeholder-siem-muted/50 outline-none focus:border-siem-accent"/>
        <div className="flex gap-1 shrink-0">
          {[['1h',1],['24h',24],['7d',168]].map(([l,h]) => (
            <button key={h} onClick={() => setHours(h)}
              className={`text-[10px] px-3 py-1 rounded-full border transition-colors ${hours===h?'border-siem-accent text-siem-accent bg-siem-accent/10':'border-siem-border text-siem-muted hover:text-siem-text'}`}>
              {l}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {loading ? <div className="text-center py-12 text-siem-muted">Loading…</div> : (<>

          {/* Flagged / malicious IPs — always shown first if any */}
          {flaggedIPs.length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-red-400 font-semibold mb-2">
                Malicious IP Connections (IOC matches)
              </div>
              <div className="bg-red-900/10 border border-red-800/30 rounded-xl overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-red-800/20 text-red-400/70">
                      <th className="text-left px-4 py-2">IP</th>
                      <th className="text-left px-4 py-2">Port</th>
                      <th className="text-left px-4 py-2">Malware</th>
                      <th className="text-left px-4 py-2">Threat</th>
                      <th className="text-left px-4 py-2">Hits</th>
                      <th className="text-left px-4 py-2">Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {flaggedIPs.map((f, i) => (
                      <tr key={i} className="border-b border-red-800/10 hover:bg-red-900/10">
                        <td className="px-4 py-2 font-mono text-[10px] text-red-300">{f.dst_ip}</td>
                        <td className="px-4 py-2 font-mono text-[10px] text-red-400/70">{f.dst_port||'—'}</td>
                        <td className="px-4 py-2 text-[10px] text-red-300">{f.malware||'—'}</td>
                        <td className="px-4 py-2 text-[10px] text-red-400/80">{f.threat_type||'—'}</td>
                        <td className="px-4 py-2 text-[10px] font-bold text-red-400">{Number(f.connection_count||0).toLocaleString()}</td>
                        <td className="px-4 py-2 text-[10px] text-siem-muted">{f.ioc_source||'—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* All connections */}
          <div>
            {flaggedIPs.length > 0 && (
              <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">
                All Connections
              </div>
            )}
            {filtered.length === 0 ? (
              <div className="text-center py-10 text-siem-muted bg-siem-surface border border-siem-border rounded-xl">
                No network connections in this window
              </div>
            ) : (
              <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-siem-border text-siem-muted">
                      <th className="text-left px-4 py-2.5">Destination IP</th>
                      <th className="text-left px-4 py-2.5">ISP / Organization</th>
                      <th className="text-left px-4 py-2.5">Port</th>
                      <th className="text-left px-4 py-2.5">Proto</th>
                      <th className="text-left px-4 py-2.5">Connections</th>
                      <th className="px-4 py-2.5 w-28"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((r, i) => {
                      const pct        = Number(r.count) / maxCount * 100
                      const priv       = isPrivate(r.dst_ip)
                      const isMalicious = flaggedSet.has(r.dst_ip)
                      return (
                        <tr key={i} className={`border-b border-siem-border/40 hover:bg-white/[0.02] transition-colors ${isMalicious ? 'bg-red-900/5' : ''}`}>
                          <td className="px-4 py-2.5 font-mono text-[10px]">
                            {isMalicious && <span className="inline-block w-1.5 h-1.5 rounded-full bg-red-400 mr-1.5 mb-0.5"/>}
                            <span className={isMalicious ? 'text-red-300' : priv ? 'text-siem-muted' : 'text-siem-text'}>{r.dst_ip||'—'}</span>
                            {!priv && !isMalicious && <span className="ml-2 text-[9px] text-orange-400/60">ext</span>}
                          </td>
                          <td className="px-4 py-2.5 text-[10px]">
                            {ispData[r.dst_ip] ? (
                              <div>
                                <div className="text-siem-text font-medium">{ispData[r.dst_ip].isp || ispData[r.dst_ip].org || '—'}</div>
                                <div className="text-siem-muted/60 text-[9px] font-mono">{ispData[r.dst_ip].country} {ispData[r.dst_ip].asn?.split(' ')[0]}</div>
                              </div>
                            ) : priv ? <span className="text-siem-muted/40">private</span>
                              : <span className="text-siem-muted/30 text-[9px]">looking up…</span>}
                          </td>
                          <td className="px-4 py-2.5 font-mono text-[10px] text-siem-text">{r.dst_port||'—'}</td>
                          <td className="px-4 py-2.5 text-[10px] text-siem-muted">{r.proto||'—'}</td>
                          <td className="px-4 py-2.5 font-bold text-siem-text">{Number(r.count).toLocaleString()}</td>
                          <td className="px-4 py-2.5">
                            <div className="h-1.5 bg-siem-border/20 rounded-full overflow-hidden w-24">
                              <div className="h-full rounded-full" style={{width:pct+'%', background: isMalicious?'#ef4444':'rgba(var(--color-accent),0.6)'}}/>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
                <div className="px-4 py-2 border-t border-siem-border/30 text-[9px] text-siem-muted/50">
                  Process attribution not available in aggregated view — use Events tab with <span className="font-mono">network</span> filter to see per-connection process names
                </div>
              </div>
            )}
          </div>
        </>)}
      </div>
    </div>
  )
}

// ── Tab: DNS ─────────────────────────────────────────────────────────────────

function TabDNS({ agent }) {
  const [domains, setDomains]   = useState([])
  const [flagged, setFlagged]   = useState([])
  const [loading, setLoading]   = useState(true)
  const [search, setSearch]     = useState('')
  const [hours, setHours]       = useState(24)

  const [newDomains, setNewDomains] = useState([])

  useEffect(() => {
    setLoading(true)
    api.get(`/api/v1/threat-intel/${agent.hostname}`, { params: { hours } })
      .then(r => {
        setDomains(r.data.top_domains || [])
        setNewDomains(r.data.new_domains || [])
        // Merge dns_category_flags (Quad9/SURBL/Spamhaus) + flagged_domains (OTX/ThreatFox IOCs)
        const catFlags = (r.data.dns_category_flags || []).map(f => ({ ...f, flag_type: 'category' }))
        const iocFlags = (r.data.flagged_domains || []).map(f => ({
          domain: f.domain, query_count: f.query_count,
          categories: f.malware || f.threat_type || 'IOC Match',
          ioc_severity: f.ioc_severity, ioc_source: f.ioc_source, flag_type: 'ioc'
        }))
        // Deduplicate by domain, prefer IOC entries
        const seen = new Set()
        const merged = [...iocFlags, ...catFlags].filter(f => {
          if (seen.has(f.domain)) return false
          seen.add(f.domain); return true
        })
        setFlagged(merged)
      })
      .catch(() => { setDomains([]); setFlagged([]) })
      .finally(() => setLoading(false))
  }, [agent.hostname, hours])

  const flaggedSet = new Set(flagged.map(f => f.domain))
  const filtered   = domains.filter(d => !search || String(d.domain||'').toLowerCase().includes(search.toLowerCase()))
  const maxCount   = Math.max(...filtered.map(r => Number(r.count)||0), 1)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="px-5 py-3 border-b border-siem-border shrink-0 flex items-center gap-3">
        {flagged.length > 0 && (
          <span className="text-[10px] px-2 py-1 bg-red-900/20 border border-red-800/40 text-red-400 rounded-lg">
            ⚠ {flagged.length} flagged domain{flagged.length>1?'s':''}
          </span>
        )}
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search domains…"
          className="flex-1 bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text placeholder-siem-muted/50 outline-none focus:border-siem-accent"/>
        <div className="flex gap-1">
          {[['1h',1],['24h',24],['7d',168]].map(([l,h]) => (
            <button key={h} onClick={() => setHours(h)}
              className={`text-[10px] px-3 py-1 rounded-full border transition-colors ${hours===h?'border-siem-accent text-siem-accent bg-siem-accent/10':'border-siem-border text-siem-muted hover:text-siem-text'}`}>
              {l}
            </button>
          ))}
        </div>
      </div>

      {/* Flagged domains alert section */}
      {!loading && flagged.length > 0 && (
        <div className="px-4 pt-4 shrink-0 space-y-2">
          <div className="text-[10px] uppercase tracking-wider text-red-400 font-semibold px-1">Flagged / Malicious Domains</div>
          {flagged.map((f,i) => (
            <div key={i} className="bg-red-900/10 border border-red-800/30 rounded-xl px-4 py-2.5 flex items-center gap-3">
              <div className="flex-1 font-mono text-[11px] text-red-300">{f.domain}</div>
              <div className="text-[10px] text-red-400/70">{f.categories}</div>
              <div className="text-[10px] text-siem-muted">{Number(f.query_count).toLocaleString()} queries</div>
            </div>
          ))}
        </div>
      )}

      <div className="flex-1 overflow-y-auto p-4 pt-3 space-y-4">
        {loading ? <div className="text-center py-12 text-siem-muted">Loading…</div> : (<>
          {/* New domains — first seen in this window */}
          {newDomains.length > 0 && (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-yellow-400 font-semibold mb-2 px-1 flex items-center gap-2">
                <span>⚡</span> New Domains — First seen in selected window ({newDomains.length})
              </div>
              <div className="bg-yellow-900/10 border border-yellow-800/30 rounded-xl overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-yellow-800/20">
                      <th className="text-left px-4 py-2 text-yellow-400/70">Domain</th>
                      <th className="text-left px-4 py-2 text-yellow-400/70">First Seen</th>
                      <th className="text-left px-4 py-2 text-yellow-400/70">Queries</th>
                    </tr>
                  </thead>
                  <tbody>
                    {newDomains.map((d,i) => (
                      <tr key={i} className="border-b border-yellow-800/10">
                        <td className="px-4 py-2 font-mono text-[10px] text-yellow-200">{d.domain}</td>
                        <td className="px-4 py-2 text-[10px] text-yellow-400/70 font-mono">
                          {d.first_seen ? new Date(d.first_seen).toLocaleString() : '—'}
                        </td>
                        <td className="px-4 py-2 text-[10px] text-yellow-400 font-mono font-bold">{Number(d.count).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-siem-border text-siem-muted">
                  <th className="text-left px-4 py-2.5">Domain / Destination</th>
                  <th className="text-left px-4 py-2.5">Queries</th>
                  <th className="text-left px-4 py-2.5">First Seen</th>
                  <th className="text-left px-4 py-2.5">Days Seen</th>
                  <th className="px-4 py-2.5 w-28"></th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0
                  ? <tr><td colSpan={3} className="text-center py-10 text-siem-muted">No DNS events in this window</td></tr>
                  : filtered.map((r,i) => {
                    const isFlagged = flaggedSet.has(r.domain)
                    const pct = Number(r.count) / maxCount * 100
                    return (
                      <tr key={i} className={`border-b border-siem-border/40 ${isFlagged?'bg-red-900/5':''} hover:bg-white/[0.02] transition-colors`}>
                        <td className="px-4 py-2.5 font-mono text-[10px]">
                          {isFlagged && <span className="inline-block w-1.5 h-1.5 rounded-full bg-red-400 mr-2 mb-0.5"/>}
                          <span className={isFlagged?'text-red-300':'text-siem-text'}>{r.domain||'—'}</span>
                          {r.persistent && <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded bg-orange-900/30 text-orange-400 border border-orange-800/30">persistent</span>}
                        </td>
                        <td className="px-4 py-2.5 font-bold text-siem-text font-mono text-[10px]">{Number(r.count).toLocaleString()}</td>
                        <td className="px-4 py-2.5 text-[10px] text-siem-muted font-mono">
                          {r.first_seen ? new Date(r.first_seen).toLocaleDateString() : '—'}
                        </td>
                        <td className="px-4 py-2.5 text-[10px]">
                          {r.days_seen != null ? (
                            <span className={Number(r.days_seen) > 7 ? 'text-orange-400' : 'text-siem-muted'}>
                              {r.days_seen}d
                            </span>
                          ) : '—'}
                        </td>
                        <td className="px-4 py-2.5">
                          <div className="h-1.5 bg-siem-border/20 rounded-full overflow-hidden w-24">
                            <div className="h-full rounded-full" style={{width:pct+'%',background:isFlagged?'#ef4444':'#22c55e'}}/>
                          </div>
                        </td>
                      </tr>
                    )
                  })
                }
              </tbody>
            </table>
          </div>
        )}
        </>)}
      </div>
    </div>
  )
}

// ── Tab: Files ────────────────────────────────────────────────────────────────

// ── VT Hash Badge ─────────────────────────────────────────────────────────────

function VTHashBadge({ hash }) {
  const [vtData, setVtData] = useState(null)
  const shortHash = hash.split(':').pop().slice(0, 10)

  useEffect(() => {
    const normalized = hash.split(':').pop().toLowerCase()
    if (normalized.length < 8) return
    api.get(`/api/v1/file-hashes/${normalized}`)
      .then(r => setVtData(r.data))
      .catch(() => {}) // not in cache yet
  }, [hash])

  const getVerdictStyle = (verdict) => {
    switch (verdict) {
      case 'malicious':   return 'bg-red-900/40 text-red-400 border-red-800'
      case 'suspicious':  return 'bg-orange-900/30 text-orange-400 border-orange-800'
      case 'clean':       return 'bg-emerald-900/20 text-emerald-400 border-emerald-800/30'
      case 'undetected':  return 'bg-siem-bg text-siem-muted border-siem-border'
      case 'queued':      return 'bg-siem-bg text-siem-muted/50 border-siem-border/50'
      default:            return 'bg-siem-bg text-siem-muted/40 border-siem-border/30'
    }
  }

  if (!vtData) {
    return <span className="font-mono text-siem-muted/50" title={hash}>{shortHash}…</span>
  }

  return (
    <div className="flex items-center gap-1.5">
      <span className="font-mono text-siem-muted/50" title={hash}>{shortHash}…</span>
      {vtData.vt_verdict && vtData.vt_verdict !== 'queued' && (
        <span className={`text-[9px] px-1.5 py-px rounded-full border font-medium ${getVerdictStyle(vtData.vt_verdict)}`}
          title={vtData.vt_family || vtData.vt_verdict}>
          {vtData.vt_verdict === 'malicious' ? `⚠ ${vtData.vt_score}/${vtData.vt_total}` :
           vtData.vt_verdict === 'suspicious' ? `? ${vtData.vt_score}/${vtData.vt_total}` :
           vtData.vt_verdict === 'clean' ? '✓' : vtData.vt_verdict}
        </span>
      )}
      {vtData.vt_verdict === 'queued' && (
        <span className="text-[9px] text-siem-muted/30">pending</span>
      )}
    </div>
  )
}

function TabFiles({ agent }) {
  const [events, setEvents]       = useState([])
  const [flaggedHashes, setFlaggedHashes] = useState([])
  const [loading, setLoading]     = useState(true)
  const [search, setSearch]       = useState('')
  const [filter, setFilter]       = useState('all')

  useEffect(() => {
    setLoading(true)
    Promise.all([
      api.get('/api/v1/events', { params: { host: agent.hostname, event_type: 'file', limit: 500 } }),
      api.get(`/api/v1/threat-intel/${agent.hostname}`, { params: { hours: 24 } }),
    ])
      .then(([evRes, tiRes]) => {
        setEvents(evRes.data.events || [])
        setFlaggedHashes(tiRes.data.flagged_hashes || [])
      })
      .catch(() => { setEvents([]); setFlaggedHashes([]) })
      .finally(() => setLoading(false))
  }, [agent.hostname])

  const parseRaw = ev => {
    if (!ev?.raw) return {}
    if (typeof ev.raw === 'string') { try { return JSON.parse(ev.raw) } catch { return {} } }
    return ev.raw || {}
  }

  // action field name is consistent across all platforms: raw.action
  const getAction = ev => {
    const raw = parseRaw(ev)
    return raw.action || '—'
  }

  // File hash — Linux sets file_hash directly, macOS sets raw.hash, Windows Sysmon sets file_hash
  const getHash = ev => {
    const raw = parseRaw(ev)
    return ev.file_hash || raw.hash || raw.file_hash || null
  }

  // Process — Linux fanotify sets process_name, Windows FIM and macOS kqueue do not
  const getProcess = ev => {
    const raw = parseRaw(ev)
    return ev.process_name || raw.process_name || null
  }

  const SUSPICIOUS_EXTS  = new Set(['.exe','.dll','.ps1','.bat','.cmd','.vbs','.js','.hta','.lnk','.scr','.pif','.com','.sh','.py'])
  const SUSPICIOUS_PATHS = ['/tmp/','/dev/shm/','\\temp\\','\\appdata\\local\\temp\\','\\windows\\temp\\','/var/tmp/']
  const EXEC_EXTS        = new Set(['.exe','.dll','.ps1','.bat','.cmd','.sh','.py','.rb','.pl','.elf'])

  const getExt  = path => { const m = String(path||'').match(/\.[^./\\]+$/); return m ? m[0].toLowerCase() : '' }
  const isSusp  = path => SUSPICIOUS_EXTS.has(getExt(path)) || SUSPICIOUS_PATHS.some(p => String(path||'').toLowerCase().includes(p))

  const filtered = events.filter(ev => {
    const path = ev.file_path || parseRaw(ev).path || ''
    if (search && !path.toLowerCase().includes(search.toLowerCase())) return false
    if (filter === 'suspicious') return isSusp(path) || ev.severity >= 3
    if (filter === 'executables') return EXEC_EXTS.has(getExt(path))
    if (filter === 'writes') {
      const a = getAction(ev)
      return a.includes('creat') || a.includes('modif') || a.includes('writ')
    }
    return true
  })

  const suspCount = events.filter(ev => {
    const path = ev.file_path || parseRaw(ev).path || ''
    return isSusp(path) || ev.severity >= 3
  }).length

  // Source tells analyst which collector fired
  const sourceLabel = src => {
    if (!src) return '—'
    if (src === 'fanotify') return 'FIM (fanotify)'
    if (src === 'inotify')  return 'FIM (inotify)'
    if (src === 'FIM')      return 'FIM'
    if (src === 'kqueue')   return 'FIM (kqueue)'
    if (src === 'Sysmon')   return 'Sysmon'
    return src
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="px-5 py-3 border-b border-siem-border shrink-0 flex items-center gap-3 flex-wrap">
        {suspCount > 0 && (
          <span className="text-[10px] px-2 py-1 bg-orange-900/20 border border-orange-800/40 text-orange-400 rounded-lg">
            ⚠ {suspCount} suspicious
          </span>
        )}
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Filter by path…"
          className="flex-1 min-w-[140px] bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text placeholder-siem-muted/50 outline-none focus:border-siem-accent"/>
        <div className="flex gap-1 flex-wrap">
          {[['all','All'],['writes','Writes'],['suspicious','Suspicious'],['executables','Executables']].map(([v,l]) => (
            <button key={v} onClick={() => setFilter(v)}
              className={`text-[10px] px-3 py-1 rounded-full border transition-colors ${filter===v?'border-siem-accent text-siem-accent bg-siem-accent/10':'border-siem-border text-siem-muted hover:text-siem-text'}`}>
              {l}
            </button>
          ))}
        </div>
      </div>
      {/* Flagged hashes from OTX/ThreatFox IOCs */}
      {!loading && flaggedHashes.length > 0 && (
        <div className="px-4 pt-3 shrink-0 space-y-1.5">
          <div className="text-[10px] uppercase tracking-wider text-red-400 font-semibold px-1 flex items-center gap-1.5">
            <AlertTriangle size={10}/> Malicious File Hashes (IOC Matches)
          </div>
          {flaggedHashes.map((f, i) => (
            <div key={i} className="bg-red-900/10 border border-red-800/30 rounded-xl px-4 py-2.5 flex items-center gap-3">
              <div className="flex-1 min-w-0">
                <div className="font-mono text-[10px] text-red-300 truncate" title={f.hash}>{f.hash?.slice(0,32)}…</div>
                {f.file_path && <div className="text-[9px] text-siem-muted truncate mt-0.5">{f.file_path}</div>}
              </div>
              <div className="text-[10px] text-red-400/80 shrink-0">{f.malware}</div>
              <div className="text-[9px] text-siem-muted shrink-0">{f.hit_count} hit{f.hit_count>1?'s':''} · {f.ioc_source?.toUpperCase()}</div>
            </div>
          ))}
        </div>
      )}

      <div className="flex-1 overflow-y-auto p-4">
        {loading ? <div className="text-center py-12 text-siem-muted">Loading…</div> : events.length === 0 ? (
          <div className="text-center py-12 space-y-2">
            <FolderOpen size={28} className="mx-auto text-siem-muted opacity-30"/>
            <div className="text-sm text-siem-muted">No file events for this host</div>
            <div className="text-[10px] text-siem-muted/50 max-w-xs mx-auto">
              {agent.os?.includes('win')
                ? 'Windows: FIM watches System32, SysWOW64, C:\\Users and C:\\ProgramData. Sysmon (event 11) also emits file events if installed.'
                : agent.os?.includes('darwin')
                  ? 'macOS: kqueue FIM watches configured paths. Check agent.yaml fim.dirs.'
                  : 'Linux: fanotify/inotify FIM watches configured paths. Check agent.yaml fim.dirs.'}
            </div>
          </div>
        ) : (
          <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-siem-border text-siem-muted">
                  <th className="text-left px-4 py-2.5 whitespace-nowrap">Time</th>
                  <th className="text-left px-4 py-2.5"></th>
                  <th className="text-left px-4 py-2.5">Action</th>
                  <th className="text-left px-4 py-2.5">File Path</th>
                  <th className="text-left px-4 py-2.5">Process</th>
                  <th className="text-left px-4 py-2.5">Hash</th>
                  <th className="text-left px-4 py-2.5">Collector</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0
                  ? <tr><td colSpan={7} className="text-center py-10 text-siem-muted">No events match filter</td></tr>
                  : filtered.map((ev, i) => {
                    const path   = ev.file_path || parseRaw(ev).path || '—'
                    const action = getAction(ev)
                    const hash   = getHash(ev)
                    const proc   = getProcess(ev)
                    const susp   = isSusp(path)
                    const isWrite = action.includes('creat') || action.includes('modif') || action.includes('writ')
                    return (
                      <tr key={ev.id||i} className={`border-b border-siem-border/40 hover:bg-white/[0.02] transition-colors ${susp?'bg-orange-900/5':''}`}>
                        <td className="px-4 py-2.5 font-mono text-[10px] text-siem-muted whitespace-nowrap">
                          {format(new Date(ev.time),'MM/dd HH:mm:ss')}
                        </td>
                        <td className="px-4 py-2.5"><SeverityBadge severity={ev.severity}/></td>
                        <td className="px-4 py-2.5">
                          <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                            action.includes('delet') ? 'bg-red-900/30 text-red-400' :
                            isWrite ? 'bg-orange-900/30 text-orange-400' :
                            'bg-siem-bg text-siem-muted'
                          }`}>{action}</span>
                        </td>
                        <td className="px-4 py-2.5 font-mono text-[10px] max-w-[260px] truncate">
                          {susp && <span className="inline-block w-1.5 h-1.5 rounded-full bg-orange-400 mr-1.5 mb-0.5 shrink-0"/>}
                          <span className={susp?'text-orange-300':'text-siem-text'} title={path}>{path}</span>
                        </td>
                        <td className="px-4 py-2.5 text-[10px] text-siem-muted">
                          {proc || <span className="opacity-30 italic">n/a</span>}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-[10px] text-siem-muted" title={hash||''}>
                          {hash ? (
                            <VTHashBadge hash={hash}/>
                          ) : '—'}
                        </td>
                        <td className="px-4 py-2.5 text-[10px] text-siem-muted/60">
                          {sourceLabel(ev.source)}
                        </td>
                      </tr>
                    )
                  })
                }
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Tab: Alerts ───────────────────────────────────────────────────────────────


function TabAlerts({ agent }) {
  const [alerts, setAlerts]     = useState([])
  const [loading, setLoading]   = useState(true)
  const [selectedId, setSelectedId] = useState(null)
  const [users, setUsers]       = useState([])

  const loadAlerts = () => {
    setLoading(true)
    api.get('/api/v1/alerts', { params: { host: agent.hostname, limit: 200 } })
      .then(r => setAlerts(r.data.alerts || []))
      .catch(() => setAlerts([]))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadAlerts()
    api.get('/api/v1/users').then(r => setUsers(r.data.users || [])).catch(() => {})
  }, [agent.hostname])

  const SEV_BORDER = { 5:'border-l-red-500', 4:'border-l-orange-500', 3:'border-l-yellow-500', 2:'border-l-blue-500', 1:'border-l-siem-border' }
  const SEV_CLS    = { 1:'bg-siem-bg text-siem-muted', 2:'bg-blue-900/30 text-blue-400', 3:'bg-yellow-900/30 text-yellow-400', 4:'bg-orange-900/30 text-orange-400', 5:'bg-red-900/30 text-red-400' }
  const STATUS_CLS = { open:'text-red-400', acknowledged:'text-yellow-400', closed:'text-emerald-400' }

  return (
    <div className="p-5 space-y-2 overflow-y-auto h-full">
      {/* Full AlertPanel — same as main Alerts page */}
      {selectedId && (
        <AlertPanelPortal
          alertId={selectedId}
          users={users}
          onClose={() => setSelectedId(null)}
          onStatusChange={() => { loadAlerts() }}
        />
      )}

      {loading ? (
        <div className="text-center py-12 text-siem-muted">Loading alerts…</div>
      ) : alerts.length === 0 ? (
        <div className="text-center py-12 text-siem-muted">No alerts for {agent.hostname}</div>
      ) : (
        alerts.map(a => (
          <div key={a.id} onClick={() => setSelectedId(a.id)}
            className={`rounded-xl p-4 border-l-2 bg-siem-surface border border-siem-border cursor-pointer hover:border-siem-accent/30 transition-colors group ${SEV_BORDER[a.severity] || 'border-l-siem-border'}`}>
            <div className="flex items-start gap-3">
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-siem-text group-hover:text-siem-accent transition-colors">{a.title}</div>
                <div className="text-xs text-siem-muted mt-0.5 line-clamp-2">{a.description}</div>
                <div className="flex items-center gap-2 mt-2 text-[10px]">
                  <span className="text-siem-muted">{a.event_type || '—'}</span>
                  <span className="text-siem-muted">·</span>
                  <span className={`font-medium ${STATUS_CLS[a.status] || 'text-siem-muted'}`}>{a.status}</span>
                  {a.assigned_to && <><span className="text-siem-muted">·</span><span className="text-siem-muted">→ {a.assigned_to}</span></>}
                </div>
              </div>
              <div className="flex flex-col items-end gap-1 shrink-0">
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${SEV_CLS[a.severity] || SEV_CLS[1]}`}>{SEV_LABEL[a.severity] || 'Info'}</span>
                <span className="text-[10px] text-siem-muted">{a.created_at ? formatDistanceToNow(new Date(a.created_at), { addSuffix: true }) : '—'}</span>
                <ChevronRight size={11} className="text-siem-muted/40 group-hover:text-siem-muted transition-colors"/>
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  )
}

// ── Tab: Device ───────────────────────────────────────────────────────────────

function TabDevice({ agent }) {
  const [healthEvents, setHealthEvents] = useState([])
  const [loading, setLoading]           = useState(true)

  useEffect(() => {
    setLoading(true)
    // Fetch last 60 health events for history charts
    api.get('/api/v1/events', { params: { host: agent.hostname, event_type: 'health', limit: 60 } })
      .then(r => setHealthEvents((r.data.events || []).reverse()))
      .catch(() => setHealthEvents([]))
      .finally(() => setLoading(false))
  }, [agent.hostname])

  const parseRaw = ev => {
    if (!ev?.raw) return null
    if (typeof ev.raw === 'string') { try { return JSON.parse(ev.raw) } catch { return null } }
    return ev.raw
  }

  const latest = healthEvents[healthEvents.length - 1]
  const raw    = parseRaw(latest)

  // Build history series for charts
  const cpuHistory  = healthEvents.map(ev => { const r = parseRaw(ev); return { t: ev.time ? format(new Date(ev.time),'HH:mm') : '', v: r?.cpu_percent ?? null } }).filter(p => p.v != null)
  const memHistory  = healthEvents.map(ev => { const r = parseRaw(ev); return { t: ev.time ? format(new Date(ev.time),'HH:mm') : '', v: r?.mem_percent ?? null } }).filter(p => p.v != null)

  const MetricBar = ({ label, value, total, unit='%', warnAt=60, critAt=80, barColor }) => {
    const pct = total ? (value / total * 100) : value
    const bg  = barColor || (pct > critAt ? '#ef4444' : pct > warnAt ? '#f97316' : '#22c55e')
    const display = total
      ? `${Number(value).toFixed(1)} / ${Number(total).toFixed(0)} ${unit}`
      : `${Number(value).toFixed(1)}${unit}`
    return (
      <div className="space-y-1">
        <div className="flex justify-between text-xs">
          <span className="text-siem-muted">{label}</span>
          <span className="font-mono text-siem-text">{display}</span>
        </div>
        <div className="h-2 bg-siem-border/20 rounded-full overflow-hidden">
          <div className="h-full rounded-full transition-all" style={{ width: Math.min(pct, 100)+'%', background: bg }}/>
        </div>
      </div>
    )
  }

  const MiniChart = ({ data, color, label, unit='%' }) => {
    if (!data?.length) return null
    return (
      <div className="bg-siem-surface border border-siem-border rounded-xl p-3">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">{label}</span>
          {data[data.length-1] && <span className="text-xs font-mono text-siem-text">{Number(data[data.length-1].v).toFixed(1)}{unit}</span>}
        </div>
        <div className="h-20">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id={`grad-${label}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={color} stopOpacity={0.3}/>
                  <stop offset="95%" stopColor={color} stopOpacity={0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="t" tick={{ fontSize: 8, fill: '#64748b' }} interval="preserveStartEnd" tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={{ background: '#0f1923', border: '1px solid #1e3a4a', borderRadius: 6, fontSize: 10 }} formatter={v => [`${Number(v).toFixed(1)}${unit}`, label]}/>
              <Area type="monotone" dataKey="v" stroke={color} fill={`url(#grad-${label})`} strokeWidth={1.5} dot={false}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    )
  }

  return (
    <div className="p-5 space-y-4 overflow-y-auto h-full">

      {/* System info */}
      <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
        <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-3">System</div>
        {[
          ['Hostname',    agent.hostname],
          ['OS',          agent.os || '—'],
          ['Agent version', agent.version || '—'],
          ['Last IP',     agent.last_ip || '—'],
          ['Agent ID',    agent.id],
          ['Last seen',   agent.last_seen ? formatDistanceToNow(new Date(agent.last_seen), { addSuffix: true }) : '—'],
        ].map(([k, v]) => (
          <div key={k} className="flex justify-between text-xs py-1.5 border-b border-siem-border/40 last:border-0">
            <span className="text-siem-muted">{k}</span>
            <span className="font-mono text-siem-text text-[11px]">{v}</span>
          </div>
        ))}
      </div>

      {loading && <div className="text-xs text-siem-muted/50 text-center py-8">Loading metrics…</div>}

      {!loading && !raw && (
        <div className="bg-siem-surface border border-siem-border rounded-xl p-6 text-center space-y-2">
          <div className="text-sm text-siem-muted">No health data yet</div>
          <div className="text-[10px] text-siem-muted/50 max-w-xs mx-auto">
            Reinstall the agent from the dashboard to get the latest version with system metrics. Health events fire every 60s.
          </div>
        </div>
      )}

      {!loading && raw && (<>

        {/* History charts */}
        <div className="grid grid-cols-2 gap-3">
          <MiniChart data={cpuHistory}  color="#22c55e" label="CPU"    unit="%"/>
          <MiniChart data={memHistory}  color="#3b82f6" label="Memory" unit="%"/>
        </div>

        {/* Current resource bars */}
        <div className="bg-siem-surface border border-siem-border rounded-xl p-4 space-y-3">
          <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold flex items-center justify-between">
            Resources
            {latest && <span className="font-normal">updated {formatDistanceToNow(new Date(latest.time), { addSuffix: true })}</span>}
          </div>

          {raw.cpu_percent != null && raw.cpu_percent >= 0 &&
            <MetricBar label="CPU" value={raw.cpu_percent} unit="%" warnAt={60} critAt={80}/>
          }
          {raw.mem_total_mb != null ? (
            <MetricBar
              label={`Memory (${Number(raw.mem_total_mb/1024).toFixed(1)} GB)`}
              value={raw.mem_used_mb} total={raw.mem_total_mb} unit="MB"
              warnAt={70} critAt={85}
              barColor={raw.mem_percent > 85 ? '#ef4444' : raw.mem_percent > 70 ? '#f97316' : '#3b82f6'}/>
          ) : raw.memory_percent != null &&
            <MetricBar label="Memory" value={raw.memory_percent} unit="%" warnAt={70} critAt={85} barColor="#3b82f6"/>
          }
        </div>

        {/* All disks */}
        {raw.disks?.length > 0 && (
          <div className="bg-siem-surface border border-siem-border rounded-xl p-4 space-y-3">
            <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">
              Disks ({raw.disks.length})
            </div>
            {raw.disks.map((d, i) => (
              <MetricBar
                key={i}
                label={`${d.mount}  (${Number(d.total_gb).toFixed(0)} GB)`}
                value={d.used_gb} total={d.total_gb} unit="GB"
                warnAt={75} critAt={90}
                barColor={d.free_percent < 10 ? '#ef4444' : d.free_percent < 25 ? '#f97316' : '#22c55e'}/>
            ))}
          </div>
        )}

        {/* Top processes */}
        {raw.top_processes?.length > 0 && (
          <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-siem-border">
              <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">
                Top processes by CPU + Memory
              </div>
            </div>
            {/* CPU bar chart */}
            <div className="px-4 pt-3 pb-1">
              <div className="text-[9px] text-siem-muted mb-2">CPU %</div>
              <div className="h-28">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={[...raw.top_processes].sort((a,b) => b.cpu_percent - a.cpu_percent).slice(0,10)} layout="vertical" margin={{ top:0, right:40, bottom:0, left:80 }}>
                    <XAxis type="number" tick={{ fontSize: 9, fill: '#64748b' }} tickLine={false} axisLine={false}/>
                    <YAxis type="category" dataKey="name" tick={{ fontSize: 9, fill: '#94a3b8' }} width={80} tickLine={false} axisLine={false}/>
                    <Tooltip contentStyle={{ background:'#0f1923', border:'1px solid #1e3a4a', borderRadius:6, fontSize:10 }} formatter={v => [`${Number(v).toFixed(1)}%`, 'CPU']}/>
                    <Bar dataKey="cpu_percent" radius={[0,3,3,0]}>
                      {raw.top_processes.slice(0,10).map((p,i) => (
                        <Cell key={i} fill={p.cpu_percent > 50 ? '#ef4444' : p.cpu_percent > 20 ? '#f97316' : '#22c55e'}/>
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
            {/* Memory bar chart */}
            <div className="px-4 pt-1 pb-3 border-t border-siem-border/30">
              <div className="text-[9px] text-siem-muted mb-2">Memory (MB)</div>
              <div className="h-28">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={[...raw.top_processes].sort((a,b) => b.mem_mb - a.mem_mb).slice(0,10)} layout="vertical" margin={{ top:0, right:40, bottom:0, left:80 }}>
                    <XAxis type="number" tick={{ fontSize: 9, fill: '#64748b' }} tickLine={false} axisLine={false}/>
                    <YAxis type="category" dataKey="name" tick={{ fontSize: 9, fill: '#94a3b8' }} width={80} tickLine={false} axisLine={false}/>
                    <Tooltip contentStyle={{ background:'#0f1923', border:'1px solid #1e3a4a', borderRadius:6, fontSize:10 }} formatter={v => [`${Number(v).toFixed(0)} MB`, 'Memory']}/>
                    <Bar dataKey="mem_mb" radius={[0,3,3,0]}>
                      {raw.top_processes.slice(0,10).map((p,i) => (
                        <Cell key={i} fill="#3b82f6"/>
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        )}

        {/* Agent internals */}
        <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
          <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-3">Agent internals</div>
          <div className="grid grid-cols-2 gap-x-6">
            {[
              ['Status',           raw.status],
              ['Uptime',           raw.uptime_seconds != null ? `${Math.floor(raw.uptime_seconds/3600)}h ${Math.floor((raw.uptime_seconds%3600)/60)}m` : '—'],
              ['Events collected', Number(raw.events_collected||0).toLocaleString()],
              ['Events forwarded', Number(raw.events_forwarded||0).toLocaleString()],
              ['Events dropped',   Number(raw.events_dropped||0).toLocaleString()],
              ['Queue depth',      Number(raw.queue_depth||0).toLocaleString()],
              ['Forward errors',   Number(raw.forward_errors||0).toLocaleString()],
              ['Goroutines',       raw.goroutines],
              ['Agent heap',       raw.agent_memory_mb != null ? `${Number(raw.agent_memory_mb).toFixed(1)} MB` : null],
            ].filter(([,v]) => v != null).map(([k, v]) => (
              <div key={k} className="flex justify-between text-xs py-1.5 border-b border-siem-border/30 last:border-0">
                <span className="text-siem-muted">{k}</span>
                <span className={`font-mono text-[11px] ${
                  k==='Events dropped'  && Number(raw.events_dropped)  > 0 ? 'text-orange-400' :
                  k==='Forward errors'  && Number(raw.forward_errors)  > 0 ? 'text-red-400' : 'text-siem-text'
                }`}>{String(v)}</span>
              </div>
            ))}
          </div>
          {raw.collectors?.length > 0 && (
            <div className="mt-3 pt-3 border-t border-siem-border/30">
              <div className="text-[10px] text-siem-muted mb-2">Active collectors</div>
              <div className="flex flex-wrap gap-1.5">
                {raw.collectors.map(c => (
                  <span key={c} className="text-[10px] px-2 py-0.5 bg-emerald-900/20 text-emerald-400 border border-emerald-800/30 rounded-full">{c}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </>)}
    </div>
  )
}

// ── Tab: Location ─────────────────────────────────────────────────────────────

function TabLocation({ agent }) {
  const [loc, setLoc]       = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    api.get('/api/v1/agents/locations')
      .then(r => {
        const locs = Array.isArray(r.data) ? r.data : (r.data.locations || [])
        setLoc(locs.find(l => l.id === agent.id || l.hostname === agent.hostname) || null)
      })
      .catch(() => setLoc(null))
      .finally(() => setLoading(false))
  }, [agent.id, agent.hostname])

  if (loading) return <div className="p-5 text-center text-siem-muted">Loading location…</div>

  if (!loc) return (
    <div className="p-5 text-center py-12">
      <MapPin size={32} className="mx-auto mb-3 text-siem-muted opacity-20"/>
      <div className="text-sm text-siem-muted">No location data for this agent</div>
      <div className="text-xs text-siem-muted/60 mt-2 max-w-sm mx-auto">
        Location is reported every 30 minutes via IP geolocation. Reinstall the latest agent to enable it.
      </div>
    </div>
  )

  const hasCoords = loc.lat && loc.lng
  const lat = Number(loc.lat).toFixed(6)
  const lng = Number(loc.lng).toFixed(6)
  // OpenStreetMap embed — no API key required
  const mapSrc = hasCoords
    ? `https://www.openstreetmap.org/export/embed.html?bbox=${Number(lng)-0.05},${Number(lat)-0.05},${Number(lng)+0.05},${Number(lat)+0.05}&layer=mapnik&marker=${lat},${lng}`
    : null

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Embedded map */}
      {hasCoords && (
        <div className="flex-1 min-h-0" style={{ minHeight: 320 }}>
          <iframe
            src={mapSrc}
            title="Agent location"
            width="100%"
            height="100%"
            style={{ border: 'none', minHeight: 320, display: 'block' }}
            loading="lazy"
          />
        </div>
      )}

      {/* Info strip below map */}
      <div className="p-4 space-y-0 bg-siem-surface border-t border-siem-border shrink-0">
        <div className="grid grid-cols-3 gap-4">
          {[
            ['Location',    [loc.location_city, loc.location_country].filter(Boolean).join(', ') || '—'],
            ['Coordinates', hasCoords ? `${Number(lat).toFixed(4)}°, ${Number(lng).toFixed(4)}°` : '—'],
            ['Source',      loc.location_source || '—'],
            ['Accuracy',    loc.location_accuracy ? `~${Math.round(loc.location_accuracy)}m` : '—'],
            ['Updated',     loc.location_updated ? formatDistanceToNow(new Date(loc.location_updated), { addSuffix: true }) : '—'],
          ].map(([k, v]) => (
            <div key={k}>
              <div className="text-[9px] uppercase tracking-wider text-siem-muted mb-0.5">{k}</div>
              <div className="text-xs font-mono text-siem-text">{v}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── AgentDetail ───────────────────────────────────────────────────────────────

// ── Tab: Terminal (Live Response) ─────────────────────────────────────────────

function TabTerminal({ agent }) {
  const [session, setSession]       = useState(null)
  const [connecting, setConnecting] = useState(false)
  const [error, setError]           = useState(null)
  const [connected, setConnected]   = useState(false)
  const termRef  = useRef(null)
  const xtermRef = useRef(null)
  const wsRef    = useRef(null)

  // Clean up on unmount or agent change
  useEffect(() => {
    return () => {
      if (wsRef.current)    wsRef.current.close()
      if (xtermRef.current) xtermRef.current.dispose()
      setSession(null); setConnected(false)
    }
  }, [agent.id])

  const startSession = async () => {
    setConnecting(true)
    setError(null)
    try {
      const { data } = await api.post('/api/v1/live-response/sessions', { agent_id: agent.id })
      setSession(data)
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Failed to start session')
    } finally {
      setConnecting(false)
    }
  }

  const endSession = async () => {
    if (wsRef.current)    { wsRef.current.close();    wsRef.current    = null }
    if (xtermRef.current) { xtermRef.current.dispose(); xtermRef.current = null }
    if (session?.session_token) {
      await api.delete(`/api/v1/live-response/sessions/${session.session_token}`).catch(() => {})
    }
    setSession(null)
    setConnected(false)
    setError(null)
  }

  // Open WebSocket IMMEDIATELY when session is set — before xterm loads
  // This ensures open_session reaches the agent without delay
  useEffect(() => {
    if (!session) return

    let dead = false
    const buffer = []

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const jwt   = localStorage.getItem('token') || ''
    const wsURL = `${proto}//${window.location.host}/api/v1/live-response/terminal?token=${session.session_token}&auth=${jwt}`
    const ws    = new WebSocket(wsURL)
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws

    ws.onopen = () => {
      if (dead) return
      setConnected(true)
      if (xtermRef.current) {
        xtermRef.current.writeln('\x1b[32m✓ Tunnel established — opening shell…\x1b[0m\r\n')
      }
    }
    ws.onmessage = (evt) => {
      if (dead) return
      const data = evt.data instanceof ArrayBuffer
        ? new Uint8Array(evt.data)
        : new TextEncoder().encode(evt.data)
      if (xtermRef.current) {
        xtermRef.current.write(data)
      } else {
        buffer.push(data)
      }
    }
    ws.onerror = () => {
      if (dead) return
      setError('WebSocket connection failed')
    }
    ws.onclose = (e) => {
      if (dead) return
      setConnected(false)
    }

    const loadXterm = async () => {
      if (dead || !termRef.current) return

      const term = new XTerm({
        cursorBlink: true,
        fontSize:    13,
        fontFamily:  '"JetBrains Mono","Fira Code","Courier New",monospace',
        theme: {
          background:  '#0a0f1a',
          foreground:  '#e2e8f0',
          cursor:      '#34d399',
          black:       '#1e293b',
          red:         '#f87171',
          green:       '#34d399',
          yellow:      '#fbbf24',
          blue:        '#60a5fa',
          magenta:     '#c084fc',
          cyan:        '#22d3ee',
          white:       '#e2e8f0',
          brightBlack: '#475569',
        },
        rows: 30, cols: 120,
      })

      term.open(termRef.current)
      term.writeln('\r\n\x1b[32m ObsidianWatch Live Response\x1b[0m')
      term.writeln(` Connecting to \x1b[36m${session.hostname}\x1b[0m as \x1b[33m${session.username}\x1b[0m…`)
      if (ws.readyState === WebSocket.OPEN) {
        term.writeln('\x1b[32m✓ Tunnel established — opening shell…\x1b[0m\r\n')
      }
      xtermRef.current = term
      buffer.forEach(d => term.write(d))
      buffer.length = 0

      term.onData(data => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(new TextEncoder().encode(data))
        }
      })
    }

    loadXterm().catch(e => setError(e.message))

    return () => {
      dead = true
      if (wsRef.current)    { wsRef.current.close();     wsRef.current    = null }
      if (xtermRef.current) { xtermRef.current.dispose(); xtermRef.current = null }
    }
  }, [session])


  // ── No session yet — show connect prompt ──────────────────────────────────
  if (!session) {
    const os = (agent.os || '').toLowerCase()
    const isWindows = os.includes('win')
    const isMac     = os.includes('darwin') || os.includes('mac')

    return (
      <div className="flex flex-col items-center justify-center h-full gap-5 p-6">
        <div className="w-16 h-16 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
          <Terminal size={28} className="text-emerald-400 opacity-70"/>
        </div>

        <div className="text-center">
          <div className="text-sm font-semibold text-siem-text mb-1">Live Response Terminal</div>
          <div className="text-xs text-siem-muted max-w-sm">
            Opens an interactive shell session directly to <span className="text-siem-text font-mono">{agent.hostname}</span> through
            the existing agent tunnel. No inbound ports required.
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/20 border border-red-800/40 rounded-lg px-4 py-2 max-w-sm">
            <AlertTriangle size={12}/> {error}
          </div>
        )}

        <button
          onClick={startSession}
          disabled={connecting}
          className="flex items-center gap-2 px-5 py-2.5 bg-emerald-900/30 border border-emerald-700 text-emerald-400 rounded-xl text-sm font-medium hover:bg-emerald-900/50 transition-colors disabled:opacity-50 disabled:cursor-wait"
        >
          {connecting
            ? <><RefreshCw size={14} className="animate-spin"/> Connecting…</>
            : <><Terminal size={14}/> Start Session</>
          }
        </button>
      </div>
    )
  }

  // ── Session active — show terminal ────────────────────────────────────────
  return (
    <div className="flex flex-col h-full bg-[#0a0f1a]">
      {/* Terminal toolbar */}
      <div className="flex items-center justify-between px-4 py-2 bg-siem-surface border-b border-siem-border shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500"/>
            <span className="w-3 h-3 rounded-full bg-yellow-500"/>
            <span className="w-3 h-3 rounded-full bg-emerald-500"/>
          </div>
          <span className="text-xs font-mono text-siem-muted">
            {session.username}@{session.hostname}
          </span>
          {connected && (
            <span className="flex items-center gap-1 text-[10px] text-emerald-400">
              <Activity size={10} className="animate-pulse"/> Live
            </span>
          )}
        </div>
        <button
          onClick={endSession}
          className="flex items-center gap-1.5 text-[11px] text-red-400 hover:text-red-300 px-2 py-1 rounded border border-red-800 hover:border-red-600 transition-colors"
        >
          <Square size={10}/> End Session
        </button>
      </div>

      {error && (
        <div className="flex-shrink-0 px-4 py-2 bg-red-950/30 border-b border-red-800 text-xs text-red-300 flex items-center gap-2">
          <AlertTriangle size={12}/> {error}
        </div>
      )}

      {/* xterm.js container */}
      <div ref={termRef} className="flex-1 p-2 overflow-hidden"/>
    </div>
  )
}

// ── Tab: Vulnerability Scan ───────────────────────────────────────────────────
function PortRow({ port, st, forceExpand }) {
  const [exp, setExp] = React.useState(false)
  React.useEffect(() => setExp(forceExpand), [forceExpand])
  const hasDetail = !!(port.risk_detail || port.banner)
  return (
    <div className={"border-b border-siem-border/20 last:border-0 " + (hasDetail ? "cursor-pointer hover:bg-white/[0.02]" : "")}
      onClick={() => hasDetail && setExp(e => !e)}>
      <div className="grid gap-0 px-4 py-2.5 items-center" style={{gridTemplateColumns:"72px 90px 140px 1fr 80px"}}>
        <span className="font-mono text-sm font-bold text-siem-text">{port.port}</span>
        <span className="text-[10px] text-siem-muted uppercase font-mono">{port.protocol}</span>
        <div className="min-w-0">
          <span className={"text-[11px] font-medium " + (port.product ? "text-siem-text" : "text-siem-muted/50")}>
            {port.product || port.service || "—"}
          </span>
          {port.version && (
            <span className="ml-1.5 text-[9px] font-mono bg-siem-bg border border-siem-border px-1.5 py-0.5 rounded text-siem-muted">
              v{port.version}
            </span>
          )}
        </div>
        <div className="min-w-0 pr-3">
          {port.risk_label
            ? <span className={"text-[11px] truncate block " + st.text}>⚠ {port.risk_label}</span>
            : port.banner
            ? <span className="text-[10px] font-mono text-siem-muted/40 truncate block">{port.banner.slice(0,60)}</span>
            : <span className="text-[10px] text-siem-muted/20">—</span>}
        </div>
        <div className="flex justify-end">
          <span className={"text-[9px] font-bold px-2 py-0.5 rounded border " + st.bg + " " + st.border + " " + st.text}>
            {st.label}
          </span>
        </div>
      </div>
      {exp && hasDetail && (
        <div className={"mx-4 mb-3 p-3 rounded-lg border " + st.bg + " " + st.border}>
          {port.risk_detail && <p className={"text-xs mb-1.5 " + st.text}>{port.risk_detail}</p>}
          {port.banner && <p className="text-[10px] font-mono text-siem-text/60 break-all">Banner: {port.banner}</p>}
        </div>
      )}
    </div>
  )
}

function FindingCard({ f, SEV }) {
  const st = SEV[f.severity] || SEV[1]
  return (
    <div className={"rounded-xl border p-4 " + st.bg + " " + st.border}>
      <div className="flex items-start gap-3">
        <span className={"w-2 h-2 rounded-full mt-1 shrink-0 " + st.dot}/>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={"text-[9px] font-bold px-2 py-0.5 rounded border " + st.bg + " " + st.border + " " + st.text}>{st.label}</span>
            <span className="text-[10px] text-siem-muted">{f.category}</span>
          </div>
          <div className={"text-sm font-semibold mb-1 " + st.text}>{f.title}</div>
          <div className="text-xs text-siem-muted/80 mb-2">{f.detail}</div>
          {f.fix && (
            <div className="bg-siem-bg border border-siem-border/50 rounded-lg px-3 py-2">
              <div className="text-[9px] uppercase tracking-wider text-siem-muted/50 mb-1">Remediation</div>
              <code className="text-[10px] font-mono text-emerald-400">{f.fix}</code>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function AIFindingCard({ finding, type: cardType }) {
  const colors = {
    critical: { bg: "bg-red-950/30", border: "border-red-800/40", text: "text-red-400", badge: "bg-red-900/40 border-red-700 text-red-300" },
    high:     { bg: "bg-orange-950/20", border: "border-orange-800/30", text: "text-orange-400", badge: "bg-orange-900/30 border-orange-700 text-orange-300" },
    medium:   { bg: "bg-yellow-950/15", border: "border-yellow-800/25", text: "text-yellow-400", badge: "bg-yellow-900/20 border-yellow-700 text-yellow-300" },
  }
  const c = colors[cardType] || colors.medium
  return (
    <div className={"rounded-xl border p-4 " + c.bg + " " + c.border}>
      <div className="text-sm font-semibold text-siem-text mb-1">{finding.title}</div>
      <div className="text-xs text-siem-muted/80 mb-2">{finding.detail}</div>
      {finding.cve_references?.length > 0 && (
        <div className="flex gap-1 flex-wrap mb-2">
          {finding.cve_references.map(cve => (
            <a key={cve} href={"https://nvd.nist.gov/vuln/detail/" + cve} target="_blank" rel="noreferrer"
              className={"text-[9px] font-mono px-2 py-0.5 rounded border cursor-pointer hover:opacity-80 " + c.badge}>
              {cve} ↗
            </a>
          ))}
        </div>
      )}
      {finding.remediation && (
        <div className="bg-siem-bg border border-siem-border/40 rounded-lg px-3 py-2 mt-2">
          <div className="text-[9px] uppercase tracking-wider text-siem-muted/40 mb-1">Fix</div>
          <code className="text-[10px] font-mono text-emerald-400/90">{finding.remediation}</code>
        </div>
      )}
    </div>
  )
}

function TabVuln({ agent }) {
  const [data, setData]           = useState(null)
  const [loading, setLoading]     = useState(true)
  const [aiLoading, setAILoading] = useState(false)
  const [aiResult, setAIResult]   = useState(null)
  const [aiError, setAIError]     = useState(null)
  const [expandAll, setExpandAll] = useState(false)
  const [activeSection, setActiveSection] = useState("overview")

  const SEV = {
    5: { label:"Critical", bg:"bg-red-950/40",    border:"border-red-800/50",    text:"text-red-400",    dot:"bg-red-400"    },
    4: { label:"High",     bg:"bg-orange-950/30", border:"border-orange-800/40", text:"text-orange-400", dot:"bg-orange-400" },
    3: { label:"Medium",   bg:"bg-yellow-950/20", border:"border-yellow-800/30", text:"text-yellow-400", dot:"bg-yellow-400" },
    2: { label:"Low",      bg:"bg-blue-950/15",   border:"border-blue-800/25",   text:"text-blue-400",   dot:"bg-blue-400"   },
    1: { label:"Info",     bg:"bg-siem-surface",  border:"border-siem-border",   text:"text-siem-muted", dot:"bg-siem-muted/40" },
  }

  const parseRaw = ev => {
    if (!ev?.raw) return null
    if (typeof ev.raw === "string") { try { return JSON.parse(ev.raw) } catch { return null } }
    return ev.raw
  }

  useEffect(() => {
    setLoading(true)
    api.get("/api/v1/agents/" + encodeURIComponent(agent.hostname) + "/vuln")
      .then(r => setData(r.data?.scan || null))
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [agent.hostname])

  // Load cached vuln AI analysis on mount
  useEffect(() => {
    api.get("/api/v1/agents/" + encodeURIComponent(agent.hostname) + "/vuln/analysis-cache")
      .then(r => {
        if (r.data?.analysis && !aiResult) {
          try {
            const clean = r.data.analysis.replace(/```json\n?|```\n?/g, "").trim()
            setAIResult(JSON.parse(clean))
          } catch (e) {}
        }
      }).catch(() => {})
  }, [agent.hostname])

  const runAIAnalysis = async () => {
    if (!data) return
    setAILoading(true); setAIError(null); setAIResult(null)
    try {
      const scan = parseRaw(data)
      const { data: res } = await api.post(
        "/api/v1/agents/" + encodeURIComponent(agent.hostname) + "/vuln/analyse",
        { scan_json: JSON.stringify(scan), host: agent.hostname },
        { timeout: 120000 }
      )
      const text = res.content?.find(b => b.type === "text")?.text || ""
      const clean = text.replace(/```json\n?|```\n?/g, "").trim()
      try {
        const parsed = JSON.parse(clean)
        setAIResult(parsed)
      } catch {
        setAIResult({ executive_summary: clean })
      }
      setActiveSection("ai")
    } catch (e) {
      setAIError(e.response?.data?.error || "AI analysis failed — check your API key in Settings → AI")
    } finally { setAILoading(false) }
  }

  if (loading) return (
    <div className="flex items-center justify-center py-16 gap-2 text-siem-muted">
      <RefreshCw size={14} className="animate-spin"/><span className="text-sm">Loading scan…</span>
    </div>
  )

  const scan = parseRaw(data)

  if (!scan) return (
    <div className="flex flex-col items-center justify-center py-20 gap-4">
      <div className="w-16 h-16 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
        <Bug size={28} className="text-siem-muted/25"/>
      </div>
      <div className="text-center">
        <div className="text-sm font-semibold text-siem-text/70 mb-1">No vulnerability scan yet</div>
        <div className="text-xs text-siem-muted/50 max-w-xs text-center">
          Agent scans all 65,535 TCP ports automatically on startup, then every 5 days.
          Redeploy the agent to trigger a new scan.
        </div>
      </div>
    </div>
  )

  const ports     = scan.open_ports || []
  const findings  = scan.findings   || []
  const packages  = scan.packages   || []
  const services  = scan.services   || []
  const critical  = ports.filter(p => p.severity >= 5)
  const high      = ports.filter(p => p.severity === 4)
  const medium    = ports.filter(p => p.severity === 3)
  const low       = ports.filter(p => p.severity <= 2)
  const topSev    = scan.critical_count > 0 ? 5 : scan.high_count > 0 ? 4 : scan.medium_count > 0 ? 3 : ports.length > 0 ? 2 : 1
  const topStyle  = SEV[topSev]

  const SECTIONS = [
    { id:"overview", label:"Overview" },
    { id:"ports",    label:`Ports (${ports.length})` },
    { id:"findings", label:`Findings (${findings.length})` },
    { id:"packages", label:`Packages (${packages.length})` },
    { id:"ai",       label:"AI Analysis", highlight: true },
  ]

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Top bar — risk summary + AI button */}
      <div className="shrink-0 px-5 py-3 border-b border-siem-border bg-siem-surface">
        <div className="flex items-center gap-4">
          {/* Posture */}
          <div className={"flex items-center gap-2.5 px-3 py-2 rounded-xl border " + topStyle.bg + " " + topStyle.border}>
            <span className={"w-2 h-2 rounded-full " + topStyle.dot}/>
            <span className={"text-sm font-bold " + topStyle.text}>{topStyle.label} Risk</span>
          </div>

          {/* Counts */}
          <div className="flex items-center gap-4">
            {[
              [scan.critical_count, "Critical", "text-red-400"],
              [scan.high_count,     "High",     "text-orange-400"],
              [scan.medium_count,   "Medium",   "text-yellow-400"],
              [ports.length,        "Open Ports","text-siem-muted"],
            ].map(([n, label, color]) => n > 0 && (
              <div key={label} className="text-center">
                <div className={"text-lg font-bold font-mono " + color}>{n}</div>
                <div className="text-[9px] text-siem-muted uppercase tracking-wide">{label}</div>
              </div>
            ))}
          </div>

          {/* Scan metadata */}
          <div className="ml-auto flex items-center gap-3 text-[10px] text-siem-muted">
            {data?.time && <span>{formatDistanceToNow(new Date(data.time), {addSuffix:true})}</span>}
            {scan.scan_duration_secs && <span>{scan.scan_duration_secs.toFixed(0)}s scan</span>}
            <span className="font-mono">65,535 ports</span>
          </div>

          {/* AI Analysis button */}
          <button onClick={runAIAnalysis} disabled={aiLoading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-500 hover:to-purple-500 disabled:opacity-50 text-white transition-all shadow-lg shadow-violet-900/30">
            {aiLoading
              ? <><RefreshCw size={12} className="animate-spin"/> Analysing…</>
              : <><Zap size={12}/> AI Analysis</>}
          </button>
        </div>

        {/* Section tabs */}
        <div className="flex gap-0 mt-3">
          {SECTIONS.map(s => (
            <button key={s.id} onClick={() => setActiveSection(s.id)}
              className={"flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium transition-colors border-b-2 " + (
                activeSection === s.id
                  ? (s.highlight ? "border-violet-400 text-violet-400" : "border-siem-accent text-siem-accent")
                  : "border-transparent text-siem-muted hover:text-siem-text"
              )}>
              {s.label}
              {s.id === "ai" && aiResult && <span className="w-1.5 h-1.5 rounded-full bg-violet-400 ml-0.5"/>}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">

        {/* ── Overview ── */}
        {activeSection === "overview" && (
          <div className="p-5 space-y-4">
            {/* System info */}
            <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
              <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3">System</div>
              <div className="grid grid-cols-2 gap-x-8">
                {[
                  ["Hostname",    scan.system?.hostname || agent.hostname],
                  ["OS",          scan.system?.os_release || scan.os || agent.os],
                  ["Kernel",      scan.system?.kernel_version || "—"],
                  ["Arch",        scan.system?.arch || "—"],
                  ["Scan time",   scan.scan_duration_secs ? scan.scan_duration_secs.toFixed(1) + "s" : "—"],
                  ["Ports scanned", "1 – 65,535 TCP"],
                  ["Packages",    (scan.packages?.length || 0) + " installed"],
                  ["Services",    (scan.services?.length || 0) + " running"],
                ].map(([k,v]) => (
                  <div key={k} className="flex justify-between text-xs py-1.5 border-b border-siem-border/20 last:border-0">
                    <span className="text-siem-muted">{k}</span>
                    <span className="font-mono text-siem-text text-[11px]">{v}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Host findings */}
            {findings.length > 0 && (
              <div className="space-y-3">
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold">Security Findings</div>
                {findings.sort((a,b) => b.severity - a.severity).map((f,i) => (
                  <FindingCard key={i} f={f} SEV={SEV}/>
                ))}
              </div>
            )}

            {/* Top risky ports preview */}
            {(critical.length + high.length) > 0 && (
              <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                <div className="px-4 py-2.5 border-b border-siem-border flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Bug size={13} className="text-red-400"/>
                    <span className="text-xs font-semibold text-siem-text">Critical & High Risk Ports</span>
                  </div>
                  <button onClick={() => setActiveSection("ports")} className="text-[10px] text-siem-muted hover:text-siem-accent">
                    View all →
                  </button>
                </div>
                {[...critical, ...high].slice(0, 8).map((p,i) => (
                  <PortRow key={i} port={p} st={SEV[p.severity] || SEV[1]} forceExpand={false}/>
                ))}
              </div>
            )}

            {findings.length === 0 && critical.length === 0 && high.length === 0 && (
              <div className="flex flex-col items-center justify-center py-10 gap-2">
                <CheckCircle size={28} className="text-emerald-400/50"/>
                <div className="text-sm font-medium text-siem-text/60">No critical or high findings</div>
                <div className="text-xs text-siem-muted/40">Run AI Analysis for a detailed assessment</div>
              </div>
            )}
          </div>
        )}

        {/* ── Ports ── */}
        {activeSection === "ports" && (
          <div className="p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="text-xs text-siem-muted">{ports.length} open TCP ports found</div>
              <button onClick={() => setExpandAll(e => !e)}
                className="text-[10px] text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-2.5 py-1">
                {expandAll ? "Collapse all" : "Expand all"}
              </button>
            </div>
            {ports.length === 0 ? (
              <div className="flex flex-col items-center py-12 gap-2">
                <CheckCircle size={24} className="text-emerald-400/40"/>
                <span className="text-sm text-siem-muted">No open TCP ports</span>
              </div>
            ) : (
              <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                <div className="grid gap-0 px-4 py-2 border-b border-siem-border/40 bg-siem-bg/40" style={{gridTemplateColumns:"72px 90px 140px 1fr 80px"}}>
                  {["Port","Proto","Service","Risk","Severity"].map(h => (
                    <span key={h} className="text-[9px] uppercase tracking-wider text-siem-muted/50 font-semibold">{h}</span>
                  ))}
                </div>
                {[...critical,...high,...medium,...low].map((p,i) => (
                  <PortRow key={i} port={p} st={SEV[p.severity]||SEV[1]} forceExpand={expandAll}/>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── Findings ── */}
        {activeSection === "findings" && (
          <div className="p-5 space-y-3">
            {findings.length === 0 ? (
              <div className="flex flex-col items-center py-12 gap-2">
                <CheckCircle size={24} className="text-emerald-400/40"/>
                <span className="text-sm text-siem-muted">No security findings</span>
              </div>
            ) : (
              findings.sort((a,b) => b.severity - a.severity).map((f,i) => (
                <FindingCard key={i} f={f} SEV={SEV}/>
              ))
            )}
          </div>
        )}

        {/* ── Packages ── */}
        {activeSection === "packages" && (
          <div className="p-5">
            {packages.length === 0 ? (
              <div className="text-center text-sm text-siem-muted py-12">No package data collected</div>
            ) : (
              <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                <div className="grid px-4 py-2 border-b border-siem-border/40 bg-siem-bg/40" style={{gridTemplateColumns:"1fr 160px 80px"}}>
                  {["Package","Version","Manager"].map(h => (
                    <span key={h} className="text-[9px] uppercase tracking-wider text-siem-muted/50 font-semibold">{h}</span>
                  ))}
                </div>
                <div className="max-h-[600px] overflow-y-auto">
                  {packages.map((pkg,i) => (
                    <div key={i} className="grid px-4 py-2 border-b border-siem-border/15 last:border-0 text-[11px]" style={{gridTemplateColumns:"1fr 160px 80px"}}>
                      <span className="font-mono text-siem-text truncate">{pkg.name}</span>
                      <span className="font-mono text-siem-muted">{pkg.version}</span>
                      <span className="text-siem-muted/50 uppercase text-[9px]">{pkg.manager}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── AI Analysis ── */}
        {activeSection === "ai" && (
          <div className="p-5 space-y-4">
            {aiError && (
              <div className="bg-red-950/20 border border-red-800/30 rounded-xl p-4 text-xs text-red-400">
                {aiError} — ensure Groq or Anthropic API key is configured in Settings.
              </div>
            )}

            {!aiResult && !aiLoading && !aiError && (
              <div className="flex flex-col items-center justify-center py-16 gap-4">
                <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-violet-600/20 to-purple-600/20 border border-violet-500/30 flex items-center justify-center">
                  <Zap size={28} className="text-violet-400"/>
                </div>
                <div className="text-center">
                  <div className="text-sm font-semibold text-siem-text mb-1">Enterprise AI Analysis</div>
                  <div className="text-xs text-siem-muted/70 max-w-sm text-center mb-4">
                    AI analyses port scan data, service versions, and security findings to produce
                    CVE matches, risk scoring, and a prioritised remediation plan.
                  </div>
                  <button onClick={runAIAnalysis}
                    className="flex items-center gap-2 mx-auto px-5 py-2.5 rounded-xl text-sm font-semibold bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-500 hover:to-purple-500 text-white transition-all shadow-lg shadow-violet-900/30">
                    <Zap size={14}/> Run AI Analysis
                  </button>
                </div>
              </div>
            )}

            {aiLoading && (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <div className="w-12 h-12 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center">
                  <RefreshCw size={20} className="text-violet-400 animate-spin"/>
                </div>
                <div className="text-sm text-siem-muted">Analysing {ports.length} ports, {packages.length} packages…</div>
                <div className="text-xs text-siem-muted/40">This takes 10-30 seconds</div>
              </div>
            )}

            {aiResult && (
              <div className="space-y-5">
                {/* Risk score + executive summary */}
                <div className="bg-siem-surface border border-siem-border rounded-xl p-5">
                  <div className="flex items-start gap-5">
                    {aiResult.risk_score != null && (
                      <div className="relative shrink-0 w-20 h-20">
                        <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
                          <circle cx="40" cy="40" r="32" fill="none" stroke="#21262d" strokeWidth="7"/>
                          <circle cx="40" cy="40" r="32" fill="none"
                            stroke={aiResult.risk_score>=80?"#ef4444":aiResult.risk_score>=60?"#f97316":aiResult.risk_score>=40?"#eab308":"#3fb950"}
                            strokeWidth="7"
                            strokeDasharray={`${2*Math.PI*32}`}
                            strokeDashoffset={`${2*Math.PI*32*(1-aiResult.risk_score/100)}`}
                            strokeLinecap="round"/>
                        </svg>
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                          <span className="text-xl font-bold font-mono text-siem-text">{aiResult.risk_score}</span>
                          <span className="text-[9px] text-siem-muted">risk</span>
                        </div>
                      </div>
                    )}
                    <div className="flex-1">
                      {aiResult.risk_label && (
                        <div className="text-xs font-bold uppercase tracking-wider text-siem-muted mb-1">{aiResult.risk_label} Risk</div>
                      )}
                      <p className="text-sm text-siem-text leading-relaxed">{aiResult.executive_summary}</p>
                    </div>
                  </div>
                </div>

                {/* Attack surface */}
                {aiResult.attack_surface_summary && (
                  <div className="bg-orange-950/15 border border-orange-800/25 rounded-xl p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <AlertTriangle size={13} className="text-orange-400"/>
                      <span className="text-xs font-semibold text-orange-400 uppercase tracking-wide">Attack Surface</span>
                    </div>
                    <p className="text-xs text-siem-muted/90 leading-relaxed">{aiResult.attack_surface_summary}</p>
                  </div>
                )}

                {/* Immediate actions */}
                {aiResult.immediate_actions?.length > 0 && (
                  <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                    <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3">Immediate Actions Required</div>
                    <div className="space-y-2">
                      {aiResult.immediate_actions.map((action, i) => (
                        <div key={i} className="flex items-start gap-3">
                          <span className="w-5 h-5 rounded-full bg-red-500/20 border border-red-500/30 text-red-400 text-[9px] font-bold flex items-center justify-center shrink-0 mt-0.5">{i+1}</span>
                          <span className="text-xs text-siem-text">{action}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Critical findings */}
                {aiResult.critical_findings?.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-[10px] uppercase tracking-wider text-red-400/80 font-semibold">Critical Findings</div>
                    {aiResult.critical_findings.map((f,i) => <AIFindingCard key={i} finding={f} type="critical"/>)}
                  </div>
                )}

                {/* High findings */}
                {aiResult.high_findings?.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-[10px] uppercase tracking-wider text-orange-400/80 font-semibold">High Risk Findings</div>
                    {aiResult.high_findings.map((f,i) => <AIFindingCard key={i} finding={f} type="high"/>)}
                  </div>
                )}

                {/* Medium findings */}
                {aiResult.medium_findings?.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-[10px] uppercase tracking-wider text-yellow-400/80 font-semibold">Medium Risk Findings</div>
                    {aiResult.medium_findings.map((f,i) => <AIFindingCard key={i} finding={f} type="medium"/>)}
                  </div>
                )}

                {/* Outdated software */}
                {aiResult.outdated_software?.length > 0 && (
                  <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                    <div className="px-4 py-2.5 border-b border-siem-border flex items-center gap-2">
                      <Bug size={13} className="text-orange-400"/>
                      <span className="text-xs font-semibold text-siem-text">Outdated Software</span>
                    </div>
                    {aiResult.outdated_software.map((sw,i) => (
                      <div key={i} className="px-4 py-3 border-b border-siem-border/20 last:border-0">
                        <div className="flex items-center gap-3 mb-1.5">
                          <span className="text-sm font-mono font-semibold text-siem-text">{sw.name}</span>
                          <span className="text-[10px] font-mono text-red-400 bg-red-950/20 border border-red-800/30 rounded px-1.5 py-0.5">{sw.installed_version}</span>
                          {sw.recommended_version && (
                            <><span className="text-siem-muted/40 text-xs">→</span>
                            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/20 border border-emerald-800/30 rounded px-1.5 py-0.5">{sw.recommended_version}</span></>
                          )}
                          {sw.cves?.map(cve => (
                            <a key={cve} href={"https://nvd.nist.gov/vuln/detail/" + cve} target="_blank" rel="noreferrer"
                              className="text-[9px] font-mono text-violet-400 border border-violet-800/40 bg-violet-950/20 rounded px-1.5 py-0.5 hover:opacity-80">
                              {cve} ↗
                            </a>
                          ))}
                        </div>
                        {sw.upgrade_command && (
                          <code className="text-[10px] font-mono text-emerald-400/80">{sw.upgrade_command}</code>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Remediation plan */}
                {aiResult.remediation_plan?.length > 0 && (
                  <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                    <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3">Remediation Plan</div>
                    <div className="space-y-3">
                      {aiResult.remediation_plan.map((step,i) => (
                        <div key={i} className="flex items-start gap-3">
                          <span className="w-6 h-6 rounded-lg bg-siem-bg border border-siem-border text-[10px] font-bold text-siem-accent flex items-center justify-center shrink-0 mt-0.5">{step.priority}</span>
                          <div className="flex-1">
                            <div className="text-xs text-siem-text font-medium">{step.action}</div>
                            <div className="flex gap-3 mt-1">
                              {step.effort && <span className="text-[9px] text-siem-muted">Effort: {step.effort}</span>}
                              {step.impact && <span className="text-[9px] text-siem-muted/60">{step.impact}</span>}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Compliance + positives */}
                <div className="grid grid-cols-2 gap-3">
                  {aiResult.compliance_notes && (
                    <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                      <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-2">Compliance Notes</div>
                      <p className="text-xs text-siem-muted/80">{aiResult.compliance_notes}</p>
                    </div>
                  )}
                  {aiResult.positive_findings?.length > 0 && (
                    <div className="bg-emerald-950/15 border border-emerald-800/25 rounded-xl p-4">
                      <div className="text-[10px] uppercase tracking-wider text-emerald-400/70 font-semibold mb-2">✓ Good Practices</div>
                      <ul className="space-y-1">
                        {aiResult.positive_findings.map((p,i) => (
                          <li key={i} className="flex items-start gap-2 text-xs text-siem-muted/80">
                            <CheckCircle size={11} className="text-emerald-400/60 mt-0.5 shrink-0"/>{p}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Re-run button */}
                <div className="flex justify-end pt-2">
                  <button onClick={runAIAnalysis}
                    className="flex items-center gap-2 px-3 py-1.5 text-xs text-violet-400 border border-violet-500/30 rounded-lg hover:bg-violet-500/10 transition-colors">
                    <RefreshCw size={11}/> Re-run analysis
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}


// ── Tab: Root Cause Analysis ──────────────────────────────────────────────────
function TabRCA({ agent }) {
  const [description, setDescription] = useState('')
  const [incidentAt,  setIncidentAt]  = useState(() => {
    const d = new Date(); d.setMinutes(0, 0, 0)
    return d.toISOString().slice(0, 16)
  })
  const [running,  setRunning]  = useState(false)
  const [rca,      setRca]      = useState(null)
  const [error,    setError]    = useState(null)
  const [chatInput,setChatInput]= useState('')
  const [chatHistory, setChatHistory] = useState([])
  const [chatLoading, setChatLoading] = useState(false)
  const [context,  setContext]  = useState(null)
  const [phase,    setPhase]    = useState('form') // form | loading | report
  const chatEndRef = useRef(null)

  // Load cache + context on mount
  useEffect(() => {
    api.get(`/api/v1/agents/${encodeURIComponent(agent.hostname)}/rca/cache`)
      .then(r => {
        if (r.data?.rca) {
          try {
            const clean = r.data.rca.replace(/```json\n?|```\n?/g, '').trim()
            const parsed = JSON.parse(clean)
            setRca(parsed); setPhase('report')
          } catch (e) {}
        }
      }).catch(() => {})
  }, [agent.hostname])

  const loadContext = () => {
    const iso = new Date(incidentAt).toISOString()
    api.get(`/api/v1/agents/${encodeURIComponent(agent.hostname)}/rca/context?incident_at=${encodeURIComponent(iso)}`)
      .then(r => setContext(r.data))
      .catch(() => {})
  }

  useEffect(() => { loadContext() }, [incidentAt, agent.hostname])

  const runRCA = async () => {
    if (!description.trim()) return
    setRunning(true); setError(null); setRca(null); setChatHistory([])
    setPhase('loading')
    try {
      const { data } = await api.post(
        `/api/v1/agents/${encodeURIComponent(agent.hostname)}/rca`,
        { host: agent.hostname, description, incident_at: new Date(incidentAt).toISOString() },
        { timeout: 90000 }
      )
      const text = data.content?.find(b => b.type === 'text')?.text || ''
      const clean = text.replace(/```json\n?|```\n?/g, '').trim()
      const s = clean.indexOf('{'), e = clean.lastIndexOf('}')
      const parsed = JSON.parse(s !== -1 ? clean.slice(s, e+1) : clean)
      setRca(parsed); setPhase('report')
    } catch (e) {
      setError(e.response?.data?.error || 'RCA failed'); setPhase('form')
    } finally { setRunning(false) }
  }

  const sendChat = async () => {
    const q = chatInput.trim(); if (!q || chatLoading) return
    const newHistory = [...chatHistory, { role: 'user', content: q }]
    setChatHistory(newHistory); setChatInput(''); setChatLoading(true)
    try {
      const { data } = await api.post(
        `/api/v1/agents/${encodeURIComponent(agent.hostname)}/rca`,
        { host: agent.hostname, description, incident_at: new Date(incidentAt).toISOString(),
          question: q, history: chatHistory },
        { timeout: 60000 }
      )
      const text = data.content?.find(b => b.type === 'text')?.text || ''
      setChatHistory([...newHistory, { role: 'assistant', content: text }])
    } catch (e) {
      setChatHistory([...newHistory, { role: 'assistant', content: '⚠ ' + (e.response?.data?.error || 'Failed') }])
    } finally {
      setChatLoading(false)
      setTimeout(() => chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50)
    }
  }

  const PHASE_COLORS = {
    'Initial Access':   { bg: 'bg-red-950/30',    border: 'border-red-800/40',    text: 'text-red-400',    dot: 'bg-red-400' },
    'Execution':        { bg: 'bg-orange-950/25',  border: 'border-orange-800/35', text: 'text-orange-400', dot: 'bg-orange-400' },
    'Persistence':      { bg: 'bg-yellow-950/20',  border: 'border-yellow-800/30', text: 'text-yellow-400', dot: 'bg-yellow-400' },
    'Privilege Escalation': { bg: 'bg-purple-950/25', border: 'border-purple-800/35', text: 'text-purple-400', dot: 'bg-purple-400' },
    'Defense Evasion':  { bg: 'bg-blue-950/25',    border: 'border-blue-800/35',   text: 'text-blue-400',   dot: 'bg-blue-400' },
    'Lateral Movement': { bg: 'bg-cyan-950/25',    border: 'border-cyan-800/35',   text: 'text-cyan-400',   dot: 'bg-cyan-400' },
    'Collection':       { bg: 'bg-teal-950/25',    border: 'border-teal-800/35',   text: 'text-teal-400',   dot: 'bg-teal-400' },
    'Exfiltration':     { bg: 'bg-pink-950/30',    border: 'border-pink-800/40',   text: 'text-pink-400',   dot: 'bg-pink-400' },
    'Impact':           { bg: 'bg-red-950/40',     border: 'border-red-700/50',    text: 'text-red-300',    dot: 'bg-red-300' },
  }
  const getPhaseStyle = phaseName => PHASE_COLORS[phaseName] || { bg:'bg-siem-surface', border:'border-siem-border', text:'text-siem-muted', dot:'bg-siem-muted' }

  const CONF_COLOR = { High: 'text-emerald-400', Medium: 'text-yellow-400', Low: 'text-orange-400' }

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Top bar */}
      <div className="shrink-0 px-5 py-3 border-b border-siem-border bg-siem-surface">
        <div className="flex items-center gap-3">
          <div className="flex-1">
            <div className="text-xs font-semibold text-siem-text">Root Cause Analysis</div>
            <div className="text-[10px] text-siem-muted">AI-powered incident investigation for {agent.hostname}</div>
          </div>
          {phase === 'report' && (
            <button onClick={() => { setPhase('form'); setRca(null); setChatHistory([]) }}
              className="text-[10px] text-siem-muted border border-siem-border rounded-lg px-3 py-1.5 hover:text-siem-text transition-colors">
              New RCA
            </button>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">

        {/* ── Form ── */}
        {(phase === 'form' || phase === 'loading') && (
          <div className="p-5 space-y-4">

            {/* Context preview */}
            {context && (
              <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3">
                  What will be analysed (±48h window)
                </div>
                <div className="grid grid-cols-3 gap-3">
                  {[
                    ['Alerts', context.alert_count, 'text-orange-400'],
                    ['Events', context.event_count, 'text-siem-accent'],
                    ['Vuln Scan', context.has_vuln ? 'Yes' : 'No', context.has_vuln ? 'text-emerald-400' : 'text-siem-muted'],
                  ].map(([label, val, color]) => (
                    <div key={label} className="bg-siem-bg border border-siem-border rounded-lg p-3 text-center">
                      <div className={`text-xl font-bold font-mono ${color}`}>{val}</div>
                      <div className="text-[9px] text-siem-muted uppercase tracking-wide mt-0.5">{label}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-2 text-[10px] text-siem-muted/50 text-center">
                  Events sampled: top 60 by severity, deduplicated · Vuln scan: ports & findings only, no package list
                </div>
              </div>
            )}

            {/* Incident time */}
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">
                When did the incident occur?
              </label>
              <input type="datetime-local" value={incidentAt}
                onChange={e => setIncidentAt(e.target.value)}
                className="w-full bg-siem-bg border border-siem-border rounded-xl px-4 py-2.5 text-sm text-siem-text focus:outline-none focus:border-siem-accent/50 font-mono"/>
            </div>

            {/* Description */}
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">
                Describe what you observed *
              </label>
              <textarea rows={4} value={description} onChange={e => setDescription(e.target.value)}
                disabled={phase === 'loading'}
                placeholder="e.g. Users reported the server became unresponsive at 2pm. We noticed unusual outbound traffic and several security alerts fired. A process named 'svchost.exe' was found running from an unusual path..."
                className="w-full bg-siem-bg border border-siem-border rounded-xl px-4 py-3 text-sm text-siem-text focus:outline-none focus:border-siem-accent/50 resize-none placeholder-siem-muted/30"/>
            </div>

            {error && (
              <div className="bg-red-950/20 border border-red-800/30 rounded-xl p-3 text-xs text-red-400">{error}</div>
            )}

            {phase === 'loading' ? (
              <div className="bg-siem-bg border border-siem-accent/20 rounded-xl p-5 space-y-3">
                <div className="flex items-center gap-2 mb-1">
                  <RefreshCw size={13} className="text-siem-accent animate-spin"/>
                  <span className="text-xs font-semibold text-siem-accent">Investigating incident…</span>
                </div>
                {['Gathering alerts and events', 'Correlating security signals', 'Mapping attack chain', 'Determining root cause', 'Writing RCA report'].map((msg, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-siem-accent/60 animate-pulse" style={{animationDelay:(i*400)+'ms'}}/>
                    <span className="text-[11px] text-siem-muted">{msg}…</span>
                  </div>
                ))}
              </div>
            ) : (
              <button onClick={runRCA} disabled={!description.trim()}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-500 hover:to-purple-500 disabled:opacity-40 disabled:cursor-not-allowed text-white transition-all shadow-lg shadow-violet-900/30">
                <Search size={15}/> Run Root Cause Analysis
              </button>
            )}

            {/* Privacy note */}
            <div className="bg-siem-bg border border-siem-border/50 rounded-xl p-3">
              <div className="text-[9px] text-siem-muted/60 leading-relaxed">
                <span className="text-siem-muted/80 font-medium">What's sent to AI:</span> Alert titles, event types, process names, command lines, IPs, file paths from the ±48h window.
                No file contents, no passwords, no customer data — only security metadata your SIEM already captures.
                Results are cached locally in your database and never leave your infrastructure except for the AI API call.
              </div>
            </div>
          </div>
        )}

        {/* ── Report ── */}
        {phase === 'report' && rca && (
          <div className="p-5 space-y-5">

            {/* Incident header */}
            <div className="bg-siem-surface border border-siem-border rounded-xl p-5">
              <div className="flex items-start justify-between gap-4 mb-3">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 mb-1">Root Cause Analysis Report</div>
                  <div className="text-base font-bold text-siem-text">{rca.incident_title || 'Security Incident'}</div>
                </div>
                {rca.confidence && (
                  <div className="shrink-0 text-center">
                    <div className={`text-sm font-bold ${CONF_COLOR[rca.confidence] || 'text-siem-muted'}`}>
                      {rca.confidence}
                    </div>
                    <div className="text-[9px] text-siem-muted uppercase tracking-wide">Confidence</div>
                  </div>
                )}
              </div>
              {rca.root_cause && (
                <div className="bg-siem-bg border border-siem-border rounded-lg p-3">
                  <div className="text-[9px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-1.5">Root Cause</div>
                  <p className="text-sm text-siem-text leading-relaxed font-medium">{rca.root_cause}</p>
                </div>
              )}
              {rca.confidence_reason && (
                <p className="text-[11px] text-siem-muted mt-2 leading-relaxed">{rca.confidence_reason}</p>
              )}
            </div>

            {/* Executive Summary */}
            {rca.executive_summary && (
              <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-2 flex items-center gap-1.5">
                  <Shield size={11}/> Executive Summary
                </div>
                <p className="text-sm text-siem-text leading-relaxed">{rca.executive_summary}</p>
              </div>
            )}

            {/* Attack chain — visual flow */}
            {rca.attack_chain?.length > 0 && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3">Attack Chain</div>
                <div className="space-y-2">
                  {rca.attack_chain.map((step, i) => {
                    const st = getPhaseStyle(step.phase)
                    return (
                      <div key={i} className="flex items-stretch gap-3">
                        {/* Connector */}
                        <div className="flex flex-col items-center shrink-0 w-8">
                          <div className={`w-7 h-7 rounded-full flex items-center justify-center border text-[9px] font-bold ${st.bg} ${st.border} ${st.text}`}>
                            {i + 1}
                          </div>
                          {i < rca.attack_chain.length - 1 && (
                            <div className="w-px flex-1 bg-siem-border/40 mt-1"/>
                          )}
                        </div>
                        {/* Card */}
                        <div className={`flex-1 rounded-xl border p-3 mb-1 ${st.bg} ${st.border}`}>
                          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                            <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${st.bg} ${st.border} ${st.text}`}>
                              {step.phase}
                            </span>
                            {step.mitre && (
                              <a href={`https://attack.mitre.org/techniques/${step.mitre.replace('.','/')}`}
                                target="_blank" rel="noreferrer"
                                className="text-[9px] font-mono text-violet-400 border border-violet-800/40 bg-violet-950/20 rounded px-1.5 py-0.5 hover:opacity-80">
                                {step.mitre} ↗
                              </a>
                            )}
                          </div>
                          <div className={`text-xs font-semibold mb-1 ${st.text}`}>{step.technique}</div>
                          {step.description && (
                            <div className="text-[11px] text-siem-text/80 leading-relaxed mb-1.5">{step.description}</div>
                          )}
                          {step.evidence && (
                            <div className="text-[10px] text-siem-muted/80 leading-snug italic border-l-2 border-siem-border/50 pl-2">Evidence: {step.evidence}</div>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Timeline */}
            {rca.timeline?.length > 0 && (
              <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3 flex items-center gap-2">
                  <Clock size={11}/> Incident Timeline
                </div>
                <div className="space-y-2">
                  {rca.timeline.map((t, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <div className="flex flex-col items-center shrink-0">
                        <span className="text-[9px] font-mono text-siem-accent bg-siem-accent/10 border border-siem-accent/20 rounded px-2 py-0.5 whitespace-nowrap">{t.time}</span>
                        {i < rca.timeline.length - 1 && <div className="w-px h-3 bg-siem-border/30 mt-1"/>}
                      </div>
                      <div className="flex-1 pb-1">
                        <div className="text-xs text-siem-text">{t.event}</div>
                        {t.significance && <div className="text-[10px] text-siem-muted/60 mt-0.5">{t.significance}</div>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Key indicators */}
            {rca.key_indicators?.length > 0 && (
              <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                <div className="px-4 py-2.5 border-b border-siem-border/40 text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold flex items-center gap-2">
                  <Activity size={11}/> Key Indicators of Compromise
                </div>
                {rca.key_indicators.map((ioc, i) => (
                  <div key={i} className={`px-4 py-2.5 border-b border-siem-border/20 last:border-0 ${i%2?'bg-white/[0.01]':''}`}>
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[9px] uppercase font-semibold text-siem-accent bg-siem-accent/10 border border-siem-accent/20 rounded px-1.5 py-0.5">{ioc.type}</span>
                      <code className="text-[11px] font-mono text-siem-text break-all">{ioc.indicator}</code>
                    </div>
                    {ioc.significance && <div className="text-[10px] text-siem-muted/60 pl-14">{ioc.significance}</div>}
                  </div>
                ))}
              </div>
            )}

            {/* Impact */}
            {rca.impact_assessment && (
              <div className="bg-red-950/15 border border-red-800/25 rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-red-400/70 font-semibold mb-3 flex items-center gap-2">
                  <AlertTriangle size={11}/> Impact Assessment
                </div>
                <div className="space-y-2">
                  {rca.impact_assessment.systems_affected?.length > 0 && (
                    <div>
                      <div className="text-[9px] text-siem-muted/60 uppercase mb-1">Systems Affected</div>
                      <div className="flex gap-1.5 flex-wrap">
                        {rca.impact_assessment.systems_affected.map((s,i) => (
                          <span key={i} className="text-[10px] font-mono bg-red-950/20 border border-red-800/30 text-red-300 rounded px-2 py-0.5">{s}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {rca.impact_assessment.data_at_risk && (
                    <div>
                      <div className="text-[9px] text-siem-muted/60 uppercase mb-0.5">Data at Risk</div>
                      <p className="text-xs text-siem-text">{rca.impact_assessment.data_at_risk}</p>
                    </div>
                  )}
                  {rca.impact_assessment.business_impact && (
                    <div>
                      <div className="text-[9px] text-siem-muted/60 uppercase mb-0.5">Business Impact</div>
                      <p className="text-xs text-siem-text">{rca.impact_assessment.business_impact}</p>
                    </div>
                  )}
                  {rca.impact_assessment.severity && (
                    <div className="flex items-center gap-2 mt-1">
                      <div className="text-[9px] text-siem-muted/60 uppercase">Severity:</div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                        rca.impact_assessment.severity === 'Critical' ? 'bg-red-900/40 border-red-700 text-red-300' :
                        rca.impact_assessment.severity === 'High' ? 'bg-orange-900/30 border-orange-700 text-orange-300' :
                        'bg-yellow-900/20 border-yellow-700 text-yellow-300'
                      }`}>{rca.impact_assessment.severity}</span>
                      {rca.impact_assessment.severity_rationale && (
                        <span className="text-[10px] text-siem-muted/60">— {rca.impact_assessment.severity_rationale}</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Contributing factors */}
            {rca.contributing_factors?.length > 0 && (
              <div className="bg-yellow-950/15 border border-yellow-800/25 rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-yellow-400/70 font-semibold mb-2">Contributing Factors</div>
                <ul className="space-y-1.5">
                  {rca.contributing_factors.map((f,i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-siem-text">
                      <span className="text-yellow-400/60 shrink-0 mt-0.5">▸</span>{f}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Remediation */}
            {rca.remediation && (
              <div className="bg-emerald-950/10 border border-emerald-800/20 rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-emerald-400/70 font-semibold mb-3 flex items-center gap-2">
                  <CheckCircle size={11}/> Remediation Plan
                </div>
                {[
                  ['Immediate (now)', rca.remediation.immediate, 'text-red-400'],
                  ['Short-term (24-48h)', rca.remediation.short_term, 'text-yellow-400'],
                  ['Long-term (systemic)', rca.remediation.long_term, 'text-emerald-400'],
                ].map(([label, items, color]) => items?.length > 0 && (
                  <div key={label} className="mb-3 last:mb-0">
                    <div className={`text-[9px] uppercase font-semibold mb-1.5 ${color}`}>{label}</div>
                    <ul className="space-y-1">
                      {items.map((a,i) => (
                        <li key={i} className="flex items-start gap-2 text-xs text-siem-text">
                          <span className="w-4 h-4 rounded bg-siem-bg border border-siem-border text-[8px] font-bold text-siem-muted flex items-center justify-center shrink-0 mt-0.5">{i+1}</span>
                          {a}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            )}

            {/* Detection gaps */}
            {rca.detection_gaps?.length > 0 && (
              <div className="bg-blue-950/15 border border-blue-800/25 rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-blue-400/70 font-semibold mb-2 flex items-center gap-1.5">
                  <Search size={11}/> Detection Gaps
                </div>
                <ul className="space-y-1.5">
                  {rca.detection_gaps.map((g,i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-siem-text">
                      <span className="text-blue-400/60 shrink-0 mt-0.5">⚡</span>{g}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Lessons learned */}
            {rca.lessons_learned?.length > 0 && (
              <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-2">Lessons Learned</div>
                <ul className="space-y-1.5">
                  {rca.lessons_learned.map((l,i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-siem-muted">
                      <span className="text-siem-accent shrink-0 mt-0.5">→</span>{l}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* AI questions */}
            {rca.questions_for_analyst?.length > 0 && (
              <div className="bg-violet-950/15 border border-violet-800/25 rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-violet-400/70 font-semibold mb-2">AI Questions for You</div>
                <ul className="space-y-2">
                  {rca.questions_for_analyst.map((q,i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-[10px] text-violet-400/60 shrink-0 mt-0.5">?</span>
                      <button onClick={() => setChatInput(q)}
                        className="text-xs text-siem-text text-left hover:text-violet-400 transition-colors leading-relaxed">
                        {q}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Chat with AI about this RCA */}
            <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-siem-border/40 flex items-center gap-2">
                <MessageSquare size={13} className="text-siem-accent"/>
                <span className="text-sm font-semibold text-siem-text">Continue Investigation</span>
                <span className="text-[10px] text-siem-muted ml-1">— ask follow-up questions about this incident</span>
              </div>

              {/* Suggested questions */}
              {chatHistory.length === 0 && rca.questions_for_analyst?.length > 0 && (
                <div className="px-4 py-3 border-b border-siem-border/30 flex flex-wrap gap-2">
                  {rca.questions_for_analyst.slice(0, 3).map((q, i) => (
                    <button key={i} onClick={() => setChatInput(q)}
                      className="text-[10px] text-left px-2.5 py-1.5 bg-violet-950/20 border border-violet-800/30 text-violet-300 rounded-lg hover:bg-violet-950/40 transition-colors max-w-xs truncate">
                      💡 {q}
                    </button>
                  ))}
                </div>
              )}

              {/* Messages */}
              <div className="p-4 space-y-4 max-h-[500px] overflow-y-auto">
                {chatHistory.length === 0 ? (
                  <div className="text-sm text-siem-muted/40 italic text-center py-4">
                    Ask anything about this incident — what happened, why, how to respond…
                  </div>
                ) : chatHistory.map((msg, i) => (
                  <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
                    {/* Avatar */}
                    <div className={`w-7 h-7 rounded-full flex items-center justify-center shrink-0 text-[10px] font-bold border ${
                      msg.role === 'user'
                        ? 'bg-violet-950/30 border-violet-800/50 text-violet-300'
                        : 'bg-siem-accent/10 border-siem-accent/30 text-siem-accent'
                    }`}>
                      {msg.role === 'user' ? 'You' : 'AI'}
                    </div>
                    {/* Message bubble */}
                    <div className={`flex-1 rounded-xl px-4 py-3 ${
                      msg.role === 'user'
                        ? 'bg-violet-950/15 border border-violet-800/25 text-siem-text'
                        : 'bg-siem-bg border border-siem-border/60'
                    }`}>
                      {msg.role === 'assistant' ? (
                        // Render AI response with basic markdown-like formatting
                        <div className="space-y-2">
                          {msg.content.split('\n\n').filter(Boolean).map((para, pi) => (
                            <p key={pi} className="text-sm text-siem-text leading-relaxed">
                              {para.split('\n').map((line, li) => (
                                <span key={li}>
                                  {li > 0 && <br/>}
                                  {line}
                                </span>
                              ))}
                            </p>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-siem-text leading-relaxed">{msg.content}</p>
                      )}
                    </div>
                  </div>
                ))}
                {chatLoading && (
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-siem-accent/10 border border-siem-accent/30 flex items-center justify-center text-[10px] font-bold text-siem-accent shrink-0">AI</div>
                    <div className="flex-1 bg-siem-bg border border-siem-border/60 rounded-xl px-4 py-3">
                      <div className="flex gap-1.5 items-center h-5">
                        {[0,1,2].map(i => (
                          <div key={i} className="w-2 h-2 rounded-full bg-siem-accent/60 animate-bounce"
                            style={{animationDelay:(i*150)+'ms'}}/>
                        ))}
                        <span className="text-[10px] text-siem-muted ml-1">Analysing…</span>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={chatEndRef}/>
              </div>

              <div className="border-t border-siem-border p-3 flex gap-2 items-end">
                <input value={chatInput} onChange={e => setChatInput(e.target.value)}
                  onKeyDown={e => { if (e.key==='Enter' && !e.shiftKey) { e.preventDefault(); sendChat() }}}
                  placeholder="Ask anything about this incident… (Enter to send)"
                  className="flex-1 bg-siem-bg border border-siem-border rounded-xl px-4 py-2.5 text-sm text-siem-text placeholder-siem-muted/30 outline-none focus:border-siem-accent/60 transition-colors"
                  disabled={chatLoading}/>
                <button onClick={sendChat} disabled={!chatInput.trim() || chatLoading}
                  className="px-4 py-2.5 bg-siem-accent text-white text-sm font-medium rounded-xl hover:bg-siem-accent/80 disabled:opacity-40 transition-colors shrink-0">
                  {chatLoading ? '…' : 'Send'}
                </button>
              </div>
            </div>

          </div>
        )}
      </div>
    </div>
  )
}


const DETAIL_TABS=[
  {id:'overview', label:'Overview',  icon:LayoutDashboard},
  {id:'events',   label:'Events',    icon:Activity},
  {id:'threats',  label:'Threats',   icon:GitBranch},
  {id:'alerts',   label:'Alerts',    icon:Zap},
  {id:'logons',   label:'Logons',    icon:LogIn},
  {id:'network',  label:'Network',   icon:Wifi},
  {id:'dns',      label:'DNS',       icon:GlobeIcon},
  {id:'files',    label:'Files',     icon:FolderOpen},
  {id:'device',   label:'Device',    icon:Cpu},
  {id:'location', label:'Location',  icon:MapPin},
  {id:'terminal',     label:'Terminal',     icon:Terminal},
  {id:'vulnerability', label:'Vulnerability', icon:Bug},
  {id:'rca',           label:'RCA',           icon:Search},
]

function AgentDetail({ agent, onBack }) {
  const [activeTab,setActiveTab]=useState('overview')
  const [tamperOpen,setTamperOpen]=useState(false)
  const [agentData,setAgentData]=useState(agent)
  const osStyle=OS_GROUPS[getOSCategory(agent.os)]||OS_GROUPS.other
  const Icon=osStyle.icon
  const reload=async()=>{try{const{data}=await api.get('/api/v1/agents');const found=(data.agents||[]).find(a=>a.id===agent.id);if(found)setAgentData(found)}catch(e){}}
  const fullHeight=['events','threats','location','logons','network','dns','files','terminal','vulnerability','rca'].includes(activeTab)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {tamperOpen&&<TamperPanel agent={agentData} onClose={()=>setTamperOpen(false)} onUpdated={reload}/>}
      <div className="px-5 pt-4 pb-0 border-b border-siem-border shrink-0">
        <button onClick={onBack} className="flex items-center gap-1.5 text-xs text-siem-muted hover:text-siem-text mb-3 transition-colors"><ChevronRight size={11} className="rotate-180"/> Back to fleet</button>
        <div className="flex items-center gap-3 mb-3">
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center border ${osStyle.border} ${osStyle.bg}`}><Icon size={15} className={osStyle.color}/></div>
          <div>
            <h2 className="text-lg font-bold text-siem-text">{agentData.hostname}</h2>
            <div className="flex items-center gap-2 mt-0.5">
              <span className={`text-[9px] px-2 py-0.5 rounded-full border font-medium ${agentData.online?'bg-emerald-900/30 text-emerald-400 border-emerald-800':'bg-siem-bg text-siem-muted border-siem-border'}`}>{agentData.online?'Online':'Offline'}</span>
              <span className="text-[10px] text-siem-muted">{agentData.os}</span>
              <span className="text-[10px] text-siem-muted">{agentData.last_ip}</span>
              <button onClick={()=>setTamperOpen(true)} className="ml-2 flex items-center gap-1 text-[9px] text-siem-muted hover:text-siem-text transition-colors">
                {agentData.tamper_locked?<Shield size={11} className="text-emerald-400"/>:<ShieldOff size={11}/>}
                {agentData.tamper_locked?'Protected':'Unprotected'}
              </button>
            </div>
          </div>
        </div>
        <div className="flex gap-0 overflow-x-auto">
          {DETAIL_TABS.map(({id,label,icon:TabIcon})=>(
            <button key={id} onClick={()=>setActiveTab(id)} className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium transition-colors border-b-2 whitespace-nowrap ${activeTab===id?'border-siem-accent text-siem-accent':'border-transparent text-siem-muted hover:text-siem-text'}`}>
              <TabIcon size={12}/>{label}
            </button>
          ))}
        </div>
      </div>
      <div className={`flex-1 ${fullHeight?'overflow-hidden':'overflow-y-auto'}`}>
        {activeTab==='overview' &&<TabOverview  agent={agentData}/>}
        {activeTab==='events'   &&<TabEvents    agent={agentData}/>}
        {activeTab==='threats'  &&<TabThreats   agent={agentData}/>}
        {activeTab==='alerts'   &&<TabAlerts    agent={agentData}/>}
        {activeTab==='logons'   &&<TabLogons    agent={agentData}/>}
        {activeTab==='network'  &&<TabNetwork   agent={agentData}/>}
        {activeTab==='dns'      &&<TabDNS       agent={agentData}/>}
        {activeTab==='files'    &&<TabFiles     agent={agentData}/>}
        {activeTab==='device'   &&<TabDevice    agent={agentData}/>}
        {activeTab==='location' &&<TabLocation  agent={agentData}/>}
        {activeTab==='terminal'     &&<TabTerminal  agent={agentData}/>}
        {activeTab==='vulnerability' &&<TabVuln      agent={agentData}/>}
        {activeTab==='rca'           &&<TabRCA       agent={agentData}/>}
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Agents() {
  const [searchParams,setSearchParams]=useSearchParams()
  const [agents,setAgents]=useState([])
  const [loading,setLoading]=useState(true)
  const [tamperAgent,setTamperAgent]=useState(null)
  const [search,setSearch]=useState('')
  const hostParam=searchParams.get('host')

  const load=async()=>{setLoading(true);try{const{data}=await api.get('/api/v1/agents');setAgents(data.agents||[])}finally{setLoading(false)}}
  useEffect(()=>{load();const id=setInterval(load,15000);return()=>clearInterval(id)},[])

  const selectedAgent=hostParam?agents.find(a=>a.hostname===hostParam):null

  if(selectedAgent) return <div className="flex flex-col h-screen overflow-hidden bg-siem-bg"><AgentDetail agent={selectedAgent} onBack={()=>setSearchParams({})}/></div>

  const filtered=agents.filter(a=>!search||a.hostname?.toLowerCase().includes(search.toLowerCase())||a.last_ip?.includes(search)||a.os?.toLowerCase().includes(search.toLowerCase()))
  const byCategory=filtered.reduce((m,a)=>{const cat=getOSCategory(a.os);if(!m[cat])m[cat]=[];m[cat].push(a);return m},{})
  const categoryOrder=['windows','linux','macos','other']
  const online=agents.filter(a=>a.online).length

  return (
    <div className="p-5 space-y-5">
      {tamperAgent&&<TamperPanel agent={tamperAgent} onClose={()=>{setTamperAgent(null);load()}} onUpdated={load}/>}
      <div className="flex items-center justify-between">
        <div><h1 className="text-xl font-bold text-siem-text">Agent Fleet</h1><p className="text-[10px] text-siem-muted mt-0.5">Click any agent to open the detail view</p></div>
        <button onClick={load} className="flex items-center gap-1.5 text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-1.5"><RefreshCw size={12}/> Refresh</button>
      </div>
      <div className="flex gap-3 flex-wrap">
        {[{label:'Total',value:agents.length},{label:'Online',value:online,color:'text-emerald-400'},{label:'Offline',value:agents.length-online,color:'text-siem-muted'},{label:'Protected',value:agents.filter(a=>a.tamper_locked).length,color:'text-blue-400'}].map(({label,value,color})=>(
          <div key={label} className="bg-siem-surface border border-siem-border rounded-xl px-4 py-3"><div className={`text-xl font-bold font-mono ${color||'text-siem-text'}`}>{value}</div><div className="text-[9px] text-siem-muted uppercase tracking-wider">{label}</div></div>
        ))}
      </div>
      <div className="relative max-w-sm">
        <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-siem-muted"/>
        <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search hostname, IP, OS…" className="w-full bg-siem-surface border border-siem-border rounded-lg pl-8 pr-3 py-2 text-sm text-siem-text placeholder-siem-muted/40 outline-none focus:border-siem-accent/50"/>
        {search&&<button onClick={()=>setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2"><X size={11} className="text-siem-muted"/></button>}
      </div>
      {loading?<div className="text-center py-16 text-siem-muted">Loading agents…</div>:(
        <div className="space-y-4">
          {categoryOrder.filter(cat=>byCategory[cat]?.length>0).map(cat=>(
            <OSGroup key={cat} category={cat} agents={byCategory[cat]} onViewTamper={a=>setTamperAgent(a)} onSelectHost={a=>setSearchParams({host:a.hostname})}/>
          ))}
        </div>
      )}
    </div>
  )
}
