import React from 'react'
import { cveHref } from '../../utils/safeHref'
import { useEffect, useState } from 'react'
import { Monitor, Server, Apple, Globe, ChevronRight } from 'lucide-react'
import * as d3 from 'd3'
import api from '../../api/client'
import { GraphCanvas } from './graph.jsx'
import { TamperPanel } from './tamper.jsx'

export function getOSCategory(os) {
  if (!os) return 'other'
  const l = os.toLowerCase()
  if (l.includes('win')) return 'windows'
  if (l.includes('linux') || l.includes('ubuntu') || l.includes('debian') || l.includes('centos') || l.includes('rhel')) return 'linux'
  if (l.includes('mac') || l.includes('darwin')) return 'macos'
  return 'other'
}

export const OS_GROUPS = {
  windows: { label: 'Windows',  icon: Monitor, color: 'text-blue-400',   border: 'border-blue-800',   bg: 'bg-blue-950/20' },
  linux:   { label: 'Linux',    icon: Server,  color: 'text-orange-400', border: 'border-orange-800', bg: 'bg-orange-950/20' },
  macos:   { label: 'macOS',    icon: Apple,   color: 'text-purple-400', border: 'border-purple-800', bg: 'bg-purple-950/20' },
  other:   { label: 'Other',    icon: Globe,   color: 'text-siem-muted', border: 'border-siem-border',bg: 'bg-siem-bg' },
}

// ── Graph constants ───────────────────────────────────────────────────────────

export const NODE_COLORS = { host:'#00d4ff', process:'#6366f1', dns:'#06b6d4', ip:'#ef4444', file:'#f59e0b', registry:'#a855f7', logon:'#10b981', cloud_account:'#f97316', identity:'#ec4899', api_call:'#84cc16', resource:'#14b8a6', device:'#3b82f6', external_ip:'#ef4444', unknown_device:'#6b7280' }

export const NODE_SHAPES = { host:'diamond', process:'circle', dns:'circle', ip:'square', file:'triangle', registry:'square', logon:'circle', cloud_account:'diamond', identity:'circle', api_call:'hexagon', resource:'square', device:'diamond', external_ip:'square', unknown_device:'circle' }

export const EDGE_COLORS = { spawned:'#94a3b8', runs:'#64748b', connected:'#3b82f6', queried:'#06b6d4', wrote:'#f59e0b', created:'#22c55e', deleted:'#ef4444', modified:'#f97316', executed:'#a855f7', lateral:'#dc2626', auth:'#10b981', called:'#84cc16', accessed:'#14b8a6', from_ip:'#64748b', contains:'#475569' }

export const SEV_COLORS = { 5:'#ef4444', 4:'#f97316', 3:'#eab308', 2:'#3b82f6', 1:'#475569' }

export const SEV_LABEL  = { 5:'Critical', 4:'High', 3:'Medium', 2:'Low', 1:'Info' }

export const SEV_DOT    = { 5:'#ef4444', 4:'#f97316', 3:'#eab308', 2:'#3b82f6', 1:'#475569' }

export const TYPE_COLOR = { registry:'#a855f7', dns:'#06b6d4', network:'#3b82f6', process:'#8b949e', file:'#eab308', logon:'#22c55e' }

export const CAT_COLOR  = { malware:'#ef4444', botnet_cc:'#ef4444', phishing:'#f97316', malicious:'#f97316', spam:'#eab308' }

// ── Graph helpers ─────────────────────────────────────────────────────────────

export function nodeRadius(d) { return (d.type==='host'||d.type==='device'||d.type==='cloud_account'?18:10) + Math.min(Math.sqrt(d.event_count||1)*2,12) }

export function drawNodeShape(el, shape, r, color, opacity, sev) {
  const sc=SEV_COLORS[sev]||'#475569', sw=sev>=3?2:1
  switch(shape) {
    case 'diamond': el.append('polygon').attr('points',`0,${-r} ${r},0 0,${r} ${-r},0`).attr('fill',color).attr('opacity',opacity).attr('stroke',sc).attr('stroke-width',sw); break
    case 'square':  el.append('rect').attr('x',-r).attr('y',-r).attr('width',r*2).attr('height',r*2).attr('rx',3).attr('fill',color).attr('opacity',opacity).attr('stroke',sc).attr('stroke-width',sw); break
    case 'triangle': el.append('polygon').attr('points',`0,${-r} ${r*.87},${r*.5} ${-r*.87},${r*.5}`).attr('fill',color).attr('opacity',opacity).attr('stroke',sc).attr('stroke-width',sw); break
    case 'hexagon': { const pts=d3.range(6).map(i=>{const a=(i*Math.PI)/3-Math.PI/6;return `${r*Math.cos(a)},${r*Math.sin(a)}`}).join(' '); el.append('polygon').attr('points',pts).attr('fill',color).attr('opacity',opacity).attr('stroke',sc).attr('stroke-width',sw); break }
    default: el.append('circle').attr('r',r).attr('fill',color).attr('opacity',opacity).attr('stroke',sc).attr('stroke-width',sw)
  }
}

export function trunc(s,n) { return s?.length>n ? s.slice(0,n-1)+'…' : (s||'') }

// ── GraphCanvas ───────────────────────────────────────────────────────────────

export function RankBar({ rows, keyField, valueField, colorFn, onDrilldown, selectedKey }) {
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

export function IntelSection({ title, icon: Icon, color='text-siem-accent', children, count, badge, defaultOpen=true }) {
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

export const EVENT_TYPE_META = {
  process:  {label:'Process',  color:'text-indigo-400'},
  network:  {label:'Network',  color:'text-blue-400'},
  dns:      {label:'DNS',      color:'text-cyan-400'},
  logon:    {label:'Logon',    color:'text-emerald-400'},
  file:     {label:'File',     color:'text-yellow-400'},
  registry: {label:'Registry', color:'text-purple-400'},
  sysmon:   {label:'Sysmon',   color:'text-pink-400'},
  health:   {label:'Health',   color:'text-teal-400'},
}

export const TAG_COLORS = {
  event_type:'bg-purple-900/40 text-purple-300 border-purple-800/60',
  severity:  'bg-orange-900/40 text-orange-300 border-orange-800/60',
  os:        'bg-blue-900/40 text-blue-300 border-blue-800/60',
  search:    'bg-siem-bg text-siem-text border-siem-border',
  src_or_dst_ip:'bg-red-900/40 text-red-300 border-red-800/60',
  dst_port:  'bg-cyan-900/40 text-cyan-300 border-cyan-800/60',
}

export const GROUP_ICONS_MAP = { Windows: Monitor, Linux: Server, macOS: Apple }

export function MiniTable({ cols, rows, empty='No data', onRowClick }) {
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

export function VTHashBadge({ hash }) {
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

// ── Tab: Vulnerability Scan ───────────────────────────────────────────────────
export function PortRow({ port, st, forceExpand }) {
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

export function FindingCard({ f, SEV }) {
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

export function AIFindingCard({ finding, type: cardType }) {
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
            <a key={cve} href={cveHref(cve)} target="_blank" rel="noreferrer"
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

