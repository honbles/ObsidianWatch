import { IPLink } from '../../components/IPLookup'
import { useEffect, useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Check, ChevronRight, X, Unlock, AlertTriangle, RefreshCw, Search, Activity, GitBranch, Cpu, Zap, User, Tag, FolderOpen, Bookmark, Maximize2 } from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import api from '../../api/client'
import AlertPanelPortal from '../../components/AlertPanel'
import { SeverityBadge } from '../../components/SeverityBadge'
import { GraphCanvas, NodeDetail } from './graph.jsx'
import { EVENT_TYPE_META, SEV_LABEL, TAG_COLORS, VTHashBadge } from './shared.jsx'
import { AgentSavedSearchPanel } from './tamper.jsx'

export function TabOverview({ agent }) {
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

export function EventPanel({ event, onClose }) {
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
          {ev.dst_ip&&<div><div className="text-siem-muted mb-0.5">Destination</div><div className="font-mono text-blue-400"><IPLink ip={ev.dst_ip}/>{ev.dst_port?`:${ev.dst_port}`:''}</div></div>}
          {ev.file_path&&<div><div className="text-siem-muted mb-0.5">File path</div><div className="font-mono text-yellow-400 break-all">{ev.file_path}</div></div>}
          {ev.reg_key&&<div><div className="text-siem-muted mb-0.5">Registry key</div><div className="font-mono text-purple-400 break-all">{ev.reg_key}</div></div>}
          {raw&&Object.keys(raw).length>0&&<div><div className="text-siem-muted mb-1">Raw data</div><pre className="bg-siem-bg border border-siem-border rounded p-2 text-[9px] text-siem-muted overflow-x-auto whitespace-pre-wrap">{JSON.stringify(raw,null,2)}</pre></div>}
          {detail?.related?.length>0&&<div><div className="text-siem-muted mb-2 font-semibold uppercase tracking-wider text-[9px]">Related events (±5 min)</div><div className="space-y-1">{detail.related.map((r,i)=><div key={i} className="flex items-center gap-2 text-[10px] bg-siem-bg rounded px-2 py-1.5"><span className="text-siem-muted font-mono">{format(new Date(r.time),'HH:mm:ss')}</span><span className={EVENT_TYPE_META[r.event_type]?.color||'text-siem-muted'}>{r.event_type}</span><span className="text-siem-muted truncate flex-1">{r.process_name||r.dst_ip||r.user_name||'—'}</span></div>)}</div></div>}
        </div>
      </div>
    </div>
  )
}

export function TabEvents({ agent }) {
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

export function TabThreats({ agent }) {
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

export function TabLogons({ agent }) {
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

export function TabNetwork({ agent }) {
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

export function TabDNS({ agent }) {
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
        </>)}
      </div>
    </div>
  )
}

// ── Tab: Files ────────────────────────────────────────────────────────────────

// ── VT Hash Badge ─────────────────────────────────────────────────────────────

export function TabFiles({ agent }) {
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

export function TabAlerts({ agent }) {
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

