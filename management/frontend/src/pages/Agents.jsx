import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Wifi, Shield, ShieldOff, ShieldCheck, ChevronRight, X, RefreshCw, Search, Activity, GitBranch, LayoutDashboard, Cpu, MapPin, Zap, Globe as GlobeIcon, Bug, LogIn, FolderOpen, Terminal } from 'lucide-react'
import api from '../api/client'
import { OS_GROUPS, getOSCategory } from './agents/shared.jsx'
import { TabAlerts, TabDNS, TabEvents, TabFiles, TabLogons, TabNetwork, TabOverview, TabThreats } from './agents/tabs_basic.jsx'
import { TabDevice, TabLocation, TabTerminal } from './agents/tabs_device.jsx'
import { TabRCA, TabVuln } from './agents/tabs_vuln.jsx'
import { TabCompliance } from './agents/tabs_compliance.jsx'
import { OSGroup, TamperPanel } from './agents/tamper.jsx'

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
  {id:'compliance', label:'Compliance', icon:ShieldCheck},
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
  const fullHeight=['events','threats','location','logons','network','dns','files','terminal','vulnerability','rca','compliance'].includes(activeTab)

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
        {activeTab==='compliance'&&<TabCompliance agent={agentData}/>}
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

