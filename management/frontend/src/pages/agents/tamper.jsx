import { useState } from 'react'
import { Wifi, WifiOff, Shield, ShieldOff, ShieldAlert, Key, Copy, Check, ChevronRight, X, Lock, Unlock, Globe as GlobeIcon } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api from '../../api/client'
import { SAVED_SEARCHES } from '../../pages/Events'
import { GROUP_ICONS_MAP, OS_GROUPS } from './shared.jsx'

export function TamperPanel({ agent, onClose, onUpdated }) {
  const [copied,setCopied]=useState(false), [toggling,setToggling]=useState(false)
  // F-03: keys are stored hashed; a key is only visible right after regeneration.
  const [newKey,setNewKey]=useState(''), [regen,setRegen]=useState(false)
  const copy=()=>{navigator.clipboard.writeText(newKey||'');setCopied(true);setTimeout(()=>setCopied(false),2000)}
  const regenerate=async()=>{
    if(!window.confirm('Generate a new install key? The previous key stops working immediately. The new key is shown only once.'))return
    setRegen(true)
    try{const r=await api.post(`/api/v1/agents/${agent.id}/regen-key`,{});setNewKey(r?.data?.install_key||r?.install_key||'');onUpdated&&onUpdated()}finally{setRegen(false)}
  }
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
              <code className="text-emerald-300 font-mono text-sm flex-1 truncate">{newKey||(agent.has_install_key?'•••••••• (stored hashed)':'Not yet set')}</code>
              {newKey&&<button onClick={copy} className="shrink-0 p-1.5 rounded border border-siem-border hover:border-siem-accent/40 text-siem-muted hover:text-siem-text">{copied?<Check size={13} className="text-emerald-400"/>:<Copy size={13}/>}</button>}
              <button onClick={regenerate} disabled={regen} className="shrink-0 text-[10px] px-2 py-1 rounded border border-siem-border text-siem-muted hover:text-siem-text">{regen?'…':'Regenerate'}</button>
            </div>
            {newKey&&<div className="text-[10px] text-amber-400 mt-1">Copy this key now — it will not be shown again.</div>}
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

export function OSGroup({ category, agents, onViewTamper, onSelectHost }) {
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

export function AgentSavedSearchPanel({ onSelect, onClose }) {
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

