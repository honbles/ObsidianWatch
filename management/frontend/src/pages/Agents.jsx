import { useEffect, useMemo, useState } from 'react'
import { useDragSize } from '../hooks/useDragSize'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { Wifi, Shield, ShieldOff, ShieldCheck, ChevronRight, X, RefreshCw, Search, Activity, GitBranch, LayoutDashboard, Cpu, MapPin, Zap, Globe as GlobeIcon, Bug, LogIn, FolderOpen, Terminal, ShieldAlert, Download } from 'lucide-react'
import api from '../api/client'
import { getOSCategory } from './agents/shared.jsx'
import { isProbe, alertsByHost } from '../utils/states'
import { PageHeader, Num, Tabs, StatePill, SevPill, Facets, countBy, useFacetFilter, DenseTable, parseFilter, relTime, downloadCSV, useSelection, SelectionBar, Dialog, Field } from '../components/ui'
import { TabAlerts, TabDNS, TabEvents, TabFiles, TabLogons, TabNetwork, TabOverview, TabThreats } from './agents/tabs_basic.jsx'
import { TabDevice, TabLocation, TabTerminal } from './agents/tabs_device.jsx'
import { TabRCA, TabVuln } from './agents/tabs_vuln.jsx'
import { TabCompliance } from './agents/tabs_compliance.jsx'
import { TamperPanel } from './agents/tamper.jsx'
import { TabResponse, IsolatedBadge, useResponseState, isAdminUser } from '../components/ResponseActions.jsx'

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
  {id:'response',     label:'Response',     icon:ShieldAlert},
  {id:'vulnerability', label:'Vulnerability', icon:Bug},
  {id:'rca',           label:'RCA',           icon:Search},
]

// Same fifteen views as before, grouped into a left rail so all of them stay one click away.
const TAB_GROUPS=[
  {label:'Summary',      ids:['overview']},
  {label:'Activity',     ids:['events','threats','alerts','logons','network','dns','files']},
  {label:'Endpoint',     ids:['device','location','compliance','vulnerability']},
  {label:'Investigate',  ids:['rca','terminal','response']},
]

function AgentDetail({ agent, onBack }) {
  const [searchP,setSearchP]=useSearchParams()
  const tabParam=searchP.get('tab')
  const activeTab=DETAIL_TABS.some(t=>t.id===tabParam)?tabParam:'overview'
  const setActiveTab=(id)=>{const n=new URLSearchParams(searchP);if(id==='overview')n.delete('tab');else n.set('tab',id);setSearchP(n,{replace:true})}
  const [railW,railHandle]=useDragSize('agent_rail',160,120,280,'x')
  const [tamperOpen,setTamperOpen]=useState(false)
  const [agentData,setAgentData]=useState(agent)
  const [respState]=useResponseState(agent.id)
  const reload=async()=>{try{const{data}=await api.get('/api/v1/agents');const found=(data.agents||[]).find(a=>a.id===agent.id);if(found)setAgentData(found)}catch(e){}}
  const fullHeight=['events','threats','location','logons','network','dns','files','terminal','vulnerability','rca','compliance','response'].includes(activeTab)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {tamperOpen&&<TamperPanel agent={agentData} onClose={()=>setTamperOpen(false)} onUpdated={reload}/>}
      <header className="ow-head notabs" style={{ flexShrink: 0, paddingBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              <h1 className="mono">{agentData.hostname}</h1>
              <StatePill state={agentData.online ? 'ok' : 'none'}>{agentData.online ? 'Online' : 'Offline'}</StatePill>
              <IsolatedBadge state={respState}/>
            </div>
            <div className="ow-sub">
              {agentData.os} · <span className="mono">{agentData.last_ip || 'no IP'}</span> · agent <span className="mono">{agentData.version || '?'}</span> · last seen {relTime(agentData.last_seen)}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="ow-btn quiet" onClick={onBack}>Back to fleet</button>
            <button className="ow-btn" onClick={()=>setTamperOpen(true)} title="Tamper protection">
              {agentData.tamper_locked?<Shield size={13} style={{color:'var(--ok)'}}/>:<ShieldOff size={13} style={{color:'var(--warn)'}}/>}
              {agentData.tamper_locked?'Tamper protected':'Not tamper protected'}
            </button>
            {!agentData.online&&isAdminUser()&&(
              <button className="ow-btn" style={{color:'var(--crit)'}} onClick={async()=>{
                if(!window.confirm(`Remove the offline agent record for ${agentData.hostname}?\n\nIts collected events are kept. If the agent is still installed somewhere it will register again the next time it connects.`))return
                try{await api.delete(`/api/v1/agents/${encodeURIComponent(agent.id)}`);onBack()}catch(e){window.alert(e.response?.data?.error||e.message)}
              }}>Remove record</button>
            )}
          </div>
        </div>
      </header>
      <div className="flex flex-1 min-h-0">
        <nav className="agent-rail relative shrink-0 overflow-y-auto border-r border-siem-border bg-siem-surface" style={{width:railW,paddingBottom:12}}>
          {TAB_GROUPS.map(g=>(
            <div key={g.label}>
              <div className="agent-rail-label">{g.label}</div>
              {g.ids.map(id=>{const t=DETAIL_TABS.find(x=>x.id===id);const TabIcon=t.icon;return(
                <button key={id} onClick={()=>setActiveTab(id)} className={`agent-rail-item ${activeTab===id?'active':''}`}><TabIcon size={13}/><span>{t.label}</span></button>
              )})}
            </div>
          ))}
          <div {...railHandle}/>
        </nav>
        <div className={`flex-1 min-w-0 ${fullHeight?'overflow-hidden':'overflow-y-auto'}`}>
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
        {activeTab==='response'     &&<TabResponse  agent={agentData}/>}
        {activeTab==='vulnerability' &&<TabVuln      agent={agentData}/>}
        {activeTab==='rca'           &&<TabRCA       agent={agentData}/>}
      </div>
      </div>
    </div>
  )
}

// ── Fleet ─────────────────────────────────────────────────────────────────────
// A host's state is reachability only: Online or Offline. Open alerts are shown beside it as a count and
// a filter, never folded into a verdict on the host. Tags (key:value allowed, e.g. env:prod) are the one
// way to group hosts; response approvals and, later, policies target them.
const OS_NAME = { linux: 'Linux', windows: 'Windows', macos: 'macOS', other: 'Other' }
const ALERT_BAND = { high: 'High or critical', some: 'Medium or lower', none: 'None' }
const alertBand = (r) => r.alerts.max >= 4 ? 'high' : r.alerts.n ? 'some' : 'none'
const GETTERS = {
  status: r => r.online ? 'online' : 'offline',
  alerts: r => alertBand(r),
  os: r => r.osCat,
  protection: r => r.tamper_locked ? 'on' : 'off',
  tags: r => r.tags.length ? r.tags : '(untagged)',
  criticality: r => r.criticality,
}

// Add or remove one tag on many hosts. PUT replaces a host's meta, so each host's other tags and
// criticality are sent back unchanged.
async function applyTag(rows, tag, mode) {
  let ok = 0, fail = []
  for (const r of rows) {
    const tags = mode === 'add' ? [...new Set([...r.tags, tag])] : r.tags.filter(t => t !== tag)
    if (mode === 'add' && tags.length > 10) { fail.push(`${r.hostname}: already has 10 tags`); continue }
    try { await api.put(`/api/v1/hosts/${encodeURIComponent(r.hostname)}/meta`, { criticality: r.criticality, tags }); ok++ }
    catch (e) { fail.push(`${r.hostname}: ${e.response?.data?.error || e.message}`) }
  }
  return { ok, fail }
}

function TagDialog({ mode, rows, allTags, onClose, onDone }) {
  const [tag, setTag] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const options = mode === 'remove' ? [...new Set(rows.flatMap(r => r.tags))].sort() : allTags
  const valid = /^[a-z0-9:_.-]{1,32}$/.test(tag.trim().toLowerCase())
  const go = async () => {
    setBusy(true); setErr('')
    const r = await applyTag(rows, tag.trim().toLowerCase(), mode)
    setBusy(false)
    if (r.fail.length) setErr(`${r.ok} updated. ${r.fail.length} failed: ${r.fail.slice(0, 3).join('; ')}`)
    else { onDone(); onClose() }
  }
  return (
    <Dialog title={`${mode === 'add' ? 'Add a tag to' : 'Remove a tag from'} ${rows.length} host${rows.length === 1 ? '' : 's'}`} onClose={onClose}
      footer={<><button className="ow-btn quiet" onClick={onClose}>Cancel</button><button className="ow-btn primary" disabled={!valid || busy} onClick={go}>{busy ? 'Saving…' : mode === 'add' ? 'Add tag' : 'Remove tag'}</button></>}>
      <Field label="Tag" hint="Lowercase letters, digits and : _ . - (up to 32). Use key:value for things like env:prod or role:server. Up to 10 tags per host.">
        <input className="input mono" autoFocus list="ow-tag-options" value={tag} onChange={e => setTag(e.target.value)} onKeyDown={e => e.key === 'Enter' && valid && go()}/>
        <datalist id="ow-tag-options">{options.map(t => <option key={t} value={t}/>)}</datalist>
      </Field>
      {options.length > 0 && <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>{options.slice(0, 20).map(t => <button key={t} className="tag mono" style={{ cursor: 'pointer', border: 0 }} onClick={() => setTag(t)}>{t}</button>)}</div>}
      {err && <div className="c-crit" style={{ fontSize: 13.5 }}>{err}</div>}
    </Dialog>
  )
}

function FleetHosts({ rows, onOpen, onTamper, filter, setFilter, sort, setSort, selected, setSelected, total, isAdmin, reload }) {
  const navigate = useNavigate()
  const toggle = (k, v) => setSelected(s => { const n = { ...s }; const set = new Set(n[k] || []); set.has(v) ? set.delete(v) : set.add(v); n[k] = set; return n })
  const faceted = useFacetFilter(rows, GETTERS, selected)
  const pick = useSelection()
  const [tagDlg, setTagDlg] = useState(null)
  const shown = useMemo(() => {
    const { fields, text } = parseFilter(filter)
    const f = faceted.filter(r => {
      if (text && !(`${r.hostname} ${r.last_ip} ${r.os} ${r.tags.join(' ')}`.toLowerCase().includes(text))) return false
      if (fields.os && !fields.os.some(v => r.osCat.startsWith(v) || (r.os || '').toLowerCase().includes(v))) return false
      if (fields.status && !fields.status.some(v => (r.online ? 'online' : 'offline').startsWith(v))) return false
      if (fields.tag && !fields.tag.some(v => r.tags.some(t => t === v || (v.endsWith('*') && t.startsWith(v.slice(0, -1)))))) return false
      if (fields.version && !fields.version.some(v => (r.version || '').startsWith(v))) return false
      return true
    })
    const by = {
      status: (a, b) => (a.online - b.online) || b.alerts.max - a.alerts.max || a.hostname.localeCompare(b.hostname),
      name: (a, b) => a.hostname.localeCompare(b.hostname),
      seen: (a, b) => new Date(b.last_seen) - new Date(a.last_seen),
      alerts: (a, b) => b.alerts.max - a.alerts.max || b.alerts.n - a.alerts.n,
    }[sort] || ((a, b) => a.hostname.localeCompare(b.hostname))
    return f.sort(by)
  }, [faceted, filter, sort])
  const [page, setPage] = useState(0)
  useEffect(() => setPage(0), [filter, sort, selected])
  const PER = 50
  const pages = Math.max(1, Math.ceil(shown.length / PER))
  const slice = shown.slice(page * PER, page * PER + PER)
  const chosen = rows.filter(r => pick.selected.has(r.id))
  const allTags = [...new Set(rows.flatMap(r => r.tags))].sort()

  const groups = [
    { key: 'status', label: 'Status', values: countBy(rows, GETTERS.status, ['online', 'offline'], { online: 'Online', offline: 'Offline' }) },
    { key: 'alerts', label: 'Open alerts', values: countBy(rows, GETTERS.alerts, ['high', 'some', 'none'], ALERT_BAND) },
    { key: 'tags', label: 'Tags', values: countBy(rows, GETTERS.tags).slice(0, 15) },
    { key: 'os', label: 'OS', values: countBy(rows, GETTERS.os, ['linux', 'windows', 'macos', 'other'], OS_NAME) },
    { key: 'protection', label: 'Tamper protection', values: countBy(rows, GETTERS.protection, ['on', 'off'], { on: 'On', off: 'Off' }) },
    { key: 'criticality', label: 'Criticality', values: countBy(rows, GETTERS.criticality, ['critical', 'high', 'normal', 'low'], { critical: 'Critical', high: 'High', normal: 'Normal', low: 'Low' }) },
  ]

  const cols = [
    { key: 'st', label: 'Status', width: '92px', render: r => <StatePill state={r.online ? 'ok' : 'none'}>{r.online ? 'Online' : 'Offline'}</StatePill> },
    { key: 'host', label: 'Host', width: 'minmax(150px, 1.3fr)', render: r => <span className="mono t1">{r.hostname}</span>, title: r => `${r.hostname} · ${r.last_ip || ''}` },
    { key: 'os', label: 'OS / agent', width: 'minmax(150px, 1.1fr)', render: r => <span className="t2">{shortOS(r.os)} · <span className="mono">{r.version || '?'}</span></span>, title: r => r.os },
    { key: 'al', label: 'Open alerts', width: '120px', render: r => r.alerts.n
      ? <Link to={`/alerts?host=${encodeURIComponent(r.hostname)}`} onClick={e => e.stopPropagation()} style={{ display: 'flex', alignItems: 'center', gap: 6 }}><span className="mono t1">{r.alerts.n}</span>{r.alerts.max >= 3 && <SevPill sev={r.alerts.max}/>}</Link>
      : <span className="t3">0</span> },
    { key: 'tags', label: 'Tags', width: 'minmax(120px, 1fr)', render: r => r.tags.length ? <span style={{ display: 'flex', gap: 4, overflow: 'hidden' }}>{r.tags.slice(0, 3).map(t => <span key={t} className="tag mono">{t}</span>)}{r.tags.length > 3 && <span className="t3">+{r.tags.length - 3}</span>}</span> : <span className="t3">—</span>, title: r => r.tags.join(', ') },
    { key: 'tp', label: 'Tamper', width: '72px', render: r => (
      <button className="ow-btn quiet" style={{ height: 24, padding: '0 4px', gap: 5, color: r.tamper_locked ? 'var(--t2)' : 'var(--warn)' }}
        onClick={e => { e.stopPropagation(); onTamper(r) }} title="Tamper protection settings">
        {r.tamper_locked ? <Shield size={13}/> : <ShieldOff size={13}/>}{r.tamper_locked ? 'On' : 'Off'}
      </button>) },
    { key: 'seen', label: 'Last seen', width: '92px', render: r => <span style={{ color: r.online ? 'var(--t2)' : 'var(--warn)' }}>{relTime(r.last_seen)}</span>, title: r => new Date(r.last_seen).toLocaleString() },
  ]

  return (
    <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
      {tagDlg && <TagDialog mode={tagDlg} rows={chosen} allTags={allTags} onClose={() => setTagDlg(null)} onDone={() => { pick.clear(); reload() }}/>}
      <Facets groups={groups} selected={selected} onToggle={toggle} onClear={() => setSelected({})}/>
      <div className="ow-card" style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
        {pick.selected.size > 0 ? (
          <SelectionBar count={pick.selected.size} total={shown.length} allMatching={shown.every(r => pick.selected.has(r.id))}
            onSelectAllMatching={() => pick.setAll(shown.map(r => r.id))} onClear={pick.clear}>
            {isAdmin && <button className="ow-btn" style={{ height: 26 }} onClick={() => setTagDlg('add')}>Add tag…</button>}
            {isAdmin && <button className="ow-btn" style={{ height: 26 }} onClick={() => setTagDlg('remove')}>Remove tag…</button>}
            <button className="ow-btn" style={{ height: 26 }} onClick={() => navigate('/response?' + chosen.map(r => 'host=' + encodeURIComponent(r.hostname)).join('&'))}>Respond…</button>
          </SelectionBar>
        ) : (
          <div className="ow-card-bar">
            <label className="ow-field" style={{ flex: 1, maxWidth: 380, height: 28 }}>
              <Search size={13} style={{ color: 'var(--t3)' }}/>
              <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter hosts · tag:env:prod os:linux status:offline" aria-label="Filter hosts"/>
              {filter && <button onClick={() => setFilter('')} aria-label="Clear filter" style={{ background: 'none', border: 0, color: 'var(--t3)', cursor: 'pointer' }}><X size={12}/></button>}
            </label>
            <span className="t2" style={{ fontSize: 13.5 }}>{shown.length.toLocaleString()} of {total.toLocaleString()}</span>
            <label className="t2" style={{ marginLeft: 'auto', fontSize: 13.5, display: 'flex', alignItems: 'center', gap: 6 }}>Sort
              <select value={sort} onChange={e => setSort(e.target.value)} className="ow-field" style={{ height: 26, padding: '0 6px', fontSize: 13.5 }}>
                <option value="status">offline first</option><option value="alerts">open alerts</option><option value="name">name</option><option value="seen">last seen</option>
              </select>
            </label>
          </div>
        )}
        <DenseTable cols={cols} rows={slice} rowKey={r => r.id} rowState={r => r.online ? null : 'none'} onRow={onOpen}
          selected={pick.selected} onSelect={pick.onSelect} onSelectAll={v => v ? pick.setAll([...new Set([...pick.selected, ...slice.map(r => r.id)])]) : pick.clear()}
          empty={rows.length ? 'No hosts match these filters.' : 'No hosts enrolled yet. Build an agent in Agent builder to enrol one.'}/>
        {shown.length > 0 && (
          <div className="ow-card-foot">
            <span>Showing {page * PER + 1}–{Math.min(shown.length, page * PER + PER)} of {shown.length.toLocaleString()}</span>
            {pages > 1 && <span style={{ display: 'flex', gap: 4 }}>
              <button className="ow-btn quiet" style={{ height: 24 }} disabled={page === 0} onClick={() => setPage(p => p - 1)}>‹ Prev</button>
              <span style={{ alignSelf: 'center' }}>{page + 1} / {pages}</span>
              <button className="ow-btn quiet" style={{ height: 24 }} disabled={page >= pages - 1} onClick={() => setPage(p => p + 1)}>Next ›</button>
            </span>}
          </div>
        )}
      </div>
    </div>
  )
}

function FleetTags({ rows, onPick }) {
  const tags = useMemo(() => {
    const m = new Map()
    for (const r of rows) for (const t of (r.tags.length ? r.tags : ['(untagged)'])) {
      const g = m.get(t) || { name: t, hosts: 0, online: 0, alerts: 0, high: 0, unprotected: 0 }
      g.hosts++; if (r.online) g.online++; g.alerts += r.alerts.n; if (r.alerts.max >= 4) g.high++; if (!r.tamper_locked) g.unprotected++
      m.set(t, g)
    }
    return [...m.values()].sort((a, b) => (a.name === '(untagged)') - (b.name === '(untagged)') || b.hosts - a.hosts)
  }, [rows])
  const cols = [
    { key: 'n', label: 'Tag', width: 'minmax(160px, 1.4fr)', render: g => g.name === '(untagged)' ? <span className="t3">Untagged</span> : <span className="tag mono">{g.name}</span> },
    { key: 'h', label: 'Hosts', width: '80px', render: g => <span className="mono t1">{g.hosts}</span> },
    { key: 'o', label: 'Online', width: '90px', render: g => <span className="mono" style={{ color: g.online < g.hosts ? 'var(--warn)' : undefined }}>{g.online}</span> },
    { key: 'a', label: 'Open alerts', width: '100px', render: g => <span className="mono">{g.alerts}</span> },
    { key: 'x', label: 'With high or critical', width: '150px', render: g => <span className="mono" style={{ color: g.high ? 'var(--warn)' : 'var(--t3)' }}>{g.high}</span> },
    { key: 'u', label: 'Tamper off', width: '100px', render: g => <span className="mono" style={{ color: g.unprotected ? 'var(--warn)' : 'var(--t3)' }}>{g.unprotected}</span> },
  ]
  return (
    <div className="ow-card" style={{ overflow: 'hidden' }}>
      <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Tags</span>
        <span className="t3" style={{ fontSize: 13.5 }}>Select hosts on the Hosts tab to add or remove tags. Response approvals and policies target tags.</span></div>
      <DenseTable cols={cols} rows={tags} rowKey={g => g.name} onRow={g => onPick(g.name)} empty="No hosts yet."/>
    </div>
  )
}

function shortOS(os) {
  if (!os) return 'Unknown OS'
  return os.replace(/\s*\((linux|darwin)\)\s*$/i, '').replace(/^Red Hat Enterprise Linux/, 'RHEL').replace(/ LTS$/, '').replace(/GNU\/Linux /, '').replace(/(\d+\.\d+)\.\d+/, '$1')
}

export default function Agents() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [agents, setAgents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [meta, setMeta] = useState({})
  const [loading, setLoading] = useState(true)
  const [loadErr, setLoadErr] = useState('')
  const [tamperAgent, setTamperAgent] = useState(null)
  const [tab, setTab] = useState('hosts')
  const [filter, setFilter] = useState('')
  const [sort, setSort] = useState('status')
  const [selected, setSelected] = useState(() => {
    const out = {}
    const os = searchParams.get('os'); if (os) out.os = new Set([os])
    const st = searchParams.get('status'); if (st) out.status = new Set([st])
    const tag = searchParams.get('tag'); if (tag) out.tags = new Set([tag])
    return out
  })
  const hostParam = searchParams.get('host')

  const load = async () => {
    try {
      const { data } = await api.get('/api/v1/agents')
      setAgents(data.agents || []); setLoadErr('')
    } catch (e) { setLoadErr(e.response?.data?.error || e.message) } finally { setLoading(false) }
    api.get('/api/v1/alerts', { params: { status: 'open', limit: 5000 } }).then(r => setAlerts(r.data?.alerts || [])).catch(() => {})
    api.get('/api/v1/hosts/meta').then(r => setMeta(Object.fromEntries((r.data?.hosts || []).map(h => [h.host, h])))).catch(() => {})
  }
  useEffect(() => { load(); const id = setInterval(load, 15000); return () => clearInterval(id) }, [])

  const rows = useMemo(() => {
    const byHost = alertsByHost(alerts)
    return agents.filter(a => !isProbe(a)).map(a => {
      const m = meta[a.hostname] || {}
      return { ...a, alerts: byHost[a.hostname] || { n: 0, max: 0 }, osCat: getOSCategory(a.os), tags: m.tags || [], criticality: m.criticality || 'normal' }
    })
  }, [agents, alerts, meta])

  const selectedAgent = hostParam ? agents.find(a => a.hostname === hostParam) : null
  if (selectedAgent) return <div className="flex flex-col h-screen overflow-hidden bg-siem-bg"><AgentDetail agent={selectedAgent} onBack={() => setSearchParams({})}/></div>

  const online = rows.filter(r => r.online).length
  const offline = rows.length - online
  const withHigh = rows.filter(r => r.alerts.max >= 4).length
  const openAlerts = rows.reduce((s, r) => s + r.alerts.n, 0)
  const protectedN = rows.filter(r => r.tamper_locked).length
  const untagged = rows.filter(r => !r.tags.length).length
  const osSeen = ['linux', 'macos', 'windows'].filter(k => rows.some(r => r.osCat === k)).map(k => OS_NAME[k])
  const isAdmin = isAdminUser()

  const exportCSV = () => downloadCSV(`fleet-${new Date().toISOString().slice(0, 10)}.csv`,
    ['status', 'hostname', 'ip', 'os', 'agent_version', 'open_alerts', 'highest_open_severity', 'tags', 'criticality', 'tamper_protected', 'last_seen'],
    rows.map(r => [r.online ? 'online' : 'offline', r.hostname, r.last_ip, r.os, r.version, r.alerts.n, r.alerts.max || '', r.tags.join(';'), r.criticality, r.tamper_locked, r.last_seen]))

  return (
    <div>
      {tamperAgent && <TamperPanel agent={tamperAgent} onClose={() => { setTamperAgent(null); load() }} onUpdated={load}/>}
      <PageHeader
        title="Fleet"
        state={loading || !rows.length ? undefined : offline ? 'warn' : 'ok'}
        stateText={offline ? `${offline} offline` : 'All online'}
        sub={loading ? 'Loading hosts…' : loadErr ? `Could not load hosts: ${loadErr}` : rows.length
          ? `${rows.length.toLocaleString()} host${rows.length === 1 ? '' : 's'} enrolled${osSeen.length ? ' across ' + osSeen.join(', ').replace(/, ([^,]*)$/, ' and $1') : ''}. Tamper protection on ${protectedN.toLocaleString()}.`
          : 'No hosts enrolled yet.'}
        actions={<>
          <button className="ow-btn" onClick={exportCSV} disabled={!rows.length}><Download size={13}/>Export</button>
          {isAdmin && <button className="ow-btn primary" onClick={() => navigate('/agent-builder')}>Enrol hosts</button>}
        </>}
        nums={<>
          <Num k="Online" v={online.toLocaleString()} unit={`of ${rows.length.toLocaleString()}`}/>
          <Num k="Offline" v={offline.toLocaleString()} tone={offline ? 'warn' : undefined}/>
          <Num k="Open alerts" v={openAlerts.toLocaleString()} title="Open alerts on enrolled hosts"/>
          <Num k="Hosts with high or critical alerts" v={withHigh} tone={withHigh ? 'crit' : undefined}/>
          <Num k="Tamper protected" v={protectedN.toLocaleString()} unit={`of ${rows.length.toLocaleString()}`} tone={protectedN < rows.length ? 'warn' : undefined}/>
          <Num k="Untagged" v={untagged} title="Hosts without tags are not covered by tag-based approvals or policies"/>
        </>}
        tabs={<Tabs value={tab} onChange={setTab} tabs={[{ id: 'hosts', label: 'Hosts' }, { id: 'tags', label: 'Tags', n: new Set(rows.flatMap(r => r.tags)).size || null }]}/>}
      />
      <div className="ow-body">
        {tab === 'hosts'
          ? <FleetHosts rows={rows} total={rows.length} onOpen={a => setSearchParams({ host: a.hostname })} onTamper={setTamperAgent} isAdmin={isAdmin} reload={load}
              filter={filter} setFilter={setFilter} sort={sort} setSort={setSort} selected={selected} setSelected={setSelected}/>
          : <FleetTags rows={rows} onPick={t => { setSelected({ tags: new Set([t]) }); setTab('hosts') }}/>}
      </div>
    </div>
  )
}
