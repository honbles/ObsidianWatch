import { useEffect, useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity, Monitor, Bell, AlertTriangle, Shield, Globe,
  Cpu, ChevronRight, Clock, CheckCircle, Zap, Database,
  RefreshCw, TrendingUp, Radio, GitBranch, Cloud, Wifi
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts'
import { format, formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { useLiveFeed } from '../api/useLiveFeed'
import { SeverityBadge } from '../components/SeverityBadge'

const SEV_COLOR = { 5:'#ef4444', 4:'#f97316', 3:'#eab308', 2:'#3b82f6', 1:'#475569' }
const SEV_LABEL = { 5:'Critical', 4:'High', 3:'Medium', 2:'Low', 1:'Info' }
const TYPE_COLOR = {
  registry:'#a855f7', dns:'#06b6d4', network:'#3b82f6',
  process:'#8b949e', file:'#eab308', logon:'#22c55e', health:'#475569',
  'devops.push':'#10b981', 'devops.secret_push':'#ef4444', 'net.fw_deny':'#f97316',
}
const SUSPICIOUS = ['rustdesk','ngrok','anydesk','cobalt','mimikatz','meterpreter']
const isSusp = v => v && SUSPICIOUS.some(k => v.toLowerCase().includes(k))
const TooltipStyle = { background:'#161b22', border:'1px solid #30363d', borderRadius:6, fontSize:10, padding:'4px 8px' }

// ── Stat card ─────────────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, sub, color='text-siem-accent', warn, onClick, trend }) {
  return (
    <div onClick={onClick}
      className={`relative bg-siem-surface border rounded-xl p-4 overflow-hidden transition-all duration-200 ${
        onClick ? 'cursor-pointer hover:border-siem-accent/40 hover:bg-white/[0.02]' : ''
      } ${warn ? 'border-red-800/50' : 'border-siem-border'}`}>
      {warn && <div className="absolute inset-0 bg-red-950/10 pointer-events-none"/>}
      <div className="relative flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="text-[10px] uppercase tracking-wider text-siem-muted/70 font-medium mb-2">{label}</div>
          <div className={`text-3xl font-bold font-mono tabular-nums leading-none ${color}`}>
            {value?.toLocaleString() ?? '—'}
          </div>
          {sub && <div className="text-[10px] text-siem-muted mt-1.5">{sub}</div>}
        </div>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${warn ? 'bg-red-500/15' : 'bg-siem-bg'}`}>
          <Icon size={16} className={warn ? 'text-red-400' : color}/>
        </div>
      </div>
      {onClick && (
        <div className="relative mt-3 flex items-center gap-1 text-[9px] text-siem-muted/40 group-hover:text-siem-accent/60 transition-colors">
          View details <ChevronRight size={9}/>
        </div>
      )}
    </div>
  )
}

// ── Section header ────────────────────────────────────────────────────────────
function Section({ title, icon: Icon, iconColor='text-siem-accent', action, children }) {
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
      <div className="flex items-center gap-2.5 px-4 py-3 border-b border-siem-border">
        <Icon size={13} className={iconColor}/>
        <span className="text-xs font-semibold text-siem-text tracking-tight">{title}</span>
        {action && <div className="ml-auto">{action}</div>}
      </div>
      {children}
    </div>
  )
}

function NavAction({ label, to, navigate }) {
  return (
    <button onClick={() => navigate(to)}
      className="flex items-center gap-1 text-[10px] text-siem-muted hover:text-siem-accent transition-colors">
      {label} <ChevronRight size={9}/>
    </button>
  )
}

// ── Mini bar ──────────────────────────────────────────────────────────────────
function MiniBar({ value, max, color }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0
  return (
    <div className="h-1 bg-siem-border/30 rounded-full overflow-hidden flex-1">
      <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color || '#58a6ff' }}/>
    </div>
  )
}

// ── Host row ──────────────────────────────────────────────────────────────────
function HostRow({ host, onClick }) {
  return (
    <div onClick={() => onClick(host)}
      className="flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.02] cursor-pointer border-b border-siem-border/20 last:border-0 group transition-colors">
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${host.online ? 'bg-emerald-400' : 'bg-red-500/50'}`}/>
      <Monitor size={11} className="text-siem-muted shrink-0"/>
      <span className="text-[11px] font-mono text-siem-text truncate flex-1">{host.hostname || host.host}</span>
      <div className="flex items-center gap-2">
        {host.max_severity >= 4 && (
          <span className="text-[8px] font-bold px-1.5 py-0.5 rounded border"
            style={{ color: SEV_COLOR[host.max_severity], borderColor: SEV_COLOR[host.max_severity] + '40' }}>
            {SEV_LABEL[host.max_severity]}
          </span>
        )}
        <span className="text-[10px] font-mono text-siem-muted">{Number(host.event_count).toLocaleString()}</span>
      </div>
      <ChevronRight size={9} className="text-siem-muted/20 group-hover:text-siem-muted shrink-0 transition-colors"/>
    </div>
  )
}

// ── Alert row ─────────────────────────────────────────────────────────────────
function AlertRow({ alert, onClick }) {
  return (
    <div onClick={() => onClick(alert)}
      className="flex items-start gap-3 px-4 py-2.5 hover:bg-white/[0.02] cursor-pointer border-b border-siem-border/20 last:border-0 group transition-colors">
      <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 animate-pulse"
        style={{ background: SEV_COLOR[alert.severity] || '#475569' }}/>
      <div className="flex-1 min-w-0">
        <div className="text-[11px] text-siem-text font-medium truncate leading-snug">{alert.title}</div>
        <div className="flex items-center gap-2 mt-0.5">
          {alert.host && <span className="text-[9px] font-mono text-siem-muted/60">{alert.host}</span>}
          <span className="text-[9px] text-siem-muted/40">
            {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
          </span>
        </div>
      </div>
      <ChevronRight size={9} className="text-siem-muted/20 group-hover:text-siem-muted mt-1 shrink-0 transition-colors"/>
    </div>
  )
}

// ── Security posture score ────────────────────────────────────────────────────
function PostureScore({ stats }) {
  const s = stats?.summary
  const openAlerts     = s?.open_alerts || 0
  const highSev        = s?.high_severity_today || 0
  const onlineAgents   = s?.online_agents || 0
  const totalAgents    = s?.total_agents || 1

  // Score 0-100: start at 100, deduct for issues
  let score = 100
  score -= Math.min(openAlerts * 5, 30)
  score -= Math.min(highSev * 3, 20)
  score -= Math.round((1 - onlineAgents / totalAgents) * 20)
  score = Math.max(0, Math.min(100, score))

  const color = score >= 80 ? '#3fb950' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444'
  const label = score >= 80 ? 'Good' : score >= 60 ? 'Fair' : score >= 40 ? 'At Risk' : 'Critical'

  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl p-4 flex items-center gap-4">
      {/* Ring */}
      <div className="relative shrink-0 w-16 h-16">
        <svg viewBox="0 0 64 64" className="w-full h-full -rotate-90">
          <circle cx="32" cy="32" r="26" fill="none" stroke="#21262d" strokeWidth="6"/>
          <circle cx="32" cy="32" r="26" fill="none" stroke={color} strokeWidth="6"
            strokeDasharray={`${2 * Math.PI * 26}`}
            strokeDashoffset={`${2 * Math.PI * 26 * (1 - score / 100)}`}
            strokeLinecap="round" style={{ transition: 'stroke-dashoffset 1s ease' }}/>
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-sm font-bold font-mono" style={{ color }}>{score}</span>
        </div>
      </div>
      <div>
        <div className="text-[10px] uppercase tracking-wider text-siem-muted/70 font-medium mb-1">Security Posture</div>
        <div className="text-lg font-bold" style={{ color }}>{label}</div>
        <div className="text-[10px] text-siem-muted mt-0.5">
          {openAlerts > 0 ? `${openAlerts} open alert${openAlerts !== 1 ? 's' : ''}` : 'No open alerts'}
          {highSev > 0 ? ` · ${highSev} high-sev events` : ''}
        </div>
      </div>
    </div>
  )
}

// ── Integration summary ───────────────────────────────────────────────────────
function IntegrationBar({ navigate }) {
  const [counts, setCounts] = useState({ cloud: 0, devops: 0, network: 0 })
  useEffect(() => {
    api.get('/api/v1/cloud-connectors').then(r => {
      const list = r.data?.connectors || []
      setCounts(c => ({ ...c, cloud: list.filter(x => x.status === 'connected').length }))
    }).catch(() => {})
    api.get('/api/v1/devops-connectors').then(r => {
      const list = r.data?.connectors || []
      setCounts(c => ({ ...c, devops: list.filter(x => x.status === 'connected').length }))
    }).catch(() => {})
    api.get('/api/v1/agents').then(r => {
      const probes = (r.data?.agents || []).filter(a => a.os?.includes('network-probe'))
      setCounts(c => ({ ...c, network: probes.length }))
    }).catch(() => {})
  }, [])

  const items = [
    { icon: Cloud,     label: 'Cloud',   count: counts.cloud,   color: 'text-orange-400', to: '/cloud' },
    { icon: GitBranch, label: 'DevOps',  count: counts.devops,  color: 'text-emerald-400', to: '/devops' },
    { icon: Radio,     label: 'Network', count: counts.network, color: 'text-cyan-400',   to: '/network' },
  ]

  return (
    <div className="grid grid-cols-3 gap-3">
      {items.map(({ icon: Icon, label, count, color, to }) => (
        <button key={label} onClick={() => navigate(to)}
          className="bg-siem-surface border border-siem-border rounded-xl p-3 flex items-center gap-3 hover:border-siem-accent/30 transition-all group">
          <div className="w-7 h-7 rounded-lg bg-siem-bg flex items-center justify-center">
            <Icon size={13} className={color}/>
          </div>
          <div className="text-left">
            <div className="text-[10px] text-siem-muted">{label}</div>
            <div className={`text-sm font-bold font-mono ${count > 0 ? 'text-siem-text' : 'text-siem-muted/50'}`}>
              {count} <span className="text-[9px] font-normal text-siem-muted/50">connected</span>
            </div>
          </div>
          <ChevronRight size={10} className="ml-auto text-siem-muted/20 group-hover:text-siem-muted transition-colors"/>
        </button>
      ))}
    </div>
  )
}

// ── MAIN DASHBOARD ────────────────────────────────────────────────────────────
const VIEWS = [
  { id: 'overview',  label: 'Overview',  icon: '⬡' },
  { id: 'endpoint',  label: 'Endpoint',  icon: '⬡' },
  { id: 'cloud',     label: 'Cloud',     icon: '⬡' },
  { id: 'devops',    label: 'DevOps',    icon: '⬡' },
]

export default function Dashboard() {
  const [stats, setStats]     = useState(null)
  const [loading, setLoading] = useState(true)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [view, setView]       = useState('overview')
  const { events: liveEvents, connected } = useLiveFeed(30)
  const navigate = useNavigate()

  const load = async () => {
    try {
      const r = await api.get('/api/v1/stats')
      setStats(r.data)
      setLastRefresh(new Date())
    } finally { setLoading(false) }
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 30000)
    return () => clearInterval(id)
  }, [])

  const s   = stats?.summary
  const d   = stats?.dashboard
  const raw = stats

  const timeline = useMemo(() =>
    (d?.timeline_48h || []).map(p => ({
      time:   format(new Date(p.hour), 'HH:mm'),
      high:   Number(p.high || 0),
      medium: Number(p.medium || 0),
      low:    Number(p.low || 0),
    })), [d])

  const eventTypes = useMemo(() =>
    (d?.by_type || raw?.by_type || []).map(e => ({
      name: e.event_type, count: Number(e.count),
      color: TYPE_COLOR[e.event_type] || '#8b949e'
    })), [d, raw])
  const maxTypeCount = Math.max(...eventTypes.map(e => e.count), 1)

  const hostsActivity = useMemo(() =>
    (d?.hosts_activity || []).map(h => ({
      ...h, hostname: h.host,
      event_count: Number(h.event_count),
      max_severity: Number(h.max_severity),
      online: true,
    })), [d])

  const topProcesses = useMemo(() => (d?.top_processes || []).slice(0, 10), [d])
  const maxProcCount = Math.max(...topProcesses.map(p => Number(p.count)), 1)

  const topDomains = useMemo(() => (d?.top_domains || []).slice(0, 10), [d])
  const maxDomCount = Math.max(...topDomains.map(d => Number(d.count)), 1)

  const threatFeed   = d?.threat_feed   || []
  const recentAlerts = d?.recent_alerts || []
  const sevDist      = raw?.by_severity || []

  if (loading) return (
    <div className="flex items-center justify-center h-full gap-3 text-siem-muted">
      <div className="w-5 h-5 border-2 border-siem-accent/30 border-t-siem-accent rounded-full animate-spin"/>
      <span className="text-sm">Loading dashboard…</span>
    </div>
  )

  return (
    <div className="h-screen overflow-y-auto bg-siem-bg">
      <div className="p-5 space-y-4 max-w-[1600px] mx-auto">

        {/* ── Header ── */}
        <div className="flex items-center justify-between">
          <div style={{ display:'flex', alignItems:'center', gap:16 }}>
            <div>
              <h1 style={{ fontSize:18, fontWeight:700, color:'var(--text)', letterSpacing:'-0.3px' }}>
                {VIEWS.find(v=>v.id===view)?.label || 'Overview'} Dashboard
              </h1>
              <div style={{ display:'flex', alignItems:'center', gap:12, marginTop:3 }}>
                <div style={{ display:'flex', alignItems:'center', gap:5, fontSize:10,
                               color: connected ? 'var(--green)' : 'var(--text3)' }}>
                  <span className={connected ? 'pulse' : ''} style={{
                    width:5, height:5, borderRadius:'50%', display:'inline-block',
                    background: connected ? 'var(--green)' : 'var(--text3)'
                  }}/>
                  {connected ? 'Live' : 'Reconnecting…'}
                </div>
                {lastRefresh && (
                  <span style={{ fontSize:10, color:'var(--text3)' }}>
                    {format(lastRefresh, 'HH:mm:ss')}
                  </span>
                )}
              </div>
            </div>
            {/* View switcher */}
            <div style={{ display:'flex', gap:3, background:'var(--surface2)',
                           border:'1px solid var(--border)', borderRadius:9, padding:3 }}>
              {VIEWS.map(v => (
                <button key={v.id} onClick={() => setView(v.id)}
                  style={{
                    padding:'4px 12px', borderRadius:7, fontSize:11.5, fontWeight:500,
                    cursor:'pointer', border:'none', transition:'all 0.15s',
                    background: view===v.id ? 'var(--surface)' : 'transparent',
                    color: view===v.id ? 'var(--accent)' : 'var(--text3)',
                    boxShadow: view===v.id ? '0 1px 4px rgba(0,0,0,0.3)' : 'none',
                    borderColor: view===v.id ? 'var(--border)' : 'transparent',
                  }}>
                  {v.label}
                </button>
              ))}
            </div>
          </div>
          <button onClick={load}
            className="flex items-center gap-1.5 text-xs text-siem-muted border border-siem-border rounded-lg px-3 py-1.5 hover:text-siem-text hover:border-siem-accent/30 transition-all">
            <RefreshCw size={11}/> Refresh
          </button>
        </div>

        {/* ── View-specific content ── */}

        {/* ── Cloud Dashboard ── */}
        {view === 'cloud' && (
          <div className="stagger" style={{ display:'flex', flexDirection:'column', gap:16 }}>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12 }}>
              {[
                { label:'Cloud Connectors', value: raw?.cloud_connectors || 0, icon:'☁', color:'var(--accent)' },
                { label:'Cloud Events (24h)', value: s?.cloud_events_today || 0, icon:'📡', color:'var(--green)' },
                { label:'GuardDuty Findings', value: raw?.guardduty_findings || 0, icon:'🛡', color:'var(--yellow)' },
                { label:'IAM Anomalies', value: raw?.iam_anomalies || 0, icon:'🔑', color:'var(--red)' },
              ].map(c => (
                <div key={c.label} className="kpi">
                  <div className="kpi-accent-line" style={{ background: `linear-gradient(90deg, ${c.color}, transparent)` }}/>
                  <div className="kpi-label">{c.label}</div>
                  <div className="kpi-value" style={{ color: c.color }}>{c.value}</div>
                </div>
              ))}
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
              <div className="card">
                <div className="card-head">Cloud Activity by Provider</div>
                <div style={{ padding:16 }}>
                  {(raw?.by_cloud_provider || []).length === 0
                    ? <div style={{ textAlign:'center', padding:'24px 0', color:'var(--text3)', fontSize:12 }}>
                        No cloud connectors configured — connect AWS, Azure or GCP under Cloud menu.
                      </div>
                    : (raw?.by_cloud_provider || []).map(p => (
                        <div key={p.provider} style={{ display:'flex', alignItems:'center', gap:10, marginBottom:8 }}>
                          <span style={{ fontSize:11, width:60, color:'var(--text2)' }}>{p.provider.toUpperCase()}</span>
                          <div style={{ flex:1, height:6, background:'var(--surface2)', borderRadius:3 }}>
                            <div style={{ height:'100%', borderRadius:3, background:'var(--accent)',
                              width:`${Math.min(100,(p.count/Math.max(...(raw?.by_cloud_provider||[{count:1}]).map(x=>x.count)))*100)}%` }}/>
                          </div>
                          <span style={{ fontSize:11, color:'var(--text3)', fontFamily:'DM Mono, monospace', width:40, textAlign:'right' }}>{p.count}</span>
                        </div>
                      ))
                  }
                </div>
              </div>
              <div className="card">
                <div className="card-head">Recent Cloud Alerts</div>
                <div style={{ padding:16, fontSize:12, color:'var(--text3)', fontStyle:'italic' }}>
                  Cloud-specific alerts will appear here. Configure cloud connectors to begin monitoring.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── DevOps Dashboard ── */}
        {view === 'devops' && (
          <div className="stagger" style={{ display:'flex', flexDirection:'column', gap:16 }}>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12 }}>
              {[
                { label:'Repos Scanned',    value: raw?.sast_repos_scanned || 0,    icon:'📁', color:'var(--accent)' },
                { label:'Total Findings',   value: raw?.sast_total_findings || 0,   icon:'🔍', color:'var(--yellow)' },
                { label:'Critical Issues',  value: raw?.sast_critical_count || 0,   icon:'🔴', color:'var(--red)' },
                { label:'DevOps Connectors',value: raw?.devops_connectors || 0,     icon:'⚙',  color:'var(--green)' },
              ].map(c => (
                <div key={c.label} className="kpi">
                  <div className="kpi-accent-line" style={{ background: `linear-gradient(90deg, ${c.color}, transparent)` }}/>
                  <div className="kpi-label">{c.label}</div>
                  <div className="kpi-value" style={{ color: c.color }}>{c.value}</div>
                </div>
              ))}
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'2fr 1fr', gap:12 }}>
              <div className="card">
                <div className="card-head">Recent SAST Scans</div>
                <div style={{ overflowX:'auto' }}>
                  {(raw?.sast_results || []).length === 0
                    ? <div style={{ padding:20, fontSize:12, color:'var(--text3)', textAlign:'center', fontStyle:'italic' }}>
                        No scans yet — connect a repo under DevOps → Code Scan to begin.
                      </div>
                    : <table className="tbl">
                        <thead><tr>
                          <th>Repo</th><th>Engine</th><th>Findings</th><th>Critical</th><th>Scanned</th>
                        </tr></thead>
                        <tbody>
                          {(raw?.sast_results || []).slice(0,8).map((r,i) => (
                            <tr key={i}>
                              <td style={{ fontFamily:'DM Mono, monospace', color:'var(--text)' }}>{r.repo}</td>
                              <td><span className="tag">{r.engine}</span></td>
                              <td style={{ fontFamily:'DM Mono, monospace' }}>{r.finding_count}</td>
                              <td style={{ color: r.critical_count > 0 ? 'var(--red)' : 'var(--text3)',
                                           fontFamily:'DM Mono, monospace', fontWeight: r.critical_count > 0 ? 600 : 400 }}>
                                {r.critical_count}
                              </td>
                              <td style={{ color:'var(--text3)', fontSize:11 }}>{r.scanned_at ? new Date(r.scanned_at).toLocaleDateString() : '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                  }
                </div>
              </div>
              <div className="card">
                <div className="card-head">Findings by Severity</div>
                <div style={{ padding:16 }}>
                  {[
                    { label:'Critical', value: raw?.sast_critical_count || 0, color:'var(--red)' },
                    { label:'High',     value: raw?.sast_high_count || 0,     color:'var(--orange)' },
                    { label:'Medium',   value: raw?.sast_medium_count || 0,   color:'var(--yellow)' },
                  ].map(s => {
                    const total = (raw?.sast_total_findings || 1)
                    return (
                      <div key={s.label} style={{ marginBottom:10 }}>
                        <div style={{ display:'flex', justifyContent:'space-between', fontSize:11, marginBottom:4 }}>
                          <span style={{ color:'var(--text2)' }}>{s.label}</span>
                          <span style={{ color:s.color, fontFamily:'DM Mono, monospace' }}>{s.value}</span>
                        </div>
                        <div style={{ height:5, background:'var(--surface2)', borderRadius:3 }}>
                          <div style={{ height:'100%', borderRadius:3, background:s.color,
                            width:`${Math.min(100,(s.value/total)*100)}%`, transition:'width 0.6s ease' }}/>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          </div>
        )}

        {view === 'endpoint' && (
          <div className="stagger" style={{ display:'flex', flexDirection:'column', gap:16 }}>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12 }}>
              {[
                { label:'Total Endpoints', value: s?.total_agents || 0,  color:'var(--accent)' },
                { label:'Online Now',      value: s?.online_agents || 0, color:'var(--green)' },
                { label:'Windows',         value: raw?.windows_agents || 0, color:'#60a5fa' },
                { label:'Linux',           value: raw?.linux_agents || 0,  color:'#fb923c' },
              ].map(c => (
                <div key={c.label} className="kpi">
                  <div className="kpi-accent-line" style={{ background:`linear-gradient(90deg, ${c.color}, transparent)` }}/>
                  <div className="kpi-label">{c.label}</div>
                  <div className="kpi-value" style={{ color:c.color }}>{c.value}</div>
                </div>
              ))}
            </div>
            <div className="card">
              <div className="card-head">Endpoint Fleet</div>
              <table className="tbl">
                <thead><tr>
                  <th>Host</th><th>OS</th><th>Status</th><th>IP</th><th>Last Seen</th><th>Events (24h)</th>
                </tr></thead>
                <tbody>
                  {(raw?.endpoint_agents || []).map((a,i) => (
                    <tr key={i} onClick={() => navigate(`/agents?host=${encodeURIComponent(a.hostname)}`)}
                      style={{ cursor:'pointer' }}>
                      <td style={{ fontFamily:'DM Mono, monospace', fontWeight:500, color:'var(--text)' }}>{a.hostname}</td>
                      <td><span className="tag">{a.os || '—'}</span></td>
                      <td>
                        <span style={{ display:'flex', alignItems:'center', gap:5, fontSize:11,
                          color: a.online ? 'var(--green)' : 'var(--text3)' }}>
                          <span style={{ width:5, height:5, borderRadius:'50%', background:'currentColor',
                            display:'inline-block' }} className={a.online ? 'pulse' : ''}/>
                          {a.online ? 'Online' : 'Offline'}
                        </span>
                      </td>
                      <td style={{ fontFamily:'DM Mono, monospace', fontSize:11, color:'var(--text2)' }}>{a.ip_address || '—'}</td>
                      <td style={{ fontSize:11, color:'var(--text3)' }}>{a.last_seen ? new Date(a.last_seen).toLocaleString() : '—'}</td>
                      <td style={{ fontFamily:'DM Mono, monospace', fontSize:11 }}>{a.events_today?.toLocaleString() || '—'}</td>
                    </tr>
                  ))}
                  {(raw?.endpoint_agents || []).length === 0 && (
                    <tr><td colSpan={6} style={{ textAlign:'center', padding:24, color:'var(--text3)', fontStyle:'italic' }}>
                      No endpoints registered
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {view === 'overview' && <>

        {/* ── Row 1: KPI strip ── */}
        <div style={{ display:'grid', gridTemplateColumns:'repeat(6,1fr)', gap:12 }}>
          {[
            { label:'Events (24h)',      value: s?.events_today,           sub: `${(s?.total_events||0).toLocaleString()} total`,  color:'var(--accent)',  click:'/events' },
            { label:'Open Alerts',       value: s?.open_alerts,            sub: s?.open_alerts > 0 ? 'Needs attention' : 'All clear', color: s?.open_alerts > 0 ? 'var(--red)' : 'var(--green)', click:'/alerts' },
            { label:'High Severity',     value: s?.high_severity_today,    sub: 'Last 24h',  color: s?.high_severity_today > 0 ? 'var(--orange)' : 'var(--text3)', click:'/events' },
            { label:'Agents Online',     value: s?.online_agents,          sub: `of ${s?.total_agents||0} total`, color:'var(--green)', click:'/agents' },
            { label:'Detection Rules',   value: d?.detection_rules_active || 0, sub: 'Active rules', color:'var(--accent)' },
            { label:'SAST Findings',     value: raw?.sast_total_findings || 0,  sub: `${raw?.sast_critical_count||0} critical`, color: raw?.sast_critical_count > 0 ? 'var(--red)' : 'var(--text2)' },
          ].map(k => (
            <div key={k.label} className="kpi" onClick={k.click ? () => navigate(k.click) : undefined}
              style={{ cursor: k.click ? 'pointer' : 'default' }}>
              <div className="kpi-accent-line" style={{ background:`linear-gradient(90deg, ${k.color}, transparent)` }}/>
              <div className="kpi-label">{k.label}</div>
              <div className="kpi-value" style={{ color:k.color, fontSize:22 }}>{(k.value ?? 0).toLocaleString()}</div>
              <div className="kpi-sub">{k.sub}</div>
            </div>
          ))}
        </div>

        {/* ── Row 2: Timeline + Alert breakdown ── */}
        <div style={{ display:'grid', gridTemplateColumns:'2fr 1fr', gap:12 }}>
          <div className="card">
            <div className="card-head">
              Event Timeline — 48h
              <button onClick={() => navigate('/events')}
                style={{ fontSize:10, color:'var(--accent)', background:'none', border:'none', cursor:'pointer' }}>
                View all →
              </button>
            </div>
            <div style={{ padding:'12px 16px 8px' }}>
              <ResponsiveContainer width="100%" height={130}>
                <AreaChart data={timeline} margin={{ top:0, right:0, left:-20, bottom:0 }}>
                  <defs>
                    {[['high','#f87171'],['medium','#fbbf24'],['low','#38bdf8']].map(([k,c])=>(
                      <linearGradient key={k} id={`ov_${k}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor={c} stopOpacity={0.3}/>
                        <stop offset="95%" stopColor={c} stopOpacity={0}/>
                      </linearGradient>
                    ))}
                  </defs>
                  <XAxis dataKey="time" tick={{ fontSize:9, fill:'var(--text3)' }} tickLine={false} axisLine={false} interval={7}/>
                  <YAxis tick={{ fontSize:9, fill:'var(--text3)' }} tickLine={false} axisLine={false}/>
                  <Tooltip contentStyle={{ background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:6, fontSize:10 }}/>
                  <Area type="monotone" dataKey="high"   stroke="#f87171" strokeWidth={1.5} fill="url(#ov_high)"   stackId="1"/>
                  <Area type="monotone" dataKey="medium" stroke="#fbbf24" strokeWidth={1.5} fill="url(#ov_medium)" stackId="1"/>
                  <Area type="monotone" dataKey="low"    stroke="#38bdf8" strokeWidth={1.5} fill="url(#ov_low)"    stackId="1"/>
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="card">
            <div className="card-head">Alert Breakdown</div>
            <div style={{ padding:'14px 16px' }}>
              {[
                { label:'Critical', sev:5, color:'var(--red)' },
                { label:'High',     sev:4, color:'var(--orange)' },
                { label:'Medium',   sev:3, color:'var(--yellow)' },
                { label:'Low',      sev:2, color:'#38bdf8' },
                { label:'Info',     sev:1, color:'var(--text3)' },
              ].map(row => {
                const count = (sevDist || []).find(x => x.severity == row.sev)?.count || 0
                const maxCount = Math.max(1, ...(sevDist || []).map(x => Number(x.count||0)))
                return (
                  <div key={row.label} style={{ marginBottom:10 }}>
                    <div style={{ display:'flex', justifyContent:'space-between', fontSize:11, marginBottom:3 }}>
                      <span style={{ color:'var(--text2)' }}>{row.label}</span>
                      <span style={{ color:row.color, fontFamily:'DM Mono, monospace' }}>{Number(count).toLocaleString()}</span>
                    </div>
                    <div style={{ height:4, background:'var(--surface2)', borderRadius:2 }}>
                      <div style={{ height:'100%', borderRadius:2, background:row.color,
                        width:`${Math.min(100,(Number(count)/maxCount)*100)}%`, transition:'width 0.6s ease' }}/>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        {/* ── Row 3: Top Processes + Top DNS + Top Countries ── */}
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12 }}>

          {/* Top Processes */}
          <div className="card">
            <div className="card-head">Top Processes</div>
            <div style={{ padding:'4px 0 8px' }}>
              {(d?.top_processes || []).slice(0,8).map((p,i) => (
                <div key={i} style={{ display:'flex', alignItems:'center', gap:10, padding:'5px 16px',
                  cursor:'pointer', transition:'background 0.1s' }}
                  onClick={() => navigate(`/events?search=${encodeURIComponent(p.process_name||'')}`)}
                  onMouseEnter={e=>e.currentTarget.style.background='rgba(56,189,248,0.03)'}
                  onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                  <span style={{ fontFamily:'DM Mono, monospace', fontSize:11, color:'var(--text)',
                    flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                    {p.process_name}
                  </span>
                  <span style={{ fontSize:10, color:'var(--text3)', fontFamily:'DM Mono, monospace', flexShrink:0 }}>
                    {Number(p.count||0).toLocaleString()}
                  </span>
                  {Number(p.max_severity) >= 4 && (
                    <span className="sev sev-4" style={{ flexShrink:0 }}>HIGH</span>
                  )}
                </div>
              ))}
              {(!d?.top_processes || d.top_processes.length === 0) && (
                <div style={{ padding:'20px 16px', color:'var(--text3)', fontSize:12, fontStyle:'italic' }}>No process data</div>
              )}
            </div>
          </div>

          {/* Top DNS */}
          <div className="card">
            <div className="card-head">Top DNS Queries</div>
            <div style={{ padding:'4px 0 8px' }}>
              {(d?.top_domains || []).slice(0,8).map((p,i) => (
                <div key={i} style={{ display:'flex', alignItems:'center', gap:10, padding:'5px 16px',
                  cursor:'pointer', transition:'background 0.1s' }}
                  onMouseEnter={e=>e.currentTarget.style.background='rgba(56,189,248,0.03)'}
                  onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                  <span style={{ fontFamily:'DM Mono, monospace', fontSize:11, color:'var(--text)',
                    flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                    {p.domain || p.dst_ip || '—'}
                  </span>
                  <span style={{ fontSize:10, color:'var(--text3)', fontFamily:'DM Mono, monospace', flexShrink:0 }}>
                    {Number(p.count||0).toLocaleString()}
                  </span>
                </div>
              ))}
              {(!d?.top_domains || d.top_domains.length === 0) && (
                <div style={{ padding:'20px 16px', color:'var(--text3)', fontSize:12, fontStyle:'italic' }}>No DNS data</div>
              )}
            </div>
          </div>

          {/* Top Countries */}
          <div className="card">
            <div className="card-head">Top Destination IPs</div>
            <div style={{ padding:'8px 16px' }}>
              {(d?.top_countries || []).slice(0,8).map((c,i) => {
                const maxC = Math.max(1, ...(d?.top_countries||[]).map(x=>Number(x.count||0)))
                return (
                  <div key={i} style={{ marginBottom:8 }}>
                    <div style={{ display:'flex', justifyContent:'space-between', fontSize:11, marginBottom:3 }}>
                      <span style={{ color:'var(--text2)', fontFamily:'DM Mono, monospace', fontSize:11 }}>{c.country || c.dst_ip || '—'}</span>
                      <span style={{ color:'var(--text3)', fontFamily:'DM Mono, monospace' }}>{Number(c.count||0).toLocaleString()}</span>
                    </div>
                    <div style={{ height:3, background:'var(--surface2)', borderRadius:2 }}>
                      <div style={{ height:'100%', borderRadius:2, background:'var(--accent)',
                        width:`${Math.min(100,(Number(c.count||0)/maxC)*100)}%` }}/>
                    </div>
                  </div>
                )
              })}
              {(!d?.top_countries || d.top_countries.length === 0) && (
                <div style={{ padding:'12px 0', color:'var(--text3)', fontSize:12, fontStyle:'italic' }}>No outbound connections yet</div>
              )}
            </div>
          </div>
        </div>

        {/* ── Row 4: Malicious IPs + Malicious Domains + Malicious Files ── */}
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12 }}>

          {/* Malicious IPs */}
          <div className="card">
            <div className="card-head" style={{ color:'var(--red)' }}>
              ⚠ Malicious IPs
              <span style={{ fontFamily:'DM Mono, monospace', color:'var(--text3)', fontSize:10, fontWeight:400, textTransform:'none', letterSpacing:0 }}>
                {(d?.malicious_ips||[]).length} detected
              </span>
            </div>
            <div style={{ padding:'4px 0 8px' }}>
              {(d?.malicious_ips || []).slice(0,6).map((item,i) => (
                <div key={i} style={{ padding:'6px 16px', borderBottom:'1px solid color-mix(in srgb, var(--border) 30%, transparent)' }}>
                  <div style={{ fontSize:11, color:'var(--red)', fontFamily:'DM Mono, monospace',
                    overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{item.title}</div>
                  <div style={{ fontSize:10, color:'var(--text3)', marginTop:2 }}>{item.host} · {item.created_at ? new Date(item.created_at).toLocaleTimeString() : ''}</div>
                </div>
              ))}
              {(!d?.malicious_ips || d.malicious_ips.length === 0) && (
                <div style={{ padding:'20px 16px', color:'var(--green)', fontSize:12, display:'flex', alignItems:'center', gap:6 }}>
                  <span>✓</span> No malicious IPs detected
                </div>
              )}
            </div>
          </div>

          {/* Malicious Domains */}
          <div className="card">
            <div className="card-head" style={{ color:'var(--orange)' }}>
              ⚠ Malicious Domains
              <span style={{ fontFamily:'DM Mono, monospace', color:'var(--text3)', fontSize:10, fontWeight:400, textTransform:'none', letterSpacing:0 }}>
                {(d?.malicious_domains||[]).length} detected
              </span>
            </div>
            <div style={{ padding:'4px 0 8px' }}>
              {(d?.malicious_domains || []).slice(0,6).map((item,i) => (
                <div key={i} style={{ padding:'6px 16px', borderBottom:'1px solid color-mix(in srgb, var(--border) 30%, transparent)' }}>
                  <div style={{ fontSize:11, color:'var(--orange)', fontFamily:'DM Mono, monospace',
                    overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{item.title}</div>
                  <div style={{ fontSize:10, color:'var(--text3)', marginTop:2 }}>{item.host} · {item.created_at ? new Date(item.created_at).toLocaleTimeString() : ''}</div>
                </div>
              ))}
              {(!d?.malicious_domains || d.malicious_domains.length === 0) && (
                <div style={{ padding:'20px 16px', color:'var(--green)', fontSize:12, display:'flex', alignItems:'center', gap:6 }}>
                  <span>✓</span> No malicious domains detected
                </div>
              )}
            </div>
          </div>

          {/* Malicious Files */}
          <div className="card">
            <div className="card-head" style={{ color:'var(--yellow)' }}>
              ⚠ Malicious Files
              <span style={{ fontFamily:'DM Mono, monospace', color:'var(--text3)', fontSize:10, fontWeight:400, textTransform:'none', letterSpacing:0 }}>
                {(d?.malicious_files||[]).length} detected
              </span>
            </div>
            <div style={{ padding:'4px 0 8px' }}>
              {(d?.malicious_files || []).slice(0,6).map((item,i) => (
                <div key={i} style={{ padding:'6px 16px', borderBottom:'1px solid color-mix(in srgb, var(--border) 30%, transparent)' }}>
                  <div style={{ fontSize:11, color:'var(--yellow)', fontFamily:'DM Mono, monospace',
                    overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{item.title}</div>
                  <div style={{ fontSize:10, color:'var(--text3)', marginTop:2 }}>{item.host} · {item.created_at ? new Date(item.created_at).toLocaleTimeString() : ''}</div>
                </div>
              ))}
              {(!d?.malicious_files || d.malicious_files.length === 0) && (
                <div style={{ padding:'20px 16px', color:'var(--green)', fontSize:12, display:'flex', alignItems:'center', gap:6 }}>
                  <span>✓</span> No malicious files detected
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Row 5: Recent Alerts + Agent Health + DevOps ── */}
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12 }}>

          {/* Recent Alerts */}
          <div className="card">
            <div className="card-head">
              Recent Alerts
              <button onClick={() => navigate('/alerts')}
                style={{ fontSize:10, color:'var(--accent)', background:'none', border:'none', cursor:'pointer' }}>All →</button>
            </div>
            <div style={{ overflowY:'auto', maxHeight:240 }}>
              {(d?.recent_alerts || []).length === 0
                ? <div style={{ padding:20, color:'var(--green)', fontSize:12, display:'flex', alignItems:'center', gap:6 }}>
                    <span>✓</span> No open alerts
                  </div>
                : (d?.recent_alerts || []).map((a,i) => (
                    <div key={i} style={{ display:'flex', alignItems:'flex-start', gap:8, padding:'8px 16px',
                      borderBottom:'1px solid color-mix(in srgb, var(--border) 25%, transparent)',
                      cursor:'pointer', transition:'background 0.1s' }}
                      onClick={() => navigate('/alerts')}
                      onMouseEnter={e=>e.currentTarget.style.background='rgba(56,189,248,0.03)'}
                      onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                      <span className={`sev sev-${a.severity||1}`} style={{ flexShrink:0, marginTop:1 }}>
                        {['','INFO','LOW','MED','HIGH','CRIT'][a.severity||1]}
                      </span>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ fontSize:11.5, fontWeight:500, color:'var(--text)',
                          overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{a.title}</div>
                        <div style={{ fontSize:10, color:'var(--text3)', marginTop:1 }}>
                          {a.host} · {a.created_at ? new Date(a.created_at).toLocaleTimeString() : ''}
                        </div>
                      </div>
                    </div>
                  ))
              }
            </div>
          </div>

          {/* Agent Health */}
          <div className="card">
            <div className="card-head">
              Agent Health
              <button onClick={() => navigate('/agents')}
                style={{ fontSize:10, color:'var(--accent)', background:'none', border:'none', cursor:'pointer' }}>Fleet →</button>
            </div>
            <div style={{ overflowY:'auto', maxHeight:240 }}>
              {(raw?.endpoint_agents || []).slice(0,8).map((a,i) => (
                <div key={i} style={{ display:'flex', alignItems:'center', gap:10, padding:'7px 16px',
                  borderBottom:'1px solid color-mix(in srgb, var(--border) 25%, transparent)',
                  cursor:'pointer', transition:'background 0.1s' }}
                  onClick={() => navigate(`/agents?host=${encodeURIComponent(a.hostname)}`)}
                  onMouseEnter={e=>e.currentTarget.style.background='rgba(56,189,248,0.03)'}
                  onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                  <span style={{ width:7, height:7, borderRadius:'50%', flexShrink:0,
                    background: a.online ? 'var(--green)' : 'var(--text3)' }}
                    className={a.online ? 'pulse' : ''}/>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ fontSize:11.5, fontWeight:500, color:'var(--text)',
                      fontFamily:'DM Mono, monospace', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {a.hostname}
                    </div>
                    <div style={{ fontSize:10, color:'var(--text3)', marginTop:1 }}>{a.os}</div>
                  </div>
                  <span style={{ fontSize:10, color: a.online ? 'var(--green)' : 'var(--text3)', flexShrink:0 }}>
                    {a.online ? 'Online' : 'Offline'}
                  </span>
                </div>
              ))}
              {(!raw?.endpoint_agents || raw.endpoint_agents.length === 0) && (
                <div style={{ padding:20, color:'var(--text3)', fontSize:12, fontStyle:'italic', textAlign:'center' }}>No agents</div>
              )}
            </div>
          </div>

          {/* DevOps Overview */}
          <div className="card">
            <div className="card-head">
              DevOps Overview
              <button onClick={() => navigate('/devops')}
                style={{ fontSize:10, color:'var(--accent)', background:'none', border:'none', cursor:'pointer' }}>DevOps →</button>
            </div>
            <div style={{ padding:'8px 0' }}>
              {(d?.devops_overview || []).length === 0
                ? <div style={{ padding:'16px 16px', color:'var(--text3)', fontSize:12, fontStyle:'italic' }}>
                    No DevOps connectors configured
                  </div>
                : (d?.devops_overview || []).map((dc,i) => (
                    <div key={i} style={{ padding:'8px 16px', borderBottom:'1px solid color-mix(in srgb, var(--border) 25%, transparent)' }}>
                      <div style={{ display:'flex', justifyContent:'space-between', marginBottom:6 }}>
                        <span style={{ fontSize:12, fontWeight:600, color:'var(--text)' }}>
                          {dc.provider} · {dc.org}
                        </span>
                        <span className="tag">{Number(dc.repos_scanned||0)} repos</span>
                      </div>
                      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
                        {[
                          { label:'Findings',  value: dc.findings,  color:'var(--yellow)' },
                          { label:'Critical',  value: dc.critical,  color:'var(--red)' },
                        ].map(m => (
                          <div key={m.label} style={{ background:'var(--surface2)', borderRadius:7, padding:'6px 10px' }}>
                            <div style={{ fontSize:9, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.08em' }}>{m.label}</div>
                            <div style={{ fontSize:16, fontWeight:600, color: Number(m.value) > 0 ? m.color : 'var(--text3)',
                              fontFamily:'DM Mono, monospace', marginTop:2 }}>{Number(m.value||0)}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))
              }
            </div>
          </div>
        </div>

        </>}

      </div>
    </div>
  )
}
