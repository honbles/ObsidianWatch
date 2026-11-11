import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Zap, Shield, ChevronDown, ChevronUp, ExternalLink, ToggleLeft, ToggleRight,
         RefreshCw, Globe, AlertCircle, CheckCircle, Clock, Monitor, Server, Apple, Cloud, GitBranch, Wifi, Code, Filter, Trash2 } from 'lucide-react'
import api from '../api/client'

const SEV_LABEL = { 1:'Info', 2:'Low', 3:'Medium', 4:'High', 5:'Critical' }
const SEV_COLOR = {
  1: 'text-gray-400 bg-gray-800/40 border-gray-700',
  2: 'text-blue-400 bg-blue-900/30 border-blue-700',
  3: 'text-yellow-400 bg-yellow-900/30 border-yellow-700',
  4: 'text-orange-400 bg-orange-900/30 border-orange-700',
  5: 'text-red-400 bg-red-900/30 border-red-700',
}
const CAT_COLOR = {
  'Execution':            'text-purple-400',
  'Discovery':            'text-blue-400',
  'Privilege Escalation': 'text-orange-400',
  'Credential Access':    'text-red-400',
  'Lateral Movement':     'text-yellow-400',
  'Persistence':          'text-pink-400',
  'Defence Evasion':      'text-indigo-400',
  'Command and Control':  'text-cyan-400',
  'Command & Control':    'text-cyan-400',
  'Exfiltration':         'text-green-400',
  'Impact':               'text-red-500',
  'Initial Access':       'text-rose-400',
  'Reconnaissance':       'text-sky-400',
  'Data Loss Prevention': 'text-teal-400',
}

// Signature ID prefixes map to OS
const sigOS = id => {
  if (id.startsWith('L-'))       return 'linux'
  if (id.startsWith('W-'))       return 'windows'
  if (id.startsWith('M-'))       return 'macos'
  if (id.startsWith('DNS-'))     return 'all'
  if (id.startsWith('C-') || id.startsWith('cloud')) return 'cloud'
  if (id.startsWith('DC-')) return 'dc'
  if (id.startsWith('DEV-')) return 'devops'
  if (id.startsWith('NET-')) return 'network'
  return 'all'
}

// Label lookup for Azure sub-categories in the cloud tab
const AZURE_SIG_LABELS = {
  'C-AZ-IAM':   'Entra ID / Identity',
  'C-AZ-COMP':  'Compute / AKS',
  'C-AZ-DATA':  'Data & Storage',
  'C-AZ-NET':   'Network',
  'C-AZ-EVA':   'Defense Evasion',
  'C-AZ-DEF':   'Defender',
  'C-AZ-AUDIT': 'Entra Audit',
}
const azureSigGroup = id => {
  for (const [prefix, label] of Object.entries(AZURE_SIG_LABELS)) {
    if (id.startsWith(prefix)) return label
  }
  return null
}

const OS_TABS = [
  { id: 'linux',   label: 'Linux',   icon: Server,  color: 'text-orange-400',  prefix: 'L-' },
  { id: 'windows', label: 'Windows', icon: Monitor, color: 'text-blue-400',    prefix: 'W-' },
  { id: 'macos',   label: 'macOS',   icon: Apple,   color: 'text-gray-300',    prefix: 'M-' },
  { id: 'cloud',   label: 'Cloud',   icon: Cloud,   color: 'text-cyan-400',    prefix: 'C-' },
  { id: 'dc',      label: 'Domain Controller', icon: Shield,    color: 'text-purple-400', prefix: 'DC-' },
  { id: 'devops',  label: 'DevOps',             icon: GitBranch, color: 'text-emerald-400', prefix: 'DEV-' },
  { id: 'network', label: 'Network',            icon: Wifi,      color: 'text-cyan-400',    prefix: 'NET-' },
  { id: 'all',     label: 'All Platforms', icon: Globe, color: 'text-cyan-400', prefix: 'DNS-' },
  { id: 'sources', label: 'Intel Sources', icon: Globe,  color: 'text-purple-400', prefix: null },
  { id: 'sast',    label: 'SAST Rules',   icon: Code,   color: 'text-emerald-400', prefix: null },
  { id: 'sigma',   label: 'Sigma Rules',  icon: Zap,    color: 'text-purple-400',  prefix: null },
]

const SOURCE_META = {
  threatfox: {
    label: 'Abuse.ch ThreatFox',
    desc: 'Known malware C2 IPs, domains and file hashes. Updated daily. Free API key required.',
    color: 'text-orange-400',
    needsKey: true,
    keyPlaceholder: 'ThreatFox API key (free at threatfox.abuse.ch)',
  },
  otx: {
    label: 'AlienVault OTX',
    desc: 'Open Threat Exchange — community threat pulses with IPs, domains and hashes.',
    color: 'text-blue-400',
    needsKey: true,
    keyPlaceholder: 'OTX API key (free at otx.alienvault.com)',
  },
  sigma: {
    label: 'Sigma Rules',
    desc: 'Community detection rules from SigmaHQ. Maps to MITRE ATT&CK. Pulled from GitHub.',
    color: 'text-purple-400',
    needsKey: false,
  },
}

function SourceCard({ source, onUpdate, onSync }) {
  const meta = SOURCE_META[source.name] || {}
  const [apiKey, setApiKey] = useState('')
  const [showKey, setShowKey] = useState(false)
  const [syncing, setSyncing] = useState(false)

  const toggle = () => onUpdate(source.name, { enabled: !source.enabled })
  const saveKey = async () => {
    if (apiKey) {
      await onUpdate(source.name, { api_key: apiKey, enabled: source.enabled })
      setApiKey(''); setShowKey(false)
    }
  }
  const sync = async () => {
    setSyncing(true)
    try { await onSync(source.name) } finally { setTimeout(() => setSyncing(false), 2000) }
  }
  const [pinPrefix, setPinPrefix] = useState('')
  const [pinMsg, setPinMsg] = useState('')
  const pinSeen = async () => {
    setPinMsg('')
    try {
      await api.post('/api/v1/threat-intel-sources/sigma/pin-seen', { prefix: pinPrefix })
      setPinMsg('Pinned. Press Sync now.'); setPinPrefix('')
    } catch (e) { setPinMsg(e?.response?.data?.error || 'Could not pin') }
  }
  const lastSync = source.last_sync ? new Date(source.last_sync).toLocaleString() : null

  return (
    <div className={`bg-siem-surface border rounded-xl p-4 space-y-3 ${source.enabled ? 'border-siem-accent/30' : 'border-siem-border'}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <Globe size={14} className={meta.color || 'text-siem-muted'} />
          <span className={`text-sm font-semibold ${meta.color || 'text-siem-text'}`}>{meta.label || source.name}</span>
          {source.enabled && source.ioc_count > 0 && (
            <span className="text-xs text-siem-green bg-siem-green/10 border border-siem-green/20 rounded px-1.5 py-0.5">
              {source.ioc_count.toLocaleString()} IOCs
            </span>
          )}
        </div>
        <button onClick={toggle}>
          {source.enabled
            ? <ToggleRight size={22} className="text-siem-green" />
            : <ToggleLeft  size={22} className="text-siem-muted" />}
        </button>
      </div>
      <p className="text-xs text-siem-muted leading-relaxed">{meta.desc}</p>
      <div className="flex items-center gap-3 text-xs">
        {source.last_error
          ? <span className="flex items-center gap-1 text-red-400"><AlertCircle size={11}/> Error</span>
          : lastSync
            ? <span className="flex items-center gap-1 text-siem-green"><CheckCircle size={11}/> Synced</span>
            : <span className="flex items-center gap-1 text-siem-muted"><Clock size={11}/> Never synced</span>}
        {lastSync && <span className="text-siem-muted">{lastSync}</span>}
        {source.last_error && <span className="text-red-400 truncate max-w-xs" title={source.last_error}>{source.last_error}</span>}
      </div>
      {source.name === 'sigma' && source.last_error && /integrity check failed/.test(source.last_error) && (
        <div className="text-xs space-y-1.5 border border-siem-border rounded-lg p-2">
          <div className="text-siem-muted">Open the release page, find sigma_core.zip, and type the first 8 characters of its sha256. If they match what the server downloaded, it is pinned for you.</div>
          <div className="flex gap-2">
            <input value={pinPrefix} onChange={e => setPinPrefix(e.target.value)} placeholder="first 8 characters, e.g. 45ccbd62"
              className="flex-1 bg-siem-bg border border-siem-border rounded px-3 py-1.5 text-xs text-siem-text focus:outline-none focus:border-siem-accent" />
            <button onClick={pinSeen} disabled={pinPrefix.trim().length < 8}
              className="px-3 py-1.5 bg-siem-accent text-white rounded text-xs disabled:opacity-40">Confirm &amp; pin</button>
          </div>
          {pinMsg && <div className="text-siem-muted">{pinMsg}</div>}
        </div>
      )}
      {meta.needsKey && source.enabled && (
        <div>
          {source.has_api_key && !showKey ? (
            <div className="flex items-center gap-2">
              <span className="text-xs text-siem-green flex items-center gap-1"><CheckCircle size={11}/> API key configured</span>
              <button onClick={() => setShowKey(true)} className="text-xs text-siem-accent hover:underline">Change</button>
            </div>
          ) : (
            <div className="flex gap-2">
              <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)}
                placeholder={meta.keyPlaceholder}
                className="flex-1 bg-siem-bg border border-siem-border rounded px-3 py-1.5 text-xs text-siem-text placeholder-siem-muted focus:outline-none focus:border-siem-accent" />
              <button onClick={saveKey} disabled={!apiKey}
                className="px-3 py-1.5 bg-siem-accent text-white rounded text-xs disabled:opacity-40">Save</button>
            </div>
          )}
        </div>
      )}
      {source.enabled && (
        <button onClick={sync} disabled={syncing}
          className="flex items-center gap-1.5 text-xs text-siem-accent hover:text-siem-accent/80 disabled:opacity-50">
          <RefreshCw size={11} className={syncing ? 'animate-spin' : ''} />
          {syncing ? 'Syncing...' : 'Sync now'}
        </button>
      )}
    </div>
  )
}

function Backtest({ sigId }) {
  const [res, setRes] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const run = async () => {
    setBusy(true); setErr('')
    try { setRes((await api.post(`/api/v1/detections/${sigId}/backtest?hours=24`)).data) }
    catch (e) { setErr(e?.response?.data?.error || 'Backtest failed') }
    finally { setBusy(false) }
  }
  return (
    <div className="mt-3">
      <button onClick={run} disabled={busy}
        className="text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-3 py-1.5 disabled:opacity-40">
        {busy ? 'Replaying…' : 'Backtest last 24h'}
      </button>
      {err && <span className="text-xs text-red-400 ml-3">{err}</span>}
      {res && (
        <div className="mt-2 text-xs text-siem-muted">
          <div><span className="text-siem-text">{res.matches}</span> matches in {res.events_scanned.toLocaleString()} events
            {res.truncated ? ' (scan capped)' : ''} — about <span className="text-siem-text">{Math.round(res.estimated_per_day)}</span> per day.</div>
          {res.top_hosts?.length > 0 && <div>Top hosts: {res.top_hosts.slice(0, 5).map(h => `${h.host} (${h.count})`).join(', ')}</div>}
          <div className="opacity-70">{res.note}</div>
        </div>
      )}
    </div>
  )
}

function SigList({ sigs, toggling, onToggle, expanded, onExpand }) {
  const byCat = {}
  sigs.forEach(s => {
    if (!byCat[s.category]) byCat[s.category] = []
    byCat[s.category].push(s)
  })

  if (sigs.length === 0) {
    return <div className="text-siem-muted text-sm text-center py-12">No signatures match your filters.</div>
  }

  return (
    <div className="space-y-4">
      {Object.entries(byCat).map(([cat, catSigs]) => (
        <div key={cat}>
          <div className={`flex items-center gap-2 mb-2 text-sm font-semibold ${CAT_COLOR[cat] || 'text-siem-text'}`}>
            <Shield size={14} />
            {cat}
            <span className="text-siem-muted text-xs font-normal">
              ({catSigs.filter(s => s.enabled).length}/{catSigs.length} active)
            </span>
          </div>
          <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
            {catSigs.map(sig => (
              <div key={sig.id} className={`border-b border-siem-border/40 last:border-0 transition-opacity ${!sig.enabled ? 'opacity-50' : ''}`}>
                <div className="flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02] transition-colors">
                  <button onClick={e => onToggle(sig, e)} disabled={toggling[sig.id]} className="shrink-0 hover:opacity-80">
                    {sig.enabled
                      ? <ToggleRight size={20} className="text-siem-green" />
                      : <ToggleLeft  size={20} className="text-siem-muted" />}
                  </button>
                  <button className="flex items-center gap-3 flex-1 text-left min-w-0"
                    onClick={() => onExpand(sig.id)}>
                    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium whitespace-nowrap ${SEV_COLOR[sig.severity]}`}>
                      {SEV_LABEL[sig.severity]}
                    </span>
                    <span className={`text-sm font-medium flex-1 truncate ${sig.enabled ? 'text-siem-text' : 'text-siem-muted line-through'}`}>
                      {sig.name}
                    </span>
                    <span className="text-siem-muted text-xs font-mono shrink-0">{sig.mitre}</span>
                    {expanded === sig.id
                      ? <ChevronUp   size={14} className="text-siem-muted shrink-0" />
                      : <ChevronDown size={14} className="text-siem-muted shrink-0" />}
                  </button>
                </div>
                {expanded === sig.id && (
                  <div className="px-4 pb-4 pt-1 bg-siem-bg/40 border-t border-siem-border/30">
                    <p className="text-siem-muted text-sm mb-3">{sig.description}</p>
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="text-xs text-siem-muted">MITRE ATT&CK:</span>
                      <a href={`https://attack.mitre.org/techniques/${sig.mitre.replace('.','/')}/`}
                        target="_blank" rel="noopener noreferrer"
                        className="flex items-center gap-1 text-xs text-siem-accent hover:underline">
                        {sig.mitre} <ExternalLink size={10}/>
                      </a>
                      <span className="text-xs text-siem-muted ml-2">Category: <span className="text-siem-text">{sig.category}</span></span>
                      <span className="text-xs text-siem-muted ml-2">
                        Status: {sig.enabled
                          ? <span className="text-siem-green">Active</span>
                          : <span className="text-red-400">Disabled</span>}
                      </span>
                    </div>
                    <Backtest sigId={sig.id}/>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

export default function Detections() {
  const [sigs, setSigs]       = useState([])
  const [sources, setSources] = useState([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(null)
  const [catFilter, setCatFilter]   = useState('')
  const [sevFilter, setSevFilter]   = useState(0)
  const [statusFilter, setStatusFilter] = useState('all')
  const [toggling, setToggling] = useState({})
  const [sigmaEnabled, setSigmaEnabled] = useState(true)
  const [sigmaCount, setSigmaCount] = useState(0)
  const [sigmaToggling, setSigmaToggling] = useState(false)
  const [osTab, setOsTab] = useState('linux')
  const navigate = useNavigate()
  // Suppression rules (GCP cloud tab)
  const [suppressRules, setSuppressRules] = useState([])
  const [suppressLoading, setSuppressLoading] = useState(false)
  const [showSuppressForm, setShowSuppressForm] = useState(false)
  const [suppressForm, setSuppressForm] = useState({ description:'', sig_id:'', principal:'', src_ip_prefix:'', method_contains:'', expires_days:'' })
  const [suppressSaving, setSuppressSaving] = useState(false)

  const fetchAll = () => {
    Promise.all([
      api.get('/api/v1/detections'),
      api.get('/api/v1/threat-intel-sources'),
    ]).then(([sigsRes, sourcesRes]) => {
      setSigs(sigsRes.data.signatures || [])
      setSources(sourcesRes.data.sources || [])
      setSigmaEnabled(sigsRes.data.sigma_enabled !== false)
      setSigmaCount(sigsRes.data.sigma_count || 0)
    }).finally(() => setLoading(false))
  }

  useEffect(() => { fetchAll() }, [])

  const loadSuppress = () => {
    setSuppressLoading(true)
    api.get('/api/v1/cloud-connectors/suppress')
      .then(r => setSuppressRules(Array.isArray(r.data) ? r.data : []))
      .catch(() => setSuppressRules([]))
      .finally(() => setSuppressLoading(false))
  }

  const deleteSuppress = async (id) => {
    await api.delete(`/api/v1/cloud-connectors/suppress/${id}`).catch(() => {})
    setSuppressRules(r => r.filter(x => x.id !== id))
  }

  const saveSuppress = async () => {
    if (!suppressForm.description) return
    if (!suppressForm.sig_id && !suppressForm.principal && !suppressForm.src_ip_prefix && !suppressForm.method_contains) return
    setSuppressSaving(true)
    try {
      const payload = { ...suppressForm }
      if (suppressForm.expires_days) {
        const d = new Date(); d.setDate(d.getDate() + parseInt(suppressForm.expires_days))
        payload.expires_at = d.toISOString()
      }
      if (payload.expires_days !== undefined) delete payload.expires_days
      await api.post('/api/v1/cloud-connectors/suppress', payload)
      setShowSuppressForm(false)
      setSuppressForm({ description:'', sig_id:'', principal:'', src_ip_prefix:'', method_contains:'', expires_days:'' })
      loadSuppress()
    } finally { setSuppressSaving(false) }
  }

  const toggle = async (sig, e) => {
    e.stopPropagation()
    setToggling(t => ({ ...t, [sig.id]: true }))
    try {
      await api.patch(`/api/v1/detections/${sig.id}`, { enabled: !sig.enabled })
      setSigs(prev => prev.map(s => s.id === sig.id ? { ...s, enabled: !s.enabled } : s))
    } finally { setToggling(t => ({ ...t, [sig.id]: false })) }
  }

  const updateSource = async (name, body) => {
    await api.patch(`/api/v1/threat-intel-sources/${name}`, body)
    const res = await api.get('/api/v1/threat-intel-sources')
    setSources(res.data.sources || [])
  }

  const toggleSigma = async () => {
    setSigmaToggling(true)
    try {
      await api.post('/api/v1/detections/sigma/toggle', { enabled: !sigmaEnabled })
      setSigmaEnabled(e => !e)
    } finally { setSigmaToggling(false) }
  }

  const syncSource = async (name) => {
    await api.post(`/api/v1/threat-intel-sources/${name}/sync`)
    setTimeout(async () => {
      const res = await api.get('/api/v1/threat-intel-sources')
      setSources(res.data.sources || [])
    }, 3000)
  }

  // Filter sigs for current OS tab
  // SAST rules state
  const [sastRules, setSastRules] = useState([])
  const [sastLangFilter, setSastLangFilter] = useState('all')
  const [sastSevFilter, setSastSevFilter] = useState('all')
  const [sastSearch, setSastSearch] = useState('')

  useEffect(() => {
    if (osTab === 'sast' && sastRules.length === 0) {
      api.get('/api/v1/sast-rules').then(r => setSastRules(r.data.rules || [])).catch(() => {})
    }
    if (osTab === 'cloud') {
      loadSuppress()
    }
  }, [osTab])

  const osSigs = (osTab === 'sources' || osTab === 'sast') ? [] : sigs.filter(s => sigOS(s.id) === osTab)

  const filtered = (osTab === 'sast' || osTab === 'sources') ? [] : osSigs.filter(s =>
    (catFilter === '' || s.category === catFilter) &&
    (sevFilter === 0 || s.severity >= sevFilter) &&
    (statusFilter === 'all' || (statusFilter === 'enabled' ? s.enabled : !s.enabled))
  )

  const categories = [...new Set(osSigs.map(s => s.category))]
  const enabledCount = osSigs.filter(s => s.enabled).length
  const totalIOCs = sources.reduce((sum, s) => sum + (s.ioc_count || 0), 0)
  const enabledSources = sources.filter(s => s.enabled).length

  // Per-OS counts for tab badges
  const osCounts = OS_TABS.reduce((acc, t) => {
    if (t.id === 'sources' || t.id === 'sast') return acc
    const all  = sigs.filter(s => sigOS(s.id) === t.id)
    const on   = all.filter(s => s.enabled)
    acc[t.id] = { total: all.length, enabled: on.length }
    return acc
  }, {})

  return (
    <div className="p-6 space-y-5">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Zap className="text-siem-accent" size={20} />
          <h1 className="text-xl font-bold text-siem-text">Threat Detection</h1>
        </div>
        <div className="flex items-center gap-2 text-xs">
          {totalIOCs > 0 && (
            <span className="text-orange-400 bg-orange-900/20 border border-orange-700/30 rounded px-2 py-0.5">
              {totalIOCs.toLocaleString()} IOCs loaded
            </span>
          )}
          {enabledSources > 0 && (
            <span className="text-blue-400 bg-blue-900/20 border border-blue-700/30 rounded px-2 py-0.5">
              {enabledSources} intel source{enabledSources !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>

      {/* OS Tabs */}
      <div className="flex gap-1 bg-siem-surface border border-siem-border rounded-xl p-1 w-fit flex-wrap">
        {OS_TABS.map(({ id, label, icon: Icon, color }) => {
          const counts = osCounts[id]
          return (
            <button key={id} onClick={() => { setOsTab(id); setCatFilter(''); setSevFilter(0); setStatusFilter('all') }}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                osTab === id ? 'bg-siem-accent text-white' : 'text-siem-muted hover:text-siem-text'
              }`}>
              <Icon size={12} className={osTab === id ? '' : color} />
              {label}
              {counts && (
                <span className={`text-[10px] ${osTab === id ? 'text-white/70' : 'text-siem-muted'}`}>
                  {counts.enabled}/{counts.total}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* Intel Sources Panel */}
      {osTab === 'sources' && (
        <div className="space-y-3">
          <p className="text-xs text-siem-muted">
            Enable sources to automatically pull IOCs (IPs, domains, hashes). Syncs daily.
            Matched IOCs trigger alerts automatically on all platforms.
          </p>
          <div className="grid grid-cols-3 gap-4">
            {sources.map(s => (
              <SourceCard key={s.name} source={s} onUpdate={updateSource} onSync={syncSource} />
            ))}
          </div>
        </div>
      )}

      {/* Sigma Rules Panel */}
      {osTab === 'sigma' && (
        <div className="space-y-4">
          <div className="bg-siem-surface border border-siem-border rounded-xl p-6 flex items-center justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <span className="text-lg font-semibold text-siem-text">Sigma Rules</span>
                <span className="text-xs px-2 py-0.5 bg-purple-950/30 border border-purple-800/30 text-purple-400 rounded-full">{sigmaCount.toLocaleString()} rules</span>
              </div>
              <p className="text-sm text-siem-muted">Community detection rules from SigmaHQ mapped to MITRE ATT&CK. Covers Windows, Linux and macOS threats. Rules are matched against process, file, network and registry events.</p>
              <p className="text-xs text-siem-muted/60 mt-2">Rules are deduplicated per host per hour — same rule will not alert more than once per hour per host.</p>
            </div>
            <div className="ml-8 flex flex-col items-center gap-2">
              <button
                onClick={toggleSigma}
                disabled={sigmaToggling}
                className={`relative w-14 h-7 rounded-full transition-colors duration-200 focus:outline-none ${sigmaEnabled ? 'bg-siem-accent' : 'bg-siem-border'}`}
              >
                <span className={`absolute top-0.5 left-0.5 w-6 h-6 bg-white rounded-full shadow transition-transform duration-200 ${sigmaEnabled ? 'translate-x-7' : 'translate-x-0'}`}/>
              </button>
              <span className={`text-xs font-medium ${sigmaEnabled ? 'text-siem-accent' : 'text-siem-muted'}`}>
                {sigmaToggling ? '...' : sigmaEnabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* SAST Rules Panel */}
      {osTab === 'sast' && (
        <div className="space-y-4">
          <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
            <div className="flex items-center gap-2.5 mb-1">
              <Code size={15} className="text-emerald-400"/>
              <span className="text-sm font-semibold text-emerald-400">SAST Rule Library</span>
              <span className="ml-auto text-[10px] text-siem-muted border border-siem-border rounded-full px-2 py-0.5">
                {sastRules.length} rules
              </span>
            </div>
            <p className="text-[11px] text-siem-muted">
              Static analysis rules used when scanning DevOps connector repositories.
              Covers OWASP Top 10 and CWE categories across Python, JavaScript/TypeScript, Go, Java, PHP, C/C++, Ruby, C#, Rust, and IaC.
              Run scans from the DevOps → SAST tab.
            </p>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex gap-1 flex-wrap">
              {['all','python','javascript','go','java','php','c','ruby','csharp','rust','any'].map(lang => (
                <button key={lang} onClick={() => setSastLangFilter(lang)}
                  className={`text-[10px] px-2.5 py-1 rounded-full border transition-colors capitalize ${
                    sastLangFilter === lang
                      ? 'bg-siem-accent border-siem-accent text-white'
                      : 'border-siem-border text-siem-muted hover:text-siem-text'
                  }`}>
                  {lang === 'javascript' ? 'JS/TS' : lang === 'csharp' ? 'C#' : lang}
                </button>
              ))}
            </div>
            <div className="flex gap-1">
              {['all','critical','high','medium','low','info'].map(sev => (
                <button key={sev} onClick={() => setSastSevFilter(sev)}
                  className={`text-[10px] px-2.5 py-1 rounded-full border transition-colors capitalize ${
                    sastSevFilter === sev
                      ? 'bg-siem-accent border-siem-accent text-white'
                      : 'border-siem-border text-siem-muted hover:text-siem-text'
                  }`}>{sev}</button>
              ))}
            </div>
            <input value={sastSearch} onChange={e => setSastSearch(e.target.value)}
              placeholder="Search rules…"
              className="ml-auto bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text placeholder-siem-muted/40 outline-none focus:border-siem-accent w-48"/>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-6 gap-2">
            {[
              ['Critical', sastRules.filter(r=>r.severity==='critical').length, 'text-red-400'],
              ['High',     sastRules.filter(r=>r.severity==='high').length,     'text-orange-400'],
              ['Medium',   sastRules.filter(r=>r.severity==='medium').length,   'text-yellow-400'],
              ['Python',   sastRules.filter(r=>r.lang==='python').length,       'text-blue-400'],
              ['JS/TS',    sastRules.filter(r=>r.lang==='javascript').length,   'text-yellow-300'],
              ['Go',       sastRules.filter(r=>r.lang==='go').length,           'text-cyan-400'],
            ].map(([label, count, color]) => (
              <div key={label} className="bg-siem-surface border border-siem-border rounded-xl p-2.5 text-center">
                <div className={`text-lg font-bold font-mono ${color}`}>{count}</div>
                <div className="text-[9px] text-siem-muted uppercase tracking-wide">{label}</div>
              </div>
            ))}
          </div>

          {/* Rules table */}
          <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
            <div className="px-4 py-2.5 border-b border-siem-border/40 flex items-center gap-2">
              <Filter size={12} className="text-siem-muted"/>
              <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">
                {sastRules.filter(r =>
                  (sastLangFilter === 'all' || r.lang === sastLangFilter) &&
                  (sastSevFilter === 'all' || r.severity === sastSevFilter) &&
                  (!sastSearch || r.title.toLowerCase().includes(sastSearch.toLowerCase()) || r.cwe.toLowerCase().includes(sastSearch.toLowerCase()))
                ).length} rules matching
              </span>
            </div>
            <div className="divide-y divide-siem-border/20 max-h-[600px] overflow-y-auto">
              {sastRules
                .filter(r =>
                  (sastLangFilter === 'all' || r.lang === sastLangFilter) &&
                  (sastSevFilter === 'all' || r.severity === sastSevFilter) &&
                  (!sastSearch || r.title.toLowerCase().includes(sastSearch.toLowerCase()) ||
                   r.cwe.toLowerCase().includes(sastSearch.toLowerCase()) ||
                   r.detail.toLowerCase().includes(sastSearch.toLowerCase()))
                )
                .sort((a,b) => {
                  const o = {critical:0,high:1,medium:2,low:3,info:4}
                  return (o[a.severity]??5)-(o[b.severity]??5)
                })
                .map(rule => {
                  const sevColor = {critical:'text-red-400',high:'text-orange-400',medium:'text-yellow-400',low:'text-blue-400',info:'text-siem-muted'}[rule.severity]||'text-siem-muted'
                  const sevBg = {critical:'bg-red-950/20 border-red-800/30',high:'bg-orange-950/15 border-orange-800/25',medium:'bg-yellow-950/10 border-yellow-800/20',low:'bg-blue-950/10 border-blue-800/20',info:'bg-siem-bg border-siem-border/30'}[rule.severity]||'bg-siem-bg border-siem-border/30'
                  const langColor = {python:'text-blue-400',javascript:'text-yellow-300',go:'text-cyan-400',java:'text-orange-300',php:'text-purple-400',c:'text-gray-300',ruby:'text-red-400',csharp:'text-green-400',rust:'text-orange-500',any:'text-siem-muted'}[rule.lang]||'text-siem-muted'
                  return (
                    <div key={rule.id} className="px-4 py-3 hover:bg-white/[0.02]">
                      <div className="flex items-start gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1 flex-wrap">
                            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${sevBg} ${sevColor}`}>{rule.severity}</span>
                            <span className={`text-[9px] font-semibold uppercase ${langColor}`}>
                              {rule.lang === 'javascript' ? 'JS/TS' : rule.lang === 'csharp' ? 'C#' : rule.lang}
                            </span>
                            <span className="text-[9px] font-mono text-siem-muted/50 border border-siem-border/30 rounded px-1.5 py-0.5">{rule.id}</span>
                            {rule.cwe && <span className="text-[9px] text-violet-400/70">{rule.cwe}</span>}
                            {rule.owasp && <span className="text-[9px] text-orange-400/50">OWASP {rule.owasp}</span>}
                            <span className="text-xs font-semibold text-siem-text">{rule.title}</span>
                          </div>
                          <div className="text-[10px] text-siem-muted/70 mb-1">{rule.detail}</div>
                          {rule.fix && (
                            <div className="text-[9px] text-emerald-400/60 bg-emerald-950/10 border border-emerald-800/20 rounded px-2 py-1">
                              Fix: {rule.fix}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )
                })}
            </div>
          </div>
        </div>
      )}

      {/* Signatures Panel */}
      {osTab !== 'sources' && osTab !== 'sast' && (
        <>
          {/* OS description */}
          <div className="text-xs text-siem-muted bg-siem-surface border border-siem-border rounded-xl px-4 py-2.5">
            {osTab === 'linux'   && <><span className="text-orange-400 font-medium">Linux</span> — rules fire on process, journald, network, dns, file, and configmon events. All conditions match against fields actually populated by Linux collectors.</>}
            {osTab === 'windows' && <><span className="text-blue-400 font-medium">Windows</span> — rules fire on ETW process, Sysmon, EventLog, network (iphlpapi), registry, FIM, and DNS events.</>}
            {osTab === 'macos'   && <><span className="text-gray-300 font-medium">macOS</span> — rules fire on process, syslog, network, dns, FSEvents (file), and configmon events.</>}
            {osTab === 'all'     && <><span className="text-cyan-400 font-medium">All Platforms</span> — DNS blocklist rules fire on any dns event regardless of OS. Requires Intel Sources to be synced.</>}
          </div>

          {/* Stats bar */}
          <div className="flex items-center gap-3 text-xs text-siem-muted">
            <span className="text-siem-green font-medium">{enabledCount}</span> active
            <span>·</span>
            <span className="text-red-400 font-medium">{osSigs.length - enabledCount}</span> disabled
            <span>·</span>
            <span className="text-siem-text font-medium">{osSigs.length}</span> total
          </div>

          {/* Category summary cards */}
          {!loading && (
            <div className="flex gap-2 flex-wrap">
              {[...new Set(osSigs.map(s => s.category))].map(cat => {
                const total  = osSigs.filter(s => s.category === cat).length
                const active = osSigs.filter(s => s.category === cat && s.enabled).length
                return (
                  <button key={cat} onClick={() => setCatFilter(catFilter === cat ? '' : cat)}
                    className={`border rounded-lg px-3 py-1.5 text-left transition-colors ${
                      catFilter === cat
                        ? 'border-siem-accent bg-siem-accent/10'
                        : 'border-siem-border bg-siem-surface hover:border-siem-accent/40'
                    }`}>
                    <span className={`text-xs font-bold ${CAT_COLOR[cat] || 'text-siem-text'}`}>{active}/{total}</span>
                    <span className="text-[10px] text-siem-muted ml-1.5">{cat}</span>
                  </button>
                )
              })}
            </div>
          )}

          {/* Filters */}
          <div className="flex gap-2 flex-wrap">
            <select className="bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text focus:outline-none"
              value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
              <option value="all">All status</option>
              <option value="enabled">Enabled only</option>
              <option value="disabled">Disabled only</option>
            </select>
            <select className="bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text focus:outline-none"
              value={catFilter} onChange={e => setCatFilter(e.target.value)}>
              <option value="">All categories</option>
              {categories.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <select className="bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text focus:outline-none"
              value={sevFilter} onChange={e => setSevFilter(Number(e.target.value))}>
              <option value={0}>All severities</option>
              <option value={3}>Medium+</option>
              <option value={4}>High+</option>
              <option value={5}>Critical only</option>
            </select>
          </div>

          {loading
            ? <div className="text-siem-muted text-sm text-center py-12">Loading signatures...</div>
            : <SigList
                sigs={filtered}
                toggling={toggling}
                onToggle={toggle}
                expanded={expanded}
                onExpand={id => setExpanded(expanded === id ? null : id)}
              />
          }

          {/* ── GCP Suppression Rules — shown only in Cloud tab ── */}
          {osTab === 'cloud' && (
            <div className="mt-8 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <Filter size={14} className="text-cyan-400"/>
                    <span className="text-sm font-semibold text-siem-text">GCP Alert Suppression Rules</span>
                    {suppressRules.length > 0 && (
                      <span className="text-xs text-cyan-400 bg-cyan-900/20 border border-cyan-700/30 rounded px-1.5 py-0.5">{suppressRules.length}</span>
                    )}
                  </div>
                  <p className="text-xs text-siem-muted mt-0.5">
                    Suppress noisy-but-legitimate GCP activity (CI/CD SA key creation, internal IPs, trusted principals) without disabling the entire rule.
                  </p>
                </div>
                <button onClick={() => setShowSuppressForm(v => !v)}
                  className="flex items-center gap-1.5 text-xs text-cyan-400 bg-cyan-900/20 border border-cyan-700/30 rounded-lg px-3 py-1.5 hover:bg-cyan-900/30">
                  <Zap size={11}/>{showSuppressForm ? 'Cancel' : '+ New Rule'}
                </button>
              </div>

              {showSuppressForm && (
                <div className="bg-siem-surface border border-cyan-700/20 rounded-xl p-4 space-y-3">
                  <div className="text-xs font-semibold text-cyan-400 uppercase tracking-wide">New Suppression Rule</div>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="col-span-2">
                      <label className="text-[10px] text-siem-muted block mb-1">Description *</label>
                      <input value={suppressForm.description} onChange={e => setSuppressForm(p=>({...p,description:e.target.value}))}
                        placeholder="e.g. CI/CD pipeline SA key creation"
                        className="w-full bg-siem-bg border border-siem-border rounded px-3 py-1.5 text-xs text-siem-text focus:outline-none focus:border-siem-accent"/>
                    </div>
                    {[
                      {k:'sig_id', label:'Sig ID / Prefix', ph:'e.g. C-GCP-025 or C-GCP-0'},
                      {k:'principal', label:'Principal (exact or @suffix)', ph:'e.g. ci-cd@proj.iam.gserviceaccount.com'},
                      {k:'src_ip_prefix', label:'Source IP Prefix', ph:'e.g. 10.128.'},
                      {k:'method_contains', label:'Method Contains', ph:'e.g. CloudBuild'},
                      {k:'expires_days', label:'Expires in days (blank = permanent)', ph:'e.g. 30'},
                    ].map(f => (
                      <div key={f.k}>
                        <label className="text-[10px] text-siem-muted block mb-1">{f.label}</label>
                        <input value={suppressForm[f.k]} onChange={e => setSuppressForm(p=>({...p,[f.k]:e.target.value}))}
                          placeholder={f.ph}
                          className="w-full bg-siem-bg border border-siem-border rounded px-3 py-1.5 text-xs text-siem-text placeholder-siem-muted/50 focus:outline-none focus:border-siem-accent font-mono"/>
                      </div>
                    ))}
                  </div>
                  <div className="flex justify-end">
                    <button onClick={saveSuppress} disabled={suppressSaving || !suppressForm.description}
                      className="px-4 py-1.5 bg-siem-accent text-white rounded-lg text-xs font-semibold disabled:opacity-40">
                      {suppressSaving ? 'Saving…' : 'Save Rule'}
                    </button>
                  </div>
                </div>
              )}

              {suppressLoading ? (
                <div className="text-siem-muted text-xs text-center py-4 flex items-center justify-center gap-2">
                  <RefreshCw size={11} className="animate-spin"/> Loading rules…
                </div>
              ) : suppressRules.length === 0 ? (
                <div className="text-siem-muted text-xs text-center py-6 bg-siem-surface border border-siem-border rounded-xl">
                  No suppression rules. Create one above to stop specific high-volume but legitimate alerts (e.g. CI/CD SA key creation).
                </div>
              ) : (
                <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden divide-y divide-siem-border/30">
                  {suppressRules.map(rule => {
                    const expired = rule.expires_at && new Date(rule.expires_at) < new Date()
                    return (
                      <div key={rule.id} className={`px-4 py-3 flex items-start gap-3 ${expired ? 'opacity-50' : ''}`}>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                            <span className="text-xs font-medium text-siem-text">{rule.description}</span>
                            {expired && <span className="text-[9px] text-red-400 border border-red-700/30 rounded px-1">EXPIRED</span>}
                          </div>
                          <div className="flex gap-1.5 flex-wrap">
                            {rule.sig_id && <span className="text-[9px] font-mono text-purple-400 bg-purple-900/20 border border-purple-700/20 rounded px-1.5 py-0.5">sig: {rule.sig_id}</span>}
                            {rule.principal && <span className="text-[9px] font-mono text-cyan-400 bg-cyan-900/20 border border-cyan-700/20 rounded px-1.5 py-0.5">principal: {rule.principal}</span>}
                            {rule.src_ip_prefix && <span className="text-[9px] font-mono text-yellow-400 bg-yellow-900/20 border border-yellow-700/20 rounded px-1.5 py-0.5">ip: {rule.src_ip_prefix}*</span>}
                            {rule.method_contains && <span className="text-[9px] font-mono text-green-400 bg-green-900/20 border border-green-700/20 rounded px-1.5 py-0.5">method: *{rule.method_contains}*</span>}
                            {rule.expires_at && !expired && <span className="text-[9px] text-siem-muted border border-siem-border rounded px-1.5 py-0.5">expires {new Date(rule.expires_at).toLocaleDateString()}</span>}
                          </div>
                        </div>
                        <button onClick={() => deleteSuppress(rule.id)}
                          className="shrink-0 text-red-400/60 hover:text-red-400 transition-colors p-1">
                          <Trash2 size={13}/>
                        </button>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}
        </>
      )}

    </div>
  )
}
