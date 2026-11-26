import { useEffect, useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Zap, Shield, ChevronDown, ChevronUp, ExternalLink, ToggleLeft, ToggleRight,
         RefreshCw, Globe, AlertCircle, CheckCircle, Clock, Monitor, Server, Apple, Cloud, GitBranch, Wifi, Code, Filter, Trash2 } from 'lucide-react'
import api from '../api/client'
import ManualIOCs from '../components/ManualIOCs'
import { PageHeader, Num, Tabs, Facets, countBy, useFacetFilter, DenseTable, SevPill, StatePill, SelectionBar, useSelection, Drawer, Field } from '../components/ui'

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
    desc: 'Open Threat Exchange - community threat pulses with IPs, domains and hashes.',
    color: 'text-blue-400',
    needsKey: true,
    keyPlaceholder: 'OTX API key (free at otx.alienvault.com)',
  },
  feodo: {
    label: 'Abuse.ch Feodo Tracker',
    desc: 'Botnet command-and-control server IPs (Emotet, QakBot, Dridex and others). Free, no key. Refreshed every sync.',
    color: 'text-red-400',
    needsKey: false,
  },
  spamhaus_bcl: {
    label: 'Spamhaus Botnet Controller List',
    desc: 'Spamhaus BCL botnet C2 servers. Subscription feed: paste the URL Spamhaus gives you.',
    color: 'text-rose-400',
    needsKey: true,
    keyPlaceholder: 'BCL feed URL from your Spamhaus subscription (https://...)',
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
          <div className="text-siem-muted">First 8 characters of sigma_core.zip's SHA-256 from the release page.</div>
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

// SigmaRuleList: the imported SigmaHQ rules, searchable, with a per-rule switch
// so a noisy rule can be turned off without disabling all of Sigma. Rules this
// server cannot evaluate (base64 modifiers, aggregations...) are marked.
function SigmaRuleList() {
  const [data, setData] = useState(null)
  const [q, setQ] = useState('')
  const [level, setLevel] = useState('')
  const [onlyEval, setOnlyEval] = useState(false)
  const [offset, setOffset] = useState(0)
  const [err, setErr] = useState('')
  const limit = 100
  const load = () => {
    api.get('/api/v1/detections/sigma/rules', { params: { q, level, evaluable: onlyEval ? 1 : 0, limit, offset } })
      .then(r => { setData(r.data); setErr('') })
      .catch(e => setErr(e.response?.data?.error || 'Failed to load Sigma rules'))
  }
  useEffect(() => { load() }, [q, level, onlyEval, offset])
  const toggle = async (r) => {
    try {
      await api.patch('/api/v1/detections/sigma/rules/' + encodeURIComponent(r.id), { enabled: !r.enabled })
      setData(d => ({ ...d, rules: d.rules.map(x => x.id === r.id ? { ...x, enabled: !r.enabled } : x) }))
    } catch (e) { setErr(e.response?.data?.error || 'Update failed (admin only)') }
  }
  const lvl = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-amber-400', low: 'text-siem-muted', informational: 'text-siem-muted' }
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl">
      <div className="flex items-center gap-3 flex-wrap px-4 py-3 border-b border-siem-border/40 text-xs">
        <input value={q} onChange={e => { setOffset(0); setQ(e.target.value) }} placeholder="Search title, MITRE, category…"
          className="bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-siem-text w-64" />
        <select value={level} onChange={e => { setOffset(0); setLevel(e.target.value) }} className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1.5 text-siem-text">
          <option value="">All levels</option><option value="critical">Critical</option><option value="high">High</option>
          <option value="medium">Medium</option><option value="low">Low</option>
        </select>
        <label className="flex items-center gap-1.5 text-siem-muted">
          <input type="checkbox" checked={onlyEval} onChange={e => { setOffset(0); setOnlyEval(e.target.checked) }} /> Only rules this server can evaluate
        </label>
        {data && <span className="text-siem-muted ml-auto">{data.total.toLocaleString()} imported · {data.enabled.toLocaleString()} enabled · {data.evaluable.toLocaleString()} evaluable</span>}
      </div>
      {err && <div className="px-4 py-2 text-xs text-red-400">{err}</div>}
      <div className="max-h-[520px] overflow-y-auto">
        {(data?.rules || []).map(r => (
          <div key={r.id} className="flex items-center gap-3 px-4 py-2 border-b border-siem-border/15 text-xs">
            <button onClick={() => toggle(r)} className={`w-9 h-5 rounded-full shrink-0 ${r.enabled ? 'bg-siem-accent' : 'bg-siem-border'}`} title={r.enabled ? 'Disable this rule' : 'Enable this rule'}>
              <span className={`block w-4 h-4 bg-white rounded-full transition-transform ${r.enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
            </button>
            <span className={`w-16 shrink-0 uppercase ${lvl[(r.level || '').toLowerCase()] || 'text-siem-muted'}`}>{r.level}</span>
            <span className="text-siem-text flex-1 truncate" title={r.title}>{r.title}</span>
            <span className="text-siem-muted shrink-0">{r.status}</span>
            <span className="text-siem-muted/70 shrink-0 w-28 truncate" title={r.mitre}>{r.mitre}</span>
            {!r.evaluable && <span className="text-amber-400 shrink-0" title={r.why}>not evaluable</span>}
          </div>
        ))}
        {data && data.rules.length === 0 && <div className="px-4 py-6 text-center text-siem-muted text-xs">No rules match.</div>}
      </div>
      {data && data.matched > limit && (
        <div className="flex items-center justify-between px-4 py-2 text-xs text-siem-muted">
          <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))} className="disabled:opacity-40">← Previous</button>
          <span>{offset + 1}–{Math.min(offset + limit, data.matched)} of {data.matched.toLocaleString()}</span>
          <button disabled={offset + limit >= data.matched} onClick={() => setOffset(offset + limit)} className="disabled:opacity-40">Next →</button>
        </div>
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
            {res.truncated ? ' (scan capped)' : ''} - about <span className="text-siem-text">{Math.round(res.estimated_per_day)}</span> per day.</div>
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
  const [osTab, setOsTab] = useState('signatures')
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
    if (osTab === 'suppress') {
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


  // ── Signatures: one catalogue, platform as a facet ──
  const PLATFORM = { linux: 'Linux', windows: 'Windows', macos: 'macOS', cloud: 'Cloud', dc: 'Domain controller', devops: 'Code', network: 'Network', all: 'Any platform' }
  const [facets, setFacets] = useState({})
  const [q, setQ] = useState('')
  const [openSig, setOpenSig] = useState(null)
  const [bulkBusy, setBulkBusy] = useState(false)
  const selection = useSelection()
  const G = useMemo(() => ({ platform: s => sigOS(s.id), status: s => s.enabled ? 'on' : 'off', severity: s => s.severity, category: s => s.category }), [])
  const faceted = useFacetFilter(sigs, G, facets)
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase()
    return faceted.filter(s => !t || `${s.id} ${s.name} ${s.mitre} ${s.category} ${s.description || ''}`.toLowerCase().includes(t))
      .sort((a, b) => b.severity - a.severity || a.name.localeCompare(b.name))
  }, [faceted, q])
  const toggleFacet = (k, v) => setFacets(f => { const n = { ...f }; const set = new Set(n[k] || []); set.has(v) ? set.delete(v) : set.add(v); n[k] = set; return n })
  const setMany = async (enabled) => {
    setBulkBusy(true)
    const ids = [...selection.selected]
    const done = []
    for (const id of ids) {
      try { await api.patch(`/api/v1/detections/${id}`, { enabled }); done.push(id) } catch { /* keep going; reported below */ }
    }
    setSigs(prev => prev.map(s => done.includes(s.id) ? { ...s, enabled } : s))
    if (done.length < ids.length) window.alert(`${ids.length - done.length} of ${ids.length} rules could not be changed.`)
    selection.clear(); setBulkBusy(false)
  }
  const enabledAll = sigs.filter(s => s.enabled).length
  const critOff = sigs.filter(s => !s.enabled && s.severity >= 5).length
  const sigFacetGroups = [
    { key: 'status', label: 'Status', values: countBy(sigs, G.status, ['on', 'off'], { on: 'Enabled', off: 'Disabled' }) },
    { key: 'platform', label: 'Platform', values: countBy(sigs, G.platform, Object.keys(PLATFORM), PLATFORM) },
    { key: 'severity', label: 'Severity', values: countBy(sigs, G.severity, [5, 4, 3, 2, 1], SEV_LABEL) },
    { key: 'category', label: 'Tactic', values: countBy(sigs, G.category) },
  ]
  const Switch = ({ on, busy, onClick, label }) => (
    <button className={`ow-switch ${on ? 'on' : ''}`} role="switch" aria-checked={on} aria-label={label} disabled={busy}
      onClick={e => { e.stopPropagation(); onClick(e) }}><span/></button>
  )

  // ── SAST rules: same table language ──
  const [sastFacets, setSastFacets] = useState({})
  const SG = useMemo(() => ({ severity: r => r.severity, lang: r => r.lang }), [])
  const sastFaceted = useFacetFilter(sastRules, SG, sastFacets)
  const sastRows = sastFaceted.filter(r => !sastSearch || `${r.id} ${r.title} ${r.cwe} ${r.detail}`.toLowerCase().includes(sastSearch.toLowerCase()))
    .sort((a, b) => ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 }[a.severity] ?? 5) - ({ critical: 0, high: 1, medium: 2, low: 3, info: 4 }[b.severity] ?? 5))
  const [openSast, setOpenSast] = useState(null)
  const SAST_SEV = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
  const LANG = { javascript: 'JS / TS', csharp: 'C#', python: 'Python', go: 'Go', java: 'Java', php: 'PHP', c: 'C / C++', ruby: 'Ruby', rust: 'Rust', any: 'Any' }

  const TABS = [
    { id: 'signatures', label: 'Signatures', n: sigs.length || null },
    { id: 'sigma', label: 'Sigma', n: sigmaCount || null },
    { id: 'sast', label: 'Code (SAST)', n: sastRules.length || null },
    { id: 'sources', label: 'Threat intelligence', n: sources.length || null },
    { id: 'suppress', label: 'Cloud suppressions' },
  ]

  return (
    <div>
      <PageHeader
        title="Rules"
        state={loading ? undefined : critOff ? 'warn' : 'ok'}
        stateText={critOff ? `${critOff} critical rule${critOff === 1 ? '' : 's'} disabled` : 'All critical rules enabled'}
        sub={`${sigs.length.toLocaleString()} built-in signatures, ${sigmaCount.toLocaleString()} Sigma rules${sigmaEnabled ? '' : ' (off)'}, ${totalIOCs.toLocaleString()} indicators from ${enabledSources} intel source${enabledSources === 1 ? '' : 's'}.`}
        nums={<>
          <Num k="Signatures enabled" v={enabledAll.toLocaleString()} unit={`of ${sigs.length.toLocaleString()}`}/>
          <Num k="Critical rules disabled" v={critOff} tone={critOff ? 'warn' : undefined}/>
          <Num k="Sigma" v={sigmaEnabled ? sigmaCount.toLocaleString() : 'Off'} tone={sigmaEnabled ? undefined : 'warn'}/>
          <Num k="Indicators loaded" v={totalIOCs.toLocaleString()}/>
          <Num k="Intel sources on" v={enabledSources} unit={`of ${sources.length}`}/>
        </>}
        tabs={<Tabs value={osTab} onChange={t => { setOsTab(t); selection.clear() }} tabs={TABS}/>}
      />
      <div className="ow-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {osTab === 'signatures' && (
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          <Facets groups={sigFacetGroups} selected={facets} onToggle={toggleFacet} onClear={() => setFacets({})}/>
          <div className="ow-card" style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
            {selection.selected.size > 0 ? (
              <SelectionBar count={selection.selected.size} total={rows.length} allMatching={rows.every(r => selection.selected.has(r.id))}
                onSelectAllMatching={() => selection.setAll(rows.map(r => r.id))} onClear={selection.clear}>
                <button className="ow-btn" style={{ height: 26 }} disabled={bulkBusy} onClick={() => setMany(true)}>Enable</button>
                <button className="ow-btn" style={{ height: 26 }} disabled={bulkBusy} onClick={() => setMany(false)}>Disable</button>
              </SelectionBar>
            ) : (
              <div className="ow-card-bar">
                <label className="ow-field" style={{ flex: 1, maxWidth: 420, height: 28 }}>
                  <Filter size={13} style={{ color: 'var(--t3)' }}/>
                  <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter by name, ID, MITRE technique or tactic" aria-label="Filter rules"/>
                </label>
                <span className="t2" style={{ fontSize: 13.5 }}>{rows.length.toLocaleString()} of {sigs.length.toLocaleString()}</span>
              </div>
            )}
            <DenseTable rows={loading ? [] : rows} rowKey={s => s.id} onRow={s => setOpenSig(s)} current={openSig?.id}
              selected={selection.selected} onSelect={selection.onSelect} onSelectAll={v => v ? selection.setAll(rows.map(r => r.id)) : selection.clear()}
              empty={loading ? 'Loading rules…' : 'No rules match these filters.'}
              cols={[
                { key: 'on', label: 'On', width: '52px', render: s => <Switch on={s.enabled} busy={toggling[s.id]} onClick={e => toggle(s, e)} label={`${s.enabled ? 'Disable' : 'Enable'} ${s.name}`}/> },
                { key: 'sev', label: 'Severity', width: '92px', render: s => <SevPill sev={s.severity}/> },
                { key: 'name', label: 'Rule', width: 'minmax(240px, 2.4fr)', render: s => <span className={s.enabled ? 't1' : 't3'}>{s.name}</span>, title: s => s.description },
                { key: 'cat', label: 'Tactic', width: 'minmax(120px, 1fr)', render: s => <span className="t2">{s.category}</span> },
                { key: 'plat', label: 'Platform', width: '120px', render: s => <span className="t2">{PLATFORM[sigOS(s.id)]}</span> },
                { key: 'mitre', label: 'MITRE', width: '96px', render: s => <span className="mono t2">{s.mitre || '—'}</span> },
                { key: 'id', label: 'ID', width: '100px', render: s => <span className="mono t3">{s.id}</span> },
              ]}/>
          </div>
        </div>
      )}

      {osTab === 'sigma' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="ow-card" style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, marginBottom: 4 }}>SigmaHQ community rules · {sigmaCount.toLocaleString()} rules</div>
              <div className="t2" style={{ fontSize: 13.5 }}>Mapped to MITRE ATT&CK. A rule alerts at most once per host per hour.</div>
            </div>
            <span className="t2" style={{ fontSize: 13.5 }}>{sigmaToggling ? 'Saving…' : sigmaEnabled ? 'Enabled' : 'Disabled'}</span>
            <Switch on={sigmaEnabled} busy={sigmaToggling} onClick={toggleSigma} label="Sigma rules on or off"/>
          </div>
          <SigmaRuleList />
        </div>
      )}

      {osTab === 'sast' && (
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          <Facets selected={sastFacets} onClear={() => setSastFacets({})}
            onToggle={(k, v) => setSastFacets(f => { const n = { ...f }; const set = new Set(n[k] || []); set.has(v) ? set.delete(v) : set.add(v); n[k] = set; return n })}
            groups={[
              { key: 'severity', label: 'Severity', values: countBy(sastRules, SG.severity, ['critical', 'high', 'medium', 'low', 'info'], { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }) },
              { key: 'lang', label: 'Language', values: countBy(sastRules, SG.lang, null, LANG) },
            ]}/>
          <div className="ow-card" style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
            <div className="ow-card-bar">
              <label className="ow-field" style={{ flex: 1, maxWidth: 420, height: 28 }}>
                <Filter size={13} style={{ color: 'var(--t3)' }}/>
                <input value={sastSearch} onChange={e => setSastSearch(e.target.value)} placeholder="Filter by title, CWE or ID" aria-label="Filter SAST rules"/>
              </label>
              <span className="t2" style={{ fontSize: 13.5 }}>{sastRows.length} of {sastRules.length}</span>
              <span className="t3" style={{ marginLeft: 'auto', fontSize: 13.5 }}>Used when repositories are scanned (Code › Connectors and scans)</span>
            </div>
            <DenseTable rows={sastRows} rowKey={r => r.id} onRow={r => setOpenSast(r)} current={openSast?.id} empty="Loading rules…"
              cols={[
                { key: 's', label: 'Severity', width: '92px', render: r => <SevPill sev={SAST_SEV[r.severity] || 1}/> },
                { key: 't', label: 'Rule', width: 'minmax(240px, 2.4fr)', render: r => <span className="t1">{r.title}</span>, title: r => r.detail },
                { key: 'l', label: 'Language', width: '96px', render: r => <span className="t2">{LANG[r.lang] || r.lang}</span> },
                { key: 'c', label: 'CWE', width: '96px', render: r => <span className="mono t2">{r.cwe || '—'}</span> },
                { key: 'o', label: 'OWASP', width: '80px', render: r => <span className="mono t2">{r.owasp || '—'}</span> },
                { key: 'i', label: 'ID', width: '140px', render: r => <span className="mono t3">{r.id}</span> },
              ]}/>
          </div>
        </div>
      )}

      {osTab === 'sources' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="t2" style={{ fontSize: 13.5 }}>Indicators sync daily; a match raises an alert.</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(381px, 1fr))', gap: 12 }}>
            {sources.map(s => <SourceCard key={s.name} source={s} onUpdate={updateSource} onSync={syncSource} />)}
          </div>
          <ManualIOCs />
        </div>
      )}

      {osTab === 'suppress' && (
        <div className="ow-card" style={{ overflow: 'hidden' }}>
          <div className="ow-card-bar">
            <span style={{ fontWeight: 600 }}>Cloud alert suppressions</span>
            <span className="t3" style={{ fontSize: 13.5 }}>Quiet known, legitimate cloud activity (CI/CD key creation, trusted principals, internal ranges) without turning a rule off</span>
            <button className="ow-btn primary" style={{ marginLeft: 'auto' }} onClick={() => setShowSuppressForm(v => !v)}>{showSuppressForm ? 'Cancel' : 'New suppression'}</button>
          </div>
          {showSuppressForm && (
            <div style={{ padding: 16, borderBottom: '1px solid var(--line)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div style={{ gridColumn: '1 / -1' }}><Field label="Description"><input className="input" value={suppressForm.description} onChange={e => setSuppressForm(p => ({ ...p, description: e.target.value }))} placeholder="e.g. CI/CD pipeline service-account key creation"/></Field></div>
              {[{ k: 'sig_id', label: 'Rule ID or prefix', ph: 'C-GCP-025 or C-GCP-0' }, { k: 'principal', label: 'Principal (exact, or @suffix)', ph: 'ci-cd@proj.iam.gserviceaccount.com' },
                { k: 'src_ip_prefix', label: 'Source IP prefix', ph: '10.128.' }, { k: 'method_contains', label: 'Method contains', ph: 'CloudBuild' },
                { k: 'expires_days', label: 'Expires after (days, blank = never)', ph: '30' }].map(f => (
                <Field key={f.k} label={f.label}><input className="input mono" value={suppressForm[f.k]} onChange={e => setSuppressForm(p => ({ ...p, [f.k]: e.target.value }))} placeholder={f.ph}/></Field>
              ))}
              <div style={{ gridColumn: '1 / -1', display: 'flex', justifyContent: 'flex-end', gap: 8, alignItems: 'center' }}>
                <span className="t3" style={{ fontSize: 13.5 }}>Needs a description and at least one match condition.</span>
                <button className="ow-btn primary" onClick={saveSuppress} disabled={suppressSaving || !suppressForm.description}>{suppressSaving ? 'Saving…' : 'Save suppression'}</button>
              </div>
            </div>
          )}
          <DenseTable rows={suppressRules} rowKey={r => r.id} empty={suppressLoading ? 'Loading…' : 'No suppressions.'}
            rowState={r => r.expires_at && new Date(r.expires_at) < new Date() ? 'none' : null}
            cols={[
              { key: 'd', label: 'Description', width: 'minmax(200px, 1.6fr)', render: r => <span className="t1">{r.description}</span> },
              { key: 'm', label: 'Matches', width: 'minmax(240px, 2fr)', render: r => <span className="mono t2">{[r.sig_id && `rule ${r.sig_id}`, r.principal && `principal ${r.principal}`, r.src_ip_prefix && `ip ${r.src_ip_prefix}*`, r.method_contains && `method *${r.method_contains}*`].filter(Boolean).join(' · ')}</span> },
              { key: 'e', label: 'Expires', width: '120px', render: r => r.expires_at ? (new Date(r.expires_at) < new Date() ? <StatePill state="none">Expired</StatePill> : <span className="t2">{new Date(r.expires_at).toLocaleDateString()}</span>) : <span className="t3">Never</span> },
              { key: 'x', label: '', width: '80px', render: r => <button className="ow-btn quiet" style={{ height: 24, color: 'var(--crit)' }} onClick={e => { e.stopPropagation(); if (window.confirm('Delete this suppression? Matching activity will alert again.')) deleteSuppress(r.id) }}>Delete</button> },
            ]}/>
        </div>
      )}
      </div>

      <Drawer open={!!openSig} onClose={() => setOpenSig(null)} label="Rule details" width={560}>
        {openSig && (() => { const s = sigs.find(x => x.id === openSig.id) || openSig; return (
          <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
            <div className="ow-head notabs" style={{ paddingBottom: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}><SevPill sev={s.severity}/><span className="mono t3">{s.id}</span>
                <button className="ow-btn quiet" style={{ marginLeft: 'auto', height: 26 }} onClick={() => setOpenSig(null)}>Close</button></div>
              <h1 style={{ fontSize: 17, marginTop: 8 }}>{s.name}</h1>
              <div className="ow-sub">{s.category} · {PLATFORM[sigOS(s.id)]}</div>
            </div>
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14, overflowY: 'auto' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}><Switch on={s.enabled} busy={toggling[s.id]} onClick={e => toggle(s, e)} label="Rule on or off"/><span>{s.enabled ? 'Enabled' : 'Disabled'}</span></div>
              {s.description && <div className="t2" style={{ lineHeight: 1.55 }}>{s.description}</div>}
              {s.mitre && <div><div className="ow-lbl" style={{ marginBottom: 4 }}>MITRE ATT&CK</div>
                <a className="c-acc mono" href={`https://attack.mitre.org/techniques/${s.mitre.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer">{s.mitre} <ExternalLink size={11} style={{ display: 'inline' }}/></a></div>}
              <div><div className="ow-lbl" style={{ marginBottom: 4 }}>Backtest</div><div className="t3" style={{ fontSize: 13.5, marginBottom: 6 }}>Run the rule over the last 24 hours of stored events to see what it would have caught.</div><Backtest sigId={s.id}/></div>
            </div>
          </div>) })()}
      </Drawer>
      <Drawer open={!!openSast} onClose={() => setOpenSast(null)} label="SAST rule details" width={560}>
        {openSast && (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12, overflowY: 'auto' }}>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}><SevPill sev={SAST_SEV[openSast.severity] || 1}/><span className="mono t3">{openSast.id}</span>
              <button className="ow-btn quiet" style={{ marginLeft: 'auto', height: 26 }} onClick={() => setOpenSast(null)}>Close</button></div>
            <div style={{ fontSize: 17, fontWeight: 600 }}>{openSast.title}</div>
            <div className="t2">{LANG[openSast.lang] || openSast.lang}{openSast.cwe && <> · <span className="mono">{openSast.cwe}</span></>}{openSast.owasp && <> · OWASP {openSast.owasp}</>}</div>
            <div style={{ lineHeight: 1.55 }}>{openSast.detail}</div>
            {openSast.fix && <div><div className="ow-lbl" style={{ marginBottom: 4 }}>Fix</div><div className="t2" style={{ lineHeight: 1.55 }}>{openSast.fix}</div></div>}
          </div>
        )}
      </Drawer>
    </div>
  )
}
