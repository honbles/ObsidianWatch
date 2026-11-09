import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Settings as SettingsIcon, Mail, CheckCircle, AlertCircle, Send,
         Zap, Cloud, Save, Eye, EyeOff, Plus, X, ChevronRight,
         Key, Shield, Database, Brain, Search, ExternalLink, RefreshCw } from 'lucide-react'
import api from '../api/client'

// ── Shared UI helpers ─────────────────────────────────────────────────────────
const inputCls = "w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"

function Result({ result }) {
  if (!result) return null
  return (
    <div className={`flex items-center gap-2 text-xs p-2.5 rounded-lg ${
      result.ok
        ? 'text-emerald-400 bg-emerald-900/20 border border-emerald-800/30'
        : 'text-red-400 bg-red-900/20 border border-red-800/30'
    }`}>
      {result.ok ? <CheckCircle size={13}/> : <AlertCircle size={13}/>}
      {result.msg}
    </div>
  )
}

// ── API Keys Tab ──────────────────────────────────────────────────────────────
const API_KEY_GROUPS = [
  {
    id: 'ai',
    label: 'AI Providers',
    icon: Brain,
    color: 'text-violet-400',
    border: 'border-violet-800/30',
    bg: 'bg-violet-950/10',
    desc: 'Power alert analysis, vulnerability assessment, and root cause analysis.',
    keys: [
      {
        key: 'groq_api_key',
        label: 'Groq API Key',
        placeholder: 'gsk_...',
        desc: 'Fast inference via Llama 3.3 70B. Free tier available.',
        link: 'https://console.groq.com',
        linkLabel: 'Get free key →',
        badge: 'Recommended',
        badgeColor: 'text-emerald-400 bg-emerald-950/30 border-emerald-800/40',
      },
      {
        key: 'anthropic_api_key',
        label: 'Anthropic API Key',
        placeholder: 'sk-ant-...',
        desc: 'Claude models. Higher quality, slower than Groq.',
        link: 'https://console.anthropic.com',
        linkLabel: 'Get key →',
        badge: 'Claude',
        badgeColor: 'text-orange-400 bg-orange-950/30 border-orange-800/40',
      },
      {
        key: 'local_llm_url',
        plain: true,
        label: 'Local model URL',
        placeholder: 'http://localhost:11434',
        desc: 'Self-hosted OpenAI-compatible server (Ollama, vLLM, llama.cpp, LM Studio). When set together with a model name, natural-language search uses it instead of Groq/Anthropic, so the question never leaves your network.',
        badge: 'Self-hosted',
        badgeColor: 'text-sky-400 bg-sky-950/30 border-sky-800/40',
      },
      {
        key: 'local_llm_model',
        plain: true,
        label: 'Local model name',
        placeholder: 'llama3.1:8b',
        desc: 'Model name as the local server knows it (for Ollama, the tag you pulled).',
        badge: 'Self-hosted',
        badgeColor: 'text-sky-400 bg-sky-950/30 border-sky-800/40',
      },
      {
        key: 'local_llm_api_key',
        label: 'Local model API key (optional)',
        placeholder: 'Only if your server requires one',
        desc: 'Sent as a Bearer token to the local server. Leave empty for Ollama.',
        badge: 'Self-hosted',
        badgeColor: 'text-sky-400 bg-sky-950/30 border-sky-800/40',
      },
    ],
  },
  {
    id: 'vuln',
    label: 'Vulnerability Intelligence',
    icon: Shield,
    color: 'text-red-400',
    border: 'border-red-800/30',
    bg: 'bg-red-950/10',
    desc: 'Real CVE data from authoritative databases — no AI guessing.',
    keys: [
      {
        key: 'nvd_api_key',
        label: 'NVD API Key',
        placeholder: 'Optional — improves rate limit 5x',
        desc: 'National Vulnerability Database. Used for package CVE lookups. Works without a key but rate-limited.',
        link: 'https://nvd.nist.gov/developers/request-an-api-key',
        linkLabel: 'Get free key →',
        badge: 'Optional',
        badgeColor: 'text-blue-400 bg-blue-950/30 border-blue-800/40',
      },
    ],
  },
  {
    id: 'threat',
    label: 'Threat Intelligence',
    icon: Search,
    color: 'text-orange-400',
    border: 'border-orange-800/30',
    bg: 'bg-orange-950/10',
    desc: 'Enrich IPs, domains, and file hashes with threat reputation data.',
    keys: [
      {
        key: 'virustotal_api_key',
        label: 'VirusTotal API Key',
        placeholder: 'Your VirusTotal API key',
        desc: 'File hash reputation for downloads, temp dirs, executables. Only checks high-risk files.',
        link: 'https://www.virustotal.com/gui/user/apikey',
        linkLabel: 'Get free key →',
        badge: 'Hash intel',
        badgeColor: 'text-blue-400 bg-blue-950/30 border-blue-800/40',
      },
      {
        key: 'virustotal_plan',
        label: 'VirusTotal Plan',
        placeholder: 'free',
        desc: 'free (4 req/min) · standard (500 req/min) · premium (1000 req/min). Controls rate limiting.',
        badge: 'Rate limit',
        badgeColor: 'text-purple-400 bg-purple-950/30 border-purple-800/40',
        isSelect: true,
        options: [
          { value: 'free',       label: 'Free — 4 req/min' },
          { value: 'standard',   label: 'Standard — 500 req/min' },
          { value: 'premium',    label: 'Premium/Enterprise — 1000 req/min' },
        ],
      },
      {
        key: 'abuseipdb_api_key',
        label: 'AbuseIPDB API Key',
        placeholder: 'Your AbuseIPDB API key',
        desc: 'IP reputation and abuse reports. Free tier: 1000 checks/day.',
        link: 'https://www.abuseipdb.com/account/api',
        linkLabel: 'Get free key →',
        badge: 'IP intel',
        badgeColor: 'text-yellow-400 bg-yellow-950/30 border-yellow-800/40',
      },
      {
        key: 'threatfox_api_key',
        label: 'ThreatFox API Key',
        placeholder: 'Your ThreatFox API key',
        desc: 'IOC database from abuse.ch. Malware indicators and C2 servers.',
        link: 'https://threatfox.abuse.ch/api/',
        linkLabel: 'Get free key →',
        badge: 'IOC feed',
        badgeColor: 'text-red-400 bg-red-950/30 border-red-800/40',
      },
      {
        key: 'otx_api_key',
        label: 'OTX API Key (AlienVault)',
        placeholder: 'Your OTX API key',
        desc: 'Open Threat Exchange — community threat intelligence.',
        link: 'https://otx.alienvault.com/api',
        linkLabel: 'Get free key →',
        badge: 'Threat feed',
        badgeColor: 'text-purple-400 bg-purple-950/30 border-purple-800/40',
      },
      {
        key: 'shodan_api_key',
        label: 'Shodan API Key',
        placeholder: 'Your Shodan API key',
        desc: 'Internet-wide scan data. Look up what Shodan knows about your IPs.',
        link: 'https://account.shodan.io/',
        linkLabel: 'Get key →',
        badge: 'Attack surface',
        badgeColor: 'text-cyan-400 bg-cyan-950/30 border-cyan-800/40',
      },
    ],
  },
]

function APIKeyRow({ keyDef, onSaved }) {
  const { key, label, placeholder, desc, link, linkLabel, badge, badgeColor, plain } = keyDef
  const [value, setValue]     = useState('')
  const [initial, setInitial] = useState('') // saved value for non-secret fields
  const [isSet, setIsSet]     = useState(false)
  const [show, setShow]       = useState(!!plain)
  const [saving, setSaving]   = useState(false)
  const [status, setStatus]   = useState(null) // null | 'saved' | 'cleared' | 'error'
  const [errMsg, setErrMsg]   = useState('')
  const [loaded, setLoaded]   = useState(false)

  useEffect(() => {
    api.get('/api/v1/settings/api-keys').then(r => {
      if (r.data[key + '_set']) setIsSet(true)
      if (plain && r.data[key]) { setValue(r.data[key]); setInitial(r.data[key]) }
    }).catch(() => {}).finally(() => setLoaded(true))
  }, [key, plain])

  const save = async () => {
    if (!value.trim()) return
    setSaving(true); setStatus(null)
    try {
      await api.post('/api/v1/settings/api-keys', { [key]: value })
      setIsSet(true); setStatus('saved'); setErrMsg('')
      if (plain) {
        // The server normalises the value (e.g. trims a trailing slash): show what was stored.
        const r = await api.get('/api/v1/settings/api-keys').catch(() => null)
        const stored = r?.data?.[key] ?? value.trim()
        setValue(stored); setInitial(stored)
      } else setValue('')
      onSaved && onSaved(key)
      setTimeout(() => setStatus(null), 3000)
    } catch (e) {
      setErrMsg(e?.response?.data?.error || '')
      setStatus('error')
    } finally { setSaving(false) }
  }

  const clear = async () => {
    setSaving(true); setStatus(null)
    try {
      await api.post('/api/v1/settings/api-keys', { [key]: '' })
      setIsSet(false); setValue(''); setInitial(''); setStatus('cleared')
      setTimeout(() => setStatus(null), 2000)
    } catch {
      setStatus('error')
    } finally { setSaving(false) }
  }

  const handleKey = e => { if (e.key === 'Enter') save() }

  if (!loaded) return null

  return (
    <div className="px-5 py-4">
      <div className="flex items-start justify-between gap-4 mb-2.5">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5 flex-wrap">
            <span className="text-xs font-semibold text-siem-text">{label}</span>
            <span className={`text-[9px] font-semibold px-2 py-0.5 rounded-full border ${badgeColor}`}>
              {badge}
            </span>
            {isSet && status !== 'cleared' && (
              <span className="flex items-center gap-1 text-[9px] text-emerald-400 bg-emerald-950/20 border border-emerald-800/30 rounded-full px-2 py-0.5">
                <CheckCircle size={8}/> Configured
              </span>
            )}
            {status === 'saved' && (
              <span className="flex items-center gap-1 text-[9px] text-emerald-400 animate-pulse">
                <CheckCircle size={9}/> Saved
              </span>
            )}
            {status === 'cleared' && (
              <span className="text-[9px] text-siem-muted">Cleared</span>
            )}
            {status === 'error' && (
              <span className="text-[9px] text-red-400">{errMsg || 'Save failed'}</span>
            )}
          </div>
          <p className="text-[10px] text-siem-muted">{desc}</p>
        </div>
        {link && (
          <a href={link} target="_blank" rel="noreferrer"
            className="shrink-0 flex items-center gap-1 text-[10px] text-siem-accent hover:opacity-80 border border-siem-accent/30 rounded-lg px-2 py-1 transition-opacity">
            {linkLabel} <ExternalLink size={9}/>
          </a>
        )}
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <input
            type={show || plain ? 'text' : 'password'}
            value={value}
            onChange={e => setValue(e.target.value)}
            onKeyDown={handleKey}
            placeholder={isSet ? '••••••••  (type new value to replace)' : placeholder}
            className={inputCls + ' pr-9 font-mono text-xs'}
          />
          <button onClick={() => setShow(s => !s)}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-siem-muted hover:text-siem-text">
            {show ? <EyeOff size={13}/> : <Eye size={13}/>}
          </button>
        </div>
        {value.trim() && value !== initial && (
          <button onClick={save} disabled={saving}
            className="shrink-0 flex items-center gap-1.5 text-[11px] font-semibold bg-siem-accent hover:bg-siem-accent/90 text-white rounded-lg px-3 disabled:opacity-40 transition-colors">
            <Save size={11}/>{saving ? '…' : 'Save'}
          </button>
        )}
        {isSet && (!value.trim() || value === initial) && (
          <button onClick={clear} disabled={saving}
            className="shrink-0 text-[10px] text-red-400/70 border border-red-800/30 rounded-lg px-2.5 hover:bg-red-950/20 transition-colors disabled:opacity-40">
            Clear
          </button>
        )}
      </div>
    </div>
  )
}

function APIKeysSettings() {
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Just trigger a load to show the page — each row loads itself
    setLoading(false)
  }, [])

  if (loading) return (
    <div className="flex items-center gap-2 text-siem-muted text-sm py-8">
      <RefreshCw size={14} className="animate-spin"/> Loading…
    </div>
  )

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h2 className="text-sm font-semibold text-siem-text mb-1">API Keys & Integrations</h2>
        <p className="text-xs text-siem-muted">
          Keys are stored in your local database and never leave your server except to call the respective API directly.
          Press Enter or click Save after typing a key.
        </p>
      </div>

      {API_KEY_GROUPS.map(group => {
        const Icon = group.icon
        return (
          <div key={group.id} className={`border rounded-xl overflow-hidden ${group.border} ${group.bg}`}>
            <div className="px-5 py-4 border-b border-siem-border/40">
              <div className="flex items-center gap-2.5 mb-0.5">
                <Icon size={15} className={group.color}/>
                <span className={`text-sm font-semibold ${group.color}`}>{group.label}</span>
              </div>
              <p className="text-[11px] text-siem-muted">{group.desc}</p>
            </div>
            <div className="divide-y divide-siem-border/20">
              {group.keys.map(keyDef => (
                <APIKeyRow key={keyDef.key} keyDef={keyDef}/>
              ))}
            </div>
          </div>
        )
      })}

      <div className="bg-siem-bg border border-siem-border/50 rounded-xl p-4 text-[11px] text-siem-muted/70 leading-relaxed">
        <p className="font-medium text-siem-muted mb-1">Security note</p>
        <p>API keys are only transmitted directly to the respective service.
        ObsidianWatch never proxies your API calls through any third-party infrastructure.
        Use the minimum permission scopes required — read-only where possible.</p>
      </div>
    </div>
  )
}

// ── SMTP Tab ──────────────────────────────────────────────────────────────────
function SMTPSettings() {
  const [form, setForm]           = useState(null)
  const [showPass, setShowPass]   = useState(false)
  const [toInput, setToInput]     = useState('')
  const [saving, setSaving]       = useState(false)
  const [testing, setTesting]     = useState(false)
  const [saveResult, setSaveResult] = useState(null)
  const [testResult, setTestResult] = useState(null)

  useEffect(() => {
    api.get('/api/v1/settings/smtp').then(r => {
      setForm({
        enabled:      r.data.enabled || false,
        host:         r.data.host || '',
        port:         r.data.port || 587,
        username:     r.data.username || '',
        password:     '',
        from:         r.data.from || '',
        to:           r.data.to || [],
        min_severity: r.data.min_severity || 4,
        use_tls:      r.data.use_tls !== false,
        has_password: r.data.has_password || false,
      })
    }).catch(() => {})
  }, [])

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))
  const addRecipient = () => {
    const email = toInput.trim()
    if (!email || !email.includes('@')) return
    setForm(f => ({ ...f, to: [...(f.to || []), email] }))
    setToInput('')
  }
  const removeRecipient = i => setForm(f => ({ ...f, to: f.to.filter((_, idx) => idx !== i) }))

  const save = async () => {
    setSaving(true); setSaveResult(null)
    try {
      await api.post('/api/v1/settings/smtp', form)
      setSaveResult({ ok: true, msg: 'Settings saved successfully.' })
      api.get('/api/v1/settings/smtp').then(r => set('has_password', r.data.has_password))
    } catch (e) {
      setSaveResult({ ok: false, msg: e.response?.data?.error || 'Save failed' })
    } finally { setSaving(false) }
  }

  const test = async () => {
    setTesting(true); setTestResult(null)
    try {
      await api.post('/api/v1/settings/smtp/test')
      setTestResult({ ok: true, msg: 'Test email sent! Check your inbox.' })
    } catch (e) {
      setTestResult({ ok: false, msg: e.response?.data?.error || 'Test failed' })
    } finally { setTesting(false) }
  }

  if (!form) return <div className="text-xs text-siem-muted">Loading…</div>

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h2 className="text-sm font-semibold text-siem-text mb-1">Email Alert Notifications</h2>
        <p className="text-xs text-siem-muted">Configure SMTP to receive email alerts when high-severity events are detected.</p>
      </div>

      <div className="bg-siem-surface border border-siem-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-medium text-siem-text">Enable email alerts</div>
            <div className="text-xs text-siem-muted">Send notifications for matching alerts</div>
          </div>
          <button onClick={() => set('enabled', !form.enabled)}
            className={`w-11 h-6 rounded-full transition-colors relative ${form.enabled ? 'bg-siem-accent' : 'bg-siem-border'}`}>
            <span className={`absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-all ${form.enabled ? 'left-5' : 'left-0.5'}`}/>
          </button>
        </div>
        <hr className="border-siem-border"/>
        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">SMTP Host</label>
            <input className={inputCls} placeholder="smtp.gmail.com" value={form.host} onChange={e => set('host', e.target.value)}/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">Port</label>
            <input className={inputCls} type="number" placeholder="587" value={form.port} onChange={e => set('port', parseInt(e.target.value) || 587)}/>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">Username</label>
            <input className={inputCls} placeholder="you@gmail.com" value={form.username} onChange={e => set('username', e.target.value)}/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">
              Password {form.has_password && !form.password && <span className="text-emerald-400 normal-case ml-1">✓ saved</span>}
            </label>
            <div className="relative">
              <input className={inputCls + ' pr-9'} type={showPass ? 'text' : 'password'}
                placeholder={form.has_password ? '•••••••• (leave blank to keep)' : 'SMTP password or app password'}
                value={form.password} onChange={e => set('password', e.target.value)}/>
              <button onClick={() => setShowPass(s => !s)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-siem-muted hover:text-siem-text">
                {showPass ? <EyeOff size={14}/> : <Eye size={14}/>}
              </button>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">From Address</label>
            <input className={inputCls} placeholder="ObsidianWatch <alerts@yourdomain.com>" value={form.from} onChange={e => set('from', e.target.value)}/>
          </div>
          <div className="flex items-end gap-3 pb-0.5">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input type="checkbox" checked={form.use_tls} onChange={e => set('use_tls', e.target.checked)} className="accent-siem-accent"/>
              <span className="text-sm text-siem-muted">Use TLS/STARTTLS</span>
            </label>
          </div>
        </div>
        <div>
          <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">Recipients</label>
          <div className="flex flex-wrap gap-1.5 mb-2">
            {form.to.map((email, i) => (
              <span key={i} className="inline-flex items-center gap-1 text-xs bg-siem-accent/10 border border-siem-accent/30 text-siem-accent rounded-full px-2.5 py-0.5">
                {email}<button onClick={() => removeRecipient(i)} className="hover:opacity-70">×</button>
              </span>
            ))}
          </div>
          <div className="flex gap-2">
            <input className={inputCls} placeholder="Add recipient email…" value={toInput}
              onChange={e => setToInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addRecipient() }}}/>
            <button onClick={addRecipient}
              className="shrink-0 text-xs border border-siem-border rounded-lg px-3 py-2 text-siem-muted hover:text-siem-accent hover:border-siem-accent transition-colors">
              <Plus size={13}/>
            </button>
          </div>
        </div>
        <div>
          <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">Minimum Severity to Email</label>
          <select className={inputCls} value={form.min_severity} onChange={e => set('min_severity', parseInt(e.target.value))}>
            <option value={1}>1 — Info (all alerts)</option>
            <option value={2}>2 — Low+</option>
            <option value={3}>3 — Medium+</option>
            <option value={4}>4 — High+ (recommended)</option>
            <option value={5}>5 — Critical only</option>
          </select>
        </div>
        <Result result={saveResult}/>
        <Result result={testResult}/>
        <div className="flex gap-2 pt-1">
          <button onClick={save} disabled={saving}
            className="flex items-center gap-2 text-xs bg-siem-accent hover:bg-siem-accent/90 text-white rounded-lg px-4 py-2 disabled:opacity-40">
            <Save size={12}/>{saving ? 'Saving…' : 'Save Settings'}
          </button>
          <button onClick={test} disabled={testing || !form.enabled}
            className="flex items-center gap-2 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-4 py-2 disabled:opacity-40">
            <Send size={12}/>{testing ? 'Sending…' : 'Send Test Email'}
          </button>
        </div>
        <div className="bg-siem-bg border border-siem-border/40 rounded-xl p-3 text-[11px] text-siem-muted space-y-1">
          <p className="font-medium text-siem-text">Common SMTP settings</p>
          <p><span className="text-siem-accent">Gmail:</span> smtp.gmail.com · Port 587 · Use an App Password</p>
          <p><span className="text-siem-accent">Office 365:</span> smtp.office365.com · Port 587</p>
          <p><span className="text-siem-accent">SendGrid:</span> smtp.sendgrid.net · Port 587 · Username: apikey</p>
        </div>
      </div>
    </div>
  )
}

// ── Cloud Tab ─────────────────────────────────────────────────────────────────
function CloudSettings() {
  const navigate = useNavigate()
  return (
    <div className="space-y-4 max-w-3xl">
      <div>
        <h2 className="text-sm font-semibold text-siem-text mb-1">Cloud Connectors</h2>
        <p className="text-xs text-siem-muted">Connect cloud accounts to pull security telemetry.</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { short:'AWS',   color:'border-orange-800/40 bg-orange-950/10', badge:'text-orange-400', desc:'CloudTrail, GuardDuty, IAM events' },
          { short:'Azure', color:'border-blue-800/40 bg-blue-950/10',     badge:'text-blue-400',   desc:'Activity Log, Entra ID, Defender' },
          { short:'GCP',   color:'border-green-800/40 bg-green-950/10',   badge:'text-green-400',  desc:'Audit Logs, Security Command Center' },
        ].map(p => (
          <div key={p.short} className={`border rounded-xl p-4 space-y-3 ${p.color}`}>
            <div className="flex items-center justify-between">
              <span className={`text-sm font-bold ${p.badge}`}>{p.short}</span>
              <span className="text-[10px] text-siem-muted border border-siem-border rounded-full px-2 py-0.5">Not connected</span>
            </div>
            <p className="text-[11px] text-siem-muted">{p.desc}</p>
            <button onClick={() => navigate(`/cloud?provider=${p.short.toLowerCase()}`)}
              className="w-full text-xs border border-siem-border text-siem-muted hover:text-siem-accent hover:border-siem-accent/50 rounded-lg py-2 transition-colors flex items-center justify-center gap-1">
              Configure <ChevronRight size={11}/>
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

function DetectionSettings() {
  const navigate = useNavigate()
  useEffect(() => { navigate('/detections', { replace: true }) }, [])
  return null
}

// ── Main Settings Page ────────────────────────────────────────────────────────
const TABS = [
  { id: 'api-keys',   label: 'API Keys',         icon: Key    },
  { id: 'email',      label: 'Email Alerts',      icon: Mail   },
  { id: 'cloud',      label: 'Cloud Connectors',  icon: Cloud  },
  { id: 'detections', label: 'Detections',        icon: Zap    },
]

const COMPONENTS = {
  'api-keys':   APIKeysSettings,
  email:        SMTPSettings,
  cloud:        CloudSettings,
  detections:   DetectionSettings,
}

export default function Settings() {
  const [searchParams, setSearchParams] = useSearchParams()
  const tab = searchParams.get('tab') || 'api-keys'
  const Active = COMPONENTS[tab] || APIKeysSettings

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <SettingsIcon className="text-siem-accent" size={20}/>
        <h1 className="text-xl font-bold text-siem-text">Settings</h1>
      </div>

      <div className="flex gap-1 bg-siem-surface border border-siem-border rounded-xl p-1 w-fit flex-wrap">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button key={id} onClick={() => setSearchParams({ tab: id })}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-colors ${
              tab === id ? 'bg-siem-accent text-white' : 'text-siem-muted hover:text-siem-text'
            }`}>
            <Icon size={13}/>{label}
          </button>
        ))}
      </div>

      <Active/>
    </div>
  )
}
