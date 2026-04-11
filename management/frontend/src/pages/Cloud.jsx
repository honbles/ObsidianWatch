import { useState, useEffect, useCallback, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Cloud as CloudIcon, CheckCircle, XCircle, RefreshCw, Eye, EyeOff, AlertCircle,
  Activity, Bell, Search, Shield, Zap, ChevronRight, Plus, Trash2, Clock,
  Database, Globe, Lock, Server, HardDrive, Key, Wifi, BarChart2, TrendingUp,
  AlertTriangle, Info, ExternalLink, ChevronDown, ChevronUp, Cpu, List,
  Filter, Layers, FileText, Sparkles, X
} from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import api from '../api/client'
import AlertPanel from '../components/AlertPanel'

// ── Constants ─────────────────────────────────────────────────────────────────
const PROVIDERS = {
  aws: {
    label: 'Amazon Web Services', color: 'text-orange-400',
    border: 'border-orange-800/40', bg: 'bg-orange-950/10',
    fields: [
      { key: 'access_key_id',     label: 'Access Key ID',     placeholder: 'AKIAIOSFODNN7EXAMPLE', secret: false },
      { key: 'secret_access_key', label: 'Secret Access Key', placeholder: '••••••••', secret: true },
      { key: 'region',            label: 'Region',            placeholder: 'us-east-1', secret: false },
      { key: 'account_id',        label: 'Account ID (optional)', placeholder: '123456789012', secret: false },
    ],
    pulls: ['CloudTrail (LookupEvents API)', 'IAM activity', 'GuardDuty findings'],
  },
  azure: {
    label: 'Microsoft Azure', color: 'text-blue-400',
    border: 'border-blue-800/40', bg: 'bg-blue-950/10',
    fields: [
      { key: 'tenant_id',       label: 'Tenant ID',       placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', secret: false },
      { key: 'client_id',       label: 'Client ID',       placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', secret: false },
      { key: 'client_secret',   label: 'Client Secret',   placeholder: '••••••••', secret: true },
      { key: 'subscription_id', label: 'Subscription ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', secret: false },
    ],
    pulls: ['Azure Activity Log', 'Entra ID sign-in logs', 'Resource changes'],
  },
  gcp: {
    label: 'Google Cloud Platform', color: 'text-green-400',
    border: 'border-green-800/40', bg: 'bg-green-950/10',
    fields: [
      { key: 'service_account', label: 'Service Account JSON', placeholder: '{ "type": "service_account", ... }', secret: true, multiline: true },
    ],
    pulls: ['Cloud Audit Logs', 'Admin Activity', 'Data Access logs', 'System Events'],
  },
}

const PROVIDER_COLORS = { aws: 'text-orange-400', azure: 'text-blue-400', gcp: 'text-green-400' }
const SEV_COLOR = { critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8', info: '#94a3b8' }
const SEV_BG    = { critical: 'rgba(248,113,113,0.08)', high: 'rgba(249,115,22,0.08)', medium: 'rgba(251,191,36,0.08)', low: 'rgba(56,189,248,0.08)', info: 'rgba(148,163,184,0.06)' }
const SEV_BORDER= { critical: 'rgba(248,113,113,0.25)', high: 'rgba(249,115,22,0.25)', medium: 'rgba(251,191,36,0.25)', low: 'rgba(56,189,248,0.25)', info: 'rgba(148,163,184,0.15)' }

// Category → icon + label mapping
const CAT_META = {
  network:  { icon: Wifi,      label: 'Network',          color: '#f87171' },
  iam:      { icon: Lock,      label: 'Identity & Access', color: '#c084fc' },
  storage:  { icon: HardDrive, label: 'Storage',          color: '#38bdf8' },
  compute:  { icon: Server,    label: 'Compute',          color: '#fb923c' },
  sql:      { icon: Database,  label: 'Database',         color: '#34d399' },
  logging:  { icon: FileText,  label: 'Logging',          color: '#fbbf24' },
  kms:      { icon: Key,       label: 'KMS / Crypto',     color: '#a78bfa' },
  default:  { icon: Shield,    label: 'Security',         color: '#94a3b8' },
}

// CIS GCP Benchmark mapping (simplified)
const CIS_MAPPING = {
  network:  'CIS 3.x — Networking',
  iam:      'CIS 1.x — Identity & Access Management',
  storage:  'CIS 5.x — Cloud Storage',
  compute:  'CIS 4.x — Virtual Machines',
  sql:      'CIS 6.x — Cloud SQL',
  logging:  'CIS 2.x — Logging & Monitoring',
  kms:      'CIS 1.x — IAM / KMS',
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function riskScore(cspm) {
  if (!cspm) return 0
  const w = { critical: 10, high: 5, medium: 2, low: 0.5 }
  const raw = (cspm.critical||0)*w.critical + (cspm.high||0)*w.high + (cspm.medium||0)*w.medium + (cspm.low||0)*w.low
  const total = (cspm.total_findings||0) + (cspm.passed||0)
  if (!total) return 0
  return Math.min(100, Math.round(raw / Math.max(total, 1) * 10))
}

function riskLabel(score) {
  if (score >= 80) return { label: 'Critical Risk',   color: '#f87171' }
  if (score >= 60) return { label: 'High Risk',       color: '#fb923c' }
  if (score >= 40) return { label: 'Medium Risk',     color: '#fbbf24' }
  if (score >= 20) return { label: 'Low Risk',        color: '#38bdf8' }
  return               { label: 'Minimal Risk',      color: '#34d399' }
}

// ── ConnectorForm ─────────────────────────────────────────────────────────────
function ConnectorForm({ provider, onSaved, onCancel }) {
  const cfg = PROVIDERS[provider]
  const [values, setValues]   = useState({})
  const [show, setShow]       = useState({})
  const [saving, setSaving]   = useState(false)
  const [testing, setTesting] = useState(false)
  const [error, setError]     = useState('')
  const [testResult, setTestResult] = useState(null)

  const save = async () => {
    setSaving(true); setError('')
    try {
      await api.post('/api/v1/cloud-connectors', { provider, credentials: values })
      onSaved()
    } catch (e) { setError(e.response?.data?.error || 'Failed to save') }
    finally { setSaving(false) }
  }
  const testConn = async () => {
    setTesting(true); setTestResult(null)
    try {
      await api.post('/api/v1/cloud-connectors/test', { provider, credentials: values })
      setTestResult({ ok: true, msg: 'Connection successful!' })
    } catch (e) { setTestResult({ ok: false, msg: e.response?.data?.error || 'Connection failed' }) }
    finally { setTesting(false) }
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-3">
        {cfg.fields.map(f => (
          <div key={f.key}>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">{f.label}</label>
            {f.multiline ? (
              <textarea rows={5}
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-xs text-siem-text font-mono focus:outline-none focus:border-siem-accent resize-none"
                placeholder={f.placeholder} value={values[f.key]||''}
                onChange={e => setValues(v => ({...v,[f.key]:e.target.value}))}/>
            ) : (
              <div className="relative">
                <input type={f.secret && !show[f.key] ? 'password' : 'text'}
                  className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-xs text-siem-text font-mono focus:outline-none focus:border-siem-accent pr-9"
                  placeholder={f.placeholder} value={values[f.key]||''}
                  onChange={e => setValues(v => ({...v,[f.key]:e.target.value}))}/>
                {f.secret && (
                  <button onClick={() => setShow(s => ({...s,[f.key]:!s[f.key]}))}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-siem-muted hover:text-siem-text">
                    {show[f.key] ? <EyeOff size={13}/> : <Eye size={13}/>}
                  </button>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
      {error && <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/20 border border-red-800/30 rounded-lg p-2"><AlertCircle size={12}/>{error}</div>}
      {testResult && (
        <div className={`flex items-center gap-2 text-xs p-2 rounded-lg ${testResult.ok ? 'text-emerald-400 bg-green-900/20' : 'text-red-400 bg-red-900/20'}`}>
          {testResult.ok ? <CheckCircle size={12}/> : <XCircle size={12}/>} {testResult.msg}
        </div>
      )}
      <div className="flex gap-2">
        <button onClick={testConn} disabled={testing}
          className="text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-4 py-2 disabled:opacity-40">
          {testing ? 'Testing…' : 'Test Connection'}
        </button>
        <button onClick={save} disabled={saving}
          className="text-xs bg-siem-accent hover:bg-siem-accent/90 text-black rounded-lg px-4 py-2 disabled:opacity-40 font-semibold">
          {saving ? 'Saving…' : 'Save & Connect'}
        </button>
        <button onClick={onCancel} className="text-xs border border-siem-border text-siem-muted rounded-lg px-4 py-2">Cancel</button>
      </div>
      <div className="bg-siem-bg border border-siem-border/40 rounded-xl p-3 space-y-1">
        <p className="text-[10px] text-siem-muted font-medium uppercase tracking-wider mb-2">What will be pulled</p>
        {cfg.pulls.map(p => (
          <div key={p} className="flex items-center gap-2 text-xs text-siem-muted">
            <span className="w-1 h-1 rounded-full bg-siem-accent/60 shrink-0"/>{p}
          </div>
        ))}
        <p className="text-[10px] text-siem-muted/50 pt-1">Polled every 5 minutes · Read-only credentials required</p>
      </div>
    </div>
  )
}

// ── FindingCard — expandable, AI-explain, resource link ───────────────────────
function FindingCard({ f, provider, projectId }) {
  const [open, setOpen]         = useState(false)
  const [aiText, setAiText]     = useState(null)
  const [aiLoading, setAiLoading] = useState(false)

  const sev = f.severity || 'info'
  const catMeta = CAT_META[f.category] || CAT_META.default
  const CatIcon = catMeta.icon
  const cis = CIS_MAPPING[f.category] || ''

  const explainWithAI = async (e) => {
    e.stopPropagation()
    if (aiText) { setAiText(null); return }
    setAiLoading(true)
    try {
      const prompt = `You are a cloud security engineer. Explain this GCP CSPM finding in plain English for a security analyst.

Finding: ${f.title}
Severity: ${f.severity}
Category: ${f.category}
Resource: ${f.resource} (${f.resource_type})
Description: ${f.description}
Remediation: ${f.remediation}
MITRE: ${f.mitre || 'N/A'}

Respond with a JSON object:
{
  "plain_english": "1-2 sentences explaining what this means in non-technical terms",
  "business_impact": "what could an attacker do if this is exploited",
  "urgency": "why this needs to be fixed now or can wait",
  "steps": ["step 1", "step 2", "step 3"]
}`
      const { data } = await api.post('/api/v1/cloud-connectors/ai-explain', {
        prompt, finding: f
      })
      const text = data.content?.find(b => b.type === 'text')?.text || data.text || ''
      const clean = text.replace(/\x60{3}json\n?|\x60{3}/g, '').trim()
      try { setAiText(JSON.parse(clean)) } catch { setAiText({ plain_english: clean }) }
    } catch (err) {
      setAiText({ plain_english: 'AI explanation unavailable — check your API key in Settings → AI.' })
    } finally { setAiLoading(false) }
  }

  // Build GCP console deep link
  const consoleLink = () => {
    if (!projectId) return null
    const base = 'https://console.cloud.google.com'
    const p = `?project=${projectId}`
    switch (f.resource_type) {
      case 'firewall_rule':      return `${base}/networking/firewalls/details/${f.resource}${p}`
      case 'storage_bucket':     return `${base}/storage/browser/${f.resource}${p}`
      case 'compute_instance':   return `${base}/compute/instancesDetail/zones/-/instances/${f.resource.split(' ')[0]}${p}`
      case 'cloud_sql':          return `${base}/sql/instances/${f.resource}/overview${p}`
      case 'iam_binding':        return `${base}/iam-admin/iam${p}`
      case 'service_account':    return `${base}/iam-admin/serviceaccounts${p}`
      case 'service_account_key':return `${base}/iam-admin/serviceaccounts${p}`
      case 'kms_key':            return `${base}/security/kms/keyrings${p}`
      case 'vpc_subnet':         return `${base}/networking/subnetworks/list${p}`
      case 'dns_policy':         return `${base}/net-services/dns/policies${p}`
      case 'audit_config':       return `${base}/iam-admin/audit-log${p}`
      default:                   return `${base}/home/dashboard${p}`
    }
  }

  const link = consoleLink()

  return (
    <div style={{
      background: open ? SEV_BG[sev] : 'var(--surface)',
      border: `1px solid ${open ? SEV_BORDER[sev] : 'var(--border)'}`,
      borderLeft: `3px solid ${SEV_COLOR[sev] || '#94a3b8'}`,
      borderRadius: 10,
      transition: 'all 0.15s',
      overflow: 'hidden',
    }}>
      {/* Row — always visible */}
      <div onClick={() => setOpen(o => !o)}
        style={{ display:'flex', alignItems:'center', gap:10, padding:'12px 14px', cursor:'pointer' }}>
        <CatIcon size={14} color={catMeta.color} style={{ flexShrink:0 }}/>
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ fontSize:12.5, fontWeight:600, color:'var(--text)', marginBottom:2, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>
            {f.title}
          </div>
          <div style={{ display:'flex', alignItems:'center', gap:6, flexWrap:'wrap' }}>
            <span style={{ fontSize:9.5, background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:4, padding:'1px 5px', color:'var(--text3)', fontFamily:'DM Mono, monospace' }}>
              {f.resource_type}
            </span>
            <span style={{ fontSize:10, color:'var(--text3)', fontFamily:'DM Mono, monospace' }}>{f.resource}</span>
            {cis && <span style={{ fontSize:9, color:'var(--text3)', opacity:0.7 }}>{cis}</span>}
          </div>
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:8, flexShrink:0 }}>
          {f.mitre && (
            <span style={{ fontSize:9, background:'rgba(0,194,224,0.1)', border:'1px solid rgba(0,194,224,0.2)', color:'var(--accent)', borderRadius:4, padding:'1px 5px', fontFamily:'DM Mono, monospace' }}>
              {f.mitre}
            </span>
          )}
          {open ? <ChevronUp size={13} color="var(--text3)"/> : <ChevronDown size={13} color="var(--text3)"/>}
        </div>
      </div>

      {/* Expanded body */}
      {open && (
        <div style={{ padding:'0 14px 14px', borderTop:'1px solid var(--border)', paddingTop:12 }}>
          {/* Description */}
          <p style={{ fontSize:12, color:'var(--text2)', lineHeight:1.6, marginBottom:10 }}>{f.description}</p>

          {/* Remediation */}
          <div style={{ background:'rgba(52,211,153,0.06)', border:'1px solid rgba(52,211,153,0.15)', borderRadius:7, padding:'8px 12px', marginBottom:10 }}>
            <div style={{ fontSize:10, fontWeight:700, color:'#34d399', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:4 }}>✓ Remediation</div>
            <p style={{ fontSize:11.5, color:'var(--text2)', lineHeight:1.6 }}>{f.remediation}</p>
          </div>

          {/* Action bar */}
          <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' }}>
            <button onClick={explainWithAI} disabled={aiLoading}
              style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, padding:'5px 10px',
                background: aiText ? 'rgba(139,92,246,0.15)' : 'rgba(0,194,224,0.1)',
                border: `1px solid ${aiText ? 'rgba(139,92,246,0.3)' : 'rgba(0,194,224,0.25)'}`,
                color: aiText ? '#a78bfa' : 'var(--accent)', borderRadius:6, cursor:'pointer', fontFamily:'inherit' }}>
              <Sparkles size={11}/>{aiLoading ? 'Explaining…' : aiText ? 'Hide AI Explanation' : 'Explain with AI'}
            </button>
            {link && (
              <a href={link} target="_blank" rel="noopener noreferrer"
                style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, padding:'5px 10px',
                  background:'var(--surface2)', border:'1px solid var(--border)',
                  color:'var(--text2)', borderRadius:6, textDecoration:'none' }}>
                <ExternalLink size={11}/>Open in GCP Console
              </a>
            )}
            <span style={{ fontSize:10, color:'var(--text3)', marginLeft:'auto' }}>
              Found: {f.scanned_at ? format(new Date(f.scanned_at), 'MMM d, yyyy HH:mm') : '—'}
            </span>
          </div>

          {/* AI Explanation */}
          {aiText && (
            <div style={{ marginTop:10, background:'rgba(139,92,246,0.06)', border:'1px solid rgba(139,92,246,0.2)', borderRadius:8, padding:'12px 14px' }}>
              <div style={{ fontSize:10, fontWeight:700, color:'#a78bfa', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>
                ✦ AI Security Analyst
              </div>
              {aiText.plain_english && (
                <p style={{ fontSize:12, color:'var(--text)', lineHeight:1.6, marginBottom:8 }}>{aiText.plain_english}</p>
              )}
              {aiText.business_impact && (
                <div style={{ marginBottom:6 }}>
                  <span style={{ fontSize:10, color:'#f87171', fontWeight:600 }}>Business Impact: </span>
                  <span style={{ fontSize:11, color:'var(--text2)' }}>{aiText.business_impact}</span>
                </div>
              )}
              {aiText.urgency && (
                <div style={{ marginBottom:8 }}>
                  <span style={{ fontSize:10, color:'#fbbf24', fontWeight:600 }}>Urgency: </span>
                  <span style={{ fontSize:11, color:'var(--text2)' }}>{aiText.urgency}</span>
                </div>
              )}
              {aiText.steps?.length > 0 && (
                <div>
                  <div style={{ fontSize:10, color:'#34d399', fontWeight:600, marginBottom:4 }}>Steps:</div>
                  {aiText.steps.map((s,i) => (
                    <div key={i} style={{ display:'flex', gap:6, marginBottom:3 }}>
                      <span style={{ fontSize:10, color:'var(--accent)', fontFamily:'DM Mono, monospace', flexShrink:0 }}>{i+1}.</span>
                      <span style={{ fontSize:11, color:'var(--text2)', lineHeight:1.5 }}>{s}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── RiskScoreGauge ─────────────────────────────────────────────────────────────
function RiskScoreGauge({ score }) {
  const rl = riskLabel(score)
  const r = 40, cx = 52, cy = 52
  const circumference = 2 * Math.PI * r
  const dash = circumference * (score / 100)
  return (
    <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:4 }}>
      <svg width={104} height={104} viewBox="0 0 104 104">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border)" strokeWidth={8}/>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={rl.color} strokeWidth={8}
          strokeDasharray={`${dash} ${circumference}`}
          strokeLinecap="round"
          style={{ transformOrigin:'center', transform:'rotate(-90deg)', transition:'stroke-dasharray 0.6s ease' }}/>
        <text x={cx} y={cy-2} textAnchor="middle" style={{ fill:'var(--text)', fontSize:18, fontWeight:700, fontFamily:'DM Mono, monospace' }}>{score}</text>
        <text x={cx} y={cy+13} textAnchor="middle" style={{ fill:'var(--text3)', fontSize:9 }}>/100</text>
      </svg>
      <span style={{ fontSize:11, fontWeight:600, color:rl.color }}>{rl.label}</span>
    </div>
  )
}

// ── ComplianceBadges ───────────────────────────────────────────────────────────
function ComplianceBadges({ findings }) {
  const frameworks = [
    { name: 'CIS GCP 1.3', categories: ['iam','network','storage','compute','sql','logging','kms'] },
    { name: 'NIST CSF',    categories: ['iam','network','logging','kms'] },
    { name: 'ISO 27001',   categories: ['iam','storage','logging'] },
    { name: 'SOC 2',       categories: ['logging','iam','network'] },
  ]
  const catCount = {}
  for (const f of (findings||[])) {
    if (f.severity === 'critical' || f.severity === 'high') {
      catCount[f.category] = (catCount[f.category]||0) + 1
    }
  }
  return (
    <div style={{ display:'flex', gap:8, flexWrap:'wrap' }}>
      {frameworks.map(fw => {
        const issues = fw.categories.reduce((s,c) => s+(catCount[c]||0), 0)
        const status = issues === 0 ? 'pass' : issues <= 3 ? 'warn' : 'fail'
        const colors = { pass: ['#34d399','rgba(52,211,153,0.1)','rgba(52,211,153,0.2)'], warn: ['#fbbf24','rgba(251,191,36,0.1)','rgba(251,191,36,0.2)'], fail: ['#f87171','rgba(248,113,113,0.1)','rgba(248,113,113,0.2)'] }
        const [c, bg, border] = colors[status]
        return (
          <div key={fw.name} style={{ fontSize:10.5, padding:'4px 10px', borderRadius:6, background:bg, border:`1px solid ${border}`, color:c, fontWeight:600 }}>
            {status === 'pass' ? '✓' : status === 'warn' ? '⚠' : '✕'} {fw.name}
            {issues > 0 && <span style={{ marginLeft:4, opacity:0.8 }}>({issues})</span>}
          </div>
        )
      })}
    </div>
  )
}

// ── AssetInventory ─────────────────────────────────────────────────────────────
function AssetInventory({ findings }) {
  const inventory = {}
  for (const f of (findings||[])) {
    const t = f.resource_type || 'other'
    if (!inventory[t]) inventory[t] = { resources: new Set(), issues: 0 }
    inventory[t].resources.add(f.resource)
    inventory[t].issues++
  }
  const typeLabels = {
    firewall_rule: { icon: Wifi, label: 'Firewall Rules' },
    storage_bucket: { icon: HardDrive, label: 'Storage Buckets' },
    compute_instance: { icon: Server, label: 'Compute Instances' },
    cloud_sql: { icon: Database, label: 'Cloud SQL' },
    iam_binding: { icon: Lock, label: 'IAM Bindings' },
    service_account: { icon: Key, label: 'Service Accounts' },
    service_account_key: { icon: Key, label: 'SA Keys' },
    kms_key: { icon: Key, label: 'KMS Keys' },
    vpc_subnet: { icon: Layers, label: 'VPC Subnets' },
    dns_policy: { icon: Globe, label: 'DNS Policies' },
    audit_config: { icon: FileText, label: 'Audit Configs' },
  }
  return (
    <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(150px,1fr))', gap:8 }}>
      {Object.entries(inventory).map(([type, data]) => {
        const meta = typeLabels[type] || { icon: Shield, label: type }
        const Icon = meta.icon
        return (
          <div key={type} style={{ background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:8, padding:'10px 12px' }}>
            <div style={{ display:'flex', alignItems:'center', gap:6, marginBottom:4 }}>
              <Icon size={12} color="var(--text3)"/>
              <span style={{ fontSize:10, color:'var(--text3)', fontWeight:600 }}>{meta.label}</span>
            </div>
            <div style={{ fontSize:18, fontWeight:700, color:'var(--text)', fontFamily:'DM Mono, monospace' }}>{data.resources.size}</div>
            <div style={{ fontSize:10, color: data.issues > 0 ? '#f87171' : '#34d399' }}>
              {data.issues} issue{data.issues !== 1 ? 's' : ''}
            </div>
          </div>
        )
      })}
      {Object.keys(inventory).length === 0 && (
        <div style={{ gridColumn:'1/-1', textAlign:'center', color:'var(--text3)', fontSize:12, padding:20 }}>
          No assets found — run a scan first
        </div>
      )}
    </div>
  )
}

// ── NetworkExposure ────────────────────────────────────────────────────────────
function NetworkExposure({ findings }) {
  const exposed = (findings||[]).filter(f => f.category === 'network' || f.resource_type === 'compute_instance')
  const publicResources = {}
  for (const f of exposed) {
    if (!publicResources[f.resource]) publicResources[f.resource] = []
    publicResources[f.resource].push(f)
  }
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
      {Object.entries(publicResources).slice(0,8).map(([res, issues]) => (
        <div key={res} style={{ display:'flex', alignItems:'center', gap:8, padding:'8px 10px',
          background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:7 }}>
          <Globe size={12} color={issues.some(i => i.severity === 'critical') ? '#f87171' : '#fb923c'}/>
          <span style={{ flex:1, fontSize:11, color:'var(--text2)', fontFamily:'DM Mono, monospace' }}>{res}</span>
          <div style={{ display:'flex', gap:4 }}>
            {issues.map((issue,i) => (
              <span key={i} style={{ fontSize:9, padding:'1px 5px', borderRadius:4,
                background: SEV_BG[issue.severity], border:`1px solid ${SEV_BORDER[issue.severity]}`,
                color: SEV_COLOR[issue.severity] }}>
                {issue.severity}
              </span>
            ))}
          </div>
        </div>
      ))}
      {Object.keys(publicResources).length === 0 && (
        <div style={{ textAlign:'center', color:'#34d399', fontSize:12, padding:16 }}>
          ✓ No publicly exposed resources detected
        </div>
      )}
    </div>
  )
}

// ── IdentityRisk ───────────────────────────────────────────────────────────────
function IdentityRisk({ findings }) {
  const iamFindings = (findings||[]).filter(f => f.category === 'iam')
  const groups = {
    'Public Access (allUsers)':   iamFindings.filter(f => f.title?.includes('allUsers') || f.title?.includes('public')),
    'Primitive Roles (Owner/Editor)': iamFindings.filter(f => f.title?.includes('Primitive') || f.title?.includes('Owner') || f.title?.includes('Editor')),
    'Admin Roles on External Identities': iamFindings.filter(f => f.title?.includes('Admin') && f.title?.includes('external')),
    'Old Service Account Keys':   iamFindings.filter(f => f.resource_type === 'service_account_key'),
    'Default SA with Keys':       iamFindings.filter(f => f.title?.includes('Default service account')),
    'Other IAM Issues':           iamFindings.filter(f => {
      const titled = ['allUsers','public','Primitive','Owner','Editor','Admin','service_account_key','Default service account']
      return !titled.some(t => f.title?.includes(t))
    }),
  }
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
      {Object.entries(groups).map(([label, items]) => {
        if (!items.length) return null
        const worst = items.reduce((a,b) => {
          const order = ['critical','high','medium','low','info']
          return order.indexOf(a.severity) <= order.indexOf(b.severity) ? a : b
        }, items[0])
        return (
          <div key={label} style={{ display:'flex', alignItems:'center', justifyContent:'space-between',
            padding:'8px 10px', background:'var(--surface2)', border:`1px solid ${SEV_BORDER[worst.severity]}`,
            borderRadius:7 }}>
            <div style={{ display:'flex', alignItems:'center', gap:7 }}>
              <Lock size={11} color={SEV_COLOR[worst.severity]}/>
              <span style={{ fontSize:11.5, color:'var(--text)' }}>{label}</span>
            </div>
            <span style={{ fontSize:11, fontWeight:700, color: SEV_COLOR[worst.severity],
              background: SEV_BG[worst.severity], border:`1px solid ${SEV_BORDER[worst.severity]}`,
              borderRadius:4, padding:'1px 7px' }}>{items.length}</span>
          </div>
        )
      })}
      {!iamFindings.length && (
        <div style={{ textAlign:'center', color:'#34d399', fontSize:12, padding:16 }}>
          ✓ No IAM issues detected
        </div>
      )}
    </div>
  )
}

// ── CSPM Dashboard ─────────────────────────────────────────────────────────────
function CSPMDashboard({ conn, cspm, loading, onRunScan, scanning }) {
  const [section, setSection] = useState('findings') // findings|assets|network|identity|compliance
  const [sevFilter, setSevFilter] = useState('all')
  const [showErrors, setShowErrors] = useState(false)
  const [catFilter, setCatFilter] = useState('all')
  const [search, setSearch]     = useState('')
  const [aiSummary, setAiSummary] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)

  const score = riskScore(cspm)
  const rl    = riskLabel(score)

  const allFindings = cspm?.findings || []

  const filteredFindings = allFindings.filter(f => {
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false
    if (catFilter !== 'all' && f.category !== catFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return (f.title+f.description+f.resource+f.category).toLowerCase().includes(q)
    }
    return true
  })

  const categories = [...new Set(allFindings.map(f => f.category))].sort()

  const runAISummary = async () => {
    if (!cspm || aiLoading) return
    setAiLoading(true)
    try {
      const compact = {
        project: cspm.project_id,
        critical: cspm.critical, high: cspm.high, medium: cspm.medium, low: cspm.low, passed: cspm.passed,
        top_findings: allFindings
          .filter(f => f.severity === 'critical' || f.severity === 'high')
          .slice(0,15)
          .map(f => ({ sev: f.severity, cat: f.category, title: f.title, resource: f.resource }))
      }
      const prompt = `You are a GCP cloud security architect. Analyse this CSPM scan and give a concise executive summary.

Return ONLY this JSON (no markdown):
{
  "executive_summary": "2-3 sentences for a CISO — overall posture and top concerns",
  "top_risks": ["risk 1", "risk 2", "risk 3"],
  "immediate_actions": ["action 1 with specific GCP console path", "action 2", "action 3"],
  "compliance_notes": "brief note on CIS GCP benchmark compliance status",
  "positive_findings": ["what is configured correctly"]
}

CSPM Data:
${JSON.stringify(compact)}`
      const { data } = await api.post('/api/v1/cloud-connectors/ai-explain', { prompt })
      const text = data.content?.find(b => b.type === 'text')?.text || data.text || ''
      const clean = text.replace(/\x60{3}json\n?|\x60{3}/g, '').trim()
      try { setAiSummary(JSON.parse(clean)) } catch { setAiSummary({ executive_summary: clean }) }
    } catch { setAiSummary({ executive_summary: 'AI summary unavailable — configure an AI key in Settings.' }) }
    finally { setAiLoading(false) }
  }

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden' }}>

      {/* ── Top action bar ── */}
      <div style={{ flexShrink:0, padding:'14px 20px', borderBottom:'1px solid var(--border)',
        background:'var(--surface)', display:'flex', alignItems:'center', justifyContent:'space-between', gap:12 }}>
        <div>
          <div style={{ fontSize:13, fontWeight:700, color:'var(--text)' }}>Cloud Security Posture — {cspm?.project_id || conn.account_id}</div>
          {cspm && <div style={{ fontSize:10.5, color:'var(--text3)', marginTop:2 }}>
            Last scan: {cspm.scanned_at ? format(new Date(cspm.scanned_at), 'MMM d, yyyy HH:mm') : '—'} · {cspm.scan_duration}
            {cspm.scc_enabled && <span style={{ color:'#34d399', marginLeft:8 }}>✓ SCC connected ({cspm.scc_findings||0} findings)</span>}
            {cspm.errors?.length > 0 && (
              <button onClick={() => setShowErrors(e => !e)}
                style={{ marginLeft:8, background:'rgba(251,146,60,0.1)', border:'1px solid rgba(251,146,60,0.25)',
                  color:'#fb923c', borderRadius:4, padding:'1px 7px', fontSize:10.5, cursor:'pointer', fontFamily:'inherit' }}>
                ⚠ {cspm.errors.length} check failed — click to see
              </button>
            )}
          </div>}
        </div>
        <div style={{ display:'flex', gap:8, alignItems:'center' }}>
          {cspm && (
            <button onClick={runAISummary} disabled={aiLoading}
              style={{ display:'flex', alignItems:'center', gap:5, fontSize:11.5, padding:'7px 13px',
                background:'rgba(139,92,246,0.1)', border:'1px solid rgba(139,92,246,0.25)',
                color:'#a78bfa', borderRadius:7, cursor:aiLoading?'wait':'pointer', fontFamily:'inherit', fontWeight:600 }}>
              <Sparkles size={12}/>{aiLoading ? 'Analysing…' : 'AI Summary'}
            </button>
          )}
          <button onClick={onRunScan} disabled={scanning}
            style={{ display:'flex', alignItems:'center', gap:6, fontSize:11.5, padding:'7px 14px',
              background: scanning ? 'var(--surface2)' : 'var(--accent)',
              color: scanning ? 'var(--text2)' : '#000',
              border:'none', borderRadius:7, cursor: scanning?'wait':'pointer', fontFamily:'inherit', fontWeight:700 }}>
            <RefreshCw size={12} style={scanning ? { animation:'spin 0.8s linear infinite' } : {}}/>
            {scanning ? 'Scanning…' : 'Run Scan'}
          </button>
        </div>
      </div>

      <div style={{ flex:1, overflow:'auto', padding:'16px 20px' }}>

        {/* ── Scan Errors Panel ── */}
        {showErrors && cspm?.errors?.length > 0 && (
          <div style={{ marginBottom:16, background:'rgba(251,146,60,0.06)', border:'1px solid rgba(251,146,60,0.25)', borderRadius:10, overflow:'hidden' }}>
            <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', padding:'10px 14px', borderBottom:'1px solid rgba(251,146,60,0.2)' }}>
              <div style={{ display:'flex', alignItems:'center', gap:7 }}>
                <span style={{ fontSize:12, fontWeight:700, color:'#fb923c' }}>⚠ Scan Check Failures</span>
                <span style={{ fontSize:10.5, color:'var(--text3)' }}>These checks could not run — usually missing IAM role or API not enabled</span>
              </div>
              <button onClick={() => setShowErrors(false)}
                style={{ background:'none', border:'none', color:'var(--text3)', cursor:'pointer', fontSize:16, padding:'0 4px', fontFamily:'inherit' }}>×</button>
            </div>
            {cspm.errors.map((err, i) => {
              const checkName = err.split(':')[0]
              const errMsg = err.slice(checkName.length + 1).trim()
              const is403 = errMsg.includes('403') || errMsg.includes('permission denied')
              const is404 = errMsg.includes('404') || errMsg.includes('not found')
              const requiredRoles = {
                kms:              'roles/cloudkms.viewer  +  enable cloudkms.googleapis.com API',
                vpc_flow_logs:    'roles/compute.networkViewer',
                dns_logging:      'roles/dns.reader  +  enable dns.googleapis.com API',
                sql:              'roles/cloudsql.viewer',
                storage:          'roles/storage.objectViewer',
                service_accounts: 'roles/iam.serviceAccountViewer',
                iam:              'roles/iam.securityReviewer',
                compute:          'roles/compute.viewer',
                audit_logging:    'roles/iam.securityReviewer',
                firewall:         'roles/compute.viewer',
                scc:              'roles/securitycenter.findingsViewer  +  enable securitycenter.googleapis.com API',
              }
              return (
                <div key={i} style={{ padding:'10px 14px', borderBottom: i < cspm.errors.length-1 ? '1px solid rgba(251,146,60,0.1)' : 'none' }}>
                  <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
                    <code style={{ fontSize:11, background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:4, padding:'1px 6px', color:'#fb923c', fontFamily:'DM Mono, monospace' }}>{checkName}</code>
                    <span style={{ fontSize:10.5, color: is403 ? '#f87171' : is404 ? '#38bdf8' : '#fb923c' }}>
                      {is403 ? '403 Permission Denied' : is404 ? '404 Not Found / API disabled' : 'Error'}
                    </span>
                  </div>
                  <div style={{ fontSize:11, color:'var(--text3)', fontFamily:'DM Mono, monospace', marginBottom:6, wordBreak:'break-all' }}>{errMsg.slice(0, 200)}</div>
                  {requiredRoles[checkName] && (
                    <div style={{ display:'flex', alignItems:'center', gap:5, fontSize:10.5 }}>
                      <span style={{ color:'#34d399', fontWeight:600 }}>Fix:</span>
                      <code style={{ color:'var(--text2)', fontFamily:'DM Mono, monospace', background:'var(--surface2)', padding:'1px 6px', borderRadius:4 }}>
                        {requiredRoles[checkName]}
                      </code>
                    </div>
                  )}
                </div>
              )
            })}
            <div style={{ padding:'10px 14px', background:'rgba(0,0,0,0.2)', fontSize:11, color:'var(--text3)' }}>
              The service account needs <strong style={{ color:'var(--text2)' }}>roles/viewer</strong> or <strong style={{ color:'var(--text2)' }}>roles/security-reviewer</strong> at minimum.
              Checks that fail are skipped — other findings are still shown.
            </div>
          </div>
        )}

        {loading && (
          <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:200, color:'var(--text3)', gap:8 }}>
            <RefreshCw size={16} style={{ animation:'spin 0.8s linear infinite' }}/> Loading last scan…
          </div>
        )}

        {!loading && !cspm && !scanning && (
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', height:300, gap:12 }}>
            <Shield size={48} color="var(--border)" strokeWidth={1}/>
            <div style={{ fontSize:15, fontWeight:600, color:'var(--text2)' }}>No scan results yet</div>
            <div style={{ fontSize:12, color:'var(--text3)' }}>Click "Run Scan" to check your cloud security posture</div>
          </div>
        )}

        {cspm && !loading && (<>

          {/* ── Summary row ── */}
          <div style={{ display:'grid', gridTemplateColumns:'auto 1fr auto', gap:16, marginBottom:16, alignItems:'start' }}>

            {/* Risk score */}
            <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:'16px 20px', display:'flex', flexDirection:'column', alignItems:'center', gap:8 }}>
              <RiskScoreGauge score={score}/>
              <div style={{ fontSize:10, color:'var(--text3)', textAlign:'center' }}>Risk Score</div>
            </div>

            {/* KPIs */}
            <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:8 }}>
              {[
                { label:'Critical', value: cspm.critical, color:'#f87171' },
                { label:'High',     value: cspm.high,     color:'#fb923c' },
                { label:'Medium',   value: cspm.medium,   color:'#fbbf24' },
                { label:'Low',      value: cspm.low,      color:'#38bdf8' },
                { label:'Passed',   value: cspm.passed,   color:'#34d399' },
                { label:'Total',    value: cspm.total_findings, color:'var(--text2)' },
              ].map(k => (
                <div key={k.label} style={{ background:'var(--surface)', border:'1px solid var(--border)',
                  borderRadius:8, padding:'10px 12px', borderTop:`2px solid ${k.color}` }}>
                  <div style={{ fontSize:10, color:'var(--text3)', marginBottom:4, fontWeight:600, textTransform:'uppercase', letterSpacing:'0.06em' }}>{k.label}</div>
                  <div style={{ fontSize:22, fontWeight:700, color:k.color, fontFamily:'DM Mono, monospace' }}>{k.value||0}</div>
                </div>
              ))}
            </div>

            {/* Compliance + SCC status */}
            <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:'16px', minWidth:220 }}>
              <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:10 }}>Compliance Status</div>
              <ComplianceBadges findings={allFindings}/>
              <div style={{ marginTop:12, paddingTop:10, borderTop:'1px solid var(--border)' }}>
                <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:6 }}>Security Command Center</div>
                {cspm.scc_enabled ? (
                  <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                    <span style={{ width:7, height:7, borderRadius:'50%', background:'#34d399', display:'inline-block' }}/>
                    <span style={{ fontSize:11, color:'#34d399', fontWeight:600 }}>Connected</span>
                    <span style={{ fontSize:10.5, color:'var(--text3)' }}>· {cspm.scc_findings||0} findings</span>
                  </div>
                ) : (
                  <div>
                    <div style={{ display:'flex', alignItems:'center', gap:6, marginBottom:4 }}>
                      <span style={{ width:7, height:7, borderRadius:'50%', background:'var(--text3)', display:'inline-block' }}/>
                      <span style={{ fontSize:11, color:'var(--text3)' }}>Not connected</span>
                    </div>
                    <div style={{ fontSize:10, color:'var(--text3)', lineHeight:1.5 }}>
                      Enable for 500+ GCP built-in checks, threat detection, and compliance posture.
                    </div>
                    <a href="https://console.cloud.google.com/security/command-center" target="_blank" rel="noopener noreferrer"
                      style={{ display:'inline-flex', alignItems:'center', gap:4, marginTop:6, fontSize:10.5,
                        color:'var(--accent)', textDecoration:'none' }}>
                      Enable SCC →
                    </a>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* ── AI Summary (if loaded) ── */}
          {aiSummary && (
            <div style={{ background:'rgba(139,92,246,0.06)', border:'1px solid rgba(139,92,246,0.2)', borderRadius:10, padding:'14px 16px', marginBottom:16 }}>
              <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:8 }}>
                <div style={{ fontSize:10, fontWeight:700, color:'#a78bfa', textTransform:'uppercase', letterSpacing:'0.06em' }}>✦ AI Executive Summary</div>
                <button onClick={() => setAiSummary(null)} style={{ background:'none', border:'none', color:'var(--text3)', cursor:'pointer', padding:0 }}>
                  <X size={13}/>
                </button>
              </div>
              {aiSummary.executive_summary && (
                <p style={{ fontSize:12.5, color:'var(--text)', lineHeight:1.7, marginBottom:10 }}>{aiSummary.executive_summary}</p>
              )}
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12 }}>
                {aiSummary.top_risks?.length > 0 && (
                  <div>
                    <div style={{ fontSize:10, color:'#f87171', fontWeight:600, marginBottom:5 }}>⚠ Top Risks</div>
                    {aiSummary.top_risks.map((r,i) => <div key={i} style={{ fontSize:11, color:'var(--text2)', marginBottom:3, lineHeight:1.4 }}>• {r}</div>)}
                  </div>
                )}
                {aiSummary.immediate_actions?.length > 0 && (
                  <div>
                    <div style={{ fontSize:10, color:'#34d399', fontWeight:600, marginBottom:5 }}>✓ Immediate Actions</div>
                    {aiSummary.immediate_actions.map((a,i) => <div key={i} style={{ fontSize:11, color:'var(--text2)', marginBottom:3, lineHeight:1.4 }}>• {a}</div>)}
                  </div>
                )}
                {aiSummary.positive_findings?.length > 0 && (
                  <div>
                    <div style={{ fontSize:10, color:'#38bdf8', fontWeight:600, marginBottom:5 }}>✦ Doing Well</div>
                    {aiSummary.positive_findings.map((p,i) => <div key={i} style={{ fontSize:11, color:'var(--text2)', marginBottom:3, lineHeight:1.4 }}>• {p}</div>)}
                  </div>
                )}
              </div>
              {aiSummary.compliance_notes && (
                <div style={{ marginTop:8, fontSize:11, color:'var(--text3)', fontStyle:'italic', borderTop:'1px solid rgba(139,92,246,0.15)', paddingTop:8 }}>
                  {aiSummary.compliance_notes}
                </div>
              )}
            </div>
          )}

          {/* ── Section nav ── */}
          <div style={{ display:'flex', gap:4, marginBottom:14, borderBottom:'1px solid var(--border)', paddingBottom:0 }}>
            {[
              { id:'findings',   label:'Findings',         icon: Shield,    count: allFindings.length },
              { id:'assets',     label:'Asset Inventory',  icon: Layers,    count: null },
              { id:'network',    label:'Network Exposure', icon: Wifi,      count: allFindings.filter(f=>f.category==='network').length },
              { id:'identity',   label:'Identity & Access',icon: Lock,      count: allFindings.filter(f=>f.category==='iam').length },
            ].map(({ id, label, icon: Icon, count }) => (
              <button key={id} onClick={() => setSection(id)}
                style={{ display:'flex', alignItems:'center', gap:5, padding:'7px 13px', fontSize:11.5,
                  background: section===id ? 'rgba(0,194,224,0.1)' : 'transparent',
                  color: section===id ? 'var(--accent)' : 'var(--text3)',
                  border:'none', borderBottom: section===id ? '2px solid var(--accent)' : '2px solid transparent',
                  cursor:'pointer', fontFamily:'inherit', fontWeight: section===id ? 600 : 400,
                  marginBottom:-1 }}>
                <Icon size={12}/>
                {label}
                {count !== null && count > 0 && (
                  <span style={{ fontSize:9.5, background:'rgba(0,194,224,0.15)', color:'var(--accent)',
                    borderRadius:10, padding:'0 5px', minWidth:16, textAlign:'center' }}>{count}</span>
                )}
              </button>
            ))}
          </div>

          {/* ── Findings section ── */}
          {section === 'findings' && (
            <div>
              {/* Filter bar */}
              <div style={{ display:'flex', gap:8, marginBottom:12, flexWrap:'wrap', alignItems:'center' }}>
                <div style={{ position:'relative', flex:1, minWidth:200 }}>
                  <Search size={11} style={{ position:'absolute', left:9, top:'50%', transform:'translateY(-50%)', color:'var(--text3)' }}/>
                  <input value={search} onChange={e => setSearch(e.target.value)}
                    placeholder="Search findings…"
                    style={{ width:'100%', background:'var(--surface)', border:'1px solid var(--border)',
                      borderRadius:7, paddingLeft:28, paddingRight:10, paddingTop:6, paddingBottom:6,
                      fontSize:11.5, color:'var(--text)', outline:'none', fontFamily:'inherit', boxSizing:'border-box' }}/>
                </div>
                <div style={{ display:'flex', gap:4 }}>
                  {['all','critical','high','medium','low'].map(s => (
                    <button key={s} onClick={() => setSevFilter(s)}
                      style={{ fontSize:10.5, padding:'4px 10px', borderRadius:6,
                        background: sevFilter===s ? (SEV_BG[s]||'rgba(0,194,224,0.1)') : 'var(--surface)',
                        border: `1px solid ${sevFilter===s ? (SEV_BORDER[s]||'rgba(0,194,224,0.3)') : 'var(--border)'}`,
                        color: sevFilter===s ? (SEV_COLOR[s]||'var(--accent)') : 'var(--text3)',
                        cursor:'pointer', fontFamily:'inherit', fontWeight: sevFilter===s ? 600 : 400 }}>
                      {s.charAt(0).toUpperCase()+s.slice(1)}
                    </button>
                  ))}
                </div>
                {categories.length > 0 && (
                  <select value={catFilter} onChange={e => setCatFilter(e.target.value)}
                    style={{ fontSize:11, padding:'5px 8px', background:'var(--surface)', border:'1px solid var(--border)',
                      borderRadius:6, color:'var(--text2)', outline:'none', fontFamily:'inherit' }}>
                    <option value="all">All categories</option>
                    {categories.map(c => <option key={c} value={c}>{CAT_META[c]?.label || c}</option>)}
                  </select>
                )}
                <span style={{ fontSize:10.5, color:'var(--text3)', marginLeft:'auto' }}>
                  {filteredFindings.length} of {allFindings.length} findings
                </span>
              </div>

              {/* Findings grouped by severity */}
              {['critical','high','medium','low'].map(sev => {
                const group = filteredFindings.filter(f => f.severity === sev)
                if (!group.length) return null
                return (
                  <div key={sev} style={{ marginBottom:16 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:8 }}>
                      <span style={{ width:7, height:7, borderRadius:'50%', background:SEV_COLOR[sev], display:'inline-block', flexShrink:0 }}/>
                      <span style={{ fontSize:11.5, fontWeight:700, color:SEV_COLOR[sev], textTransform:'uppercase', letterSpacing:'0.07em' }}>
                        {sev} — {group.length} finding{group.length!==1?'s':''}
                      </span>
                    </div>
                    <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                      {group.map((f,i) => (
                        <FindingCard key={f.id||i} f={f} provider={conn.provider} projectId={cspm.project_id}/>
                      ))}
                    </div>
                  </div>
                )
              })}

              {filteredFindings.length === 0 && (
                <div style={{ textAlign:'center', padding:40, color:search||sevFilter!=='all' ? 'var(--text3)' : '#34d399', fontSize:13 }}>
                  {search||sevFilter!=='all' ? 'No findings match your filter' : '✓ No findings — your cloud posture looks clean!'}
                </div>
              )}
            </div>
          )}

          {/* ── Asset Inventory section ── */}
          {section === 'assets' && (
            <div>
              <div style={{ fontSize:12, color:'var(--text3)', marginBottom:12 }}>
                Resources detected across your GCP project with outstanding security findings.
              </div>
              <AssetInventory findings={allFindings}/>
            </div>
          )}

          {/* ── Network Exposure section ── */}
          {section === 'network' && (
            <div>
              <div style={{ fontSize:12, color:'var(--text3)', marginBottom:12 }}>
                Resources with network-level exposure — open firewall rules, public IPs, publicly accessible services.
              </div>
              <NetworkExposure findings={allFindings}/>
              <div style={{ marginTop:16 }}>
                <div style={{ fontSize:11, fontWeight:600, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>All Network Findings</div>
                <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                  {allFindings.filter(f => f.category === 'network').map((f,i) => (
                    <FindingCard key={f.id||i} f={f} provider={conn.provider} projectId={cspm.project_id}/>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── Identity & Access section ── */}
          {section === 'identity' && (
            <div>
              <div style={{ fontSize:12, color:'var(--text3)', marginBottom:12 }}>
                IAM misconfigurations, excessive permissions, service account key risks.
              </div>
              <IdentityRisk findings={allFindings}/>
              <div style={{ marginTop:16 }}>
                <div style={{ fontSize:11, fontWeight:600, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>All IAM Findings</div>
                <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                  {allFindings.filter(f => f.category === 'iam').map((f,i) => (
                    <FindingCard key={f.id||i} f={f} provider={conn.provider} projectId={cspm.project_id}/>
                  ))}
                </div>
              </div>
            </div>
          )}

        </>)}
      </div>
    </div>
  )
}

// ── CloudEventsAlerts — clickable event + alert rows with slide-out panels ────
const SEV_LABELS = ['', 'Info', 'Low', 'Medium', 'High', 'Critical']
const SEV_COLORS_CLS = ['', 'text-siem-muted', 'text-blue-400', 'text-yellow-400', 'text-orange-400', 'text-red-400']

function CloudEventPanel({ event, onClose }) {
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(true)
  const [aiText, setAiText]   = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('details')

  useEffect(() => {
    setLoading(true)
    api.get(`/api/v1/events/${event.id}`)
      .then(r => setDetail(r.data))
      .catch(() => setDetail(null))
      .finally(() => setLoading(false))
  }, [event.id])

  // Auto-run AI on open
  useEffect(() => {
    if (!loading && detail && !aiText && !aiLoading) runAI()
  }, [loading, detail])

  const ev = detail?.event || event
  const related = detail?.related || []

  const runAI = async () => {
    setAiLoading(true)
    try {
      const raw = ev.raw ? (typeof ev.raw === 'string' ? ev.raw : JSON.stringify(ev.raw)) : ''
      const res = await api.post('/api/v1/ai/analyse', {
        title:       ev.event_type || 'Cloud Event',
        severity:    ev.severity || 3,
        description: `Cloud event from ${ev.source || ev.host}`,
        host:        ev.host || '',
        event_type:  ev.event_type || '',
        raw_event:   raw.slice(0, 3000),
      })
      const text = res.data.content?.find(b => b.type === 'text')?.text || ''
      const clean = text.replace(/\x60{3}json\n?|\x60{3}/g, '').trim()
      const start = clean.indexOf('{'), end = clean.lastIndexOf('}')
      if (start !== -1 && end !== -1) {
        try { setAiText(JSON.parse(clean.slice(start, end+1))) } catch { setAiText({ summary: clean }) }
      }
    } catch { /* no AI configured - silent */ }
    finally { setAiLoading(false) }
  }

  const rawObj = ev.raw ? (typeof ev.raw === 'string' ? (() => { try { return JSON.parse(ev.raw) } catch { return ev.raw } })() : ev.raw) : null

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-2xl bg-siem-surface border-l border-siem-border h-full overflow-y-auto shadow-2xl flex flex-col"
           onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex-shrink-0 flex items-center justify-between px-5 py-4 border-b border-siem-border sticky top-0 bg-siem-surface z-10">
          <div className="flex items-center gap-2">
            <span className={`text-[10px] border rounded px-1.5 py-0.5 font-mono ${SEV_COLORS_CLS[ev.severity]||'text-siem-muted'} border-current/30`}>
              {SEV_LABELS[ev.severity]||'Event'}
            </span>
            <span className="text-xs font-mono text-siem-accent">{ev.event_type}</span>
            <span className="text-xs text-siem-muted">· {ev.host || ev.source}</span>
          </div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text"><X size={18}/></button>
        </div>

        {/* Tabs */}
        <div className="flex-shrink-0 flex gap-1 px-5 py-2 border-b border-siem-border">
          {[
            { id: 'ai',      label: 'AI Analysis', icon: Sparkles },
            { id: 'details', label: 'Details',      icon: List },
            { id: 'raw',     label: 'Raw',          icon: FileText },
          ].map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setActiveTab(id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                activeTab === id ? 'bg-siem-accent text-black' : 'text-siem-muted hover:text-siem-text'
              }`}>
              <Icon size={11}/>{label}
              {id === 'ai' && aiLoading && <RefreshCw size={9} className="animate-spin"/>}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center justify-center flex-1 text-siem-muted text-sm gap-2">
            <RefreshCw size={14} className="animate-spin"/>Loading…
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto p-5 space-y-4">

            {/* AI Analysis Tab */}
            {activeTab === 'ai' && (
              <div>
                {aiLoading && (
                  <div className="flex items-center gap-2 text-siem-muted text-sm p-6">
                    <RefreshCw size={14} className="animate-spin"/>Analysing with AI…
                  </div>
                )}
                {!aiLoading && !aiText && (
                  <div className="flex flex-col items-center gap-3 py-10 text-siem-muted">
                    <Sparkles size={24} className="opacity-40"/>
                    <span className="text-xs">No AI provider configured</span>
                    <button onClick={runAI} className="text-xs border border-siem-border px-3 py-1.5 rounded-lg hover:text-siem-text">
                      Retry Analysis
                    </button>
                  </div>
                )}
                {aiText && (
                  <div className="space-y-4">
                    {aiText.summary && (
                      <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
                        <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">Summary</div>
                        <p className="text-sm text-siem-text leading-relaxed">{aiText.summary}</p>
                      </div>
                    )}
                    {aiText.what_happened && (
                      <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
                        <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">What Happened</div>
                        <p className="text-xs text-siem-text/80 leading-relaxed">{aiText.what_happened}</p>
                      </div>
                    )}
                    {aiText.threat_assessment && (
                      <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
                        <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">Threat Assessment</div>
                        <p className="text-xs text-siem-text/80 leading-relaxed">{aiText.threat_assessment}</p>
                      </div>
                    )}
                    {aiText.recommended_actions?.length > 0 && (
                      <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
                        <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">Recommended Actions</div>
                        <div className="space-y-1">
                          {aiText.recommended_actions.map((a, i) => (
                            <div key={i} className="flex gap-2 text-xs text-siem-text/80">
                              <span className="text-siem-accent font-mono shrink-0">{i+1}.</span>{a}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {aiText.false_positive_indicators && (
                      <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
                        <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">False Positive Indicators</div>
                        <p className="text-xs text-siem-text/70 leading-relaxed">{aiText.false_positive_indicators}</p>
                      </div>
                    )}
                    <button onClick={runAI} disabled={aiLoading}
                      className="text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-1.5 flex items-center gap-1.5 disabled:opacity-40">
                      <RefreshCw size={11}/>Re-run Analysis
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* Details Tab */}
            {activeTab === 'details' && (
              <div className="space-y-4">
                <div className="bg-siem-bg rounded-xl border border-siem-border overflow-hidden">
                  {[
                    ['Time',       ev.time ? format(new Date(ev.time), 'yyyy-MM-dd HH:mm:ss') : '—'],
                    ['Event Type', ev.event_type],
                    ['Source',     ev.source],
                    ['Host',       ev.host],
                    ['Severity',   SEV_LABELS[ev.severity] || ev.severity],
                    ['Agent ID',   ev.agent_id],
                  ].filter(([,v]) => v).map(([label, value], i) => (
                    <div key={label} className={`flex gap-3 px-4 py-2.5 text-sm ${i%2===0?'':'bg-white/[0.02]'}`}>
                      <span className="text-siem-muted w-28 shrink-0 text-xs">{label}</span>
                      <span className="text-siem-text font-mono text-xs break-all">{String(value)}</span>
                    </div>
                  ))}
                </div>
                {related.length > 0 && (
                  <div>
                    <div className="text-xs uppercase tracking-wider text-siem-muted mb-2">Related Events (±5 min)</div>
                    <div className="space-y-1">
                      {related.slice(0,10).map((r, i) => (
                        <div key={i} className="flex items-center gap-2 text-[11px] bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5">
                          <span className="text-siem-muted font-mono">{format(new Date(r.time), 'HH:mm:ss')}</span>
                          <span className="text-siem-accent font-mono">{r.event_type}</span>
                          <span className="text-siem-muted truncate flex-1">{r.source}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Raw Tab */}
            {activeTab === 'raw' && rawObj && (
              <pre className="bg-siem-bg border border-siem-border rounded-xl p-4 text-xs text-siem-accent overflow-x-auto max-h-[60vh] whitespace-pre-wrap break-all">
                {JSON.stringify(rawObj, null, 2)}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function CloudAlertPanel({ alert, onClose, users }) {
  // Reuse AlertPanel directly - pass the alert id
  const AlertPanelComponent = AlertPanel
  return <AlertPanelComponent alertId={alert.id} users={users} onClose={onClose} onStatusChange={() => {}}/>
}

function CloudEventsAlerts({ tab, events, alerts, loadingE, loadingA, search, setSearch }) {
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [selectedAlert, setSelectedAlert] = useState(null)

  const filteredEvents = search
    ? events.filter(e => JSON.stringify(e).toLowerCase().includes(search.toLowerCase()))
    : events
  const filteredAlerts = search
    ? alerts.filter(a => (a.title+a.description).toLowerCase().includes(search.toLowerCase()))
    : alerts

  return (
    <div className="flex flex-col h-full">
      {/* Search */}
      <div className="flex-shrink-0 px-5 py-2 border-b border-siem-border">
        <div className="relative">
          <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-siem-muted"/>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter…"
            className="w-full bg-siem-bg border border-siem-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-siem-text focus:outline-none focus:border-siem-accent"/>
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto divide-y divide-siem-border/50">

        {tab === 'events' && <>
          {loadingE && (
            <div className="flex items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <RefreshCw size={14} className="animate-spin"/>Loading events…
            </div>
          )}
          {!loadingE && filteredEvents.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <Activity size={20} className="opacity-30"/>No cloud events yet
            </div>
          )}
          {filteredEvents.map(ev => (
            <button key={ev.id} onClick={() => setSelectedEvent(ev)}
              className="w-full px-5 py-3 hover:bg-siem-surface/60 text-left transition-colors group">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <span className={`text-[10px] font-mono border rounded px-1.5 py-0.5 shrink-0 ${SEV_COLORS_CLS[ev.severity]||'text-siem-muted'} border-current/30`}>
                    {SEV_LABELS[ev.severity]||'—'}
                  </span>
                  <span className="text-[10px] font-mono text-siem-accent shrink-0">{ev.event_type}</span>
                  <span className="text-xs text-siem-text truncate">{ev.source || ev.host}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] text-siem-muted opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1">
                    <Sparkles size={9}/> AI
                  </span>
                  <span className="text-[10px] text-siem-muted">{ev.time ? formatDistanceToNow(new Date(ev.time), { addSuffix: true }) : ''}</span>
                  <ChevronRight size={12} className="text-siem-muted/40 group-hover:text-siem-accent transition-colors"/>
                </div>
              </div>
              {ev.user_name && <div className="text-[10px] text-siem-muted mt-0.5 ml-16">User: {ev.user_name}</div>}
            </button>
          ))}
        </>}

        {tab === 'alerts' && <>
          {loadingA && (
            <div className="flex items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <RefreshCw size={14} className="animate-spin"/>Loading alerts…
            </div>
          )}
          {!loadingA && filteredAlerts.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <Bell size={20} className="opacity-30"/>No cloud alerts
            </div>
          )}
          {filteredAlerts.map(a => {
            const sevColor = ['','text-siem-muted','text-blue-400','text-yellow-400','text-orange-400','text-red-400'][a.severity]||'text-siem-muted'
            const statusColor = { open:'text-red-400', acknowledged:'text-yellow-400', closed:'text-siem-muted' }[a.status]||'text-siem-muted'
            return (
              <button key={a.id} onClick={() => setSelectedAlert(a)}
                className="w-full px-5 py-3 hover:bg-siem-surface/60 text-left transition-colors group">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className={`text-[10px] font-mono shrink-0 ${sevColor}`}>
                      {SEV_LABELS[a.severity]||'—'}
                    </span>
                    <span className="text-xs font-medium text-siem-text truncate">{a.title}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] text-siem-muted opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1">
                      <Sparkles size={9}/> AI
                    </span>
                    <span className={`text-[10px] ${statusColor}`}>{a.status}</span>
                    <span className="text-[10px] text-siem-muted">{a.created_at ? formatDistanceToNow(new Date(a.created_at), { addSuffix: true }) : ''}</span>
                    <ChevronRight size={12} className="text-siem-muted/40 group-hover:text-siem-accent transition-colors"/>
                  </div>
                </div>
                {a.description && (
                  <div className="text-[10px] text-siem-muted mt-1 line-clamp-1 ml-8">{a.description}</div>
                )}
              </button>
            )
          })}
        </>}
      </div>

      {/* Slide-out panels */}
      {selectedEvent && <CloudEventPanel event={selectedEvent} onClose={() => setSelectedEvent(null)}/>}
      {selectedAlert && <AlertPanel alertId={selectedAlert.id} users={[]} onClose={() => setSelectedAlert(null)} onStatusChange={() => {}}/>}
    </div>
  )
}

// ── ConnectorDetail ────────────────────────────────────────────────────────────
function ConnectorDetail({ conn, onSync, onDisconnect, syncing }) {
  const [tab, setTab]           = useState('cspm')
  const [cspm, setCspm]         = useState(null)
  const [cspmLoading, setCspmLoading] = useState(false)
  const [cspmScanning, setCspmScanning] = useState(false)
  const [events, setEvents]     = useState([])
  const [alerts, setAlerts]     = useState([])
  const [loadingE, setLoadingE] = useState(false)
  const [loadingA, setLoadingA] = useState(false)
  const [search, setSearch]     = useState('')

  const loadEvents = useCallback(async () => {
    setLoadingE(true)
    try {
      // Fetch only events belonging to this cloud provider
      // GCP:   cloud.gcp_audit
      // AWS:   cloud.cloudtrail, cloud.guardduty
      // Azure: cloud.azure_activity, cloud.entra_signin
      const providerEventTypes = {
        gcp:   ['cloud.gcp_audit'],
        aws:   ['cloud.cloudtrail', 'cloud.guardduty'],
        azure: ['cloud.azure_activity', 'cloud.entra_signin'],
      }
      const provider = conn.provider || 'gcp'
      const types = providerEventTypes[provider] || [`cloud.${provider}`]

      // Fetch once per event type and merge
      const results = await Promise.all(
        types.map(et => api.get('/api/v1/events', { params: { event_type: et, limit: 200 } })
          .then(r => r.data?.events || []).catch(() => []))
      )
      const merged = results.flat().sort((a,b) => new Date(b.time) - new Date(a.time))
      setEvents(merged.slice(0, 500))
    } catch { setEvents([]) } finally { setLoadingE(false) }
  }, [conn.provider])

  const loadAlerts = useCallback(async () => {
    setLoadingA(true)
    try {
      const { data } = await api.get('/api/v1/alerts', { params: { limit: 200 } })
      const allAlerts = Array.isArray(data) ? data : (data?.alerts || [])
      const providerEventTypes = {
        gcp:   ['cloud.gcp_audit'],
        aws:   ['cloud.cloudtrail', 'cloud.guardduty'],
        azure: ['cloud.azure_activity', 'cloud.entra_signin'],
      }
      const provider = conn.provider || 'gcp'
      const types = providerEventTypes[provider] || [`cloud.${provider}`]
      setAlerts(allAlerts.filter(a => types.includes(a.event_type)))
    } catch { setAlerts([]) } finally { setLoadingA(false) }
  }, [conn.provider])

  const loadCSPM = useCallback(async () => {
    setCspmLoading(true)
    try {
      const { data } = await api.get(`/api/v1/cloud-connectors/${conn.id}/cspm`)
      setCspm(data?.project_id ? data : null)
    } catch { setCspm(null) } finally { setCspmLoading(false) }
  }, [conn.id])

  const runCSPM = async () => {
    setCspmScanning(true)
    try {
      const { data } = await api.post(`/api/v1/cloud-connectors/${conn.id}/cspm`)
      setCspm(data)
    } catch (e) { alert('CSPM scan failed: ' + (e.response?.data?.error || e.message)) }
    finally { setCspmScanning(false) }
  }

  useEffect(() => {
    if (tab === 'events') loadEvents()
    if (tab === 'alerts') loadAlerts()
    if (tab === 'cspm')   loadCSPM()
  }, [tab, loadEvents, loadAlerts, loadCSPM])

  const tabs = [
    { id: 'cspm',     label: 'CSPM',      icon: Shield   },
    { id: 'overview', label: 'Overview',  icon: Database },
    { id: 'events',   label: 'Events',    icon: Activity },
    { id: 'alerts',   label: 'Alerts',    icon: Bell     },
  ]

  const statusBadge = conn.status === 'connected'
    ? 'bg-green-950/40 text-emerald-400 border-emerald-800'
    : conn.status === 'error'
    ? 'bg-red-950/40 text-red-400 border-red-800'
    : 'bg-yellow-950/40 text-yellow-400 border-yellow-800'

  const filteredEvents = search ? events.filter(e => JSON.stringify(e).toLowerCase().includes(search.toLowerCase())) : events
  const filteredAlerts = search ? alerts.filter(a => (a.title+a.description).toLowerCase().includes(search.toLowerCase())) : alerts

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex-shrink-0 px-5 py-3 border-b border-siem-border bg-siem-surface">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <span className={`text-xl font-bold ${PROVIDER_COLORS[conn.provider] || 'text-siem-muted'}`}>
              {conn.provider?.toUpperCase()}
            </span>
            <div>
              <div className="text-sm font-semibold text-siem-text">{conn.account_label || conn.account_id || 'Unnamed account'}</div>
              <div className="text-[11px] text-siem-muted">{conn.account_id || 'Project ID not set'}</div>
            </div>
            <span className={`text-[10px] border rounded-full px-2 py-0.5 ${statusBadge}`}>{conn.status}</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={onSync} disabled={syncing}
              className="flex items-center gap-1.5 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-3 py-1.5 disabled:opacity-40">
              <RefreshCw size={11} className={syncing ? 'animate-spin' : ''}/> Sync now
            </button>
            <button onClick={onDisconnect}
              className="flex items-center gap-1.5 text-xs border border-red-800 text-red-400 hover:bg-red-950/20 rounded-lg px-3 py-1.5">
              <Trash2 size={11}/> Disconnect
            </button>
          </div>
        </div>
        <div className="flex gap-1">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setTab(id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                tab === id ? 'bg-siem-accent text-black' : 'text-siem-muted hover:text-siem-text'
              }`}>
              <Icon size={11}/>{label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 min-h-0 overflow-hidden">

        {tab === 'cspm' && (
          <CSPMDashboard
            conn={conn} cspm={cspm} loading={cspmLoading}
            onRunScan={runCSPM} scanning={cspmScanning}/>
        )}

        {tab === 'overview' && (
          <div className="p-6 overflow-auto h-full space-y-4">
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: 'Total Events', value: conn.event_count?.toLocaleString() || '0', icon: Activity, color: 'text-blue-400' },
                { label: 'Last Sync', value: conn.last_sync ? formatDistanceToNow(new Date(conn.last_sync), { addSuffix: true }) : 'Never', icon: Clock, color: 'text-emerald-400' },
                { label: 'Status', value: conn.status || 'unknown', icon: Globe, color: PROVIDER_COLORS[conn.provider] || 'text-siem-muted' },
              ].map(({ label, value, icon: Icon, color }) => (
                <div key={label} className="bg-siem-surface border border-siem-border rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-2"><Icon size={14} className={color}/><span className="text-[10px] uppercase tracking-wider text-siem-muted">{label}</span></div>
                  <div className="text-lg font-bold text-siem-text">{value}</div>
                </div>
              ))}
            </div>
            {conn.last_error && (
              <div className="flex items-start gap-2 p-3 rounded-lg bg-red-950/20 border border-red-800 text-xs text-red-300">
                <AlertCircle size={13} className="mt-0.5 shrink-0"/>
                <div><span className="font-medium">Last error: </span>{conn.last_error}</div>
              </div>
            )}
          </div>
        )}

        {(tab === 'events' || tab === 'alerts') && (
          <CloudEventsAlerts
            tab={tab}
            events={events} alerts={alerts}
            loadingE={loadingE} loadingA={loadingA}
            search={search} setSearch={setSearch}
          />
        )}
      </div>
    </div>
  )
}

// ── Main Cloud page ────────────────────────────────────────────────────────────
export default function CloudPage() {
  const [searchParams] = useSearchParams()
  const [connectors, setConnectors] = useState([])
  const [selected, setSelected]     = useState(null)
  const [adding, setAdding]         = useState(null)
  const [syncing, setSyncing]       = useState({})
  const [loading, setLoading]       = useState(true)

  const load = useCallback(async () => {
    try {
      const { data } = await api.get('/api/v1/cloud-connectors')
      const list = Array.isArray(data?.connectors) ? data.connectors : []
      setConnectors(list)
      const provider = searchParams.get('provider')
      if (provider) {
        const match = list.find(c => c.provider === provider)
        if (match) setSelected(match.id)
      } else if (!selected && list.length > 0) {
        setSelected(list[0].id)
      }
    } catch {} finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const triggerSync = async (id) => {
    setSyncing(s => ({...s,[id]:true}))
    try { await api.post(`/api/v1/cloud-connectors/${id}/sync`) } catch {}
    setTimeout(() => { setSyncing(s => ({...s,[id]:false})); load() }, 3000)
  }

  const disconnect = async (id) => {
    if (!confirm('Disconnect this cloud account?')) return
    await api.delete(`/api/v1/cloud-connectors/${id}`).catch(() => {})
    if (selected === id) setSelected(null)
    load()
  }

  const selectedConn = connectors.find(c => c.id === selected)

  return (
    <div className="flex h-screen bg-siem-bg text-siem-text overflow-hidden">
      {/* Sidebar */}
      <div className="w-64 flex-shrink-0 flex flex-col border-r border-siem-border">
        <div className="flex-shrink-0 px-4 py-3 border-b border-siem-border bg-siem-surface">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CloudIcon size={15} className="text-cyan-400"/>
              <span className="text-sm font-semibold">Cloud Accounts</span>
            </div>
            <button onClick={load} className="text-siem-muted hover:text-siem-text">
              <RefreshCw size={12} className={loading ? 'animate-spin' : ''}/>
            </button>
          </div>
          <div className="text-[10px] text-siem-muted mt-1">
            {connectors.length} connected · {connectors.filter(c => c.status === 'connected').length} healthy
          </div>
        </div>

        <div className="flex-1 overflow-y-auto min-h-0 py-1">
          {connectors.map(conn => {
            const isSelected = selected === conn.id
            return (
              <button key={conn.id} onClick={() => { setSelected(conn.id); setAdding(null) }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 text-left transition-colors ${
                  isSelected ? 'bg-siem-accent/10 border-r-2 border-siem-accent' : 'hover:bg-siem-surface'
                }`}>
                <span className={`text-sm font-bold ${PROVIDER_COLORS[conn.provider] || 'text-siem-muted'}`}>
                  {conn.provider === 'aws' ? 'AWS' : conn.provider === 'azure' ? 'AZ' : 'GCP'}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-siem-text truncate">
                    {conn.account_label || conn.account_id || `${conn.provider.toUpperCase()} account`}
                  </div>
                  <div className="flex items-center gap-1.5 text-[10px] text-siem-muted">
                    <span className={`w-1.5 h-1.5 rounded-full ${
                      conn.status === 'connected' ? 'bg-emerald-400' : conn.status === 'error' ? 'bg-red-400' : 'bg-yellow-400'
                    }`}/>
                    {conn.status}
                  </div>
                </div>
                <ChevronRight size={11} className="text-siem-muted shrink-0"/>
              </button>
            )
          })}
          {!loading && connectors.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <CloudIcon size={22} className="opacity-30"/>No cloud accounts
            </div>
          )}
        </div>

        <div className="flex-shrink-0 border-t border-siem-border p-3 space-y-1">
          <p className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">Add account</p>
          {Object.entries(PROVIDERS).map(([provider, cfg]) => (
            <button key={provider} onClick={() => { setAdding(provider); setSelected(null) }}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs border transition-colors ${
                adding === provider ? `${cfg.border} ${cfg.bg} ${cfg.color}` : 'border-siem-border text-siem-muted hover:text-siem-text hover:border-siem-text/30'
              }`}>
              <Plus size={10}/>{cfg.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main panel */}
      <div className="flex-1 min-w-0 overflow-hidden">
        {adding && (
          <div className="p-6 max-w-2xl overflow-auto h-full">
            <div className="flex items-center gap-2 mb-4">
              <span className={`text-lg font-bold ${PROVIDERS[adding]?.color}`}>{PROVIDERS[adding]?.label}</span>
            </div>
            <ConnectorForm provider={adding} onSaved={() => { setAdding(null); load() }} onCancel={() => setAdding(null)}/>
          </div>
        )}

        {selectedConn && !adding && (
          <ConnectorDetail
            conn={selectedConn}
            onSync={() => triggerSync(selectedConn.id)}
            onDisconnect={() => disconnect(selectedConn.id)}
            syncing={syncing[selectedConn.id]}/>
        )}

        {!selectedConn && !adding && (
          <div className="flex flex-col items-center justify-center h-full text-siem-muted gap-4">
            <div className="w-16 h-16 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
              <CloudIcon size={30} className="opacity-40"/>
            </div>
            <div className="text-center">
              <div className="text-sm font-medium text-siem-text mb-1">Cloud Security Posture</div>
              <div className="text-xs max-w-xs text-center">Connect AWS, Azure, or GCP to start monitoring your cloud security posture.</div>
            </div>
            <div className="flex gap-3 text-[10px] mt-2">
              {Object.entries(PROVIDERS).map(([p, cfg]) => (
                <button key={p} onClick={() => setAdding(p)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border ${cfg.border} ${cfg.color} transition-colors`}>
                  <Plus size={10}/>{p.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
