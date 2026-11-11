import { useState, useEffect, useCallback } from 'react'
import { safeHref } from '../utils/safeHref'
import { GitBranch, GitCommit, Code, Bell, Activity, Search,
         RefreshCw, Plus, Trash2, ChevronRight, AlertTriangle,
         CheckCircle, XCircle, Eye, EyeOff, Clock, User,
         Shield, FileText, Lock, Zap, Bug, ExternalLink, Hash } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api, { runScan } from '../api/client'
import AlertPanel from '../components/AlertPanel'

// ── Provider config ───────────────────────────────────────────────────────────
const PROVIDERS = {
  github: {
    label: 'GitHub',
    color: 'text-white',
    border: 'border-gray-700',
    bg: 'bg-gray-900/40',
    fields: [
      { key: 'token', label: 'Personal Access Token', placeholder: 'ghp_xxxxxxxxxxxxxxxxxxxx', secret: true,
        help: 'Needs: repo, read:org, admin:org (audit_log), read:user' },
    ],
    pulls: ['Org audit log (member changes, repo visibility, webhooks)', 'Commit history + diffs', 'Pipeline runs', 'Secret scanning on push'],
    webhookEvents: ['push', 'repository', 'member', 'org', 'workflow_run', 'team'],
  },
  gitlab: {
    label: 'GitLab',
    color: 'text-orange-400',
    border: 'border-orange-800/40',
    bg: 'bg-orange-950/10',
    fields: [
      { key: 'token',    label: 'Access Token',     placeholder: 'glpat-xxxxxxxxxxxxxxxxxxxx', secret: true,
        help: 'Needs: api, read_api, read_audit_log' },
      { key: 'base_url', label: 'GitLab URL (optional)', placeholder: 'https://gitlab.com', secret: false,
        help: 'Leave blank for gitlab.com. Use your self-hosted URL otherwise.' },
    ],
    pulls: ['Group audit events', 'Commit history + diffs', 'Pipeline runs', 'Secret scanning on push'],
    webhookEvents: ['push', 'merge_request', 'member', 'group'],
  },
  azuredevops: {
    label: 'Azure DevOps',
    color: 'text-blue-400',
    border: 'border-blue-800/40',
    bg: 'bg-blue-950/10',
    fields: [
      { key: 'token',    label: 'Personal Access Token', placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', secret: true, help: 'Needs: Code (Read), Project and Team (Read). Create at: dev.azure.com → User Settings → Personal Access Tokens' },
      { key: 'project',  label: 'Project (Optional)',    placeholder: 'MyProject', help: 'Leave blank to sync all projects in the organization.' },
      { key: 'base_url', label: 'Azure DevOps URL (Optional)', placeholder: 'https://dev.azure.com/myorg', help: 'Leave blank to auto-build from organization name.' },
    ],
    webhookEvents: [],
    pulls: ['Commit history + diffs', 'Secret scanning on push', 'SAST across all repos'],
  },
}

const SEVERITY_COLORS = ['', 'text-siem-muted', 'text-blue-400', 'text-yellow-400', 'text-orange-400', 'text-red-400']
const SEVERITY_LABELS = ['', 'Info', 'Low', 'Medium', 'High', 'Critical']
const STATUS_COLORS   = { open: 'text-red-400', acknowledged: 'text-yellow-400', closed: 'text-siem-muted' }

// ── ConnectorForm ─────────────────────────────────────────────────────────────
function ConnectorForm({ provider, onSaved, onCancel }) {
  const cfg = PROVIDERS[provider]
  const [org, setOrg]           = useState('')
  const [values, setValues]     = useState({})
  const [show, setShow]         = useState({})
  const [saving, setSaving]     = useState(false)
  const [testing, setTesting]   = useState(false)
  const [error, setError]       = useState('')
  const [testResult, setTestResult] = useState(null)
  const [webhookInfo, setWebhookInfo] = useState(null)

  const test = async () => {
    setTesting(true); setTestResult(null)
    try {
      const { data } = await api.post('/api/v1/devops-connectors/test', {
        provider, org, credentials: values,
      })
      setTestResult({ ok: true, msg: `Connected: ${data.label}` })
    } catch (e) {
      const msg = e.response?.data?.error || e.message || 'Connection failed'
      setTestResult({ ok: false, msg })
    } finally { setTesting(false) }
  }

  const save = async () => {
    setSaving(true); setError('')
    try {
      const { data } = await api.post('/api/v1/devops-connectors', {
        provider, org, label: testResult?.msg || org, credentials: values,
      })
      setWebhookInfo(data)
    } catch (e) {
      setError(e.response?.data?.error || 'Failed to save')
    } finally { setSaving(false) }
  }

  if (webhookInfo) {
    const webhookURL = `${window.location.protocol}//${window.location.host}/api/v1/devops/webhook/${webhookInfo.id}`
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2 text-emerald-400">
          <CheckCircle size={16}/> <span className="font-medium">Connected successfully!</span>
        </div>
        <div className="bg-siem-bg border border-siem-border rounded-xl p-4 space-y-3">
          <p className="text-xs font-medium text-siem-text">Webhook setup (optional but recommended for real-time alerts)</p>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">Webhook URL</label>
            <div className="font-mono text-xs text-siem-accent bg-siem-surface border border-siem-border rounded-lg px-3 py-2 break-all">
              {webhookURL}
            </div>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">Webhook Secret</label>
            <div className="font-mono text-xs text-siem-accent bg-siem-surface border border-siem-border rounded-lg px-3 py-2">
              {webhookInfo.webhook_secret}
            </div>
          </div>
          <p className="text-[11px] text-siem-muted">
            Add these in your {cfg.label} org settings → Webhooks → Add webhook.<br/>
            Events to subscribe: <span className="text-siem-text">{cfg.webhookEvents.join(', ')}</span>
          </p>
        </div>
        <button onClick={onSaved}
          className="text-xs bg-siem-accent text-white rounded-lg px-4 py-2">
          Done
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">
          {provider === 'github' ? 'Organization or Username' : provider === 'azuredevops' ? 'Organization Name' : 'Group Path or Project'}
        </label>
        <input value={org} onChange={e => setOrg(e.target.value)}
          placeholder={provider === 'github' ? 'my-org or username' : provider === 'azuredevops' ? 'my-organization' : 'my-group or my-group/my-project'}
          className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-xs text-siem-text font-mono focus:outline-none focus:border-siem-accent"/>
      </div>

      {cfg.fields.map(f => (
        <div key={f.key}>
          <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">{f.label}</label>
          <div className="relative">
            <input
              type={f.secret && !show[f.key] ? 'password' : 'text'}
              className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-xs text-siem-text font-mono focus:outline-none focus:border-siem-accent pr-9"
              placeholder={f.placeholder}
              value={values[f.key] || ''}
              onChange={e => setValues(v => ({ ...v, [f.key]: e.target.value }))}
            />
            {f.secret && (
              <button onClick={() => setShow(s => ({ ...s, [f.key]: !s[f.key] }))}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-siem-muted hover:text-siem-text">
                {show[f.key] ? <EyeOff size={13}/> : <Eye size={13}/>}
              </button>
            )}
          </div>
          {f.help && <p className="text-[10px] text-siem-muted mt-1">{f.help}</p>}
        </div>
      ))}

      {error && <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/20 border border-red-800/30 rounded-lg p-2"><AlertTriangle size={12}/>{error}</div>}
      {testResult && (
        <div className={`flex items-center gap-2 text-xs p-2 rounded-lg ${testResult.ok ? 'text-emerald-400 bg-green-900/20' : 'text-red-400 bg-red-900/20'}`}>
          {testResult.ok ? <CheckCircle size={12}/> : <XCircle size={12}/>} {testResult.msg}
        </div>
      )}

      <div className="flex gap-2">
        <button onClick={test} disabled={testing || !org}
          className="text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-4 py-2 disabled:opacity-40">
          {testing ? 'Testing…' : 'Test Connection'}
        </button>
        <button onClick={save} disabled={saving || !org || !testResult?.ok}
          className="text-xs bg-siem-accent hover:bg-siem-accent/90 text-white rounded-lg px-4 py-2 disabled:opacity-40">
          {saving ? 'Saving…' : 'Save & Connect'}
        </button>
        <button onClick={onCancel} className="text-xs border border-siem-border text-siem-muted rounded-lg px-4 py-2">
          Cancel
        </button>
      </div>

      <div className="bg-siem-bg border border-siem-border/40 rounded-xl p-3 space-y-1">
        <p className="text-[10px] text-siem-muted font-medium uppercase tracking-wider">What will be pulled</p>
        {cfg.pulls.map(p => (
          <div key={p} className="flex items-center gap-2 text-xs text-siem-muted">
            <span className="w-1 h-1 rounded-full bg-siem-accent/60 shrink-0"/>{p}
          </div>
        ))}
        <p className="text-[10px] text-siem-muted/50 pt-1">Polled every 5 minutes · Secret scanning on every commit</p>
      </div>
    </div>
  )
}

// ── CommitRow ─────────────────────────────────────────────────────────────────
function CommitRow({ commit, onClick }) {
  const parsedDiff = Array.isArray(commit.diff_summary) ? commit.diff_summary : (typeof commit.diff_summary === 'string' ? JSON.parse(commit.diff_summary || '[]') : [])
  const hasDiff = parsedDiff.length > 0
  return (
    <div onClick={onClick}
      className="px-4 py-3 hover:bg-siem-surface/60 cursor-pointer border-b border-siem-border/40">
      <div className="flex items-start gap-3">
        <GitCommit size={14} className="text-siem-muted mt-0.5 shrink-0"/>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-siem-muted shrink-0">{commit.id.slice(0,7)}</span>
            <span className="text-xs text-siem-text truncate">{commit.message?.split('\n')[0]}</span>
          </div>
          <div className="flex items-center gap-3 text-[10px] text-siem-muted mt-1">
            <span className="flex items-center gap-1"><User size={9}/>{commit.author_username || commit.author_name}</span>
            <span className="truncate">{commit.repo}</span>
            {commit.branch && commit.branch !== 'unknown' && (
              <span className="flex items-center gap-1"><GitBranch size={9}/>{commit.branch}</span>
            )}
            <span className="ml-auto shrink-0">
              {commit.pushed_at ? formatDistanceToNow(new Date(commit.pushed_at), { addSuffix: true }) : ''}
            </span>
          </div>
          {hasDiff && (
            <div className="flex items-center gap-2 mt-1 text-[10px]">
              <span className="text-emerald-400">+{commit.additions}</span>
              <span className="text-red-400">-{commit.deletions}</span>
              <span className="text-siem-muted">{commit.files_changed} files</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── CommitDetail ──────────────────────────────────────────────────────────────
function CommitDetail({ commit, onClose }) {
  const diffs = Array.isArray(commit.diff_summary) ? commit.diff_summary : (typeof commit.diff_summary === 'string' ? JSON.parse(commit.diff_summary || '[]') : [])

  return (
    <div className="flex flex-col h-full bg-siem-bg">
      <div className="flex items-center justify-between px-4 py-3 border-b border-siem-border bg-siem-surface flex-shrink-0">
        <div className="flex items-center gap-2">
          <GitCommit size={14} className="text-siem-accent"/>
          <span className="font-mono text-sm text-siem-text">{commit.id.slice(0,7)}</span>
          <span className="text-xs text-siem-muted truncate max-w-xs">{commit.message?.split('\n')[0]}</span>
        </div>
        <button onClick={onClose} className="text-siem-muted hover:text-siem-text text-xs px-2 py-1 border border-siem-border rounded">
          ← Back
        </button>
      </div>

      <div className="flex-shrink-0 px-4 py-3 border-b border-siem-border bg-siem-surface/50">
        <div className="grid grid-cols-3 gap-4 text-xs">
          <div><span className="text-siem-muted">Author: </span><span className="text-siem-text">{commit.author_name} &lt;{commit.author_email}&gt;</span></div>
          <div><span className="text-siem-muted">Repo: </span><span className="text-siem-text">{commit.repo}</span></div>
          <div><span className="text-siem-muted">When: </span><span className="text-siem-text">{commit.pushed_at ? formatDistanceToNow(new Date(commit.pushed_at), { addSuffix: true }) : ''}</span></div>
        </div>
        <div className="flex items-center gap-4 mt-2 text-[11px]">
          <span className="text-emerald-400 font-medium">+{commit.additions} additions</span>
          <span className="text-red-400 font-medium">-{commit.deletions} deletions</span>
          <span className="text-siem-muted">{commit.files_changed} files changed</span>
          {commit.url && (
            <a href={safeHref(commit.url)} target="_blank" rel="noopener noreferrer"
              className="text-siem-accent hover:underline ml-auto">
              View on {commit.url.includes('github') ? 'GitHub' : 'GitLab'} →
            </a>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto min-h-0 p-4 space-y-3">
        {diffs.length === 0 && (
          <div className="text-xs text-siem-muted text-center py-8">No diff available</div>
        )}
        {diffs.map((d, i) => (
          <div key={i} className="border border-siem-border rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-3 py-2 bg-siem-surface border-b border-siem-border">
              <span className="font-mono text-[11px] text-siem-text">{d.file}</span>
              <div className="flex items-center gap-2 text-[10px]">
                {d.status && (
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-medium ${
                    d.status === 'added' ? 'bg-emerald-950/40 text-emerald-400' :
                    d.status === 'removed' ? 'bg-red-950/40 text-red-400' :
                    'bg-blue-950/40 text-blue-400'
                  }`}>{d.status}</span>
                )}
                <span className="text-emerald-400">+{d.additions}</span>
                <span className="text-red-400">-{d.deletions}</span>
              </div>
            </div>
            {d.patch && (
              <pre className="text-[10px] font-mono overflow-x-auto p-3 bg-[#0a0f1a] max-h-64 overflow-y-auto leading-relaxed">
                {d.patch.split('\n').map((line, j) => (
                  <div key={j} className={
                    line.startsWith('+') && !line.startsWith('+++') ? 'text-emerald-400 bg-emerald-950/20' :
                    line.startsWith('-') && !line.startsWith('---') ? 'text-red-400 bg-red-950/20' :
                    line.startsWith('@@') ? 'text-blue-400' :
                    'text-siem-muted'
                  }>{line}</div>
                ))}
              </pre>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── ConnectorDetail ───────────────────────────────────────────────────────────
function PosturePanel({ conn }) {
  const [res, setRes] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const sevCls = { high: 'text-red-400', medium: 'text-orange-400', low: 'text-yellow-400' }
  useEffect(() => {
    api.get(`/api/v1/devops-connectors/${conn.id}/posture`).then(r => setRes(r.data)).catch(() => {})
  }, [conn.id])
  const run = async () => {
    setBusy(true); setErr(''); setRes(null)
    try { setRes((await runScan(`/api/v1/devops-connectors/${conn.id}/posture`)).data) }
    catch (e) { setErr(e.response?.data?.error || e.message || 'Posture scan failed') }
    finally { setBusy(false) }
  }
  return (
    <div className="p-5 space-y-3">
      <div className="flex items-center gap-3">
        <button onClick={run} disabled={busy} className="px-4 py-2 text-xs font-semibold bg-siem-accent text-white rounded-xl disabled:opacity-40">
          {busy ? 'Scanning…' : 'Run posture check'}
        </button>
        <span className="text-xs text-siem-muted">Branch protection, secret scanning, push protection and org 2FA (GitHub).</span>
      </div>
      {err && <div className="text-sm text-red-400">{err}</div>}
      {res && (
        <div className="text-xs space-y-1">
          <div className="text-siem-muted">{res.repos_checked} repos checked · {(res.findings || []).length} findings</div>
          {(res.findings || []).map((f, i) => (
            <div key={i} className="border border-siem-border rounded-lg p-3">
              <span className={`font-semibold uppercase mr-2 ${sevCls[f.severity] || ''}`}>{f.severity}</span>
              <span className="font-medium">{f.title}</span>
              <span className="text-siem-muted ml-2 font-mono">{f.resource}</span>
              <div className="text-siem-muted mt-1">{f.detail} <span className="text-siem-text">Fix: {f.fix}</span></div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ConnectorDetail({ conn, onSync, onDisconnect, syncing }) {
  const [tab, setTab]           = useState('commits')
  const [commits, setCommits]   = useState([])
  const [alerts, setAlerts]     = useState([])
  const [selectedAlertId, setSelectedAlertId] = useState(null)
  const [events, setEvents]     = useState([])
  const [selectedCommit, setSelectedCommit] = useState(null)
  const [loading, setLoading]   = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [scanning, setScanning]   = useState(false)
  const [scanError, setScanError] = useState(null)
  const [aiScan, setAiScan]       = useState(null)
  const [aiScanLoading, setAiScanLoading] = useState(false)
  const [sastResult, setSastResult] = useState(null)
  const [sasting, setSasting]       = useState(false)
  const [sastError, setSastError]   = useState(null)
  const [aiSast, setAiSast]         = useState(null)
  const [aiSastLoading, setAiSastLoading] = useState(false)
  const [sastFilter, setSastFilter] = useState('all')
  const [expandedFindings, setExpandedFindings] = useState({})
  const [sastRepos, setSastRepos]   = useState([])
  const [sastSelRepo, setSastSelRepo] = useState('')
  const [sastSelBranch, setSastSelBranch] = useState('')
  const [search, setSearch]     = useState('')
  const [repoFilter, setRepoFilter] = useState('')
  const [repos, setRepos]       = useState([])

  const loadCommits = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await api.get(`/api/v1/devops-connectors/${conn.id}/commits`, {
        params: { repo: repoFilter, limit: 100 }
      })
      const list = Array.isArray(data) ? data : []
      setCommits(list)
      // Extract unique repos
      const uniqueRepos = [...new Set(list.map(c => c.repo))].filter(Boolean)
      setRepos(uniqueRepos)
    } catch { setCommits([]) } finally { setLoading(false) }
  }, [conn.id, repoFilter])

  const loadAlerts = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/alerts', {
        params: { host: conn.org, limit: 100, all_time: 1 }
      })
      // handler returns { alerts: [...] } when host filter is used
      const alertList = data?.alerts ?? (Array.isArray(data) ? data : [])
      setAlerts(alertList)
    } catch { setAlerts([]) } finally { setLoading(false) }
  }, [conn.org])

  const loadEvents = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/events', {
        params: { host: conn.org, limit: 500, all_time: 1 }
      })
      setEvents(Array.isArray(data?.events) ? data.events : [])
    } catch { setEvents([]) } finally { setLoading(false) }
  }, [conn.org])

  // Load cached SAST result for a specific repo (called when repo selector changes)
  const loadSASTForRepo = useCallback(async (repo, branch) => {
    if (!repo) return
    try {
      const params = new URLSearchParams({ repo })
      if (branch) params.set('branch', branch)
      const { data } = await api.get(`/api/v1/devops-connectors/${conn.id}/sast?${params}`)
      if (data?.scan) {
        setSastResult(data.scan)
        setAiSast(null)
        if (data.scan.ai_summary) {
          try {
            const clean = data.scan.ai_summary.replace(/```json\n?|```\n?/g, '').trim()
            setAiSast(JSON.parse(clean))
          } catch (e) { setAiSast({ executive_summary: data.scan.ai_summary }) }
        }
      } else {
        setSastResult(null)
        setAiSast(null)
      }
    } catch {}
  }, [conn.id])

  const loadSAST = useCallback(async () => {
    // Load available repos for the selector
    api.get(`/api/v1/devops-connectors/${conn.id}/sast/repos`)
      .then(r => {
        const repos = r.data.repos || []
        setSastRepos(repos)
        // Pre-select first repo if none selected
        if (repos.length === 1 && !sastSelRepo) {
          setSastSelRepo(repos[0].repo)
          setSastSelBranch(repos[0].branch)
        }
      }).catch(() => {})
    try {
      // Load most recent scan result
      const { data } = await api.get(`/api/v1/devops-connectors/${conn.id}/sast`)
      if (data?.scan) {
        setSastResult(data.scan)
        if (data.scan.ai_summary) {
          try {
            const clean = data.scan.ai_summary.replace(/```json\n?|```\n?/g, '').trim()
            setAiSast(JSON.parse(clean))
          } catch (e) { setAiSast({ executive_summary: data.scan.ai_summary }) }
        }
      }
    } catch {}
  }, [conn.id])

  const loadCodeScan = useCallback(async () => {
    try {
      const { data } = await api.get(`/api/v1/devops-connectors/${conn.id}/code-scan`)
      if (data?.scan) {
        setScanResult(data.scan)
        if (data.scan.ai_summary) {
          try {
            const clean = data.scan.ai_summary.replace(/```json\n?|```\n?/g, '').trim()
            setAiScan(JSON.parse(clean))
          } catch (e) { setAiScan({ executive_summary: data.scan.ai_summary }) }
        }
      }
    } catch {}
  }, [conn.id])

  useEffect(() => {
    setSelectedCommit(null)
    if (tab === 'commits')   loadCommits()
    if (tab === 'alerts')    loadAlerts()
    if (tab === 'events')    loadEvents()
    if (tab === 'code-scan') loadCodeScan()
    if (tab === 'sast') loadSAST()
  }, [tab, loadCommits, loadAlerts, loadEvents, loadCodeScan, loadSAST])

  useEffect(() => { if (tab === 'commits') loadCommits() }, [repoFilter])

  const cfg = PROVIDERS[conn.provider] || {}

  const filteredCommits = search
    ? commits.filter(c => (c.message + c.author_name + c.author_username + c.repo)
        .toLowerCase().includes(search.toLowerCase()))
    : commits

  if (selectedCommit) {
    return <CommitDetail commit={selectedCommit} onClose={() => setSelectedCommit(null)}/>
  }

  const statusBadge = conn.status === 'connected'
    ? 'bg-green-950/40 text-emerald-400 border-emerald-800'
    : conn.status === 'error'
    ? 'bg-red-950/40 text-red-400 border-red-800'
    : 'bg-yellow-950/40 text-yellow-400 border-yellow-800'

  const tabs = [
    { id: 'commits',   label: 'Code Changes', icon: GitCommit },
    { id: 'code-scan', label: 'Code Scan',     icon: Shield    },
    { id: 'sast',      label: 'SAST',          icon: Code      },
    { id: 'events',    label: 'Events',        icon: Activity  },
    { id: 'alerts',    label: 'Alerts',        icon: Bell      },
    ...((['github', 'gitlab', 'azuredevops'].includes(conn.provider)) ? [{ id: 'posture', label: 'Posture', icon: Shield }] : []),
  ]

  return (
    <>
    <div className="flex flex-col h-full">
      <div className="flex-shrink-0 px-6 py-4 border-b border-siem-border bg-siem-surface">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className={`font-bold text-lg ${cfg.color || 'text-siem-text'}`}>
              {conn.provider?.toUpperCase()}
            </span>
            <div>
              <div className="text-sm font-semibold text-siem-text">{conn.org}</div>
              <div className="text-[11px] text-siem-muted">{conn.label}</div>
            </div>
            <span className={`text-[10px] border rounded-full px-2 py-0.5 ${statusBadge}`}>
              {conn.status}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={onSync} disabled={syncing}
              className="flex items-center gap-1.5 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-3 py-1.5 disabled:opacity-40">
              <RefreshCw size={11} className={syncing ? 'animate-spin' : ''}/> Sync
            </button>
            <button onClick={onDisconnect}
              className="flex items-center gap-1.5 text-xs border border-red-800 text-red-400 hover:bg-red-950/20 rounded-lg px-3 py-1.5">
              <Trash2 size={11}/> Disconnect
            </button>
          </div>
        </div>

        <div className="flex gap-1 mt-3">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setTab(id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                tab === id ? 'bg-siem-accent text-white' : 'text-siem-muted hover:text-siem-text'
              }`}>
              <Icon size={11}/>{label}
            </button>
          ))}
        </div>
      </div>

      {/* Filters for commits */}
      {tab === 'commits' && (
        <div className="flex-shrink-0 flex gap-2 px-4 py-2 border-b border-siem-border">
          <div className="relative flex-1">
            <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-siem-muted"/>
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search commits, authors, messages…"
              className="w-full bg-siem-bg border border-siem-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-siem-text focus:outline-none focus:border-siem-accent"/>
          </div>
          {repos.length > 0 && (
            <select value={repoFilter} onChange={e => setRepoFilter(e.target.value)}
              className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1.5 text-xs text-siem-text focus:outline-none focus:border-siem-accent">
              <option value="">All repos</option>
              {repos.map(r => <option key={r} value={r}>{r.split('/').pop()}</option>)}
            </select>
          )}
        </div>
      )}

      {/* Search for events/alerts */}
      {(tab === 'events' || tab === 'alerts') && (
        <div className="flex-shrink-0 px-4 py-2 border-b border-siem-border">
          <div className="relative">
            <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-siem-muted"/>
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Filter…"
              className="w-full bg-siem-bg border border-siem-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-siem-text focus:outline-none focus:border-siem-accent"/>
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto min-h-0">

        {/* Commits / Code Changes */}
        {tab === 'commits' && (
          <>
            {loading && <div className="flex items-center justify-center h-32 text-siem-muted text-xs gap-2"><RefreshCw size={14} className="animate-spin"/>Loading…</div>}
            {!loading && filteredCommits.length === 0 && (
              <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
                <GitCommit size={20} className="opacity-30"/>
                No commits yet — trigger a sync or wait for the next poll
              </div>
            )}
            {filteredCommits.map(c => (
              <CommitRow key={c.id} commit={c} onClick={() => setSelectedCommit(c)}/>
            ))}
          </>
        )}

        {/* Events */}
        {tab === 'events' && (
          <div className="divide-y divide-siem-border/40">
            {loading && <div className="flex items-center justify-center h-32 text-siem-muted text-xs gap-2"><RefreshCw size={14} className="animate-spin"/>Loading…</div>}
            {!loading && events.length === 0 && (
              <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
                <Activity size={20} className="opacity-30"/>No events yet
              </div>
            )}
            {(search ? events.filter(e => JSON.stringify(e).toLowerCase().includes(search.toLowerCase())) : events)
              .map(ev => (
                <div key={ev.id} className="px-4 py-3 hover:bg-siem-surface/50">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`text-[10px] shrink-0 ${SEVERITY_COLORS[ev.severity] || 'text-siem-muted'}`}>
                        {SEVERITY_LABELS[ev.severity] || ev.severity}
                      </span>
                      <span className="font-mono text-[10px] text-siem-muted shrink-0">{ev.event_type}</span>
                      {ev.user_name && <span className="text-xs text-siem-text truncate">{ev.user_name}</span>}
                    </div>
                    <span className="text-[10px] text-siem-muted shrink-0">
                      {ev.time ? formatDistanceToNow(new Date(ev.time), { addSuffix: true }) : ''}
                    </span>
                  </div>
                </div>
              ))}
          </div>
        )}

        {tab === 'posture' && <PosturePanel conn={conn} />}

        {/* SAST — Static Analysis */}
        {tab === 'sast' && (
          <div className="p-5 space-y-4">

            {/* Header */}
            <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
              <div className="flex items-start gap-3">
                <Code size={16} className="text-siem-accent mt-0.5"/>
                <div>
                  <div className="text-sm font-semibold text-siem-text mb-0.5">Static Application Security Testing</div>
                  <div className="text-[11px] text-siem-muted">
                    Fetches source code from your repos and scans for security vulnerabilities using
                    OWASP-aligned rules across Python, JavaScript/TypeScript, Go, Java, PHP, and C/C++.
                    Covers SQL injection, XSS, command injection, deserialization, weak crypto, and more.
                  </div>
                </div>
              </div>
            </div>

            {/* Repo / branch selector */}
            {sastRepos.length > 0 && (
              <div className="flex items-center gap-3 flex-wrap">
                <div className="flex flex-col gap-1">
                  <label className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Repository</label>
                  <select value={sastSelRepo} onChange={e => {
                    const repo = e.target.value
                    setSastSelRepo(repo)
                    const r = sastRepos.find(r => r.repo === repo)
                    const branch = r?.branch || ''
                    if (r) setSastSelBranch(branch)
                    // Load cached result for this repo immediately
                    if (repo) loadSASTForRepo(repo, branch)
                    else loadSAST()
                  }} className="bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text focus:outline-none focus:border-siem-accent min-w-[200px]">
                    <option value="">All repos</option>
                    {sastRepos.map(r => (
                      <option key={r.repo} value={r.repo}>{r.repo}</option>
                    ))}
                  </select>
                </div>
                {sastSelRepo && (
                  <div className="flex flex-col gap-1">
                    <label className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Branch</label>
                    <input
                      value={sastSelBranch}
                      onChange={e => setSastSelBranch(e.target.value)}
                      placeholder="HEAD"
                      className="bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text font-mono focus:outline-none focus:border-siem-accent w-36"
                    />
                  </div>
                )}
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center gap-3 flex-wrap">
              <button onClick={async () => {
                setSasting(true); setSastError(null)
                try {
                  const params = new URLSearchParams()
                  if (sastSelRepo) params.set('repo', sastSelRepo)
                  if (sastSelBranch) params.set('branch', sastSelBranch)
                  const url = `/api/v1/devops-connectors/${conn.id}/sast${params.toString() ? '?' + params.toString() : ''}`
                  const { data } = await runScan(url)
                  setSastResult(data); setAiSast(null)
                } catch (e) { setSastError(e.response?.data?.error || 'SAST scan failed') }
                finally { setSasting(false) }
              }} disabled={sasting}
                className="flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-siem-accent hover:bg-siem-accent/90 text-white rounded-xl disabled:opacity-40 transition-colors">
                <Code size={13} className={sasting ? 'animate-pulse' : ''}/>
                {sasting ? 'Scanning source code…' : 'Run SAST Scan'}
              </button>
              {sasting && <span className="text-[10px] text-siem-muted">Large repos can take 2-5 min — results saved automatically, refresh if page times out</span>}
              {!sasting && sastResult?.scanned_at && (
                <span className="text-[10px] text-siem-muted/60 flex items-center gap-1">
                  <Clock size={10}/>
                  Last scanned {formatDistanceToNow(new Date(sastResult.scanned_at), { addSuffix: true })}
                  {sastResult.repo && <span className="text-siem-accent/60 ml-1">· {sastResult.repo.split('/').slice(-1)[0]}</span>}
                </span>
              )}
              {sastResult && !aiSast && !sasting && (
                <button onClick={async () => {
                  setAiSastLoading(true)
                  try {
                    const { data } = await api.post(`/api/v1/devops-connectors/${conn.id}/sast/ai`, {}, { timeout: 60000 })
                    const text = data.content?.find(b => b.type === 'text')?.text || ''
                    const clean = text.replace(/```json\n?|```\n?/g, '').trim()
                    try { setAiSast(JSON.parse(clean)) } catch { setAiSast({ executive_summary: clean }) }
                  } catch (e) { setSastError(e.response?.data?.error || 'AI triage failed') }
                  finally { setAiSastLoading(false) }
                }} disabled={aiSastLoading}
                  className="flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-violet-600 hover:bg-violet-500 text-white rounded-xl disabled:opacity-40 transition-colors">
                  <Zap size={13}/>{aiSastLoading ? 'Triaging…' : 'AI Triage'}
                </button>
              )}
            </div>

            {sastError && (
              <div className="bg-red-950/20 border border-red-800/30 rounded-xl p-3 text-xs text-red-400">{sastError}</div>
            )}

            {!sastResult && !sasting && (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <div className="w-14 h-14 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
                  <Code size={24} className="text-siem-muted/30"/>
                </div>
                <div className="text-center">
                  <div className="text-sm font-medium text-siem-text/70 mb-1">No SAST results yet</div>
                  <div className="text-xs text-siem-muted/50 max-w-sm">
                    Click Run SAST Scan to analyse source code for security vulnerabilities.
                    Ensure the connector is synced and the token has repo read access.
                  </div>
                </div>
              </div>
            )}

            {sasting && (
              <div className="bg-siem-bg border border-siem-accent/20 rounded-xl p-5 space-y-3">
                {['Fetching repository file tree', 'Downloading source files', 'Running security rules', 'Analysing patterns', 'Deduplicating findings'].map((msg, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-siem-accent/60 animate-pulse" style={{animationDelay:`${i*400}ms`}}/>
                    <span className="text-[11px] text-siem-muted">{msg}…</span>
                  </div>
                ))}
              </div>
            )}

            {sastResult && (
              <div className="space-y-4">

                {/* Stats */}
                <div className="grid grid-cols-5 gap-3">
                  {[
                    ['Repos',    sastResult.scanned_repos,   'text-siem-text'],
                    ['Files',    sastResult.scanned_files,   'text-siem-muted'],
                    ['Critical', sastResult.critical_count,  'text-red-400'],
                    ['High',     sastResult.high_count,      'text-orange-400'],
                    ['Medium',   sastResult.medium_count,    'text-yellow-400'],
                  ].map(([label, val, color]) => (
                    <div key={label} className="bg-siem-surface border border-siem-border rounded-xl p-3 text-center">
                      <div className={`text-xl font-bold font-mono ${color}`}>{val ?? 0}</div>
                      <div className="text-[9px] text-siem-muted uppercase tracking-wide mt-0.5">{label}</div>
                    </div>
                  ))}
                </div>

                {/* AI Triage */}
                {aiSast && (
                  <div className="bg-violet-950/15 border border-violet-800/25 rounded-xl p-4 space-y-3">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Zap size={13} className="text-violet-400"/>
                      <span className="text-[10px] uppercase tracking-wider text-violet-400/80 font-semibold">AI Security Triage</span>
                      {aiSast.risk_label && (
                        <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border ml-auto ${
                          aiSast.risk_label === 'Critical' ? 'text-red-400 border-red-800 bg-red-950/30' :
                          aiSast.risk_label === 'High'     ? 'text-orange-400 border-orange-800 bg-orange-950/20' :
                          aiSast.risk_label === 'Medium'   ? 'text-yellow-400 border-yellow-800 bg-yellow-950/20' :
                          'text-emerald-400 border-emerald-800 bg-emerald-950/20'
                        }`}>{aiSast.risk_label}</span>
                      )}
                      {aiSast.true_positive_rate != null && (
                        <span className="text-[9px] text-siem-muted border border-siem-border rounded-full px-2 py-0.5">
                          ~{aiSast.true_positive_rate}% true positive
                        </span>
                      )}
                    </div>
                    {aiSast.executive_summary && <p className="text-xs text-siem-text leading-relaxed">{aiSast.executive_summary}</p>}
                    {aiSast.systemic_issues?.length > 0 && (
                      <div>
                        <div className="text-[9px] uppercase text-orange-400/70 font-semibold mb-1.5">Systemic Issues</div>
                        <ul className="space-y-1">
                          {aiSast.systemic_issues.map((s, i) => (
                            <li key={i} className="text-xs text-siem-muted flex gap-2">
                              <span className="text-orange-400/50 shrink-0">▸</span>{s}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {aiSast.false_positive_indicators?.length > 0 && (
                      <div>
                        <div className="text-[9px] uppercase text-emerald-400/60 font-semibold mb-1.5">Likely False Positives</div>
                        <ul className="space-y-1">
                          {aiSast.false_positive_indicators.map((fp, i) => (
                            <li key={i} className="text-[10px] text-siem-muted/70 flex gap-2">
                              <span className="text-emerald-400/40 shrink-0">→</span>{fp}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {aiSast.immediate_actions?.length > 0 && (
                      <div>
                        <div className="text-[9px] uppercase text-red-400/70 font-semibold mb-1.5">Immediate Actions</div>
                        <ul className="space-y-1">
                          {aiSast.immediate_actions.map((a, i) => (
                            <li key={i} className="text-xs text-siem-text flex gap-2">
                              <span className="text-red-400/50 shrink-0">{i+1}.</span>{a}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}

                {/* Severity filter */}
                {sastResult.findings?.length > 0 && (
                  <div className="flex gap-1">
                    {['all','critical','high','medium','low','info'].map(sev => (
                      <button key={sev} onClick={() => setSastFilter(sev)}
                        className={`text-[10px] px-2.5 py-1 rounded-full border transition-colors capitalize ${
                          sastFilter === sev
                            ? 'bg-siem-accent border-siem-accent text-white'
                            : 'border-siem-border text-siem-muted hover:text-siem-text'
                        }`}>
                        {sev}
                      </button>
                    ))}
                  </div>
                )}

                {/* Findings */}
                {sastResult.findings?.length > 0 ? (
                  <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                    <div className="px-4 py-2.5 border-b border-siem-border/40 flex items-center gap-2">
                      <Code size={13} className="text-siem-accent"/>
                      <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">
                        Findings ({sastResult.findings.filter(f => sastFilter === 'all' || f.severity === sastFilter).length})
                      </span>
                    </div>
                    <div className="max-h-[500px] overflow-y-auto divide-y divide-siem-border/20">
                      {sastResult.findings
                        .filter(f => sastFilter === 'all' || f.severity === sastFilter)
                        .sort((a, b) => {
                          const o = {critical:0,high:1,medium:2,low:3,info:4}
                          return (o[a.severity]??5)-(o[b.severity]??5)
                        })
                        .map((f, i) => {
                          const sevColor = {critical:'text-red-400',high:'text-orange-400',medium:'text-yellow-400',low:'text-blue-400',info:'text-siem-muted'}[f.severity]||'text-siem-muted'
                          const sevBg = {critical:'bg-red-950/20 border-red-800/30',high:'bg-orange-950/15 border-orange-800/25',medium:'bg-yellow-950/10 border-yellow-800/20',low:'bg-blue-950/10 border-blue-800/20',info:'bg-siem-bg border-siem-border/30'}[f.severity]||'bg-siem-bg border-siem-border/30'
                          const expanded = expandedFindings[i]
                          const toggle = () => setExpandedFindings(p => ({...p, [i]: !p[i]}))
                          return (
                            <div key={i} className="border-b border-siem-border/20 last:border-0">
                              {/* Summary row — always visible, click to expand */}
                              <div className="px-4 py-3 hover:bg-white/[0.02] cursor-pointer" onClick={toggle}>
                                <div className="flex items-center justify-between gap-3">
                                  <div className="flex items-center gap-2 flex-wrap flex-1 min-w-0">
                                    <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border shrink-0 ${sevBg} ${sevColor}`}>{f.severity}</span>
                                    <span className="text-xs font-semibold text-siem-text">{f.title}</span>
                                    {f.cwe && <span className="text-[9px] text-violet-400/60 shrink-0">{f.cwe}</span>}
                                    {f.engine && f.engine !== 'semgrep' && (
                                      <span className={`text-[9px] px-1 rounded shrink-0 ${
                                        f.engine === 'codeql' ? 'bg-blue-950/40 text-blue-400' :
                                        f.engine?.includes('+') ? 'bg-purple-950/40 text-purple-400' :
                                        'bg-siem-surface text-siem-muted'
                                      }`}>{f.engine}</span>
                                    )}
                                  </div>
                                  <div className="flex items-center gap-3 shrink-0">
                                    <span className="text-[10px] font-mono text-siem-muted/50 hidden sm:block">{f.file?.split('/').slice(-2).join('/')}</span>
                                    {f.line > 0 && <span className="text-[10px] text-siem-muted/50">{f.end_line && f.end_line > f.line ? `:${f.line}–${f.end_line}` : `:${f.line}`}</span>}
                                    <span className="text-siem-muted/40 text-xs">{expanded ? '▲' : '▼'}</span>
                                  </div>
                                </div>
                                {/* Snippet always shown collapsed */}
                                {f.snippet && !expanded && (
                                  <code className="block text-[10px] font-mono bg-siem-bg border border-siem-border/30 rounded px-2 py-1 text-siem-muted/60 truncate mt-1.5">
                                    {f.snippet}
                                  </code>
                                )}
                              </div>

                              {/* Expanded detail */}
                              {expanded && (
                                <div className="px-4 pb-4 space-y-3 bg-siem-surface/30">

                                  {/* File + location */}
                                  <div className="flex items-center gap-2 text-[10px] pt-1">
                                    <span className="text-siem-muted/50">File</span>
                                    <code className="font-mono text-siem-accent/80">{f.file}</code>
                                    {f.line > 0 && <span className="text-siem-muted/50">{f.end_line && f.end_line > f.line ? `lines ${f.line}–${f.end_line}` : `line ${f.line}`}</span>}
                                    {f.repo && <span className="ml-auto text-siem-muted/40">{f.repo}</span>}
                                  </div>

                                  {/* Rule ID + OWASP */}
                                  <div className="flex items-center gap-3 flex-wrap text-[10px]">
                                    <div className="flex items-center gap-1.5">
                                      <span className="text-siem-muted/50">Rule</span>
                                      <code className="font-mono text-siem-muted border border-siem-border/40 rounded px-1.5 py-0.5">{f.rule_id}</code>
                                    </div>
                                    {f.cwe && (
                                      <div className="flex items-center gap-1.5">
                                        <span className="text-siem-muted/50">CWE</span>
                                        <span className="text-violet-400">{f.cwe}</span>
                                      </div>
                                    )}
                                    {f.owasp && (
                                      <div className="flex items-center gap-1.5">
                                        <span className="text-siem-muted/50">OWASP</span>
                                        <span className="text-orange-400/70">{f.owasp}</span>
                                      </div>
                                    )}
                                    <div className="flex items-center gap-1.5">
                                      <span className="text-siem-muted/50">Engine</span>
                                      <span className="text-siem-muted/60">{f.engine || 'semgrep'}</span>
                                    </div>
                                  </div>

                                  {/* Code snippet — full, not truncated */}
                                  {f.snippet && (
                                    <div>
                                      <div className="text-[9px] uppercase tracking-wider text-siem-muted/40 mb-1">Matched code</div>
                                      <code className="block text-[11px] font-mono bg-black/30 border border-siem-border/40 rounded px-3 py-2 text-green-400/80 whitespace-pre-wrap break-all">
                                        {f.snippet}
                                      </code>
                                    </div>
                                  )}

                                  {/* Description */}
                                  <div>
                                    <div className="text-[9px] uppercase tracking-wider text-siem-muted/40 mb-1">What this means</div>
                                    <p className="text-[11px] text-siem-muted leading-relaxed">{f.detail}</p>
                                  </div>

                                  {/* Fix */}
                                  {f.fix && (
                                    <div className="bg-emerald-950/20 border border-emerald-800/30 rounded-lg px-3 py-2">
                                      <div className="text-[9px] uppercase tracking-wider text-emerald-400/60 mb-1">Recommended fix</div>
                                      <p className="text-[11px] text-emerald-300/80 leading-relaxed">{f.fix}</p>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          )
                        })}
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-10 gap-2">
                    <CheckCircle size={24} className="text-emerald-400/50"/>
                    <div className="text-sm text-siem-text/60">No security issues found</div>
                    <div className="text-xs text-siem-muted/40">
                      Scanned {sastResult.scanned_files} files across {sastResult.scanned_repos} repos
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Code Scan */}
        {tab === 'code-scan' && (
          <div className="p-5 space-y-4">

            {/* Scan actions */}
            <div className="flex items-center gap-3">
              <button onClick={async () => {
                setScanning(true); setScanError(null)
                try {
                  const { data } = await api.post(`/api/v1/devops-connectors/${conn.id}/code-scan`)
                  setScanResult(data)
                  setAiScan(null)
                } catch (e) { setScanError(e.response?.data?.error || 'Scan failed') }
                finally { setScanning(false) }
              }} disabled={scanning}
                className="flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-siem-accent hover:bg-siem-accent/90 text-white rounded-xl disabled:opacity-40 transition-colors">
                <Shield size={13} className={scanning ? 'animate-pulse' : ''}/>
                {scanning ? 'Scanning…' : 'Run Code Scan'}
              </button>
              {scanResult && !aiScan && (
                <button onClick={async () => {
                  setAiScanLoading(true)
                  try {
                    const { data } = await api.post(`/api/v1/devops-connectors/${conn.id}/code-scan/ai`, {}, { timeout: 60000 })
                    const text = data.content?.find(b => b.type === 'text')?.text || ''
                    const clean = text.replace(/```json\n?|```\n?/g, '').trim()
                    try { setAiScan(JSON.parse(clean)) } catch { setAiScan({ executive_summary: clean }) }
                  } catch (e) { setScanError(e.response?.data?.error || 'AI analysis failed') }
                  finally { setAiScanLoading(false) }
                }} disabled={aiScanLoading}
                  className="flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-violet-600 hover:bg-violet-500 text-white rounded-xl disabled:opacity-40 transition-colors">
                  <Zap size={13} className={aiScanLoading ? 'animate-pulse' : ''}/>
                  {aiScanLoading ? 'Analysing…' : 'AI Analysis'}
                </button>
              )}
            </div>

            {scanError && (
              <div className="bg-red-950/20 border border-red-800/30 rounded-xl p-3 text-xs text-red-400">{scanError}</div>
            )}

            {/* No scan yet */}
            {!scanResult && !scanning && (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <div className="w-14 h-14 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
                  <Shield size={24} className="text-siem-muted/30"/>
                </div>
                <div className="text-center">
                  <div className="text-sm font-medium text-siem-text/70 mb-1">No scan results</div>
                  <div className="text-xs text-siem-muted/50 max-w-xs">
                    Scans commit history for secrets, sensitive files, dangerous code patterns, and vulnerable dependencies.
                    Sync the connector first to pull commits.
                  </div>
                </div>
              </div>
            )}

            {/* Scan results */}
            {scanResult && (
              <div className="space-y-4">

                {/* Summary cards */}
                <div className="grid grid-cols-4 gap-3">
                  {[
                    ['Findings', scanResult.finding_count, 'text-siem-text'],
                    ['Critical', scanResult.critical_count, 'text-red-400'],
                    ['High',     scanResult.high_count,     'text-orange-400'],
                    ['Medium',   scanResult.medium_count,   'text-yellow-400'],
                  ].map(([label, val, color]) => (
                    <div key={label} className="bg-siem-surface border border-siem-border rounded-xl p-3 text-center">
                      <div className={`text-2xl font-bold font-mono ${color}`}>{val ?? 0}</div>
                      <div className="text-[9px] text-siem-muted uppercase tracking-wide mt-0.5">{label}</div>
                    </div>
                  ))}
                </div>

                {/* AI Summary */}
                {aiScan && (
                  <div className="bg-violet-950/15 border border-violet-800/25 rounded-xl p-4 space-y-3">
                    <div className="flex items-center gap-2">
                      <Zap size={13} className="text-violet-400"/>
                      <span className="text-[10px] uppercase tracking-wider text-violet-400/80 font-semibold">AI Security Assessment</span>
                      {aiScan.risk_label && (
                        <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border ml-auto ${
                          aiScan.risk_label === 'Critical' ? 'text-red-400 border-red-800 bg-red-950/30' :
                          aiScan.risk_label === 'High'     ? 'text-orange-400 border-orange-800 bg-orange-950/20' :
                          aiScan.risk_label === 'Medium'   ? 'text-yellow-400 border-yellow-800 bg-yellow-950/20' :
                          'text-emerald-400 border-emerald-800 bg-emerald-950/20'
                        }`}>{aiScan.risk_label}</span>
                      )}
                    </div>
                    {aiScan.executive_summary && <p className="text-xs text-siem-text leading-relaxed">{aiScan.executive_summary}</p>}
                    {aiScan.patterns && (
                      <div className="bg-siem-bg/50 rounded-lg p-3">
                        <div className="text-[9px] uppercase text-siem-muted/60 font-semibold mb-1">Patterns Detected</div>
                        <p className="text-xs text-siem-muted/80">{aiScan.patterns}</p>
                      </div>
                    )}
                    {aiScan.immediate_actions?.length > 0 && (
                      <div>
                        <div className="text-[9px] uppercase text-emerald-400/70 font-semibold mb-2">Immediate Actions</div>
                        <ul className="space-y-1">
                          {aiScan.immediate_actions.map((a, i) => (
                            <li key={i} className="flex items-start gap-2 text-xs text-siem-text">
                              <span className="text-emerald-400/60 shrink-0">→</span>{a}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}

                {/* Findings list */}
                {scanResult.findings?.length > 0 ? (
                  <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                    <div className="px-4 py-2.5 border-b border-siem-border/40 flex items-center gap-2">
                      <Bug size={13} className="text-siem-accent"/>
                      <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">
                        Findings ({scanResult.findings.length})
                      </span>
                    </div>
                    <div className="max-h-96 overflow-y-auto divide-y divide-siem-border/20">
                      {scanResult.findings
                        .sort((a, b) => {
                          const order = { critical:0, high:1, medium:2, low:3, info:4 }
                          return (order[a.severity]??5) - (order[b.severity]??5)
                        })
                        .map((f, i) => {
                          const sevColor = {
                            critical: 'text-red-400',
                            high:     'text-orange-400',
                            medium:   'text-yellow-400',
                            low:      'text-blue-400',
                            info:     'text-siem-muted',
                          }[f.severity] || 'text-siem-muted'
                          const catIcon = {
                            secret:         '🔑',
                            sensitive_file: '📄',
                            dangerous_code: '⚠️',
                            dependency:     '📦',
                            config:         '⚙️',
                          }[f.category] || '•'
                          return (
                            <div key={i} className="px-4 py-3 hover:bg-white/[0.02]">
                              <div className="flex items-start gap-3">
                                <span className="text-sm shrink-0 mt-0.5">{catIcon}</span>
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                                    <span className={`text-[10px] font-bold uppercase ${sevColor}`}>{f.severity}</span>
                                    <span className="text-xs font-medium text-siem-text truncate">{f.title}</span>
                                  </div>
                                  <div className="text-[10px] text-siem-muted truncate">{f.file}</div>
                                  {f.detail && <div className="text-[10px] text-siem-muted/60 mt-0.5">{f.detail}</div>}
                                  <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                                    {f.repo && <span className="text-[9px] text-siem-muted/50 font-mono">{f.repo}</span>}
                                    {f.author && <span className="text-[9px] text-siem-muted/50">by {f.author}</span>}
                                    {f.commit && (
                                      <span className="text-[9px] font-mono text-violet-400/60">
                                        {f.commit.slice(0, 7)}
                                      </span>
                                    )}
                                    {f.remediation && (
                                      <div className="w-full mt-1 text-[9px] text-emerald-400/70 bg-emerald-950/10 border border-emerald-800/20 rounded px-2 py-1">
                                        Fix: {f.remediation}
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </div>
                            </div>
                          )
                        })}
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-10 gap-2">
                    <CheckCircle size={24} className="text-emerald-400/50"/>
                    <div className="text-sm text-siem-text/60">No issues found</div>
                    <div className="text-xs text-siem-muted/40">
                      Scanned {scanResult.scanned_commits} commits across {scanResult.repo_count} repos
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Alerts */}
        {tab === 'alerts' && (
          <div className="divide-y divide-siem-border/40">
            {loading && <div className="flex items-center justify-center h-32 text-siem-muted text-xs gap-2"><RefreshCw size={14} className="animate-spin"/>Loading…</div>}
            {!loading && alerts.length === 0 && (
              <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
                <Bell size={20} className="opacity-30"/>No alerts for this org
              </div>
            )}
            {(search ? alerts.filter(a => (a.title+a.description).toLowerCase().includes(search.toLowerCase())) : alerts)
              .map(a => (
                <div key={a.id}
                  className="px-4 py-3 hover:bg-siem-surface/50 cursor-pointer"
                  onClick={() => setSelectedAlertId(a.id)}>
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`text-[10px] shrink-0 ${SEVERITY_COLORS[a.severity] || 'text-siem-muted'}`}>
                        {SEVERITY_LABELS[a.severity] || a.severity}
                      </span>
                      <span className="text-xs text-siem-text truncate">{a.title}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`text-[10px] ${STATUS_COLORS[a.status] || 'text-siem-muted'}`}>{a.status}</span>
                      <span className="text-[10px] text-siem-muted">
                        {a.created_at ? formatDistanceToNow(new Date(a.created_at), { addSuffix: true }) : ''}
                      </span>
                    </div>
                  </div>
                  {a.description && <div className="text-[10px] text-siem-muted mt-1 line-clamp-1">{a.description}</div>}
                </div>
              ))}
          </div>
        )}
      </div>
    </div>

    {/* Alert detail panel — rendered at component root so it overlays correctly */}
    {selectedAlertId && (
      <div className="fixed inset-0 z-50 flex items-start justify-end bg-black/40"
        onClick={e => { if (e.target === e.currentTarget) setSelectedAlertId(null) }}>
        <div className="h-full w-full max-w-2xl bg-siem-bg border-l border-siem-border overflow-y-auto">
          <AlertPanel
            alertId={selectedAlertId}
            users={[]}
            onClose={() => { setSelectedAlertId(null); loadAlerts() }}
            onStatusChange={() => loadAlerts()}
          />
        </div>
      </div>
    )}
    </>
  )
}

// ── Main DevOps page ──────────────────────────────────────────────────────────
export default function DevOps() {
  const [connectors, setConnectors] = useState([])
  const [selected, setSelected]     = useState(null)
  const [adding, setAdding]         = useState(null)
  const [syncing, setSyncing]       = useState({})
  const [loading, setLoading]       = useState(true)

  const load = useCallback(async () => {
    try {
      const { data } = await api.get('/api/v1/devops-connectors')
      const list = Array.isArray(data?.connectors) ? data.connectors : []
      setConnectors(list)
      // Only auto-select first connector on initial load — use functional
      // update to read current selected value without adding it as a dependency
      setSelected(cur => {
        if (cur) return cur  // already selected — don't change
        return list.length > 0 ? list[0].id : null
      })
    } catch {} finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const triggerSync = async (id) => {
    setSyncing(s => ({ ...s, [id]: true }))
    try { await api.post(`/api/v1/devops-connectors/${id}/sync`) } catch {}
    setTimeout(() => { setSyncing(s => ({ ...s, [id]: false })); load() }, 3000)
  }

  const disconnect = async (id) => {
    if (!confirm('Disconnect this DevOps connector?')) return
    await api.delete(`/api/v1/devops-connectors/${id}`).catch(() => {})
    if (selected === id) setSelected(null)
    load()
  }

  const selectedConn = connectors.find(c => c.id === selected)

  return (
    <div className="flex h-screen bg-siem-bg text-siem-text overflow-hidden">

      {/* Sidebar */}
      <div className="w-72 flex-shrink-0 flex flex-col border-r border-siem-border">

        <div className="flex-shrink-0 px-4 py-3 border-b border-siem-border bg-siem-surface">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <GitBranch size={16} className="text-emerald-400"/>
              <span className="text-sm font-semibold">DevOps</span>
            </div>
            <button onClick={load} className="text-siem-muted hover:text-siem-text">
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''}/>
            </button>
          </div>
          <div className="text-[10px] text-siem-muted mt-1">
            {connectors.length} connected · GitHub, GitLab
          </div>
        </div>

        <div className="flex-1 overflow-y-auto min-h-0 py-2">
          {connectors.map(conn => {
            const cfg = PROVIDERS[conn.provider] || {}
            const isSelected = selected === conn.id
            return (
              <button key={conn.id} onClick={() => { setSelected(conn.id); setAdding(null) }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 text-left transition-colors ${
                  isSelected ? 'bg-siem-accent/10 border-r-2 border-siem-accent' : 'hover:bg-siem-surface'
                }`}>
                <Code size={14} className={cfg.color || 'text-siem-muted'}/>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-siem-text truncate">{conn.org}</div>
                  <div className="flex items-center gap-1.5 text-[10px] text-siem-muted">
                    <span className={`w-1.5 h-1.5 rounded-full ${
                      conn.status === 'connected' ? 'bg-emerald-400' :
                      conn.status === 'error' ? 'bg-red-400' : 'bg-yellow-400'
                    }`}/>
                    {conn.provider} · {conn.status}
                    {conn.event_count > 0 && <span className="ml-1">· {conn.event_count.toLocaleString()} events</span>}
                  </div>
                </div>
                <ChevronRight size={12} className="text-siem-muted shrink-0"/>
              </button>
            )
          })}
          {!loading && connectors.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <GitBranch size={24} className="opacity-30"/>No DevOps connected
            </div>
          )}
        </div>

        <div className="flex-shrink-0 border-t border-siem-border p-3 space-y-1">
          <p className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">Add connector</p>
          {Object.entries(PROVIDERS).map(([provider, cfg]) => (
            <button key={provider}
              onClick={() => { setAdding(provider); setSelected(null) }}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs border transition-colors ${
                adding === provider
                  ? `${cfg.border} ${cfg.bg} ${cfg.color}`
                  : 'border-siem-border text-siem-muted hover:text-siem-text'
              }`}>
              <Plus size={11}/>{cfg.label}
            </button>
          ))}
        </div>
      </div>

      {/* Right panel */}
      <div className="flex-1 min-w-0">
        {adding && (
          <div className="p-6 max-w-2xl">
            <div className="flex items-center gap-2 mb-4">
              <span className={`text-lg font-bold ${PROVIDERS[adding]?.color}`}>
                {PROVIDERS[adding]?.label}
              </span>
            </div>
            <ConnectorForm
              provider={adding}
              onSaved={() => { setAdding(null); load() }}
              onCancel={() => setAdding(null)}
            />
          </div>
        )}

        {selectedConn && !adding && (
          <ConnectorDetail
            key={`connector-${selectedConn.id}-${selectedConn.provider}`}
            conn={selectedConn}
            onSync={() => triggerSync(selectedConn.id)}
            onDisconnect={() => disconnect(selectedConn.id)}
            syncing={!!syncing[selectedConn.id]}
          />
        )}

        {!selectedConn && !adding && (
          <div className="flex flex-col items-center justify-center h-full text-siem-muted gap-4">
            <div className="w-16 h-16 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
              <GitBranch size={32} className="opacity-40"/>
            </div>
            <div className="text-center">
              <div className="text-sm font-medium text-siem-text mb-1">DevOps Security</div>
              <div className="text-xs max-w-xs text-center">
                Connect GitHub or GitLab to monitor code changes, detect secrets in commits, and alert on supply chain threats.
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 text-[10px] mt-2 max-w-xs">
              {[
                { icon: Lock, text: 'Secret detection on every push' },
                { icon: Shield, text: 'CI/CD pipeline tamper detection' },
                { icon: FileText, text: 'Full commit diff audit trail' },
                { icon: Bell, text: 'Real-time alerts on org changes' },
              ].map(({ icon: Icon, text }) => (
                <div key={text} className="flex items-center gap-2 text-siem-muted p-2 bg-siem-surface rounded-lg border border-siem-border">
                  <Icon size={11} className="text-siem-accent shrink-0"/>{text}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
