import { useState, useEffect, useRef } from 'react'
import api from '../api/client'

const PLATFORMS = [
  {
    id: 'linux',
    label: 'Linux',
    icon: '🐧',
    desc: 'Ubuntu · Debian · RHEL · CentOS',
    sub: 'Installs as systemd service',
    installCmd: 'chmod +x obsidianwatch-linux-agent && sudo ./obsidianwatch-linux-agent install',
    uninstallCmd: 'sudo ./obsidianwatch-linux-agent uninstall',
    binary: 'obsidianwatch-linux-agent',
    color: 'emerald',
  },
  {
    id: 'windows',
    label: 'Windows',
    icon: '⊞',
    desc: 'Windows 10/11 · Server 2016+',
    sub: 'Installs as Windows Service with tamper DACL',
    installCmd: '.\\obsidianwatch-win-agent.exe install',
    uninstallCmd: '.\\obsidianwatch-win-agent.exe uninstall',
    binary: 'obsidianwatch-win-agent.exe',
    color: 'blue',
    adminNote: 'Run as Administrator',
  },
  {
    id: 'macos',
    label: 'macOS',
    icon: '🍎',
    desc: 'macOS 12 Monterey+',
    sub: 'Installs as launchd daemon',
    installCmd: 'chmod +x obsidianwatch-macos-agent && sudo ./obsidianwatch-macos-agent install',
    uninstallCmd: 'sudo ./obsidianwatch-macos-agent uninstall',
    binary: 'obsidianwatch-macos-agent',
    color: 'purple',
  },
  {
    id: 'network',
    label: 'Network Probe',
    icon: '📡',
    desc: 'Any Linux host on the network',
    sub: 'Receives syslog · NetFlow · SNMP from all network devices',
    installCmd: 'chmod +x obsidianwatch-network-probe && sudo ./obsidianwatch-network-probe install',
    uninstallCmd: 'sudo ./obsidianwatch-network-probe uninstall',
    binary: 'obsidianwatch-network-probe',
    color: 'cyan',
    isProbe: true,
    note: 'Drop one probe per site. Point all network devices at probe IP:514 (syslog) and :2055 (NetFlow).',
  },
]

const FIELD_GROUPS = [
  {
    title: 'Connection',
    icon: '⬡',
    fields: [
      { key: 'backend_url',    label: 'Backend URL',    placeholder: 'https://192.168.1.140:8443', required: true, hint: 'Agent ingest endpoint (port 8443)' },
      { key: 'management_url', label: 'Management URL', placeholder: 'http://192.168.1.140',       required: true, hint: 'Management dashboard URL' },
      { key: 'agent_api_key',  label: 'Agent API Key',  placeholder: 'openssl rand -hex 32',       required: true, hint: 'Matches agent_api_key in server.yaml', password: true },
      { key: 'site_name',      label: 'Site Name (Network Probe only)', placeholder: 'HQ-Network', required: false, hint: 'Friendly name for this network probe location', probeOnly: true },
    ],
  },
  {
    title: 'CA Certificate',
    icon: '🔒',
    fields: [
      { key: 'ca_cert', label: 'Backend CA Certificate (PEM)', placeholder: '-----BEGIN CERTIFICATE-----\n...', hint: 'CA cert for the agent backend (:8443) — embedded in the binary', textarea: true },
      { key: 'management_ca_cert', label: 'Management CA Certificate (PEM)', placeholder: '-----BEGIN CERTIFICATE-----\n...', hint: 'Only needed if management uses HTTPS with a self-signed cert. Leave empty if HTTP.', textarea: true, optional: true },
    ],
  },
]

const COLOR_MAP = {
  emerald: { badge: 'bg-emerald-500/15 text-emerald-400 ring-emerald-500/20', btn: 'from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500', dot: 'bg-emerald-400' },
  blue:    { badge: 'bg-blue-500/15 text-blue-400 ring-blue-500/20',          btn: 'from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500',   dot: 'bg-blue-400'    },
  purple:  { badge: 'bg-purple-500/15 text-purple-400 ring-purple-500/20',    btn: 'from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500',   dot: 'bg-purple-400'  },
  cyan:    { badge: 'bg-cyan-500/15 text-cyan-400 ring-cyan-500/20',          btn: 'from-cyan-600 to-teal-600 hover:from-cyan-500 hover:to-teal-500',     dot: 'bg-cyan-400'    },
}

function fmtSize(bytes) {
  if (!bytes) return ''
  if (bytes > 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024).toFixed(0)} KB`
}

function fmtDate(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
}

function PlatformCard({ platform, status, form, onBuild, onDownloadCached, building }) {
  const p = PLATFORMS.find(x => x.id === platform)
  const c = COLOR_MAP[p.color]
  const hasZip = status?.has_zip
  const isBuilding = status?.building || building[platform]

  return (
    <div className={`rounded-xl border bg-siem-surface transition-all ${
      hasZip ? 'border-siem-border-hover' : 'border-siem-border'
    }`}>
      {/* Header */}
      <div className="p-5 border-b border-siem-border flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="text-3xl">{p.icon}</span>
          <div>
            <div className="font-semibold text-siem-text">{p.label}</div>
            <div className="text-xs text-siem-muted">{p.desc}</div>
            <div className="text-xs text-siem-muted/60">{p.sub}</div>
          </div>
        </div>
        {/* Status badge */}
        <div className="flex-shrink-0 text-right">
          {isBuilding ? (
            <span className="text-xs text-amber-400 flex items-center gap-1">
              <span className="animate-spin inline-block">⟳</span> Compiling...
            </span>
          ) : hasZip ? (
            <div>
              <span className={`text-xs px-2 py-0.5 rounded-full ring-1 ${c.badge}`}>
                ✓ Ready
              </span>
              <div className="text-xs text-siem-muted mt-1">
                {fmtSize(status.zip_size)} · {fmtDate(status.zip_built_at)}
              </div>
            </div>
          ) : status?.last_error ? (
            <span className="text-xs text-red-400" title={status.last_error}>✗ Build failed</span>
          ) : (
            <span className="text-xs text-siem-muted">Not compiled</span>
          )}
        </div>
      </div>

      {/* Actions */}
      <div className="p-4 space-y-3">
        {/* Download saved zip — main action, shown when ready */}
        {hasZip && (
          <button
            onClick={() => onDownloadCached(platform)}
            className={`w-full py-2.5 rounded-lg bg-gradient-to-r ${c.btn} text-white text-sm font-semibold transition-all shadow-sm`}
          >
            ⬇ Download {p.label} Agent
          </button>
        )}

        {/* Build / Rebuild button */}
        <button
          onClick={() => onBuild(platform)}
          disabled={isBuilding || !form.backend_url || !form.management_url || !form.agent_api_key}
          className={`w-full py-2 rounded-lg border text-sm font-medium transition-all disabled:opacity-40 disabled:cursor-not-allowed ${
            hasZip
              ? 'border-siem-border text-siem-muted hover:text-siem-text hover:border-siem-border-hover'
              : 'border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10'
          }`}
        >
          {isBuilding ? '⟳ Compiling...' : hasZip ? '↺ Rebuild' : '▶ Build Agent'}
        </button>

        {/* Install command (shown when ready) */}
        {hasZip && (
          <div className="rounded-lg bg-siem-bg border border-siem-border p-3">
            {p.adminNote && (
              <div className="text-xs text-amber-400 mb-1.5">⚠ {p.adminNote}</div>
            )}
            <div className="font-mono text-xs text-green-300 select-all leading-relaxed">{p.installCmd}</div>
          </div>
        )}

        {status?.last_error && (
          <div className="text-xs text-red-400 bg-red-500/10 rounded-lg p-2 break-all">{status.last_error}</div>
        )}
      </div>
    </div>
  )
}

export default function AgentBuilder() {
  const [form, setForm] = useState({
    backend_url: '', management_url: '', agent_api_key: '',
    ca_cert: '', management_ca_cert: '',
  })
  const [buildStatus, setBuildStatus] = useState({})
  const [savedKeys, setSavedKeys]     = useState({})
  const [building, setBuilding]       = useState({})
  const [downloading, setDownloading] = useState({})
  const [error, setError]             = useState('')
  const [success, setSuccess]         = useState('')
  const [showPwd, setShowPwd]         = useState({})
  const pollRef = useRef(null)

  const fetchStatus = () =>
    api.get('/api/v1/agent-builder/status').then(r => setBuildStatus(r.data)).catch(() => {})

  useEffect(() => {
    fetchStatus()
    api.get('/api/v1/agent-builder/settings').then(r => {
      setSavedKeys(r.data)
      setForm(f => ({
        backend_url:        f.backend_url        || r.data.default_backend_url    || '',
        management_url:     f.management_url     || r.data.default_management_url || '',
        agent_api_key:      f.agent_api_key      || r.data.default_agent_api_key  || '',
        ca_cert:            f.ca_cert            || r.data.default_ca_cert        || '',
        management_ca_cert: f.management_ca_cert || '',
      }))
    }).catch(() => {})
    pollRef.current = setInterval(fetchStatus, 3000)
    return () => clearInterval(pollRef.current)
  }, [])

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const handleBuild = async (platform) => {
    setError(''); setSuccess('')
    if (!form.backend_url || !form.management_url || !form.agent_api_key) {
      setError('Fill in Backend URL, Management URL and Agent API Key before building.')
      return
    }
    setBuilding(b => ({ ...b, [platform]: true }))
    try {
      await api.post('/api/v1/agent-builder/build', { platform, ...form })
      setSuccess(`${platform} build started — this takes 1–2 minutes on first run.`)
    } catch (e) {
      setError('Build failed: ' + (e.response?.data?.error || e.message))
    }
    // Poll will update status; clear local building flag after a moment
    setTimeout(() => setBuilding(b => ({ ...b, [platform]: false })), 2000)
  }

  const handleDownloadCached = async (platform) => {
    setError(''); setSuccess('')
    setDownloading(d => ({ ...d, [platform]: true }))
    try {
      const resp = await api.get(
        `/api/v1/agent-builder/download/${platform}`,
        { responseType: 'blob' }
      )
      const url = URL.createObjectURL(resp.data)
      const a   = document.createElement('a')
      const st  = buildStatus[platform]
      const ts  = st?.zip_built_at ? new Date(st.zip_built_at).toISOString().slice(0,10).replace(/-/g,'') : new Date().toISOString().slice(0,10).replace(/-/g,'')
      a.href     = url
      a.download = `obsidianwatch-${platform}-agent-${ts}.zip`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(`Download failed: ${e.response?.data?.error || e.message}`)
    } finally {
      setDownloading(d => ({ ...d, [platform]: false }))
    }
  }

  const anyBuilding = Object.values(buildStatus).some(s => s?.building) || Object.values(building).some(Boolean)

  return (
    <div className="p-6 max-w-5xl mx-auto">

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-500/20 ring-1 ring-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold text-sm">AB</div>
          <h1 className="text-xl font-semibold text-siem-text">Agent Builder</h1>
          {anyBuilding && <span className="text-xs text-amber-400 animate-pulse ml-2">● compiling</span>}
          <a href="/setup?rerun=1"
            className="ml-auto text-xs text-siem-muted hover:text-cyan-400 transition-colors border border-siem-border hover:border-cyan-500/30 rounded-lg px-3 py-1.5">
            ⚙ Reconfigure setup
          </a>
        </div>
        <p className="text-siem-muted text-sm ml-11">
          Configure the agents once. The server compiles each platform with your settings baked into the binary — no config file needed at deployment.
        </p>
      </div>

      {/* Config form */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-8">
        {FIELD_GROUPS.map(group => (
          <div key={group.title} className="rounded-xl border border-siem-border bg-siem-surface overflow-hidden">
            <div className="px-5 py-3 border-b border-siem-border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-siem-muted">{group.icon}</span>
                <span className="text-sm font-semibold text-siem-text">{group.title}</span>
              </div>
              {group.note && <span className="text-xs text-siem-muted/60">{group.note}</span>}
            </div>
            <div className="p-5 space-y-4">
              {group.fields.map(field => {
                const isSaved = savedKeys[`has_${field.key}`]
                return (
                  <div key={field.key}>
                    <div className="flex items-center gap-2 mb-1.5">
                      <label className="text-xs font-medium text-siem-text">
                        {field.label}
                        {field.required && <span className="text-red-400 ml-0.5">*</span>}
                      </label>
                      {isSaved && !form[field.key] && (
                        <span className="text-xs px-1.5 py-0.5 rounded bg-green-500/15 text-green-400 ring-1 ring-green-500/20">saved</span>
                      )}
                    </div>
                    {field.textarea ? (
                      <textarea
                        rows={3}
                        value={form[field.key]}
                        onChange={e => set(field.key, e.target.value)}
                        placeholder={field.placeholder}
                        className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-xs font-mono text-siem-text placeholder-siem-muted focus:outline-none focus:border-cyan-500/50 resize-none"
                      />
                    ) : (
                      <div className="relative">
                        <input
                          type={field.password && !showPwd[field.key] ? 'password' : 'text'}
                          value={form[field.key]}
                          onChange={e => set(field.key, e.target.value)}
                          placeholder={isSaved && !form[field.key] ? '(using saved key)' : field.placeholder}
                          className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text placeholder-siem-muted focus:outline-none focus:border-cyan-500/50 pr-12"
                        />
                        {field.password && (
                          <button
                            type="button"
                            onClick={() => setShowPwd(s => ({ ...s, [field.key]: !s[field.key] }))}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-siem-muted hover:text-siem-text text-xs"
                          >
                            {showPwd[field.key] ? 'hide' : 'show'}
                          </button>
                        )}
                      </div>
                    )}
                    {field.hint && <p className="text-xs text-siem-muted mt-1">{field.hint}</p>}
                  </div>
                )
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Feedback */}
      {error   && <div className="mb-5 px-4 py-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">{error}</div>}
      {success && <div className="mb-5 px-4 py-3 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 text-sm">{success}</div>}

      {/* Platform cards */}
      <div>
        <h2 className="text-xs font-medium text-siem-muted uppercase tracking-wider mb-4">Agent Packages</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {PLATFORMS.map(p => (
            <PlatformCard
              key={p.id}
              platform={p.id}
              status={buildStatus[p.id]}
              form={form}
              onBuild={handleBuild}
              onDownloadCached={handleDownloadCached}
              building={building}
            />
          ))}
        </div>
      </div>

      {/* Info footer */}
      <div className="mt-6 rounded-xl border border-siem-border bg-siem-surface p-4">
        <div className="grid grid-cols-3 gap-6 text-xs text-siem-muted">
          <div>
            <div className="font-medium text-siem-text mb-1">What's in the zip</div>
            <div>Single binary with config embedded · INSTALL.md · No yaml file needed</div>
          </div>
          <div>
            <div className="font-medium text-siem-text mb-1">Install key</div>
            <div>Auto-generated at install time · Visible on dashboard under Agents → shield icon</div>
          </div>
          <div>
            <div className="font-medium text-siem-text mb-1">Re-deploy</div>
            <div>Click Rebuild any time to recompile with updated settings · Previous zip replaced</div>
          </div>
        </div>
      </div>
    </div>
  )
}
