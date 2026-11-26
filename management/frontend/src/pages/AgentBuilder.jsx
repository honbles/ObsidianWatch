import { useState, useEffect, useRef } from 'react'
import api from '../api/client'
import { PageHeader } from '../components/ui'
import { Server, Monitor, Laptop, Radar, Network, Lock } from 'lucide-react'

const PLATFORMS = [
  {
    id: 'linux',
    label: 'Linux',
    icon: Server,
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
    icon: Monitor,
    desc: 'Windows 10/11 · Server 2016+',
    sub: 'Installs as Windows Service with tamper DACL',
    installCmd: '.\\obsidianwatch-win-agent.exe install',
    uninstallCmd: '.\\obsidianwatch-win-agent.exe uninstall',
    binary: 'obsidianwatch-win-agent.exe',
    color: 'blue',
    adminNote: 'Run as Administrator',
  },
  {
    id: 'macos-arm64',
    label: 'macOS (Apple Silicon)',
    icon: Laptop,
    desc: 'M1/M2/M3 Macs · macOS 12+',
    sub: 'Native arm64 build. Installs as launchd daemon',
    installCmd: 'chmod +x obsidianwatch-macos-agent && sudo ./obsidianwatch-macos-agent install',
    uninstallCmd: 'sudo ./obsidianwatch-macos-agent uninstall',
    binary: 'obsidianwatch-macos-agent',
    color: 'purple',
  },
  {
    id: 'macos',
    label: 'macOS (Intel)',
    icon: Laptop,
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
    icon: Radar,
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
    icon: Network,
    fields: [
      { key: 'backend_url',    label: 'Backend URL',    placeholder: 'https://192.168.1.140:8443', required: true, hint: 'Where agents send events, enroll and open live response.' },
      { key: 'management_url', label: 'Management URL', placeholder: 'https://192.168.1.140',      required: false, hint: 'Optional. Agents do not connect to it; it is only kept reachable while a host is isolated.' },
      { key: 'enroll_days',    label: 'Enrollment token valid for (days)', placeholder: '30', required: false, hint: '1 to 90 days. Enrolled agents are not affected when it expires.' },
      { key: 'enroll_max_uses', label: 'Maximum hosts for this build', placeholder: '500', required: false, hint: 'Revoke the token in Platform settings → Agent enrollment if the file leaks.' },
      { key: 'site_name',      label: 'Site Name (Network Probe only)', placeholder: 'HQ-Network', required: false, hint: 'Friendly name for this network probe location', probeOnly: true },
    ],
  },
  {
    title: 'CA Certificate',
    icon: Lock,
    fields: [
      { key: 'ca_cert', label: 'Backend CA Certificate (PEM)', placeholder: '-----BEGIN CERTIFICATE-----\n...', hint: 'CA cert for the agent backend (:8443) - embedded in the binary', textarea: true },
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
          <span className="ow-tile-icon"><p.icon size={20} strokeWidth={1.6}/></span>
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
        {/* Download saved zip - main action, shown when ready */}
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
          disabled={isBuilding || !form.backend_url}
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

// The server mints the enrollment token; the form only sets its lifetime and host limit.
function buildPayload(platform, form) {
  const { enroll_days, enroll_max_uses, ...rest } = form
  return { platform, ...rest, enroll_ttl_hours: Math.round(Number(enroll_days) * 24) || 720, enroll_max_uses: Number(enroll_max_uses) || 500 }
}

export default function AgentBuilder() {
  const [form, setForm] = useState({
    backend_url: '', management_url: '', enroll_days: '30', enroll_max_uses: '500',
    ca_cert: '', management_ca_cert: '', enable_live_response: false,
    /* [APP-FORM-BEGIN] */ enable_app_profile: false, /* [APP-FORM-END] */
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
        enroll_days:        f.enroll_days        || String(Math.round((r.data.default_enroll_ttl_hours || 720) / 24)),
        enroll_max_uses:    f.enroll_max_uses    || String(r.data.default_enroll_max_uses || 500),
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
    if (!form.backend_url) {
      setError('Fill in the Backend URL before building.')
      return
    }
    const days = Number(form.enroll_days), uses = Number(form.enroll_max_uses)
    if (!(days >= 1 && days <= 90) || !(uses >= 1 && uses <= 100000)) {
      setError('Enrollment token: 1 to 90 days and 1 to 100000 hosts.')
      return
    }
    setBuilding(b => ({ ...b, [platform]: true }))
    try {
      await api.post('/api/v1/agent-builder/build', buildPayload(platform, form))
      setSuccess(`${platform} build started - this takes 1–2 minutes on first run.`)
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
    <div>
      <PageHeader title="Agent builder"
        state={anyBuilding ? 'info' : undefined} stateText="Compiling"
        sub="Settings are compiled into each agent package."
        actions={<a href="/setup?rerun=1" className="ow-btn" style={{ textDecoration: 'none' }}>Re-run setup</a>}/>
      <div className="ow-body" style={{ maxWidth: 1180 }}>
      {/* Config form */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-8">
        {FIELD_GROUPS.map(group => (
          <div key={group.title} className="rounded-xl border border-siem-border bg-siem-surface overflow-hidden">
            <div className="px-5 py-3 border-b border-siem-border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <group.icon size={15} strokeWidth={1.7} className="text-siem-muted"/>
                <span className="text-sm font-semibold text-siem-text">{group.title}</span>
              </div>
              {group.note && <span className="text-xs text-siem-muted/60">{group.note}</span>}
            </div>
            <div className="p-5 space-y-4">
              {group.title === 'Connection' && (
                <label className="flex items-start gap-2 text-xs text-siem-muted">
                  <input type="checkbox" checked={!!form.enable_live_response} onChange={e => setForm(f => ({ ...f, enable_live_response: e.target.checked }))} />
                  <span><b className="text-siem-text">Enable Live Response (remote shell)</b> - off by default. Agents built with this on accept analyst terminal sessions as root/SYSTEM.</span>
                </label>
              )}
              {/* [APP-BUILDER-BEGIN] */}
              {group.title === 'Connection' && (
                <div className="space-y-2">
                  <label className="flex items-start gap-2 text-xs text-siem-muted">
                    <input type="checkbox" checked={!!form.enable_app_profile} onChange={e => setForm(f => ({ ...f, enable_app_profile: e.target.checked }))} />
                    <span><b className="text-siem-text">Enable the app-server profile (Application Monitoring)</b> - local OpenTelemetry receiver and, on Linux, the runtime sensor. For application hosts.</span>
                  </label>
                  {form.enable_app_profile && (
                    <div className="ml-6 grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs font-medium text-siem-text mb-1">Unix socket path (optional)</label>
                        <input value={form.app_otlp_socket || ''} onChange={e => setForm(f => ({ ...f, app_otlp_socket: e.target.value }))}
                          placeholder="/run/obsidianwatch/otlp.sock" className="w-full bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text font-mono" />
                        <span className="block text-[10px] text-siem-muted mt-1">For containers: mount this socket into the container instead of using the network.</span>
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-siem-text mb-1">Host sensor tier (Linux)</label>
                        <select value={form.app_sensor_mode || 'auto'} onChange={e => setForm(f => ({ ...f, app_sensor_mode: e.target.value }))}
                          className="w-full bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text">
                          <option value="auto">Automatic (best available)</option><option value="procevent">Proc connector + polling</option><option value="poll">Polling only (works without root)</option>
                        </select>
                        <span className="block text-[10px] text-siem-muted mt-1">Discovers services by their listening ports and watches what they run, connect to and write.</span>
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-siem-text mb-1">Environment for discovered services</label>
                        <input value={form.app_environment || ''} onChange={e => setForm(f => ({ ...f, app_environment: e.target.value }))}
                          placeholder="prod" className="w-full bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text font-mono" />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-siem-text mb-1">Client address storage</label>
                        <select value={form.app_client_ip_mode || 'full'} onChange={e => setForm(f => ({ ...f, app_client_ip_mode: e.target.value }))}
                          className="w-full bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text">
                          <option value="full">Full address</option><option value="truncated">Truncated (/24, /48)</option><option value="off">Do not store</option>
                        </select>
                      </div>
                      <label className="md:col-span-2 flex items-start gap-2 text-xs text-siem-muted">
                        <input type="checkbox" checked={!!form.app_requests_ebpf} onChange={e => setForm(f => ({ ...f, app_requests_ebpf: e.target.checked }))} />
                        <span><b className="text-siem-text">Trace requests without code changes (eBPF, Linux)</b> - requests, errors, latency and traces without code changes (Tier 1). Linux 5.8+ with BTF, agent as root.</span>
                      </label>
                    </div>
                  )}
                </div>
              )}
              {/* [APP-BUILDER-END] */}
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
    </div>
  )
}
