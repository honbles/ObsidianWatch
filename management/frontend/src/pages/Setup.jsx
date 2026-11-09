import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'

export default function Setup() {
  const navigate = useNavigate()
  const [status, setStatus]   = useState(null)
  const [form, setForm]       = useState({
    backend_domain: '',
    backend_url: '',
    management_url: '',
    agent_api_key: '',
    groq_api_key: '',
    nvd_api_key: '',
    anthropic_api_key: '',
    threatfox_api_key: '',
    otx_api_key: '',
  })
  const [saving, setSaving]   = useState(false)
  const [error, setError]     = useState('')
  const [showPwd, setShowPwd] = useState({})

  useEffect(() => {
    api.get('/api/v1/setup/status').then(r => {
      const s = r.data
      setStatus(s)
      setForm(f => ({
        ...f,
        backend_url:    s.backend_url    || '',
        management_url: s.management_url || '',
      }))
      // Only auto-redirect away if complete AND not explicitly visiting /setup
      if (s.is_complete && !window.location.search.includes('rerun')) {
        navigate('/')
      }
    }).catch(() => navigate('/'))
  }, [])

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const submit = async () => {
    setError('')
    if (!form.agent_api_key) {
      setError('Agent API Key is required — it must match the key in backend/docker/server.yaml')
      return
    }
    setSaving(true)
    try {
      await api.post('/api/v1/setup/complete', form)
      navigate('/')
    } catch (e) {
      setError(e.response?.data?.error || e.message)
    } finally {
      setSaving(false)
    }
  }

  if (!status) return (
    <div className="min-h-screen bg-siem-bg flex items-center justify-center">
      <div className="text-siem-muted text-sm">Loading...</div>
    </div>
  )

  return (
    <div className="min-h-screen bg-siem-bg flex items-center justify-center p-6">
      <div className="w-full max-w-xl">

        {/* Header */}
        <div className="text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 ring-2 ring-cyan-500/30 flex items-center justify-center text-2xl mx-auto mb-4">👁</div>
          <h1 className="text-2xl font-bold text-siem-text mb-1">Welcome to ObsidianWatch</h1>
          <p className="text-siem-muted text-sm">Complete setup to deploy agents and start collecting events</p>
        </div>

        {/* Detected IPs */}
        <div className="rounded-xl border border-siem-border bg-siem-surface p-4 mb-5">
          <p className="text-xs font-medium text-siem-muted uppercase tracking-wider mb-3">Auto-detected network</p>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <div className="text-xs text-siem-muted mb-0.5">Private IP</div>
              <div className="font-mono text-cyan-400">{status.private_ip || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-siem-muted mb-0.5">Public IP</div>
              <div className="font-mono text-cyan-400">{status.public_ip || '—'}</div>
            </div>
          </div>
          <p className="text-xs text-siem-muted mt-3">
            TLS certificate already includes both IPs. Agents connecting to either will work.
          </p>
        </div>

        <div className="space-y-4 mb-5">

          {/* Agent API Key — required */}
          <div className="rounded-xl border border-red-500/20 bg-siem-surface overflow-hidden">
            <div className="px-4 py-2.5 bg-red-500/10 border-b border-red-500/20 flex items-center gap-2">
              <span className="text-red-400 text-sm font-semibold">🔑 Agent API Key</span>
              <span className="text-xs text-red-400/70 ml-auto">Required</span>
            </div>
            <div className="p-4">
              <div className="relative">
                <input
                  type={showPwd.agent ? 'text' : 'password'}
                  value={form.agent_api_key}
                  onChange={e => set('agent_api_key', e.target.value)}
                  placeholder="Paste from backend/docker/server.yaml → auth.api_keys[0]"
                  className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text placeholder-siem-muted focus:outline-none focus:border-cyan-500/50 pr-12"
                />
                <button type="button" onClick={() => setShowPwd(s => ({...s, agent: !s.agent}))}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-siem-muted hover:text-siem-text">
                  {showPwd.agent ? 'hide' : 'show'}
                </button>
              </div>
              <p className="text-xs text-siem-muted mt-1.5">
                Choose any strong key (generate with <code className="text-cyan-400">openssl rand -hex 32</code>). This will be written to both <code className="text-cyan-400">backend/docker/server.yaml</code> and <code className="text-cyan-400">management/docker/server.yaml</code> automatically, and embedded into all agent binaries.
              </p>
            </div>
          </div>

          {/* Optional domain */}
          <div className="rounded-xl border border-siem-border bg-siem-surface overflow-hidden">
            <div className="px-4 py-2.5 border-b border-siem-border flex items-center gap-2">
              <span className="text-siem-text text-sm font-semibold">🌐 Backend Domain</span>
              <span className="text-xs text-siem-muted ml-auto">Optional</span>
            </div>
            <div className="p-4">
              <input
                type="text"
                value={form.backend_domain}
                onChange={e => set('backend_domain', e.target.value)}
                placeholder="e.g. siem.company.com (leave blank to use IP)"
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text placeholder-siem-muted focus:outline-none focus:border-cyan-500/50"
              />
              <p className="text-xs text-siem-muted mt-1.5">
                If set, the domain is recorded and the agent cache cleared. To add it to the TLS certificate, set EXTRA_SAN_DNS in .env and run "docker compose up cert-init" (the CA key is kept out of the running services).
              </p>
            </div>
          </div>

          {/* URL overrides */}
          <div className="rounded-xl border border-siem-border bg-siem-surface overflow-hidden">
            <div className="px-4 py-2.5 border-b border-siem-border">
              <span className="text-siem-text text-sm font-semibold">⬡ Connection URLs</span>
            </div>
            <div className="p-4 space-y-3">
              <div>
                <label className="text-xs font-medium text-siem-text mb-1 block">Backend URL</label>
                <input type="text" value={form.backend_url}
                  onChange={e => set('backend_url', e.target.value)}
                  className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-cyan-500/50" />
                <p className="text-xs text-siem-muted mt-1">Agent event ingest — auto-detected from public IP</p>
              </div>
              <div>
                <label className="text-xs font-medium text-siem-text mb-1 block">Management URL</label>
                <input type="text" value={form.management_url}
                  onChange={e => set('management_url', e.target.value)}
                  className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-cyan-500/50" />
                <p className="text-xs text-siem-muted mt-1">Dashboard URL — auto-detected from private IP</p>
              </div>
            </div>
          </div>

          {/* AI keys */}
          <div className="rounded-xl border border-purple-500/20 bg-siem-surface overflow-hidden">
            <div className="px-4 py-2.5 bg-purple-500/10 border-b border-purple-500/20">
              <span className="text-purple-400 text-sm font-semibold">◈ AI Analysis</span>
              <span className="text-xs text-purple-400/70 ml-2">Optional — AI-powered alert analysis</span>
            </div>
            <div className="p-4 space-y-3">
              {[
                { key: 'groq_api_key', label: 'Groq API Key', placeholder: 'gsk_... — free at console.groq.com' },
                { key: 'nvd_api_key', label: 'NVD API Key (CVE Database)', placeholder: 'Optional — get free key at nvd.nist.gov/developers — raises rate limit for faster CVE lookups' },
                { key: 'anthropic_api_key', label: 'Anthropic API Key', placeholder: 'sk-ant-... — console.anthropic.com' },
              ].map(f => (
                <div key={f.key}>
                  <label className="text-xs font-medium text-siem-text mb-1 block">{f.label}</label>
                  <div className="relative">
                    <input type={showPwd[f.key] ? 'text' : 'password'}
                      value={form[f.key]} onChange={e => set(f.key, e.target.value)}
                      placeholder={f.placeholder}
                      className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text placeholder-siem-muted focus:outline-none focus:border-cyan-500/50 pr-12" />
                    <button type="button" onClick={() => setShowPwd(s => ({...s, [f.key]: !s[f.key]}))}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-siem-muted hover:text-siem-text">
                      {showPwd[f.key] ? 'hide' : 'show'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Intel keys */}
          <div className="rounded-xl border border-orange-500/20 bg-siem-surface overflow-hidden">
            <div className="px-4 py-2.5 bg-orange-500/10 border-b border-orange-500/20">
              <span className="text-orange-400 text-sm font-semibold">◉ Threat Intelligence</span>
              <span className="text-xs text-orange-400/70 ml-2">Optional — IOC feeds for automated detection</span>
            </div>
            <div className="p-4 space-y-3">
              {[
                { key: 'threatfox_api_key', label: 'ThreatFox API Key', placeholder: 'Free at threatfox.abuse.ch' },
                { key: 'otx_api_key', label: 'OTX API Key', placeholder: 'Free at otx.alienvault.com' },
              ].map(f => (
                <div key={f.key}>
                  <label className="text-xs font-medium text-siem-text mb-1 block">{f.label}</label>
                  <div className="relative">
                    <input type={showPwd[f.key] ? 'text' : 'password'}
                      value={form[f.key]} onChange={e => set(f.key, e.target.value)}
                      placeholder={f.placeholder}
                      className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text placeholder-siem-muted focus:outline-none focus:border-cyan-500/50 pr-12" />
                    <button type="button" onClick={() => setShowPwd(s => ({...s, [f.key]: !s[f.key]}))}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-siem-muted hover:text-siem-text">
                      {showPwd[f.key] ? 'hide' : 'show'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {error && (
          <div className="mb-4 px-4 py-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
            {error}
          </div>
        )}

        <button onClick={submit} disabled={saving}
          className="w-full py-3.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white font-semibold text-sm transition-all shadow-lg shadow-cyan-900/20">
          {saving ? '⟳ Saving...' : 'Complete Setup →'}
        </button>

        <p className="text-center text-xs text-siem-muted mt-4">
          You can change these settings later in Agent Builder and Settings
        </p>
      </div>
    </div>
  )
}
