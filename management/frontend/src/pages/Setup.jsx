import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Eye, EyeOff, AlertCircle } from 'lucide-react'
import api from '../api/client'
import { AuthLayout } from '../components/AuthLayout'

export default function Setup() {
  const navigate = useNavigate()
  const [status, setStatus]   = useState(null)
  const [form, setForm]       = useState({
    backend_domain: '',
    backend_url: '',
    management_url: '',
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
    <AuthLayout><div className="auth-sub" style={{ textAlign: 'center' }}>Loading…</div></AuthLayout>
  )

  // A plain render function, not a component, so inputs keep focus while typing.
  const secret = (k, label, placeholder) => (
    <div key={k}>
      <label className="auth-label" htmlFor={'setup-' + k}>{label}</label>
      <div className="auth-pass">
        <input id={'setup-' + k} className="input auth-input" type={showPwd[k] ? 'text' : 'password'} value={form[k]}
          onChange={e => set(k, e.target.value)} placeholder={placeholder} autoComplete="off" spellCheck={false}/>
        <button type="button" className="auth-reveal" onClick={() => setShowPwd(s => ({ ...s, [k]: !s[k] }))}
          aria-label={showPwd[k] ? 'Hide key' : 'Show key'}>{showPwd[k] ? <EyeOff size={15}/> : <Eye size={15}/>}</button>
      </div>
    </div>
  )

  return (
    <AuthLayout wide>
      <div className="auth-eyebrow" style={{ color: 'var(--acc)', marginBottom: 10 }}>First-run setup</div>
      <h1 className="auth-title">Welcome to ObsidianWatch</h1>
      <p className="auth-sub">How agents and people reach this server. You can change this later.</p>

      <div className="setup-sec">
        <div className="setup-h">Detected network</div>
        <div className="setup-grid">
          <div><div className="setup-k">Private IP</div><div className="mono t1">{status.private_ip || '-'}</div></div>
          <div><div className="setup-k">Public IP</div><div className="mono t1">{status.public_ip || '-'}</div></div>
        </div>
        <p className="setup-note">The TLS certificate covers both addresses.</p>
      </div>

      <div className="setup-sec">
        <div className="setup-h">Connection <span className="setup-opt">Backend domain optional</span></div>
        <label className="auth-label" htmlFor="setup-domain">Backend domain</label>
        <input id="setup-domain" className="input auth-input" type="text" value={form.backend_domain}
          onChange={e => set('backend_domain', e.target.value)} placeholder="siem.company.com"/>
        <p className="setup-note">Blank uses the IP address. To add the domain to the TLS certificate, set EXTRA_SAN_DNS in .env and run docker compose up cert-init.</p>
        <label className="auth-label" htmlFor="setup-backend">Backend URL</label>
        <input id="setup-backend" className="input auth-input mono" type="text" value={form.backend_url} onChange={e => set('backend_url', e.target.value)}/>
        <p className="setup-note">Where agents send events. Detected from the public IP.</p>
        <label className="auth-label" htmlFor="setup-mgmt">Management URL</label>
        <input id="setup-mgmt" className="input auth-input mono" type="text" value={form.management_url} onChange={e => set('management_url', e.target.value)}/>
        <p className="setup-note">Where people open this console. Detected from the private IP.</p>
      </div>

      <div className="setup-sec">
        <div className="setup-h">AI analysis <span className="setup-opt">Optional</span></div>
        <p className="setup-note" style={{ marginTop: 0 }}>Explains alerts and suggests next steps. The NVD key raises the CVE lookup rate limit.</p>
        {secret('groq_api_key', 'Groq API key', 'gsk_…  (free at console.groq.com)')}
        {secret('anthropic_api_key', 'Anthropic API key', 'sk-ant-…  (console.anthropic.com)')}
        {secret('nvd_api_key', 'NVD API key', 'Free at nvd.nist.gov/developers')}
      </div>

      <div className="setup-sec">
        <div className="setup-h">Threat intelligence <span className="setup-opt">Optional</span></div>
        <p className="setup-note" style={{ marginTop: 0 }}>Indicator feeds used by automated detection.</p>
        {secret('threatfox_api_key', 'ThreatFox API key', 'Free at threatfox.abuse.ch')}
        {secret('otx_api_key', 'OTX API key', 'Free at otx.alienvault.com')}
      </div>

      {error && <div className="auth-error" role="alert"><AlertCircle size={15}/><span>{error}</span></div>}

      <button onClick={submit} disabled={saving} className="ow-btn primary auth-submit" style={{ width: '100%' }}>
        {saving ? <><span className="ow-spin" aria-hidden="true"/>Saving…</> : 'Complete setup'}
      </button>
    </AuthLayout>
  )
}
