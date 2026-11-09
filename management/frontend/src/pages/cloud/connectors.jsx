import { useState, useEffect, useCallback } from 'react'
import { CheckCircle, XCircle, RefreshCw, Eye, EyeOff, AlertCircle, Activity, Search, Shield, Zap, Trash2, BarChart2, Layers, FileText, CheckSquare } from 'lucide-react'
import api, { runScan } from '../../api/client'
import { PanelBlastRadius } from './blast.jsx'
import { PanelCISBenchmark, PanelCompliance } from './compliance.jsx'
import { PanelDeepDive } from './deepdive.jsx'
import { PanelAssetGraph, PanelAttackSurface, PanelEventTimeline, PanelOverview } from './overview.jsx'
import { PROVIDERS, PROVIDER_COLORS } from './shared.jsx'

// ── ConnectorForm ─────────────────────────────────────────────────────────────
export function ConnectorForm({ provider, onSaved, onCancel }) {
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

// ── ConnectorDetail — 5-panel architecture ────────────────────────────────────
export function ConnectorDetail({ conn, onSync, onDisconnect, syncing }) {
  const [tab, setTab]               = useState('overview')
  const [cspm, setCspm]             = useState(null)
  const [cspmLoading, setCspmLoading]   = useState(false)
  const [cis, setCis]                   = useState(null)
  const [cisLoading, setCisLoading]     = useState(false)
  const [cisScanning, setCisScanning]   = useState(false)
  const [cspmScanning, setCspmScanning] = useState(false)
  const [events, setEvents]         = useState([])
  const [loadingE, setLoadingE]     = useState(false)
  const [cmdbAssets, setCmdbAssets] = useState(null)
  const [cmdbLoading, setCmdbLoading] = useState(false)
  const [blast, setBlast]           = useState(null)
  const [blastLoading, setBlastLoading] = useState(false)
  const [blastScanning, setBlastScanning] = useState(false)

  const loadEvents = useCallback(async () => {
    setLoadingE(true)
    try {
      const provider = conn.provider || 'gcp'
      const agentPrefixes = {
        gcp:   [`gcp-auditlog-${conn.id}`, `gcp-vpcflow-${conn.id}`, `gcp-dns-${conn.id}`, `gcp-ids-${conn.id}`, `gcp-cloudrun-${conn.id}`, `gcp-gkeaudit-${conn.id}`],
        aws:   [`aws-cloudtrail-${conn.id}`, `aws-guardduty-${conn.id}`, `aws-securityhub-${conn.id}`],
        azure: [`azure-activitylog-${conn.id}`, `azure-entra-${conn.id}`,
                `azure-entra-audit-${conn.id}`, `azure-defender-${conn.id}`,
                `azure-nsgflow-${conn.id}`],
      }
      const prefixes = agentPrefixes[provider] || [`${provider}-${conn.id}`]
      const results = await Promise.all(
        prefixes.map(agentId => api.get('/api/v1/events', { params: { agent_id: agentId, limit: 500 } })
          .then(r => r.data?.events || []).catch(() => []))
      )
      setEvents(results.flat().sort((a,b) => new Date(b.time) - new Date(a.time)).slice(0, 500))
    } catch { setEvents([]) } finally { setLoadingE(false) }
  }, [conn.provider, conn.id])

  const loadCSPM = useCallback(async () => {
    setCspmLoading(true)
    try {
      const { data } = await api.get(`/api/v1/cloud-connectors/${conn.id}/cspm`)
      // GCP uses project_id, Azure uses subscription_id
      const hasData = data?.project_id || data?.subscription_id
      setCspm(hasData ? data : null)
    } catch { setCspm(null) } finally { setCspmLoading(false) }
  }, [conn.id])

  const loadCIS = async () => {
    setCisLoading(true)
    try {
      const { data } = await api.get(`/api/v1/cloud-connectors/${conn.id}/cis`)
      if (data?.controls?.length > 0) setCis(data)
    } catch {} finally { setCisLoading(false) }
  }

  const runCIS = async () => {
    setCisScanning(true)
    try {
      const { data } = await runScan(`/api/v1/cloud-connectors/${conn.id}/cis`)
      setCis(data)
    } catch (e) { alert('CIS scan failed: ' + (e.response?.data?.error || e.message)) }
    finally { setCisScanning(false) }
  }

  const runCSPM = async () => {
    setCspmScanning(true)
    try {
      const { data } = await runScan(`/api/v1/cloud-connectors/${conn.id}/cspm`)
      setCspm(data)
    } catch (e) { alert('Scan failed: ' + (e.response?.data?.error || e.message)) }
    finally { setCspmScanning(false) }
  }

  const importOrg = async () => {
    const role_name = window.prompt('Name of the read-only role to assume in every member account (e.g. ObsidianWatchReadOnly):')
    if (!role_name) return
    const external_id = window.prompt('External ID for that role (leave blank if none):') || ''
    try {
      const { data: dry } = await api.post(`/api/v1/cloud-connectors/${conn.id}/aws-org-import`, { role_name, external_id, dry_run: true })
      const n = dry?.accounts?.length || 0
      if (!n) { window.alert('No active member accounts found to import.'); return }
      if (!window.confirm(`Create ${n} AWS connectors (one per member account)?\n\n` + dry.accounts.slice(0, 15).map(a => `${a.account_id}  ${a.name}`).join('\n') + (n > 15 ? `\n…and ${n - 15} more` : '') + `\n\n${dry.note}`)) return
      const { data } = await api.post(`/api/v1/cloud-connectors/${conn.id}/aws-org-import`, { role_name, external_id })
      window.alert(`Imported ${(data.accounts || []).filter(a => a.status === 'imported').length} accounts. Reload the connector list to see them.`)
    } catch (e) {
      window.alert(e?.response?.data?.error || 'Import failed')
    }
  }

  const loadCMDB = useCallback(async () => {
    if (conn.provider !== 'gcp' && conn.provider !== 'azure' && conn.provider !== 'aws') return
    setCmdbLoading(true)
    try {
      const { data } = await api.get(`/api/v1/cloud-connectors/${conn.id}/assets`)
      setCmdbAssets(data?.assets ? data : null)
    } catch { setCmdbAssets(null) } finally { setCmdbLoading(false) }
  }, [conn.id, conn.provider])

  const runCMDB = async () => {
    setCmdbLoading(true)
    try {
      await api.post(`/api/v1/cloud-connectors/${conn.id}/assets`)
      setTimeout(loadCMDB, 3000) // poll after 3s
    } catch { } finally { setCmdbLoading(false) }
  }



  const loadBlast = useCallback(async () => {
    if (conn.provider !== 'gcp' && conn.provider !== 'azure' && conn.provider !== 'aws') return
    setBlastLoading(true)
    try {
      const { data } = await api.get(`/api/v1/cloud-connectors/${conn.id}/blast`)
      setBlast(data?.nodes?.length ? data : null)
    } catch { setBlast(null) } finally { setBlastLoading(false) }
  }, [conn.id, conn.provider])

  const runBlast = async () => {
    setBlastScanning(true)
    try {
      const { data } = await runScan(`/api/v1/cloud-connectors/${conn.id}/blast`)
      setBlast(data)
    } catch (e) { alert('Blast radius scan failed: ' + (e.response?.data?.error || e.message)) }
    finally { setBlastScanning(false) }
  }

  useEffect(() => {
    loadCSPM()
    loadCIS()
  }, [loadCSPM])

  useEffect(() => {
    if (tab === 'timeline') loadEvents()
    if (tab === 'assets') loadCMDB()
    if (tab === 'blast') loadBlast()
  }, [tab, loadEvents, loadCMDB, loadBlast])

  const statusBadge = conn.status === 'connected'
    ? 'bg-green-950/40 text-emerald-400 border-emerald-800'
    : conn.status === 'error'
    ? 'bg-red-950/40 text-red-400 border-red-800'
    : 'bg-yellow-950/40 text-yellow-400 border-yellow-800'

  const tabs = [
    { id:'overview',    label:'Overview',       icon: BarChart2   },
    { id:'assets',      label:'Asset Graph',    icon: Layers      },
    { id:'attack',      label:'Attack Surface', icon: Zap         },
    { id:'timeline',    label:'Event Timeline', icon: Activity    },
    { id:'deepdive',    label:'Deep Dive',      icon: Search      },
    { id:'blast',       label:'Blast Radius',   icon: Shield      },
    { id:'cis',         label:'CIS Benchmark',  icon: CheckSquare },
    { id:'compliance',  label:'Compliance',     icon: FileText    },
  ]

  // Badge counts per tab
  const tabCounts = {
    overview: cspm?.total_findings || null,
    assets:   cmdbAssets ? cmdbAssets.total_assets : (cspm ? [...new Set((cspm.findings||[]).map(f => f.resource).filter(Boolean))].length : null),
    attack:   cspm ? (cspm.findings||[]).filter(f => f.category==='network' || (f.title||'').toLowerCase().includes('public')).length : null,
    timeline: events.length || null,
    deepdive: null,
    blast:    blast?.summary?.critical_paths || null,
    cis:      cis ? cis.failed : null,
    compliance: null,
  }

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
            {cspm && (
              <span style={{ fontSize:10, padding:'2px 8px', borderRadius:10,
                background: cspm.critical > 0 ? 'rgba(248,113,113,0.1)' : 'rgba(52,211,153,0.1)',
                color: cspm.critical > 0 ? '#f87171' : '#34d399',
                border: `1px solid ${cspm.critical > 0 ? 'rgba(248,113,113,0.25)' : 'rgba(52,211,153,0.25)'}` }}>
                {cspm.critical > 0 ? `${cspm.critical} critical` : `${cspm.total_findings} findings`}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button onClick={onSync} disabled={syncing}
              className="flex items-center gap-1.5 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-3 py-1.5 disabled:opacity-40">
              <RefreshCw size={11} className={syncing ? 'animate-spin' : ''}/> Sync now
            </button>
            {conn.provider === 'aws' && (
              <button onClick={importOrg}
                title="Create one connector per active member account of this AWS Organization"
                className="flex items-center gap-1.5 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-3 py-1.5">
                <Layers size={11}/> Import org accounts
              </button>
            )}
            <button onClick={onDisconnect}
              className="flex items-center gap-1.5 text-xs border border-red-800 text-red-400 hover:bg-red-950/20 rounded-lg px-3 py-1.5">
              <Trash2 size={11}/> Disconnect
            </button>
          </div>
        </div>

        {/* 5-tab nav */}
        <div className="flex gap-1">
          {tabs.map(({ id, label, icon: Icon }) => {
            const count = tabCounts[id]
            return (
              <button key={id} onClick={() => setTab(id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  tab === id ? 'bg-siem-accent text-black' : 'text-siem-muted hover:text-siem-text'
                }`}>
                <Icon size={11}/>{label}
                {count !== null && count > 0 && (
                  <span style={{ fontSize:9.5, background: tab===id ? 'rgba(0,0,0,0.2)' : 'rgba(0,194,224,0.15)',
                    color: tab===id ? '#000' : 'var(--accent)', borderRadius:10, padding:'0 5px', minWidth:15, textAlign:'center' }}>
                    {count}
                  </span>
                )}
              </button>
            )
          })}
        </div>
      </div>

      {/* Panel content */}
      <div className="flex-1 min-h-0 overflow-hidden">
        {tab === 'overview' && (
          <PanelOverview conn={conn} cspm={cspm} loading={cspmLoading} onRunScan={runCSPM} scanning={cspmScanning} onTabChange={setTab}/>
        )}
        {tab === 'assets' && (
          <PanelAssetGraph cspm={cspm} cmdbAssets={cmdbAssets} cmdbLoading={cmdbLoading} onRunCMDB={runCMDB} conn={conn}/>
        )}

        {tab === 'attack' && (
          <PanelAttackSurface cspm={cspm} conn={conn}/>
        )}
        {tab === 'timeline' && (
          <PanelEventTimeline events={events} loading={loadingE} conn={conn}/>
        )}
        {tab === 'deepdive' && (
          <PanelDeepDive cspm={cspm} conn={conn}/>
        )}
        {tab === 'blast' && (
          <PanelBlastRadius blast={blast} loading={blastLoading} scanning={blastScanning} onRunScan={runBlast} conn={conn}/>
        )}
        {tab === 'cis' && (
          <PanelCISBenchmark cis={cis} loading={cisLoading} scanning={cisScanning} onRunScan={runCIS} conn={conn}/>
        )}
        {tab === 'compliance' && (
          <PanelCompliance connId={conn.id} provider={conn.provider}/>
        )}
      </div>
    </div>
  )
}

