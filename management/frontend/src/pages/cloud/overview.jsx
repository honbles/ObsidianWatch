import { useEffect, useState } from 'react'
import { RefreshCw, Activity, Search, Shield, Zap, ChevronRight, Database, Globe, Lock, Server, HardDrive, Key, Wifi, AlertTriangle, Info, Cpu, List, Filter, Layers, FileText, Sparkles, X } from 'lucide-react'
import { format } from 'date-fns'
import api from '../../api/client'
import { FindingCard, RiskScoreGauge } from './cspm.jsx'
import { CloudEventPanel } from './events.jsx'
import { CAT_META, SEV_BG, SEV_BORDER, SEV_COLOR, riskLabel, riskScore } from './shared.jsx'

// ── Panel: Overview ───────────────────────────────────────────────────────────
function ScanTrend({ connId, refreshKey }) {
  const [pts, setPts] = useState([])
  useEffect(() => {
    let live = true
    api.get(`/api/v1/cloud-connectors/${connId}/cspm/history?days=90`)
      .then(r => { if (live) setPts(r.data?.points || []) }).catch(() => {})
    return () => { live = false }
  }, [connId, refreshKey])
  if (pts.length < 2) return null
  const w = 220, h = 38
  const vals = pts.map(p => p.critical + p.high)
  const max = Math.max(...vals, 1)
  const path = vals.map((v, i) => `${(i / (vals.length - 1)) * w},${h - (v / max) * (h - 4) - 2}`).join(' ')
  const first = vals[0], last = vals[vals.length - 1]
  const delta = last - first
  return (
    <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:16, fontSize:11, color:'var(--text3)' }}>
      <svg width={w} height={h} role="img" aria-label="Critical and high findings over time">
        <polyline fill="none" stroke="#f87171" strokeWidth="1.5" points={path}/>
      </svg>
      <div>
        Critical + high over {pts.length} scans: <span style={{ color:'var(--text)' }}>{first} → {last}</span>
        {' '}<span style={{ color: delta > 0 ? '#f87171' : delta < 0 ? '#34d399' : 'var(--text3)' }}>
          {delta > 0 ? `▲ ${delta}` : delta < 0 ? `▼ ${-delta}` : 'no change'}
        </span>
      </div>
    </div>
  )
}

export function PanelOverview({ conn, cspm, loading, onRunScan, scanning, onTabChange }) {
  const [aiSummary, setAiSummary] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [showErrors, setShowErrors] = useState(false)
  const score  = riskScore(cspm)
  const rl     = riskLabel(score)
  const all    = cspm?.findings || []

  const runAI = async () => {
    if (!cspm || aiLoading) return
    setAiLoading(true)
    try {
      const compact = {
        project: cspm.project_id,
        critical: cspm.critical, high: cspm.high, medium: cspm.medium, low: cspm.low, passed: cspm.passed,
        top_findings: all.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0,12)
          .map(f => ({ sev: f.severity, cat: f.category, title: f.title }))
      }
      const providerName = conn?.provider === 'azure' ? 'Azure' : 'GCP'
      const complianceNote = conn?.provider === 'azure' ? 'CIS Azure benchmark note' : 'CIS GCP benchmark note'
      const prompt = `You are a ${providerName} cloud security architect. Analyse this CSPM scan and return ONLY this JSON (no markdown):\n{"executive_summary":"2-3 sentences for a CISO","top_risks":["risk 1","risk 2","risk 3"],"immediate_actions":["action 1","action 2","action 3"],"compliance_notes":"brief ${complianceNote}","positive_findings":["what is correct"]}\n\nData: ${JSON.stringify(compact)}`
      const { data } = await api.post('/api/v1/cloud-connectors/ai-explain', { prompt })
      const text = data.content?.find(b => b.type === 'text')?.text || data.text || ''
      const clean = text.replace(/```json\n?|```/g, '').trim()
      try { setAiSummary(JSON.parse(clean)) } catch { setAiSummary({ executive_summary: clean }) }
    } catch { setAiSummary({ executive_summary: 'AI summary unavailable.' }) }
    finally { setAiLoading(false) }
  }

  const requiredRoles = {
    // GCP checks
    kms:              'roles/cloudkms.viewer + enable cloudkms.googleapis.com',
    vpc_flow_logs:    'roles/compute.networkViewer',
    dns_logging:      'roles/dns.reader + enable dns.googleapis.com',
    scc:              'roles/securitycenter.findingsViewer + enable securitycenter.googleapis.com',
    gke:              'roles/container.viewer + enable container.googleapis.com',
    bigquery:         'roles/bigquery.metadataViewer + enable bigquery.googleapis.com',
    secret_manager:   'roles/secretmanager.viewer + enable secretmanager.googleapis.com',
    org_policies:     'roles/orgpolicy.policyViewer',
    cloud_run:        'roles/run.viewer + enable run.googleapis.com',
    artifact_registry:'roles/artifactregistry.reader + enable artifactregistry.googleapis.com',
    cloud_functions:  'roles/cloudfunctions.viewer + enable cloudfunctions.googleapis.com',
    pubsub:           'roles/pubsub.viewer + enable pubsub.googleapis.com',
    org_iam:          'roles/resourcemanager.organizationViewer (auto when SCC enabled)',
    // Azure checks
    app_service:        'Microsoft.Web/sites/read  (Reader role)',
    container_registry: 'Microsoft.ContainerRegistry/registries/read  (Reader role)',
    functions:          'Microsoft.Web/sites/read  (Reader role)',
    sql_advanced:       'Microsoft.Sql/servers/read + Microsoft.Sql/servers/advancedThreatProtectionSettings/read',
    keyvault:           'Microsoft.KeyVault/vaults/read  (Reader role)',
    sql:                'Microsoft.Sql/servers/read  (Reader role)',
    aks:                'Microsoft.ContainerService/managedClusters/read  (Reader role)',
    defender:           'Microsoft.Security/pricings/read  (Security Reader role)',
    entra:              'AuditLog.Read.All + Policy.Read.All  (Graph API permissions)',
  }

  const catBars = Object.entries(
    all.reduce((acc, f) => { acc[f.category] = (acc[f.category]||0) + 1; return acc }, {})
  ).sort((a,b) => b[1]-a[1]).slice(0,6)
  const maxCat = catBars[0]?.[1] || 1

  const isAzure = conn?.provider === 'azure'
  const compChecks = isAzure ? [
    { name: 'CIS Azure 2.0', cats: ['iam','network','storage','compute','sql','logging','kms'], color: '#38bdf8' },
    { name: 'NIST CSF',      cats: ['iam','network','logging','kms'],                           color: '#34d399' },
    { name: 'PCI DSS',       cats: ['network','compute','logging'],                             color: '#fb923c' },
    { name: 'SOC 2',         cats: ['logging','iam','network'],                                 color: '#a78bfa' },
  ] : [
    { name: 'CIS GCP 1.3', cats: ['iam','network','storage','compute','sql','logging','kms'], color: '#34d399' },
    { name: 'NIST CSF',    cats: ['iam','network','logging','kms'],                           color: '#38bdf8' },
    { name: 'PCI DSS',     cats: ['network','compute','logging'],                             color: '#fb923c' },
    { name: 'SOC 2',       cats: ['logging','iam','network'],                                 color: '#a78bfa' },
  ]

  return (
    <div style={{ height:'100%', overflow:'auto', padding:'20px 24px', background:'var(--bg)' }}>

      <ScanTrend connId={conn.id} refreshKey={cspm?.scanned_at}/>

      {/* ── Top action bar ── */}
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:20 }}>
        <div>
          <div style={{ fontSize:14, fontWeight:700, color:'var(--text)' }}>
            {cspm?.project_id || cspm?.subscription_id || conn.account_id || (conn.provider === 'azure' ? 'Azure Subscription' : 'GCP Project')}
          </div>
          {cspm && <div style={{ fontSize:11, color:'var(--text3)', marginTop:2 }}>
            Last scan: {cspm.scanned_at ? format(new Date(cspm.scanned_at), 'MMM d, yyyy HH:mm') : '—'}
            {' · '}{cspm.scan_duration || ''}
            {cspm.scc_enabled && <span style={{ color:'#34d399', marginLeft:8 }}>✓ SCC ({cspm.scc_findings||0} findings)</span>}
            {cspm.defender_enabled && <span style={{ color:'#38bdf8', marginLeft:8 }}>✓ Defender ({cspm.defender_findings||0} findings)</span>}
          </div>}
        </div>
        <div style={{ display:'flex', gap:8 }}>
          {cspm && (
            <button onClick={runAI} disabled={aiLoading}
              style={{ display:'flex', alignItems:'center', gap:6, fontSize:11.5, padding:'7px 14px',
                background:'rgba(139,92,246,0.1)', border:'1px solid rgba(139,92,246,0.3)',
                color:'#a78bfa', borderRadius:8, cursor: aiLoading ? 'wait':'pointer', fontFamily:'inherit', fontWeight:600 }}>
              <Sparkles size={12}/>{aiLoading ? 'Analysing…' : 'AI Summary'}
            </button>
          )}
          <button onClick={onRunScan} disabled={scanning}
            style={{ display:'flex', alignItems:'center', gap:6, fontSize:11.5, padding:'7px 14px',
              background: scanning ? 'var(--surface2)' : 'var(--accent)',
              color: scanning ? 'var(--text2)' : '#000',
              border:'none', borderRadius:8, cursor: scanning?'wait':'pointer', fontFamily:'inherit', fontWeight:700 }}>
            <RefreshCw size={12} style={scanning ? { animation:'spin 0.8s linear infinite' } : {}}/>
            {scanning ? 'Scanning…' : 'Run Scan'}
          </button>
        </div>
      </div>

      {loading && (
        <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:200, color:'var(--text3)', gap:8 }}>
          <RefreshCw size={16} style={{ animation:'spin 0.8s linear infinite' }}/> Loading…
        </div>
      )}

      {!loading && !cspm && !scanning && (
        <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', height:260, gap:12 }}>
          <Shield size={44} color="var(--border)" strokeWidth={1}/>
          <div style={{ fontSize:14, fontWeight:600, color:'var(--text2)' }}>No scan results yet</div>
          <div style={{ fontSize:12, color:'var(--text3)' }}>Click "Run Scan" to assess your cloud security posture</div>
        </div>
      )}

      {cspm && !loading && (<>

        {/* ── Scan errors ── */}
        {cspm.errors?.length > 0 && (
          <div style={{ marginBottom:16 }}>
            <button onClick={() => setShowErrors(e => !e)}
              style={{ display:'flex', alignItems:'center', gap:6, fontSize:11, padding:'6px 12px',
                background:'rgba(251,146,60,0.08)', border:'1px solid rgba(251,146,60,0.25)',
                color:'#fb923c', borderRadius:7, cursor:'pointer', fontFamily:'inherit' }}>
              <AlertTriangle size={11}/>{cspm.errors.length} check{cspm.errors.length>1?'s':''} failed — {showErrors?'hide':'show'}
            </button>
            {showErrors && (
              <div style={{ marginTop:8, background:'var(--surface)', border:'1px solid rgba(251,146,60,0.2)', borderRadius:8, overflow:'hidden' }}>
                {cspm.errors.map((err, i) => {
                  const name = err.split(':')[0]
                  const msg  = err.slice(name.length+1).trim()
                  return (
                    <div key={i} style={{ padding:'10px 14px', borderBottom: i < cspm.errors.length-1 ? '1px solid var(--border)':'none' }}>
                      <div style={{ display:'flex', gap:8, alignItems:'center', marginBottom:3 }}>
                        <code style={{ fontSize:10.5, background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:4, padding:'1px 6px', color:'#fb923c', fontFamily:'DM Mono,monospace' }}>{name}</code>
                      </div>
                      <div style={{ fontSize:10.5, color:'var(--text3)', fontFamily:'DM Mono,monospace', wordBreak:'break-all', marginBottom: requiredRoles[name] ? 5 : 0 }}>{msg.slice(0,180)}</div>
                      {requiredRoles[name] && (
                        <div style={{ fontSize:10.5 }}><span style={{ color:'#34d399', fontWeight:600 }}>Fix: </span>
                          <code style={{ color:'var(--text2)', fontFamily:'DM Mono,monospace', background:'var(--surface2)', padding:'1px 6px', borderRadius:4 }}>{requiredRoles[name]}</code>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}

        {/* ── Hero row: score + KPIs ── */}
        <div style={{ display:'grid', gridTemplateColumns:'180px 1fr', gap:16, marginBottom:16 }}>
          {/* Risk gauge */}
          <div style={{ background:'var(--surface)', border:`1px solid var(--border)`, borderRadius:14,
            padding:'20px 16px', display:'flex', flexDirection:'column', alignItems:'center', gap:10,
            borderTop:`3px solid ${rl.color}` }}>
            <RiskScoreGauge score={score}/>
            <div style={{ fontSize:10, color:'var(--text3)', textAlign:'center', lineHeight:1.4 }}>
              <span style={{ fontSize:13, fontWeight:700, color:rl.color, display:'block' }}>{rl.label}</span>
              Risk Score
            </div>
            {cspm.scc_enabled && (
              <div style={{ display:'flex', alignItems:'center', gap:5, fontSize:10 }}>
                <span style={{ width:6, height:6, borderRadius:'50%', background:'#34d399', display:'inline-block' }}/>
                <span style={{ color:'#34d399' }}>SCC Active</span>
              </div>
            )}
          </div>

          {/* KPI grid */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:8 }}>
            {[
              { label:'Critical', value: cspm.critical,        color:'#f87171',       bg:'rgba(248,113,113,0.08)',  tab:'deepdive' },
              { label:'High',     value: cspm.high,            color:'#fb923c',        bg:'rgba(251,146,60,0.08)',   tab:'deepdive' },
              { label:'Medium',   value: cspm.medium,          color:'#fbbf24',        bg:'rgba(251,191,36,0.08)',   tab:'deepdive' },
              { label:'Low',      value: cspm.low,             color:'#38bdf8',        bg:'rgba(56,189,248,0.08)',   tab:'deepdive' },
              { label:'Passed',   value: cspm.passed,          color:'#34d399',        bg:'rgba(52,211,153,0.08)',   tab:null },
              { label:'Assets',   value: [...new Set((cspm.findings||[]).map(f=>f.resource).filter(Boolean))].length, color:'var(--text2)', bg:'var(--surface)', tab:'assets' },
            ].map(k => (
              <div key={k.label} onClick={() => k.tab && onTabChange?.(k.tab)}
                style={{ background:k.bg, border:'1px solid var(--border)',
                  borderRadius:10, padding:'12px 14px', borderLeft:`3px solid ${k.color}`,
                  cursor: k.tab ? 'pointer' : 'default',
                  transition:'opacity 0.15s',
                }}
                onMouseEnter={e => { if (k.tab) e.currentTarget.style.opacity='0.8' }}
                onMouseLeave={e => { e.currentTarget.style.opacity='1' }}
              >
                <div style={{ fontSize:9.5, color:'var(--text3)', fontWeight:700, textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:5 }}>
                  {k.label}{k.tab && <span style={{ marginLeft:4, opacity:0.5 }}>↗</span>}
                </div>
                <div style={{ fontSize:24, fontWeight:800, color:k.color, fontFamily:'DM Mono,monospace', lineHeight:1 }}>{k.value||0}</div>
              </div>
            ))}
          </div>
        </div>

        {/* ── AI Summary ── */}
        {aiSummary && (
          <div style={{ background:'rgba(139,92,246,0.06)', border:'1px solid rgba(139,92,246,0.2)', borderRadius:12, padding:'16px 18px', marginBottom:16 }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:10 }}>
              <div style={{ fontSize:10, fontWeight:700, color:'#a78bfa', textTransform:'uppercase', letterSpacing:'0.06em' }}>✦ AI Executive Summary</div>
              <button onClick={() => setAiSummary(null)} style={{ background:'none', border:'none', color:'var(--text3)', cursor:'pointer', padding:0 }}><X size={13}/></button>
            </div>
            {aiSummary.executive_summary && <p style={{ fontSize:12.5, color:'var(--text)', lineHeight:1.75, marginBottom:12 }}>{aiSummary.executive_summary}</p>}
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:14 }}>
              {aiSummary.top_risks?.length > 0 && (
                <div>
                  <div style={{ fontSize:10, color:'#f87171', fontWeight:700, marginBottom:6 }}>⚠ Top Risks</div>
                  {aiSummary.top_risks.map((r,i) => <div key={i} style={{ fontSize:11, color:'var(--text2)', marginBottom:4, lineHeight:1.5 }}>· {r}</div>)}
                </div>
              )}
              {aiSummary.immediate_actions?.length > 0 && (
                <div>
                  <div style={{ fontSize:10, color:'#34d399', fontWeight:700, marginBottom:6 }}>✓ Immediate Actions</div>
                  {aiSummary.immediate_actions.map((a,i) => <div key={i} style={{ fontSize:11, color:'var(--text2)', marginBottom:4, lineHeight:1.5 }}>· {a}</div>)}
                </div>
              )}
              {aiSummary.positive_findings?.length > 0 && (
                <div>
                  <div style={{ fontSize:10, color:'#38bdf8', fontWeight:700, marginBottom:6 }}>✦ Doing Well</div>
                  {aiSummary.positive_findings.map((p,i) => <div key={i} style={{ fontSize:11, color:'var(--text2)', marginBottom:4, lineHeight:1.5 }}>· {p}</div>)}
                </div>
              )}
            </div>
            {aiSummary.compliance_notes && (
              <div style={{ marginTop:10, fontSize:11, color:'var(--text3)', fontStyle:'italic', borderTop:'1px solid rgba(139,92,246,0.15)', paddingTop:10 }}>{aiSummary.compliance_notes}</div>
            )}
          </div>
        )}

        {/* ── Bottom row: category breakdown + compliance ── */}
        <div style={{ display:'grid', gridTemplateColumns:'1fr 260px', gap:16 }}>

          {/* Category bar chart */}
          <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:'16px 18px' }}>
            <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:14 }}>Findings by Category</div>
            {catBars.length === 0
              ? <div style={{ fontSize:12, color:'var(--text3)', textAlign:'center', padding:'24px 0' }}>No findings</div>
              : catBars.map(([cat, count]) => (
                <div key={cat} style={{ marginBottom:10, cursor:'pointer' }}
                  onClick={() => onTabChange?.('deepdive')}
                  onMouseEnter={e => e.currentTarget.style.opacity='0.75'}
                  onMouseLeave={e => e.currentTarget.style.opacity='1'}
                >
                  <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:6, fontSize:11.5, color:'var(--text2)' }}>
                      {CAT_META[cat]?.icon && (() => { const Icon = CAT_META[cat].icon; return <Icon size={11} color={CAT_META[cat].color}/>; })()}
                      {CAT_META[cat]?.label || cat}
                    </div>
                    <span style={{ fontSize:11, fontFamily:'DM Mono,monospace', color:'var(--text3)' }}>{count} ↗</span>
                  </div>
                  <div style={{ height:5, background:'var(--surface2)', borderRadius:4, overflow:'hidden' }}>
                    <div style={{ height:'100%', borderRadius:4, width:`${(count/maxCat)*100}%`,
                      background: CAT_META[cat]?.color || 'var(--accent)', transition:'width 0.6s ease' }}/>
                  </div>
                </div>
              ))
            }
          </div>

          {/* Compliance status */}
          <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:'16px 18px' }}>
            <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:14 }}>Compliance Posture</div>
            {compChecks.map(({ name, cats, color }) => {
              // Count findings (fail) and passed checks in the relevant categories
              const failFindings = all.filter(f => cats.includes(f.category))
              const fail = failFindings.length
              // Use actual passed count proportionally if available, otherwise estimate
              const totalChecks = fail + Math.round((cspm.passed || 0) * (cats.length / 7))
              const pct = totalChecks === 0 ? 0 : Math.max(0, Math.min(100, Math.round(((totalChecks - fail) / totalChecks) * 100)))
              return (
                <div key={name} style={{ marginBottom:12, cursor:'pointer' }}
                  onClick={() => onTabChange?.('deepdive')}
                  onMouseEnter={e => e.currentTarget.style.opacity='0.75'}
                  onMouseLeave={e => e.currentTarget.style.opacity='1'}
                >
                  <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
                    <span style={{ fontSize:11, color:'var(--text2)' }}>{name}</span>
                    <span style={{ fontSize:11, fontFamily:'DM Mono,monospace', color }}>{pct}% ↗</span>
                  </div>
                  <div style={{ height:5, background:'var(--surface2)', borderRadius:4, overflow:'hidden' }}>
                    <div style={{ height:'100%', borderRadius:4, width:`${pct}%`, background:color, transition:'width 0.6s ease' }}/>
                  </div>
                </div>
              )
            })}
            <div style={{ marginTop:14, paddingTop:12, borderTop:'1px solid var(--border)' }}>
              {conn?.provider === 'azure' ? (<>
                <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>Microsoft Defender for Cloud</div>
                {cspm.defender_enabled
                  ? <div style={{ display:'flex', alignItems:'center', gap:6, fontSize:11 }}>
                      <span style={{ width:7, height:7, borderRadius:'50%', background:'#34d399', display:'inline-block' }}/>
                      <span style={{ color:'#34d399', fontWeight:600 }}>Active</span>
                      <span style={{ color:'var(--text3)' }}>· {cspm.defender_findings||0} findings</span>
                    </div>
                  : <div style={{ fontSize:11, color:'var(--text3)' }}>
                      Plans on Free tier ·{' '}
                      <a href="https://portal.azure.com/#view/Microsoft_Azure_Security" target="_blank" rel="noopener noreferrer"
                        style={{ color:'var(--accent)', textDecoration:'none' }}>Upgrade Defender →</a>
                    </div>
                }
              </>) : (<>
                <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>Security Command Center</div>
                {cspm.scc_enabled
                  ? <div style={{ display:'flex', alignItems:'center', gap:6, fontSize:11 }}>
                      <span style={{ width:7, height:7, borderRadius:'50%', background:'#34d399', display:'inline-block' }}/>
                      <span style={{ color:'#34d399', fontWeight:600 }}>Connected</span>
                      <span style={{ color:'var(--text3)' }}>· {cspm.scc_findings||0} findings</span>
                    </div>
                  : <div style={{ fontSize:11, color:'var(--text3)' }}>
                      Not enabled ·{' '}
                      <a href="https://console.cloud.google.com/security/command-center" target="_blank" rel="noopener noreferrer"
                        style={{ color:'var(--accent)', textDecoration:'none' }}>Enable SCC →</a>
                    </div>
                }
              </>)}
            </div>
          </div>
        </div>
      </>)}
    </div>
  )
}

// ── Panel: Asset Graph ────────────────────────────────────────────────────────
export function PanelAssetGraph({ cspm, cmdbAssets, cmdbLoading, onRunCMDB, conn }) {
  const [selected, setSelected] = useState(null)
  const [viewMode, setViewMode] = useState('all') // all | findings | clean
  const all = cspm?.findings || []

  // Build asset nodes — prefer CMDB data, fall back to findings
  const assetMap = {}

  // If we have CMDB data, seed all resources (even clean ones)
  if (cmdbAssets?.assets) {
    for (const a of cmdbAssets.assets) {
      const shortName = a.short_name || a.name?.split('/').pop() || a.name
      const typeKey = a.asset_type?.split('/')?.pop()?.toLowerCase().replace(/\s/g,'_') || 'resource'
      assetMap[a.name] = {
        id: a.name,
        shortName,
        type: typeKey,
        findings: [],
        category: 'clean',
        location: a.location,
        firstSeen: a.first_seen,
        isClean: true,
      }
    }
  }

  // Overlay findings from CSPM
  for (const f of all) {
    if (!f.resource) continue
    const key = f.resource
    if (!assetMap[key]) {
      assetMap[key] = { id: key, shortName: f.resource.split('/').pop() || f.resource,
        type: f.resource_type || 'resource', findings: [], category: f.category, isClean: false }
    }
    assetMap[key].findings.push(f)
    assetMap[key].isClean = false
    assetMap[key].category = f.category
  }

  const allAssets = Object.values(assetMap)
  const assets = allAssets.filter(a => {
    if (viewMode === 'findings') return !a.isClean
    if (viewMode === 'clean') return a.isClean
    return true
  })

  // Group by resource type
  const groups = assets.reduce((acc, a) => {
    const g = a.type || 'other'
    ;(acc[g] = acc[g] || []).push(a)
    return acc
  }, {})

  const typeIcons = {
    // GCP
    firewall_rule: Wifi, iam_binding: Lock, gcs_bucket: HardDrive, storage_bucket: HardDrive, compute_instance: Cpu,
    cloud_sql: Database, service_account: Key, service_account_key: Key, kms_key: Key,
    vpc_subnet: Wifi, dns_policy: Globe, gke_cluster: Server, gke_node_pool: Server,
    bigquery_dataset: Database, secret: HardDrive, org_policy: Shield, audit_config: FileText, resource: Server,
    // Azure
    nsg: Wifi, storage_account: HardDrive, virtual_machine: Cpu, sql_server: Database, sql_database: Database,
    key_vault: Key, aks_cluster: Server, role_assignment: Lock, classic_admin: Lock, entra_tenant: Lock,
    diagnostic_setting: FileText, defender_plan: Shield, application_gateway: Globe,
    app_service: Zap, function_app: Zap, container_registry: HardDrive,
  }
  const typeLabels = {
    // GCP
    firewall_rule:'Firewall Rules', iam_binding:'IAM Bindings', gcs_bucket:'Storage Buckets', storage_bucket:'Storage Buckets',
    compute_instance:'Compute VMs', cloud_sql:'Cloud SQL', service_account:'Service Accounts',
    service_account_key:'SA Keys', kms_key:'KMS Keys', vpc_subnet:'VPC Subnets',
    dns_policy:'DNS Policies', gke_cluster:'GKE Clusters', gke_node_pool:'Node Pools',
    bigquery_dataset:'BigQuery', secret:'Secrets', org_policy:'Org Policies', audit_config:'Audit Configs', resource:'Resources',
    // Azure
    nsg:'Network Security Groups', storage_account:'Storage Accounts', virtual_machine:'Virtual Machines',
    sql_server:'SQL Servers', sql_database:'SQL Databases', key_vault:'Key Vaults',
    aks_cluster:'AKS Clusters', role_assignment:'Role Assignments', classic_admin:'Classic Admins',
    entra_tenant:'Entra ID', diagnostic_setting:'Diagnostic Settings', defender_plan:'Defender Plans',
    application_gateway:'App Gateways', app_service:'App Services', function_app:'Function Apps',
    container_registry:'Container Registries',
  }

  const worstSev = (asset) => {
    const order = ['critical','high','medium','low','info']
    for (const s of order) if (asset.findings.some(f => f.severity === s)) return s
    return 'low'
  }

  const selAsset = assets.find(a => a.id === selected)

  return (
    <div style={{ height:'100%', display:'flex', overflow:'hidden' }}>
      {/* Left: grouped asset list */}
      <div style={{ flex:1, overflow:'auto', padding:'20px 18px' }}>
        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:4 }}>
          <div style={{ fontSize:13, fontWeight:700, color:'var(--text)' }}>Asset Inventory</div>
          {(conn?.provider === 'gcp' || conn?.provider === 'azure') && (
            <button onClick={onRunCMDB} disabled={cmdbLoading}
              style={{ display:'flex', alignItems:'center', gap:5, fontSize:10.5, padding:'5px 10px',
                background:'rgba(0,194,224,0.08)', border:'1px solid rgba(0,194,224,0.2)',
                color:'var(--accent)', borderRadius:6, cursor:cmdbLoading?'wait':'pointer', fontFamily:'inherit' }}>
              <RefreshCw size={10} style={cmdbLoading ? {animation:'spin 0.8s linear infinite'} : {}}/> 
              {cmdbLoading ? 'Scanning…' : 'Full Inventory'}
            </button>
          )}
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:12, marginTop:6 }}>
          <div style={{ fontSize:11, color:'var(--text3)', flex:1 }}>
            {cmdbAssets ? (
              <span>{cmdbAssets.total_assets} total resources · {allAssets.filter(a=>!a.isClean).length} with findings</span>
            ) : (
              <span>{assets.length} resources with findings · click any asset to explore</span>
            )}
          </div>
          {cmdbAssets && (
            <div style={{ display:'flex', gap:4 }}>
              {[['all','All'],['findings','Issues'],['clean','Clean']].map(([v,l]) => (
                <button key={v} onClick={()=>setViewMode(v)}
                  style={{ fontSize:10, padding:'3px 8px', borderRadius:5, cursor:'pointer', fontFamily:'inherit',
                    background: viewMode===v ? 'rgba(0,194,224,0.1)' : 'transparent',
                    border: `1px solid ${viewMode===v ? 'rgba(0,194,224,0.3)' : 'var(--border)'}`,
                    color: viewMode===v ? 'var(--accent)' : 'var(--text3)', fontWeight: viewMode===v?600:400 }}>{l}</button>
              ))}
            </div>
          )}
        </div>

        {assets.length === 0 && !cmdbLoading && (
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', height:200, color:'var(--text3)', gap:8 }}>
            <Layers size={36} strokeWidth={1} color="var(--border)"/>
            <div style={{ fontSize:13 }}>{cmdbAssets ? 'No assets match this filter' : 'Run a scan or Full Inventory to populate'}</div>
            {!cmdbAssets && (conn?.provider === 'gcp' || conn?.provider === 'azure') && (
              <button onClick={onRunCMDB} style={{ fontSize:11, padding:'6px 14px', borderRadius:7, cursor:'pointer', fontFamily:'inherit',
                background:'rgba(0,194,224,0.08)', border:'1px solid rgba(0,194,224,0.2)', color:'var(--accent)' }}>
                Run Full Inventory
              </button>
            )}
          </div>
        )}

        {Object.entries(groups).sort((a,b) => b[1].length - a[1].length).map(([type, items]) => {
          const TypeIcon = typeIcons[type] || Server
          return (
            <div key={type} style={{ marginBottom:20 }}>
              <div style={{ display:'flex', alignItems:'center', gap:7, marginBottom:8, paddingBottom:6, borderBottom:'1px solid var(--border)' }}>
                <TypeIcon size={12} color="var(--text3)"/>
                <span style={{ fontSize:10.5, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.07em' }}>
                  {typeLabels[type] || type}
                </span>
                <span style={{ fontSize:10, background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:10, padding:'0 6px', color:'var(--text3)' }}>
                  {items.length}
                </span>
              </div>
              <div style={{ display:'flex', flexDirection:'column', gap:4 }}>
                {items.map(asset => {
                  const sev = worstSev(asset)
                  const isSelected = selected === asset.id
                  return (
                    <button key={asset.id} onClick={() => setSelected(isSelected ? null : asset.id)}
                      style={{ display:'flex', alignItems:'center', gap:10, padding:'9px 12px',
                        background: isSelected ? 'rgba(0,194,224,0.08)' : 'var(--surface)',
                        border: `1px solid ${isSelected ? 'var(--accent)' : 'var(--border)'}`,
                        borderLeft: `3px solid ${asset.isClean ? '#34d399' : (SEV_COLOR[sev] || 'var(--border)')}`,
                        borderRadius:8, cursor:'pointer', textAlign:'left', fontFamily:'inherit',
                        width:'100%', transition:'all 0.15s' }}>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ fontSize:11.5, color:'var(--text)', fontFamily:'DM Mono,monospace', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>
                          {asset.shortName || asset.id}
                        </div>
                        <div style={{ fontSize:10, color:'var(--text3)', marginTop:2 }}>
                          {asset.isClean
                            ? <span style={{ color:'#34d399' }}>✓ Clean</span>
                            : <>{asset.findings.length} finding{asset.findings.length!==1?'s':''} · {asset.category}</>
                          }
                          {asset.location && <span style={{ marginLeft:6, opacity:0.6 }}>{asset.location}</span>}
                        </div>
                      </div>
                      <div style={{ display:'flex', gap:4, flexShrink:0 }}>
                        {!asset.isClean && ['critical','high','medium'].map(s => {
                          const n = asset.findings.filter(f => f.severity===s).length
                          if (!n) return null
                          return <span key={s} style={{ fontSize:9.5, background:SEV_BG[s], color:SEV_COLOR[s],
                            border:`1px solid ${SEV_BORDER[s]}`, borderRadius:10, padding:'1px 6px', fontFamily:'DM Mono,monospace' }}>{n}</span>
                        })}
                        {asset.isClean && <span style={{ fontSize:9.5, color:'#34d399', opacity:0.6 }}>✓</span>}
                      </div>
                      <ChevronRight size={11} color="var(--text3)" style={{ flexShrink:0, transform: isSelected ? 'rotate(90deg)' : 'none', transition:'transform 0.15s' }}/>
                    </button>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>

      {/* Right: detail panel */}
      {selAsset && (
        <div style={{ width:340, flexShrink:0, borderLeft:'1px solid var(--border)', overflow:'auto', padding:'20px 18px', background:'var(--surface)' }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:14 }}>
            <div>
              <div style={{ fontSize:11, color:'var(--text3)', marginBottom:4, fontFamily:'DM Mono,monospace', wordBreak:'break-all' }}>{selAsset.id}</div>
              <div style={{ fontSize:10, color:'var(--text3)' }}>{typeLabels[selAsset.type] || selAsset.type}</div>
            </div>
            <button onClick={() => setSelected(null)} style={{ background:'none', border:'none', color:'var(--text3)', cursor:'pointer', padding:0, flexShrink:0 }}>
              <X size={14}/>
            </button>
          </div>
          <div style={{ display:'flex', gap:6, flexWrap:'wrap', marginBottom:14 }}>
            {['critical','high','medium','low'].map(s => {
              const n = selAsset.findings.filter(f => f.severity===s).length
              if (!n) return null
              return <span key={s} style={{ fontSize:10.5, background:SEV_BG[s], color:SEV_COLOR[s], border:`1px solid ${SEV_BORDER[s]}`, borderRadius:6, padding:'2px 8px' }}>{n} {s}</span>
            })}
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
            {selAsset.findings.map((f, i) => (
              <FindingCard key={f.id||i} f={f} provider={conn?.provider || "gcp"} projectId={cspm?.project_id} subscriptionId={cspm?.subscription_id}/>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Panel: Attack Surface ─────────────────────────────────────────────────────
export function PanelAttackSurface({ cspm, conn }) {
  const all = cspm?.findings || []
  const isAzure = conn?.provider === 'azure'

  const openFW = all.filter(f => f.resource_type === 'firewall_rule' || f.resource_type === 'nsg')
  const publicIPs = all.filter(f =>
    (f.resource_type === 'compute_instance' || f.resource_type === 'virtual_machine') &&
    (f.title.toLowerCase().includes('public') || f.title.toLowerCase().includes('internet'))
  )
  const pubStorage = all.filter(f =>
    (f.resource_type === 'gcs_bucket' || f.resource_type === 'bigquery_dataset' ||
     f.resource_type === 'storage_account' || f.resource_type === 'storage_bucket') &&
    (f.title.toLowerCase().includes('public') || f.title.toLowerCase().includes('alluser'))
  )
  const pubSQL = all.filter(f =>
    (f.resource_type === 'cloud_sql' || f.resource_type === 'sql_server' || f.resource_type === 'sql_database') &&
    (f.title.toLowerCase().includes('public') || f.title.toLowerCase().includes('0.0.0.0'))
  )
  const network = all.filter(f =>
    f.category === 'network' ||
    ['compute_instance','firewall_rule','nsg','application_gateway','virtual_machine'].includes(f.resource_type) ||
    (f.resource_type||'').includes('firewall')
  )

  const surfaceCards = [
    {
      label: isAzure ? 'Open NSG Rules' : 'Open Firewall Rules',
      count: openFW.length, color: '#f87171', icon: Wifi, items: openFW,
      desc: isAzure ? 'NSG rules allowing unrestricted inbound traffic' : 'Firewall rules allowing unrestricted inbound traffic'
    },
    {
      label: isAzure ? 'Exposed VMs' : 'Public IPs',
      count: publicIPs.length, color: '#fb923c', icon: Globe, items: publicIPs,
      desc: isAzure ? 'VMs with internet-accessible ports' : 'Compute instances with external IP addresses'
    },
    {
      label: 'Public Storage',
      count: pubStorage.length, color: '#fbbf24', icon: HardDrive, items: pubStorage,
      desc: isAzure ? 'Storage accounts with public blob access enabled' : 'Storage buckets or datasets accessible without auth'
    },
    {
      label: 'Exposed Databases',
      count: pubSQL.length, color: '#f87171', icon: Database, items: pubSQL,
      desc: isAzure ? 'SQL Servers with public network access enabled' : 'Cloud SQL instances accessible from 0.0.0.0/0'
    },
  ]

  const [expanded, setExpanded] = useState(null)

  return (
    <div style={{ height:'100%', overflow:'auto', padding:'20px 24px', background:'var(--bg)' }}>
      <div style={{ fontSize:13, fontWeight:700, color:'var(--text)', marginBottom:4 }}>Attack Surface</div>
      <div style={{ fontSize:11, color:'var(--text3)', marginBottom:20 }}>
        Resources directly reachable from the internet or with critical network exposure
      </div>

      {all.length === 0 && (
        <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', height:220, color:'var(--text3)', gap:8 }}>
          <Shield size={40} strokeWidth={1} color="var(--border)"/>
          <div style={{ fontSize:13 }}>Run a scan to map your attack surface</div>
        </div>
      )}

      {/* Surface summary cards */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12, marginBottom:24 }}>
        {surfaceCards.map(card => (
          <button key={card.label} onClick={() => setExpanded(expanded===card.label ? null : card.label)}
            style={{ padding:'14px 16px', background: expanded===card.label ? `${card.color}18` : 'var(--surface)',
              border: `1px solid ${expanded===card.label ? card.color+'55' : 'var(--border)'}`,
              borderTop: `3px solid ${card.color}`, borderRadius:10, cursor:'pointer', fontFamily:'inherit', textAlign:'left' }}>
            <div style={{ display:'flex', alignItems:'center', gap:7, marginBottom:8 }}>
              <card.icon size={13} color={card.color}/>
              <span style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em' }}>{card.label}</span>
            </div>
            <div style={{ fontSize:26, fontWeight:800, color: card.count > 0 ? card.color : '#34d399', fontFamily:'DM Mono,monospace', marginBottom:4 }}>{card.count}</div>
            <div style={{ fontSize:10.5, color:'var(--text3)', lineHeight:1.4 }}>{card.count > 0 ? card.desc : 'None detected'}</div>
          </button>
        ))}
      </div>

      {/* Expanded findings */}
      {expanded && (() => {
        const card = surfaceCards.find(c => c.label === expanded)
        return card?.items.length > 0 ? (
          <div style={{ marginBottom:20 }}>
            <div style={{ fontSize:11, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:10 }}>
              {card.label} — {card.items.length} finding{card.items.length!==1?'s':''}
            </div>
            <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
              {card.items.map((f,i) => <FindingCard key={f.id||i} f={f} provider={conn?.provider || "gcp"} projectId={cspm?.project_id} subscriptionId={cspm?.subscription_id}/>)}
            </div>
          </div>
        ) : null
      })()}

      {/* All network/exposure findings when nothing selected */}
      {!expanded && all.length > 0 && (
        <div>
          <div style={{ fontSize:11, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:10 }}>
            All Network & Exposure Findings
          </div>
          {network.length === 0
            ? <div style={{ fontSize:12, color:'#34d399', padding:'20px 0', textAlign:'center' }}>✓ No network exposure findings detected</div>
            : <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                {network.map((f,i) => <FindingCard key={f.id||i} f={f} provider={conn?.provider || "gcp"} projectId={cspm?.project_id} subscriptionId={cspm?.subscription_id}/>)}
              </div>
          }
        </div>
      )}
    </div>
  )
}

// ── Panel: Event Timeline ─────────────────────────────────────────────────────
export function PanelEventTimeline({ events, loading, conn }) {
  const [selected, setSelected] = useState(null)
  const [sevFilter, setSevFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')

  const filtered = events.filter(e => {
    if (sevFilter !== 'all' && String(e.severity) !== sevFilter) return false
    if (typeFilter !== 'all' && e.event_type !== typeFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return JSON.stringify(e).toLowerCase().includes(q)
    }
    return true
  })

  const eventTypes = [...new Set(events.map(e => e.event_type).filter(Boolean))].slice(0,12)
  const SEV_NUM_COLOR = { 5:'#f87171', 4:'#fb923c', 3:'#fbbf24', 2:'#38bdf8', 1:'var(--text3)' }
  const SEV_NUM_LABEL = { 5:'Critical', 4:'High', 3:'Medium', 2:'Low', 1:'Info' }

  // Group events by date
  const byDate = filtered.reduce((acc, e) => {
    const d = e.time ? format(new Date(e.time), 'MMM d, yyyy') : 'Unknown'
    ;(acc[d] = acc[d] || []).push(e)
    return acc
  }, {})

  const selEvent = events.find(e => e.id === selected)

  return (
    <div style={{ height:'100%', display:'flex', overflow:'hidden' }}>
      {/* Timeline list */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
        {/* Filter bar */}
        <div style={{ flexShrink:0, padding:'12px 18px', borderBottom:'1px solid var(--border)', background:'var(--surface)',
          display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
          <div style={{ position:'relative', flex:1, minWidth:180 }}>
            <Search size={11} style={{ position:'absolute', left:9, top:'50%', transform:'translateY(-50%)', color:'var(--text3)' }}/>
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search events…"
              style={{ width:'100%', background:'var(--bg)', border:'1px solid var(--border)', borderRadius:7,
                paddingLeft:28, paddingRight:10, paddingTop:6, paddingBottom:6, fontSize:11.5,
                color:'var(--text)', outline:'none', fontFamily:'inherit', boxSizing:'border-box' }}/>
          </div>
          <div style={{ display:'flex', gap:4 }}>
            {[['all','All'],[5,'Crit'],[4,'High'],[3,'Med'],[2,'Low'],[1,'Info']].map(([v,l]) => (
              <button key={v} onClick={() => setSevFilter(String(v))}
                style={{ fontSize:10.5, padding:'4px 9px', borderRadius:6, cursor:'pointer', fontFamily:'inherit',
                  background: String(sevFilter)===String(v) ? (SEV_BG[v]||'rgba(0,194,224,0.1)') : 'var(--surface)',
                  border: `1px solid ${String(sevFilter)===String(v) ? (SEV_BORDER[v]||'rgba(0,194,224,0.3)') : 'var(--border)'}`,
                  color: String(sevFilter)===String(v) ? (SEV_COLOR[v]||'var(--accent)') : 'var(--text3)',
                  fontWeight: String(sevFilter)===String(v) ? 600 : 400 }}>{l}</button>
            ))}
          </div>
          {eventTypes.length > 0 && (
            <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
              style={{ fontSize:11, padding:'5px 8px', background:'var(--surface)', border:'1px solid var(--border)',
                borderRadius:6, color:'var(--text2)', outline:'none', fontFamily:'inherit' }}>
              <option value="all">All types</option>
              {eventTypes.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          )}
          <span style={{ fontSize:10.5, color:'var(--text3)', marginLeft:'auto' }}>{filtered.length} events</span>
        </div>

        {/* Timeline */}
        <div style={{ flex:1, overflow:'auto', padding:'16px 18px' }}>
          {loading && (
            <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:160, color:'var(--text3)', gap:8 }}>
              <RefreshCw size={14} style={{ animation:'spin 0.8s linear infinite' }}/> Loading events…
            </div>
          )}
          {!loading && filtered.length === 0 && (
            <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', height:200, color:'var(--text3)', gap:8 }}>
              <Activity size={36} strokeWidth={1} color="var(--border)"/>
              <div style={{ fontSize:13 }}>{events.length === 0 ? 'No events ingested yet — sync the connector' : 'No events match your filter'}</div>
            </div>
          )}
          {Object.entries(byDate).map(([date, dayEvents]) => (
            <div key={date} style={{ marginBottom:20 }}>
              <div style={{ fontSize:10.5, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.07em',
                marginBottom:8, paddingBottom:6, borderBottom:'1px solid var(--border)' }}>
                {date} · {dayEvents.length} event{dayEvents.length!==1?'s':''}
              </div>
              <div style={{ position:'relative' }}>
                {/* Timeline spine */}
                <div style={{ position:'absolute', left:11, top:8, bottom:8, width:1, background:'var(--border)' }}/>
                <div style={{ display:'flex', flexDirection:'column', gap:4 }}>
                  {dayEvents.map((ev, i) => {
                    const sevColor = SEV_NUM_COLOR[ev.severity] || 'var(--text3)'
                    const isSelected = selected === ev.id
                    let raw = {}
                    try { raw = typeof ev.raw === 'string' ? JSON.parse(ev.raw) : (ev.raw || {}) } catch {}
                    const method = raw.method_name || ''
                    const principal = ev.user_name || raw.principal || ''
                    // Friendly display for extended log types
                    const TYPE_LABELS = {
                      'cloud.gcp_vpc_flow': `VPC Flow · ${raw.src_ip||''} → ${raw.dst_ip||''} ${raw.disposition ? `(${raw.disposition})` : ''}`.trim(),
                      'cloud.gcp_dns': `DNS Query · ${raw.query_name||''} ${raw.query_type ? `[${raw.query_type}]` : ''} ${raw.response_code||''}`.trim(),
                      'cloud.gcp_ids': `IDS · ${raw.threat_name||raw.threat_type||''} ${raw.category||''}`.trim(),
                      'cloud.gcp_cloud_run': `Cloud Run · ${raw.service_name||''} ${raw.method||''} ${raw.status ? `[${raw.status}]` : ''} ${raw.remote_ip||''}`.trim(),
                      'cloud.gcp_gke_audit': `GKE · ${raw.method_name||''} ${raw.resource_name ? raw.resource_name.split('/').pop() : ''}`.trim(),
                      'cloud.gcp_correlation': ev.description?.split('\n')[0] || 'Correlation Alert',
                      'cloud.gcp_anomaly': ev.description?.split('\n')[0] || 'Anomaly Alert',
                      'cloud.gcp_assets': 'Asset Inventory Event',
                      'cloud.azure_defender': `Defender · ${raw.display_name||raw.alert_type||''} ${raw.severity ? `[${raw.severity}]` : ''}`.trim(),
                      'cloud.entra_audit':    `Entra Audit · ${raw.activity||raw.activity_display_name||''}`.trim(),
                      'cloud.azure_nsg_flow': `NSG Flow · ${raw.nsg_name||''} ${raw.disposition||''}`.trim(),
                      'cloud.azure_correlation': ev.description?.split('\n')[0] || 'Azure Correlation',
                      'cloud.azure_anomaly': ev.description?.split('\n')[0] || 'Azure Anomaly',
                      'cloud.aws_anomaly': ev.description?.split('\n')[0] || 'AWS Anomaly',
                    }
                    const displayTitle = method || TYPE_LABELS[ev.event_type] || ev.event_type || 'Cloud Event'
                    const sourceTag = {
                      'cloud.gcp_vpc_flow':      { label:'VPC Flow',  color:'#38bdf8' },
                      'cloud.gcp_dns':            { label:'DNS',       color:'#a78bfa' },
                      'cloud.gcp_ids':            { label:'IDS',       color:'#f87171' },
                      'cloud.gcp_cloud_run':      { label:'Cloud Run', color:'#34d399' },
                      'cloud.gcp_gke_audit':      { label:'GKE Audit', color:'#60a5fa' },
                      'cloud.gcp_correlation':    { label:'CORR',      color:'#fb923c' },
                      'cloud.gcp_anomaly':        { label:'ANOM',      color:'#fbbf24' },
                      'cloud.azure_defender':     { label:'Defender',  color:'#f87171' },
                      'cloud.entra_audit':        { label:'Entra',     color:'#38bdf8' },
                      'cloud.azure_nsg_flow':     { label:'NSG Flow',  color:'#a78bfa' },
                      'cloud.azure_correlation':  { label:'CORR',      color:'#fb923c' },
                      'cloud.azure_anomaly':      { label:'ANOM',      color:'#fbbf24' },
                      'cloud.aws_anomaly':        { label:'ANOM',      color:'#fbbf24' },
                    }[ev.event_type]
                    return (
                      <button key={ev.id||i} onClick={() => setSelected(isSelected ? null : ev.id)}
                        style={{ display:'flex', gap:12, alignItems:'flex-start', padding:'8px 10px 8px 28px',
                          background: isSelected ? 'rgba(0,194,224,0.06)' : 'transparent',
                          border: `1px solid ${isSelected ? 'rgba(0,194,224,0.3)' : 'transparent'}`,
                          borderRadius:8, cursor:'pointer', textAlign:'left', fontFamily:'inherit', position:'relative' }}>
                        {/* dot */}
                        <span style={{ position:'absolute', left:7, top:14, width:9, height:9, borderRadius:'50%',
                          background: sevColor, border:'2px solid var(--bg)', flexShrink:0 }}/>
                        <div style={{ flex:1, minWidth:0 }}>
                          <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:2 }}>
                            <span style={{ fontSize:11.5, fontWeight:600, color:'var(--text)',
                              whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis', flex:1 }}>
                              {displayTitle}
                            </span>
                            {sourceTag && (
                              <span style={{ fontSize:9, padding:'1px 5px', borderRadius:3, fontFamily:'DM Mono,monospace',
                                background:`${sourceTag.color}18`, color:sourceTag.color, border:`1px solid ${sourceTag.color}40`, flexShrink:0 }}>
                                {sourceTag.label}
                              </span>
                            )}
                            <span style={{ fontSize:9.5, color:'var(--text3)', flexShrink:0 }}>
                              {ev.time ? format(new Date(ev.time), 'HH:mm:ss') : ''}
                            </span>
                          </div>
                          <div style={{ display:'flex', gap:8, fontSize:10.5, color:'var(--text3)' }}>
                            {principal && <span style={{ color:'var(--accent)', fontFamily:'DM Mono,monospace' }}>{principal}</span>}
                            {ev.src_ip && <span>{ev.src_ip}</span>}
                            <span style={{ color: sevColor }}>{SEV_NUM_LABEL[ev.severity] || ev.event_type}</span>
                          </div>
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Event detail slide-out */}
      {selEvent && (
        <div style={{ width:340, flexShrink:0, borderLeft:'1px solid var(--border)', overflow:'auto', padding:'18px 16px', background:'var(--surface)' }}>
          <CloudEventPanel event={selEvent} onClose={() => setSelected(null)}/>
        </div>
      )}
    </div>
  )
}

// ── Panel: Blast Radius ──────────────────────────────────────────────────────
// ── Blast Radius — Principal List + Focus Graph ───────────────────────────────

