import { useState, useEffect, useCallback } from 'react'
import { RefreshCw, Database, Key, ChevronDown, Sparkles } from 'lucide-react'
import api, { runScan } from '../../api/client'

// ── CISControlCard — expandable with AI explain ───────────────────────────────
export function CISControlCard({ control }) {
  const [open, setOpen]       = useState(false)
  const [aiText, setAiText]   = useState(null)
  const [aiLoading, setAiLoading] = useState(false)

  const statusColors = { PASS:'#34d399', FAIL:'#f87171', UNKNOWN:'var(--text3)', NOT_APPLICABLE:'var(--text3)' }
  const statusBg     = { PASS:'rgba(52,211,153,0.05)', FAIL:'rgba(248,113,113,0.05)', UNKNOWN:'rgba(100,116,139,0.03)', NOT_APPLICABLE:'rgba(100,116,139,0.03)' }
  const col = statusColors[control.status] || 'var(--text3)'

  const explainAI = async (e) => {
    e.stopPropagation()
    if (aiText) { setAiText(null); return }
    setAiLoading(true)
    try {
      const prompt = `You are a GCP cloud security engineer. A CIS benchmark control is ${control.status}.

CIS Control: ${control.id} — ${control.title}
Section: ${control.section} | Level: ${control.level} | MITRE: ${control.mitre || 'N/A'}
Description: ${control.description}
Evidence found: ${control.evidence}
Remediation: ${control.remediation}

Return ONLY this JSON (no markdown):
{
  "plain_english": "1-2 sentences explaining what this control checks and why it matters",
  "risk_if_failed": "what an attacker could do if this is not fixed",
  "steps": ["exact gcloud command or console step 1", "step 2", "step 3"],
  "time_to_fix": "estimate e.g. 5 minutes / 1 hour / requires change window"
}`
      const { data } = await api.post('/api/v1/cloud-connectors/ai-explain', { prompt })
      const text = data.content?.find(b => b.type === 'text')?.text || data.text || ''
      const clean = text.replace(/```json\n?|```/g, '').trim()
      try { setAiText(JSON.parse(clean)) } catch { setAiText({ plain_english: clean }) }
    } catch { setAiText({ plain_english: 'AI explanation unavailable — check AI key in Settings.' }) }
    finally { setAiLoading(false) }
  }

  return (
    <div style={{
      background: open ? statusBg[control.status] : 'var(--surface)',
      border: `1px solid ${open ? col + '40' : 'var(--border)'}`,
      borderLeft: `3px solid ${col}`,
      borderRadius: 8, overflow: 'hidden', transition: 'all 0.15s',
    }}>
      {/* Header row — always visible, clickable */}
      <div onClick={() => setOpen(o => !o)}
        style={{ display:'flex', alignItems:'flex-start', gap:12, padding:'12px 14px', cursor:'pointer' }}>
        <div style={{ flexShrink:0, marginTop:1, fontSize:14, color:col }}>
          {control.status === 'PASS' ? '✓' : control.status === 'FAIL' ? '✗' : '?'}
        </div>
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:3, flexWrap:'wrap' }}>
            <span style={{ fontFamily:'DM Mono,monospace', fontSize:11, fontWeight:700, color:'var(--accent)', flexShrink:0 }}>
              CIS {control.id}
            </span>
            <span style={{ fontSize:12.5, fontWeight:600, color:'var(--text)' }}>{control.title}</span>
            <span style={{ fontSize:9.5, background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:4, padding:'1px 5px', color:'var(--text3)', flexShrink:0 }}>
              L{control.level}
            </span>
            <span style={{ fontSize:9.5, background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:4, padding:'1px 5px', color:'var(--text3)', flexShrink:0 }}>
              {control.section}
            </span>
            {control.mitre && (
              <span style={{ fontSize:9.5, background:'rgba(0,194,224,0.08)', border:'1px solid rgba(0,194,224,0.2)', borderRadius:4, padding:'1px 5px', color:'var(--accent)', flexShrink:0 }}>
                {control.mitre}
              </span>
            )}
          </div>
          <div style={{ fontSize:11, color:'var(--text3)' }}>{control.evidence}</div>
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:8, flexShrink:0 }}>
          <span style={{ fontSize:11, fontWeight:700, color:col, fontFamily:'DM Mono,monospace' }}>{control.status}</span>
          <ChevronDown size={13} color="var(--text3)" style={{ transform: open ? 'rotate(180deg)' : 'none', transition:'transform 0.15s' }}/>
        </div>
      </div>

      {/* Expanded body */}
      {open && (
        <div style={{ padding:'0 14px 14px', borderTop:'1px solid var(--border)' }}>
          <p style={{ fontSize:12, color:'var(--text2)', lineHeight:1.6, margin:'10px 0' }}>{control.description}</p>

          {control.status === 'FAIL' && (
            <div style={{ background:'rgba(52,211,153,0.06)', border:'1px solid rgba(52,211,153,0.2)', borderRadius:7, padding:'8px 12px', marginBottom:10 }}>
              <div style={{ fontSize:10, fontWeight:700, color:'#34d399', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:4 }}>✓ Remediation</div>
              <p style={{ fontSize:11.5, color:'var(--text2)', lineHeight:1.6, margin:0 }}>{control.remediation}</p>
            </div>
          )}

          {/* Action bar */}
          <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
            <button onClick={explainAI} disabled={aiLoading}
              style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, padding:'5px 10px',
                background: aiText ? 'rgba(139,92,246,0.15)' : 'rgba(0,194,224,0.08)',
                border: `1px solid ${aiText ? 'rgba(139,92,246,0.3)' : 'rgba(0,194,224,0.2)'}`,
                color: aiText ? '#a78bfa' : 'var(--accent)', borderRadius:6, cursor:'pointer', fontFamily:'inherit' }}>
              <Sparkles size={11}/>{aiLoading ? 'Analysing…' : aiText ? 'Hide AI' : 'Explain with AI'}
            </button>
          </div>

          {/* AI panel */}
          {aiText && (
            <div style={{ marginTop:10, background:'rgba(139,92,246,0.06)', border:'1px solid rgba(139,92,246,0.2)', borderRadius:8, padding:'12px 14px' }}>
              <div style={{ fontSize:10, fontWeight:700, color:'#a78bfa', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>✦ AI Analysis</div>
              {aiText.plain_english && <p style={{ fontSize:12, color:'var(--text)', lineHeight:1.6, marginBottom:8 }}>{aiText.plain_english}</p>}
              {aiText.risk_if_failed && (
                <div style={{ marginBottom:8 }}>
                  <span style={{ fontSize:10, color:'#f87171', fontWeight:600 }}>Risk: </span>
                  <span style={{ fontSize:11, color:'var(--text2)' }}>{aiText.risk_if_failed}</span>
                </div>
              )}
              {aiText.time_to_fix && (
                <div style={{ marginBottom:8 }}>
                  <span style={{ fontSize:10, color:'#fbbf24', fontWeight:600 }}>Time to fix: </span>
                  <span style={{ fontSize:11, color:'var(--text2)' }}>{aiText.time_to_fix}</span>
                </div>
              )}
              {aiText.steps?.length > 0 && (
                <div>
                  <div style={{ fontSize:10, color:'#34d399', fontWeight:600, marginBottom:4 }}>Steps:</div>
                  {aiText.steps.map((s, i) => (
                    <div key={i} style={{ display:'flex', gap:6, marginBottom:4 }}>
                      <span style={{ fontSize:10, color:'var(--accent)', fontFamily:'DM Mono,monospace', flexShrink:0 }}>{i+1}.</span>
                      <code style={{ fontSize:11, color:'var(--text2)', lineHeight:1.5, background:'var(--surface2)', padding:'1px 6px', borderRadius:4, display:'inline-block' }}>{s}</code>
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

// ── ComplianceControlCard — expandable with AI explain ────────────────────────
export function ComplianceControlCard({ ctrl, frameworkColors }) {
  const [open, setOpen]       = useState(false)
  const [aiText, setAiText]   = useState(null)
  const [aiLoading, setAiLoading] = useState(false)

  const FRAMEWORK_COLORS = frameworkColors || {
    'SOC2':        { color:'#a78bfa', bg:'rgba(167,139,250,0.08)', border:'rgba(167,139,250,0.25)' },
    'PCI-DSS':     { color:'#fb923c', bg:'rgba(251,146,60,0.08)',  border:'rgba(251,146,60,0.25)'  },
    'ISO27001':    { color:'#38bdf8', bg:'rgba(56,189,248,0.08)',  border:'rgba(56,189,248,0.25)'  },
    'NIST-800-53': { color:'#34d399', bg:'rgba(52,211,153,0.08)', border:'rgba(52,211,153,0.25)'  },
  }
  const fc = FRAMEWORK_COLORS[ctrl.framework] || { color:'var(--text2)', bg:'var(--surface2)', border:'var(--border)' }
  const isFail = ctrl.status === 'FAIL'
  const statusColor = isFail ? '#f87171' : ctrl.status === 'PASS' ? '#34d399' : 'var(--text3)'

  const explainAI = async (e) => {
    e.stopPropagation()
    if (aiText) { setAiText(null); return }
    setAiLoading(true)
    try {
      const prompt = `You are a cloud security compliance expert. A compliance control is ${ctrl.status}.

Framework: ${ctrl.framework}
Control: ${ctrl.control_id} — ${ctrl.title}
Description: ${ctrl.description}
${ctrl.finding_ids?.length ? `Contributing CSPM findings: ${ctrl.finding_ids.length} finding(s) in this category` : ''}

Return ONLY this JSON (no markdown):
{
  "plain_english": "1-2 sentences: what auditors look for with this control",
  "business_risk": "what compliance or business risk this failure creates",
  "evidence_needed": "what evidence an auditor would need to see this as PASS",
  "remediation_priority": "immediate / short-term / planned",
  "steps": ["specific action 1", "specific action 2"]
}`
      const { data } = await api.post('/api/v1/cloud-connectors/ai-explain', { prompt })
      const text = data.content?.find(b => b.type === 'text')?.text || data.text || ''
      const clean = text.replace(/```json\n?|```/g, '').trim()
      try { setAiText(JSON.parse(clean)) } catch { setAiText({ plain_english: clean }) }
    } catch { setAiText({ plain_english: 'AI explanation unavailable.' }) }
    finally { setAiLoading(false) }
  }

  return (
    <div style={{
      background: open ? (isFail ? 'rgba(248,113,113,0.04)' : 'var(--surface2)') : 'var(--surface)',
      border: `1px solid ${open ? (isFail ? 'rgba(248,113,113,0.25)' : fc.border) : 'var(--border)'}`,
      borderLeft: `3px solid ${statusColor}`,
      borderRadius: 8, overflow:'hidden', transition:'all 0.15s',
    }}>
      {/* Header */}
      <div onClick={() => setOpen(o => !o)}
        style={{ display:'flex', alignItems:'flex-start', gap:12, padding:'12px 14px', cursor:'pointer' }}>
        <div style={{ fontSize:14, flexShrink:0, marginTop:1, color:statusColor }}>
          {ctrl.status === 'PASS' ? '✓' : ctrl.status === 'FAIL' ? '✗' : '?'}
        </div>
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:3, flexWrap:'wrap' }}>
            <span style={{ fontSize:11, fontWeight:700, color:fc.color, background:fc.bg,
              border:`1px solid ${fc.border}`, borderRadius:4, padding:'1px 7px',
              fontFamily:'DM Mono,monospace', flexShrink:0 }}>
              {ctrl.control_id}
            </span>
            <span style={{ fontSize:12.5, fontWeight:600, color:'var(--text)' }}>{ctrl.title}</span>
          </div>
          <p style={{ fontSize:11, color:'var(--text3)', margin:0, lineHeight:1.4 }}>{ctrl.description}</p>
          {ctrl.finding_ids?.length > 0 && (
            <span style={{ fontSize:10, color:'#f87171', marginTop:3, display:'block' }}>
              {ctrl.finding_ids.length} CSPM finding{ctrl.finding_ids.length !== 1 ? 's' : ''} contributing
            </span>
          )}
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:8, flexShrink:0 }}>
          <span style={{ fontSize:11, fontWeight:700, color:statusColor, fontFamily:'DM Mono,monospace' }}>{ctrl.status}</span>
          <ChevronDown size={13} color="var(--text3)" style={{ transform: open ? 'rotate(180deg)' : 'none', transition:'transform 0.15s' }}/>
        </div>
      </div>

      {/* Expanded */}
      {open && (
        <div style={{ padding:'0 14px 14px', borderTop:'1px solid var(--border)' }}>
          <div style={{ display:'flex', gap:8, alignItems:'center', marginTop:10, flexWrap:'wrap' }}>
            <button onClick={explainAI} disabled={aiLoading}
              style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, padding:'5px 10px',
                background: aiText ? 'rgba(139,92,246,0.15)' : 'rgba(0,194,224,0.08)',
                border:`1px solid ${aiText ? 'rgba(139,92,246,0.3)' : 'rgba(0,194,224,0.2)'}`,
                color: aiText ? '#a78bfa' : 'var(--accent)', borderRadius:6, cursor:'pointer', fontFamily:'inherit' }}>
              <Sparkles size={11}/>{aiLoading ? 'Analysing…' : aiText ? 'Hide AI' : 'Explain with AI'}
            </button>
            {ctrl.finding_ids?.length > 0 && (
              <span style={{ fontSize:10.5, color:'var(--text3)' }}>
                → Review the Deep Dive tab to see the {ctrl.finding_ids.length} related CSPM finding{ctrl.finding_ids.length !== 1 ? 's' : ''}
              </span>
            )}
          </div>

          {aiText && (
            <div style={{ marginTop:10, background:'rgba(139,92,246,0.06)', border:'1px solid rgba(139,92,246,0.2)', borderRadius:8, padding:'12px 14px' }}>
              <div style={{ fontSize:10, fontWeight:700, color:'#a78bfa', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>✦ AI Compliance Analysis</div>
              {aiText.plain_english && <p style={{ fontSize:12, color:'var(--text)', lineHeight:1.6, marginBottom:8 }}>{aiText.plain_english}</p>}
              {aiText.business_risk && (
                <div style={{ marginBottom:6 }}>
                  <span style={{ fontSize:10, color:'#f87171', fontWeight:600 }}>Business risk: </span>
                  <span style={{ fontSize:11, color:'var(--text2)' }}>{aiText.business_risk}</span>
                </div>
              )}
              {aiText.evidence_needed && (
                <div style={{ marginBottom:6 }}>
                  <span style={{ fontSize:10, color:'#38bdf8', fontWeight:600 }}>Auditor evidence needed: </span>
                  <span style={{ fontSize:11, color:'var(--text2)' }}>{aiText.evidence_needed}</span>
                </div>
              )}
              {aiText.remediation_priority && (
                <div style={{ marginBottom: aiText.steps?.length ? 8 : 0 }}>
                  <span style={{ fontSize:10, color:'#fbbf24', fontWeight:600 }}>Priority: </span>
                  <span style={{ fontSize:11, color:'var(--text2)', textTransform:'capitalize' }}>{aiText.remediation_priority}</span>
                </div>
              )}
              {aiText.steps?.length > 0 && (
                <div>
                  <div style={{ fontSize:10, color:'#34d399', fontWeight:600, marginBottom:4 }}>Actions:</div>
                  {aiText.steps.map((s, i) => (
                    <div key={i} style={{ display:'flex', gap:6, marginBottom:3 }}>
                      <span style={{ fontSize:10, color:'var(--accent)', fontFamily:'DM Mono,monospace', flexShrink:0 }}>{i+1}.</span>
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

// ── Panel: Compliance Frameworks ─────────────────────────────────────────────
export function PanelCompliance({ connId, provider }) {
  const [report, setReport]     = useState(null)
  const [loading, setLoading]   = useState(true)
  const [running, setRunning]   = useState(false)
  const [framework, setFramework] = useState('all')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await api.get(`/api/v1/cloud-connectors/${connId}/compliance`)
      setReport(data?.scores?.length ? data : null)
    } catch { setReport(null) }
    finally { setLoading(false) }
  }, [connId])

  useEffect(() => { load() }, [load])

  const run = async () => {
    setRunning(true)
    try {
      const { data } = await runScan(`/api/v1/cloud-connectors/${connId}/compliance`)
      setReport(data?.scores?.length ? data : null)
    } catch (e) { alert('Compliance mapping failed: ' + (e.response?.data?.error || e.message)) }
    finally { setRunning(false) }
  }

  const FRAMEWORK_COLORS = {
    'SOC2':        { color: '#a78bfa', bg: 'rgba(167,139,250,0.08)', border: 'rgba(167,139,250,0.25)' },
    'PCI-DSS':     { color: '#fb923c', bg: 'rgba(251,146,60,0.08)',  border: 'rgba(251,146,60,0.25)'  },
    'ISO27001':    { color: '#38bdf8', bg: 'rgba(56,189,248,0.08)',  border: 'rgba(56,189,248,0.25)'  },
    'NIST-800-53': { color: '#34d399', bg: 'rgba(52,211,153,0.08)', border: 'rgba(52,211,153,0.25)'  },
  }

  const controls  = report?.controls || []
  const scores    = report?.scores   || []
  const frameworks = ['all', ...new Set(controls.map(c => c.framework))]
  const filtered   = framework === 'all' ? controls : controls.filter(c => c.framework === framework)
  const failedFirst = [...filtered].sort((a,b) => {
    if (a.status === 'FAIL' && b.status !== 'FAIL') return -1
    if (b.status === 'FAIL' && a.status !== 'FAIL') return 1
    return 0
  })

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden' }}>
      <div style={{ padding:'20px 24px 0', flexShrink:0 }}>
        <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:16 }}>
          <div>
            <h3 style={{ fontSize:15, fontWeight:700, color:'var(--text)', marginBottom:4 }}>Compliance Framework Mapping</h3>
            <p style={{ fontSize:11.5, color:'var(--text3)' }}>
              CSPM findings mapped to SOC 2, PCI-DSS v4.0, ISO 27001:2022, and NIST 800-53 Rev5.
              {report?.scanned_at && <span style={{ marginLeft:8 }}>Last updated: {new Date(report.scanned_at).toLocaleString()}</span>}
            </p>
          </div>
          <button onClick={run} disabled={running}
            style={{ display:'flex', alignItems:'center', gap:7, padding:'8px 16px',
              background: running ? 'var(--surface2)' : 'var(--accent)',
              color: running ? 'var(--text2)' : '#000',
              border:'none', borderRadius:8, fontSize:12, fontWeight:600,
              cursor: running ? 'wait' : 'pointer', fontFamily:'inherit', flexShrink:0 }}>
            <RefreshCw size={12} style={running ? { animation:'spin 0.8s linear infinite' } : {}}/>
            {running ? 'Mapping…' : 'Remap Compliance'}
          </button>
        </div>

        {scores.length > 0 && (
          <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:10, marginBottom:16 }}>
            {scores.map(s => {
              const fc = FRAMEWORK_COLORS[s.framework] || { color:'var(--text2)', bg:'var(--surface2)', border:'var(--border)' }
              const pct = Math.round(s.score_percent)
              return (
                <button key={s.framework}
                  onClick={() => setFramework(framework === s.framework ? 'all' : s.framework)}
                  style={{ padding:'14px 16px', background: framework === s.framework ? fc.bg : 'var(--surface)',
                    border:`1px solid ${framework === s.framework ? fc.border : 'var(--border)'}`,
                    borderTop:`3px solid ${fc.color}`, borderRadius:10, cursor:'pointer', fontFamily:'inherit', textAlign:'left', transition:'all 0.15s' }}>
                  <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:6 }}>{s.framework}</div>
                  <div style={{ display:'flex', alignItems:'baseline', gap:4, marginBottom:6 }}>
                    <span style={{ fontSize:26, fontWeight:800, color: pct>=80?'#34d399':pct>=60?'#fbbf24':'#f87171', fontFamily:'DM Mono,monospace' }}>{pct}%</span>
                    <span style={{ fontSize:10.5, color:'var(--text3)' }}>compliant</span>
                  </div>
                  <div style={{ height:4, background:'var(--surface2)', borderRadius:3, overflow:'hidden', marginBottom:6 }}>
                    <div style={{ height:'100%', borderRadius:3, background:pct>=80?'#34d399':pct>=60?'#fbbf24':'#f87171', width:`${pct}%`, transition:'width 0.6s ease' }}/>
                  </div>
                  <div style={{ display:'flex', gap:8, fontSize:10.5 }}>
                    <span style={{ color:'#34d399' }}>✓ {s.passed} passed</span>
                    <span style={{ color:'#f87171' }}>✗ {s.failed} failed</span>
                  </div>
                </button>
              )
            })}
          </div>
        )}

        {controls.length > 0 && (
          <div style={{ display:'flex', gap:4, borderBottom:'1px solid var(--border)', marginBottom:0, paddingBottom:0 }}>
            {frameworks.map(fw => (
              <button key={fw} onClick={() => setFramework(fw)}
                style={{ padding:'6px 14px', fontSize:11.5, background:'transparent',
                  color: framework===fw ? 'var(--accent)' : 'var(--text3)',
                  border:'none', borderBottom: framework===fw ? '2px solid var(--accent)' : '2px solid transparent',
                  cursor:'pointer', fontFamily:'inherit', fontWeight: framework===fw ? 600 : 400, marginBottom:-1 }}>
                {fw === 'all' ? 'All Frameworks' : fw}
                <span style={{ marginLeft:5, fontSize:10, background:framework===fw?'rgba(0,194,224,0.15)':'var(--surface2)',
                  color:framework===fw?'var(--accent)':'var(--text3)', borderRadius:10, padding:'0 5px' }}>
                  {fw==='all' ? controls.length : controls.filter(c => c.framework===fw).length}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>

      <div style={{ flex:1, overflowY:'auto', padding:'16px 24px 24px' }}>
        {loading && (
          <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:200, color:'var(--text3)', gap:8 }}>
            <RefreshCw size={14} style={{ animation:'spin 0.8s linear infinite' }}/> Loading compliance data…
          </div>
        )}
        {!loading && !report && (
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', height:280, color:'var(--text3)', gap:10 }}>
            <div style={{ fontSize:36 }}>📋</div>
            <div style={{ fontSize:14, fontWeight:600, color:'var(--text2)' }}>No compliance report yet</div>
            <div style={{ fontSize:12, maxWidth:360, textAlign:'center', lineHeight:1.6 }}>
              {provider === 'aws' ? 'Run the CIS benchmark first (CIS tab), then click "Remap Compliance" to generate framework mappings.' : 'Run a CSPM scan first, then click "Remap Compliance" to generate framework mappings.'}
            </div>
            <button onClick={run} disabled={running}
              style={{ marginTop:8, padding:'8px 20px', background:'var(--accent)', color:'#000',
                border:'none', borderRadius:8, fontSize:12, fontWeight:600, cursor:'pointer', fontFamily:'inherit' }}>
              {running ? 'Mapping…' : 'Generate Compliance Report'}
            </button>
          </div>
        )}
        {report && !loading && (
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            {failedFirst.length === 0 && (
              <div style={{ textAlign:'center', padding:40, color:'#34d399', fontSize:13 }}>
                ✓ All controls passing for the selected framework
              </div>
            )}
            {failedFirst.map((ctrl, i) => (
              <ComplianceControlCard key={i} ctrl={ctrl} frameworkColors={FRAMEWORK_COLORS}/>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── CIS GCP Benchmark Panel ───────────────────────────────────────────────────
export function PanelCISBenchmark({ cis, loading, scanning, onRunScan, conn }) {
  const [filter, setFilter] = useState('all')
  const [sectionFilter, setSectionFilter] = useState('all')

  const sections = ['all','IAM','Logging','Networking','VM','Storage','CloudSQL']
  const statusFilters = [
    { id:'all',     label:'All',     color:'var(--text2)' },
    { id:'FAIL',    label:'Failed',  color:'var(--red)' },
    { id:'PASS',    label:'Passed',  color:'var(--green)' },
    { id:'UNKNOWN', label:'Unknown', color:'var(--text3)' },
  ]

  const controls = cis?.controls || []
  const filtered = controls.filter(c => {
    if (filter !== 'all' && c.status !== filter) return false
    if (sectionFilter !== 'all' && c.section !== sectionFilter) return false
    return true
  })

  const score = cis ? Math.round(cis.score_percent) : 0
  const scoreColor = score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--yellow)' : 'var(--red)'

  const sectionStats = {}
  for (const c of controls) {
    if (!sectionStats[c.section]) sectionStats[c.section] = { pass:0, fail:0, total:0 }
    sectionStats[c.section].total++
    if (c.status === 'PASS') sectionStats[c.section].pass++
    else if (c.status === 'FAIL') sectionStats[c.section].fail++
  }

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden' }}>
      {/* Header */}
      <div style={{ padding:'20px 24px 0', flexShrink:0 }}>
        <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:20 }}>
          <div>
            <h3 style={{ fontSize:15, fontWeight:700, color:'var(--text)', marginBottom:4 }}>
              CIS {conn?.provider === 'azure' ? 'Microsoft Azure Foundations' : conn?.provider === 'aws' ? 'AWS-style Foundations' : 'Google Cloud Platform Foundation'} Benchmark{conn?.provider === 'aws' ? '' : ' v2.0'}
              <span style={{ fontSize:11, fontWeight:500, color:'var(--text3)', marginLeft:8 }}>
                (subset{cis?.controls?.length ? ` — ${cis.controls.length} controls assessed` : ''}, not the full benchmark)
              </span>
            </h3>
            <p style={{ fontSize:11.5, color:'var(--text3)' }}>
              {conn?.provider === 'aws'
                ? 'Posture checks across IAM, Storage (S3), Logging and Networking. Own control IDs mapped to CIS topics, not CIS numbering.'
                : conn?.provider === 'azure'
                ? 'Formal compliance assessment across IAM, Defender, Storage, Database, Logging, Networking, VMs and Key Vault.'
                : 'Formal compliance assessment across IAM, Logging, Networking, VMs, Storage and Cloud SQL.'
              }
            </p>
          </div>
          <div style={{ display:'flex', alignItems:'center', gap:10, flexShrink:0 }}>
            {cis && (
              <div style={{ textAlign:'center', padding:'8px 16px', background:'var(--surface2)',
                border:`2px solid ${scoreColor}`, borderRadius:10 }}>
                <div style={{ fontSize:24, fontWeight:700, color:scoreColor, fontFamily:'DM Mono, monospace' }}>
                  {score}%
                </div>
                <div style={{ fontSize:9.5, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.08em' }}>
                  CIS Score
                </div>
              </div>
            )}
            <button onClick={onRunScan} disabled={scanning}
              style={{ display:'flex', alignItems:'center', gap:7, padding:'8px 16px',
                background: scanning ? 'var(--surface2)' : 'var(--accent)',
                color: scanning ? 'var(--text2)' : '#000',
                border:'none', borderRadius:8, fontSize:12.5, fontWeight:600,
                cursor: scanning ? 'wait' : 'pointer', fontFamily:'inherit' }}>
              {scanning ? '⟳ Scanning…' : '⟳ Run Assessment'}
            </button>
          </div>
        </div>

        {cis && (
          <>
            {/* Score breakdown by section */}
            <div style={{ display:'grid', gridTemplateColumns:'repeat(6,1fr)', gap:8, marginBottom:16 }}>
              {Object.entries(sectionStats).map(([sec, stats]) => {
                const pct = stats.total ? Math.round(stats.pass/stats.total*100) : 0
                const col = pct >= 80 ? 'var(--green)' : pct >= 60 ? 'var(--yellow)' : 'var(--red)'
                return (
                  <div key={sec}
                    onClick={() => setSectionFilter(sectionFilter === sec ? 'all' : sec)}
                    style={{ background: sectionFilter === sec ? 'var(--surface3)' : 'var(--surface2)',
                      border:`1px solid ${sectionFilter === sec ? col : 'var(--border)'}`,
                      borderRadius:8, padding:'10px 12px', cursor:'pointer', transition:'all 0.15s' }}>
                    <div style={{ fontSize:10, color:'var(--text3)', marginBottom:4 }}>{sec}</div>
                    <div style={{ fontSize:16, fontWeight:700, color:col, fontFamily:'DM Mono, monospace' }}>{pct}%</div>
                    <div style={{ fontSize:9.5, color:'var(--text3)', marginTop:2 }}>
                      {stats.pass}/{stats.total} passed
                    </div>
                    <div style={{ height:3, background:'var(--surface)', borderRadius:2, marginTop:6 }}>
                      <div style={{ height:'100%', borderRadius:2, background:col, width:`${pct}%`, transition:'width 0.5s' }}/>
                    </div>
                  </div>
                )
              })}
            </div>

            {/* KPI row */}
            <div style={{ display:'flex', gap:8, marginBottom:16, flexWrap:'wrap' }}>
              {statusFilters.map(f => {
                const count = f.id === 'all' ? controls.length :
                  controls.filter(c => c.status === f.id).length
                return (
                  <button key={f.id}
                    onClick={() => setFilter(f.id)}
                    style={{ display:'flex', alignItems:'center', gap:6, padding:'5px 12px',
                      borderRadius:20, border:`1px solid ${filter === f.id ? f.color : 'var(--border)'}`,
                      background: filter === f.id ? `color-mix(in srgb, ${f.color} 10%, transparent)` : 'transparent',
                      color: filter === f.id ? f.color : 'var(--text3)',
                      cursor:'pointer', fontSize:11.5, fontFamily:'inherit' }}>
                    <span style={{ fontFamily:'DM Mono, monospace', fontWeight:700 }}>{count}</span>
                    {f.label}
                  </button>
                )
              })}
              <span style={{ marginLeft:'auto', fontSize:11, color:'var(--text3)', alignSelf:'center' }}>
                Scanned: {cis.scanned_at ? new Date(cis.scanned_at).toLocaleString() : '—'}
                {' · '}L1: {Math.round(cis.level1_score||0)}% · L2: {Math.round(cis.level2_score||0)}%
              </span>
            </div>
          </>
        )}
      </div>

      {/* Controls list */}
      <div style={{ flex:1, overflowY:'auto', padding:'0 24px 24px' }}>
        {loading && <div style={{ textAlign:'center', padding:40, color:'var(--text3)' }}>Loading assessment…</div>}

        {!loading && !cis && !scanning && (
          <div style={{ textAlign:'center', padding:60, color:'var(--text3)' }}>
            <div style={{ fontSize:32, marginBottom:12 }}>📋</div>
            <div style={{ fontSize:14, fontWeight:500, color:'var(--text2)', marginBottom:6 }}>
              No CIS assessment yet
            </div>
            <div style={{ fontSize:12 }}>Click "Run Assessment" to check against CIS {conn?.provider === 'azure' ? 'Azure Foundations' : conn?.provider === 'aws' ? 'AWS' : 'GCP'} Benchmark</div>
          </div>
        )}

        {cis && !loading && (
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            {filtered.length === 0 && (
              <div style={{ textAlign:'center', padding:30, color:'var(--text3)', fontSize:12 }}>
                No controls match your filter
              </div>
            )}
            {filtered.map((control, i) => (
              <CISControlCard key={i} control={control}/>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

