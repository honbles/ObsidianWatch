import { useEffect, useState, useRef } from 'react'
import { cveHref } from '../../utils/safeHref'
import { Shield, Key, AlertTriangle, RefreshCw, Search, Activity, Clock, Zap, Bug, CheckCircle, MessageSquare } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api, { runScan } from '../../api/client'
import { AIFindingCard, FindingCard, PortRow } from './shared.jsx'

export function TabVuln({ agent }) {
  const [data, setData]           = useState(null)
  const [loading, setLoading]     = useState(true)
  const [aiLoading, setAILoading] = useState(false)
  const [aiResult, setAIResult]   = useState(null)
  const [aiError, setAIError]     = useState(null)
  const [expandAll, setExpandAll] = useState(false)
  const [activeSection, setActiveSection] = useState("overview")

  const SEV = {
    5: { label:"Critical", bg:"bg-red-950/40",    border:"border-red-800/50",    text:"text-red-400",    dot:"bg-red-400"    },
    4: { label:"High",     bg:"bg-orange-950/30", border:"border-orange-800/40", text:"text-orange-400", dot:"bg-orange-400" },
    3: { label:"Medium",   bg:"bg-yellow-950/20", border:"border-yellow-800/30", text:"text-yellow-400", dot:"bg-yellow-400" },
    2: { label:"Low",      bg:"bg-blue-950/15",   border:"border-blue-800/25",   text:"text-blue-400",   dot:"bg-blue-400"   },
    1: { label:"Info",     bg:"bg-siem-surface",  border:"border-siem-border",   text:"text-siem-muted", dot:"bg-siem-muted/40" },
  }

  const parseRaw = ev => {
    if (!ev?.raw) return null
    if (typeof ev.raw === "string") { try { return JSON.parse(ev.raw) } catch { return null } }
    return ev.raw
  }

  useEffect(() => {
    setLoading(true)
    api.get("/api/v1/agents/" + encodeURIComponent(agent.hostname) + "/vuln")
      .then(r => setData(r.data?.scan || null))
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [agent.hostname])

  // Load cached vuln AI analysis on mount
  useEffect(() => {
    api.get("/api/v1/agents/" + encodeURIComponent(agent.hostname) + "/vuln/analysis-cache")
      .then(r => {
        if (r.data?.analysis && !aiResult) {
          try {
            const clean = r.data.analysis.replace(/```json\n?|```\n?/g, "").trim()
            setAIResult(JSON.parse(clean))
          } catch (e) {}
        }
      }).catch(() => {})
  }, [agent.hostname])

  const [osv, setOsv] = useState(null)
  const [osvBusy, setOsvBusy] = useState(false)
  const [osvErr, setOsvErr] = useState(null)
  const [hc, setHc] = useState(null)
  const runHC = async () => {
    try { setHc((await api.get("/api/v1/agents/" + encodeURIComponent(agent.hostname) + "/compliance")).data) }
    catch (e) { setOsvErr(e.response?.data?.error || "Host checks failed") }
  }
  const runOSV = async () => {
    setOsvBusy(true); setOsvErr(null)
    try {
      const r = await runScan("/api/v1/agents/" + encodeURIComponent(agent.hostname) + "/vuln/osv")
      setOsv(r.data)
    } catch (e) {
      setOsvErr(e.response?.data?.error || e.message || "OSV lookup failed")
    } finally { setOsvBusy(false) }
  }

  const runAIAnalysis = async () => {
    if (!data) return
    setAILoading(true); setAIError(null); setAIResult(null)
    try {
      const scan = parseRaw(data)
      const { data: res } = await api.post(
        "/api/v1/agents/" + encodeURIComponent(agent.hostname) + "/vuln/analyse",
        { scan_json: JSON.stringify(scan), host: agent.hostname },
        { timeout: 120000 }
      )
      const text = res.content?.find(b => b.type === "text")?.text || ""
      const clean = text.replace(/```json\n?|```\n?/g, "").trim()
      try {
        const parsed = JSON.parse(clean)
        setAIResult(parsed)
      } catch {
        setAIResult({ executive_summary: clean })
      }
      setActiveSection("ai")
    } catch (e) {
      setAIError(e.response?.data?.error || "AI analysis failed — check your API key in Settings → AI")
    } finally { setAILoading(false) }
  }

  if (loading) return (
    <div className="flex items-center justify-center py-16 gap-2 text-siem-muted">
      <RefreshCw size={14} className="animate-spin"/><span className="text-sm">Loading scan…</span>
    </div>
  )

  const scan = parseRaw(data)

  if (!scan) return (
    <div className="flex flex-col items-center justify-center py-20 gap-4">
      <div className="w-16 h-16 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
        <Bug size={28} className="text-siem-muted/25"/>
      </div>
      <div className="text-center">
        <div className="text-sm font-semibold text-siem-text/70 mb-1">No vulnerability scan yet</div>
        <div className="text-xs text-siem-muted/50 max-w-xs text-center">
          Agent scans all 65,535 TCP ports automatically on startup, then every 5 days.
          Redeploy the agent to trigger a new scan.
        </div>
      </div>
    </div>
  )

  const ports     = scan.open_ports || []
  const findings  = scan.findings   || []
  const packages  = scan.packages   || []
  const services  = scan.services   || []
  const critical  = ports.filter(p => p.severity >= 5)
  const high      = ports.filter(p => p.severity === 4)
  const medium    = ports.filter(p => p.severity === 3)
  const low       = ports.filter(p => p.severity <= 2)
  const topSev    = scan.critical_count > 0 ? 5 : scan.high_count > 0 ? 4 : scan.medium_count > 0 ? 3 : ports.length > 0 ? 2 : 1
  const topStyle  = SEV[topSev]

  const SECTIONS = [
    { id:"overview", label:"Overview" },
    { id:"ports",    label:`Ports (${ports.length})` },
    { id:"findings", label:`Findings (${findings.length})` },
    { id:"packages", label:`Packages (${packages.length})` },
    { id:"ai",       label:"AI Analysis", highlight: true },
  ]

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Top bar — risk summary + AI button */}
      <div className="shrink-0 px-5 py-3 border-b border-siem-border bg-siem-surface">
        <div className="flex items-center gap-4">
          {/* Posture */}
          <div className={"flex items-center gap-2.5 px-3 py-2 rounded-xl border " + topStyle.bg + " " + topStyle.border}>
            <span className={"w-2 h-2 rounded-full " + topStyle.dot}/>
            <span className={"text-sm font-bold " + topStyle.text}>{topStyle.label} Risk</span>
          </div>

          {/* Counts */}
          <div className="flex items-center gap-4">
            {[
              [scan.critical_count, "Critical", "text-red-400"],
              [scan.high_count,     "High",     "text-orange-400"],
              [scan.medium_count,   "Medium",   "text-yellow-400"],
              [ports.length,        "Open Ports","text-siem-muted"],
            ].map(([n, label, color]) => n > 0 && (
              <div key={label} className="text-center">
                <div className={"text-lg font-bold font-mono " + color}>{n}</div>
                <div className="text-[9px] text-siem-muted uppercase tracking-wide">{label}</div>
              </div>
            ))}
          </div>

          {/* Scan metadata */}
          <div className="ml-auto flex items-center gap-3 text-[10px] text-siem-muted">
            {data?.time && <span>{formatDistanceToNow(new Date(data.time), {addSuffix:true})}</span>}
            {scan.scan_duration_secs && <span>{scan.scan_duration_secs.toFixed(0)}s scan</span>}
            <span className="font-mono">65,535 ports</span>
          </div>

          {/* AI Analysis button */}
          <button onClick={runAIAnalysis} disabled={aiLoading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-500 hover:to-purple-500 disabled:opacity-50 text-white transition-all shadow-lg shadow-violet-900/30">
            {aiLoading
              ? <><RefreshCw size={12} className="animate-spin"/> Analysing…</>
              : <><Zap size={12}/> AI Analysis</>}
          </button>
        </div>

        {/* Section tabs */}
        <div className="flex gap-0 mt-3">
          {SECTIONS.map(s => (
            <button key={s.id} onClick={() => setActiveSection(s.id)}
              className={"flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium transition-colors border-b-2 " + (
                activeSection === s.id
                  ? (s.highlight ? "border-violet-400 text-violet-400" : "border-siem-accent text-siem-accent")
                  : "border-transparent text-siem-muted hover:text-siem-text"
              )}>
              {s.label}
              {s.id === "ai" && aiResult && <span className="w-1.5 h-1.5 rounded-full bg-violet-400 ml-0.5"/>}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">

        {/* ── Overview ── */}
        {activeSection === "overview" && (
          <div className="p-5 space-y-4">
            {/* System info */}
            <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
              <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3">System</div>
              <div className="grid grid-cols-2 gap-x-8">
                {[
                  ["Hostname",    scan.system?.hostname || agent.hostname],
                  ["OS",          scan.system?.os_release || scan.os || agent.os],
                  ["Kernel",      scan.system?.kernel_version || "—"],
                  ["Arch",        scan.system?.arch || "—"],
                  ["Scan time",   scan.scan_duration_secs ? scan.scan_duration_secs.toFixed(1) + "s" : "—"],
                  ["Ports scanned", "1 – 65,535 TCP"],
                  ["Packages",    (scan.packages?.length || 0) + " installed"],
                  ["Services",    (scan.services?.length || 0) + " running"],
                ].map(([k,v]) => (
                  <div key={k} className="flex justify-between text-xs py-1.5 border-b border-siem-border/20 last:border-0">
                    <span className="text-siem-muted">{k}</span>
                    <span className="font-mono text-siem-text text-[11px]">{v}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Host findings */}
            {findings.length > 0 && (
              <div className="space-y-3">
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold">Security Findings</div>
                {findings.sort((a,b) => b.severity - a.severity).map((f,i) => (
                  <FindingCard key={i} f={f} SEV={SEV}/>
                ))}
              </div>
            )}

            {/* Top risky ports preview */}
            {(critical.length + high.length) > 0 && (
              <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                <div className="px-4 py-2.5 border-b border-siem-border flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Bug size={13} className="text-red-400"/>
                    <span className="text-xs font-semibold text-siem-text">Critical & High Risk Ports</span>
                  </div>
                  <button onClick={() => setActiveSection("ports")} className="text-[10px] text-siem-muted hover:text-siem-accent">
                    View all →
                  </button>
                </div>
                {[...critical, ...high].slice(0, 8).map((p,i) => (
                  <PortRow key={i} port={p} st={SEV[p.severity] || SEV[1]} forceExpand={false}/>
                ))}
              </div>
            )}

            {findings.length === 0 && critical.length === 0 && high.length === 0 && (
              <div className="flex flex-col items-center justify-center py-10 gap-2">
                <CheckCircle size={28} className="text-emerald-400/50"/>
                <div className="text-sm font-medium text-siem-text/60">No critical or high findings</div>
                <div className="text-xs text-siem-muted/40">Run AI Analysis for a detailed assessment</div>
              </div>
            )}
          </div>
        )}

        {/* ── Ports ── */}
        {activeSection === "ports" && (
          <div className="p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="text-xs text-siem-muted">{ports.length} open TCP ports found</div>
              <button onClick={() => setExpandAll(e => !e)}
                className="text-[10px] text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-2.5 py-1">
                {expandAll ? "Collapse all" : "Expand all"}
              </button>
            </div>
            {ports.length === 0 ? (
              <div className="flex flex-col items-center py-12 gap-2">
                <CheckCircle size={24} className="text-emerald-400/40"/>
                <span className="text-sm text-siem-muted">No open TCP ports</span>
              </div>
            ) : (
              <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                <div className="grid gap-0 px-4 py-2 border-b border-siem-border/40 bg-siem-bg/40" style={{gridTemplateColumns:"72px 90px 140px 1fr 80px"}}>
                  {["Port","Proto","Service","Risk","Severity"].map(h => (
                    <span key={h} className="text-[9px] uppercase tracking-wider text-siem-muted/50 font-semibold">{h}</span>
                  ))}
                </div>
                {[...critical,...high,...medium,...low].map((p,i) => (
                  <PortRow key={i} port={p} st={SEV[p.severity]||SEV[1]} forceExpand={expandAll}/>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── Findings ── */}
        {activeSection === "findings" && (
          <div className="p-5 space-y-3">
            {findings.length === 0 ? (
              <div className="flex flex-col items-center py-12 gap-2">
                <CheckCircle size={24} className="text-emerald-400/40"/>
                <span className="text-sm text-siem-muted">No security findings</span>
              </div>
            ) : (
              findings.sort((a,b) => b.severity - a.severity).map((f,i) => (
                <FindingCard key={i} f={f} SEV={SEV}/>
              ))
            )}
          </div>
        )}

        {/* ── Packages ── */}
        {activeSection === "packages" && (
          <div className="p-5">
            {packages.length === 0 ? (
              <div className="text-center text-sm text-siem-muted py-12">No package data collected</div>
            ) : (<>
              <div className="mb-3 flex items-center gap-3">
                <button onClick={runOSV} disabled={osvBusy}
                  className="text-xs px-3 py-1.5 rounded-lg border border-siem-border bg-siem-surface hover:bg-siem-bg disabled:opacity-50">
                  {osvBusy ? "Checking OSV…" : "Check packages against OSV"}
                </button>
                <button onClick={runHC}
                  className="text-xs px-3 py-1.5 rounded-lg border border-siem-border bg-siem-surface hover:bg-siem-bg">Run host hygiene checks</button>
                {osvErr && <span className="text-xs text-red-400">{osvErr}</span>}
                {osv && <span className="text-xs text-siem-muted">{osv.packages_checked} packages ({osv.ecosystem}) · {(osv.findings||[]).length} advisories</span>}
              </div>
              {hc && (
                <div className="mb-4 bg-siem-surface border border-siem-border rounded-xl">
                  <div className="px-4 py-2 text-[11px] text-siem-muted border-b border-siem-border/30">
                    {hc.passed}/{hc.total} passed — {hc.scope}
                  </div>
                  {hc.checks.map(c => (
                    <div key={c.id} className="px-4 py-2 border-b border-siem-border/15 last:border-0 text-[11px]">
                      <span className={c.status === "pass" ? "text-emerald-400" : "text-red-400"}>{c.status.toUpperCase()}</span>
                      <span className="ml-2 text-siem-text">{c.id} {c.title}</span>
                      {c.status === "fail" && <div className="text-siem-muted mt-0.5">{c.detail} — {c.fix}</div>}
                    </div>
                  ))}
                </div>
              )}
              {osv && (osv.findings||[]).length > 0 && (
                <div className="mb-4 bg-siem-surface border border-siem-border rounded-xl max-h-[320px] overflow-y-auto">
                  {osv.findings.map((f,i) => (
                    <div key={i} className="px-4 py-2 border-b border-siem-border/15 last:border-0 text-[11px]">
                      <span className="font-mono text-siem-text">{f.title || f.id}</span>
                      <span className="ml-2 text-siem-muted">{f.severity}</span>
                      {f.fix && <span className="ml-2 text-emerald-400">{f.fix}</span>}
                      <span className="ml-2 text-siem-muted/60">{f.rule_id}</span>
                    </div>
                  ))}
                </div>
              )}
              <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                <div className="grid px-4 py-2 border-b border-siem-border/40 bg-siem-bg/40" style={{gridTemplateColumns:"1fr 160px 80px"}}>
                  {["Package","Version","Manager"].map(h => (
                    <span key={h} className="text-[9px] uppercase tracking-wider text-siem-muted/50 font-semibold">{h}</span>
                  ))}
                </div>
                <div className="max-h-[600px] overflow-y-auto">
                  {packages.map((pkg,i) => (
                    <div key={i} className="grid px-4 py-2 border-b border-siem-border/15 last:border-0 text-[11px]" style={{gridTemplateColumns:"1fr 160px 80px"}}>
                      <span className="font-mono text-siem-text truncate">{pkg.name}</span>
                      <span className="font-mono text-siem-muted">{pkg.version}</span>
                      <span className="text-siem-muted/50 uppercase text-[9px]">{pkg.manager}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>)}
          </div>
        )}

        {/* ── AI Analysis ── */}
        {activeSection === "ai" && (
          <div className="p-5 space-y-4">
            {aiError && (
              <div className="bg-red-950/20 border border-red-800/30 rounded-xl p-4 text-xs text-red-400">
                {aiError} — ensure Groq or Anthropic API key is configured in Settings.
              </div>
            )}

            {!aiResult && !aiLoading && !aiError && (
              <div className="flex flex-col items-center justify-center py-16 gap-4">
                <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-violet-600/20 to-purple-600/20 border border-violet-500/30 flex items-center justify-center">
                  <Zap size={28} className="text-violet-400"/>
                </div>
                <div className="text-center">
                  <div className="text-sm font-semibold text-siem-text mb-1">Enterprise AI Analysis</div>
                  <div className="text-xs text-siem-muted/70 max-w-sm text-center mb-4">
                    AI analyses port scan data, service versions, and security findings to produce
                    CVE matches, risk scoring, and a prioritised remediation plan.
                  </div>
                  <button onClick={runAIAnalysis}
                    className="flex items-center gap-2 mx-auto px-5 py-2.5 rounded-xl text-sm font-semibold bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-500 hover:to-purple-500 text-white transition-all shadow-lg shadow-violet-900/30">
                    <Zap size={14}/> Run AI Analysis
                  </button>
                </div>
              </div>
            )}

            {aiLoading && (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <div className="w-12 h-12 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center">
                  <RefreshCw size={20} className="text-violet-400 animate-spin"/>
                </div>
                <div className="text-sm text-siem-muted">Analysing {ports.length} ports, {packages.length} packages…</div>
                <div className="text-xs text-siem-muted/40">This takes 10-30 seconds</div>
              </div>
            )}

            {aiResult && (
              <div className="space-y-5">
                {/* Risk score + executive summary */}
                <div className="bg-siem-surface border border-siem-border rounded-xl p-5">
                  <div className="flex items-start gap-5">
                    {aiResult.risk_score != null && (
                      <div className="relative shrink-0 w-20 h-20">
                        <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
                          <circle cx="40" cy="40" r="32" fill="none" stroke="#21262d" strokeWidth="7"/>
                          <circle cx="40" cy="40" r="32" fill="none"
                            stroke={aiResult.risk_score>=80?"#ef4444":aiResult.risk_score>=60?"#f97316":aiResult.risk_score>=40?"#eab308":"#3fb950"}
                            strokeWidth="7"
                            strokeDasharray={`${2*Math.PI*32}`}
                            strokeDashoffset={`${2*Math.PI*32*(1-aiResult.risk_score/100)}`}
                            strokeLinecap="round"/>
                        </svg>
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                          <span className="text-xl font-bold font-mono text-siem-text">{aiResult.risk_score}</span>
                          <span className="text-[9px] text-siem-muted">risk</span>
                        </div>
                      </div>
                    )}
                    <div className="flex-1">
                      {aiResult.risk_label && (
                        <div className="text-xs font-bold uppercase tracking-wider text-siem-muted mb-1">{aiResult.risk_label} Risk</div>
                      )}
                      <p className="text-sm text-siem-text leading-relaxed">{aiResult.executive_summary}</p>
                    </div>
                  </div>
                </div>

                {/* Attack surface */}
                {aiResult.attack_surface_summary && (
                  <div className="bg-orange-950/15 border border-orange-800/25 rounded-xl p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <AlertTriangle size={13} className="text-orange-400"/>
                      <span className="text-xs font-semibold text-orange-400 uppercase tracking-wide">Attack Surface</span>
                    </div>
                    <p className="text-xs text-siem-muted/90 leading-relaxed">{aiResult.attack_surface_summary}</p>
                  </div>
                )}

                {/* Immediate actions */}
                {aiResult.immediate_actions?.length > 0 && (
                  <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                    <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3">Immediate Actions Required</div>
                    <div className="space-y-2">
                      {aiResult.immediate_actions.map((action, i) => (
                        <div key={i} className="flex items-start gap-3">
                          <span className="w-5 h-5 rounded-full bg-red-500/20 border border-red-500/30 text-red-400 text-[9px] font-bold flex items-center justify-center shrink-0 mt-0.5">{i+1}</span>
                          <span className="text-xs text-siem-text">{action}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Critical findings */}
                {aiResult.critical_findings?.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-[10px] uppercase tracking-wider text-red-400/80 font-semibold">Critical Findings</div>
                    {aiResult.critical_findings.map((f,i) => <AIFindingCard key={i} finding={f} type="critical"/>)}
                  </div>
                )}

                {/* High findings */}
                {aiResult.high_findings?.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-[10px] uppercase tracking-wider text-orange-400/80 font-semibold">High Risk Findings</div>
                    {aiResult.high_findings.map((f,i) => <AIFindingCard key={i} finding={f} type="high"/>)}
                  </div>
                )}

                {/* Medium findings */}
                {aiResult.medium_findings?.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-[10px] uppercase tracking-wider text-yellow-400/80 font-semibold">Medium Risk Findings</div>
                    {aiResult.medium_findings.map((f,i) => <AIFindingCard key={i} finding={f} type="medium"/>)}
                  </div>
                )}

                {/* Outdated software */}
                {aiResult.outdated_software?.length > 0 && (
                  <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                    <div className="px-4 py-2.5 border-b border-siem-border flex items-center gap-2">
                      <Bug size={13} className="text-orange-400"/>
                      <span className="text-xs font-semibold text-siem-text">Outdated Software</span>
                    </div>
                    {aiResult.outdated_software.map((sw,i) => (
                      <div key={i} className="px-4 py-3 border-b border-siem-border/20 last:border-0">
                        <div className="flex items-center gap-3 mb-1.5">
                          <span className="text-sm font-mono font-semibold text-siem-text">{sw.name}</span>
                          <span className="text-[10px] font-mono text-red-400 bg-red-950/20 border border-red-800/30 rounded px-1.5 py-0.5">{sw.installed_version}</span>
                          {sw.recommended_version && (
                            <><span className="text-siem-muted/40 text-xs">→</span>
                            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/20 border border-emerald-800/30 rounded px-1.5 py-0.5">{sw.recommended_version}</span></>
                          )}
                          {sw.cves?.map(cve => (
                            <a key={cve} href={cveHref(cve)} target="_blank" rel="noreferrer"
                              className="text-[9px] font-mono text-violet-400 border border-violet-800/40 bg-violet-950/20 rounded px-1.5 py-0.5 hover:opacity-80">
                              {cve} ↗
                            </a>
                          ))}
                        </div>
                        {sw.upgrade_command && (
                          <code className="text-[10px] font-mono text-emerald-400/80">{sw.upgrade_command}</code>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Remediation plan */}
                {aiResult.remediation_plan?.length > 0 && (
                  <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                    <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3">Remediation Plan</div>
                    <div className="space-y-3">
                      {aiResult.remediation_plan.map((step,i) => (
                        <div key={i} className="flex items-start gap-3">
                          <span className="w-6 h-6 rounded-lg bg-siem-bg border border-siem-border text-[10px] font-bold text-siem-accent flex items-center justify-center shrink-0 mt-0.5">{step.priority}</span>
                          <div className="flex-1">
                            <div className="text-xs text-siem-text font-medium">{step.action}</div>
                            <div className="flex gap-3 mt-1">
                              {step.effort && <span className="text-[9px] text-siem-muted">Effort: {step.effort}</span>}
                              {step.impact && <span className="text-[9px] text-siem-muted/60">{step.impact}</span>}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Compliance + positives */}
                <div className="grid grid-cols-2 gap-3">
                  {aiResult.compliance_notes && (
                    <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                      <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-2">Compliance Notes</div>
                      <p className="text-xs text-siem-muted/80">{aiResult.compliance_notes}</p>
                    </div>
                  )}
                  {aiResult.positive_findings?.length > 0 && (
                    <div className="bg-emerald-950/15 border border-emerald-800/25 rounded-xl p-4">
                      <div className="text-[10px] uppercase tracking-wider text-emerald-400/70 font-semibold mb-2">✓ Good Practices</div>
                      <ul className="space-y-1">
                        {aiResult.positive_findings.map((p,i) => (
                          <li key={i} className="flex items-start gap-2 text-xs text-siem-muted/80">
                            <CheckCircle size={11} className="text-emerald-400/60 mt-0.5 shrink-0"/>{p}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Re-run button */}
                <div className="flex justify-end pt-2">
                  <button onClick={runAIAnalysis}
                    className="flex items-center gap-2 px-3 py-1.5 text-xs text-violet-400 border border-violet-500/30 rounded-lg hover:bg-violet-500/10 transition-colors">
                    <RefreshCw size={11}/> Re-run analysis
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Tab: Root Cause Analysis ──────────────────────────────────────────────────
export function TabRCA({ agent }) {
  const [description, setDescription] = useState('')
  const [incidentAt,  setIncidentAt]  = useState(() => {
    const d = new Date(); d.setMinutes(0, 0, 0)
    return d.toISOString().slice(0, 16)
  })
  const [running,  setRunning]  = useState(false)
  const [rca,      setRca]      = useState(null)
  const [error,    setError]    = useState(null)
  const [chatInput,setChatInput]= useState('')
  const [chatHistory, setChatHistory] = useState([])
  const [chatLoading, setChatLoading] = useState(false)
  const [context,  setContext]  = useState(null)
  const [phase,    setPhase]    = useState('form') // form | loading | report
  const chatEndRef = useRef(null)

  // Load cache + context on mount
  useEffect(() => {
    api.get(`/api/v1/agents/${encodeURIComponent(agent.hostname)}/rca/cache`)
      .then(r => {
        if (r.data?.rca) {
          try {
            const clean = r.data.rca.replace(/```json\n?|```\n?/g, '').trim()
            const parsed = JSON.parse(clean)
            setRca(parsed); setPhase('report')
          } catch (e) {}
        }
      }).catch(() => {})
  }, [agent.hostname])

  const loadContext = () => {
    const iso = new Date(incidentAt).toISOString()
    api.get(`/api/v1/agents/${encodeURIComponent(agent.hostname)}/rca/context?incident_at=${encodeURIComponent(iso)}`)
      .then(r => setContext(r.data))
      .catch(() => {})
  }

  useEffect(() => { loadContext() }, [incidentAt, agent.hostname])

  const runRCA = async () => {
    if (!description.trim()) return
    setRunning(true); setError(null); setRca(null); setChatHistory([])
    setPhase('loading')
    try {
      const { data } = await api.post(
        `/api/v1/agents/${encodeURIComponent(agent.hostname)}/rca`,
        { host: agent.hostname, description, incident_at: new Date(incidentAt).toISOString() },
        { timeout: 90000 }
      )
      const text = data.content?.find(b => b.type === 'text')?.text || ''
      const clean = text.replace(/```json\n?|```\n?/g, '').trim()
      const s = clean.indexOf('{'), e = clean.lastIndexOf('}')
      const parsed = JSON.parse(s !== -1 ? clean.slice(s, e+1) : clean)
      setRca(parsed); setPhase('report')
    } catch (e) {
      setError(e.response?.data?.error || 'RCA failed'); setPhase('form')
    } finally { setRunning(false) }
  }

  const sendChat = async () => {
    const q = chatInput.trim(); if (!q || chatLoading) return
    const newHistory = [...chatHistory, { role: 'user', content: q }]
    setChatHistory(newHistory); setChatInput(''); setChatLoading(true)
    try {
      const { data } = await api.post(
        `/api/v1/agents/${encodeURIComponent(agent.hostname)}/rca`,
        { host: agent.hostname, description, incident_at: new Date(incidentAt).toISOString(),
          question: q, history: chatHistory },
        { timeout: 60000 }
      )
      const text = data.content?.find(b => b.type === 'text')?.text || ''
      setChatHistory([...newHistory, { role: 'assistant', content: text }])
    } catch (e) {
      setChatHistory([...newHistory, { role: 'assistant', content: '⚠ ' + (e.response?.data?.error || 'Failed') }])
    } finally {
      setChatLoading(false)
      setTimeout(() => chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50)
    }
  }

  const PHASE_COLORS = {
    'Initial Access':   { bg: 'bg-red-950/30',    border: 'border-red-800/40',    text: 'text-red-400',    dot: 'bg-red-400' },
    'Execution':        { bg: 'bg-orange-950/25',  border: 'border-orange-800/35', text: 'text-orange-400', dot: 'bg-orange-400' },
    'Persistence':      { bg: 'bg-yellow-950/20',  border: 'border-yellow-800/30', text: 'text-yellow-400', dot: 'bg-yellow-400' },
    'Privilege Escalation': { bg: 'bg-purple-950/25', border: 'border-purple-800/35', text: 'text-purple-400', dot: 'bg-purple-400' },
    'Defense Evasion':  { bg: 'bg-blue-950/25',    border: 'border-blue-800/35',   text: 'text-blue-400',   dot: 'bg-blue-400' },
    'Lateral Movement': { bg: 'bg-cyan-950/25',    border: 'border-cyan-800/35',   text: 'text-cyan-400',   dot: 'bg-cyan-400' },
    'Collection':       { bg: 'bg-teal-950/25',    border: 'border-teal-800/35',   text: 'text-teal-400',   dot: 'bg-teal-400' },
    'Exfiltration':     { bg: 'bg-pink-950/30',    border: 'border-pink-800/40',   text: 'text-pink-400',   dot: 'bg-pink-400' },
    'Impact':           { bg: 'bg-red-950/40',     border: 'border-red-700/50',    text: 'text-red-300',    dot: 'bg-red-300' },
  }
  const getPhaseStyle = phaseName => PHASE_COLORS[phaseName] || { bg:'bg-siem-surface', border:'border-siem-border', text:'text-siem-muted', dot:'bg-siem-muted' }

  const CONF_COLOR = { High: 'text-emerald-400', Medium: 'text-yellow-400', Low: 'text-orange-400' }

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Top bar */}
      <div className="shrink-0 px-5 py-3 border-b border-siem-border bg-siem-surface">
        <div className="flex items-center gap-3">
          <div className="flex-1">
            <div className="text-xs font-semibold text-siem-text">Root Cause Analysis</div>
            <div className="text-[10px] text-siem-muted">AI-powered incident investigation for {agent.hostname}</div>
          </div>
          {phase === 'report' && (
            <button onClick={() => { setPhase('form'); setRca(null); setChatHistory([]) }}
              className="text-[10px] text-siem-muted border border-siem-border rounded-lg px-3 py-1.5 hover:text-siem-text transition-colors">
              New RCA
            </button>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">

        {/* ── Form ── */}
        {(phase === 'form' || phase === 'loading') && (
          <div className="p-5 space-y-4">

            {/* Context preview */}
            {context && (
              <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3">
                  What will be analysed (±48h window)
                </div>
                <div className="grid grid-cols-3 gap-3">
                  {[
                    ['Alerts', context.alert_count, 'text-orange-400'],
                    ['Events', context.event_count, 'text-siem-accent'],
                    ['Vuln Scan', context.has_vuln ? 'Yes' : 'No', context.has_vuln ? 'text-emerald-400' : 'text-siem-muted'],
                  ].map(([label, val, color]) => (
                    <div key={label} className="bg-siem-bg border border-siem-border rounded-lg p-3 text-center">
                      <div className={`text-xl font-bold font-mono ${color}`}>{val}</div>
                      <div className="text-[9px] text-siem-muted uppercase tracking-wide mt-0.5">{label}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-2 text-[10px] text-siem-muted/50 text-center">
                  Events sampled: top 60 by severity, deduplicated · Vuln scan: ports & findings only, no package list
                </div>
              </div>
            )}

            {/* Incident time */}
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">
                When did the incident occur?
              </label>
              <input type="datetime-local" value={incidentAt}
                onChange={e => setIncidentAt(e.target.value)}
                className="w-full bg-siem-bg border border-siem-border rounded-xl px-4 py-2.5 text-sm text-siem-text focus:outline-none focus:border-siem-accent/50 font-mono"/>
            </div>

            {/* Description */}
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">
                Describe what you observed *
              </label>
              <textarea rows={4} value={description} onChange={e => setDescription(e.target.value)}
                disabled={phase === 'loading'}
                placeholder="e.g. Users reported the server became unresponsive at 2pm. We noticed unusual outbound traffic and several security alerts fired. A process named 'svchost.exe' was found running from an unusual path..."
                className="w-full bg-siem-bg border border-siem-border rounded-xl px-4 py-3 text-sm text-siem-text focus:outline-none focus:border-siem-accent/50 resize-none placeholder-siem-muted/30"/>
            </div>

            {error && (
              <div className="bg-red-950/20 border border-red-800/30 rounded-xl p-3 text-xs text-red-400">{error}</div>
            )}

            {phase === 'loading' ? (
              <div className="bg-siem-bg border border-siem-accent/20 rounded-xl p-5 space-y-3">
                <div className="flex items-center gap-2 mb-1">
                  <RefreshCw size={13} className="text-siem-accent animate-spin"/>
                  <span className="text-xs font-semibold text-siem-accent">Investigating incident…</span>
                </div>
                {['Gathering alerts and events', 'Correlating security signals', 'Mapping attack chain', 'Determining root cause', 'Writing RCA report'].map((msg, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-siem-accent/60 animate-pulse" style={{animationDelay:(i*400)+'ms'}}/>
                    <span className="text-[11px] text-siem-muted">{msg}…</span>
                  </div>
                ))}
              </div>
            ) : (
              <button onClick={runRCA} disabled={!description.trim()}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-500 hover:to-purple-500 disabled:opacity-40 disabled:cursor-not-allowed text-white transition-all shadow-lg shadow-violet-900/30">
                <Search size={15}/> Run Root Cause Analysis
              </button>
            )}

            {/* Privacy note */}
            <div className="bg-siem-bg border border-siem-border/50 rounded-xl p-3">
              <div className="text-[9px] text-siem-muted/60 leading-relaxed">
                <span className="text-siem-muted/80 font-medium">What's sent to AI:</span> Alert titles, event types, process names, command lines, IPs, file paths from the ±48h window.
                No file contents, no passwords, no customer data — only security metadata your SIEM already captures.
                Results are cached locally in your database and never leave your infrastructure except for the AI API call.
              </div>
            </div>
          </div>
        )}

        {/* ── Report ── */}
        {phase === 'report' && rca && (
          <div className="p-5 space-y-5">

            {/* Incident header */}
            <div className="bg-siem-surface border border-siem-border rounded-xl p-5">
              <div className="flex items-start justify-between gap-4 mb-3">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 mb-1">Root Cause Analysis Report</div>
                  <div className="text-base font-bold text-siem-text">{rca.incident_title || 'Security Incident'}</div>
                </div>
                {rca.confidence && (
                  <div className="shrink-0 text-center">
                    <div className={`text-sm font-bold ${CONF_COLOR[rca.confidence] || 'text-siem-muted'}`}>
                      {rca.confidence}
                    </div>
                    <div className="text-[9px] text-siem-muted uppercase tracking-wide">Confidence</div>
                  </div>
                )}
              </div>
              {rca.root_cause && (
                <div className="bg-siem-bg border border-siem-border rounded-lg p-3">
                  <div className="text-[9px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-1.5">Root Cause</div>
                  <p className="text-sm text-siem-text leading-relaxed font-medium">{rca.root_cause}</p>
                </div>
              )}
              {rca.confidence_reason && (
                <p className="text-[11px] text-siem-muted mt-2 leading-relaxed">{rca.confidence_reason}</p>
              )}
            </div>

            {/* Executive Summary */}
            {rca.executive_summary && (
              <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-2 flex items-center gap-1.5">
                  <Shield size={11}/> Executive Summary
                </div>
                <p className="text-sm text-siem-text leading-relaxed">{rca.executive_summary}</p>
              </div>
            )}

            {/* Attack chain — visual flow */}
            {rca.attack_chain?.length > 0 && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3">Attack Chain</div>
                <div className="space-y-2">
                  {rca.attack_chain.map((step, i) => {
                    const st = getPhaseStyle(step.phase)
                    return (
                      <div key={i} className="flex items-stretch gap-3">
                        {/* Connector */}
                        <div className="flex flex-col items-center shrink-0 w-8">
                          <div className={`w-7 h-7 rounded-full flex items-center justify-center border text-[9px] font-bold ${st.bg} ${st.border} ${st.text}`}>
                            {i + 1}
                          </div>
                          {i < rca.attack_chain.length - 1 && (
                            <div className="w-px flex-1 bg-siem-border/40 mt-1"/>
                          )}
                        </div>
                        {/* Card */}
                        <div className={`flex-1 rounded-xl border p-3 mb-1 ${st.bg} ${st.border}`}>
                          <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                            <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${st.bg} ${st.border} ${st.text}`}>
                              {step.phase}
                            </span>
                            {step.mitre && (
                              <a href={`https://attack.mitre.org/techniques/${step.mitre.replace('.','/')}`}
                                target="_blank" rel="noreferrer"
                                className="text-[9px] font-mono text-violet-400 border border-violet-800/40 bg-violet-950/20 rounded px-1.5 py-0.5 hover:opacity-80">
                                {step.mitre} ↗
                              </a>
                            )}
                          </div>
                          <div className={`text-xs font-semibold mb-1 ${st.text}`}>{step.technique}</div>
                          {step.description && (
                            <div className="text-[11px] text-siem-text/80 leading-relaxed mb-1.5">{step.description}</div>
                          )}
                          {step.evidence && (
                            <div className="text-[10px] text-siem-muted/80 leading-snug italic border-l-2 border-siem-border/50 pl-2">Evidence: {step.evidence}</div>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Timeline */}
            {rca.timeline?.length > 0 && (
              <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-3 flex items-center gap-2">
                  <Clock size={11}/> Incident Timeline
                </div>
                <div className="space-y-2">
                  {rca.timeline.map((t, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <div className="flex flex-col items-center shrink-0">
                        <span className="text-[9px] font-mono text-siem-accent bg-siem-accent/10 border border-siem-accent/20 rounded px-2 py-0.5 whitespace-nowrap">{t.time}</span>
                        {i < rca.timeline.length - 1 && <div className="w-px h-3 bg-siem-border/30 mt-1"/>}
                      </div>
                      <div className="flex-1 pb-1">
                        <div className="text-xs text-siem-text">{t.event}</div>
                        {t.significance && <div className="text-[10px] text-siem-muted/60 mt-0.5">{t.significance}</div>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Key indicators */}
            {rca.key_indicators?.length > 0 && (
              <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                <div className="px-4 py-2.5 border-b border-siem-border/40 text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold flex items-center gap-2">
                  <Activity size={11}/> Key Indicators of Compromise
                </div>
                {rca.key_indicators.map((ioc, i) => (
                  <div key={i} className={`px-4 py-2.5 border-b border-siem-border/20 last:border-0 ${i%2?'bg-white/[0.01]':''}`}>
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[9px] uppercase font-semibold text-siem-accent bg-siem-accent/10 border border-siem-accent/20 rounded px-1.5 py-0.5">{ioc.type}</span>
                      <code className="text-[11px] font-mono text-siem-text break-all">{ioc.indicator}</code>
                    </div>
                    {ioc.significance && <div className="text-[10px] text-siem-muted/60 pl-14">{ioc.significance}</div>}
                  </div>
                ))}
              </div>
            )}

            {/* Impact */}
            {rca.impact_assessment && (
              <div className="bg-red-950/15 border border-red-800/25 rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-red-400/70 font-semibold mb-3 flex items-center gap-2">
                  <AlertTriangle size={11}/> Impact Assessment
                </div>
                <div className="space-y-2">
                  {rca.impact_assessment.systems_affected?.length > 0 && (
                    <div>
                      <div className="text-[9px] text-siem-muted/60 uppercase mb-1">Systems Affected</div>
                      <div className="flex gap-1.5 flex-wrap">
                        {rca.impact_assessment.systems_affected.map((s,i) => (
                          <span key={i} className="text-[10px] font-mono bg-red-950/20 border border-red-800/30 text-red-300 rounded px-2 py-0.5">{s}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {rca.impact_assessment.data_at_risk && (
                    <div>
                      <div className="text-[9px] text-siem-muted/60 uppercase mb-0.5">Data at Risk</div>
                      <p className="text-xs text-siem-text">{rca.impact_assessment.data_at_risk}</p>
                    </div>
                  )}
                  {rca.impact_assessment.business_impact && (
                    <div>
                      <div className="text-[9px] text-siem-muted/60 uppercase mb-0.5">Business Impact</div>
                      <p className="text-xs text-siem-text">{rca.impact_assessment.business_impact}</p>
                    </div>
                  )}
                  {rca.impact_assessment.severity && (
                    <div className="flex items-center gap-2 mt-1">
                      <div className="text-[9px] text-siem-muted/60 uppercase">Severity:</div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                        rca.impact_assessment.severity === 'Critical' ? 'bg-red-900/40 border-red-700 text-red-300' :
                        rca.impact_assessment.severity === 'High' ? 'bg-orange-900/30 border-orange-700 text-orange-300' :
                        'bg-yellow-900/20 border-yellow-700 text-yellow-300'
                      }`}>{rca.impact_assessment.severity}</span>
                      {rca.impact_assessment.severity_rationale && (
                        <span className="text-[10px] text-siem-muted/60">— {rca.impact_assessment.severity_rationale}</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Contributing factors */}
            {rca.contributing_factors?.length > 0 && (
              <div className="bg-yellow-950/15 border border-yellow-800/25 rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-yellow-400/70 font-semibold mb-2">Contributing Factors</div>
                <ul className="space-y-1.5">
                  {rca.contributing_factors.map((f,i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-siem-text">
                      <span className="text-yellow-400/60 shrink-0 mt-0.5">▸</span>{f}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Remediation */}
            {rca.remediation && (
              <div className="bg-emerald-950/10 border border-emerald-800/20 rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-emerald-400/70 font-semibold mb-3 flex items-center gap-2">
                  <CheckCircle size={11}/> Remediation Plan
                </div>
                {[
                  ['Immediate (now)', rca.remediation.immediate, 'text-red-400'],
                  ['Short-term (24-48h)', rca.remediation.short_term, 'text-yellow-400'],
                  ['Long-term (systemic)', rca.remediation.long_term, 'text-emerald-400'],
                ].map(([label, items, color]) => items?.length > 0 && (
                  <div key={label} className="mb-3 last:mb-0">
                    <div className={`text-[9px] uppercase font-semibold mb-1.5 ${color}`}>{label}</div>
                    <ul className="space-y-1">
                      {items.map((a,i) => (
                        <li key={i} className="flex items-start gap-2 text-xs text-siem-text">
                          <span className="w-4 h-4 rounded bg-siem-bg border border-siem-border text-[8px] font-bold text-siem-muted flex items-center justify-center shrink-0 mt-0.5">{i+1}</span>
                          {a}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            )}

            {/* Detection gaps */}
            {rca.detection_gaps?.length > 0 && (
              <div className="bg-blue-950/15 border border-blue-800/25 rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-blue-400/70 font-semibold mb-2 flex items-center gap-1.5">
                  <Search size={11}/> Detection Gaps
                </div>
                <ul className="space-y-1.5">
                  {rca.detection_gaps.map((g,i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-siem-text">
                      <span className="text-blue-400/60 shrink-0 mt-0.5">⚡</span>{g}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Lessons learned */}
            {rca.lessons_learned?.length > 0 && (
              <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-siem-muted/60 font-semibold mb-2">Lessons Learned</div>
                <ul className="space-y-1.5">
                  {rca.lessons_learned.map((l,i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-siem-muted">
                      <span className="text-siem-accent shrink-0 mt-0.5">→</span>{l}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* AI questions */}
            {rca.questions_for_analyst?.length > 0 && (
              <div className="bg-violet-950/15 border border-violet-800/25 rounded-xl p-4">
                <div className="text-[10px] uppercase tracking-wider text-violet-400/70 font-semibold mb-2">AI Questions for You</div>
                <ul className="space-y-2">
                  {rca.questions_for_analyst.map((q,i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-[10px] text-violet-400/60 shrink-0 mt-0.5">?</span>
                      <button onClick={() => setChatInput(q)}
                        className="text-xs text-siem-text text-left hover:text-violet-400 transition-colors leading-relaxed">
                        {q}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Chat with AI about this RCA */}
            <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-siem-border/40 flex items-center gap-2">
                <MessageSquare size={13} className="text-siem-accent"/>
                <span className="text-sm font-semibold text-siem-text">Continue Investigation</span>
                <span className="text-[10px] text-siem-muted ml-1">— ask follow-up questions about this incident</span>
              </div>

              {/* Suggested questions */}
              {chatHistory.length === 0 && rca.questions_for_analyst?.length > 0 && (
                <div className="px-4 py-3 border-b border-siem-border/30 flex flex-wrap gap-2">
                  {rca.questions_for_analyst.slice(0, 3).map((q, i) => (
                    <button key={i} onClick={() => setChatInput(q)}
                      className="text-[10px] text-left px-2.5 py-1.5 bg-violet-950/20 border border-violet-800/30 text-violet-300 rounded-lg hover:bg-violet-950/40 transition-colors max-w-xs truncate">
                      💡 {q}
                    </button>
                  ))}
                </div>
              )}

              {/* Messages */}
              <div className="p-4 space-y-4 max-h-[500px] overflow-y-auto">
                {chatHistory.length === 0 ? (
                  <div className="text-sm text-siem-muted/40 italic text-center py-4">
                    Ask anything about this incident — what happened, why, how to respond…
                  </div>
                ) : chatHistory.map((msg, i) => (
                  <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
                    {/* Avatar */}
                    <div className={`w-7 h-7 rounded-full flex items-center justify-center shrink-0 text-[10px] font-bold border ${
                      msg.role === 'user'
                        ? 'bg-violet-950/30 border-violet-800/50 text-violet-300'
                        : 'bg-siem-accent/10 border-siem-accent/30 text-siem-accent'
                    }`}>
                      {msg.role === 'user' ? 'You' : 'AI'}
                    </div>
                    {/* Message bubble */}
                    <div className={`flex-1 rounded-xl px-4 py-3 ${
                      msg.role === 'user'
                        ? 'bg-violet-950/15 border border-violet-800/25 text-siem-text'
                        : 'bg-siem-bg border border-siem-border/60'
                    }`}>
                      {msg.role === 'assistant' ? (
                        // Render AI response with basic markdown-like formatting
                        <div className="space-y-2">
                          {msg.content.split('\n\n').filter(Boolean).map((para, pi) => (
                            <p key={pi} className="text-sm text-siem-text leading-relaxed">
                              {para.split('\n').map((line, li) => (
                                <span key={li}>
                                  {li > 0 && <br/>}
                                  {line}
                                </span>
                              ))}
                            </p>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-siem-text leading-relaxed">{msg.content}</p>
                      )}
                    </div>
                  </div>
                ))}
                {chatLoading && (
                  <div className="flex gap-3">
                    <div className="w-7 h-7 rounded-full bg-siem-accent/10 border border-siem-accent/30 flex items-center justify-center text-[10px] font-bold text-siem-accent shrink-0">AI</div>
                    <div className="flex-1 bg-siem-bg border border-siem-border/60 rounded-xl px-4 py-3">
                      <div className="flex gap-1.5 items-center h-5">
                        {[0,1,2].map(i => (
                          <div key={i} className="w-2 h-2 rounded-full bg-siem-accent/60 animate-bounce"
                            style={{animationDelay:(i*150)+'ms'}}/>
                        ))}
                        <span className="text-[10px] text-siem-muted ml-1">Analysing…</span>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={chatEndRef}/>
              </div>

              <div className="border-t border-siem-border p-3 flex gap-2 items-end">
                <input value={chatInput} onChange={e => setChatInput(e.target.value)}
                  onKeyDown={e => { if (e.key==='Enter' && !e.shiftKey) { e.preventDefault(); sendChat() }}}
                  placeholder="Ask anything about this incident… (Enter to send)"
                  className="flex-1 bg-siem-bg border border-siem-border rounded-xl px-4 py-2.5 text-sm text-siem-text placeholder-siem-muted/30 outline-none focus:border-siem-accent/60 transition-colors"
                  disabled={chatLoading}/>
                <button onClick={sendChat} disabled={!chatInput.trim() || chatLoading}
                  className="px-4 py-2.5 bg-siem-accent text-white text-sm font-medium rounded-xl hover:bg-siem-accent/80 disabled:opacity-40 transition-colors shrink-0">
                  {chatLoading ? '…' : 'Send'}
                </button>
              </div>
            </div>

          </div>
        )}
      </div>
    </div>
  )
}

