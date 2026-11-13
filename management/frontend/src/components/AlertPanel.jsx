import { IPLink } from './IPLookup'
import AlertGraph from './AlertGraph'
import { useEffect, useState, useCallback, useRef } from 'react'
import { createPortal } from 'react-dom'
import { Bell, CheckCircle, XCircle, RefreshCw, X,
         User, MessageSquare, Clock, AlertTriangle, UserCheck, FileText,
         Shield, ExternalLink, ChevronRight, Hash, Zap, Target,
         Eye, Activity, Search, GitBranch } from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { SeverityBadge } from './SeverityBadge'

const SEV_COLOR = { 5:'#ef4444', 4:'#f97316', 3:'#eab308', 2:'#3b82f6', 1:'#475569' }
const SEV_LABEL = { 5:'Critical', 4:'High', 3:'Medium', 2:'Low', 1:'Info' }

function StatusBadge({ status }) {
  const s = {
    open:         'bg-red-900/30 text-red-400 border-red-800',
    acknowledged: 'bg-yellow-900/30 text-yellow-400 border-yellow-800',
    closed:       'bg-siem-bg text-siem-muted border-siem-border',
  }
  return (
    <span className={`text-[9px] px-2 py-0.5 rounded-full border font-semibold uppercase ${s[status] || s.closed}`}>
      {status === 'open' && <span className="inline-block w-1 h-1 rounded-full bg-red-400 animate-pulse mr-1"/>}
      {status}
    </span>
  )
}

// ── Risk score ring ───────────────────────────────────────────────────────────
function RiskRing({ score, fp }) {
  const riskColor = score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#eab308' : '#3b82f6'
  const fpColor   = fp >= 60 ? '#3fb950' : fp >= 30 ? '#eab308' : '#ef4444'
  return (
    <div className="flex items-center gap-5">
      {/* Risk score */}
      <div className="flex flex-col items-center gap-1">
        <div className="relative w-16 h-16">
          <svg viewBox="0 0 64 64" className="w-full h-full -rotate-90">
            <circle cx="32" cy="32" r="26" fill="none" stroke="#21262d" strokeWidth="6"/>
            <circle cx="32" cy="32" r="26" fill="none" stroke={riskColor} strokeWidth="6"
              strokeDasharray={`${2 * Math.PI * 26}`}
              strokeDashoffset={`${2 * Math.PI * 26 * (1 - score / 100)}`}
              strokeLinecap="round"/>
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-lg font-bold font-mono" style={{ color: riskColor }}>{score}</span>
          </div>
        </div>
        <span className="text-[9px] text-siem-muted uppercase tracking-wide">Risk Score</span>
      </div>

      {/* FP probability */}
      <div className="flex flex-col items-center gap-1">
        <div className="relative w-16 h-16">
          <svg viewBox="0 0 64 64" className="w-full h-full -rotate-90">
            <circle cx="32" cy="32" r="26" fill="none" stroke="#21262d" strokeWidth="6"/>
            <circle cx="32" cy="32" r="26" fill="none" stroke={fpColor} strokeWidth="6"
              strokeDasharray={`${2 * Math.PI * 26}`}
              strokeDashoffset={`${2 * Math.PI * 26 * (1 - fp / 100)}`}
              strokeLinecap="round"/>
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-lg font-bold font-mono" style={{ color: fpColor }}>{fp}%</span>
          </div>
        </div>
        <span className="text-[9px] text-siem-muted uppercase tracking-wide">False Positive</span>
      </div>
    </div>
  )
}

// ── Verdict badge ─────────────────────────────────────────────────────────────
function VerdictBadge({ verdict }) {
  const styles = {
    THREAT:       'bg-red-950/50 border-red-700 text-red-300',
    SUSPICIOUS:   'bg-orange-950/40 border-orange-700 text-orange-300',
    LIKELY_FP:    'bg-yellow-950/30 border-yellow-700 text-yellow-300',
    FALSE_POSITIVE:'bg-emerald-950/30 border-emerald-700 text-emerald-300',
  }
  const icons = {
    THREAT: '🔴', SUSPICIOUS: '🟠', LIKELY_FP: '🟡', FALSE_POSITIVE: '🟢'
  }
  const labels = {
    THREAT: 'Confirmed Threat', SUSPICIOUS: 'Suspicious',
    LIKELY_FP: 'Likely False Positive', FALSE_POSITIVE: 'False Positive'
  }
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full border ${styles[verdict] || styles.SUSPICIOUS}`}>
      {icons[verdict] || '🟠'} {labels[verdict] || verdict}
    </span>
  )
}

// ── Assign modal ──────────────────────────────────────────────────────────────
function AssignModal({ alert, users, onClose, onDone }) {
  const [assignTo, setAssignTo] = useState(alert.assigned_to || '')
  const [notes, setNotes]       = useState(alert.case_notes || '')
  const [saving, setSaving]     = useState(false)
  const [error, setError]       = useState('')

  const save = async () => {
    if (!assignTo.trim()) { setError('Select an analyst'); return }
    setSaving(true)
    try {
      await api.patch(`/api/v1/alerts/${alert.id}/assign`, { assigned_to: assignTo, notes })
      onDone(); onClose()
    } catch (e) { setError(e.response?.data?.error || 'Failed') }
    finally { setSaving(false) }
  }

  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm"
         onClick={e => { e.stopPropagation(); onClose() }}>
      <div className="bg-siem-surface border border-siem-border rounded-2xl p-6 w-full max-w-md shadow-2xl"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-4">
          <UserCheck size={15} className="text-siem-accent"/>
          <h2 className="text-sm font-bold text-siem-text">Assign to Analyst</h2>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={14}/></button>
        </div>
        <div className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 mb-4 text-xs text-siem-text truncate">{alert.title}</div>
        <div className="space-y-3">
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1.5">Analyst *</label>
            {users.length > 0 ? (
              <select value={assignTo} onChange={e => setAssignTo(e.target.value)}
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent">
                <option value="">— Select analyst —</option>
                {users.map(u => <option key={u.id} value={u.username}>{u.username} ({u.role})</option>)}
              </select>
            ) : (
              <input value={assignTo} onChange={e => setAssignTo(e.target.value)} placeholder="Username"
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"/>
            )}
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1.5">Notes</label>
            <textarea rows={3} value={notes} onChange={e => setNotes(e.target.value)}
              className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent resize-none"/>
          </div>
          {error && <div className="text-red-400 text-xs">{error}</div>}
          <div className="flex gap-2">
            <button onClick={save} disabled={saving || !assignTo}
              className="flex-1 text-xs bg-siem-accent hover:bg-siem-accent/90 disabled:opacity-40 text-white px-4 py-2 rounded-lg font-medium">
              {saving ? 'Assigning…' : 'Assign & Acknowledge'}
            </button>
            <button onClick={onClose} className="text-xs text-siem-muted border border-siem-border rounded-lg px-4 py-2">Cancel</button>
          </div>
        </div>
      </div>
    </div>, document.body
  )
}

// ── Close modal ───────────────────────────────────────────────────────────────
function CloseModal({ alert, onClose, onDone }) {
  const [comment, setComment] = useState(alert.review_comment || '')
  const [saving, setSaving]   = useState(false)
  const [error, setError]     = useState('')

  const save = async () => {
    if (!comment.trim()) { setError('Add a review comment'); return }
    setSaving(true)
    try {
      await api.patch(`/api/v1/alerts/${alert.id}/close-review`, { comment })
      onDone(); onClose()
    } catch (e) { setError(e.response?.data?.error || 'Failed') }
    finally { setSaving(false) }
  }

  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm"
         onClick={e => { e.stopPropagation(); onClose() }}>
      <div className="bg-siem-surface border border-siem-border rounded-2xl p-6 w-full max-w-md shadow-2xl"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-4">
          <XCircle size={15} className="text-siem-muted"/>
          <h2 className="text-sm font-bold text-siem-text">Close Alert</h2>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={14}/></button>
        </div>
        <div className="space-y-3">
          <textarea rows={4} value={comment} onChange={e => setComment(e.target.value)}
            placeholder="What was found, actions taken, resolution…"
            className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent resize-none"/>
          {error && <div className="text-red-400 text-xs">{error}</div>}
          <div className="flex gap-2">
            <button onClick={save} disabled={saving}
              className="flex-1 text-xs bg-emerald-900/40 border border-emerald-700 hover:bg-emerald-900/60 text-emerald-300 px-4 py-2 rounded-lg font-medium">
              {saving ? 'Closing…' : 'Close Alert'}
            </button>
            <button onClick={onClose} className="text-xs text-siem-muted border border-siem-border rounded-lg px-4 py-2">Cancel</button>
          </div>
        </div>
      </div>
    </div>, document.body
  )
}

// ── AI Analysis report ────────────────────────────────────────────────────────
function AIReport({ analysis, onRerun, loading }) {
  if (loading) return (
    <div className="bg-siem-bg border border-siem-accent/20 rounded-xl p-5 space-y-3">
      <div className="flex items-center gap-2 mb-1">
        <div className="w-4 h-4 rounded bg-siem-accent/20 flex items-center justify-center">
          <Zap size={10} className="text-siem-accent animate-pulse"/>
        </div>
        <span className="text-xs font-semibold text-siem-accent">Analysing alert…</span>
      </div>
      {['Checking threat indicators', 'Assessing false positive probability', 'Looking up MITRE techniques', 'Generating recommendations'].map((msg, i) => (
        <div key={i} className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full bg-siem-accent/60 animate-pulse" style={{ animationDelay: `${i * 300}ms` }}/>
          <span className="text-[11px] text-siem-muted">{msg}…</span>
        </div>
      ))}
    </div>
  )

  const a = analysis
  if (!a) return null

  return (
    <div className="space-y-3">

      {/* Header: scores + verdict */}
      <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <RiskRing score={a.risk_score ?? 50} fp={a.fp_probability ?? 50}/>
          <div className="flex-1 min-w-0 space-y-2">
            {a.verdict && <VerdictBadge verdict={a.verdict}/>}
            {a.summary && (
              <p className="text-sm text-siem-text leading-snug font-medium">{a.summary}</p>
            )}
          </div>
          <button onClick={onRerun}
            className="text-[10px] text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-2.5 py-1.5 transition-colors shrink-0">
            <RefreshCw size={10} className="inline mr-1"/>Re-run
          </button>
        </div>
      </div>

      {/* What happened */}
      {a.what_happened && (
        <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Eye size={12} className="text-siem-accent"/>
            <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">What Happened</span>
          </div>
          <p className="text-xs text-siem-text leading-relaxed">{a.what_happened}</p>
        </div>
      )}

      {/* Threat assessment */}
      {a.threat_assessment && (
        <div className={`rounded-xl p-4 border ${
          a.verdict === 'THREAT' ? 'bg-red-950/20 border-red-800/40' :
          a.verdict === 'SUSPICIOUS' ? 'bg-orange-950/15 border-orange-800/30' :
          a.verdict === 'FALSE_POSITIVE' ? 'bg-emerald-950/15 border-emerald-800/30' :
          'bg-yellow-950/15 border-yellow-800/25'
        }`}>
          <div className="flex items-center gap-2 mb-2">
            <Target size={12} className={
              a.verdict === 'THREAT' ? 'text-red-400' :
              a.verdict === 'SUSPICIOUS' ? 'text-orange-400' :
              a.verdict === 'FALSE_POSITIVE' ? 'text-emerald-400' : 'text-yellow-400'
            }/>
            <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Threat Assessment</span>
          </div>
          <p className="text-xs text-siem-text leading-relaxed">{a.threat_assessment}</p>
        </div>
      )}

      {/* False positive indicators */}
      {a.false_positive_indicators && (
        <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Search size={12} className="text-emerald-400"/>
            <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">False Positive Indicators</span>
          </div>
          <p className="text-xs text-siem-text leading-relaxed">{a.false_positive_indicators}</p>
        </div>
      )}

      {/* Hash analysis */}
      {a.hash_analysis && a.hash_analysis !== 'null' && (
        <div className="bg-purple-950/20 border border-purple-800/30 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Hash size={12} className="text-purple-400"/>
            <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Hash Intelligence</span>
          </div>
          <p className="text-xs text-siem-text leading-relaxed">{a.hash_analysis}</p>
        </div>
      )}

      {/* MITRE context */}
      {a.mitre_context && (
        <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Shield size={12} className="text-blue-400"/>
            <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">MITRE ATT&CK Context</span>
          </div>
          <p className="text-xs text-siem-text leading-relaxed">{a.mitre_context}</p>
        </div>
      )}

      {/* Affected system */}
      {a.affected_system && (
        <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Activity size={12} className="text-orange-400"/>
            <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Blast Radius</span>
          </div>
          <p className="text-xs text-siem-text leading-relaxed">{a.affected_system}</p>
        </div>
      )}

      {/* Attack timeline */}
      {a.timeline?.length > 0 && (
        <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Clock size={12} className="text-siem-accent"/>
            <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Attack Timeline</span>
          </div>
          <div className="space-y-2">
            {a.timeline.map((t, i) => (
              <div key={i} className="flex items-start gap-3">
                <div className="flex flex-col items-center shrink-0">
                  <span className="text-[9px] font-mono text-siem-accent bg-siem-accent/10 border border-siem-accent/20 rounded px-1.5 py-0.5 whitespace-nowrap">{t.time}</span>
                  {i < a.timeline.length - 1 && <div className="w-px h-4 bg-siem-border/50 mt-1"/>}
                </div>
                <p className="text-xs text-siem-text leading-snug pt-0.5">{t.event}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommended actions */}
      {a.recommended_actions?.length > 0 && (
        <div className="bg-emerald-950/15 border border-emerald-800/30 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <CheckCircle size={12} className="text-emerald-400"/>
            <span className="text-[10px] uppercase tracking-wider text-emerald-400/80 font-semibold">Recommended Actions</span>
          </div>
          <ol className="space-y-2">
            {a.recommended_actions.map((action, i) => (
              <li key={i} className="flex items-start gap-3">
                <span className="w-5 h-5 rounded-full bg-emerald-900/40 border border-emerald-700 text-emerald-400 text-[9px] font-bold flex items-center justify-center shrink-0 mt-0.5">{i+1}</span>
                <span className="text-xs text-siem-text leading-relaxed">{action}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Investigation questions */}
      {a.investigation_questions?.length > 0 && (
        <div className="bg-yellow-950/15 border border-yellow-800/25 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Search size={12} className="text-yellow-400"/>
            <span className="text-[10px] uppercase tracking-wider text-yellow-400/80 font-semibold">Investigation Questions</span>
          </div>
          <ul className="space-y-2">
            {a.investigation_questions.map((q, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-siem-muted">
                <ChevronRight size={11} className="text-yellow-400/60 mt-0.5 shrink-0"/>
                <span className="leading-relaxed">{q}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="text-[9px] text-siem-muted/40 text-center">AI analysis — verify independently before taking action</p>
    </div>
  )
}

// ── Main panel ────────────────────────────────────────────────────────────────
function AlertPanel({ alertId, users, onClose, onStatusChange, inline = false }) {
  const [data, setData]             = useState(null)
  const [loading, setLoading]       = useState(true)
  const [showAssign, setShowAssign] = useState(false)
  const [showClose, setShowClose]   = useState(false)
  const [editNotes, setEditNotes]   = useState(false)
  const [notes, setNotes]           = useState('')
  const [savingNotes, setSavingNotes] = useState(false)
  const [aiAnalysis, setAiAnalysis] = useState(null)
  const [aiLoading, setAiLoading]   = useState(false)
  const [aiError, setAiError]       = useState(null)
  const [chatHistory, setChatHistory] = useState([])
  const [chatInput, setChatInput]   = useState('')
  const [chatLoading, setChatLoading] = useState(false)
  const [activeTab, setActiveTab]   = useState('analysis') // analysis | details | raw
  const chatEndRef = useRef(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.get(`/api/v1/alerts/${alertId}`)
      setData(res.data)
      setNotes(res.data.alert?.case_notes || '')
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [alertId])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    const handler = e => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onClose])

  const alert = data?.alert
  const ev    = data?.related_event

  const buildContext = () => {
    const mitreMatch = alert?.title?.match(/\[([T]\d+[.\d]*)\]/)
    return {
      alert_id:     alert?.id || 0,
      title:        alert?.title || '',
      severity:     alert?.severity || 3,
      description:  alert?.description || '',
      host:         alert?.host || '',
      event_type:   alert?.event_type || '',
      process_name: ev?.process_name || '',
      command_line: ev?.command_line || '',
      user_name:    ev?.user_name || '',
      src_ip:       ev?.src_ip || '',
      dst_ip:       ev?.dst_ip || '',
      dst_port:     ev?.dst_port || 0,
      file_path:    ev?.file_path || '',
      file_hash:    ev?.file_hash || '',
      reg_key:      ev?.reg_key || '',
      reg_value:    ev?.reg_value || '',
      mitre:        mitreMatch ? mitreMatch[1] : '',
      category:     alert?.description?.match(/Category: ([^\n|]+)/)?.[1]?.trim() || '',
      raw_event:    ev?.raw ? JSON.stringify(ev.raw, null, 2) : '',
    }
  }

  // Load cached AI analysis or auto-run on first open
  useEffect(() => {
    if (!alert) return
    // If cached analysis exists in alert data, use it instantly
    if (alert.ai_analysis) {
      try {
        const cached = typeof alert.ai_analysis === 'string'
          ? JSON.parse(alert.ai_analysis.replace(/```json|```/g, '').trim())
          : alert.ai_analysis
        if (cached && typeof cached === 'object') {
          setAiAnalysis(cached)
          return
        }
      } catch (e) { /* fall through to auto-run */ }
    }
    // No cache — auto-run
    if (!aiAnalysis && !aiLoading) runAiAnalysis()
  }, [alert?.id])

  const runAiAnalysis = async () => {
    if (!alert) return
    setAiLoading(true)
    setAiError(null)
    setAiAnalysis(null)
    try {
      const response = await api.post('/api/v1/ai/analyse', buildContext())
      const text = response.data.content?.find(b => b.type === 'text')?.text || ''
      let jsonStr = text.replace(/```json|```/g, '').trim()
      const start = jsonStr.indexOf('{'), end = jsonStr.lastIndexOf('}')
      if (start !== -1 && end !== -1) jsonStr = jsonStr.slice(start, end + 1)
      setAiAnalysis(JSON.parse(jsonStr))
    } catch (err) {
      // Silently fail if no AI configured — don't show error
      const msg = err.response?.data?.error || ''
      if (!msg.includes('No AI provider') && !msg.includes('no AI provider')) {
        setAiError(msg || 'Analysis failed')
      }
    } finally { setAiLoading(false) }
  }

  const saveNotes = async () => {
    setSavingNotes(true)
    try { await api.patch(`/api/v1/alerts/${alertId}/notes`, { notes }); setEditNotes(false); load() }
    finally { setSavingNotes(false) }
  }

  const sendChat = async () => {
    const q = chatInput.trim()
    if (!q || chatLoading) return
    const newHistory = [...chatHistory, { role: 'user', content: q }]
    setChatHistory(newHistory); setChatInput(''); setChatLoading(true)
    try {
      const res = await api.post('/api/v1/ai/chat', { ...buildContext(), history: chatHistory, question: q })
      setChatHistory([...newHistory, { role: 'assistant', content: res.data.answer }])
    } catch (err) {
      setChatHistory([...newHistory, { role: 'assistant', content: '⚠ ' + (err.response?.data?.error || 'Failed') }])
    } finally {
      setChatLoading(false)
      setTimeout(() => chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50)
    }
  }

  const TABS = [
    { id: 'analysis', label: 'AI Analysis', icon: Zap },
    { id: 'details',  label: 'Details',     icon: FileText },
    { id: 'graph',    label: 'Graph',       icon: GitBranch },
    { id: 'chat',     label: 'Chat',        icon: MessageSquare },
  ]

  const panelContent = (
    <div className={inline
      ? "h-full w-full bg-siem-surface border-l border-siem-border flex flex-col overflow-hidden"
      : "relative z-10 h-full w-full max-w-2xl bg-siem-surface border-l border-siem-border shadow-2xl flex flex-col overflow-hidden"}
      onClick={e => e.stopPropagation()}>

      {showAssign && alert && (
        <AssignModal alert={alert} users={users}
          onClose={() => setShowAssign(false)} onDone={() => { onStatusChange(); load() }}/>
      )}
      {showClose && alert && (
        <CloseModal alert={alert}
          onClose={() => setShowClose(false)} onDone={() => { onStatusChange(); load() }}/>
      )}

      {/* Header */}
      <div className="shrink-0 px-5 py-3.5 border-b border-siem-border bg-siem-surface">
        <div className="flex items-center gap-2">
          <Bell size={14} className="text-siem-accent shrink-0"/>
          <span className="font-semibold text-siem-text text-sm flex-1 truncate">Alert Detail</span>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text p-1 rounded hover:bg-white/5">
            <X size={15}/>
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex-1 flex items-center justify-center text-siem-muted text-sm gap-2">
          <RefreshCw size={14} className="animate-spin"/> Loading…
        </div>
      ) : !alert ? (
        <div className="flex-1 flex items-center justify-center text-siem-muted text-sm">Alert not found</div>
      ) : (
        <>
          {/* Alert summary bar */}
          <div className="shrink-0 px-5 py-3 border-b border-siem-border bg-siem-bg/50">
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <SeverityBadge severity={alert.severity}/>
              <StatusBadge status={alert.status}/>
              {alert.assigned_to && (
                <span className="flex items-center gap-1 text-[9px] text-yellow-400 bg-yellow-950/20 border border-yellow-800/30 rounded-full px-2 py-0.5">
                  <User size={8}/>{alert.assigned_to}
                </span>
              )}
              <span className="text-[9px] text-siem-muted ml-auto flex items-center gap-1">
                <Clock size={9}/> {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
              </span>
            </div>
            <div className="text-sm font-semibold text-siem-text leading-snug">{alert.title}</div>
            {alert.host && (
              <div className="text-[10px] font-mono text-siem-muted mt-0.5">{alert.host}</div>
            )}
          </div>

          {/* Tabs */}
          <div className="shrink-0 flex border-b border-siem-border px-5">
            {TABS.map(({ id, label, icon: Icon }) => (
              <button key={id} onClick={() => setActiveTab(id)}
                className={`flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium border-b-2 transition-colors ${
                  activeTab === id
                    ? 'border-siem-accent text-siem-accent'
                    : 'border-transparent text-siem-muted hover:text-siem-text'
                }`}>
                <Icon size={11}/>
                {label}
                {id === 'analysis' && aiLoading && (
                  <div className="w-1.5 h-1.5 rounded-full bg-siem-accent animate-pulse ml-0.5"/>
                )}
                {id === 'analysis' && aiAnalysis && !aiLoading && (
                  <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 ml-0.5"/>
                )}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="flex-1 overflow-y-auto">

            {/* ── AI Analysis tab ── */}
            {activeTab === 'analysis' && (
              <div className="p-5 space-y-4">
                {aiError && (
                  <div className="bg-red-950/20 border border-red-800/30 rounded-xl p-3 flex items-center justify-between gap-3">
                    <span className="text-xs text-red-400">{aiError}</span>
                    <button onClick={runAiAnalysis} className="text-[10px] text-siem-muted border border-siem-border rounded px-2 py-1 hover:text-siem-text shrink-0">
                      Retry
                    </button>
                  </div>
                )}
                <AIReport analysis={aiAnalysis} loading={aiLoading} onRerun={runAiAnalysis}/>
                {!aiAnalysis && !aiLoading && !aiError && (
                  <div className="flex flex-col items-center justify-center py-12 gap-3">
                    <div className="w-12 h-12 rounded-xl bg-siem-accent/10 border border-siem-accent/20 flex items-center justify-center">
                      <Zap size={20} className="text-siem-accent/60"/>
                    </div>
                    <div className="text-xs text-siem-muted text-center">
                      No AI provider configured.<br/>Add a Groq or Anthropic key in Settings.
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── Details tab ── */}
            {activeTab === 'details' && (
              <div className="p-5 space-y-4">

                {/* Alert info */}
                <div className="bg-siem-bg border border-siem-border rounded-xl overflow-hidden">
                  <div className="px-4 py-2.5 border-b border-siem-border/40 bg-siem-surface/50">
                    <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Alert Info</span>
                  </div>
                  {[
                    ['Alert ID',    `#${alert.id}`],
                    ['Host',        alert.host || '—'],
                    ['Event Type',  alert.event_type || '—'],
                    ['Status',      alert.status],
                    ['Assigned To', alert.assigned_to || 'Unassigned'],
                    ['Created',     format(new Date(alert.created_at), 'yyyy-MM-dd HH:mm:ss')],
                  ].map(([k, v], i) => (
                    <div key={k} className={`flex gap-3 px-4 py-2 text-xs ${i % 2 ? 'bg-white/[0.01]' : ''}`}>
                      <span className="text-siem-muted w-28 shrink-0">{k}</span>
                      <span className="text-siem-text font-mono text-[10px] break-all">{v}</span>
                    </div>
                  ))}
                </div>

                {/* Description */}
                {alert.description && (
                  <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
                    <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">Description</div>
                    <p className="text-xs text-siem-text leading-relaxed">{alert.description}</p>
                  </div>
                )}

                {/* Triggering event */}
                {ev && (
                  <div className="bg-siem-bg border border-siem-accent/20 rounded-xl overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-2.5 border-b border-siem-border/40">
                      <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Triggering Event</span>
                      <a href={`/events?id=${ev.id}`} onClick={onClose}
                        className="flex items-center gap-1 text-[10px] text-siem-accent border border-siem-accent/30 hover:bg-siem-accent/10 rounded px-2 py-0.5">
                        <ExternalLink size={9}/> View in Events
                      </a>
                    </div>
                    {[
                      ['Time',      format(new Date(ev.time), 'yyyy-MM-dd HH:mm:ss')],
                      ['Host',      ev.host],
                      ['OS',        ev.os],
                      ['Type',      ev.event_type],
                      ['Source',    ev.source],
                      ['Process',   ev.process_name],
                      ['Command',   ev.command_line],
                      ['User',      ev.user_name],
                      ['PID',       ev.pid],
                      ['Src IP',    ev.src_ip],
                      ['Dst IP',    ev.dst_ip],
                      ['Dst Port',  ev.dst_port],
                      ['File Path', ev.file_path],
                      ['File Hash', ev.file_hash],
                      ['Reg Key',   ev.reg_key],
                      ['Reg Value', ev.reg_value],
                    ].filter(([, v]) => v).map(([k, v], i) => (
                      <div key={k} className={`flex gap-3 px-4 py-2 text-xs ${i % 2 ? 'bg-white/[0.01]' : ''}`}>
                        <span className="text-siem-muted w-24 shrink-0">{k}</span>
                        <span className="text-siem-text font-mono text-[10px] break-all">{(k === 'Src IP' || k === 'Dst IP') ? <IPLink ip={String(v)} /> : String(v)}</span>
                      </div>
                    ))}
                    {ev.raw && (
                      <details className="px-4 py-2 border-t border-siem-border/30">
                        <summary className="text-[10px] text-siem-muted cursor-pointer hover:text-siem-text">Raw event data</summary>
                        <pre className="text-[9px] text-siem-muted mt-2 overflow-x-auto whitespace-pre-wrap break-all">
                          {JSON.stringify(ev.raw, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                )}

                {/* Case notes */}
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <FileText size={11} className="text-siem-muted"/>
                    <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Case Notes</span>
                    {!editNotes && alert.status !== 'closed' && (
                      <button onClick={() => setEditNotes(true)}
                        className="ml-auto text-[9px] text-siem-muted hover:text-siem-accent border border-siem-border rounded px-2 py-0.5">
                        Edit
                      </button>
                    )}
                  </div>
                  {editNotes ? (
                    <div>
                      <textarea rows={4} value={notes} onChange={e => setNotes(e.target.value)}
                        className="w-full bg-siem-bg border border-siem-accent/40 rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none resize-none"/>
                      <div className="flex gap-2 mt-2">
                        <button onClick={saveNotes} disabled={savingNotes}
                          className="text-xs bg-siem-accent/20 border border-siem-accent/40 text-siem-accent rounded-lg px-3 py-1">
                          {savingNotes ? 'Saving…' : 'Save'}
                        </button>
                        <button onClick={() => { setEditNotes(false); setNotes(alert.case_notes || '') }}
                          className="text-xs text-siem-muted border border-siem-border rounded-lg px-3 py-1">Cancel</button>
                      </div>
                    </div>
                  ) : (
                    <div className="bg-siem-bg border border-siem-border rounded-xl p-3 min-h-[60px]">
                      {alert.case_notes
                        ? <p className="text-xs text-siem-text leading-relaxed whitespace-pre-wrap">{alert.case_notes}</p>
                        : <p className="text-[10px] text-siem-muted/50 italic">No case notes.</p>}
                    </div>
                  )}
                </div>

                {/* Review comment */}
                {alert.review_comment && (
                  <div className="bg-emerald-950/20 border border-emerald-800/30 rounded-xl p-3">
                    <div className="text-[10px] text-emerald-400 font-semibold mb-1 flex items-center gap-1">
                      <CheckCircle size={9}/> Review Comment
                    </div>
                    <p className="text-xs text-siem-text leading-relaxed">{alert.review_comment}</p>
                    {alert.closed_by && (
                      <p className="text-[9px] text-siem-muted mt-1">
                        Closed by {alert.closed_by}
                        {alert.closed_at && <> · {format(new Date(alert.closed_at), 'yyyy-MM-dd HH:mm')}</>}
                      </p>
                    )}
                  </div>
                )}

                {/* Actions */}
                {alert.status !== 'closed' && (
                  <div className="flex gap-2 flex-wrap pt-1">
                    {(alert.status === 'open' || (alert.status === 'acknowledged' && !alert.assigned_to)) && (
                      <button onClick={() => setShowAssign(true)}
                        className="flex items-center gap-1.5 text-xs text-yellow-400 border border-yellow-800 hover:bg-yellow-900/20 rounded-lg px-3 py-2 transition-colors">
                        <UserCheck size={12}/> Assign to Analyst
                      </button>
                    )}
                    <button onClick={() => setShowClose(true)}
                      className="flex items-center gap-1.5 text-xs text-siem-muted border border-siem-border hover:border-siem-accent/40 hover:text-siem-text rounded-lg px-3 py-2 transition-colors">
                      <XCircle size={12}/> Close with Review
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* ── Chat tab ── */}
            {activeTab === 'graph' && alert && (
              <AlertGraph alertId={alert.id}/>
            )}

            {activeTab === 'chat' && (
              <div className="flex flex-col h-full">
                <div className="flex-1 overflow-y-auto p-4 space-y-3">
                  {chatHistory.length === 0 ? (
                    <div className="text-center py-8">
                      <MessageSquare size={24} className="mx-auto mb-2 text-siem-muted/30"/>
                      <p className="text-xs text-siem-muted/60">Ask anything about this alert</p>
                      <div className="flex flex-wrap gap-2 justify-center mt-4">
                        {['Is this a false positive?', 'What should I check next?', 'Explain the MITRE technique', 'What processes should I kill?'].map(q => (
                          <button key={q} onClick={() => { setChatInput(q); setActiveTab('chat') }}
                            className="text-[10px] text-siem-muted border border-siem-border rounded-full px-2.5 py-1 hover:text-siem-text hover:border-siem-accent/30 transition-colors">
                            {q}
                          </button>
                        ))}
                      </div>
                    </div>
                  ) : (
                    chatHistory.map((msg, i) => (
                      <div key={i} className={`flex gap-2 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                        {msg.role === 'assistant' && (
                          <div className="w-5 h-5 rounded-full bg-siem-accent/20 border border-siem-accent/40 flex items-center justify-center shrink-0 mt-0.5">
                            <Zap size={9} className="text-siem-accent"/>
                          </div>
                        )}
                        <div className={`max-w-[85%] rounded-xl px-3 py-2 text-xs leading-relaxed ${
                          msg.role === 'user'
                            ? 'bg-siem-accent/15 border border-siem-accent/30 text-siem-text'
                            : 'bg-siem-bg border border-siem-border text-siem-text'
                        }`}>
                          {msg.content}
                        </div>
                      </div>
                    ))
                  )}
                  {chatLoading && (
                    <div className="flex gap-2">
                      <div className="w-5 h-5 rounded-full bg-siem-accent/20 border border-siem-accent/40 flex items-center justify-center shrink-0">
                        <Zap size={9} className="text-siem-accent"/>
                      </div>
                      <div className="bg-siem-bg border border-siem-border rounded-xl px-3 py-2 flex gap-1 items-center">
                        {[0,1,2].map(i => <div key={i} className="w-1.5 h-1.5 rounded-full bg-siem-accent animate-bounce" style={{animationDelay:`${i*150}ms`}}/>)}
                      </div>
                    </div>
                  )}
                  <div ref={chatEndRef}/>
                </div>
                <div className="shrink-0 border-t border-siem-border p-3 flex gap-2">
                  <input value={chatInput} onChange={e => setChatInput(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat() } }}
                    placeholder="Ask about this alert…"
                    className="flex-1 bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-xs text-siem-text placeholder-siem-muted/40 outline-none focus:border-siem-accent/50"
                    disabled={chatLoading}/>
                  <button onClick={sendChat} disabled={!chatInput.trim() || chatLoading}
                    className="text-xs px-3 py-2 bg-siem-accent/20 border border-siem-accent/40 text-siem-accent rounded-lg hover:bg-siem-accent/30 disabled:opacity-40 transition-colors">
                    Send
                  </button>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )

  const panel = inline ? panelContent : (
    <div className="fixed inset-0 z-[80] flex justify-end">
      <div className="absolute inset-0 bg-black/60" onClick={onClose}/>
      {panelContent}
    </div>
  )

  return inline ? panel : createPortal(panel, document.body)
}

export { AlertPanel }
export default AlertPanel
