import { useState, useEffect } from 'react'
import { RefreshCw, Activity, Bell, Search, ChevronRight, List, Filter, FileText, Sparkles, X } from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import api from '../../api/client'
import AlertPanel from '../../components/AlertPanel'
import { ConnectorDetail } from './connectors.jsx'
import { SEV_COLORS_CLS, SEV_LABELS } from './shared.jsx'

export function CloudEventPanel({ event, onClose }) {
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(true)
  const [aiText, setAiText]   = useState(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('details')

  useEffect(() => {
    setLoading(true)
    api.get(`/api/v1/events/${event.id}`)
      .then(r => setDetail(r.data))
      .catch(() => setDetail(null))
      .finally(() => setLoading(false))
  }, [event.id])

  // Auto-run AI on open
  useEffect(() => {
    if (!loading && detail && !aiText && !aiLoading) runAI()
  }, [loading, detail])

  const ev = detail?.event || event
  const related = detail?.related || []

  const runAI = async () => {
    setAiLoading(true)
    try {
      const raw = ev.raw ? (typeof ev.raw === 'string' ? ev.raw : JSON.stringify(ev.raw)) : ''
      const res = await api.post('/api/v1/ai/analyse', {
        title:       ev.event_type || 'Cloud Event',
        severity:    ev.severity || 3,
        description: `Cloud event from ${ev.source || ev.host}`,
        host:        ev.host || '',
        event_type:  ev.event_type || '',
        raw_event:   raw.slice(0, 3000),
      })
      const text = res.data.content?.find(b => b.type === 'text')?.text || ''
      const clean = text.replace(/\x60{3}json\n?|\x60{3}/g, '').trim()
      const start = clean.indexOf('{'), end = clean.lastIndexOf('}')
      if (start !== -1 && end !== -1) {
        try { setAiText(JSON.parse(clean.slice(start, end+1))) } catch { setAiText({ summary: clean }) }
      }
    } catch { /* no AI configured - silent */ }
    finally { setAiLoading(false) }
  }

  const rawObj = ev.raw ? (typeof ev.raw === 'string' ? (() => { try { return JSON.parse(ev.raw) } catch { return ev.raw } })() : ev.raw) : null

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-2xl bg-siem-surface border-l border-siem-border h-full overflow-y-auto shadow-2xl flex flex-col"
           onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex-shrink-0 flex items-center justify-between px-5 py-4 border-b border-siem-border sticky top-0 bg-siem-surface z-10">
          <div className="flex items-center gap-2">
            <span className={`text-[10px] border rounded px-1.5 py-0.5 font-mono ${SEV_COLORS_CLS[ev.severity]||'text-siem-muted'} border-current/30`}>
              {SEV_LABELS[ev.severity]||'Event'}
            </span>
            <span className="text-xs font-mono text-siem-accent">{ev.event_type}</span>
            <span className="text-xs text-siem-muted">· {ev.host || ev.source}</span>
          </div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text"><X size={18}/></button>
        </div>

        {/* Tabs */}
        <div className="flex-shrink-0 flex gap-1 px-5 py-2 border-b border-siem-border">
          {[
            { id: 'ai',      label: 'AI Analysis', icon: Sparkles },
            { id: 'details', label: 'Details',      icon: List },
            { id: 'raw',     label: 'Raw',          icon: FileText },
          ].map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setActiveTab(id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                activeTab === id ? 'bg-siem-accent text-black' : 'text-siem-muted hover:text-siem-text'
              }`}>
              <Icon size={11}/>{label}
              {id === 'ai' && aiLoading && <RefreshCw size={9} className="animate-spin"/>}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center justify-center flex-1 text-siem-muted text-sm gap-2">
            <RefreshCw size={14} className="animate-spin"/>Loading…
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto p-5 space-y-4">

            {/* AI Analysis Tab */}
            {activeTab === 'ai' && (
              <div>
                {aiLoading && (
                  <div className="flex items-center gap-2 text-siem-muted text-sm p-6">
                    <RefreshCw size={14} className="animate-spin"/>Analysing with AI…
                  </div>
                )}
                {!aiLoading && !aiText && (
                  <div className="flex flex-col items-center gap-3 py-10 text-siem-muted">
                    <Sparkles size={24} className="opacity-40"/>
                    <span className="text-xs">No AI provider configured</span>
                    <button onClick={runAI} className="text-xs border border-siem-border px-3 py-1.5 rounded-lg hover:text-siem-text">
                      Retry Analysis
                    </button>
                  </div>
                )}
                {aiText && (
                  <div className="space-y-4">
                    {aiText.summary && (
                      <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
                        <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">Summary</div>
                        <p className="text-sm text-siem-text leading-relaxed">{aiText.summary}</p>
                      </div>
                    )}
                    {aiText.what_happened && (
                      <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
                        <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">What Happened</div>
                        <p className="text-xs text-siem-text/80 leading-relaxed">{aiText.what_happened}</p>
                      </div>
                    )}
                    {aiText.threat_assessment && (
                      <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
                        <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">Threat Assessment</div>
                        <p className="text-xs text-siem-text/80 leading-relaxed">{aiText.threat_assessment}</p>
                      </div>
                    )}
                    {aiText.recommended_actions?.length > 0 && (
                      <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
                        <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">Recommended Actions</div>
                        <div className="space-y-1">
                          {aiText.recommended_actions.map((a, i) => (
                            <div key={i} className="flex gap-2 text-xs text-siem-text/80">
                              <span className="text-siem-accent font-mono shrink-0">{i+1}.</span>{a}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {aiText.false_positive_indicators && (
                      <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
                        <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">False Positive Indicators</div>
                        <p className="text-xs text-siem-text/70 leading-relaxed">{aiText.false_positive_indicators}</p>
                      </div>
                    )}
                    <button onClick={runAI} disabled={aiLoading}
                      className="text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-1.5 flex items-center gap-1.5 disabled:opacity-40">
                      <RefreshCw size={11}/>Re-run Analysis
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* Details Tab */}
            {activeTab === 'details' && (
              <div className="space-y-4">
                <div className="bg-siem-bg rounded-xl border border-siem-border overflow-hidden">
                  {[
                    ['Time',       ev.time ? format(new Date(ev.time), 'yyyy-MM-dd HH:mm:ss') : '—'],
                    ['Event Type', ev.event_type],
                    ['Source',     ev.source],
                    ['Host',       ev.host],
                    ['Severity',   SEV_LABELS[ev.severity] || ev.severity],
                    ['Agent ID',   ev.agent_id],
                  ].filter(([,v]) => v).map(([label, value], i) => (
                    <div key={label} className={`flex gap-3 px-4 py-2.5 text-sm ${i%2===0?'':'bg-white/[0.02]'}`}>
                      <span className="text-siem-muted w-28 shrink-0 text-xs">{label}</span>
                      <span className="text-siem-text font-mono text-xs break-all">{String(value)}</span>
                    </div>
                  ))}
                </div>
                {related.length > 0 && (
                  <div>
                    <div className="text-xs uppercase tracking-wider text-siem-muted mb-2">Related Events (±5 min)</div>
                    <div className="space-y-1">
                      {related.slice(0,10).map((r, i) => (
                        <div key={i} className="flex items-center gap-2 text-[11px] bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5">
                          <span className="text-siem-muted font-mono">{format(new Date(r.time), 'HH:mm:ss')}</span>
                          <span className="text-siem-accent font-mono">{r.event_type}</span>
                          <span className="text-siem-muted truncate flex-1">{r.source}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Raw Tab */}
            {activeTab === 'raw' && rawObj && (
              <pre className="bg-siem-bg border border-siem-border rounded-xl p-4 text-xs text-siem-accent overflow-x-auto max-h-[60vh] whitespace-pre-wrap break-all">
                {JSON.stringify(rawObj, null, 2)}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export function CloudAlertPanel({ alert, onClose, users }) {
  // Reuse AlertPanel directly - pass the alert id
  const AlertPanelComponent = AlertPanel
  return <AlertPanelComponent alertId={alert.id} users={users} onClose={onClose} onStatusChange={() => {}}/>
}

export function CloudEventsAlerts({ tab, events, alerts, loadingE, loadingA, search, setSearch }) {
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [selectedAlert, setSelectedAlert] = useState(null)

  const filteredEvents = search
    ? events.filter(e => JSON.stringify(e).toLowerCase().includes(search.toLowerCase()))
    : events
  const filteredAlerts = search
    ? alerts.filter(a => (a.title+a.description).toLowerCase().includes(search.toLowerCase()))
    : alerts

  return (
    <div className="flex flex-col h-full">
      {/* Search */}
      <div className="flex-shrink-0 px-5 py-2 border-b border-siem-border">
        <div className="relative">
          <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-siem-muted"/>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter…"
            className="w-full bg-siem-bg border border-siem-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-siem-text focus:outline-none focus:border-siem-accent"/>
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto divide-y divide-siem-border/50">

        {tab === 'events' && <>
          {loadingE && (
            <div className="flex items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <RefreshCw size={14} className="animate-spin"/>Loading events…
            </div>
          )}
          {!loadingE && filteredEvents.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <Activity size={20} className="opacity-30"/>No cloud events yet
            </div>
          )}
          {filteredEvents.map(ev => (
            <button key={ev.id} onClick={() => setSelectedEvent(ev)}
              className="w-full px-5 py-3 hover:bg-siem-surface/60 text-left transition-colors group">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <span className={`text-[10px] font-mono border rounded px-1.5 py-0.5 shrink-0 ${SEV_COLORS_CLS[ev.severity]||'text-siem-muted'} border-current/30`}>
                    {SEV_LABELS[ev.severity]||'—'}
                  </span>
                  <span className="text-[10px] font-mono text-siem-accent shrink-0">{ev.event_type}</span>
                  <span className="text-xs text-siem-text truncate">{ev.source || ev.host}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] text-siem-muted opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1">
                    <Sparkles size={9}/> AI
                  </span>
                  <span className="text-[10px] text-siem-muted">{ev.time ? formatDistanceToNow(new Date(ev.time), { addSuffix: true }) : ''}</span>
                  <ChevronRight size={12} className="text-siem-muted/40 group-hover:text-siem-accent transition-colors"/>
                </div>
              </div>
              {ev.user_name && <div className="text-[10px] text-siem-muted mt-0.5 ml-16">User: {ev.user_name}</div>}
            </button>
          ))}
        </>}

        {tab === 'alerts' && <>
          {loadingA && (
            <div className="flex items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <RefreshCw size={14} className="animate-spin"/>Loading alerts…
            </div>
          )}
          {!loadingA && filteredAlerts.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <Bell size={20} className="opacity-30"/>No cloud alerts
            </div>
          )}
          {filteredAlerts.map(a => {
            const sevColor = ['','text-siem-muted','text-blue-400','text-yellow-400','text-orange-400','text-red-400'][a.severity]||'text-siem-muted'
            const statusColor = { open:'text-red-400', acknowledged:'text-yellow-400', closed:'text-siem-muted' }[a.status]||'text-siem-muted'
            return (
              <button key={a.id} onClick={() => setSelectedAlert(a)}
                className="w-full px-5 py-3 hover:bg-siem-surface/60 text-left transition-colors group">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className={`text-[10px] font-mono shrink-0 ${sevColor}`}>
                      {SEV_LABELS[a.severity]||'—'}
                    </span>
                    <span className="text-xs font-medium text-siem-text truncate">{a.title}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] text-siem-muted opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1">
                      <Sparkles size={9}/> AI
                    </span>
                    <span className={`text-[10px] ${statusColor}`}>{a.status}</span>
                    <span className="text-[10px] text-siem-muted">{a.created_at ? formatDistanceToNow(new Date(a.created_at), { addSuffix: true }) : ''}</span>
                    <ChevronRight size={12} className="text-siem-muted/40 group-hover:text-siem-accent transition-colors"/>
                  </div>
                </div>
                {a.description && (
                  <div className="text-[10px] text-siem-muted mt-1 line-clamp-1 ml-8">{a.description}</div>
                )}
              </button>
            )
          })}
        </>}
      </div>

      {/* Slide-out panels */}
      {selectedEvent && <CloudEventPanel event={selectedEvent} onClose={() => setSelectedEvent(null)}/>}
      {selectedAlert && <AlertPanel alertId={selectedAlert.id} users={[]} onClose={() => setSelectedAlert(null)} onStatusChange={() => {}}/>}
    </div>
  )
}

// ── ConnectorDetail ────────────────────────────────────────────────────────────

