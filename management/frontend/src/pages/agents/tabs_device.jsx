import '@xterm/xterm/css/xterm.css'
import { Terminal as XTerm } from '@xterm/xterm'
import { useEffect, useState, useRef } from 'react'
import { AlertTriangle, RefreshCw, Activity, MapPin, Terminal, Square } from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts'
import api, { getWSTicket } from '../../api/client'
import AgentMap from '../../components/AgentMap'

export function TabDevice({ agent }) {
  const [healthEvents, setHealthEvents] = useState([])
  const [loading, setLoading]           = useState(true)

  useEffect(() => {
    setLoading(true)
    // Fetch last 60 health events for history charts
    api.get('/api/v1/events', { params: { host: agent.hostname, event_type: 'health', limit: 60 } })
      .then(r => setHealthEvents((r.data.events || []).reverse()))
      .catch(() => setHealthEvents([]))
      .finally(() => setLoading(false))
  }, [agent.hostname])

  const parseRaw = ev => {
    if (!ev?.raw) return null
    if (typeof ev.raw === 'string') { try { return JSON.parse(ev.raw) } catch { return null } }
    return ev.raw
  }

  const latest = healthEvents[healthEvents.length - 1]
  const raw    = parseRaw(latest)

  // Build history series for charts
  const cpuHistory  = healthEvents.map(ev => { const r = parseRaw(ev); return { t: ev.time ? format(new Date(ev.time),'HH:mm') : '', v: r?.cpu_percent ?? null } }).filter(p => p.v != null)
  const memHistory  = healthEvents.map(ev => { const r = parseRaw(ev); return { t: ev.time ? format(new Date(ev.time),'HH:mm') : '', v: r?.mem_percent ?? null } }).filter(p => p.v != null)

  const MetricBar = ({ label, value, total, unit='%', warnAt=60, critAt=80, barColor }) => {
    const pct = total ? (value / total * 100) : value
    const bg  = barColor || (pct > critAt ? '#ef4444' : pct > warnAt ? '#f97316' : '#22c55e')
    const display = total
      ? `${Number(value).toFixed(1)} / ${Number(total).toFixed(0)} ${unit}`
      : `${Number(value).toFixed(1)}${unit}`
    return (
      <div className="space-y-1">
        <div className="flex justify-between text-xs">
          <span className="text-siem-muted">{label}</span>
          <span className="font-mono text-siem-text">{display}</span>
        </div>
        <div className="h-2 bg-siem-border/20 rounded-full overflow-hidden">
          <div className="h-full rounded-full transition-all" style={{ width: Math.min(pct, 100)+'%', background: bg }}/>
        </div>
      </div>
    )
  }

  const MiniChart = ({ data, color, label, unit='%' }) => {
    if (!data?.length) return null
    return (
      <div className="bg-siem-surface border border-siem-border rounded-xl p-3">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">{label}</span>
          {data[data.length-1] && <span className="text-xs font-mono text-siem-text">{Number(data[data.length-1].v).toFixed(1)}{unit}</span>}
        </div>
        <div className="h-20">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id={`grad-${label}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={color} stopOpacity={0.3}/>
                  <stop offset="95%" stopColor={color} stopOpacity={0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="t" tick={{ fontSize: 8, fill: '#64748b' }} interval="preserveStartEnd" tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={{ background: '#0f1923', border: '1px solid #1e3a4a', borderRadius: 6, fontSize: 10 }} formatter={v => [`${Number(v).toFixed(1)}${unit}`, label]}/>
              <Area type="monotone" dataKey="v" stroke={color} fill={`url(#grad-${label})`} strokeWidth={1.5} dot={false}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    )
  }

  return (
    <div className="p-5 space-y-4 overflow-y-auto h-full">

      {/* System info */}
      <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
        <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-3">System</div>
        {[
          ['Hostname',    agent.hostname],
          ['OS',          agent.os || '—'],
          ['Agent version', agent.version || '—'],
          ['Last IP',     agent.last_ip || '—'],
          ['Agent ID',    agent.id],
          ['Last seen',   agent.last_seen ? formatDistanceToNow(new Date(agent.last_seen), { addSuffix: true }) : '—'],
        ].map(([k, v]) => (
          <div key={k} className="flex justify-between text-xs py-1.5 border-b border-siem-border/40 last:border-0">
            <span className="text-siem-muted">{k}</span>
            <span className="font-mono text-siem-text text-[11px]">{v}</span>
          </div>
        ))}
      </div>

      {loading && <div className="text-xs text-siem-muted/50 text-center py-8">Loading metrics…</div>}

      {!loading && !raw && (
        <div className="bg-siem-surface border border-siem-border rounded-xl p-6 text-center space-y-2">
          <div className="text-sm text-siem-muted">No health data yet</div>
          <div className="text-[10px] text-siem-muted/50 max-w-xs mx-auto">
            Reinstall the agent from the dashboard to get the latest version with system metrics. Health events fire every 60s.
          </div>
        </div>
      )}

      {!loading && raw && (<>

        {/* History charts */}
        <div className="grid grid-cols-2 gap-3">
          <MiniChart data={cpuHistory}  color="#22c55e" label="CPU"    unit="%"/>
          <MiniChart data={memHistory}  color="#3b82f6" label="Memory" unit="%"/>
        </div>

        {/* Current resource bars */}
        <div className="bg-siem-surface border border-siem-border rounded-xl p-4 space-y-3">
          <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold flex items-center justify-between">
            Resources
            {latest && <span className="font-normal">updated {formatDistanceToNow(new Date(latest.time), { addSuffix: true })}</span>}
          </div>

          {raw.cpu_percent != null && raw.cpu_percent >= 0 &&
            <MetricBar label="CPU" value={raw.cpu_percent} unit="%" warnAt={60} critAt={80}/>
          }
          {raw.mem_total_mb != null ? (
            <MetricBar
              label={`Memory (${Number(raw.mem_total_mb/1024).toFixed(1)} GB)`}
              value={raw.mem_used_mb} total={raw.mem_total_mb} unit="MB"
              warnAt={70} critAt={85}
              barColor={raw.mem_percent > 85 ? '#ef4444' : raw.mem_percent > 70 ? '#f97316' : '#3b82f6'}/>
          ) : raw.memory_percent != null &&
            <MetricBar label="Memory" value={raw.memory_percent} unit="%" warnAt={70} critAt={85} barColor="#3b82f6"/>
          }
        </div>

        {/* All disks */}
        {raw.disks?.length > 0 && (
          <div className="bg-siem-surface border border-siem-border rounded-xl p-4 space-y-3">
            <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">
              Disks ({raw.disks.length})
            </div>
            {raw.disks.map((d, i) => (
              <MetricBar
                key={i}
                label={`${d.mount}  (${Number(d.total_gb).toFixed(0)} GB)`}
                value={d.used_gb} total={d.total_gb} unit="GB"
                warnAt={75} critAt={90}
                barColor={d.free_percent < 10 ? '#ef4444' : d.free_percent < 25 ? '#f97316' : '#22c55e'}/>
            ))}
          </div>
        )}

        {/* Top processes */}
        {raw.top_processes?.length > 0 && (
          <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-siem-border">
              <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">
                Top processes by CPU + Memory
              </div>
            </div>
            {/* CPU bar chart */}
            <div className="px-4 pt-3 pb-1">
              <div className="text-[9px] text-siem-muted mb-2">CPU %</div>
              <div className="h-28">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={[...raw.top_processes].sort((a,b) => b.cpu_percent - a.cpu_percent).slice(0,10)} layout="vertical" margin={{ top:0, right:40, bottom:0, left:80 }}>
                    <XAxis type="number" tick={{ fontSize: 9, fill: '#64748b' }} tickLine={false} axisLine={false}/>
                    <YAxis type="category" dataKey="name" tick={{ fontSize: 9, fill: '#94a3b8' }} width={80} tickLine={false} axisLine={false}/>
                    <Tooltip contentStyle={{ background:'#0f1923', border:'1px solid #1e3a4a', borderRadius:6, fontSize:10 }} formatter={v => [`${Number(v).toFixed(1)}%`, 'CPU']}/>
                    <Bar dataKey="cpu_percent" radius={[0,3,3,0]}>
                      {raw.top_processes.slice(0,10).map((p,i) => (
                        <Cell key={i} fill={p.cpu_percent > 50 ? '#ef4444' : p.cpu_percent > 20 ? '#f97316' : '#22c55e'}/>
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
            {/* Memory bar chart */}
            <div className="px-4 pt-1 pb-3 border-t border-siem-border/30">
              <div className="text-[9px] text-siem-muted mb-2">Memory (MB)</div>
              <div className="h-28">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={[...raw.top_processes].sort((a,b) => b.mem_mb - a.mem_mb).slice(0,10)} layout="vertical" margin={{ top:0, right:40, bottom:0, left:80 }}>
                    <XAxis type="number" tick={{ fontSize: 9, fill: '#64748b' }} tickLine={false} axisLine={false}/>
                    <YAxis type="category" dataKey="name" tick={{ fontSize: 9, fill: '#94a3b8' }} width={80} tickLine={false} axisLine={false}/>
                    <Tooltip contentStyle={{ background:'#0f1923', border:'1px solid #1e3a4a', borderRadius:6, fontSize:10 }} formatter={v => [`${Number(v).toFixed(0)} MB`, 'Memory']}/>
                    <Bar dataKey="mem_mb" radius={[0,3,3,0]}>
                      {raw.top_processes.slice(0,10).map((p,i) => (
                        <Cell key={i} fill="#3b82f6"/>
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        )}

        {/* Agent internals */}
        <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
          <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-3">Agent internals</div>
          <div className="grid grid-cols-2 gap-x-6">
            {[
              ['Status',           raw.status],
              ['Uptime',           raw.uptime_seconds != null ? `${Math.floor(raw.uptime_seconds/3600)}h ${Math.floor((raw.uptime_seconds%3600)/60)}m` : '—'],
              ['Events collected', Number(raw.events_collected||0).toLocaleString()],
              ['Events forwarded', Number(raw.events_forwarded||0).toLocaleString()],
              ['Events dropped',   Number(raw.events_dropped||0).toLocaleString()],
              ['Queue depth',      Number(raw.queue_depth||0).toLocaleString()],
              ['Forward errors',   Number(raw.forward_errors||0).toLocaleString()],
              ['Goroutines',       raw.goroutines],
              ['Agent heap',       raw.agent_memory_mb != null ? `${Number(raw.agent_memory_mb).toFixed(1)} MB` : null],
            ].filter(([,v]) => v != null).map(([k, v]) => (
              <div key={k} className="flex justify-between text-xs py-1.5 border-b border-siem-border/30 last:border-0">
                <span className="text-siem-muted">{k}</span>
                <span className={`font-mono text-[11px] ${
                  k==='Events dropped'  && Number(raw.events_dropped)  > 0 ? 'text-orange-400' :
                  k==='Forward errors'  && Number(raw.forward_errors)  > 0 ? 'text-red-400' : 'text-siem-text'
                }`}>{String(v)}</span>
              </div>
            ))}
          </div>
          {raw.collectors?.length > 0 && (
            <div className="mt-3 pt-3 border-t border-siem-border/30">
              <div className="text-[10px] text-siem-muted mb-2">Active collectors</div>
              <div className="flex flex-wrap gap-1.5">
                {raw.collectors.map(c => (
                  <span key={c} className="text-[10px] px-2 py-0.5 bg-emerald-900/20 text-emerald-400 border border-emerald-800/30 rounded-full">{c}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </>)}
    </div>
  )
}

// ── Tab: Location ─────────────────────────────────────────────────────────────

export function TabLocation({ agent }) {
  const [loc, setLoc]       = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    api.get('/api/v1/agents/locations')
      .then(r => {
        const locs = Array.isArray(r.data) ? r.data : (r.data.locations || [])
        setLoc(locs.find(l => l.id === agent.id || l.hostname === agent.hostname) || null)
      })
      .catch(() => setLoc(null))
      .finally(() => setLoading(false))
  }, [agent.id, agent.hostname])

  if (loading) return <div className="p-5 text-center text-siem-muted">Loading location…</div>

  if (!loc) return (
    <div className="p-5 text-center py-12">
      <MapPin size={32} className="mx-auto mb-3 text-siem-muted opacity-20"/>
      <div className="text-sm text-siem-muted">No location data for this agent</div>
      <div className="text-xs text-siem-muted/60 mt-2 max-w-sm mx-auto">
        Location is reported every 30 minutes via IP geolocation. Reinstall the latest agent to enable it.
      </div>
    </div>
  )

  const hasCoords = loc.lat && loc.lng
  const lat = Number(loc.lat).toFixed(6)
  const lng = Number(loc.lng).toFixed(6)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Draggable map */}
      {hasCoords && (
        <div className="flex-1 min-h-0" style={{ minHeight: 320 }}>
          <AgentMap lat={Number(lat)} lng={Number(lng)} accuracy={Number(loc.location_accuracy) || 0}
            label={[loc.location_city, loc.location_country].filter(Boolean).join(', ')} />
        </div>
      )}

      {/* Info strip below map */}
      <div className="p-4 space-y-0 bg-siem-surface border-t border-siem-border shrink-0">
        <div className="grid grid-cols-3 gap-4">
          {[
            ['Location',    [loc.location_city, loc.location_country].filter(Boolean).join(', ') || '—'],
            ['Coordinates', hasCoords ? `${Number(lat).toFixed(4)}°, ${Number(lng).toFixed(4)}°` : '—'],
            ['Source',      loc.location_source || '—'],
            ['Accuracy',    loc.location_accuracy ? `~${Math.round(loc.location_accuracy)}m` : '—'],
            ['Updated',     loc.location_updated ? formatDistanceToNow(new Date(loc.location_updated), { addSuffix: true }) : '—'],
          ].map(([k, v]) => (
            <div key={k}>
              <div className="text-[9px] uppercase tracking-wider text-siem-muted mb-0.5">{k}</div>
              <div className="text-xs font-mono text-siem-text">{v}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── AgentDetail ───────────────────────────────────────────────────────────────

// ── Tab: Terminal (Live Response) ─────────────────────────────────────────────

export function TabTerminal({ agent }) {
  const [session, setSession]       = useState(null)
  const [connecting, setConnecting] = useState(false)
  const [error, setError]           = useState(null)
  const [connected, setConnected]   = useState(false)
  const termRef  = useRef(null)
  const xtermRef = useRef(null)
  const wsRef    = useRef(null)

  // Clean up on unmount or agent change
  useEffect(() => {
    return () => {
      if (wsRef.current)    wsRef.current.close()
      if (xtermRef.current) xtermRef.current.dispose()
      setSession(null); setConnected(false)
    }
  }, [agent.id])

  const startSession = async () => {
    setConnecting(true)
    setError(null)
    try {
      const { data } = await api.post('/api/v1/live-response/sessions', { agent_id: agent.id })
      setSession(data)
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Failed to start session')
    } finally {
      setConnecting(false)
    }
  }

  const endSession = async () => {
    if (wsRef.current)    { wsRef.current.close();    wsRef.current    = null }
    if (xtermRef.current) { xtermRef.current.dispose(); xtermRef.current = null }
    if (session?.session_token) {
      await api.delete(`/api/v1/live-response/sessions/${session.session_token}`).catch(() => {})
    }
    setSession(null)
    setConnected(false)
    setError(null)
  }

  // Open WebSocket IMMEDIATELY when session is set — before xterm loads
  // This ensures open_session reaches the agent without delay
  useEffect(() => {
    if (!session) return

    let dead = false
    let ws   = null
    const buffer = []

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsReady = (async () => {
      let ticket
      try { ticket = await getWSTicket() } catch { if (!dead) setError('Could not authorise the terminal connection'); return null }
      if (dead) return null
      const wsURL = `${proto}//${window.location.host}/api/v1/live-response/terminal?token=${session.session_token}&ticket=${encodeURIComponent(ticket)}`
      ws = new WebSocket(wsURL)
      ws.binaryType = 'arraybuffer'
      wsRef.current = ws

      ws.onopen = () => {
        if (dead) return
        setConnected(true)
        if (xtermRef.current) {
          xtermRef.current.writeln('\x1b[32m✓ Tunnel established — opening shell…\x1b[0m\r\n')
        }
      }
      ws.onmessage = (evt) => {
        if (dead) return
        const data = evt.data instanceof ArrayBuffer
          ? new Uint8Array(evt.data)
          : new TextEncoder().encode(evt.data)
        if (xtermRef.current) {
          xtermRef.current.write(data)
        } else {
          buffer.push(data)
        }
      }
      ws.onerror = () => {
        if (dead) return
        setError('WebSocket connection failed')
      }
      ws.onclose = (e) => {
        if (dead) return
        setConnected(false)
      }
      return ws
    })()

    const loadXterm = async () => {
      await wsReady
      if (dead || !termRef.current || !ws) return

      const term = new XTerm({
        cursorBlink: true,
        fontSize:    13,
        fontFamily:  '"JetBrains Mono","Fira Code","Courier New",monospace',
        theme: {
          background:  '#0a0f1a',
          foreground:  '#e2e8f0',
          cursor:      '#34d399',
          black:       '#1e293b',
          red:         '#f87171',
          green:       '#34d399',
          yellow:      '#fbbf24',
          blue:        '#60a5fa',
          magenta:     '#c084fc',
          cyan:        '#22d3ee',
          white:       '#e2e8f0',
          brightBlack: '#475569',
        },
        rows: 30, cols: 120,
      })

      term.open(termRef.current)
      term.writeln('\r\n\x1b[32m ObsidianWatch Live Response\x1b[0m')
      term.writeln(` Connecting to \x1b[36m${session.hostname}\x1b[0m as \x1b[33m${session.username}\x1b[0m…`)
      if (ws.readyState === WebSocket.OPEN) {
        term.writeln('\x1b[32m✓ Tunnel established — opening shell…\x1b[0m\r\n')
      }
      xtermRef.current = term
      buffer.forEach(d => term.write(d))
      buffer.length = 0

      term.onData(data => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(new TextEncoder().encode(data))
        }
      })
    }

    loadXterm().catch(e => setError(e.message))

    return () => {
      dead = true
      if (wsRef.current)    { wsRef.current.close();     wsRef.current    = null }
      if (xtermRef.current) { xtermRef.current.dispose(); xtermRef.current = null }
    }
  }, [session])


  // ── No session yet — show connect prompt ──────────────────────────────────
  if (!session) {
    const os = (agent.os || '').toLowerCase()
    const isWindows = os.includes('win')
    const isMac     = os.includes('darwin') || os.includes('mac')

    return (
      <div className="flex flex-col items-center justify-center h-full gap-5 p-6">
        <div className="w-16 h-16 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
          <Terminal size={28} className="text-emerald-400 opacity-70"/>
        </div>

        <div className="text-center">
          <div className="text-sm font-semibold text-siem-text mb-1">Live Response Terminal</div>
          <div className="text-xs text-siem-muted max-w-sm">
            Opens an interactive shell session directly to <span className="text-siem-text font-mono">{agent.hostname}</span> through
            the existing agent tunnel. No inbound ports required.
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/20 border border-red-800/40 rounded-lg px-4 py-2 max-w-sm">
            <AlertTriangle size={12}/> {error}
          </div>
        )}

        <button
          onClick={startSession}
          disabled={connecting}
          className="flex items-center gap-2 px-5 py-2.5 bg-emerald-900/30 border border-emerald-700 text-emerald-400 rounded-xl text-sm font-medium hover:bg-emerald-900/50 transition-colors disabled:opacity-50 disabled:cursor-wait"
        >
          {connecting
            ? <><RefreshCw size={14} className="animate-spin"/> Connecting…</>
            : <><Terminal size={14}/> Start Session</>
          }
        </button>
      </div>
    )
  }

  // ── Session active — show terminal ────────────────────────────────────────
  return (
    <div className="flex flex-col h-full bg-[#0a0f1a]">
      {/* Terminal toolbar */}
      <div className="flex items-center justify-between px-4 py-2 bg-siem-surface border-b border-siem-border shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500"/>
            <span className="w-3 h-3 rounded-full bg-yellow-500"/>
            <span className="w-3 h-3 rounded-full bg-emerald-500"/>
          </div>
          <span className="text-xs font-mono text-siem-muted">
            {session.username}@{session.hostname}
          </span>
          {connected && (
            <span className="flex items-center gap-1 text-[10px] text-emerald-400">
              <Activity size={10} className="animate-pulse"/> Live
            </span>
          )}
        </div>
        <button
          onClick={endSession}
          className="flex items-center gap-1.5 text-[11px] text-red-400 hover:text-red-300 px-2 py-1 rounded border border-red-800 hover:border-red-600 transition-colors"
        >
          <Square size={10}/> End Session
        </button>
      </div>

      {error && (
        <div className="flex-shrink-0 px-4 py-2 bg-red-950/30 border-b border-red-800 text-xs text-red-300 flex items-center gap-2">
          <AlertTriangle size={12}/> {error}
        </div>
      )}

      {/* xterm.js container */}
      <div ref={termRef} className="flex-1 p-2 overflow-hidden"/>
    </div>
  )
}

