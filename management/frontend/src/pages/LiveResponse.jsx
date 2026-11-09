import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { useEffect, useState, useRef, useCallback } from 'react'
import { Terminal, Monitor, Server, Globe, Wifi, WifiOff,
         Play, Square, Clock, User, Shield, AlertTriangle, RefreshCw,
         ChevronRight, X, Activity } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api, { getWSTicket } from '../api/client'

// ── OS helpers ────────────────────────────────────────────────────────────────
function OSIcon({ os }) {
  const l = (os || '').toLowerCase()
  if (l.includes('win'))   return <Monitor size={14} className="text-blue-400" />
  if (l.includes('linux')) return <Server  size={14} className="text-orange-400" />
  return                          <Globe   size={14} className="text-siem-muted" />
}

function StatusBadge({ status }) {
  const map = {
    active:  'bg-emerald-950/40 text-emerald-400 border-emerald-700',
    pending: 'bg-yellow-950/40 text-yellow-400 border-yellow-700',
    closed:  'bg-siem-surface text-siem-muted border-siem-border',
    failed:  'bg-red-950/40 text-red-400 border-red-700',
  }
  return (
    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${map[status] || map.closed}`}>
      {status}
    </span>
  )
}

// ── SSH Terminal ──────────────────────────────────────────────────────────────
function SSHTerminal({ session, onClose }) {
  const termRef    = useRef(null)
  const xtermRef   = useRef(null)
  const wsRef      = useRef(null)
  const [status, setStatus] = useState('connecting') // connecting | connected | error | closed
  const [errorMsg, setErrorMsg] = useState(null)

  useEffect(() => {
    if (!termRef.current || !session) return

    let term = null
    let ws   = null
    let dead = false
    let ro   = null

    // ── 1. Open WebSocket IMMEDIATELY — do not wait for xterm ──────────────
    // The terminal WS must open as fast as possible so the server sends
    // open_session to the agent before the agent-side tunnel times out.
    // Buffer for data arriving before xterm is ready
    const buffer = []
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsReady = (async () => {
      let ticket
      try { ticket = await getWSTicket() } catch {
        if (!dead) { setStatus('error'); setErrorMsg('Could not authorise the terminal connection') }
        return null
      }
      if (dead) return null
      const wsURL = `${proto}//${window.location.host}/api/v1/live-response/terminal` +
                    `?token=${session.session_token}&ticket=${encodeURIComponent(ticket)}`

      ws = new WebSocket(wsURL)
      ws.binaryType = 'arraybuffer'
      wsRef.current = ws

      ws.onopen = () => {
        if (dead) return
        setStatus('connected')
        if (term) {
          term.writeln('\x1b[32m✓ Tunnel established\x1b[0m\r\n')
        }
      }

      ws.onmessage = (evt) => {
        if (dead) return
        const data = evt.data instanceof ArrayBuffer
          ? new Uint8Array(evt.data)
          : new TextEncoder().encode(evt.data)
        if (term) {
          term.write(data)
        } else {
          buffer.push(data) // xterm not ready yet — buffer it
        }
      }

      ws.onerror = (e) => {
        if (dead) return
        setStatus('error')
        setErrorMsg('WebSocket connection failed — check server logs')
        if (term) term.writeln('\r\n\x1b[31m✗ Connection failed\x1b[0m')
      }

      ws.onclose = (e) => {
        if (dead) return
        setStatus('closed')
        if (term) term.writeln(`\r\n\x1b[33m● Session closed (${e.code})\x1b[0m`)
      }
      return ws
    })()

    // ── 2. Load xterm.js and mount terminal ────────────────────────────────
    const mountTerminal = async () => {
      await wsReady
      if (dead || !termRef.current) return

      term = new XTerm({
        cursorBlink: true,
        fontSize: 13,
        fontFamily: '"JetBrains Mono", "Fira Code", "Courier New", monospace',
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
        rows: 30,
        cols: 120,
      })

      const fit = new FitAddon()
      term.loadAddon(fit)
      term.open(termRef.current)
      try { fit.fit() } catch (_) { /* container not measurable yet */ }
      if (typeof ResizeObserver !== 'undefined') {
        ro = new ResizeObserver(() => { try { fit.fit() } catch (_) {} })
        ro.observe(termRef.current)
      }
      xtermRef.current = term

      term.writeln('\r\n\x1b[32m ObsidianWatch Live Response\x1b[0m')
      term.writeln(` Connecting to \x1b[36m${session.hostname}\x1b[0m via SSH...`)

      // Flush buffered data
      buffer.forEach(d => term.write(d))
      buffer.length = 0

      // If already connected show it
      if (ws && ws.readyState === WebSocket.OPEN) {
        term.writeln('\x1b[32m✓ Tunnel established\x1b[0m\r\n')
      }

      // Terminal input → WebSocket
      // xterm gives us strings — encode to UTF-8 bytes then send as binary
      // The backend expects raw bytes (it json.Marshal's them before forwarding)
      // Keep the remote PTY the same size as the browser terminal. Sent as a
      // TEXT frame (keystrokes are binary), clamped server-side.
      const sendSize = () => {
        if (ws && ws.readyState === WebSocket.OPEN && term.cols && term.rows) {
          ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
        }
      }
      term.onResize(sendSize)
      if (!ws) { /* ticket failed; error already shown */ }
      else if (ws.readyState === WebSocket.OPEN) sendSize()
      else ws.addEventListener('open', sendSize, { once: true })

      term.onData(data => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(new TextEncoder().encode(data))
        }
      })
    }

    mountTerminal().catch(err => {
      console.error('xterm load failed:', err)
      setErrorMsg('Terminal failed to load — check internet connectivity')
      setStatus('error')
    })

    return () => {
      dead = true
      if (ro) ro.disconnect()
      if (ws) ws.close()
      if (xtermRef.current) { xtermRef.current.dispose(); xtermRef.current = null }
    }
  }, [session])

  const statusColor = {
    connecting: 'text-yellow-400',
    connected:  'text-emerald-400',
    error:      'text-red-400',
    closed:     'text-siem-muted',
  }[status]

  return (
    <div className="flex flex-col h-full bg-[#0a0f1a]">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-siem-surface border-b border-siem-border flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500" />
            <span className="w-3 h-3 rounded-full bg-yellow-500" />
            <span className="w-3 h-3 rounded-full bg-emerald-500" />
          </div>
          <span className="text-xs font-mono text-siem-muted">
            {session.username}@{session.hostname}
          </span>
          <span className={`text-[10px] flex items-center gap-1 ${statusColor}`}>
            {status === 'connected' && <><Activity size={10} className="animate-pulse" /> Live</>}
            {status === 'connecting' && <><RefreshCw size={10} className="animate-spin" /> Connecting…</>}
            {status === 'error'      && <><AlertTriangle size={10} /> Error</>}
            {status === 'closed'     && '● Closed'}
          </span>
        </div>
        <button onClick={onClose}
          className="flex items-center gap-1.5 text-[11px] text-red-400 hover:text-red-300 px-2 py-1 rounded border border-red-800 hover:border-red-600 transition-colors">
          <Square size={10} /> End Session
        </button>
      </div>

      {errorMsg && (
        <div className="flex-shrink-0 px-4 py-2 bg-red-950/30 border-b border-red-800 text-xs text-red-300 flex items-center gap-2">
          <AlertTriangle size={12} /> {errorMsg}
        </div>
      )}

      <div ref={termRef} className="flex-1 p-2 overflow-hidden" />
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function LiveResponse() {
  const [agents, setAgents]               = useState([])
  const [sessions, setSessions]           = useState([])
  const [activeSession, setActiveSession] = useState(null)
  const [loading, setLoading]             = useState(true)
  const [connecting, setConnecting]       = useState(null)
  const [error, setError]                 = useState(null)

  const fetchData = useCallback(async () => {
    try {
      const [{ data: agentData }, { data: sessionData }] = await Promise.all([
        api.get('/api/v1/live-response/agents'),
        api.get('/api/v1/live-response/sessions'),
      ])
      setAgents(Array.isArray(agentData) ? agentData : [])
      setSessions(Array.isArray(sessionData) ? sessionData : [])
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 15_000)
    return () => clearInterval(id)
  }, [fetchData])

  const initiateSession = async (agent) => {
    setConnecting(agent.id)
    setError(null)
    try {
      const { data } = await api.post('/api/v1/live-response/sessions', { agent_id: agent.id })
      setActiveSession(data)
      fetchData()
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Failed to start session')
    } finally {
      setConnecting(null)
    }
  }

  const closeSession = async () => {
    if (activeSession?.session_token) {
      await api.delete(`/api/v1/live-response/sessions/${activeSession.session_token}`).catch(() => {})
    }
    setActiveSession(null)
    fetchData()
  }

  const lrReady    = agents.filter(a => a.lr_ready).length
  const tunnelOn   = agents.filter(a => a.tunnel_online).length
  const activeSess = sessions.filter(s => s.status === 'active').length

  return (
    <div className="flex h-screen bg-siem-bg text-siem-text overflow-hidden">

      {/* Left panel */}
      <div className="w-80 flex-shrink-0 flex flex-col border-r border-siem-border">

        <div className="flex-shrink-0 px-4 py-3 border-b border-siem-border bg-siem-surface">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Terminal size={16} className="text-emerald-400" />
              <span className="text-sm font-semibold">Live Response</span>
            </div>
            <button onClick={fetchData} className="text-siem-muted hover:text-siem-text">
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
          <div className="flex gap-3 text-[10px] text-siem-muted">
            <span className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />{lrReady} ready
            </span>
            <span className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />{tunnelOn} tunnels
            </span>
            <span className="flex items-center gap-1">
              <Activity size={9} className="text-yellow-400" />{activeSess} active
            </span>
          </div>
        </div>

        {error && (
          <div className="flex-shrink-0 mx-3 mt-2 p-2 rounded bg-red-950/30 border border-red-800 text-[11px] text-red-300 flex items-center gap-1.5">
            <AlertTriangle size={11} />{error}
          </div>
        )}

        <div className="flex-shrink-0 px-3 pt-3 pb-1 text-[10px] font-mono uppercase tracking-wider text-siem-muted">
          Endpoints ({agents.length})
        </div>

        <div className="flex-1 overflow-y-auto min-h-0">
          {agents.map(agent => {
            const isConnecting = connecting === agent.id
            const isActive     = activeSession?.agent_id === agent.id

            return (
              <div key={agent.id}
                className={`mx-2 mb-1.5 rounded-lg border transition-colors
                  ${isActive
                    ? 'border-emerald-700 bg-emerald-950/20'
                    : 'border-siem-border bg-siem-surface hover:border-siem-text/30'
                  }`}>
                <div className="flex items-center gap-2 px-3 py-2.5">
                  <OSIcon os={agent.os} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-medium truncate">{agent.hostname}</span>
                      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${agent.online ? 'bg-emerald-400' : 'bg-siem-muted'}`} />
                    </div>
                    <div className="flex items-center gap-1.5 text-[10px] text-siem-muted mt-0.5">
                      <span className="font-mono uppercase">ssh</span>
                      {agent.lr_username && <span>· {agent.lr_username}</span>}
                      {agent.tunnel_online
                        ? <span className="text-emerald-400 flex items-center gap-0.5"><Wifi size={8} /> tunnel</span>
                        : <span className="text-siem-muted flex items-center gap-0.5"><WifiOff size={8} /> no tunnel</span>
                      }
                    </div>
                  </div>
                </div>

                <div className="px-3 pb-2.5">
                  {!agent.lr_ready ? (
                    <div className="flex items-center gap-1.5 text-[10px] text-yellow-400 bg-yellow-950/20 px-2 py-1 rounded border border-yellow-800">
                      <AlertTriangle size={9} />
                      {!agent.lr_username ? 'No credentials — rebuild agent' : 'Tunnel offline'}
                    </div>
                  ) : isActive ? (
                    <div className="flex items-center gap-1.5 text-[10px] text-emerald-400">
                      <Activity size={10} className="animate-pulse" /> Session active
                    </div>
                  ) : (
                    <button
                      onClick={() => initiateSession(agent)}
                      disabled={isConnecting}
                      className="w-full flex items-center justify-center gap-1.5 text-[11px] py-1.5 rounded
                        bg-emerald-950/30 text-emerald-400 border border-emerald-800
                        hover:bg-emerald-900/40 hover:border-emerald-600 transition-colors
                        disabled:opacity-50 disabled:cursor-wait">
                      {isConnecting
                        ? <><RefreshCw size={10} className="animate-spin" /> Connecting…</>
                        : <><Play size={10} /> Start SSH Session</>
                      }
                    </button>
                  )}
                </div>
              </div>
            )
          })}

          {!loading && agents.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <Terminal size={20} className="opacity-30" />
              No agents found
            </div>
          )}
        </div>

        {/* Session history */}
        <div className="flex-shrink-0 border-t border-siem-border">
          <div className="px-3 py-2 text-[10px] font-mono uppercase tracking-wider text-siem-muted">
            Recent Sessions
          </div>
          <div className="max-h-48 overflow-y-auto">
            {sessions.slice(0, 10).map(s => (
              <div key={s.id} className="flex items-center gap-2 px-3 py-1.5 hover:bg-siem-surface border-b border-siem-border/50">
                <StatusBadge status={s.status} />
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] truncate">{s.agent_id}</div>
                  <div className="text-[9px] text-siem-muted flex items-center gap-1">
                    <User size={8} />{s.initiated_by}
                    <Clock size={8} className="ml-1" />
                    {formatDistanceToNow(new Date(s.created_at), { addSuffix: true })}
                  </div>
                </div>
                <span className="text-[9px] font-mono text-siem-muted uppercase">{s.protocol}</span>
              </div>
            ))}
            {sessions.length === 0 && (
              <div className="px-3 py-3 text-[10px] text-siem-muted text-center">No sessions yet</div>
            )}
          </div>
        </div>
      </div>

      {/* Right panel */}
      <div className="flex-1 min-w-0">
        {activeSession ? (
          <SSHTerminal session={activeSession} onClose={closeSession} />
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-siem-muted gap-4">
            <div className="w-16 h-16 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
              <Terminal size={32} className="opacity-40" />
            </div>
            <div className="text-center">
              <div className="text-sm font-medium text-siem-text mb-1">Live Response</div>
              <div className="text-xs max-w-xs text-center">
                Select an endpoint and click <strong>Start SSH Session</strong> to open an interactive terminal.
              </div>
            </div>
            <div className="flex items-center gap-4 text-[10px] mt-2">
              <span className="flex items-center gap-1.5 text-blue-400"><Monitor size={11} /> Windows (OpenSSH)</span>
              <span className="flex items-center gap-1.5 text-orange-400"><Server size={11} /> Linux</span>
              <span className="flex items-center gap-1.5 text-gray-400"><Globe size={11} /> macOS</span>
            </div>
            <div className="text-[10px] text-siem-muted/60 max-w-xs text-center mt-2 p-3 rounded border border-siem-border bg-siem-surface">
              <Shield size={10} className="inline mr-1" />
              Sessions are encrypted end-to-end through the agent tunnel. No ports opened externally.
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
