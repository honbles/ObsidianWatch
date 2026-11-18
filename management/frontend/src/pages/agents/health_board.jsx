import { useEffect, useState } from 'react'
import { formatDistanceToNow } from 'date-fns'
import api from '../../api/client'

const DOT = { ok: 'bg-emerald-400', warn: 'bg-amber-400', error: 'bg-red-500', unknown: 'bg-siem-muted' }
const TXT = { ok: 'text-emerald-300', warn: 'text-amber-300', error: 'text-red-300', unknown: 'text-siem-muted' }

// Everything the agent runs, one row each, green when healthy. Built from the agent's latest
// health event plus the live-response tunnel state.
export function HealthBoard({ agent }) {
  const [raw, setRaw] = useState(null)
  const [at, setAt] = useState(null)
  const [tunnel, setTunnel] = useState(null)
  useEffect(() => {
    let live = true
    const load = async () => {
      try {
        const { data } = await api.get('/api/v1/events', { params: { host: agent.hostname, event_type: 'health', limit: 1 } })
        const ev = (data.events || [])[0]
        if (live && ev) { setAt(ev.time); setRaw(typeof ev.raw === 'string' ? JSON.parse(ev.raw) : ev.raw) }
      } catch { /* leave as is */ }
      try { const { data } = await api.get(`/api/v1/agents/${agent.id}/response`); if (live) setTunnel(!!data.tunnel_online) } catch { /* not available */ }
    }
    load(); const t = setInterval(load, 30000)
    return () => { live = false; clearInterval(t) }
  }, [agent.hostname, agent.id])

  const rows = []
  const age = at ? (Date.now() - new Date(at).getTime()) / 1000 : null
  rows.push({ name: 'Agent heartbeat', state: !agent.online ? 'error' : age == null ? 'unknown' : age > 300 ? 'error' : age > 150 ? 'warn' : 'ok',
    detail: at ? `last health report ${formatDistanceToNow(new Date(at), { addSuffix: true })}` : 'no health report yet' })
  if (raw) {
    if (Array.isArray(raw.components)) raw.components.forEach(c => rows.push(c))
    else {
      (raw.collectors || []).forEach(c => rows.push({ name: `${c} collector`, state: 'ok', detail: 'running' }))
      if (raw.sysmon_status) rows.push({ name: 'Sysmon', state: raw.sysmon_status === 'running' ? 'ok' : 'error', detail: raw.sysmon_status.replace(/_/g, ' ') })
    }
    rows.push({ name: 'Event forwarding', state: raw.forward_errors > 0 && raw.queue_depth > 1000 ? 'error' : raw.forward_errors > 0 ? 'warn' : 'ok',
      detail: `${(raw.events_forwarded ?? 0).toLocaleString()} sent, ${raw.forward_errors ?? 0} errors, queue ${raw.queue_depth ?? 0}` })
    if (raw.events_dropped > 0 || raw.rate_limit_drops > 0) rows.push({ name: 'Event drops', state: 'warn', detail: `${raw.events_dropped || 0} dropped, ${raw.rate_limit_drops || 0} rate-limited` })
  }
  if (tunnel !== null) rows.push({ name: 'Live Response tunnel', state: tunnel ? 'ok' : 'warn', detail: tunnel ? 'connected (response actions available)' : 'not connected (needs live_response enabled)' })

  const worst = rows.some(r => r.state === 'error') ? 'error' : rows.some(r => r.state === 'warn') ? 'warn' : 'ok'
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Agent health</div>
        <span className={`text-[10px] font-semibold ${TXT[worst]}`}>{worst === 'ok' ? 'All components healthy' : worst === 'warn' ? 'Needs attention' : 'Component failing'}</span>
      </div>
      <div className="grid md:grid-cols-2 gap-x-6">
        {rows.map((r, i) => (
          <div key={i} className="flex items-center gap-2 text-xs py-1.5 border-b border-siem-border/40">
            <span className={`w-2 h-2 rounded-full shrink-0 ${DOT[r.state] || DOT.unknown}`} />
            <span className="text-siem-text">{r.name}</span>
            <span className={`ml-auto font-mono text-[11px] truncate ${TXT[r.state] || TXT.unknown}`} title={r.detail}>{r.detail}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
