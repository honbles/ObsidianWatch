import { useMemo } from 'react'
import { appMs } from './appFormat'

// Waterfall of one sampled trace. spans: [{span_id,parent_id,name,service,start_ms,dur_ms,status,...}]
export default function AppTraceWaterfall({ trace }) {
  const rows = useMemo(() => {
    const spans = Array.isArray(trace.spans) ? trace.spans : []
    const byId = new Map(spans.map(s => [s.span_id, s]))
    const depth = (s) => { let d = 0, cur = s, guard = 0; while (cur.parent_id && byId.has(cur.parent_id) && guard++ < 50) { cur = byId.get(cur.parent_id); d++ } return d }
    const total = Math.max(1, ...spans.map(s => (s.start_ms || 0) + (s.dur_ms || 0)))
    return { total, list: [...spans].sort((a, b) => (a.start_ms || 0) - (b.start_ms || 0)).map(s => ({ ...s, depth: depth(s) })) }
  }, [trace])
  const truncated = trace.span_count > rows.list.length
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-siem-muted">
        <span>Total <b className="text-siem-text">{appMs(trace.duration_ms)}</b></span>
        <span>Spans <b className="text-siem-text">{trace.span_count}</b></span>
        <span>Kept because <b className="text-siem-text">{trace.keep_reason}</b></span>
        <span>Status <b className={trace.status === 'error' ? 'text-red-300' : 'text-siem-text'}>{trace.status || '-'}</b></span>
        <span className="font-mono">{trace.trace_id}</span>
      </div>
      <div className="card divide-y divide-siem-border/50">
        {rows.list.map((s, i) => {
          const left = ((s.start_ms || 0) / rows.total) * 100
          const width = Math.max(0.6, ((s.dur_ms || 0) / rows.total) * 100)
          const bad = s.status === 'error'
          const detail = [s.method, s.route, s.code || '', s.db && `db:${s.db}`, s.peer && `→${s.peer}`, s.exception && `! ${s.exception}`].filter(Boolean).join(' ')
          return (
            <div key={s.span_id + i} className="grid grid-cols-[minmax(160px,34%)_1fr_70px] items-center gap-2 px-2 py-1 text-[11px]">
              <div className="truncate" style={{ paddingLeft: s.depth * 12 }} title={`${s.name} ${detail}`}>
                <span className={bad ? 'text-red-300' : 'text-siem-text'}>{s.name || s.span_id}</span>
                {s.service && <span className="text-siem-muted"> · {s.service}</span>}
              </div>
              <div className="relative h-3 bg-white/5 rounded">
                <div className={`absolute h-3 rounded ${bad ? 'bg-red-500/70' : 'bg-siem-accent/60'}`} style={{ left: `${left}%`, width: `${Math.min(width, 100 - left)}%` }} />
              </div>
              <div className="text-right text-siem-muted">{appMs(s.dur_ms)}</div>
            </div>
          )
        })}
      </div>
      {truncated && <div className="text-[11px] text-amber-300">Only {rows.list.length} of {trace.span_count} spans were kept (traces are capped at 64 KB).</div>}
    </div>
  )
}
