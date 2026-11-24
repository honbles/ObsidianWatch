import { useState } from 'react'
import { Sparkline } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'

function fmt(v, unit) {
  if (v == null || Number.isNaN(v)) return '-'
  if (unit === 'By') return v >= 1073741824 ? `${(v / 1073741824).toFixed(2)} GiB` : `${(v / 1048576).toFixed(1)} MiB`
  if (unit === 's') return `${(v * 1000).toFixed(1)} ms`
  if (unit === '1' && v <= 1.5) return `${(v * 100).toFixed(1)}%`
  return Math.abs(v) >= 100 ? v.toFixed(0) : v.toFixed(2)
}

// One row per runtime or pool series the service reports; click a row for its chart over the range.
function Detail({ service, range, row, instance }) {
  const { data } = useAppLoad(() => appApi.metrics(service.id, range, { name: row.name, instance }), [service.id, range.from, range.to, row.name, instance])
  const s = (data?.series || []).find(x => x.attr === row.attr)
  const pts = s?.points || []
  return (
    <div className="px-3 py-2 bg-siem-surface2/40">
      <Sparkline values={pts.map(p => p.avg)} width={480} height={48} />
      <div className="text-[11px] text-siem-muted mt-1">{pts.length} points, step {data?.step_min || '-'} min. Highest {fmt(Math.max(...pts.map(p => p.max), 0), row.unit)}.</div>
    </div>
  )
}

export default function AppTabMetrics({ service, range }) {
  const [instance, setInstance] = useState('')
  const [open, setOpen] = useState('')
  const { data, loading, error } = useAppLoad(() => appApi.metrics(service.id, range, instance ? { instance } : {}), [service.id, range.from, range.to, instance])
  const rows = data?.metrics || []
  const insts = (service.instances_list || []).filter(Boolean)
  return (
    <div className="space-y-2">
      {insts.length > 1 && (
        <div className="flex items-center gap-2 text-xs text-siem-muted">Instance
          <select className="bg-siem-surface2 border border-siem-border rounded px-1.5 py-1 text-siem-text" value={instance} onChange={e => setInstance(e.target.value)}>
            <option value="">All</option>{insts.map(i => <option key={i} value={i}>{i}</option>)}
          </select>
        </div>)}
      <div className="card">
        {error ? <div className="p-4 text-xs text-red-300">{String(error)}</div>
          : loading ? <div className="p-4 text-xs text-siem-muted">Loading...</div>
          : rows.length === 0 ? <div className="p-4 text-xs text-siem-muted">No runtime metrics in this range. Turn on the OpenTelemetry metrics exporter in the application (see the setup guide); only runtime and connection-pool metrics are kept.</div>
          : (
            <table className="w-full text-xs">
              <thead><tr className="text-siem-muted text-left"><th className="px-3 py-2">Metric</th><th>Detail</th><th className="text-right">Latest</th><th className="text-right">Average</th><th className="text-right">Max</th><th className="text-right px-3">Instances</th></tr></thead>
              <tbody>
                {rows.map(r => {
                  const k = r.name + '|' + r.attr
                  return [
                    <tr key={k} className="border-t border-siem-border/50 cursor-pointer hover:bg-siem-surface2/40" onClick={() => setOpen(open === k ? '' : k)}>
                      <td className="px-3 py-1.5 font-mono">{r.name}</td><td className="font-mono text-siem-muted">{r.attr || '-'}</td>
                      <td className="text-right">{fmt(r.last, r.unit)}</td><td className="text-right">{fmt(r.avg, r.unit)}</td><td className="text-right">{fmt(r.max, r.unit)}</td><td className="text-right px-3">{r.instances}</td>
                    </tr>,
                    open === k && <tr key={k + 'd'}><td colSpan={6}><Detail service={service} range={range} row={r} instance={instance} /></td></tr>,
                  ]
                })}
              </tbody>
            </table>)}
      </div>
      <div className="text-[11px] text-siem-muted">Only an allowlist of runtime and pool metrics is accepted (CPU, memory, event loop, garbage collection, connection pools). Attributes are limited to states and pool names; nothing else leaves the host. Rule APM-O07 alerts when an instance stays saturated.</div>
    </div>
  )
}
