import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appInt, appMs, appRel } from '../../../components/app/appFormat'

// Jobs and message consumers: runs, failures, duration and the last run. A job with a steady cadence shows how
// often it usually runs, so a missed run is easy to see.
export default function AppTabOperations({ service, range }) {
  const { data, loading, error } = useAppLoad(() => appApi.operations(service.id, range), [service.id, range.from, range.to])
  const rows = data?.operations || []
  return (
    <div className="space-y-2">
      <div className="card">
        {error ? <div className="p-4 text-xs text-red-300">{String(error)}</div>
          : loading ? <div className="p-4 text-xs text-siem-muted">Loading...</div>
          : rows.length === 0 ? <div className="p-4 text-xs text-siem-muted">No jobs or message consumers in this range.</div> : (
            <table className="w-full text-xs">
              <thead><tr className="text-siem-muted text-left"><th className="px-3 py-2">Name</th><th>Kind</th><th className="text-right">Runs</th><th className="text-right">Failures</th><th className="text-right">p50</th><th className="text-right">p95</th><th className="text-right">Usually every</th><th className="text-right px-3">Last run</th></tr></thead>
              <tbody>{rows.map(o => (
                <tr key={o.kind + o.name} className="border-t border-siem-border/50">
                  <td className="px-3 py-1.5 font-mono break-all">{o.name}</td><td>{o.kind}</td>
                  <td className="text-right">{appInt(o.runs)}</td>
                  <td className={`text-right ${o.failures > 0 ? 'text-red-300' : ''}`}>{appInt(o.failures)}{o.failures > 0 ? ` (${(o.failure_rate * 100).toFixed(0)}%)` : ''}</td>
                  <td className="text-right">{appMs(o.p50_ms)}</td><td className="text-right">{appMs(o.p95_ms, o.over_range)}</td>
                  <td className="text-right">{o.usual_interval_min ? `${o.usual_interval_min >= 120 ? Math.round(o.usual_interval_min / 60) + ' h' : Math.round(o.usual_interval_min) + ' min'}` : '-'}</td>
                  <td className="text-right px-3">{appRel(o.last_run)}</td></tr>))}</tbody>
            </table>)}
      </div>
      <div className="text-xs text-siem-muted">Only job and queue names are sent.</div>
    </div>
  )
}
