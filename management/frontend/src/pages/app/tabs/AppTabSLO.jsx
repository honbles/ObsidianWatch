import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appTime } from '../../../components/app/appFormat'

function Slo({ s, days }) {
  const rem = Math.max(0, Math.min(100, s.budget_remaining_pct))
  const over = s.budget_remaining_pct < 0
  const tone = over ? 'bg-red-500' : rem < 25 ? 'bg-amber-500' : 'bg-emerald-500'
  return (
    <div className="card p-4 space-y-2">
      <div className="flex items-baseline justify-between gap-2 flex-wrap">
        <div className="text-sm font-medium text-siem-text capitalize">{s.name}{s.latency_target_ms ? ` (under ${s.latency_target_ms} ms)` : ''}</div>
        <div className="text-xs text-siem-muted">objective {s.target_pct}% over {days} days</div>
      </div>
      <div className="flex items-baseline gap-4 flex-wrap">
        <div><span className="text-2xl text-siem-text">{s.sli_pct.toFixed(2)}%</span> <span className="text-xs text-siem-muted">achieved over {s.calls.toLocaleString()} requests</span></div>
        <div className={`text-sm ${over ? 'text-red-300' : 'text-siem-text'}`}>{over ? 'Budget exhausted' : `${s.budget_remaining_pct.toFixed(0)}% of the error budget left`}</div>
      </div>
      <div className="h-2 rounded bg-siem-surface2 overflow-hidden"><div className={`h-full ${tone}`} style={{ width: `${over ? 100 : rem}%` }} /></div>
      <div className="text-xs text-siem-muted flex gap-4 flex-wrap">
        <span>{Math.round(s.bad).toLocaleString()} bad of {Math.round(s.budget_bad).toLocaleString()} allowed</span>
        <span>burn rate {s.burn_1h.toFixed(1)}x over 1 h, {s.burn_6h.toFixed(1)}x over 6 h <span title="1x spends the budget exactly over the window">(1x is on pace)</span></span>
        <span>{s.exhausts_at ? <>at the last day's pace the budget runs out {appTime(s.exhausts_at)}</> : over ? '' : 'not on course to run out'}</span>
      </div>
    </div>
  )
}

// The objective, what has been achieved over its window, the error budget left and when it would run out.
export default function AppTabSLO({ service }) {
  const { data, loading, error } = useAppLoad(() => appApi.slo(service.id), [service.id])
  const slos = data?.slos || []
  return (
    <div className="space-y-2">
      {error ? <div className="card p-4 text-xs text-red-300">{String(error)}</div>
        : loading ? <div className="card p-4 text-xs text-siem-muted">Loading...</div>
        : slos.map(s => <Slo key={s.name} s={s} days={data.window_days} />)}
      {!loading && !error && !service.settings?.latency_target_ms && <div className="text-[11px] text-siem-muted">Set a latency target in Settings to add a latency objective.</div>}
      <div className="text-[11px] text-siem-muted">Availability counts requests that did not fail. By default the objective is 100 minus the service's error budget (99.9% when none is set); change it, the window (7 or 28 days) and the latency share in Settings. Latency is estimated from the latency histogram. Rule APM-O13 alerts when the budget is spent far faster than the objective allows, over a long and a short window together.</div>
    </div>
  )
}
