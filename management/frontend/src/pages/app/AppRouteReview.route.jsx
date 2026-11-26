import { useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useTimeRange, StateBlock } from '../../components/shared'
import { appApi, appResolveService } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import AppPageHeader from '../../components/app/AppPageHeader'
import AppStatCard from '../../components/app/AppStatCard'
import AppRoutePolicyPanel from '../../components/app/AppRoutePolicyPanel'
import { appInt, appPct, appMs, appRel, appTime, appIsAdmin } from '../../components/app/appFormat'

export const appPath = '/applications/services/:key/routes/:method/*'

const PAGE = 25
const sel = 'bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text'

// One route: its numbers, the masking review, and every captured request (paged, filterable).
export default function AppRouteReview() {
  const { key, method, '*': splat } = useParams()
  const route = '/' + (splat || '')
  const range = useTimeRange(24 * 3600e3)
  const [sp, setSp] = useSearchParams()
  const status = sp.get('status') || ''
  const page = Math.max(0, parseInt(sp.get('page') || '0', 10) || 0)
  const admin = appIsAdmin()
  const [rev, setRev] = useState(0)
  const patch = (o) => { const n = new URLSearchParams(sp); Object.entries(o).forEach(([k, v]) => (v ? n.set(k, v) : n.delete(k))); setSp(n, { replace: true }) }

  const svcQ = useAppLoad(() => appResolveService(key), [key])
  const svc = svcQ.data
  const routes = useAppLoad(() => appApi.routes(svc.id, range), [svc?.id, range.from, range.to, rev], !!svc)
  const r = useMemo(() => (routes.data?.routes || []).find(x => x.method === method && x.route === route), [routes.data, method, route])
  const reviewed = r && (r.payload_review === 'reviewed' || r.payload_review === 'new_fields')
  const list = useAppLoad(() => appApi.payloads(svc.id, range, { route, method, status: status || undefined, limit: PAGE, offset: page * PAGE }),
    [svc?.id, route, method, status, page, range.from, range.to, rev, r?.policy?.reviewed_at], !!svc && admin && !!reviewed)
  const total = list.data?.total || 0
  const svcPath = `/applications/services/${encodeURIComponent(key)}`

  return (
    <div className="p-6 space-y-4">
      <AppPageHeader title={svc ? svc.name : 'Route'} subtitle={svc ? svc.environment : undefined} range={range} />
      <StateBlock loading={svcQ.loading} error={svcQ.error || (!svcQ.loading && !svc ? 'Service not found' : null)}>
        {svc && (
          <>
            <div className="flex items-center gap-3 text-xs">
              <Link to={`${svcPath}?tab=routes`} className="text-siem-accent hover:underline">&larr; Routes</Link>
              <span className="font-mono text-sm text-siem-text">{method} {route}</span>
            </div>
            {!r && !routes.loading && <div className="card p-4 text-xs text-siem-muted">This route has no traffic recorded in the selected range. Widen the range above to see it.</div>}
            {r && (
              <>
                {r.declared && !r.observed && <div className="card p-3 text-xs text-teal-300">Declared by the API spec, no traffic yet. You can review and mask its fields now; the agent applies the review as soon as requests arrive.</div>}
                {r.not_in_spec && <div className="card p-3 text-xs text-amber-300">This route is receiving traffic but is not in the loaded API spec.</div>}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  <AppStatCard label="Calls" value={appInt(r.stats.calls)} />
                  <AppStatCard label="Error rate" value={appPct(r.stats.error_rate)} />
                  <AppStatCard label="401/403" value={appInt(r.stats.status_401_403)} />
                  <AppStatCard label="p95" value={appMs(r.stats.p95_ms, r.stats.over_range)} />
                  <AppStatCard label="Last seen" value={appRel(r.last_seen)} />
                </div>
                {(r.params || []).length === 0
                  ? <div className="card p-4 text-xs text-siem-muted">No query or body fields seen on this route.</div>
                  : <AppRoutePolicyPanel service={svc} route={r} onSaved={() => setRev(x => x + 1)} />}
                <div className="card p-4 space-y-3">
                  <div className="flex items-center gap-3 flex-wrap">
                    <div className="text-sm font-medium text-siem-text">Captured requests</div>
                    <select className={sel} value={status} onChange={e => patch({ status: e.target.value, page: '' })}>
                      <option value="">Any status</option><option value="2xx">2xx</option><option value="3xx">3xx</option>
                      <option value="4xx">4xx</option><option value="5xx">5xx</option><option value="401">401</option><option value="403">403</option><option value="500">500</option>
                    </select>
                    <span className="text-[11px] text-siem-muted">Admin only. Values appear only for fields left unmasked on a reviewed route.</span>
                  </div>
                  {!admin ? <div className="text-xs text-amber-300">Viewing captured requests needs the admin role.</div>
                    : !reviewed ? <div className="text-xs text-siem-muted">Nothing is captured until this route is reviewed.</div>
                    : (
                      <StateBlock loading={list.loading && !list.data} error={list.error}>
                        <div className="overflow-x-auto">
                          <table className="w-full text-xs">
                            <thead><tr className="text-left text-siem-muted">
                              <th className="py-1 pr-3 font-normal">Time</th><th className="font-normal">Status</th><th className="font-normal text-right pr-3">Latency</th>
                              <th className="font-normal">Fields</th><th className="font-normal">Withheld</th><th className="font-normal text-right">Trace</th></tr></thead>
                            <tbody>
                              {(list.data?.payloads || []).map((s, i) => (
                                <tr key={i} className="border-t border-siem-border align-top">
                                  <td className="py-1.5 pr-3 whitespace-nowrap">{appTime(s.time)}</td>
                                  <td className={s.status >= 400 ? 'text-red-300' : ''}>{s.status || '-'}</td>
                                  <td className="text-right pr-3">{s.duration_ms ? appMs(s.duration_ms) : '-'}</td>
                                  <td className="font-mono break-all">{Object.entries(s.params).map(([k, v]) => <span key={k} className="mr-3">{k}=<span className="text-siem-text">{v}</span></span>)}</td>
                                  <td className="font-mono text-siem-muted break-all">{s.withheld.join(', ') || '-'}</td>
                                  <td className="text-right">{s.trace_id ? <Link className="text-siem-accent hover:underline" to={`/applications/traces/${encodeURIComponent(s.trace_id)}?svc=${encodeURIComponent(key)}`}>open</Link> : '-'}</td>
                                </tr>))}
                              {!(list.data?.payloads || []).length && <tr><td colSpan={6} className="py-3 text-siem-muted">None in this range{status ? ' for that status' : ''}. Samples arrive after the agent pulls the policy and the route receives traffic.</td></tr>}
                            </tbody>
                          </table>
                        </div>
                        <div className="flex items-center gap-3 text-xs text-siem-muted pt-2">
                          <span>{total ? `${page * PAGE + 1}-${Math.min(total, page * PAGE + (list.data?.payloads || []).length)} of ${appInt(total)}` : '0 requests'}</span>
                          <button className="btn-secondary text-xs" disabled={page === 0} onClick={() => patch({ page: page > 1 ? String(page - 1) : '' })}>Previous</button>
                          <button className="btn-secondary text-xs" disabled={!list.data?.has_more} onClick={() => patch({ page: String(page + 1) })}>Next</button>
                        </div>
                      </StateBlock>)}
                </div>
              </>)}
          </>)}
      </StateBlock>
    </div>
  )
}
