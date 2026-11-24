import { Link, useParams, useSearchParams, useNavigate } from 'react-router-dom'
import { StateBlock } from '../../components/shared'
import { appApi } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import AppTraceWaterfall from '../../components/app/AppTraceWaterfall'
import { PageHeader, StatePill } from '../../components/ui'
import { appMs, appTime, appReviewPath, appSplitRequest } from '../../components/app/appFormat'
import { appSplitKey } from '../../api/app'

export const appPath = '/applications/traces/:traceId'

// One sampled trace as a page of its own, so it can be linked from alerts, errors and routes and shared.
export default function AppTrace() {
  const { traceId } = useParams()
  const [sp] = useSearchParams()
  const navigate = useNavigate()
  const svcKey = sp.get('svc') || ''
  const { data: t, loading, error } = useAppLoad(() => appApi.trace(traceId), [traceId])
  const req = t ? appSplitRequest(t.root_route) : null
  const svc = svcKey ? appSplitKey(svcKey) : null
  return (
    <div>
      <PageHeader title={t?.root_route || 'Trace'} mono
        state={t ? (t.status === 'error' ? 'crit' : 'ok') : undefined} stateText={t?.status === 'error' ? 'Error' : 'OK'}
        sub={<>Trace <span className="mono t1">{traceId}</span>{t && <> · {appTime(t.started)} · {appMs(t.duration_ms)} · {t.span_count} spans · kept because {t.keep_reason}</>}</>}
        actions={<>
          <button className="ow-btn" onClick={() => navigate(-1)}>Back</button>
          {svc && <Link className="ow-btn" style={{ textDecoration: 'none' }} to={`/applications/services/${encodeURIComponent(svcKey)}?tab=traces`}>All traces of {svc.name}</Link>}
          {svc && req && <Link className="ow-btn primary" style={{ textDecoration: 'none' }} to={appReviewPath({ name: svc.name, environment: svc.environment }, req.method, req.route)}>Open route</Link>}
        </>}/>
      <div className="ow-body">
        <StateBlock loading={loading && !t} error={error} empty={!loading && !t} emptyText="This trace is gone. Sampled traces are kept for 7 days.">
          {t && <div className="ow-card" style={{ padding: 16 }}><AppTraceWaterfall trace={t}/></div>}
        </StateBlock>
        {t?.status === 'error' && <div className="t3" style={{ fontSize: 12, marginTop: 8 }}><StatePill state="crit">Error</StatePill> Failed spans are marked in the waterfall.</div>}
      </div>
    </div>
  )
}
