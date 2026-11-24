import { useNavigate, useParams, Link } from 'react-router-dom'
import { appResolveService } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import { PageHeader } from '../../components/ui'
import { AppErrorDetail } from './tabs/AppTabErrors'

export const appPath = '/applications/services/:key/errors/:id'

// One error group as its own page: stack, versions, sample traces, triage.
export default function AppError() {
  const { key, id } = useParams()
  const navigate = useNavigate()
  const { data: svc } = useAppLoad(() => appResolveService(key), [key])
  return (
    <div>
      <PageHeader title="Error group" sub={svc ? <>In <Link to={`/applications/services/${encodeURIComponent(key)}?tab=errors`} className="mono c-acc">{svc.name}</Link> · {svc.environment}</> : 'Loading…'}
        actions={<button className="ow-btn" onClick={() => navigate(-1)}>Back</button>}/>
      <div className="ow-body">
        {svc && <AppErrorDetail id={Number(id)} service={svc} svcKey={key} onChanged={() => {}} page/>}
      </div>
    </div>
  )
}
