import { Navigate, useParams } from 'react-router-dom'
import { StateBlock } from '../../components/shared'
import { appApi } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'

export const appPath = '/applications/instances/:id'

// Entity chips for kind "service_instance" link here; send the analyst to the instance in its service.
export default function AppEntityInstance() {
  const { id } = useParams()
  const { data, loading, error } = useAppLoad(() => appApi.instance(id), [id])
  if (data) return <Navigate to={`/applications/services/${encodeURIComponent(data.key)}?tab=instances&instance=${data.id}`} replace />
  return <div className="p-6"><StateBlock loading={loading} error={error} /></div>
}
