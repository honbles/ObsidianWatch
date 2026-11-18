import { Navigate, useParams } from 'react-router-dom'

export const appPath = '/applications/routes/:key'

// Entity chips for kind "route" use the key "name|environment|METHOD /template".
export default function AppEntityRoute() {
  const { key } = useParams()
  const first = key.indexOf('|'), second = key.indexOf('|', first + 1)
  if (first < 0 || second < 0) return <Navigate to="/applications/services" replace />
  const svc = key.slice(0, second)
  const route = key.slice(second + 1).replace(/^[A-Z]+ /, '')
  return <Navigate to={`/applications/services/${encodeURIComponent(svc)}?tab=routes&route=${encodeURIComponent(route)}`} replace />
}
