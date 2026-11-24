// One alert on its own page (shareable link). The Alerts list opens the same panel at the side for quick triage.
import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import api from '../api/client'
import AlertPanel from '../components/AlertPanel'
import { PageHeader } from '../components/ui'

export default function AlertPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [users, setUsers] = useState([])
  useEffect(() => { api.get('/api/v1/assignees').then(r => setUsers(r.data.users || [])).catch(() => {}) }, [])
  return (
    <div>
      <PageHeader title={`Alert #${id}`} actions={<><button className="ow-btn" onClick={() => navigate(-1)}>Back</button><Link className="ow-btn" style={{ textDecoration: 'none' }} to="/alerts">All alerts</Link></>}/>
      <div style={{ height: 'calc(100vh - var(--topbar-h) - 86px)', display: 'flex', flexDirection: 'column' }}>
        <AlertPanel alertId={Number(id)} users={users} onClose={() => navigate('/alerts')} onStatusChange={() => {}} inline/>
      </div>
    </div>
  )
}
