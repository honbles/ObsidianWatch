import { useEffect, useState } from 'react'
import { Users as UsersIcon, Plus, Trash2, ShieldCheck, User } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'
import { PageHeader, Num, DenseTable, StatePill, Dialog, Field } from '../components/ui'

export default function Users() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ username: '', password: '', role: 'analyst' })
  const [error, setError] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/users')
      setUsers(data.users || [])
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const create = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await api.post('/api/v1/users', form)
      setShowCreate(false)
      setForm({ username: '', password: '', role: 'analyst' })
      load()
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create user')
    }
  }

  const del = async (id, username) => {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return
    await api.delete(`/api/v1/users/${id}`)
    load()
  }

  const dormant = (u) => !u.last_login || Date.now() - new Date(u.last_login) > 90 * 86400e3
  const userState = (u) => !u.password_changed ? 'warn' : dormant(u) ? 'none' : 'ok'
  return (
    <div>
      <PageHeader title="Users and access"
        state={loading ? undefined : users.some(u => !u.password_changed) ? 'warn' : 'ok'}
        stateText={users.filter(u => !u.password_changed).length ? `${users.filter(u => !u.password_changed).length} still on the initial password` : 'All passwords changed'}
        sub="Admins manage the platform, analysts triage and respond, viewers read."
        actions={<button className="ow-btn primary" onClick={() => setShowCreate(true)}><Plus size={13}/>New user</button>}
        nums={<>
          <Num k="Users" v={users.length}/>
          <Num k="Admins" v={users.filter(u => u.role === 'admin').length}/>
          <Num k="Initial password" v={users.filter(u => !u.password_changed).length} tone={users.some(u => !u.password_changed) ? 'warn' : undefined}/>
          <Num k="No login in 90 days" v={users.filter(dormant).length} title="Never signed in, or not for 90 days"/>
        </>}/>
      <div className="ow-body">
        <div className="ow-card" style={{ overflow: 'hidden' }}>
          <DenseTable rows={loading ? [] : users} rowKey={u => u.id} rowState={u => userState(u) === 'ok' ? null : userState(u)} empty={loading ? 'Loading…' : 'No users.'} cols={[
            { key: 'u', label: 'User', width: 'minmax(160px, 1.4fr)', render: u => <span className="t1" style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span className="tb-avatar">{u.username[0]?.toUpperCase()}</span>{u.username}</span> },
            { key: 'r', label: 'Role', width: '110px', render: u => <StatePill state={u.role === 'admin' ? 'info' : 'none'} dot={false}>{u.role[0].toUpperCase() + u.role.slice(1)}</StatePill> },
            { key: 'p', label: 'Password', width: '130px', render: u => u.password_changed ? <span className="t2">Changed</span> : <StatePill state="warn">Initial</StatePill> },
            { key: 'l', label: 'Last login', width: '160px', render: u => u.last_login ? <span className={dormant(u) ? 'c-warn' : 't2'}>{format(new Date(u.last_login), 'dd MMM yyyy HH:mm')}</span> : <span className="t3">Never</span> },
            { key: 'c', label: 'Created', width: '120px', render: u => <span className="t2">{format(new Date(u.created_at), 'dd MMM yyyy')}</span> },
            { key: 'x', label: '', width: '80px', render: u => u.username !== 'admin' && <button className="ow-btn quiet" style={{ height: 24, color: 'var(--crit)' }} onClick={() => del(u.id, u.username)}><Trash2 size={13}/>Delete</button> },
          ]}/>
        </div>
      </div>
      {showCreate && (
        <Dialog title="New user" onClose={() => setShowCreate(false)}>
          <form onSubmit={create} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <Field label="Username"><input className="input" autoFocus required value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))}/></Field>
            <Field label="Password" hint="At least 10 characters. They will be asked to change it."><input className="input" type="password" required minLength={10} value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))}/></Field>
            <Field label="Role"><select className="input" value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
              <option value="analyst">Analyst</option><option value="viewer">Viewer (read only)</option><option value="admin">Admin</option></select></Field>
            {error && <div className="c-crit" style={{ fontSize: 12.5 }}>{error}</div>}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button type="button" className="ow-btn quiet" onClick={() => setShowCreate(false)}>Cancel</button>
              <button type="submit" className="ow-btn primary">Create user</button>
            </div>
          </form>
        </Dialog>
      )}
    </div>
  )
}
